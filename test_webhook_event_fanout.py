import json
import time
import unittest

from council_contracts import ReceiptEnvelope, RoundHandoffReceipt, WebhookDispatchReceipt
from lifecycle_hooks import AllowListedTestHookManager, LifecycleHookError
from webhook_event_fanout import SignedWebhookDispatcher, WebhookDispatchError, WebhookEndpointConfig


class RecordingHTTPPost:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.calls = []

    def __call__(self, url, body, headers, timeout_sec):
        self.calls.append({
            "url": url,
            "body": body,
            "headers": headers,
            "timeout_sec": timeout_sec,
        })
        index = min(len(self.calls) - 1, len(self.statuses) - 1)
        return self.statuses[index], b"ok"


class TestWebhookEventFanout(unittest.TestCase):

    def _handoff(self):
        return ReceiptEnvelope.seal(RoundHandoffReceipt(
            round_index=1,
            objective_id="obj_webhook",
            status="COMPLETED",
            summary="session complete",
            evidence_uris=["receipt://ok"],
            next_steps=[],
            blocker_description=None,
            transcript_discarded_turns=0,
            workspace_state_sha256="state_sha",
            handoff_timestamp=time.time()
        ))

    def test_successful_dispatch_signs_payload_and_seals_receipt(self):
        recorder = RecordingHTTPPost([204])
        dispatcher = SignedWebhookDispatcher(
            endpoints=[WebhookEndpointConfig(
                name="ops",
                target_url="https://example.com/council",
                secret="shared-secret",
                allowed_event_types={"SESSION_STOP"}
            )],
            http_post=recorder,
            clock=lambda: 123.0
        )

        receipts = dispatcher.dispatch_event("SESSION_STOP", {"session_id": "sess_1"}, event_id="evt_001")

        self.assertEqual(len(receipts), 1)
        self.assertIsInstance(receipts[0].payload, WebhookDispatchReceipt)
        self.assertTrue(receipts[0].payload.delivered)
        self.assertEqual(receipts[0].payload.attempt_count, 1)
        call = recorder.calls[0]
        signature = call["headers"][dispatcher.SIGNATURE_HEADER].removeprefix("v1=")
        self.assertTrue(dispatcher.verify_signature("shared-secret", "123", call["body"], signature))
        self.assertEqual(call["headers"][dispatcher.IDEMPOTENCY_HEADER], "evt_001")
        self.assertEqual(json.loads(call["body"])["payload"]["session_id"], "sess_1")

    def test_non_2xx_responses_are_retried_and_receipted(self):
        recorder = RecordingHTTPPost([503, 503])
        dispatcher = SignedWebhookDispatcher(
            endpoints=[WebhookEndpointConfig(
                name="ops",
                target_url="https://example.com/council",
                secret="shared-secret",
                max_attempts=2,
                retry_backoff_sec=9.0
            )],
            http_post=recorder,
            clock=lambda: 200.0
        )

        receipts = dispatcher.dispatch_event("ESCALATION_TRIGGERED", {"level": "critical"}, event_id="evt_retry")

        self.assertEqual(len(recorder.calls), 2)
        receipt = receipts[0].payload
        self.assertFalse(receipt.delivered)
        self.assertEqual(receipt.http_status_code, 503)
        self.assertEqual(receipt.attempt_count, 2)
        self.assertEqual(receipt.next_retry_at, 209.0)

    def test_endpoint_event_allowlist_skips_irrelevant_event(self):
        recorder = RecordingHTTPPost([204])
        dispatcher = SignedWebhookDispatcher(
            endpoints=[WebhookEndpointConfig(
                name="ops",
                target_url="https://example.com/council",
                secret="shared-secret",
                allowed_event_types={"SESSION_STOP"}
            )],
            http_post=recorder
        )

        receipts = dispatcher.dispatch_event("CRITICAL_SECURITY_VETO", {"reason": "blocked"})

        self.assertEqual(receipts, [])
        self.assertEqual(recorder.calls, [])

    def test_endpoint_policy_rejects_insecure_or_private_targets(self):
        dispatcher = SignedWebhookDispatcher(
            endpoints=[WebhookEndpointConfig(
                name="bad",
                target_url="http://example.com/council",
                secret="shared-secret"
            )],
            http_post=RecordingHTTPPost([204])
        )

        with self.assertRaises(WebhookDispatchError):
            dispatcher.dispatch_event("SESSION_STOP", {"session_id": "sess_1"})

        dispatcher = SignedWebhookDispatcher(
            endpoints=[WebhookEndpointConfig(
                name="local",
                target_url="https://127.0.0.1/council",
                secret="shared-secret"
            )],
            http_post=RecordingHTTPPost([204])
        )
        with self.assertRaises(WebhookDispatchError):
            dispatcher.dispatch_event("SESSION_STOP", {"session_id": "sess_1"})

    def test_lifecycle_stop_fans_out_with_source_receipt_binding(self):
        recorder = RecordingHTTPPost([204])
        dispatcher = SignedWebhookDispatcher(
            endpoints=[WebhookEndpointConfig(
                name="ops",
                target_url="https://example.com/council",
                secret="shared-secret",
                allowed_event_types={"SESSION_STOP"}
            )],
            http_post=recorder,
            clock=lambda: 321.0
        )
        manager = AllowListedTestHookManager(
            allowed_operations={"FILESYSTEM_WRITE"},
            webhook_dispatcher=dispatcher
        )
        manager.session_start("sess_stop", {"purpose": "webhook"})

        stop_env = manager.stop("sess_stop", self._handoff())

        self.assertEqual(len(manager.webhook_dispatch_receipts), 1)
        dispatch_receipt = manager.webhook_dispatch_receipts[0].payload
        self.assertEqual(dispatch_receipt.event_type, "SESSION_STOP")
        self.assertEqual(dispatch_receipt.source_receipt_sha256, stop_env.payload_sha256)
        body = json.loads(recorder.calls[0]["body"])
        self.assertEqual(body["payload"]["hook_payload_sha256"], stop_env.payload_sha256)

    def test_lifecycle_security_veto_fans_out_before_raise(self):
        dispatcher = SignedWebhookDispatcher(
            endpoints=[WebhookEndpointConfig(
                name="security",
                target_url="https://example.com/security",
                secret="shared-secret",
                allowed_event_types={"CRITICAL_SECURITY_VETO"}
            )],
            http_post=RecordingHTTPPost([204]),
            clock=lambda: 456.0
        )
        manager = AllowListedTestHookManager(
            allowed_operations={"FILESYSTEM_WRITE"},
            webhook_dispatcher=dispatcher
        )
        manager.session_start("sess_veto", {"purpose": "webhook"})

        with self.assertRaises(LifecycleHookError):
            manager.pre_tool_use("sess_veto", "SUBPROCESS_EXEC", {"command": "rm -rf /"})

        self.assertEqual(len(manager.webhook_dispatch_receipts), 1)
        receipt = manager.webhook_dispatch_receipts[0].payload
        self.assertEqual(receipt.event_type, "CRITICAL_SECURITY_VETO")
        self.assertTrue(receipt.delivered)

    def test_lifecycle_failed_post_fans_out_tainted_session(self):
        dispatcher = SignedWebhookDispatcher(
            endpoints=[WebhookEndpointConfig(
                name="ops",
                target_url="https://example.com/taint",
                secret="shared-secret",
                allowed_event_types={"TAINTED_SESSION"}
            )],
            http_post=RecordingHTTPPost([204]),
            clock=lambda: 789.0
        )
        manager = AllowListedTestHookManager(
            allowed_operations={"SUBPROCESS_EXEC"},
            webhook_dispatcher=dispatcher
        )
        manager.session_start("sess_taint", {"purpose": "webhook"})

        pre_env = manager.pre_tool_use("sess_taint", "SUBPROCESS_EXEC", {"command": "pytest"})
        manager.post_tool_use(pre_env, {"error": "boom"}, is_success=False)

        self.assertEqual(len(manager.webhook_dispatch_receipts), 1)
        receipt = manager.webhook_dispatch_receipts[0].payload
        self.assertEqual(receipt.event_type, "TAINTED_SESSION")
        self.assertTrue(receipt.delivered)


if __name__ == "__main__":
    unittest.main()
