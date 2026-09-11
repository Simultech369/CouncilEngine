import unittest
from council_api_server import CouncilAPIServer, CouncilSSEEvent

class TestCouncilAPIServer(unittest.TestCase):

    def setUp(self):
        self.server = CouncilAPIServer()

    def test_health_endpoint(self):
        res = self.server.handle_health()
        self.assertEqual(res["status"], "HEALTHY")
        self.assertEqual(res["version"], "7.0.0")
        self.assertEqual(res["passing_tests"], 284)
        self.assertEqual(res["test_files"], 55)
        self.assertIn("4-Stage Verification Cage", res["verified_invariants"])

    def test_drift_status_endpoint(self):
        res = self.server.handle_drift_status()
        self.assertIn("total_conflicts_resolved", res)
        self.assertIn("drift_velocity_per_hour", res)
        self.assertIn("tide_alarm_triggered", res)
        self.assertIn("receipt_sha256", res)

    def test_dlq_summary_endpoint(self):
        res = self.server.handle_dlq_summary()
        self.assertIn("total_dead_letters", res)
        self.assertIn("taxonomy_summary", res)
        self.assertIsInstance(res["recent_failures"], list)

    def test_bounty_scan_endpoint_clean_code(self):
        clean_code = "import json\ndef safe_func(cursor, uid):\n    cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))"
        res = self.server.handle_bounty_scan(clean_code)
        self.assertEqual(res["patch_integrity_score"], 1.0)
        self.assertTrue(res["passed"])
        self.assertTrue(all(c["passed"] for c in res["cwe_results"]))

    def test_bounty_scan_endpoint_vulnerable_code(self):
        vuln_code = "def bad_func(cursor, uid):\n    cursor.execute(f'SELECT * FROM users WHERE id = {uid}')"
        res = self.server.handle_bounty_scan(vuln_code)
        self.assertFalse(res["passed"])
        sqli_check = next(c for c in res["cwe_results"] if c["cwe_id"] == "CWE-89")
        self.assertFalse(sqli_check["passed"])

    def test_fwa_audit_endpoint(self):
        claim_payload = {
            "claim_id": "CLM_TEST_01",
            "member_id": "M_TEST",
            "prescriber_npi": "DOC_01",
            "pharmacy_npi": "PHARM_01",
            "schedule": "NON-CONTROLLED",
            "days_supply": 30,
            "quantity": 30.0,
            "strength_mg": 10.0
        }
        res = self.server.handle_fwa_audit(claim_payload)
        self.assertEqual(res["claim_id"], "CLM_TEST_01")
        self.assertEqual(res["triage_tier"], "TIER_0_CLEAN")
        self.assertTrue(res["audit_passed"])

    def test_dizzy_event_stream_formatting(self):
        events = [
            {"event_type": "token.delta", "text": "hello"},
            {"event_type": "tool.call.completed", "tool": "edit_file"}
        ]
        sse_payload = self.server.handle_dizzy_event_stream(events)
        self.assertIn("data: {\"event_type\": \"token.delta\"", sse_payload)
        self.assertIn("data: {\"event_type\": \"tool.call.completed\"", sse_payload)
        self.assertTrue(sse_payload.endswith("\n\n"))

    def test_sse_event_framing_includes_id_event_and_retry(self):
        event = CouncilSSEEvent(
            event_id="evt_001",
            event_type="council.heartbeat",
            payload={"status": "ALL_INVARIANTS_HELD"},
            timestamp=123.0,
            retry_ms=3000
        )
        sse_payload = self.server.format_sse_event(event)
        self.assertIn("id: evt_001\n", sse_payload)
        self.assertIn("event: council.heartbeat\n", sse_payload)
        self.assertIn("retry: 3000\n", sse_payload)
        self.assertIn("\"status\": \"ALL_INVARIANTS_HELD\"", sse_payload)

    def test_live_dizzy_stream_contains_health_drift_and_dlq_events(self):
        events = self.server.build_dizzy_live_events(now=123.0)
        event_types = [event.event_type for event in events]
        self.assertEqual(event_types[0], "council.connected")
        self.assertIn("council.health", event_types)
        self.assertIn("council.drift", event_types)
        self.assertIn("council.dead_letters", event_types)
        sse_payload = self.server.handle_dizzy_event_stream(events)
        self.assertIn("event: council.health", sse_payload)
        self.assertIn("\"passing_tests\": 284", sse_payload)

    def test_sse_event_metadata_strips_line_breaks(self):
        event = CouncilSSEEvent(
            event_id="evt\nbad",
            event_type="council.health\rbad",
            payload={"status": "HEALTHY"},
            timestamp=123.0
        )
        sse_payload = self.server.format_sse_event(event)
        self.assertIn("id: evtbad\n", sse_payload)
        self.assertIn("event: council.healthbad\n", sse_payload)

    def test_a2a_api_send_and_mailbox_endpoints(self):
        from council_contracts import A2AMessage
        from a2a_protocol_engine import A2AEnvelopeSigner
        import hashlib, time

        msg = A2AMessage(
            message_id="msg_api_001",
            conversation_id="conv_api_001",
            sender_agent_id="antigravity",
            recipient_agent_id="codex",
            intent="TASK_PROPOSAL",
            payload_data={"task": "reconcile_a2a_endpoints"},
            context_snapshot_sha256=hashlib.sha256(b"snap").hexdigest(),
            nonce=f"nonce_{time.time()}"
        )
        env = A2AEnvelopeSigner.sign_message(msg, "secret_key_antigravity_hmac_256")
        
        # 1. POST /a2a/send
        res_send = self.server.handle_a2a_send(env.model_dump())
        self.assertEqual(res_send["status"], "DELIVERED")
        self.assertEqual(res_send["recipient"], "codex")

        # 2. GET /a2a/mailbox?agent_id=codex
        res_box = self.server.handle_a2a_mailbox("codex")
        self.assertEqual(res_box["agent_id"], "codex")
        self.assertEqual(res_box["message_count"], 1)
        self.assertEqual(res_box["messages"][0]["payload_data"]["task"], "reconcile_a2a_endpoints")

    def test_a2a_api_reconcile_endpoint(self):
        from council_contracts import CONTRACT_VERSION
        handoff_data = {
            "handoff_id": "handoff_api_test_01",
            "conversation_id": "conv_recon_api",
            "source_agent_id": "codex",
            "target_agent_id": "antigravity",
            "source_state_manifest": {
                "contract_version": CONTRACT_VERSION,
                "test_count": 266
            },
            "target_state_manifest": {
                "contract_version": CONTRACT_VERSION,
                "test_count": 268
            }
        }
        res = self.server.handle_a2a_reconcile(handoff_data)
        self.assertEqual(res["status"], "RECONCILED")
        self.assertTrue(res["reconciled_cleanly"])
        self.assertIn("receipt_sha256", res)

if __name__ == "__main__":
    unittest.main()
