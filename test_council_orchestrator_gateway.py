import hashlib
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from council_contracts import (
    ArtifactProvenanceRecord,
    ModelInvocationReceipt,
    ModelQualificationReceipt,
    PacketSensitivityReceipt,
    ReceiptEnvelope,
)
from council_orchestrator import LiveCouncilOrchestrator
from model_routes import create_route_attestation


class TestCouncilOrchestratorGatewayBoundary(unittest.TestCase):
    def setUp(self):
        self.test_state_dir = tempfile.mkdtemp()
        self.previous_state_dir = os.environ.get("COUNCIL_STATE_DIR")
        os.environ["COUNCIL_STATE_DIR"] = self.test_state_dir
        self.now = time.time()
        self.route = create_route_attestation(
            route_id="route_ollama_qwen_local",
            provider_name="ollama_local",
            endpoint_url="http://127.0.0.1:11434/api/generate",
            compliance_tier="LOCAL_ONLY_VERIFIED",
            content_retention_days=0,
            zdr_verified=True,
            fallbacks_allowed=False,
            validity_sec=3500,
        )
        self.qual = ReceiptEnvelope.seal(ModelQualificationReceipt(
            composite_key="ollama_local:qwen2.5-coder:7b",
            model_slug="qwen2.5-coder:7b",
            model_family="qwen",
            provider="ollama_local",
            status="REVIEW_USABLE_FRESH",
            benign_control_passed=True,
            grounded_bug_passed=True,
            exact_line_quote_verified=True,
            json_schema_conformity=True,
            evaluated_at=self.now - 100,
            expires_at=self.now + 86400,
        ))
        artifact = ArtifactProvenanceRecord(
            artifact_id="art_patch",
            artifact_type="REPO_FILE",
            path_or_identifier="contracts/PBMRebateTreasury.sol",
            content_sha256="sha_patch",
            source_upstream_commit=None,
            source_upstream_url=None,
            provenance_verified=False,
            classification_reason="internal patch under review",
        )
        self.packet = ReceiptEnvelope.seal(PacketSensitivityReceipt(
            snapshot_composite_state_sha256="state_gateway_boundary",
            sensitivity_tier="INTERNAL_NO_TRAIN_OK",
            public_safe_verified=False,
            private_artifact_count=1,
            artifacts=[artifact],
        ))

    def tearDown(self):
        if self.previous_state_dir is None:
            os.environ.pop("COUNCIL_STATE_DIR", None)
        else:
            os.environ["COUNCIL_STATE_DIR"] = self.previous_state_dir
        shutil.rmtree(self.test_state_dir, ignore_errors=True)

    def _invocation_env(self, raw_response: str):
        inv = ModelInvocationReceipt(
            packet_payload_sha256=self.packet.payload_sha256,
            route_attestation_payload_sha256=self.route.payload_sha256,
            qualification_payload_sha256=self.qual.payload_sha256,
            paid_budget_payload_sha256=None,
            model_slug="qwen2.5-coder:7b",
            model_family="qwen",
            provider="ollama_local",
            route_id=self.route.payload.route_id,
            request_payload_sha256=hashlib.sha256(b"prompt").hexdigest(),
            response_payload_sha256=hashlib.sha256(raw_response.encode("utf-8")).hexdigest(),
            prompt_tokens=12,
            completion_tokens=6,
            latency_ms=5.0,
            completed_at=self.now,
        )
        return ReceiptEnvelope.seal(inv)

    def test_dispatch_model_vote_uses_invoke_with_resilience_receipt(self):
        raw_response = '{"decision": "approve", "confidence": 0.91, "summary": "Gateway path verified."}'
        expected_invocation = self._invocation_env(raw_response)

        orchestrator = LiveCouncilOrchestrator()
        orchestrator.gateway.invoke_with_resilience = MagicMock(return_value=(expected_invocation, raw_response))
        orchestrator.gateway.dispatch_call = MagicMock(side_effect=AssertionError("dispatch_call bypassed gateway API"))

        inv_env, vote = orchestrator.dispatch_model_vote(
            "qwen2.5-coder:7b",
            "qwen",
            "ollama_local",
            self.route,
            self.qual,
            self.packet,
            "--- a/contracts/PBMRebateTreasury.sol\n+++ b/contracts/PBMRebateTreasury.sol\n",
        )

        orchestrator.gateway.invoke_with_resilience.assert_called_once()
        kwargs = orchestrator.gateway.invoke_with_resilience.call_args.kwargs
        self.assertIsNotNone(kwargs["context_engine"])
        self.assertEqual(inv_env.payload_sha256, expected_invocation.payload_sha256)
        self.assertEqual(vote.invocation_payload_sha256, expected_invocation.payload_sha256)
        self.assertEqual(vote.decision, "approve")

    def test_dispatch_model_vote_falls_back_to_abstain_on_unreachable_gateway(self):
        orchestrator = LiveCouncilOrchestrator()
        orchestrator.gateway.invoke_with_resilience = MagicMock(return_value=(None, None))

        inv_env, vote = orchestrator.dispatch_model_vote(
            "qwen2.5-coder:7b",
            "qwen",
            "ollama_local",
            self.route,
            self.qual,
            self.packet,
            "--- a/contracts/PBMRebateTreasury.sol\n+++ b/contracts/PBMRebateTreasury.sol\n",
        )

        self.assertIsNotNone(inv_env)
        self.assertEqual(vote.decision, "abstain")
        self.assertEqual(vote.confidence, 0.0)
        self.assertIn("gateway invocation unreachable", vote.redacted_summary)

    def test_run_live_council_evaluates_heterogeneous_jury_and_stability(self):
        from council_contracts import RedactedVoteRecord
        orchestrator = LiveCouncilOrchestrator()
        orchestrator.qual_runner.qualify_model = MagicMock(return_value=self.qual)

        def mock_vote(slug, fam, prov, route, qual, packet, patch_text):
            inv = self._invocation_env('{"decision": "approve", "confidence": 0.95}')
            vote = RedactedVoteRecord(
                voter_slug=slug,
                model_family=fam,
                provider=prov,
                invocation_payload_sha256=inv.payload_sha256,
                decision="approve",
                confidence=0.95,
                reasoning_sha256=hashlib.sha256(b"reason").hexdigest(),
                redacted_summary=f"Approved by {fam}"
            )
            return inv, vote

        orchestrator.dispatch_model_vote = MagicMock(side_effect=mock_vote)

        patch_bytes = b"--- a/src/auth.py\n+++ b/src/auth.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        result = orchestrator.run_live_council(patch_bytes, "repo_state_abc123")

        self.assertEqual(result["verdict"], "APPROVED")
        self.assertTrue(result["supermajority"])
        self.assertIsNotNone(result["heterogeneous_jury_receipt_sha256"])
        self.assertGreaterEqual(result["beta_binomial_stability"], 0.0)
        self.assertGreaterEqual(result["echo_chamber_risk_score"], 0.0)
        self.assertTrue(orchestrator.prompt_registry.has_prompt("council.juror.security"))
        self.assertTrue(orchestrator.prompt_registry.has_prompt("council.juror.performance"))
        self.assertTrue(orchestrator.prompt_registry.has_prompt("council.juror.architecture"))

if __name__ == "__main__":
    unittest.main()
