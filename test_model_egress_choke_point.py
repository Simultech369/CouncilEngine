import ast
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

from model_gateway import ModelGateway
from model_routes import create_route_attestation
from log_derived_context_engine import LogDerivedContextEngine, LogReconstructionDesyncError
from council_contracts import (
    ReceiptEnvelope, RouteAttestationReceipt, ModelQualificationReceipt,
    PacketSensitivityReceipt, ArtifactProvenanceRecord
)
from council_verifier import VerificationError

class TestModelEgressChokePoint(unittest.TestCase):

    def setUp(self):
        self.test_state_dir = tempfile.mkdtemp()
        self.previous_state_dir = os.environ.get("COUNCIL_STATE_DIR")
        os.environ["COUNCIL_STATE_DIR"] = self.test_state_dir
        self.gateway = ModelGateway()
        self.now = time.time()

        # Valid clean route
        self.valid_local_route = create_route_attestation(
            route_id="route_ollama_qwen_local",
            provider_name="ollama_local",
            endpoint_url="http://127.0.0.1:11434/api/generate",
            compliance_tier="LOCAL_ONLY_VERIFIED",
            content_retention_days=0,
            zdr_verified=True,
            fallbacks_allowed=False,
            validity_sec=3500
        )

        # Valid clean qualification
        self.valid_qual = ReceiptEnvelope.seal(ModelQualificationReceipt(
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
            expires_at=self.now + 86400
        ))

        # Valid clean packet
        art = ArtifactProvenanceRecord(
            artifact_id="art_main",
            artifact_type="REPO_FILE",
            path_or_identifier="src/main.py",
            content_sha256="sha_main",
            source_upstream_commit="commit_123",
            source_upstream_url="https://github.com/org/repo",
            provenance_verified=True,
            classification_reason="Public repository source file"
        )
        self.valid_public_packet = ReceiptEnvelope.seal(PacketSensitivityReceipt(
            snapshot_composite_state_sha256="state_001",
            sensitivity_tier="PUBLIC_SAFE",
            public_safe_verified=True,
            private_artifact_count=0,
            artifacts=[art]
        ))

    def tearDown(self):
        if self.previous_state_dir is None:
            os.environ.pop("COUNCIL_STATE_DIR", None)
        else:
            os.environ["COUNCIL_STATE_DIR"] = self.previous_state_dir
        shutil.rmtree(self.test_state_dir, ignore_errors=True)

    def _build_context_engine(self, model="qwen2.5-coder:7b", family="qwen", provider="ollama_local", route_id="route_ollama_qwen_local"):
        ctx = LogDerivedContextEngine(session_id="test_egress_session")
        ctx.append_event("CONFIG_SET", "system", {
            "model_slug": model,
            "model_family": family,
            "provider": provider,
            "route_id": route_id,
            "temperature": 0.1,
            "max_tokens": 256
        })
        ctx.append_event("USER_INPUT", "user", {"content": "Run security check."})
        return ctx

    def test_sol_canary_probe_fails_closed_before_http(self):
        """
        Canary Test: Expired route + PUBLIC_PROVENANCE_ONLY + LOCAL_ONLY_REQUIRED packet + QUARANTINED qualification
        Must raise VerificationError before ANY HTTP network call is made.
        """
        expired_public_route = create_route_attestation(
            route_id="route_public_expired",
            provider_name="ollama_local",
            endpoint_url="http://127.0.0.1:11434/api/generate",
            compliance_tier="PUBLIC_PROVENANCE_ONLY",
            content_retention_days=0,
            zdr_verified=False,
            fallbacks_allowed=False,
            validity_sec=-100  # Expired in the past!
        )

        local_packet = ReceiptEnvelope.seal(PacketSensitivityReceipt(
            snapshot_composite_state_sha256="state_002",
            sensitivity_tier="LOCAL_ONLY_REQUIRED",
            public_safe_verified=False,
            private_artifact_count=1,
            artifacts=[ArtifactProvenanceRecord(
                artifact_id="art_secret",
                artifact_type="REPO_FILE",
                path_or_identifier="secrets.env",
                content_sha256="sha_secret",
                source_upstream_commit=None,
                source_upstream_url=None,
                provenance_verified=False,
                classification_reason="Private credential file"
            )]
        ))

        quarantined_qual = ReceiptEnvelope.seal(ModelQualificationReceipt(
            composite_key="ollama_local:qwen2.5-coder:7b",
            model_slug="qwen2.5-coder:7b",
            model_family="qwen",
            provider="ollama_local",
            status="QUARANTINED",  # Quarantined!
            benign_control_passed=False,
            grounded_bug_passed=False,
            exact_line_quote_verified=False,
            json_schema_conformity=False,
            evaluated_at=self.now - 100,
            expires_at=self.now + 86400
        ))

        ctx = self._build_context_engine(route_id="route_public_expired")

        with patch("requests.post") as mock_post:
            with self.assertRaises(VerificationError):
                self.gateway.dispatch_call(
                    model_slug="qwen2.5-coder:7b",
                    model_family="qwen",
                    provider="ollama_local",
                    route_env=expired_public_route,
                    qual_env=quarantined_qual,
                    packet_env=local_packet,
                    budget_env=None,
                    prompt_text="Run security check.",
                    temperature=0.1,
                    max_tokens=256,
                    context_engine=ctx
                )

            # Assert ZERO network calls were made
            mock_post.assert_not_called()

    def test_clean_dispatch_passes_predispatch_verifier(self):
        ctx = self._build_context_engine()

        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"response": "All checks passed clean."},
                raise_for_status=lambda: None
            )

            inv_env, resp = self.gateway.dispatch_call(
                model_slug="qwen2.5-coder:7b",
                model_family="qwen",
                provider="ollama_local",
                route_env=self.valid_local_route,
                qual_env=self.valid_qual,
                packet_env=self.valid_public_packet,
                budget_env=None,
                prompt_text="Run security check.",
                temperature=0.1,
                max_tokens=256,
                context_engine=ctx
            )

            self.assertIsNotNone(inv_env)
            self.assertEqual(resp, "All checks passed clean.")
            mock_post.assert_called_once()

    def test_static_ast_scan_no_raw_requests_outside_gateway(self):
        """
        Static AST Scan: Verifies that no production Python module makes direct un-gatewayed
        requests.post or requests.get calls for model inference outside of ModelGateway.
        """
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        allowed_files = {
            "model_gateway.py",
            "council_api_server.py",  # Server REST listener
            "test_model_gateway_log_guard.py",
            "test_model_egress_choke_point.py",
            "test_dead_letter_and_gateway.py",
            "test_council_api_server.py",
            "test_p2p_gossip_transport.py",
            "p2p_gossip_transport.py"
        }

        violations = []
        for root, _, files in os.walk(repo_dir):
            for file in files:
                if file.endswith(".py") and not file.startswith("test_") and file not in allowed_files:
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    
                    try:
                        tree = ast.parse(content, filename=file)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call):
                                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                                    if node.func.value.id == "requests" and node.func.attr in ["post", "get"]:
                                        violations.append(f"{file}:{node.lineno} calls requests.{node.func.attr}")
                    except Exception:
                        pass

        # Print all violations for migration visibility
        if violations:
            print(f"\n[AST Egress Scan] Found {len(violations)} raw requests calls to migrate:")
            for v in violations:
                print(f"  - {v}")

        # Assert no violations once callers are migrated
        self.assertEqual(len(violations), 0, f"Found un-gatewayed requests calls: {violations}")

if __name__ == "__main__":
    unittest.main()
