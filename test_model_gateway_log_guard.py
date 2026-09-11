import unittest
import os
import shutil
import tempfile
import time
from unittest.mock import patch, MagicMock
from model_gateway import ModelGateway
from log_derived_context_engine import LogDerivedContextEngine, LogReconstructionDesyncError
from model_routes import create_route_attestation
from council_verifier import VerificationError
from prompt_config_registry import PromptConfigRegistry
from council_contracts import (
    ModelQualificationReceipt, PacketSensitivityReceipt, ArtifactProvenanceRecord, ReceiptEnvelope
)

class TestModelGatewayLogGuard(unittest.TestCase):

    def setUp(self):
        self.test_state_dir = tempfile.mkdtemp()
        self.previous_state_dir = os.environ.get("COUNCIL_STATE_DIR")
        os.environ["COUNCIL_STATE_DIR"] = self.test_state_dir
        self.gateway = ModelGateway()
        self.route = create_route_attestation(
            route_id="route_ollama_qwen_local",
            provider_name="ollama_local",
            endpoint_url="http://127.0.0.1:11434/api/generate",
            compliance_tier="LOCAL_ONLY_VERIFIED",
            content_retention_days=0,
            zdr_verified=True,
            fallbacks_allowed=False,
            validity_sec=3500
        )

        now = time.time()
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
            evaluated_at=now - 100,
            expires_at=now + 86400
        ))

        art = ArtifactProvenanceRecord(
            artifact_id="art_001",
            artifact_type="REPO_FILE",
            path_or_identifier="src/main.py",
            content_sha256="sha_main_file",
            source_upstream_commit="commit_123",
            source_upstream_url="https://github.com/org/repo",
            provenance_verified=True,
            classification_reason="Public repository verified file"
        )

        self.packet = ReceiptEnvelope.seal(PacketSensitivityReceipt(
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

    def test_clean_dispatch_passes_wire_context_guard(self):
        ctx_engine = LogDerivedContextEngine(session_id="sess_01")
        ctx_engine.append_event("CONFIG_SET", "system", {
            "model_slug": "qwen2.5-coder:7b",
            "provider": "ollama_local",
            "route_id": "route_ollama_qwen_local",
            "temperature": 0.1,
            "max_tokens": 256,
            "provider_parameters": {"seed": 42}
        })
        ctx_engine.append_event("USER_INPUT", "user", {"content": "Analyze repository."})

        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"response": "Analysis complete."},
                raise_for_status=lambda: None
            )

            inv_env, resp = self.gateway.dispatch_call(
                model_slug="qwen2.5-coder:7b",
                model_family="qwen",
                provider="ollama_local",
                route_env=self.route,
                qual_env=self.qual,
                packet_env=self.packet,
                budget_env=None,
                prompt_text="Analyze repository.",
                temperature=0.1,
                max_tokens=256,
                provider_parameters={"seed": 42},
                context_engine=ctx_engine
            )

            self.assertIsNotNone(inv_env)
            self.assertEqual(resp, "Analysis complete.")
            mock_post.assert_called_once()

    def test_invoke_with_resilience_is_primary_dispatch_api(self):
        ctx_engine = LogDerivedContextEngine(session_id="sess_invoke_primary")
        ctx_engine.append_event("CONFIG_SET", "system", {
            "model_slug": "qwen2.5-coder:7b",
            "provider": "ollama_local",
            "route_id": "route_ollama_qwen_local",
            "temperature": 0.1,
            "max_tokens": 256
        })
        ctx_engine.append_event("USER_INPUT", "user", {"content": "Analyze repository."})

        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"response": "Analysis complete."},
                raise_for_status=lambda: None
            )

            inv_env, resp = self.gateway.invoke_with_resilience(
                model_slug="qwen2.5-coder:7b",
                model_family="qwen",
                provider="ollama_local",
                route_env=self.route,
                qual_env=self.qual,
                packet_env=self.packet,
                budget_env=None,
                prompt_text="Analyze repository.",
                temperature=0.1,
                max_tokens=256,
                context_engine=ctx_engine
            )

            self.assertIsNotNone(inv_env)
            self.assertEqual(resp, "Analysis complete.")
            mock_post.assert_called_once()

    def test_route_drift_raises_desync_before_network_call(self):
        ctx_engine = LogDerivedContextEngine(session_id="sess_route_drift")
        ctx_engine.append_event("CONFIG_SET", "system", {
            "model_slug": "qwen2.5-coder:7b",
            "provider": "ollama_local",
            "route_id": "route_ollama_qwen_local",  # Log specifies route_ollama_qwen_local
            "temperature": 0.1,
            "max_tokens": 256
        })
        ctx_engine.append_event("USER_INPUT", "user", {"content": "Analyze repository."})

        drift_route = create_route_attestation(
            route_id="route_siliconflow_glm",  # Drifted route!
            provider_name="siliconflow",
            endpoint_url="https://api.siliconflow.cn/v1/chat/completions",
            compliance_tier="HOSTED_NO_TRAIN",
            content_retention_days=0,
            zdr_verified=True,
            fallbacks_allowed=False,
            validity_sec=3500
        )

        with patch("requests.post") as mock_post:
            with self.assertRaises(LogReconstructionDesyncError):
                self.gateway.dispatch_call(
                    model_slug="qwen2.5-coder:7b",
                    model_family="qwen",
                    provider="siliconflow",
                    route_env=drift_route,
                    qual_env=self.qual,
                    packet_env=self.packet,
                    budget_env=None,
                    prompt_text="Analyze repository.",
                    temperature=0.1,
                    max_tokens=256,
                    context_engine=ctx_engine
                )

            mock_post.assert_not_called()

    def test_missing_context_engine_raises_error(self):
        with self.assertRaises(ValueError):
            self.gateway.dispatch_call(
                model_slug="qwen2.5-coder:7b",
                model_family="qwen",
                provider="ollama_local",
                route_env=self.route,
                qual_env=self.qual,
                packet_env=self.packet,
                budget_env=None,
                prompt_text="Analyze repository.",
                context_engine=None  # Missing mandatory context engine!
            )

    def test_qualification_probe_requires_context_engine(self):
        with self.assertRaises(ValueError):
            self.gateway.dispatch_qualification_probe(
                model_slug="qwen2.5-coder:7b",
                model_family="qwen",
                provider="ollama_local",
                route_env=self.route,
                prompt_text="Analyze repository.",
                context_engine=None
            )

    def test_qualification_probe_desync_blocks_network_call(self):
        ctx_engine = LogDerivedContextEngine(session_id="sess_probe_desync")
        ctx_engine.append_event("CONFIG_SET", "system", {
            "model_slug": "qwen2.5-coder:7b",
            "provider": "ollama_local",
            "route_id": "route_ollama_qwen_local",
            "temperature": 0.1,
            "max_tokens": 128
        })
        ctx_engine.append_event("USER_INPUT", "user", {"content": "Analyze repository."})

        with patch("requests.post") as mock_post:
            with self.assertRaises(LogReconstructionDesyncError):
                self.gateway.dispatch_qualification_probe(
                    model_slug="qwen2.5-coder:7b",
                    model_family="qwen",
                    provider="ollama_local",
                    route_env=self.route,
                    prompt_text="Analyze repository.",
                    temperature=0.1,
                    max_tokens=256,
                    context_engine=ctx_engine
                )

            mock_post.assert_not_called()

    def test_tampered_max_tokens_or_seed_raises_desync_before_network_call(self):
        ctx_engine = LogDerivedContextEngine(session_id="sess_02")
        ctx_engine.append_event("CONFIG_SET", "system", {
            "model_slug": "qwen2.5-coder:7b",
            "provider": "ollama_local",
            "route_id": "route_ollama_qwen_local",
            "temperature": 0.1,
            "max_tokens": 128,
            "provider_parameters": {"seed": 42}
        })
        ctx_engine.append_event("USER_INPUT", "user", {"content": "Analyze repository."})

        with patch("requests.post") as mock_post:
            with self.assertRaises(LogReconstructionDesyncError):
                self.gateway.dispatch_call(
                    model_slug="qwen2.5-coder:7b",
                    model_family="qwen",
                    provider="ollama_local",
                    route_env=self.route,
                    qual_env=self.qual,
                    packet_env=self.packet,
                    budget_env=None,
                    prompt_text="Analyze repository.",
                    temperature=0.1,
                    max_tokens=512,  # Tampered!
                    provider_parameters={"seed": 42},
                    context_engine=ctx_engine
                )

            mock_post.assert_not_called()

    def test_registered_prompt_resolved_and_dispatched_successfully(self):
        registry = PromptConfigRegistry()
        registry.register_prompt_version(
            prompt_id="audit.code",
            version="1.0.0",
            system_prompt="You are a strict security auditor.",
            stage="ACTIVE"
        )
        ctx_engine = LogDerivedContextEngine(session_id="sess_reg_01")
        ctx_engine.append_event("CONFIG_SET", "system", {
            "model_slug": "qwen2.5-coder:7b",
            "provider": "ollama_local",
            "route_id": "route_ollama_qwen_local",
            "temperature": 0.1,
            "max_tokens": 256,
            "system_prompt": "You are a strict security auditor."
        })
        ctx_engine.append_event("USER_INPUT", "user", {"content": "Scan for vulnerabilities."})

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"response": "No vulnerabilities found."}

        with patch("requests.post", return_value=mock_resp) as mock_post:
            inv_env, raw_resp = self.gateway.dispatch_call(
                model_slug="qwen2.5-coder:7b",
                model_family="qwen",
                provider="ollama_local",
                route_env=self.route,
                qual_env=self.qual,
                packet_env=self.packet,
                budget_env=None,
                prompt_text="Scan for vulnerabilities.",
                temperature=0.1,
                max_tokens=256,
                context_engine=ctx_engine,
                prompt_id="audit.code",
                prompt_registry=registry
            )

            mock_post.assert_called_once()
            self.assertIsNotNone(inv_env)
            self.assertEqual(raw_resp, "No vulnerabilities found.")

    def test_registered_prompt_hash_mismatch_raises_verification_error(self):
        registry = PromptConfigRegistry()
        registry.register_prompt_version(
            prompt_id="audit.code",
            version="1.0.0",
            system_prompt="You are a strict security auditor.",
            stage="ACTIVE"
        )
        ctx_engine = LogDerivedContextEngine(session_id="sess_reg_02")

        with patch("requests.post") as mock_post:
            with self.assertRaises(VerificationError):
                self.gateway.dispatch_call(
                    model_slug="qwen2.5-coder:7b",
                    model_family="qwen",
                    provider="ollama_local",
                    route_env=self.route,
                    qual_env=self.qual,
                    packet_env=self.packet,
                    budget_env=None,
                    prompt_text="Scan for vulnerabilities.",
                    system_prompt="Tampered prompt instructions.",
                    temperature=0.1,
                    max_tokens=256,
                    context_engine=ctx_engine,
                    prompt_id="audit.code",
                    prompt_registry=registry
                )

            mock_post.assert_not_called()

    def test_missing_prompt_registry_with_prompt_id_raises_value_error(self):
        ctx_engine = LogDerivedContextEngine(session_id="sess_reg_03")

        with patch("requests.post") as mock_post:
            with self.assertRaises(ValueError):
                self.gateway.dispatch_call(
                    model_slug="qwen2.5-coder:7b",
                    model_family="qwen",
                    provider="ollama_local",
                    route_env=self.route,
                    qual_env=self.qual,
                    packet_env=self.packet,
                    budget_env=None,
                    prompt_text="Scan for vulnerabilities.",
                    context_engine=ctx_engine,
                    prompt_id="unregistered.prompt"
                )

            mock_post.assert_not_called()

if __name__ == "__main__":
    unittest.main()
