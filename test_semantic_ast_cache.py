import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from council_contracts import (
    ArtifactProvenanceRecord,
    ModelQualificationReceipt,
    PacketSensitivityReceipt,
    ReceiptEnvelope,
)
from log_derived_context_engine import LogDerivedContextEngine
from model_gateway import ModelGateway
from model_routes import create_route_attestation
from semantic_ast_cache import SemanticASTCache


class TestSemanticASTCache(unittest.TestCase):

    def setUp(self):
        self.test_state_dir = tempfile.mkdtemp()
        self.previous_state_dir = os.environ.get("COUNCIL_STATE_DIR")
        os.environ["COUNCIL_STATE_DIR"] = self.test_state_dir

    def tearDown(self):
        if self.previous_state_dir is None:
            os.environ.pop("COUNCIL_STATE_DIR", None)
        else:
            os.environ["COUNCIL_STATE_DIR"] = self.previous_state_dir
        shutil.rmtree(self.test_state_dir, ignore_errors=True)

    def test_exact_prompt_hit_returns_cached_response(self):
        cache = SemanticASTCache()
        cache.store(
            model_slug="qwen2.5-coder:7b",
            provider="ollama_local",
            route_id="route_local",
            system_prompt="Review code.",
            prompt_text="def add(a, b): return a + b",
            sensitivity_tier="PUBLIC_SAFE",
            response_text='{"decision":"approve"}'
        )

        hit = cache.lookup(
            model_slug="qwen2.5-coder:7b",
            provider="ollama_local",
            route_id="route_local",
            system_prompt="Review code.",
            prompt_text="def add(a, b): return a + b",
            sensitivity_tier="PUBLIC_SAFE"
        )

        self.assertIsNotNone(hit)
        self.assertEqual(hit.hit_type, "EXACT")
        self.assertEqual(hit.entry.response_text, '{"decision":"approve"}')
        self.assertEqual(hit.entry.hit_count, 1)

    def test_ast_equivalent_prompt_hit_ignores_python_formatting(self):
        cache = SemanticASTCache()
        first_prompt = "Review this:\n```python\ndef add(a, b):\n    return a + b\n```"
        second_prompt = "Review this:\n```python\ndef add(a,b):\n return a+b\n```"

        cache.store(
            model_slug="qwen2.5-coder:7b",
            provider="ollama_local",
            route_id="route_local",
            system_prompt="Review code.",
            prompt_text=first_prompt,
            sensitivity_tier="PUBLIC_SAFE",
            response_text='{"decision":"approve"}'
        )
        hit = cache.lookup(
            model_slug="qwen2.5-coder:7b",
            provider="ollama_local",
            route_id="route_local",
            system_prompt="Review code.",
            prompt_text=second_prompt,
            sensitivity_tier="PUBLIC_SAFE"
        )

        self.assertIsNotNone(hit)
        self.assertEqual(hit.hit_type, "AST_SEMANTIC")
        self.assertEqual(hit.similarity_score, 1.0)

    def test_private_sensitivity_is_not_cached_by_default(self):
        cache = SemanticASTCache()
        stored = cache.store(
            model_slug="qwen2.5-coder:7b",
            provider="ollama_local",
            route_id="route_local",
            system_prompt="Review private code.",
            prompt_text="secret = True",
            sensitivity_tier="LOCAL_ONLY_REQUIRED",
            response_text="private response"
        )
        hit = cache.lookup(
            model_slug="qwen2.5-coder:7b",
            provider="ollama_local",
            route_id="route_local",
            system_prompt="Review private code.",
            prompt_text="secret = True",
            sensitivity_tier="LOCAL_ONLY_REQUIRED"
        )

        self.assertIsNone(stored)
        self.assertIsNone(hit)

    def test_persistent_storage_round_trip(self):
        cache_path = os.path.join(self.test_state_dir, "semantic_cache.json")
        cache = SemanticASTCache(storage_path=cache_path)
        cache.store(
            model_slug="qwen2.5-coder:7b",
            provider="ollama_local",
            route_id="route_local",
            system_prompt="Review code.",
            prompt_text="def add(a, b): return a + b",
            sensitivity_tier="PUBLIC_SAFE",
            response_text="cached"
        )

        reloaded = SemanticASTCache(storage_path=cache_path)
        hit = reloaded.lookup(
            model_slug="qwen2.5-coder:7b",
            provider="ollama_local",
            route_id="route_local",
            system_prompt="Review code.",
            prompt_text="def add(a, b): return a + b",
            sensitivity_tier="PUBLIC_SAFE"
        )

        self.assertIsNotNone(hit)
        self.assertEqual(hit.entry.response_text, "cached")

    def test_model_gateway_uses_cache_before_second_network_call(self):
        cache = SemanticASTCache()
        gateway = ModelGateway(semantic_cache=cache)
        route = create_route_attestation(
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
        qual = ReceiptEnvelope.seal(ModelQualificationReceipt(
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
        packet = ReceiptEnvelope.seal(PacketSensitivityReceipt(
            snapshot_composite_state_sha256="state_001",
            sensitivity_tier="PUBLIC_SAFE",
            public_safe_verified=True,
            private_artifact_count=0,
            artifacts=[ArtifactProvenanceRecord(
                artifact_id="art_001",
                artifact_type="REPO_FILE",
                path_or_identifier="src/main.py",
                content_sha256="sha_main",
                source_upstream_commit="commit_123",
                source_upstream_url="https://github.com/org/repo",
                provenance_verified=True,
                classification_reason="Public repository source file"
            )]
        ))

        def build_context():
            ctx = LogDerivedContextEngine(session_id=f"sess_cache_{time.time()}")
            ctx.append_event("CONFIG_SET", "system", {
                "model_slug": "qwen2.5-coder:7b",
                "provider": "ollama_local",
                "route_id": "route_ollama_qwen_local",
                "temperature": 0.1,
                "max_tokens": 256
            })
            ctx.append_event("USER_INPUT", "user", {"content": "Run security check."})
            return ctx

        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"response": "All checks passed clean."},
                raise_for_status=lambda: None
            )
            first_env, first_resp = gateway.dispatch_call(
                model_slug="qwen2.5-coder:7b",
                model_family="qwen",
                provider="ollama_local",
                route_env=route,
                qual_env=qual,
                packet_env=packet,
                budget_env=None,
                prompt_text="Run security check.",
                temperature=0.1,
                max_tokens=256,
                context_engine=build_context()
            )
            second_env, second_resp = gateway.dispatch_call(
                model_slug="qwen2.5-coder:7b",
                model_family="qwen",
                provider="ollama_local",
                route_env=route,
                qual_env=qual,
                packet_env=packet,
                budget_env=None,
                prompt_text="Run security check.",
                temperature=0.1,
                max_tokens=256,
                context_engine=build_context()
            )

        self.assertIsNotNone(first_env)
        self.assertIsNotNone(second_env)
        self.assertEqual(first_resp, "All checks passed clean.")
        self.assertEqual(second_resp, "All checks passed clean.")
        mock_post.assert_called_once()


if __name__ == "__main__":
    unittest.main()
