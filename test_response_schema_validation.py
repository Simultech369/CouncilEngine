"""
Comprehensive Unit Tests for ResponseSchemaValidator & ResponseSchemaValidationReceipt.
Enforces fail-closed structured outputs and validation of every model response.
"""

import unittest
import json
import hashlib
from unittest.mock import patch, MagicMock

from council_contracts import (
    ReceiptEnvelope,
    RouteAttestationReceipt,
    ModelQualificationReceipt,
    PacketSensitivityReceipt,
    ResponseSchemaValidationReceipt,
)
from log_derived_context_engine import LogDerivedContextEngine
from model_gateway import (
    ModelGateway,
    ResponseSchemaValidator,
    ResponseSchemaViolationError,
)


class TestResponseSchemaValidator(unittest.TestCase):
    def setUp(self):
        self.model_slug = "qwen2.5-coder:7b"
        self.route_id = "route_local_test"

    def test_valid_json_no_schema_passes(self):
        raw = json.dumps({"status": "ok", "confidence": 0.95})
        fmt = {"type": "json_object"}
        receipt, parsed = ResponseSchemaValidator.validate(
            raw_response=raw,
            response_format=fmt,
            model_slug=self.model_slug,
            route_id=self.route_id,
        )
        self.assertTrue(receipt.validation_passed)
        self.assertTrue(receipt.is_valid_json)
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(receipt.invocation_model_slug, self.model_slug)
        self.assertEqual(receipt.invocation_route_id, self.route_id)

    def test_invalid_json_fails_closed(self):
        raw = "Error: Internal server hallucination. Not JSON."
        fmt = {"type": "json_object"}
        with self.assertRaises(ResponseSchemaViolationError) as cm:
            ResponseSchemaValidator.validate(
                raw_response=raw,
                response_format=fmt,
                model_slug=self.model_slug,
                route_id=self.route_id,
            )
        self.assertIn("not valid JSON", str(cm.exception))

    def test_json_primitive_or_array_fails_closed(self):
        raw = json.dumps(["an", "array", "not", "an", "object"])
        fmt = {"type": "json_object"}
        with self.assertRaises(ResponseSchemaViolationError) as cm:
            ResponseSchemaValidator.validate(
                raw_response=raw,
                response_format=fmt,
                model_slug=self.model_slug,
                route_id=self.route_id,
            )
        self.assertIn("not an object", str(cm.exception))

    def test_required_fields_all_present(self):
        raw = json.dumps({"decision": "APPROVE", "reason": "No reentrancy detected"})
        fmt = {
            "type": "json_object",
            "schema": {
                "required_fields": ["decision", "reason"],
                "field_types": {"decision": "str", "reason": "str"},
            },
        }
        receipt, parsed = ResponseSchemaValidator.validate(
            raw_response=raw,
            response_format=fmt,
            model_slug=self.model_slug,
            route_id=self.route_id,
        )
        self.assertTrue(receipt.validation_passed)
        self.assertTrue(receipt.required_fields_present)
        self.assertEqual(receipt.missing_fields, [])
        self.assertEqual(parsed["decision"], "APPROVE")

    def test_required_fields_missing_fails_closed(self):
        raw = json.dumps({"decision": "APPROVE"})
        fmt = {
            "type": "json_object",
            "schema": {
                "required_fields": ["decision", "reason"],
                "field_types": {"decision": "str", "reason": "str"},
            },
        }
        with self.assertRaises(ResponseSchemaViolationError) as cm:
            ResponseSchemaValidator.validate(
                raw_response=raw,
                response_format=fmt,
                model_slug=self.model_slug,
                route_id=self.route_id,
            )
        self.assertIn("Missing required fields", str(cm.exception))

    def test_type_mismatch_fails_closed(self):
        raw = json.dumps({
            "decision": "APPROVE",
            "reason": "Clear",
            "risk_score": "LOW"  # should be int or number
        })
        fmt = {
            "type": "json_object",
            "schema": {
                "required_fields": ["decision", "reason", "risk_score"],
                "field_types": {
                    "decision": "str",
                    "reason": "str",
                    "risk_score": "number",
                },
            },
        }
        with self.assertRaises(ResponseSchemaViolationError) as cm:
            ResponseSchemaValidator.validate(
                raw_response=raw,
                response_format=fmt,
                model_slug=self.model_slug,
                route_id=self.route_id,
            )
        self.assertIn("Type mismatches", str(cm.exception))

    def test_extra_fields_reject_policy(self):
        raw = json.dumps({
            "decision": "APPROVE",
            "reason": "Clear",
            "unauthorized_injection": "bypass_gate"
        })
        fmt = {
            "type": "json_object",
            "schema": {
                "required_fields": ["decision", "reason"],
                "field_types": {"decision": "str", "reason": "str"},
                "extra_fields_policy": "REJECT",
            },
        }
        with self.assertRaises(ResponseSchemaViolationError) as cm:
            ResponseSchemaValidator.validate(
                raw_response=raw,
                response_format=fmt,
                model_slug=self.model_slug,
                route_id=self.route_id,
            )
        self.assertIn("Rejected extra fields", str(cm.exception))

    def test_extra_fields_allow_policy(self):
        raw = json.dumps({
            "decision": "APPROVE",
            "reason": "Clear",
            "metadata_debug": "extra info"
        })
        fmt = {
            "type": "json_object",
            "schema": {
                "required_fields": ["decision", "reason"],
                "field_types": {"decision": "str", "reason": "str"},
                "extra_fields_policy": "ALLOW",
            },
        }
        receipt, parsed = ResponseSchemaValidator.validate(
            raw_response=raw,
            response_format=fmt,
            model_slug=self.model_slug,
            route_id=self.route_id,
        )
        self.assertTrue(receipt.validation_passed)
        self.assertIn("metadata_debug", receipt.extra_fields)
        self.assertEqual(parsed["metadata_debug"], "extra info")


import time
from model_routes import create_route_attestation
from council_contracts import ArtifactProvenanceRecord


class TestModelGatewaySchemaEnforcement(unittest.TestCase):
    def setUp(self):
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

    def _build_context(self, prompt: str, resp_fmt: dict) -> LogDerivedContextEngine:
        ctx = LogDerivedContextEngine(session_id="sess_schema_enforce")
        ctx.append_event("CONFIG_SET", "system", {
            "model_slug": "qwen2.5-coder:7b",
            "provider": "ollama_local",
            "route_id": "route_ollama_qwen_local",
            "temperature": 0.1,
            "max_tokens": 256,
            "response_format": resp_fmt,
        })
        ctx.append_event("USER_INPUT", "user", {"content": prompt})
        return ctx

    def test_gateway_enforces_schema_and_seals_receipt(self):
        prompt = "Evaluate reentrancy."
        resp_fmt = {
            "type": "json_object",
            "schema": {
                "required_fields": ["reentrancy_risk", "reason"],
                "field_types": {"reentrancy_risk": "bool", "reason": "str"},
            },
        }
        ctx = self._build_context(prompt, resp_fmt)

        valid_resp_json = json.dumps({"reentrancy_risk": False, "reason": "Pure getter"})

        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"response": valid_resp_json},
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
                prompt_text=prompt,
                temperature=0.1,
                max_tokens=256,
                response_format=resp_fmt,
                context_engine=ctx,
            )

            self.assertIsNotNone(inv_env)
            self.assertEqual(resp, valid_resp_json)
            # Verify sealed validation receipt was created and stored
            self.assertIsNotNone(self.gateway.last_validation_receipt)
            self.assertTrue(self.gateway.last_validation_receipt.payload.validation_passed)
            self.assertTrue(self.gateway.last_validation_receipt.payload.required_fields_present)

    def test_gateway_fails_closed_and_records_dlq_on_violation(self):
        prompt = "Evaluate reentrancy."
        resp_fmt = {
            "type": "json_object",
            "schema": {
                "required_fields": ["reentrancy_risk", "reason"],
                "field_types": {"reentrancy_risk": "bool", "reason": "str"},
            },
        }
        ctx = self._build_context(prompt, resp_fmt)

        # Mock model returning invalid structure (missing "reason", reentrancy_risk is string)
        bad_resp_json = json.dumps({"reentrancy_risk": "NOT_A_BOOL"})

        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"response": bad_resp_json},
                raise_for_status=lambda: None
            )

            with self.assertRaises(ResponseSchemaViolationError):
                self.gateway.invoke_with_resilience(
                    model_slug="qwen2.5-coder:7b",
                    model_family="qwen",
                    provider="ollama_local",
                    route_env=self.route,
                    qual_env=self.qual,
                    packet_env=self.packet,
                    budget_env=None,
                    prompt_text=prompt,
                    temperature=0.1,
                    max_tokens=256,
                    response_format=resp_fmt,
                    context_engine=ctx,
                )

            # Assert failure recorded in DLQ
            dead_letters = self.gateway.dlq.list_dead_letters()
            self.assertGreater(len(dead_letters), 0)
            last_dlq = dead_letters[-1]
            self.assertEqual(last_dlq.source_model_slug, "qwen2.5-coder:7b")
            self.assertEqual(last_dlq.failure_category, "SCHEMA_VIOLATION")


if __name__ == "__main__":
    unittest.main()
