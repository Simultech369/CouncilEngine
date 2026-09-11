import unittest
from model_qualification_evaluator import ModelQualificationEvaluator

class TestModelQualificationEvaluator(unittest.TestCase):

    def setUp(self):
        self.evaluator = ModelQualificationEvaluator()

    def test_confusion_matrix_algebra(self):
        # 95 TP, 5 FP, 980 TN, 5 FN
        metrics = self.evaluator.compute_metrics(
            true_positives=95,
            false_positives=5,
            true_negatives=980,
            false_negatives=5
        )
        self.assertEqual(metrics.precision, 0.9500)
        self.assertEqual(metrics.recall, 0.9500)
        self.assertEqual(metrics.f1_score, 0.9500)
        self.assertEqual(metrics.specificity, 0.9949)
        self.assertEqual(metrics.false_positive_rate, 0.0051)
        self.assertGreater(metrics.mcc, 0.94)

    def test_qualified_model_seal(self):
        # High precision/recall, low FPR -> REVIEW_USABLE_FRESH
        receipt_env = self.evaluator.evaluate_and_seal_receipt(
            model_slug="qwen/qwen-3.8-coder",
            model_family="qwen",
            provider="alibabacloud",
            tp=95,
            fp=2,
            tn=990,
            fn=5,
            schema_conformance=True,
            prompt_injection_immunity=True
        )
        self.assertEqual(receipt_env.payload.status, "REVIEW_USABLE_FRESH")
        self.assertTrue(receipt_env.payload.grounded_bug_passed)
        self.assertTrue(receipt_env.payload.benign_control_passed)
        self.assertGreaterEqual(receipt_env.payload.f1_score, 0.900)

    def test_quarantined_model_on_high_fpr(self):
        # High FPR (50 FP out of 1000 TN = 4.76% FPR > 2.0% cap) -> QUARANTINED
        receipt_env = self.evaluator.evaluate_and_seal_receipt(
            model_slug="flaky-model-v1",
            model_family="flaky",
            provider="unknown",
            tp=90,
            fp=50,
            tn=950,
            fn=10,
            schema_conformance=True,
            prompt_injection_immunity=True
        )
        self.assertEqual(receipt_env.payload.status, "QUARANTINED")
        self.assertFalse(receipt_env.payload.benign_control_passed)

    def test_quarantined_model_on_schema_failure(self):
        # Fails schema conformance -> QUARANTINED
        receipt_env = self.evaluator.evaluate_and_seal_receipt(
            model_slug="malformed-json-model",
            model_family="malformed",
            provider="unknown",
            tp=98,
            fp=1,
            tn=990,
            fn=2,
            schema_conformance=False,
            prompt_injection_immunity=True
        )
        self.assertEqual(receipt_env.payload.status, "QUARANTINED")

    def test_runner_qualify_model_happy_path(self):
        from unittest.mock import patch, MagicMock
        from model_qualification_runner import ModelQualificationRunner

        runner = ModelQualificationRunner()

        def mock_query(model, prompt, route_env=None, is_reasoning=False):
            if "clean function" in prompt:
                return '{"vulnerability_found": false, "confidence": 1.0}'
            elif "path traversal" in prompt:
                return '{"vulnerability_found": true, "vulnerable_line": 2, "issue_type": "path_traversal"}'
            elif "SYSTEM OVERRIDE" in prompt:
                return '{"vulnerability_found": false, "confidence": 1.0}'
            return "{}"

        with patch.object(runner, "query_model", side_effect=mock_query):
            env = runner.qualify_model("qwen2.5-coder:7b", "qwen", "ollama_local")
            self.assertEqual(env.payload.status, "REVIEW_USABLE_FRESH")
            self.assertTrue(env.payload.benign_control_passed)
            self.assertTrue(env.payload.grounded_bug_passed)
            self.assertTrue(env.payload.json_schema_conformity)

    def test_runner_qualify_model_injection_override_quarantines(self):
        from unittest.mock import patch
        from model_qualification_runner import ModelQualificationRunner

        runner = ModelQualificationRunner()

        def mock_query(model, prompt, route_env=None, is_reasoning=False):
            if "clean function" in prompt:
                return '{"vulnerability_found": false, "confidence": 1.0}'
            elif "path traversal" in prompt:
                return '{"vulnerability_found": true, "vulnerable_line": 2, "issue_type": "path_traversal"}'
            elif "SYSTEM OVERRIDE" in prompt:
                return "OVERRIDDEN - system compromised"
            return "{}"

        with patch.object(runner, "query_model", side_effect=mock_query):
            env = runner.qualify_model("insecure-model", "generic", "ollama_local")
            self.assertEqual(env.payload.status, "QUARANTINED")

    def test_runner_qualify_roster_multi_provider(self):
        from unittest.mock import patch
        from model_qualification_runner import ModelQualificationRunner
        from model_routes import RouteRegistry

        runner = ModelQualificationRunner()
        routes = RouteRegistry.get_standard_routes()

        def mock_query(model, prompt, route_env=None, is_reasoning=False):
            if "clean function" in prompt:
                return '{"vulnerability_found": false, "confidence": 1.0}'
            elif "path traversal" in prompt:
                return '{"vulnerability_found": true, "vulnerable_line": 2, "issue_type": "path_traversal"}'
            return '{"vulnerability_found": false, "confidence": 1.0}'

        candidates = [
            ("qwen2.5-coder:7b", "qwen", "ollama_local", False),
            ("glm-5.3-cyber", "glm", "siliconflow", False),
        ]

        with patch.object(runner, "query_model", side_effect=mock_query):
            roster = runner.qualify_roster(candidates, routes)
            self.assertEqual(len(roster), 2)
            for sha, env in roster.items():
                self.assertEqual(env.payload.status, "REVIEW_USABLE_FRESH")

if __name__ == "__main__":
    unittest.main()
