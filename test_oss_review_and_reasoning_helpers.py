import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from oss_review_detailed import get_critique
from oss_review_planning import query_oss_reviewer
from probe_reasoning_extraction import query_reasoning_scout


class TestOSSReviewAndReasoningHelpers(unittest.TestCase):

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

    def test_planning_reviewer_strips_think_and_fenced_json(self):
        raw = (
            "<think>private reasoning</think>\n"
            "```json\n"
            "{"
            "\"reviewer_model\":\"qwen2.5-coder:7b\","
            "\"verdict\":\"APPROVE_WITH_RESERVATIONS\","
            "\"top_strengths\":[\"receipts\"],"
            "\"critical_blindspots\":[\"stream backpressure\"],"
            "\"actionable_recommendations\":[\"add SSE tests\"]"
            "}\n"
            "```"
        )
        with patch("oss_review_planning.ModelGateway.dispatch_qualification_probe", return_value=(None, raw)) as mock_dispatch:
            result = query_oss_reviewer("qwen2.5-coder:7b", "Architecture", "streaming")

        self.assertEqual(result["reviewer_model"], "qwen2.5-coder:7b")
        self.assertEqual(result["verdict"], "APPROVE_WITH_RESERVATIONS")
        self.assertEqual(result["critical_blindspots"], ["stream backpressure"])
        kwargs = mock_dispatch.call_args.kwargs
        self.assertEqual(kwargs["provider"], "ollama_local")
        self.assertEqual(kwargs["route_env"].payload.route_id, "route_oss_review_planning_local")

    def test_detailed_reviewer_parses_json_and_tags_reviewer(self):
        raw = (
            "{"
            "\"verdict\":\"APPROVE\","
            "\"key_strength\":\"deterministic receipts\","
            "\"identified_risk\":\"stale route inventory\","
            "\"concrete_recommendation\":\"refresh before dispatch\""
            "}"
        )
        with patch("oss_review_detailed.ModelGateway.dispatch_qualification_probe", return_value=(None, raw)):
            result = get_critique("glm4:latest", "Security")

        self.assertEqual(result["reviewer"], "glm4:latest")
        self.assertEqual(result["verdict"], "APPROVE")
        self.assertEqual(result["identified_risk"], "stale route inventory")

    def test_reasoning_probe_extracts_thinking_trace_and_json_payload(self):
        raw = (
            "<think>check line two for interpolation</think>\n"
            "{\"vulnerability_found\": true, \"vulnerable_line\": 2, \"cwe\": \"CWE-89\"}"
        )
        with patch("probe_reasoning_extraction.ModelGateway.dispatch_qualification_probe", return_value=(None, raw)):
            result = query_reasoning_scout("deepseek-r1:1.5b", "audit sql")

        self.assertGreater(result["thinking_trace_len"], 0)
        self.assertEqual(result["parsed_json"]["vulnerable_line"], 2)
        self.assertEqual(result["parsed_json"]["cwe"], "CWE-89")


if __name__ == "__main__":
    unittest.main()
