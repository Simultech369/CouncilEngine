import json
import socket
import subprocess
from unittest.mock import patch
import unittest

from rlvr_ruler_reward_engine import CouncilRLVRRewardEngine
from sovereign_swebench_batch_runner import (
    SovereignSWEBenchBatchRunner,
    SovereignSWEBenchTask,
    StaticSubcommitteeReviewer,
)


class CapturingRewardEngine(CouncilRLVRRewardEngine):
    def __init__(self):
        self.calls = []
        self.receipts = []

    def score_verifiable_signals(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        env = super().score_verifiable_signals(*args, **kwargs)
        self.receipts.append(env)
        return env


class CapturingStaticSubcommitteeReviewer(StaticSubcommitteeReviewer):
    def __init__(self):
        self.calls = []
        self.receipts = []

    def convene_subcommittees_and_seal(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        env = super().convene_subcommittees_and_seal(*args, **kwargs)
        self.receipts.append(env)
        return env


class TestSovereignSWEBenchBatchRunner(unittest.TestCase):

    def setUp(self):
        self.runner = SovereignSWEBenchBatchRunner()
        self.original_code = (
            "def add(a, b):\n"
            "    return a - b\n"
        )

    def _clean_task(self, task_id="task_clean"):
        return SovereignSWEBenchTask(
            task_id=task_id,
            source_label="mock_swe_bench_lite",
            target_file="src/calc.py",
            original_code=self.original_code,
            search_block="return a - b",
            replace_block="return a + b",
            objective="Fix add() so it returns the sum of its inputs.",
        )

    def test_clean_task_is_accepted_and_sealed(self):
        env = self.runner.run_batch([self._clean_task()], batch_id="batch_clean")

        self.assertEqual(env.receipt_type, "SovereignSWEBenchBatchReceipt")
        self.assertEqual(env.payload.total_tasks, 1)
        self.assertEqual(env.payload.static_accept_count, 1)
        self.assertEqual(env.payload.rejected_count, 0)
        self.assertEqual(env.payload.manual_triage_count, 0)
        self.assertTrue(env.payload.local_only)
        self.assertFalse(env.payload.network_calls_permitted)
        self.assertFalse(env.payload.model_invocation_permitted)
        self.assertFalse(env.payload.patch_application_permitted)
        self.assertFalse(env.payload.target_repo_mutation_permitted)
        self.assertFalse(env.payload.production_authority)
        self.assertFalse(env.payload.tests_executed)
        self.assertEqual(env.payload.authority_scope, "STATIC_REHEARSAL_ONLY")
        self.assertEqual(env.payload.reward_signal_mode, "STATIC_REHEARSAL_SIGNALS_ONLY")

        result = env.payload.results[0]
        self.assertEqual(result.outcome, "STATIC_REHEARSAL_ACCEPTED")
        self.assertEqual(result.rejection_reasons, [])
        self.assertTrue(result.ast_valid)
        self.assertTrue(result.static_guardrails_held)
        self.assertFalse(result.tests_executed)
        self.assertFalse(result.model_invoked)
        self.assertFalse(result.target_repo_mutated)
        self.assertFalse(result.production_authority)
        self.assertEqual(result.execution_evidence_status, "NOT_EXECUTED_STATIC_REHEARSAL")
        self.assertGreaterEqual(result.static_rehearsal_score, 0.8)
        self.assertIsNotNone(result.patch_payload_sha256)
        self.assertIsNotNone(result.subcommittee_payload_sha256)
        self.assertIsNotNone(result.reward_payload_sha256)

    def test_missing_search_block_rejects_without_patch_or_reward(self):
        task = self._clean_task("task_missing_search")
        task = task.model_copy(update={"search_block": "return does_not_exist"})

        env = self.runner.run_batch([task], batch_id="batch_missing")
        result = env.payload.results[0]

        self.assertEqual(env.payload.rejected_count, 1)
        self.assertEqual(result.outcome, "REJECTED")
        self.assertIn("SEARCH_BLOCK_NOT_FOUND", result.rejection_reasons)
        self.assertIsNone(result.patch_payload_sha256)
        self.assertIsNone(result.reward_payload_sha256)
        self.assertFalse(result.tests_executed)
        self.assertFalse(result.production_authority)

    def test_suspicious_patch_is_manual_triage_not_accepted(self):
        task = self._clean_task("task_suspicious")
        task = task.model_copy(update={
            "replace_block": "assert True\n    with open('../forbidden.txt', 'r') as f:\n        pass\n    return a + b"
        })

        env = self.runner.run_batch([task], batch_id="batch_suspicious")
        result = env.payload.results[0]

        self.assertEqual(env.payload.static_accept_count, 0)
        self.assertEqual(env.payload.manual_triage_count, 1)
        self.assertEqual(result.outcome, "MANUAL_TRIAGE")
        self.assertIn("PATCH_INTEGRITY_BELOW_THRESHOLD", result.rejection_reasons)
        self.assertTrue(any("CWE-22" in reason for reason in result.rejection_reasons))
        self.assertTrue(any("assert True" in reason for reason in result.rejection_reasons))
        self.assertTrue(result.ast_valid)
        self.assertLess(result.static_rehearsal_score, 0.8)

    def test_receipt_does_not_store_raw_code(self):
        task = self._clean_task("task_no_raw_code")
        env = self.runner.run_batch([task], batch_id="batch_no_raw_code")
        payload_json = json.dumps(env.payload.model_dump(), sort_keys=True)

        self.assertNotIn("return a - b", payload_json)
        self.assertNotIn("return a + b", payload_json)
        self.assertNotIn(task.target_file, payload_json)
        self.assertEqual(len(env.payload.input_manifest_sha256), 64)

    def test_static_rehearsal_does_not_fabricate_execution_signals(self):
        env = self.runner.run_batch([self._clean_task()], batch_id="batch_static_only")
        payload_json = json.dumps(env.payload.model_dump(), sort_keys=True)

        self.assertNotIn("tests_passed", payload_json)
        self.assertIn("static_ast_parse_valid", payload_json)
        self.assertIn("static_rehearsal_boundary_bound", payload_json)
        self.assertIn("NOT_EXECUTED_STATIC_REHEARSAL", payload_json)

    def test_sensitive_metadata_is_hashed_not_stored_verbatim(self):
        sensitive_values = [
            "issue-gho_" + ("a" * 48),
            "issue-ghp_" + ("b" * 48),
            "issue-ghs_" + ("c" * 48),
            "issue-ghu_" + ("d" * 48),
            "issue-github_pat_" + ("e" * 64),
            "issue-sk-proj-" + ("f" * 64),
            "src/calc.py\nreturn a + b",
        ]

        for index, sensitive_value in enumerate(sensitive_values):
            with self.subTest(sensitive_value=sensitive_value[:16]):
                task = self._clean_task(sensitive_value)
                task = task.model_copy(update={"target_file": sensitive_value})

                env = self.runner.run_batch(
                    [task],
                    batch_id=sensitive_value,
                    builder_model_slug=sensitive_value,
                    breaker_model_slug=sensitive_value,
                )
                payload_json = json.dumps(env.payload.model_dump(), sort_keys=True)
                result = env.payload.results[0]

                self.assertNotIn(sensitive_value, payload_json)
                self.assertNotIn("gho_", payload_json)
                self.assertNotIn("ghp_", payload_json)
                self.assertNotIn("ghs_", payload_json)
                self.assertNotIn("ghu_", payload_json)
                self.assertNotIn("github_pat_", payload_json)
                self.assertNotIn("sk-proj-", payload_json)
                self.assertNotIn("return a + b", payload_json)
                self.assertTrue(result.task_ref.startswith("task_id_sha256:"))
                self.assertTrue(result.target_file_ref.startswith("target_file_sha256:"))
                self.assertTrue(env.payload.batch_ref.startswith("batch_id_sha256:"))
                self.assertTrue(env.payload.builder_model_ref.startswith("builder_model_sha256:"))
                self.assertTrue(env.payload.breaker_model_ref.startswith("breaker_model_sha256:"))
                self.assertEqual(len(result.task_id_sha256), 64)
                self.assertEqual(len(result.target_file_sha256), 64)

    def test_child_reward_receipt_does_not_store_raw_metadata_ids(self):
        reward_engine = CapturingRewardEngine()
        runner = SovereignSWEBenchBatchRunner(reward_engine=reward_engine)
        sensitive_id = "issue-gho_" + ("a" * 48)
        sensitive_batch = "batch-gho_" + ("b" * 48)
        task = self._clean_task(sensitive_id)

        env = runner.run_batch([task], batch_id=sensitive_batch)
        reward_json = json.dumps(reward_engine.receipts[0].payload.model_dump(), sort_keys=True)

        self.assertEqual(len(reward_engine.calls), 1)
        self.assertEqual(env.payload.results[0].reward_payload_sha256, reward_engine.receipts[0].payload_sha256)
        self.assertNotIn(sensitive_id, reward_json)
        self.assertNotIn(sensitive_batch, reward_json)
        self.assertNotIn("gho_", reward_json)
        self.assertIn("static_rehearsal:", reward_engine.calls[0]["kwargs"]["trajectory_id"])
        self.assertNotIn(sensitive_id, reward_engine.calls[0]["kwargs"]["trajectory_id"])

    def test_child_subcommittee_receipt_does_not_store_raw_metadata_ids(self):
        reviewer = CapturingStaticSubcommitteeReviewer()
        runner = SovereignSWEBenchBatchRunner(subcommittee_engine=reviewer)
        sensitive_id = "issue-gho_" + ("a" * 48)
        sensitive_batch = "batch-ghp_" + ("b" * 48)
        task = self._clean_task(sensitive_id)

        env = runner.run_batch([task], batch_id=sensitive_batch)
        subcommittee_json = json.dumps(reviewer.receipts[0].payload.model_dump(), sort_keys=True)
        evaluation = reviewer.receipts[0].payload.evaluations[0]

        self.assertEqual(len(reviewer.calls), 1)
        self.assertEqual(env.payload.results[0].subcommittee_payload_sha256, reviewer.receipts[0].payload_sha256)
        self.assertNotIn(sensitive_id, subcommittee_json)
        self.assertNotIn(sensitive_batch, subcommittee_json)
        self.assertNotIn("gho_", subcommittee_json)
        self.assertNotIn("ghp_", subcommittee_json)
        self.assertEqual(evaluation.assigned_model_slug, "static_reviewer_no_model_invoked")
        self.assertIn("NO_MODEL_INVOCATION", evaluation.invariants_checked)
        self.assertTrue(reviewer.calls[0]["kwargs"]["task_id"].startswith("task:"))
        self.assertNotIn(sensitive_id, reviewer.calls[0]["kwargs"]["task_id"])

    def test_child_static_receipts_deny_execution_authority(self):
        reward_engine = CapturingRewardEngine()
        reviewer = CapturingStaticSubcommitteeReviewer()
        runner = SovereignSWEBenchBatchRunner(
            reward_engine=reward_engine,
            subcommittee_engine=reviewer,
        )

        env = runner.run_batch([self._clean_task()], batch_id="batch_child_authority")
        reward_json = json.dumps(reward_engine.receipts[0].payload.model_dump(), sort_keys=True)
        subcommittee_json = json.dumps(reviewer.receipts[0].payload.model_dump(), sort_keys=True)
        result = env.payload.results[0]

        self.assertFalse(result.tests_executed)
        self.assertFalse(result.model_invoked)
        self.assertFalse(result.target_repo_mutated)
        self.assertFalse(result.production_authority)
        self.assertNotIn("TEST_EXIT_CODE", reward_json)
        self.assertNotIn("tests_passed", reward_json)
        self.assertIn("static_rehearsal_boundary_bound", reward_json)
        self.assertIn("NO_PATCH_APPLICATION", subcommittee_json)
        self.assertIn("NO_NETWORK_CALL", subcommittee_json)

    def test_default_runner_avoids_gateway_persistence_process_and_socket_side_effects(self):
        with patch("os.makedirs", side_effect=AssertionError("unexpected persistence directory")), \
             patch.object(socket, "socket", side_effect=AssertionError("unexpected socket creation")), \
             patch.object(subprocess, "run", side_effect=AssertionError("unexpected subprocess launch")):
            runner = SovereignSWEBenchBatchRunner()
            env = runner.run_batch([self._clean_task()], batch_id="batch_no_persistence")

        self.assertEqual(env.payload.results[0].outcome, "STATIC_REHEARSAL_ACCEPTED")


if __name__ == "__main__":
    unittest.main()
