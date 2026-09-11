import shutil
import tempfile
import unittest
from dead_letter_queue import DeadLetterQueue
from dspy_self_healing_optimizer import DSPySelfHealingOptimizer

class TestDSPySelfHealingOptimizer(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.dlq = DeadLetterQueue(storage_dir=self.test_dir)
        self.optimizer = DSPySelfHealingOptimizer(dlq=self.dlq)

        # Populate sample dead letters
        self.dlq.record_failure(
            model_slug="qwen/qwen-3.8-coder",
            failure_category="SCHEMA_VIOLATION",
            error_message="Missing required field 'patch_sha256' in proposal JSON",
            raw_prompt="Generate patch for auth.py",
            raw_response="{'unified_diff': '...'}"
        )
        self.dlq.record_failure(
            model_slug="deepseek/deepseek-v4-moe",
            failure_category="PROMPT_INJECTION_DETECTED",
            error_message="Detected instruction override probe 'IGNORE PREVIOUS INSTRUCTIONS'",
            raw_prompt="System test with injection payload",
            raw_response="I will now ignore instructions..."
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_mine_training_demonstrations(self):
        demos = self.optimizer.mine_training_demonstrations(category="SCHEMA_VIOLATION", max_examples=5)
        self.assertEqual(len(demos), 1)
        self.assertEqual(demos[0]["failure_category"], "SCHEMA_VIOLATION")
        self.assertIn("patch_sha256", demos[0]["error_rule"])

    def test_compile_optimized_prompt(self):
        base_prompt = "You are a secure coding model adhering to strict council invariants."
        candidate = self.optimizer.compile_optimized_prompt(
            target_model_slug="qwen/qwen-3.8-coder",
            failure_category="SCHEMA_VIOLATION",
            base_system_prompt=base_prompt,
            max_demonstrations=2
        )
        self.assertEqual(candidate.mined_dead_letters_count, 1)
        self.assertIn("SELF-HEALING FEW-SHOT GUARDRAILS", candidate.system_prompt_compiled)
        self.assertIn("Missing required field 'patch_sha256'", candidate.system_prompt_compiled)
        self.assertTrue(len(candidate.candidate_sha256) == 64)

    def test_benchmark_and_qualify_candidate(self):
        candidate = self.optimizer.compile_optimized_prompt(
            target_model_slug="qwen/qwen-3.8-coder",
            failure_category="SCHEMA_VIOLATION",
            base_system_prompt="Base prompt",
            max_demonstrations=1
        )
        receipt_env = self.optimizer.benchmark_and_qualify_candidate(
            candidate=candidate,
            simulated_tp=96,
            simulated_fp=1,
            simulated_tn=992,
            simulated_fn=4
        )
        payload = receipt_env.payload
        self.assertEqual(payload.status, "REVIEW_USABLE_FRESH")
        self.assertGreaterEqual(payload.f1_score, 0.900)
        self.assertGreaterEqual(payload.precision_score, 0.950)
        self.assertGreaterEqual(payload.recall_score, 0.950)
        self.assertTrue(payload.benign_control_passed)
        self.assertTrue(payload.grounded_bug_passed)

if __name__ == "__main__":
    unittest.main()
