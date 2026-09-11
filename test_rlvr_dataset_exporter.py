import json
import unittest

from rlvr_dataset_exporter import RLVRDatasetExporter, RLVRDatasetExportReceipt
from rlvr_ruler_reward_engine import CouncilRLVRRewardEngine


class TestRLVRDatasetExporter(unittest.TestCase):

    def test_export_jsonl_keeps_only_threshold_passing_trajectories(self):
        reward_engine = CouncilRLVRRewardEngine()
        good = reward_engine.score_verifiable_signals(
            trajectory_id="traj_good",
            objective_id="obj_patch",
            system_prompt="Fix and verify.",
            trajectory_text="Tests passed.",
            checks=[{"name": "tests_passed", "verifier_kind": "TEST_EXIT_CODE", "passed": True}]
        )
        weak = reward_engine.score_verifiable_signals(
            trajectory_id="traj_weak",
            objective_id="obj_patch",
            system_prompt="Fix and verify.",
            trajectory_text="Tests failed.",
            checks=[{"name": "tests_passed", "verifier_kind": "TEST_EXIT_CODE", "passed": False}]
        )

        jsonl_text, receipt_env = RLVRDatasetExporter().export_jsonl(
            reward_receipt_envs=[weak, good],
            messages_by_trajectory_id={
                "traj_good": [{"role": "user", "content": "Fix bug"}, {"role": "assistant", "content": "Done"}],
                "traj_weak": [{"role": "user", "content": "Fix bug"}, {"role": "assistant", "content": "Failed"}],
            },
            min_reward_threshold=0.8
        )

        lines = [json.loads(line) for line in jsonl_text.splitlines()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["reward"], 1.0)
        self.assertEqual(lines[0]["metadata"]["trajectory_id"], "traj_good")
        self.assertIsInstance(receipt_env.payload, RLVRDatasetExportReceipt)
        self.assertEqual(receipt_env.payload.accepted_count, 1)
        self.assertEqual(receipt_env.payload.rejected_count, 1)

    def test_export_jsonl_rejects_missing_messages(self):
        reward_engine = CouncilRLVRRewardEngine()
        reward = reward_engine.score_verifiable_signals(
            trajectory_id="traj_missing_messages",
            objective_id="obj_patch",
            system_prompt="Fix and verify.",
            trajectory_text="Tests passed.",
            checks=[{"name": "tests_passed", "verifier_kind": "TEST_EXIT_CODE", "passed": True}]
        )

        jsonl_text, receipt_env = RLVRDatasetExporter().export_jsonl(
            reward_receipt_envs=[reward],
            messages_by_trajectory_id={},
            min_reward_threshold=0.8
        )

        self.assertEqual(jsonl_text, "")
        self.assertEqual(receipt_env.payload.accepted_count, 0)
        self.assertEqual(receipt_env.payload.rejected_count, 1)


if __name__ == "__main__":
    unittest.main()
