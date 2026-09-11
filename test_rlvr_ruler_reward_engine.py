import unittest

from council_contracts import ReceiptEnvelope
from rlvr_ruler_reward_engine import (
    CouncilRLVRRewardEngine,
    CouncilRULERRewardEngine,
    TrajectoryRewardReceipt,
)


class TestRLVRRULERRewardEngine(unittest.TestCase):

    def test_rlvr_weighted_reward_emits_scalar_receipt(self):
        engine = CouncilRLVRRewardEngine()

        receipt_env = engine.score_verifiable_signals(
            trajectory_id="traj_patch_001",
            objective_id="obj_fix_tests",
            system_prompt="Fix the bug and keep the patch minimal.",
            trajectory_text="Ran tests, patched parser, reran tests.",
            checks=[
                {"name": "tests_passed", "verifier_kind": "TEST_EXIT_CODE", "passed": True, "weight": 2.0},
                {"name": "ast_valid", "verifier_kind": "AST_PARSE", "passed": True, "weight": 1.0},
                {"name": "receipt_valid", "verifier_kind": "RECEIPT_VALIDATION", "passed": False, "weight": 1.0},
            ]
        )

        self.assertIsInstance(receipt_env, ReceiptEnvelope)
        self.assertIsInstance(receipt_env.payload, TrajectoryRewardReceipt)
        self.assertEqual(receipt_env.payload.reward_mode, "RLVR")
        self.assertEqual(receipt_env.payload.scalar_reward, 0.75)
        self.assertEqual(len(receipt_env.payload.signals), 3)

    def test_execution_reward_convenience_uses_verifiable_checks(self):
        engine = CouncilRLVRRewardEngine()

        receipt_env = engine.score_from_execution(
            trajectory_id="traj_failed_tests",
            objective_id="obj_verify",
            system_prompt="Produce a verifiable patch.",
            trajectory_text="Patch compiled but tests failed.",
            test_exit_code=1,
            ast_valid=True,
            receipt_valid=True
        )

        self.assertEqual(receipt_env.payload.scalar_reward, 0.5)
        self.assertEqual(receipt_env.payload.signals[0].signal_name, "tests_passed")
        self.assertFalse(receipt_env.payload.signals[0].passed)

    def test_ruler_relative_rankings_produce_group_rewards(self):
        engine = CouncilRULERRewardEngine()
        trajectories = {
            "traj_a": "Answer is complete but verbose.",
            "traj_b": "Answer is complete and concise.",
            "traj_c": "Answer misses the main question.",
        }

        receipts = engine.score_relative_rankings(
            objective_id="obj_support_reply",
            system_prompt="Resolve the user support question accurately and concisely.",
            trajectories_by_id=trajectories,
            ranked_trajectory_ids=["traj_b", "traj_a", "traj_c"],
            judge_model_slug="judge/local-test",
            judge_rationale="traj_b best, traj_c incomplete"
        )
        by_id = {env.payload.trajectory_id: env.payload for env in receipts}

        self.assertEqual(len(receipts), 3)
        self.assertEqual(by_id["traj_b"].scalar_reward, 1.0)
        self.assertEqual(by_id["traj_a"].scalar_reward, 0.5)
        self.assertEqual(by_id["traj_c"].scalar_reward, 0.0)
        self.assertGreater(by_id["traj_b"].normalized_group_reward, by_id["traj_a"].normalized_group_reward)
        self.assertEqual(by_id["traj_b"].rank_in_group, 1)
        self.assertEqual(by_id["traj_b"].group_size, 3)

    def test_ruler_judge_scores_must_cover_exact_group(self):
        engine = CouncilRULERRewardEngine()

        with self.assertRaises(ValueError) as ctx:
            engine.score_judged_group(
                objective_id="obj_rag",
                system_prompt="Answer with citations.",
                trajectories_by_id={"traj_a": "good", "traj_b": "bad"},
                judge_scores_by_trajectory_id={"traj_a": 1.0},
                judge_model_slug="judge/local-test"
            )
        self.assertIn("cover exactly", str(ctx.exception))

    def test_rlvr_rejects_invalid_check_weight(self):
        engine = CouncilRLVRRewardEngine()

        with self.assertRaises(ValueError) as ctx:
            engine.score_verifiable_signals(
                trajectory_id="traj_bad_weight",
                objective_id="obj_bad",
                system_prompt="Verify.",
                trajectory_text="No-op.",
                checks=[{"name": "bad", "passed": True, "weight": 0.0}]
            )
        self.assertIn("weight must be positive", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
