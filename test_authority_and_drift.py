import time
import unittest
from authority_conflict_detector import AuthorityConflictDetector, AuthorityRank
from council_contracts import DriftObservationReceipt

class TestAuthorityAndDrift(unittest.TestCase):

    def setUp(self):
        self.detector = AuthorityConflictDetector()

    def test_live_ast_overrides_memory(self):
        ast_claim = "def add(a, b): return a + b"
        mem_claim = "def add(a, b): return a * b"

        winner, record = self.detector.resolve_conflict(
            claim_a_text=ast_claim,
            claim_a_rank=AuthorityRank.LIVE_AST_OR_CONTRACT, # Rank 1
            claim_b_text=mem_claim,
            claim_b_rank=AuthorityRank.SESSION_MEMORY,       # Rank 5
            drift_category="STALE_MEMORY_PURGE",
            rationale="Live AST file contents reflect real commit state"
        )
        self.assertEqual(winner, ast_claim)
        self.assertEqual(record.winning_rank, 1)
        self.assertEqual(record.losing_rank, 5)
        self.assertEqual(record.drift_category, "STALE_MEMORY_PURGE")

    def test_sandbox_execution_overrides_model_opinion(self):
        exec_claim = "Exit code 0: 10 tests passed"
        opinion_claim = "I suspect this function might fail on edge cases"

        winner, record = self.detector.resolve_conflict(
            claim_a_text=opinion_claim,
            claim_a_rank=AuthorityRank.MODEL_OPINION,        # Rank 7
            claim_b_text=exec_claim,
            claim_b_rank=AuthorityRank.VERIFIED_EXECUTION,   # Rank 2
            drift_category="SECURITY_RELAXATION_PRESSURE",
            rationale="Pytest sandbox execution proves non-failure"
        )
        self.assertEqual(winner, exec_claim)
        self.assertEqual(record.winning_rank, 2)
        self.assertEqual(record.losing_rank, 7)

    def test_drift_velocity_and_tide_alarm(self):
        # Fire 20 rapid overrides to simulate high-frequency drift
        for i in range(20):
            self.detector.resolve_conflict(
                f"Claim AST {i}", 1, f"Claim Memory {i}", 5,
                "SECURITY_RELAXATION_PRESSURE", "Testing drift threshold"
            )

        drift_env = self.detector.compute_drift_observation(window_sec=3600.0)
        self.assertIsInstance(drift_env.payload, DriftObservationReceipt)
        self.assertEqual(drift_env.payload.total_conflicts_resolved, 20)
        self.assertTrue(drift_env.payload.tide_alarm_triggered)
        self.assertIn("SECURITY_RELAXATION_PRESSURE", drift_env.payload.net_drift_vector)

if __name__ == "__main__":
    unittest.main()
