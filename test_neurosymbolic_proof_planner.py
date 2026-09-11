import unittest
from neurosymbolic_proof_planner import NeuroSymbolicProofPlanner, JointProgramAndProofPlan

class TestNeuroSymbolicProofPlanner(unittest.TestCase):

    def setUp(self):
        self.planner = NeuroSymbolicProofPlanner()

    def test_synthesize_joint_plan(self):
        plan = self.planner.synthesize_joint_plan(
            target_module="pricing",
            function_name="calculate_total",
            input_variables=["base_price", "tax", "shipping"],
            invariants=[
                {"name": "non_negativity", "type": "bound"},
                {"name": "sum_monotonicity", "type": "ordering"}
            ]
        )
        self.assertIsInstance(plan, JointProgramAndProofPlan)
        self.assertTrue(plan.proof_verified)
        self.assertEqual(len(plan.smt_clauses), 2)
        self.assertIn("def calculate_total", plan.synthesized_code)
        self.assertTrue(len(plan.proof_sha256) == 64)

    def test_verify_smt_clause_monotonicity_valid(self):
        # Valid non-overlapping, strictly increasing tiers: [min, max, rate]
        valid_tiers = [
            (0.0, 100.0, 0.05),
            (100.0, 500.0, 0.10),
            (500.0, 1000.0, 0.15)
        ]
        ok, err = self.planner.verify_smt_clause_monotonicity(valid_tiers)
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_verify_smt_clause_monotonicity_overlapping(self):
        # Overlapping tiers: Tier 1 goes up to 150, but Tier 2 starts at 100
        overlapping_tiers = [
            (0.0, 150.0, 0.05),
            (100.0, 500.0, 0.10)
        ]
        ok, err = self.planner.verify_smt_clause_monotonicity(overlapping_tiers)
        self.assertFalse(ok)
        self.assertIn("Overlapping tier boundary", err)

    def test_verify_smt_clause_monotonicity_non_monotonic_rate(self):
        # Non-monotonic rebate rate drop: Tier 1 rate is 0.15, but Tier 2 rate is 0.10
        non_monotonic_tiers = [
            (0.0, 100.0, 0.15),
            (100.0, 500.0, 0.10)
        ]
        ok, err = self.planner.verify_smt_clause_monotonicity(non_monotonic_tiers)
        self.assertFalse(ok)
        self.assertIn("Non-monotonic rebate rate drop", err)

if __name__ == "__main__":
    unittest.main()
