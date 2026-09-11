import unittest
from heterogeneous_jury_engine import HeterogeneousJuryEngine, JuryJurorVote, HeterogeneousJuryReceipt

class TestHeterogeneousJuryEngine(unittest.TestCase):

    def setUp(self):
        self.engine = HeterogeneousJuryEngine()

    def test_heterogeneous_consensus_approval(self):
        votes = [
            JuryJurorVote(juror_id="j1", model_family="ANTHROPIC", vote="APPROVE", confidence_score=0.95, rationale="Clean AST"),
            JuryJurorVote(juror_id="j2", model_family="OPENAI", vote="APPROVE", confidence_score=0.92, rationale="Passes tests"),
            JuryJurorVote(juror_id="j3", model_family="QWEN", vote="APPROVE", confidence_score=0.90, rationale="No regressions")
        ]
        receipt = self.engine.evaluate_jury_deliberation("case_101", votes)
        self.assertIsInstance(receipt, HeterogeneousJuryReceipt)
        self.assertEqual(receipt.distinct_families_count, 3)
        self.assertEqual(receipt.consensus_decision, "APPROVED_CONSENSUS")
        self.assertGreater(receipt.beta_binomial_stability, 0.70)
        self.assertTrue(len(receipt.receipt_sha256) == 64)

    def test_dissenting_proof_override(self):
        # 3 approvals, but 1 rejection with a verified SMT counterexample
        votes = [
            JuryJurorVote(juror_id="j1", model_family="ANTHROPIC", vote="APPROVE", confidence_score=0.95, rationale="Looks good"),
            JuryJurorVote(juror_id="j2", model_family="OPENAI", vote="APPROVE", confidence_score=0.90, rationale="Looks good"),
            JuryJurorVote(juror_id="j3", model_family="DEEPSEEK", vote="APPROVE", confidence_score=0.92, rationale="Looks good"),
            JuryJurorVote(
                juror_id="j4_scout",
                model_family="LOCAL_OSS",
                vote="REJECT",
                confidence_score=0.99,
                rationale="Found SMT invariant tier overlap counterexample",
                formal_counterexample_sha256="ce_sha_smt_violation_proven"
            )
        ]
        receipt = self.engine.evaluate_jury_deliberation("case_102", votes)
        self.assertEqual(receipt.consensus_decision, "DISSENTING_PROOF_OVERRIDE")
        self.assertEqual(receipt.echo_chamber_risk_score, 0.0)

    def test_hung_jury_single_family(self):
        # Monolithic jury of 3 models from the SAME family (echo chamber risk)
        votes = [
            JuryJurorVote(juror_id="j1", model_family="ANTHROPIC", vote="APPROVE", confidence_score=0.95, rationale="OK"),
            JuryJurorVote(juror_id="j2", model_family="ANTHROPIC", vote="APPROVE", confidence_score=0.95, rationale="OK"),
            JuryJurorVote(juror_id="j3", model_family="ANTHROPIC", vote="APPROVE", confidence_score=0.95, rationale="OK")
        ]
        receipt = self.engine.evaluate_jury_deliberation("case_103", votes)
        self.assertEqual(receipt.distinct_families_count, 1)
        self.assertEqual(receipt.consensus_decision, "HUNG_JURY")
        self.assertEqual(receipt.echo_chamber_risk_score, 1.0)

if __name__ == "__main__":
    unittest.main()
