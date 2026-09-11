import unittest
import os
from vision_policy_miner import VisionPolicyMiner
from council_contracts import VisionPolicyReceipt

class TestVisionPolicyMiner(unittest.TestCase):

    def setUp(self):
        self.workspace_root = os.path.dirname(os.path.abspath(__file__))
        self.miner = VisionPolicyMiner(self.workspace_root)

    def test_mine_repository_evidence(self):
        evidence = self.miner.mine_repository_evidence()
        self.assertGreaterEqual(evidence["test_suites_count"], 30)
        self.assertGreaterEqual(evidence["blueprints_count"], 10)
        self.assertIn("council_contracts.py", evidence["core_contracts"])

    def test_generate_fault_line_hypotheticals(self):
        hypos = self.miner.generate_fault_line_hypotheticals()
        self.assertEqual(len(hypos), 8)
        self.assertTrue(all(h.proposing_argument and h.opposing_argument for h in hypos))
        self.assertTrue(all(h.policy_verdict in ["ACCEPTED", "REJECTED"] for h in hypos))

    def test_compile_vision_constitution_candidate_draft_default(self):
        vision_md, receipt_env = self.miner.compile_vision_constitution(human_approved=False)
        self.assertIn("Status:** `CANDIDATE_DRAFT`", vision_md)
        self.assertFalse(receipt_env.payload.human_approved)
        self.assertIsNone(receipt_env.payload.author_signature)

    def test_compile_vision_constitution_approved(self):
        vision_md, receipt_env = self.miner.compile_vision_constitution(
            human_approved=True,
            author_signature="Architect_Lead_Signoff"
        )
        self.assertIn("# Autonomous Council Engine: Testable Acceptance Constitution", vision_md)
        self.assertIn("Status:** `APPROVED`", vision_md)
        self.assertIn("Deterministic checks decide admissibility", vision_md)
        self.assertIn("NO LLM Statistical Anomaly Detection", vision_md)

        receipt = receipt_env.payload
        self.assertIsInstance(receipt, VisionPolicyReceipt)
        self.assertTrue(receipt.human_approved)
        self.assertEqual(receipt.author_signature, "Architect_Lead_Signoff")
        self.assertEqual(receipt.total_principles_mined, 5)
        self.assertEqual(receipt.total_non_goals_mined, 4)
        self.assertEqual(receipt.fault_line_hypotheticals_count, 8)

if __name__ == "__main__":
    unittest.main()
