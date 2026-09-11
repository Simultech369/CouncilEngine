import os
import shutil
import tempfile
import unittest
from council_e2e_orchestrator import CouncilE2EOrchestrator, MasterExecutionReceipt
from windows_spend_ledger import WindowsAtomicSpendLedger

class TestCouncilE2EOrchestrator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.previous_state_dir = os.environ.get("COUNCIL_STATE_DIR")
        os.environ["COUNCIL_STATE_DIR"] = self.temp_dir
        self.db_path = os.path.join(self.temp_dir, "test_ledger.db")
        self.ledger = WindowsAtomicSpendLedger(db_path=self.db_path, hard_cap_usd=2.00)
        self.orchestrator = CouncilE2EOrchestrator(ledger=self.ledger)

    def tearDown(self):
        if self.previous_state_dir is None:
            os.environ.pop("COUNCIL_STATE_DIR", None)
        else:
            os.environ["COUNCIL_STATE_DIR"] = self.previous_state_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_execute_e2e_pipeline_success(self):
        source_code = "def process_transaction(amount, fee):\n    return amount - fee"
        patch_diff = """--- a/src/tx.py
+++ b/src/tx.py
@@ -1,2 +1,2 @@
 def process_transaction(amount, fee):
-    return amount - fee
+    return (amount - fee) if amount >= fee else 0
"""
        receipt = self.orchestrator.execute_e2e_pipeline(
            target_module="transaction_service",
            source_code=source_code,
            patch_diff=patch_diff,
            budget_reservation_cents=25
        )

        self.assertIsInstance(receipt, MasterExecutionReceipt)
        self.assertEqual(receipt.target_module, "transaction_service")
        self.assertTrue(receipt.stage_1_preflight_passed)
        self.assertTrue(receipt.stage_2_proof_plan_passed)
        self.assertTrue(receipt.stage_3_rag_grounding_passed)
        self.assertFalse(receipt.stage_4_sandbox_passed)
        self.assertTrue(receipt.stage_5_jury_consensus_passed)
        self.assertTrue(receipt.stage_6_spend_settled_passed)
        self.assertFalse(receipt.overall_pipeline_passed)
        self.assertEqual(receipt.spent_amount_cents, 15)
        self.assertIsNone(receipt.authorization_receipt_sha256)
        self.assertTrue(len(receipt.master_receipt_sha256) == 64)

if __name__ == "__main__":
    unittest.main()
