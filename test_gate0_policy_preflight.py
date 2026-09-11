import unittest
import os
from vision_policy_miner import VisionPolicyMiner
from gate0_policy_preflight import Gate0PolicyPreflight
from council_contracts import Gate0PreflightReceipt
from human_approval import HMACApprovalAuthenticator, DenyAllApprovalAuthenticator

class TestGate0PolicyPreflight(unittest.TestCase):

    def setUp(self):
        workspace_root = os.path.dirname(os.path.abspath(__file__))
        miner = VisionPolicyMiner(workspace_root)
        _, self.policy_receipt = miner.compile_vision_constitution()
        
        self.authenticator = HMACApprovalAuthenticator()
        self.authenticator.register_key("key_operator_001", "super_secret_operator_key_999")
        
        self.valid_approval = HMACApprovalAuthenticator.create_signed_approval(
            subject_type="VISION_POLICY",
            subject_payload_sha256=self.policy_receipt.payload_sha256,
            approver_identity="alice_security_lead",
            approver_key_id="key_operator_001",
            secret_key="super_secret_operator_key_999",
            validity_sec=3600
        )

        self.preflight = Gate0PolicyPreflight(
            vision_policy_receipt=self.policy_receipt,
            approval_receipt=self.valid_approval,
            authenticator=self.authenticator
        )

    def test_clean_proposal_passes_preflight(self):
        clean_diff = """
+from council_contracts import ReceiptEnvelope
+def execute_safe_check():
+    return ReceiptEnvelope.seal(True)
"""
        receipt_env = self.preflight.evaluate_proposal("PROP_001", "transaction_engine", clean_diff)
        receipt = receipt_env.payload
        self.assertIsInstance(receipt, Gate0PreflightReceipt)
        self.assertTrue(receipt.passed_preflight)
        self.assertEqual(len(receipt.rejection_reasons), 0)
        self.assertIn("Principle #2: Cryptographic Lineage Enforcement", receipt.matched_principles)

    def test_unauthenticated_or_forged_approval_rejected(self):
        forged_approval = HMACApprovalAuthenticator.create_signed_approval(
            subject_type="VISION_POLICY",
            subject_payload_sha256=self.policy_receipt.payload_sha256,
            approver_identity="forger",
            approver_key_id="key_operator_001",
            secret_key="wrong_forged_key",
            validity_sec=3600
        )
        with self.assertRaises(ValueError):
            Gate0PolicyPreflight(
                vision_policy_receipt=self.policy_receipt,
                approval_receipt=forged_approval,
                authenticator=self.authenticator
            )

    def test_taboo_llm_statistical_anomaly_rejected(self):
        bad_diff = """
+def scan_claims_for_anomalies(claims_table):
+    prompt = f"Identify outlier anomaly patterns in {claims_table}"
+    return llm_detect(prompt)
"""
        receipt_env = self.preflight.evaluate_proposal("PROP_002", "fwa_fraud_detector", bad_diff)
        receipt = receipt_env.payload
        self.assertFalse(receipt.passed_preflight)
        self.assertIn("Violation of Non-Goal #1: Cannot use language models/prompts for raw numerical anomaly or risk detection; use deterministic statistics (ECOD/Mahalanobis).", receipt.rejection_reasons)

    def test_semantic_variant_llm_risk_pattern_rejected(self):
        bad_diff_variant = """
+def check_pharmacy_claims(claims_batch):
+    res = language_model.predict_risk("find suspicious payment risk patterns in batch")
+    return res
"""
        receipt_env = self.preflight.evaluate_proposal("PROP_003", "pbm_claims_auditor", bad_diff_variant)
        receipt = receipt_env.payload
        self.assertFalse(receipt.passed_preflight)
        self.assertIn("NO LLM Statistical Anomaly Detection", receipt.matched_non_goals)

    def test_taboo_insecure_sandbox_bypass_rejected(self):
        bad_diff = """
+def run_eval():
+    return execute_command(cmd, --insecure=True, skip_sandbox=True)
"""
        receipt_env = self.preflight.evaluate_proposal("PROP_004", "ci_cd_workflow", bad_diff)
        receipt = receipt_env.payload
        self.assertFalse(receipt.passed_preflight)
        self.assertIn("Violation of Non-Goal #2: Insecure bypass or sandbox disabling detected.", receipt.rejection_reasons)

if __name__ == "__main__":
    unittest.main()
