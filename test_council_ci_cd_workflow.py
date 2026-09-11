import os
import unittest
from vision_policy_miner import VisionPolicyMiner
from council_ci_cd_workflow import CouncilCICDWorkflow, CICDEvaluationResult
from human_approval import HMACApprovalAuthenticator

class TestCouncilCICDWorkflow(unittest.TestCase):

    def setUp(self):
        workspace_root = os.path.dirname(os.path.abspath(__file__))
        miner = VisionPolicyMiner(workspace_root)
        _, self.policy_env = miner.compile_vision_constitution()
        
        self.authenticator = HMACApprovalAuthenticator()
        self.authenticator.register_key("key_operator_001", "operator_secret_123")
        
        self.approval_env = HMACApprovalAuthenticator.create_signed_approval(
            subject_type="VISION_POLICY",
            subject_payload_sha256=self.policy_env.payload_sha256,
            approver_identity="alice_lead",
            approver_key_id="key_operator_001",
            secret_key="operator_secret_123",
            validity_sec=3600
        )

        self.workflow = CouncilCICDWorkflow(
            policy_receipt_env=self.policy_env,
            policy_approval_env=self.approval_env,
            authenticator=self.authenticator
        )

    def test_generate_github_workflow_yaml(self):
        yaml_str = self.workflow.generate_github_workflow_yaml()
        self.assertIn("name: Council Admissibility & Verification Gate", yaml_str)
        self.assertIn("actions/checkout@v4", yaml_str)
        self.assertIn("pydantic==2.10.6", yaml_str)
        self.assertIn("test_gate0_policy_preflight.py", yaml_str)
        self.assertIn("test_bounty_vulnerability_engine.py", yaml_str)
        self.assertIn("test_pbm_rebate_engine.py", yaml_str)
        self.assertIn("test_rag_evidence_engine.py", yaml_str)
        self.assertIn("test_docker_sandbox_daemon.py", yaml_str)
        self.assertIn("test_full_integrated_pipeline.py", yaml_str)

    def test_evaluate_pr_pipeline_with_live_stage_receipts(self):
        stage_receipts = [
            {"step_id": "step_ast", "name": "AST CWE Sanitizer", "status": "PASSED", "duration_sec": 0.1, "exit_code": 0},
            {"step_id": "step_pbm", "name": "Decimal Math & HIPAA Tokenizer", "status": "PASSED", "duration_sec": 0.1, "exit_code": 0},
            {"step_id": "step_rag", "name": "Two-Stage RAG & Citation Grounding", "status": "PASSED", "duration_sec": 0.1, "exit_code": 0},
            {"step_id": "step_sandbox", "name": "Zero-Network Docker Sandbox", "status": "PASSED", "duration_sec": 0.1, "exit_code": 0},
            {"step_id": "step_council", "name": "Multi-Family Council Quorum", "status": "PASSED", "duration_sec": 0.1, "exit_code": 0},
        ]
        eval_res = self.workflow.evaluate_pr_pipeline(
            pr_number=101,
            branch_name="feature/secure-auth",
            touched_files=["src/auth.py", "tests/test_auth.py"],
            candidate_diff="+from council_contracts import ReceiptEnvelope\n+def check(): return True",
            stage_execution_receipts=stage_receipts
        )
        self.assertIsInstance(eval_res, CICDEvaluationResult)
        self.assertEqual(eval_res.pr_number, 101)
        self.assertEqual(eval_res.branch_name, "feature/secure-auth")
        self.assertEqual(eval_res.total_steps, 6)
        self.assertEqual(eval_res.passed_steps, 6)
        self.assertTrue(eval_res.all_passed)
        self.assertIsNotNone(eval_res.gate0_receipt_sha256)
        self.assertIn("Autonomous Council Verification Gate — PR #101", eval_res.pr_comment_markdown)
        self.assertIn("PASSED (ALL GATES CLEAN)", eval_res.pr_comment_markdown)

    def test_dry_run_without_live_receipts_marks_stages_not_run(self):
        eval_res = self.workflow.evaluate_pr_pipeline(
            pr_number=103,
            branch_name="feature/unexecuted-pr",
            touched_files=["src/utils.py"],
            candidate_diff="+from council_contracts import ReceiptEnvelope\n+def test(): pass"
        )
        self.assertFalse(eval_res.all_passed)
        self.assertEqual(eval_res.passed_steps, 1)  # Only Gate 0 passed
        self.assertIn("AWAITING_EXECUTION_EVIDENCE", eval_res.pr_comment_markdown)

    def test_evaluate_pr_pipeline_rejected_at_gate0(self):
        eval_res = self.workflow.evaluate_pr_pipeline(
            pr_number=102,
            branch_name="feature/llm-fraud-scan",
            touched_files=["pbm_fraud_detector.py"],
            candidate_diff="+def scan(): prompt = 'find anomaly'; return language_model(prompt)"
        )
        self.assertFalse(eval_res.all_passed)
        self.assertIsNone(eval_res.authorization_receipt_sha256)
        self.assertIn("REJECTED AT GATE 0 (POLICY CONSTITUTION VIOLATION)", eval_res.pr_comment_markdown)

if __name__ == "__main__":
    unittest.main()
