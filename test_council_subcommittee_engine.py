"""
Unit tests for Council Subcommittee & OSS Model Rotation Engine.
"""

import unittest
from council_contracts import SubcommitteeConvocationReceipt
from council_verifier import CouncilReceiptVerifier
from council_subcommittee_engine import CouncilSubcommitteeEngine

class TestCouncilSubcommitteeEngine(unittest.TestCase):

    def setUp(self):
        self.engine = CouncilSubcommitteeEngine()

    def test_subcommittee_prompts_registered(self):
        reg = self.engine.prompt_registry
        self.assertTrue(reg.has_prompt("council.subcommittee.secops"))
        self.assertTrue(reg.has_prompt("council.subcommittee.consensus"))
        self.assertTrue(reg.has_prompt("council.subcommittee.integrity"))
        self.assertTrue(reg.has_prompt("council.subcommittee.audit"))

    def test_model_rotation_deterministic(self):
        # Round 1
        m0_r1 = self.engine.get_rotated_model_for_subcommittee(0, rotation_round=1)
        m1_r1 = self.engine.get_rotated_model_for_subcommittee(1, rotation_round=1)
        self.assertEqual(m0_r1, "qwen2.5-coder:7b")
        self.assertEqual(m1_r1, "glm4:latest")

        # Round 2 rotation shift
        m0_r2 = self.engine.get_rotated_model_for_subcommittee(0, rotation_round=2)
        self.assertEqual(m0_r2, "glm4:latest")

    def test_subcommittee_convocation_clean_proposal(self):
        clean_proposal = {
            "task": "add_audit_hook",
            "code": "def process_claim(cid: str) -> bool: return len(cid) > 0"
        }
        receipt_env = self.engine.convene_subcommittees_and_seal(
            convocation_id="convoc_001",
            task_id="task_audit_hook_01",
            proposal=clean_proposal,
            rotation_round=1
        )

        CouncilReceiptVerifier.verify_envelope(receipt_env, SubcommitteeConvocationReceipt)
        self.assertEqual(receipt_env.payload.overall_verdict, "UNANIMOUS_APPROVAL")
        self.assertTrue(receipt_env.payload.guardrails_held)
        self.assertEqual(len(receipt_env.payload.evaluations), 4)

    def test_subcommittee_convocation_secops_token_veto(self):
        leaked_token_proposal = {
            "task": "connect_github",
            "code": "GITHUB_TOKEN = 'ghp_secretTokenHere1234567890'\ndef sync(): pass"
        }
        receipt_env = self.engine.convene_subcommittees_and_seal(
            convocation_id="convoc_002",
            task_id="task_token_leak",
            proposal=leaked_token_proposal,
            rotation_round=2
        )

        self.assertEqual(receipt_env.payload.overall_verdict, "VETOED")
        self.assertFalse(receipt_env.payload.guardrails_held)
        secops_eval = next(e for e in receipt_env.payload.evaluations if e.subcommittee_name == "SecOps")
        self.assertEqual(secops_eval.verdict, "REJECT")
        self.assertIn("Token leak", secops_eval.findings_summary)

    def test_subcommittee_convocation_code_integrity_cwe_veto(self):
        sqli_proposal = {
            "task": "query_user",
            "code": "def fetch(cursor, uid): cursor.execute(f'SELECT * FROM users WHERE id = {uid}')"
        }
        receipt_env = self.engine.convene_subcommittees_and_seal(
            convocation_id="convoc_003",
            task_id="task_sqli",
            proposal=sqli_proposal,
            rotation_round=3
        )

        self.assertEqual(receipt_env.payload.overall_verdict, "VETOED")
        self.assertFalse(receipt_env.payload.guardrails_held)
        integrity_eval = next(e for e in receipt_env.payload.evaluations if e.subcommittee_name == "CodeIntegrity")
        self.assertEqual(integrity_eval.verdict, "REJECT")

if __name__ == "__main__":
    unittest.main()
