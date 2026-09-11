import unittest

from council_verifier import CouncilReceiptVerifier
from task_router import AgentTaskRouteReceipt, AgentTaskRouter


class TestAgentTaskRouter(unittest.TestCase):

    def setUp(self):
        self.router = AgentTaskRouter()

    def test_routes_mutual_credit_safety_to_formal_fuzz_security_and_integrator(self):
        receipt_env = self.router.route_task(
            "Make sure our mutual credit clearinghouse is safe and prove solvency invariants",
            candidate_files=[
                "contracts/PharmacyMutualCredit.sol",
                "test/PharmacyMutualCredit.test.js",
                "test/foundry/TreasurySolvencyInvariant.t.sol",
            ],
        )

        CouncilReceiptVerifier.verify_envelope(receipt_env, AgentTaskRouteReceipt)
        roles = [assignment.role_id for assignment in receipt_env.payload.assignments]

        self.assertIn("FORMAL_PROVER", roles)
        self.assertIn("SOLIDITY_SEMANTICS_REVIEWER", roles)
        self.assertIn("TEST_WRITER", roles)
        self.assertIn("INTEGRATOR", roles)
        self.assertTrue(receipt_env.payload.higher_review_recommended)
        self.assertEqual(receipt_env.payload.final_decision_owner, "HumanOwner")

    def test_routes_external_a2a_without_remote_execution_or_disclosure(self):
        receipt_env = self.router.route_task(
            "Add external A2A Agent Card JSON-RPC adapter with read-only redaction",
            candidate_files=[
                "tools/council/external_a2a_adapter.py",
                "tools/council/test_external_a2a_adapter.py",
                "test/A2AProtocolEngine.test.js",
            ],
            evidence_surfaces=["review-context/ANTIGRAVITY_TO_CODEX_HANDOFF_2026-08-26.md"],
        )

        roles = [assignment.role_id for assignment in receipt_env.payload.assignments]
        self.assertIn("A2A_PROTOCOL_REVIEWER", roles)
        self.assertIn("SECURITY_REVIEWER", roles)
        self.assertIn("TEST_WRITER", roles)

        a2a_assignment = next(
            assignment for assignment in receipt_env.payload.assignments
            if assignment.role_id == "A2A_PROTOCOL_REVIEWER"
        )
        self.assertFalse(a2a_assignment.can_mutate_files)
        self.assertFalse(a2a_assignment.external_disclosure_allowed)
        self.assertIn("Do not grant remote execution authority.", a2a_assignment.non_scope)
        self.assertEqual(receipt_env.payload.risk_tier, "MEDIUM")

    def test_l3_terms_block_mutation_and_assign_human_owner(self):
        receipt_env = self.router.route_task(
            "Commit and push the Solidity CEI refactor for PBMRebateTreasury",
            candidate_files=[
                "contracts/PBMRebateTreasury.sol",
                "test/PBMRebateTreasury.security.test.js",
            ],
        )

        self.assertTrue(receipt_env.payload.human_l3_required)
        self.assertEqual(receipt_env.payload.risk_tier, "L3_HUMAN_REQUIRED")
        self.assertEqual(receipt_env.payload.final_decision_owner, "HumanOwner")

        for assignment in receipt_env.payload.assignments:
            self.assertFalse(assignment.can_mutate_files)
            self.assertIn("human_l3_authorization_required", assignment.escalation_triggers)

    def test_rejects_overbroad_context_flag_without_dropping_route(self):
        files = [f"tools/council/module_{idx}.py" for idx in range(30)]
        receipt_env = self.router.route_task(
            "Debug broad council suite timeout",
            candidate_files=files,
        )

        self.assertTrue(receipt_env.payload.rejected_overbroad_context)
        self.assertGreater(len(receipt_env.payload.assignments), 0)
        for assignment in receipt_env.payload.assignments:
            self.assertLessEqual(len(assignment.scope_files), self.router.MAX_FILES_PER_ASSIGNMENT)


if __name__ == "__main__":
    unittest.main()

