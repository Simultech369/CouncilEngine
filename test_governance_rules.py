import unittest
import os
from governance_rules import (
    load_formal_rules,
    save_formal_rules,
    load_working_practices,
    FormalGovernanceEngine,
    record_working_practice,
    get_complete_invariants_and_practices_context,
    INITIAL_FORMAL_RULES,
    INITIAL_WORKING_PRACTICES
)

class TestGovernanceRulesEngine(unittest.TestCase):
    def setUp(self):
        import copy
        save_formal_rules(copy.deepcopy(INITIAL_FORMAL_RULES))

    def test_formal_rules_loaded(self):
        rules = load_formal_rules()
        self.assertIn("RULE-SEC-001", rules)
        self.assertEqual(rules["RULE-SEC-001"]["status"], "ACTIVE")
        self.assertEqual(rules["RULE-SEC-001"]["version"], 1)

    def test_working_practices_loaded(self):
        practices = load_working_practices()
        self.assertIn("PRAC-FE-001", practices)
        self.assertIn("guideline", practices["PRAC-FE-001"])

    def test_rule_amendment_lifecycle_supermajority(self):
        # 1. Propose re-evaluation
        proposal = FormalGovernanceEngine.propose_reevaluation(
            rule_id="RULE-MON-001",
            proposed_action="AMEND",
            justification="Updated to support dynamic 2-digit bps fractional remainder tracking",
            proposer="subcouncil_c_lead",
            new_statement="Collaborator royalty splits must sum to exactly 10,000 basis points (100.00%) with automated deterministic remainder redistribution."
        )
        self.assertEqual(proposal["status"], "PROPOSED_FOR_COUNCIL_VOTE")

        # 2. Council votes with 3/3 approvals (100% supermajority)
        council_votes = [
            {"model_slug": "qwen2.5-coder:7b", "decision": "approve"},
            {"model_slug": "glm4:latest", "decision": "approve"},
            {"model_slug": "mistral:latest", "decision": "approve"}
        ]

        result = FormalGovernanceEngine.evaluate_and_seal_amendment(
            proposal_id=proposal["proposal_id"],
            rule_id="RULE-MON-001",
            proposed_action="AMEND",
            new_statement=proposal.get("new_statement") or "Updated rule statement",
            justification="Updated to support dynamic 2-digit bps fractional remainder tracking",
            council_votes=council_votes
        )

        self.assertEqual(result["verdict"], "AMENDMENT_PASSED_AND_SEALED")
        self.assertTrue(result["supermajority_met"])
        self.assertEqual(result["new_version"], 2)

        # Verify updated rule in ledger
        rules = load_formal_rules()
        self.assertEqual(rules["RULE-MON-001"]["version"], 2)
        self.assertEqual(len(rules["RULE-MON-001"]["history"]), 1)
        self.assertIn("deterministic remainder", rules["RULE-MON-001"]["statement"])

    def test_rule_amendment_rejected_below_supermajority(self):
        proposal = FormalGovernanceEngine.propose_reevaluation(
            rule_id="RULE-SEC-001",
            proposed_action="DEPRECATE",
            justification="Disable timing safe checks (unsafe proposal)",
            proposer="rogue_agent"
        )

        # Council votes with 1 approve, 2 reject (33.3% < 67%)
        council_votes = [
            {"model_slug": "qwen2.5-coder:7b", "decision": "reject"},
            {"model_slug": "glm4:latest", "decision": "reject"},
            {"model_slug": "mistral:latest", "decision": "approve"}
        ]

        result = FormalGovernanceEngine.evaluate_and_seal_amendment(
            proposal_id=proposal["proposal_id"],
            rule_id="RULE-SEC-001",
            proposed_action="DEPRECATE",
            new_statement=None,
            justification="Disable timing safe checks",
            council_votes=council_votes
        )

        self.assertEqual(result["verdict"], "AMENDMENT_REJECTED_REVERTED_TO_ACTIVE")
        self.assertFalse(result["supermajority_met"])

        # Verify rule remains active at version 1
        rules = load_formal_rules()
        self.assertEqual(rules["RULE-SEC-001"]["status"], "ACTIVE")
        self.assertEqual(rules["RULE-SEC-001"]["version"], 1)

    def test_prompt_context_segregation(self):
        context = get_complete_invariants_and_practices_context()
        self.assertIn("SECTION I: FORMAL GOVERNANCE RULES", context)
        self.assertIn("SECTION II: WORKING BEST PRACTICES", context)
        self.assertIn("RULE-SEC-001", context)
        self.assertIn("PRAC-FE-001", context)

if __name__ == "__main__":
    unittest.main()
