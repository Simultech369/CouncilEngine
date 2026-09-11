"""
Unit tests for Dual-Agent Continuous Handoff & Delta Auditor Daemon.
"""

import unittest
from council_contracts import HandoffBundleReceipt, CONTRACT_VERSION
from council_verifier import CouncilReceiptVerifier
from handoff_reconciliation_daemon import HandoffReconciliationDaemon

class TestHandoffReconciliationDaemon(unittest.TestCase):

    def setUp(self):
        self.daemon = HandoffReconciliationDaemon()

    def test_scan_workspace_state(self):
        state = self.daemon.scan_workspace_state()
        self.assertIn("test_suite_count", state)
        self.assertIn("non_test_file_count", state)
        self.assertGreaterEqual(state["test_suite_count"], 50)
        self.assertGreaterEqual(state["non_test_file_count"], 50)
        self.assertEqual(state["contract_version"], CONTRACT_VERSION)
        self.assertGreaterEqual(state["rule_invariants_count"], 4)

    def test_generate_return_prompt_markdown(self):
        prompt = self.daemon.generate_return_prompt_markdown(
            bundle_id="bundle_test_001",
            baseline_tests=280,
            delta_created=["a2a_protocol_engine.py", "council_subcommittee_engine.py"],
            delta_modified=["FULL_SYSTEM_HANDOFF.md"],
            next_work_slices=["Audit A2A socket convergence", "Scale SWE-bench patch synthesizer"]
        )

        self.assertIn("# Antigravity to Codex Return Handoff (bundle_test_001)", prompt)
        self.assertIn("280 Automated Tests Passing", prompt)
        self.assertIn("`a2a_protocol_engine.py`", prompt)
        self.assertIn("RULE-SEC-004", prompt)
        self.assertIn("Route by capability, not by aspirational name.", prompt)
        self.assertIn("Use the best available model on this surface.", prompt)
        self.assertIn("Treat partial scan excerpts and usage-limit outputs as provisional evidence, not a sealed receipt; refresh live truth before repeating status claims.", prompt)
        self.assertIn("SURFACE_CAPABILITY_ROUTING_SPEC.md", prompt)
        self.assertIn("python -m unittest discover", prompt)

    def test_package_and_seal_bundle(self):
        receipt_env, prompt = self.daemon.package_and_seal_bundle(
            bundle_id="bundle_handoff_codex_001",
            baseline_test_count=280,
            delta_files_created=["handoff_reconciliation_daemon.py"],
            delta_files_modified=["council_contracts.py"],
            next_work_slices=["Review Section 26 HandoffBundleReceipt"]
        )

        CouncilReceiptVerifier.verify_envelope(receipt_env, HandoffBundleReceipt)
        payload = receipt_env.payload
        self.assertEqual(payload.bundle_id, "bundle_handoff_codex_001")
        self.assertEqual(payload.manifest.source_lead_agent, "antigravity")
        self.assertEqual(payload.manifest.target_review_agent, "codex")
        self.assertEqual(payload.manifest.baseline_test_count, 280)
        self.assertTrue(payload.reconciliation_clean)
        self.assertIn("handoff_reconciliation_daemon.py", payload.manifest.delta_files_created)

    def test_rule_sec_004_no_tokens_in_prompt(self):
        _, prompt = self.daemon.package_and_seal_bundle(
            bundle_id="bundle_sec_check_001",
            baseline_test_count=280,
            delta_files_created=[],
            delta_files_modified=[],
            next_work_slices=[]
        )

        forbidden = ["ghp_", "github_pat_", "sk-proj-", "Bearer "]
        for bad in forbidden:
            self.assertNotIn(bad, prompt)

if __name__ == "__main__":
    unittest.main()
