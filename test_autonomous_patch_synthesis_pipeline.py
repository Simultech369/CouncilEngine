"""
Unit tests for Autonomous Patch Synthesis & Dual-Gate Verification Pipeline.
"""

import unittest
from council_contracts import AutonomousPatchSynthesisReceipt
from council_verifier import CouncilReceiptVerifier
from autonomous_patch_synthesis_pipeline import AutonomousPatchSynthesisPipeline

class TestAutonomousPatchSynthesisPipeline(unittest.TestCase):

    def setUp(self):
        self.pipeline = AutonomousPatchSynthesisPipeline()

    def test_identify_cwe_sqli_and_traversal(self):
        vuln_sqli = "def search(cursor, q): cursor.execute(f'SELECT * FROM items WHERE name = {q}')"
        cwe_sqli = self.pipeline.identify_cwe(vuln_sqli)
        self.assertEqual(cwe_sqli, "CWE-89")

        vuln_trav = "def read(path): f = open('../secret/' + path)"
        cwe_trav = self.pipeline.identify_cwe(vuln_trav)
        self.assertEqual(cwe_trav, "CWE-22")

    def test_end_to_end_remediation_sqli(self):
        vuln_code = (
            "def search_products(cursor, category: str, min_price: float):\n"
            "    cursor.execute(f'SELECT id, name FROM products WHERE cat = {category}')\n"
        )
        test_oracle = "assert len(search_products(mock_cursor, 'electronics', 10.0)) >= 0"

        receipt_env, remediated_code = self.pipeline.execute_end_to_end_remediation(
            pipeline_run_id="run_sqli_fix_001",
            target_component="product_repository",
            vulnerable_code=vuln_code,
            test_oracle_code=test_oracle
        )

        CouncilReceiptVerifier.verify_envelope(receipt_env, AutonomousPatchSynthesisReceipt)
        self.assertEqual(receipt_env.payload.vulnerability_cwe_id, "CWE-89")
        self.assertTrue(receipt_env.payload.gate1_ast_passed)
        self.assertTrue(receipt_env.payload.gate2_sandbox_passed)
        self.assertGreaterEqual(receipt_env.payload.patch_integrity_score, 0.95)
        self.assertIn("%s", remediated_code)
        self.assertNotIn("f'SELECT", remediated_code)

    def test_end_to_end_remediation_path_traversal(self):
        vuln_code = (
            "def read_tenant_file(base_dir: str, tenant_id: str, filepath: str):\n"
            "    return open(base_dir + '/' + tenant_id + '/' + filepath).read()\n"
        )
        test_oracle = "assert read_tenant_file('/tmp', 'tenant_1', 'doc.txt') is not None"

        receipt_env, remediated_code = self.pipeline.execute_end_to_end_remediation(
            pipeline_run_id="run_trav_fix_002",
            target_component="tenant_filestore",
            vulnerable_code=vuln_code,
            test_oracle_code=test_oracle
        )

        CouncilReceiptVerifier.verify_envelope(receipt_env, AutonomousPatchSynthesisReceipt)
        self.assertEqual(receipt_env.payload.vulnerability_cwe_id, "CWE-22")
        self.assertTrue(receipt_env.payload.gate1_ast_passed)
        self.assertTrue(receipt_env.payload.gate2_sandbox_passed)
        self.assertIn("os.path.realpath", remediated_code)
        self.assertIn("target_path.startswith(safe_base)", remediated_code)

    def test_prompt_registry_integration(self):
        self.assertTrue(self.pipeline.prompt_registry.has_prompt("council.patch.synthesizer"))

if __name__ == "__main__":
    unittest.main()
