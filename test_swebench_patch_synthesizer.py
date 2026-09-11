import unittest
from swebench_patch_synthesizer import SWEBenchPatchSynthesizer

class TestSWEBenchPatchSynthesizer(unittest.TestCase):

    def setUp(self):
        self.synthesizer = SWEBenchPatchSynthesizer()
        self.sample_code = """
def calculate_discount(price, is_member):
    if is_member:
        return price * 0.90
    return price
"""

    def test_reproduction_harness_generation(self):
        harness = self.synthesizer.generate_reproduction_harness(
            issue_id="ISSUE_101",
            target_module="pricing",
            failing_function="calculate_discount",
            expected_output="90.0",
            input_args="100.0, True"
        )
        self.assertIn("TestIssueReproduction_ISSUE_101", harness.fail_to_pass_test_code)
        self.assertIn("TestBaselineRegression_ISSUE_101", harness.pass_to_pass_regression_code)
        self.assertTrue(len(harness.test_sha256) == 64)

    def test_search_replace_hunk_application(self):
        search_block = "return price * 0.90"
        replace_block = "return price * 0.85"

        ok, patched = self.synthesizer.apply_search_replace_block(self.sample_code, search_block, replace_block)
        self.assertTrue(ok)
        self.assertIn("0.85", patched)
        self.assertNotIn("0.90", patched)

    def test_patch_integrity_score_clean_patch(self):
        clean_patch = """
def calculate_discount(price, is_member):
    if is_member:
        return price * 0.85
    return price
"""
        res = self.synthesizer.evaluate_patch_integrity("src/pricing.py", self.sample_code, clean_patch)
        self.assertTrue(res.ast_valid)
        self.assertEqual(res.patch_integrity_score, 1.0)
        self.assertEqual(len(res.cwe_violations), 0)
        self.assertEqual(len(res.anti_patterns_detected), 0)

    def test_patch_integrity_score_penalizes_anti_patterns(self):
        # Patch includes 'assert True' and path traversal
        malicious_patch = """
def calculate_discount(price, is_member):
    assert True
    with open('../forbidden.txt', 'r') as f:
        pass
    return price
"""
        res = self.synthesizer.evaluate_patch_integrity("src/pricing.py", self.sample_code, malicious_patch)
        self.assertLess(res.patch_integrity_score, 0.95)
        self.assertIn("CWE-22: Path Traversal sequence detected", res.cwe_violations)
        self.assertTrue(any("assert True" in ap for ap in res.anti_patterns_detected))

if __name__ == "__main__":
    unittest.main()
