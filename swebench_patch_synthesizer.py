import ast
import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import ImmutableContract

class ReproductionTestHarness(ImmutableContract):
    test_id: str
    target_module: str
    fail_to_pass_test_code: str
    pass_to_pass_regression_code: str
    test_sha256: str

class PatchSynthesisResult(ImmutableContract):
    patch_id: str
    target_file: str
    unified_diff: str
    patch_sha256: str
    ast_valid: bool
    patch_integrity_score: float
    cwe_violations: List[str]
    anti_patterns_detected: List[str]

class SWEBenchPatchSynthesizer:
    """
    Automated SWE-bench and GitHub Issue Bounty Patch Synthesizer:
    - Generates FAIL_TO_PASS reproduction harnesses.
    - Synthesizes search/replace unified diffs.
    - Computes Patch Integrity Score (PIS >= 0.95).
    """

    ANTI_PATTERNS = [
        (re.compile(r"assert\s+True", re.IGNORECASE), "Bypass Anti-Pattern: Tautological 'assert True' detected"),
        (re.compile(r"@pytest\.mark\.skip"), "Bypass Anti-Pattern: Test skip decorator '@pytest.mark.skip' injected"),
        (re.compile(r"unittest\.skip"), "Bypass Anti-Pattern: Test skip decorator 'unittest.skip' injected"),
        (re.compile(r"#\s*noqa"), "Suppression Anti-Pattern: '# noqa' linter suppression injected")
    ]

    def generate_reproduction_harness(
        self,
        issue_id: str,
        target_module: str,
        failing_function: str,
        expected_output: str,
        input_args: str
    ) -> ReproductionTestHarness:
        """Generates deterministic FAIL_TO_PASS and PASS_TO_PASS tests."""
        f2p_code = f"""
import unittest
from {target_module} import {failing_function}

class TestIssueReproduction_{issue_id}(unittest.TestCase):
    def test_reproduce_bug(self):
        result = {failing_function}({input_args})
        self.assertEqual(result, {expected_output})
"""
        p2p_code = f"""
import unittest
from {target_module} import {failing_function}

class TestBaselineRegression_{issue_id}(unittest.TestCase):
    def test_baseline_pass(self):
        # Baseline invariant check
        self.assertTrue(callable({failing_function}))
"""
        combined = f2p_code + "\n" + p2p_code
        test_sha = hashlib.sha256(combined.encode("utf-8")).hexdigest()

        return ReproductionTestHarness(
            test_id=f"harness_{issue_id}",
            target_module=target_module,
            fail_to_pass_test_code=f2p_code.strip(),
            pass_to_pass_regression_code=p2p_code.strip(),
            test_sha256=test_sha
        )

    def apply_search_replace_block(self, original_content: str, search_block: str, replace_block: str) -> Tuple[bool, str]:
        """Applies exact search/replace hunk."""
        if search_block not in original_content:
            return False, original_content
        
        patched_content = original_content.replace(search_block, replace_block, 1)
        return True, patched_content

    def evaluate_patch_integrity(self, target_file: str, original_code: str, patched_code: str) -> PatchSynthesisResult:
        """
        Computes Patch Integrity Score (PIS):
        PIS = w1 * AST + w2 * CWE + w3 * Minimality - Penalties
        """
        patch_bytes = f"--- a/{target_file}\n+++ b/{target_file}\n".encode("utf-8") + patched_code.encode("utf-8")
        patch_sha = hashlib.sha256(patch_bytes).hexdigest()

        # 1. AST Syntax Check
        ast_valid = False
        try:
            ast.parse(patched_code)
            ast_valid = True
        except Exception:
            ast_valid = False

        # 2. Anti-pattern detection
        anti_patterns = []
        for pattern, msg in self.ANTI_PATTERNS:
            if pattern.search(patched_code):
                anti_patterns.append(msg)

        # 3. CWE checks
        cwe_violations = []
        if "../" in patched_code or "..\\" in patched_code:
            cwe_violations.append("CWE-22: Path Traversal sequence detected")
        if "shell=True" in patched_code:
            cwe_violations.append("CWE-78: Subprocess command injection (shell=True)")

        # 4. Calculate PIS
        base_score = 1.0 if ast_valid else 0.0
        if cwe_violations:
            base_score -= 0.50 * len(cwe_violations)
        if anti_patterns:
            base_score -= 0.25 * len(anti_patterns)

        # Check patch minimality (penalty if touched lines > 50)
        line_delta = abs(len(patched_code.splitlines()) - len(original_code.splitlines()))
        if line_delta > 50:
            base_score -= 0.10

        pis = max(0.0, min(1.0, round(base_score, 4)))

        unified_diff = f"--- a/{target_file}\n+++ b/{target_file}\n@@ -1,1 +1,1 @@\n"

        return PatchSynthesisResult(
            patch_id=f"patch_{patch_sha[:10]}",
            target_file=target_file,
            unified_diff=unified_diff,
            patch_sha256=patch_sha,
            ast_valid=ast_valid,
            patch_integrity_score=pis,
            cwe_violations=cwe_violations,
            anti_patterns_detected=anti_patterns
        )
