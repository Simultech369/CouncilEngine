"""
test_anti_wrapper_audit.py - Unit tests for Anti-Wrapper Theatre, Dead-Code, and ΔLOC Scanner.
"""

import unittest
import tempfile
import os
import shutil
from anti_wrapper_audit import (
    CodeMetrics,
    DeadCodeScanner,
    WrapperTheatreDetector,
    AntiWrapperAuditor,
)


class TestCodeMetrics(unittest.TestCase):
    def test_metrics_line_counts(self):
        sample = (
            "# Header comment\n"
            "\n"
            "def foo():\n"
            "    # inner comment\n"
            "    return 42\n"
            "\n"
        )
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py", encoding="utf-8") as f:
            f.write(sample)
            f_path = f.name

        try:
            metrics = CodeMetrics.analyze_file(f_path)
            self.assertEqual(metrics["total_lines"], 6)
            self.assertEqual(metrics["comment_lines"], 2)
            self.assertEqual(metrics["blank_lines"], 2)
            self.assertEqual(metrics["code_lines"], 2)
        finally:
            os.remove(f_path)


class TestDeadCodeScanner(unittest.TestCase):
    def test_detects_unused_private_helper(self):
        code = (
            "def public_api():\n"
            "    return 1\n"
            "\n"
            "def _unused_internal_helper():\n"
            "    return 'dead'\n"
        )
        res = DeadCodeScanner.scan_file("sample.py", code)
        self.assertIn("_unused_internal_helper", res["unused_helpers"])

    def test_ignores_called_private_helper(self):
        code = (
            "def _used_helper():\n"
            "    return 10\n"
            "\n"
            "def public_api():\n"
            "    return _used_helper()\n"
        )
        res = DeadCodeScanner.scan_file("sample.py", code)
        self.assertNotIn("_used_helper", res["unused_helpers"])


class TestWrapperTheatreDetector(unittest.TestCase):
    def test_detects_naked_wrapper(self):
        code = (
            "def get_user_name(user):\n"
            "    return user.get('name')\n"
        )
        findings = WrapperTheatreDetector.scan_file("module.py", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["classification"], "NAKED_WRAPPER")
        self.assertEqual(findings[0]["target_called"], "get")

    def test_recognizes_contractual_wrapper(self):
        code = (
            "def secure_dispatch(payload):\n"
            "    ReceiptEnvelope.seal(payload)\n"
            "    return raw_dispatch(payload)\n"
        )
        findings = WrapperTheatreDetector.scan_file("module.py", code)
        # Should NOT be flagged as naked wrapper because it has contract markers
        self.assertEqual(len(findings), 0)

    def test_recognizes_compatibility_shim(self):
        code = (
            "def legacy_call(*args, **kwargs):\n"
            "    '''Backward-compatible adapter for legacy callers.'''\n"
            "    return new_call(*args, **kwargs)\n"
        )
        findings = WrapperTheatreDetector.scan_file("module.py", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["classification"], "COMPATIBILITY_SHIM")

    def test_ignores_test_fixtures(self):
        code = (
            "class TestSuite(unittest.TestCase):\n"
            "    def tearDown(self):\n"
            "        shutil.rmtree(self.tmp)\n"
        )
        findings = WrapperTheatreDetector.scan_file("test_suite.py", code)
        self.assertEqual(len(findings), 0)


class TestAntiWrapperAuditor(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_auditor_end_to_end(self):
        # Create a sample production file with dead code & naked wrapper
        prod_file = os.path.join(self.test_dir, "prod.py")
        with open(prod_file, "w", encoding="utf-8") as f:
            f.write(
                "# Production module\n"
                "def _dead_helper():\n"
                "    return 'orphan'\n"
                "\n"
                "def naked_passthrough(x):\n"
                "    return target(x)\n"
            )

        # Create a sample test file
        test_file = os.path.join(self.test_dir, "test_prod.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(
                "def test_example():\n"
                "    assert True\n"
            )

        auditor = AntiWrapperAuditor(target_dir=self.test_dir)
        report = auditor.run_audit()

        self.assertEqual(report["scanned_python_files"], 2)
        self.assertEqual(report["dead_code_summary"]["total_unused_helpers"], 1)
        self.assertEqual(report["wrapper_theatre_summary"]["naked_wrappers_count"], 1)

        md = auditor.format_markdown_report(report)
        self.assertIn("ΔLOC", md)
        self.assertIn("naked_passthrough", md)

    def test_unused_compatibility_helper_is_flagged(self):
        # A private compatibility shim with zero call sites must be caught as dead code
        code = (
            "def _legacy_compat_shim(x):\n"
            "    '''Backward-compatible shim.'''\n"
            "    return x\n"
        )
        res = DeadCodeScanner.scan_file("legacy.py", code)
        self.assertIn("_legacy_compat_shim", res["unused_helpers"])

    def test_contractual_wrapper_with_receipt_passes_clean(self):
        # Function wrapping an underlying call but sealing a ReceiptEnvelope
        code = (
            "def dispatch_with_contract(payload):\n"
            "    ReceiptEnvelope.seal(payload)\n"
            "    return underlying_dispatch(payload)\n"
        )
        findings = WrapperTheatreDetector.scan_file("gateway.py", code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()

