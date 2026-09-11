import unittest
from sandboxed_patch_generator import SandboxedPatchGenerator
from council_contracts import PatchReceipt, ExecutionSandboxReceipt

class TestSandboxedPatchGenerator(unittest.TestCase):

    def setUp(self):
        self.generator = SandboxedPatchGenerator()

    def test_run_sandbox_verification_truthfulness(self):
        sample_patch = (
            b"--- a/src/math_helper.py\n"
            b"+++ b/src/math_helper.py\n"
            b"@@ -1,3 +1,3 @@\n"
            b" def multiply(a, b):\n"
            b"-    return a + b\n"
            b"+    return a * b\n"
        )
        test_code = (
            "def multiply(a, b):\n"
            "    return a * b\n\n"
            "def test_multiply():\n"
            "    assert multiply(3, 4) == 12\n"
        )

        patch_env, sandbox_env = self.generator.run_sandbox_verification(
            raw_patch_bytes=sample_patch,
            test_code=test_code,
            parent_snapshot_sha256="0" * 64
        )

        # 1. Assert PatchReceipt
        self.assertIsInstance(patch_env.payload, PatchReceipt)
        self.assertTrue(patch_env.payload.sanitization_passed)
        self.assertEqual(patch_env.payload.target_files_touched, ["src/math_helper.py"])
        self.assertEqual(patch_env.payload.hunks_count, 1)

        # 2. Assert ExecutionSandboxReceipt truthfulness
        self.assertIsInstance(sandbox_env.payload, ExecutionSandboxReceipt)
        self.assertEqual(sandbox_env.payload.isolation_mode, "LOCAL_SUBPROCESS_MOCK")
        self.assertEqual(sandbox_env.payload.container_engine, "local_subprocess")
        self.assertFalse(sandbox_env.payload.network_isolated)
        self.assertEqual(sandbox_env.payload.test_exit_code, 0)
        self.assertTrue(sandbox_env.payload.test_passed)
        self.assertGreater(sandbox_env.payload.duration_sec, 0.0)
        self.assertGreaterEqual(len(self.generator.last_hook_receipts), 5)
        self.assertEqual(self.generator.last_hook_receipts[-2].payload.phase, "PRE_TOOL_USE")
        self.assertEqual(self.generator.last_hook_receipts[-1].payload.phase, "POST_TOOL_USE")

if __name__ == "__main__":
    unittest.main()
