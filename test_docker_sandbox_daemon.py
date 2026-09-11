import os
import unittest
from docker_sandbox_daemon import DockerSandboxDaemon, DockerSandboxConfig
from council_contracts import ExecutionSandboxReceipt
from lifecycle_hooks import LifecycleHookError

class TestDockerSandboxDaemon(unittest.TestCase):

    def setUp(self):
        self.daemon = DockerSandboxDaemon()

    def test_build_docker_run_command_security_flags(self):
        cmd = self.daemon.build_docker_run_command(
            patch_payload_sha="dummy_patch_sha_999",
            test_command="pytest tests/test_auth.py",
            workspace_host_path="./"
        )
        cmd_str = " ".join(cmd)
        self.assertIn("--network=none", cmd_str)
        self.assertIn("--read-only", cmd_str)
        self.assertIn("--cap-drop=ALL", cmd_str)
        self.assertIn("--security-opt=no-new-privileges:true", cmd_str)
        self.assertIn("--cpus=1.0", cmd_str)
        self.assertIn("--memory=512m", cmd_str)
        self.assertIn("swebench-executor:prod-py311", cmd_str)
        self.assertIn("pytest tests/test_auth.py", cmd_str)
        self.assertEqual(self.daemon.last_hook_receipts[-2].payload.phase, "PRE_TOOL_USE")
        self.assertEqual(self.daemon.last_hook_receipts[-1].payload.phase, "POST_TOOL_USE")

    def test_execute_in_sandbox_simulation(self):
        receipt_env = self.daemon.execute_in_sandbox(
            patch_payload_sha="dummy_patch_sha_999",
            test_command="pytest tests/",
            workspace_host_path="./",
            mock_execution=True
        )
        payload = receipt_env.payload
        self.assertIsInstance(payload, ExecutionSandboxReceipt)
        self.assertEqual(payload.test_exit_code, 0)
        self.assertEqual(payload.isolation_mode, "LOCAL_SUBPROCESS_MOCK")
        self.assertEqual(payload.execution_mode, "SIMULATED")
        self.assertEqual(payload.container_engine, "docker_mock")
        self.assertFalse(payload.network_isolated)
        self.assertTrue(len(payload.stdout_sha256) == 64)
        self.assertTrue(len(payload.stderr_sha256) == 64)
        self.assertGreater(payload.duration_sec, 0.0)
        self.assertEqual(self.daemon.last_hook_receipts[-2].payload.phase, "PRE_TOOL_USE")
        self.assertEqual(self.daemon.last_hook_receipts[-1].payload.phase, "POST_TOOL_USE")

    def test_dangerous_sandbox_command_rejected_before_docker_invocation(self):
        with self.assertRaises(LifecycleHookError):
            self.daemon.execute_in_sandbox(
                patch_payload_sha="dummy_patch_sha_999",
                test_command="pytest tests/ && rm -rf /",
                workspace_host_path="./",
                mock_execution=True
            )

if __name__ == "__main__":
    unittest.main()
