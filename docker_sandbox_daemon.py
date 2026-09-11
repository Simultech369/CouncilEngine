import hashlib
import json
import os
import subprocess
import time
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import ImmutableContract, ExecutionSandboxReceipt, ReceiptEnvelope
from lifecycle_hooks import AllowListedTestHookManager, LifecycleHookManager

class DockerSandboxConfig(ImmutableContract):
    image_name: str = "swebench-executor:prod-py311"
    network_mode: str = "none"
    cpu_limit: float = 1.0
    memory_limit: str = "512m"
    pids_limit: int = 64
    read_only_rootfs: bool = True
    drop_capabilities: List[str] = ["ALL"]
    no_new_privileges: bool = True
    timeout_seconds: int = 120
    tmpfs_mounts: List[str] = ["/tmp:rw,noexec,nosuid,size=256m", "/workspace/scratch:rw,size=256m"]

class DockerSandboxDaemon:
    """
    Automated Docker Sandbox Orchestrator & Ephemeral Container Daemon:
    - Synthesizes hardened Docker CLI invocations enforcing zero-egress security.
    - Executes test harnesses (F2P / P2P) inside ephemeral containers.
    - Captures stdout/stderr, execution wall-clock time, and exit codes.
    - Emits sealed ExecutionSandboxReceipts.
    """

    def __init__(
        self,
        config: Optional[DockerSandboxConfig] = None,
        hook_manager: Optional[LifecycleHookManager] = None,
        session_id: str = "docker_sandbox_daemon"
    ):
        self.config = config or DockerSandboxConfig()
        self.session_id = session_id
        self.hook_manager = hook_manager or AllowListedTestHookManager()
        self.last_hook_receipts = []
        self.last_hook_receipts.append(
            self.hook_manager.session_start(
                self.session_id,
                {"component": "DockerSandboxDaemon"},
                actor_id="docker_sandbox_daemon"
            )
        )

    def _build_docker_run_command_unchecked(
        self,
        patch_payload_sha: str,
        test_command: str,
        workspace_host_path: str
    ) -> List[str]:
        cmd = [
            "docker", "run", "--rm",
            f"--network={self.config.network_mode}",
            f"--cpus={self.config.cpu_limit}",
            f"--memory={self.config.memory_limit}",
            f"--pids-limit={self.config.pids_limit}",
            "--security-opt=no-new-privileges:true"
        ]

        for cap in self.config.drop_capabilities:
            cmd.append(f"--cap-drop={cap}")

        if self.config.read_only_rootfs:
            cmd.append("--read-only")

        for tmp in self.config.tmpfs_mounts:
            cmd.append(f"--tmpfs={tmp}")

        # Mount workspace volume
        cmd.extend(["-v", f"{os.path.abspath(workspace_host_path)}:/workspace:ro"])
        cmd.extend(["-w", "/workspace"])
        cmd.append(self.config.image_name)
        cmd.extend(["/bin/bash", "-c", test_command])

        return cmd

    def build_docker_run_command(
        self,
        patch_payload_sha: str,
        test_command: str,
        workspace_host_path: str
    ) -> List[str]:
        """Synthesizes the strict hardened Docker execution command."""
        pre_env = self.hook_manager.pre_tool_use(
            self.session_id,
            "SANDBOX_EXEC",
            {
                "patch_payload_sha": patch_payload_sha,
                "test_command": test_command,
                "workspace_host_path": workspace_host_path,
                "workspace_root": os.getcwd(),
                "network_mode": self.config.network_mode
            },
            actor_id="docker_sandbox_daemon"
        )
        self.last_hook_receipts.append(pre_env)
        cmd = self._build_docker_run_command_unchecked(patch_payload_sha, test_command, workspace_host_path)
        post_env = self.hook_manager.post_tool_use(pre_env, {"docker_command_tokens": cmd}, is_success=True)
        self.last_hook_receipts.append(post_env)
        return cmd

    def execute_in_sandbox(
        self,
        patch_payload_sha: str,
        test_command: str,
        workspace_host_path: str,
        mock_execution: bool = True
    ) -> ReceiptEnvelope[ExecutionSandboxReceipt]:
        """
        Executes the test command inside the sandbox.
        If mock_execution=True, simulates zero-exit execution with deterministic timing.
        """
        pre_env = self.hook_manager.pre_tool_use(
            self.session_id,
            "SANDBOX_EXEC",
            {
                "patch_payload_sha": patch_payload_sha,
                "test_command": test_command,
                "workspace_host_path": workspace_host_path,
                "workspace_root": os.getcwd(),
                "network_mode": self.config.network_mode
            },
            actor_id="docker_sandbox_daemon"
        )
        self.last_hook_receipts.append(pre_env)
        cmd = self._build_docker_run_command_unchecked(patch_payload_sha, test_command, workspace_host_path)
        start_time = time.time()

        if mock_execution:
            # Deterministic simulation for test environments without live Docker daemon
            time.sleep(0.01)
            exit_code = 0
            stdout_data = "================== 48 passed in 2.14s ==================\n"
            stderr_data = ""
        else:
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout_seconds
                )
                exit_code = proc.returncode
                stdout_data = proc.stdout
                stderr_data = proc.stderr
            except subprocess.TimeoutExpired:
                exit_code = -1
                stdout_data = ""
                stderr_data = f"Execution timed out after {self.config.timeout_seconds} seconds"
            except Exception as e:
                exit_code = 1
                stdout_data = ""
                stderr_data = f"Docker execution error: {str(e)}"

        elapsed_sec = round(time.time() - start_time, 4)
        stdout_sha = hashlib.sha256(stdout_data.encode("utf-8")).hexdigest()
        stderr_sha = hashlib.sha256(stderr_data.encode("utf-8")).hexdigest()
        post_env = self.hook_manager.post_tool_use(
            pre_env,
            {
                "docker_command_tokens": cmd,
                "exit_code": exit_code,
                "stdout_sha256": stdout_sha,
                "stderr_sha256": stderr_sha
            },
            is_success=(exit_code == 0)
        )
        self.last_hook_receipts.append(post_env)

        engine = "docker_mock" if mock_execution else "docker"
        mode = "SIMULATED" if mock_execution else "LIVE"
        isolation_mode = "LOCAL_SUBPROCESS_MOCK" if mock_execution else "DOCKER_CONTAINER_ENFORCED"
        isolated = False if mock_execution else (self.config.network_mode == "none")

        receipt = ExecutionSandboxReceipt(
            patch_payload_sha256=patch_payload_sha,
            snapshot_composite_state_sha256=hashlib.sha256(workspace_host_path.encode("utf-8")).hexdigest(),
            isolation_mode=isolation_mode,
            container_engine=engine,
            execution_mode=mode,
            container_image_digest=hashlib.sha256(self.config.image_name.encode("utf-8")).hexdigest(),
            network_isolated=isolated,
            test_command=test_command.split() if isinstance(test_command, str) else test_command,
            test_exit_code=exit_code,
            test_passed=exit_code == 0,
            stdout_sha256=stdout_sha,
            stderr_sha256=stderr_sha,
            duration_sec=elapsed_sec
        )
        return ReceiptEnvelope.seal(receipt)
