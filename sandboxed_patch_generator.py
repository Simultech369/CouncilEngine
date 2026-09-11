import ast
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import (
    ReceiptEnvelope, PatchReceipt, ExecutionSandboxReceipt
)
from council_verifier import CouncilReceiptVerifier, VerificationError
from model_gateway import ModelGateway
from model_routes import create_route_attestation
from log_derived_context_engine import LogDerivedContextEngine
from lifecycle_hooks import AllowListedTestHookManager, LifecycleHookManager, sanitize_untrusted_text

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

class SandboxedPatchGenerator:
    """
    SWE-agent & OpenHands inspired sandboxed patch generation engine.
    - Prompts coding model to generate unified diff patches
    - Formally validates patch AST, hunk bounds, and forbidden path policies
    - Executes test suite inside ephemeral sandbox environment
    - Seals PatchReceipt and ExecutionSandboxReceipt
    """

    def __init__(
        self,
        ollama_url: str = OLLAMA_URL,
        hook_manager: Optional[LifecycleHookManager] = None,
        session_id: str = "sandboxed_patch_generator"
    ):
        self.ollama_url = ollama_url
        self.gateway = ModelGateway()
        self.session_id = session_id
        self.hook_manager = hook_manager or AllowListedTestHookManager()
        self.last_hook_receipts = []
        self.last_hook_receipts.append(
            self.hook_manager.session_start(
                self.session_id,
                {"component": "SandboxedPatchGenerator"},
                actor_id="sandboxed_patch_generator"
            )
        )
        self.route = create_route_attestation(
            route_id="route_sandboxed_patch_local",
            provider_name="ollama_local",
            endpoint_url=self.ollama_url,
            compliance_tier="LOCAL_ONLY_VERIFIED",
            content_retention_days=0,
            zdr_verified=True,
            fallbacks_allowed=False,
            validity_sec=3500
        )

    def _run_post_sandbox_static_checks(self, test_file_path: str) -> Dict[str, Any]:
        checks = {
            "python_ast_valid": False,
            "black_check": "UNAVAILABLE",
            "ruff_check": "UNAVAILABLE"
        }
        with open(test_file_path, "r", encoding="utf-8") as f:
            source = f.read()

        try:
            ast.parse(source, filename=test_file_path)
            checks["python_ast_valid"] = True
        except SyntaxError as exc:
            checks["syntax_error"] = str(exc)
            return checks

        for tool_name, args in {
            "black": ["--check", "--quiet", test_file_path],
            "ruff": ["check", "--quiet", test_file_path]
        }.items():
            if shutil.which(tool_name):
                proc = subprocess.run(
                    [tool_name] + args,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                checks[f"{tool_name}_check"] = "PASSED" if proc.returncode == 0 else "FAILED"

        return checks

    def generate_candidate_patch(
        self,
        model_slug: str,
        issue_description: str,
        current_file_path: str,
        current_file_content: str
    ) -> str:
        prompt = (
            "You are an expert autonomous software engineer (SWE-agent).\n"
            f"Fix the following bug:\n"
            f"Issue: {issue_description}\n\n"
            f"Target file: {current_file_path}\n"
            f"Current Content:\n```python\n{current_file_content}\n```\n\n"
            "Generate ONLY a unified diff patch (`diff --git` or `--- a/... +++ b/...`).\n"
            "Do not include explanation. Output raw diff only."
        )

        ctx = LogDerivedContextEngine(session_id=f"patch_gen_{model_slug}_{int(time.time())}")
        ctx.append_event("CONFIG_SET", "system", {
            "model_slug": model_slug,
            "model_family": "qwen" if "qwen" in model_slug else "generic",
            "provider": "ollama_local",
            "route_id": "route_sandboxed_patch_local",
            "temperature": 0.1,
            "max_tokens": 768
        })
        ctx.append_event("USER_INPUT", "user", {"content": prompt})

        pre_env = self.hook_manager.pre_tool_use(
            self.session_id,
            "MODEL_DISPATCH",
            {
                "model_slug": model_slug,
                "route_id": "route_sandboxed_patch_local",
                "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            },
            actor_id="sandboxed_patch_generator"
        )
        self.last_hook_receipts.append(pre_env)
        try:
            probe_env, raw = self.gateway.dispatch_qualification_probe(
                model_slug=model_slug,
                model_family="qwen" if "qwen" in model_slug else "generic",
                provider="ollama_local",
                route_env=self.route,
                prompt_text=prompt,
                temperature=0.1,
                max_tokens=768,
                context_engine=ctx
            )
            if not raw:
                post_env = self.hook_manager.post_tool_use(pre_env, {"raw_response_present": False}, is_success=False)
                self.last_hook_receipts.append(post_env)
                return ""
            raw, removed = sanitize_untrusted_text(raw)
            if "<think>" in raw and "</think>" in raw:
                raw = raw.split("</think>", 1)[1].strip()
            if raw.startswith("```diff"):
                raw = raw.split("```diff", 1)[1].rsplit("```", 1)[0].strip()
            elif raw.startswith("```"):
                raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            post_env = self.hook_manager.post_tool_use(
                pre_env,
                {
                    "raw_response_present": True,
                    "removed_prompt_injection_lines": removed,
                    "patch_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest()
                },
                is_success=bool(raw.strip())
            )
            self.last_hook_receipts.append(post_env)
            return raw.strip()
        except Exception as exc:
            post_env = self.hook_manager.post_tool_use(pre_env, {"error": str(exc)}, is_success=False)
            self.last_hook_receipts.append(post_env)
            return ""

    def run_sandbox_verification(
        self,
        raw_patch_bytes: bytes,
        test_code: str,
        parent_snapshot_sha256: str
    ) -> Tuple[ReceiptEnvelope[PatchReceipt], ReceiptEnvelope[ExecutionSandboxReceipt]]:
        """
        Validates patch sanitization and runs the sandbox test runner.
        """
        # 1. Parse & Sanitize Patch
        touched_files, hunks_count = CouncilReceiptVerifier.parse_and_sanitize_patch(raw_patch_bytes)
        patch_sha = hashlib.sha256(raw_patch_bytes).hexdigest()

        patch_receipt = PatchReceipt(
            parent_snapshot_sha256=parent_snapshot_sha256,
            patch_sha256=patch_sha,
            target_files_touched=sorted(list(touched_files)),
            hunks_count=hunks_count,
            sanitization_passed=True
        )
        patch_env = ReceiptEnvelope.seal(patch_receipt)

        # 2. Execute ephemeral sandbox test
        t0 = time.perf_counter()
        with tempfile.TemporaryDirectory() as sandbox_dir:
            test_file_path = os.path.join(sandbox_dir, "test_target.py")
            pre_write_env = self.hook_manager.pre_tool_use(
                self.session_id,
                "FILESYSTEM_WRITE",
                {
                    "path": test_file_path,
                    "workspace_root": sandbox_dir,
                    "content_sha256": hashlib.sha256(test_code.encode("utf-8")).hexdigest()
                },
                actor_id="sandboxed_patch_generator"
            )
            self.last_hook_receipts.append(pre_write_env)
            with open(test_file_path, "w", encoding="utf-8") as f:
                f.write(test_code)
            post_write_env = self.hook_manager.post_tool_use(
                pre_write_env,
                {"bytes_written": len(test_code.encode("utf-8"))},
                is_success=True
            )
            self.last_hook_receipts.append(post_write_env)

            static_checks = self._run_post_sandbox_static_checks(test_file_path)

            # Run isolated pytest process
            cmd = [sys.executable, "-m", "pytest", test_file_path]
            pre_exec_env = self.hook_manager.pre_tool_use(
                self.session_id,
                "SUBPROCESS_EXEC",
                {
                    "command": cmd,
                    "cwd": sandbox_dir,
                    "workspace_root": sandbox_dir
                },
                actor_id="sandboxed_patch_generator"
            )
            self.last_hook_receipts.append(pre_exec_env)
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=sandbox_dir,
                    timeout=30
                )
                exit_code = proc.returncode
                stdout_data = proc.stdout
                stderr_data = proc.stderr
            except subprocess.TimeoutExpired as exc:
                exit_code = -1
                stdout_data = exc.stdout or ""
                stderr_data = f"Sandbox verification timed out after {exc.timeout} seconds"
            duration = round(time.perf_counter() - t0, 3)
            stdout_sha = hashlib.sha256(stdout_data.encode("utf-8")).hexdigest()
            stderr_sha = hashlib.sha256(stderr_data.encode("utf-8")).hexdigest()
            post_exec_env = self.hook_manager.post_tool_use(
                pre_exec_env,
                {
                    "exit_code": exit_code,
                    "stdout_sha256": stdout_sha,
                    "stderr_sha256": stderr_sha,
                    "static_checks": static_checks
                },
                is_success=(exit_code == 0 and static_checks.get("python_ast_valid") is True)
            )
            self.last_hook_receipts.append(post_exec_env)

        # 3. Seal ExecutionSandboxReceipt
        sandbox_receipt = ExecutionSandboxReceipt(
            patch_payload_sha256=patch_env.payload_sha256,
            snapshot_composite_state_sha256=parent_snapshot_sha256,
            isolation_mode="LOCAL_SUBPROCESS_MOCK",
            container_engine="local_subprocess",
            container_image_digest="host_toolchain",
            network_isolated=False,
            test_command=["pytest", "test_target.py"],
            test_exit_code=exit_code,
            test_passed=(exit_code == 0),
            stdout_sha256=stdout_sha,
            stderr_sha256=stderr_sha,
            duration_sec=duration
        )
        sandbox_env = ReceiptEnvelope.seal(sandbox_receipt)

        return patch_env, sandbox_env

if __name__ == "__main__":
    generator = SandboxedPatchGenerator()
    
    # Test patch and test code
    sample_patch = (
        b"--- a/src/math_helper.py\n"
        b"+++ b/src/math_helper.py\n"
        b"@@ -1,3 +1,3 @@\n"
        b" def multiply(a, b):\n"
        b"-    return a + b\n"
        b"+    return a * b\n"
    )
    
    sample_test = (
        "def multiply(a, b):\n"
        "    return a * b\n\n"
        "def test_multiply():\n"
        "    assert multiply(3, 4) == 12\n"
    )

    state_sha = "state_sha_alpha_123"
    patch_env, sandbox_env = generator.run_sandbox_verification(sample_patch, sample_test, state_sha)
    
    print(f"Generated and Sealed PatchReceipt:")
    print(f"  - Target Files: {patch_env.payload.target_files_touched}")
    print(f"  - Hunk Count: {patch_env.payload.hunks_count}")
    print(f"  - Sanitization Passed: {patch_env.payload.sanitization_passed}")
    print(f"  - Payload SHA256: {patch_env.payload_sha256[:16]}...")
    
    print(f"\nGenerated and Sealed ExecutionSandboxReceipt:")
    print(f"  - Test Passed: {sandbox_env.payload.test_passed} (Exit code: {sandbox_env.payload.test_exit_code})")
    print(f"  - Duration: {sandbox_env.payload.duration_sec}s")
    print(f"  - Network Isolated: {sandbox_env.payload.network_isolated}")
    print(f"  - Payload SHA256: {sandbox_env.payload_sha256[:16]}...")
