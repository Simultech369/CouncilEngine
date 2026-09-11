import hashlib
import subprocess
import time
from typing import Dict, List, Optional, Tuple, Literal
from urllib.parse import urlparse

from council_contracts import ImmutableContract, ReceiptEnvelope
from lifecycle_hooks import AllowListedTestHookManager, LifecycleHookError, LifecycleHookManager, sanitize_untrusted_text


class AgentReachFetchReceipt(ImmutableContract):
    tool_name: Literal["gh", "yt-dlp", "jina", "reddit-scout"]
    source_url: str
    tool_args_sha256: str
    raw_stdout_sha256: str
    sanitized_markdown_sha256: str
    removed_prompt_injection_lines_count: int
    exit_code: int
    duration_sec: float
    pre_hook_payload_sha256: str
    post_hook_payload_sha256: str
    fetched_at: float


class AgentReachAdapter:
    """
    Hook-gated adapter for local evidence-gathering CLI tools.
    Runs commands without a shell, sanitizes untrusted output, and seals a receipt.
    """

    DEFAULT_TOOL_COMMANDS = {
        "gh": ["gh"],
        "yt-dlp": ["yt-dlp"],
        "jina": ["jina"],
        "reddit-scout": ["reddit-scout"]
    }

    def __init__(
        self,
        tool_commands: Optional[Dict[str, List[str]]] = None,
        hook_manager: Optional[LifecycleHookManager] = None,
        session_id: str = "agent_reach_adapter"
    ):
        self.tool_commands = tool_commands or self.DEFAULT_TOOL_COMMANDS
        self.session_id = session_id
        self.hook_manager = hook_manager or AllowListedTestHookManager()
        self.last_hook_receipts = []
        self.last_hook_receipts.append(
            self.hook_manager.session_start(
                self.session_id,
                {"component": "AgentReachAdapter"},
                actor_id="agent_reach_adapter"
            )
        )

    @staticmethod
    def _args_sha256(tool_args: List[str]) -> str:
        return hashlib.sha256("\x00".join(tool_args).encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_domain(source_url: str, allowed_domains: Optional[List[str]]) -> None:
        if not allowed_domains:
            return
        host = (urlparse(source_url).hostname or "").lower()
        normalized_allowed = [d.lower().lstrip(".") for d in allowed_domains]
        if not any(host == d or host.endswith("." + d) for d in normalized_allowed):
            raise LifecycleHookError(f"AGENT_REACH_CLI rejected: host '{host}' is outside allowed domains")

    def fetch_text(
        self,
        tool_name: Literal["gh", "yt-dlp", "jina", "reddit-scout"],
        tool_args: List[str],
        source_url: str,
        allowed_domains: Optional[List[str]] = None,
        timeout_sec: float = 30.0
    ) -> Tuple[str, ReceiptEnvelope[AgentReachFetchReceipt]]:
        self._validate_domain(source_url, allowed_domains)
        if tool_name not in self.tool_commands:
            raise LifecycleHookError(f"AGENT_REACH_CLI rejected: no command registered for '{tool_name}'")

        pre_env = self.hook_manager.pre_tool_use(
            self.session_id,
            "AGENT_REACH_CLI",
            {
                "tool_name": tool_name,
                "tool_args": tool_args,
                "source_url": source_url
            },
            actor_id="agent_reach_adapter"
        )
        self.last_hook_receipts.append(pre_env)

        command = list(self.tool_commands[tool_name]) + list(tool_args)
        started = time.perf_counter()
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            shell=False
        )
        duration = round(time.perf_counter() - started, 4)

        raw_stdout = proc.stdout or ""
        raw_stderr = proc.stderr or ""
        sanitized_text, removed_count = sanitize_untrusted_text(raw_stdout)
        raw_stdout_sha = hashlib.sha256(raw_stdout.encode("utf-8")).hexdigest()
        sanitized_sha = hashlib.sha256(sanitized_text.encode("utf-8")).hexdigest()

        post_env = self.hook_manager.post_tool_use(
            pre_env,
            {
                "exit_code": proc.returncode,
                "raw_stdout_sha256": raw_stdout_sha,
                "sanitized_markdown_sha256": sanitized_sha,
                "removed_prompt_injection_lines_count": removed_count,
                "stderr_sha256": hashlib.sha256(raw_stderr.encode("utf-8")).hexdigest()
            },
            is_success=(proc.returncode == 0)
        )
        self.last_hook_receipts.append(post_env)

        if proc.returncode != 0:
            raise LifecycleHookError(f"AGENT_REACH_CLI failed closed with exit code {proc.returncode}")

        receipt = AgentReachFetchReceipt(
            tool_name=tool_name,
            source_url=source_url,
            tool_args_sha256=self._args_sha256(tool_args),
            raw_stdout_sha256=raw_stdout_sha,
            sanitized_markdown_sha256=sanitized_sha,
            removed_prompt_injection_lines_count=removed_count,
            exit_code=proc.returncode,
            duration_sec=duration,
            pre_hook_payload_sha256=pre_env.payload_sha256,
            post_hook_payload_sha256=post_env.payload_sha256,
            fetched_at=time.time()
        )
        return sanitized_text, ReceiptEnvelope.seal(receipt)
