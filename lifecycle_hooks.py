import hashlib
import json
import os
import re
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Set
from council_contracts import LifecycleHookReceipt, RoundHandoffReceipt, ReceiptEnvelope

class LifecycleHookError(Exception):
    pass

PROMPT_INJECTION_LINE_RE = re.compile(
    r"(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions|"
    r"system\s*:|developer\s*:|assistant\s*:|"
    r"<\|im_start\|>|<\|system\|>|jailbreak|prompt\s+injection)"
)

def sanitize_untrusted_text(text: str) -> tuple[str, int]:
    """Removes obvious prompt-injection directives before evidence enters model context."""
    sanitized_lines = []
    removed_count = 0
    for line in text.splitlines():
        if PROMPT_INJECTION_LINE_RE.search(line):
            sanitized_lines.append("[REMOVED_UNTRUSTED_INSTRUCTION]")
            removed_count += 1
        else:
            sanitized_lines.append(line)
    return "\n".join(sanitized_lines), removed_count

class LifecycleHookManager(ABC):
    @abstractmethod
    def session_start(self, session_id: str, context: Dict[str, Any], actor_id: str = "orchestrator") -> ReceiptEnvelope[LifecycleHookReceipt]:
        pass

    @abstractmethod
    def pre_tool_use(self, session_id: str, operation: str, arguments: Dict[str, Any], actor_id: str = "agent") -> ReceiptEnvelope[LifecycleHookReceipt]:
        pass

    @abstractmethod
    def post_tool_use(self, pre_receipt_env: ReceiptEnvelope[LifecycleHookReceipt], outcome: Dict[str, Any], is_success: bool = True) -> ReceiptEnvelope[LifecycleHookReceipt]:
        pass

    @abstractmethod
    def stop(self, session_id: str, handoff_env: ReceiptEnvelope[RoundHandoffReceipt], actor_id: str = "orchestrator") -> ReceiptEnvelope[LifecycleHookReceipt]:
        pass

    @abstractmethod
    def subagent_stop(self, parent_session_id: str, child_session_id: str, handoff_env: ReceiptEnvelope[RoundHandoffReceipt], actor_id: str = "subagent") -> ReceiptEnvelope[LifecycleHookReceipt]:
        pass

class DefaultHookManager(LifecycleHookManager):
    """
    Default fail-closed Hook Manager: denies all operations unless explicitly permitted.
    """
    def session_start(self, session_id: str, context: Dict[str, Any], actor_id: str = "orchestrator") -> ReceiptEnvelope[LifecycleHookReceipt]:
        raise LifecycleHookError(f"DefaultHookManager: session_start denied for '{session_id}' (no hook policy configured)")

    def pre_tool_use(self, session_id: str, operation: str, arguments: Dict[str, Any], actor_id: str = "agent") -> ReceiptEnvelope[LifecycleHookReceipt]:
        raise LifecycleHookError(f"DefaultHookManager: pre_tool_use denied for operation '{operation}'")

    def post_tool_use(self, pre_receipt_env: ReceiptEnvelope[LifecycleHookReceipt], outcome: Dict[str, Any], is_success: bool = True) -> ReceiptEnvelope[LifecycleHookReceipt]:
        raise LifecycleHookError("DefaultHookManager: post_tool_use denied")

    def stop(self, session_id: str, handoff_env: ReceiptEnvelope[RoundHandoffReceipt], actor_id: str = "orchestrator") -> ReceiptEnvelope[LifecycleHookReceipt]:
        raise LifecycleHookError(f"DefaultHookManager: stop denied for '{session_id}'")

    def subagent_stop(self, parent_session_id: str, child_session_id: str, handoff_env: ReceiptEnvelope[RoundHandoffReceipt], actor_id: str = "subagent") -> ReceiptEnvelope[LifecycleHookReceipt]:
        raise LifecycleHookError(f"DefaultHookManager: subagent_stop denied for child '{child_session_id}'")

class AllowListedTestHookManager(LifecycleHookManager):
    """
    Explicitly allowlisted Hook Manager for verified workflows and test harnesses.
    Maintains session state, ensures pre/post correlation, and taints sessions on unhandled failures.
    """
    DANGEROUS_COMMAND_RE = re.compile(
        r"(?i)(\brm\s+-rf\s+[/\\.]|\bdel\s+/(s|q)\b|"
        r"\bremove-item\b.*(?:^|\s)-recurse\b|--privileged\b|--network=host\b|"
        r"docker\.sock|/var/run/docker\.sock|invoke-expression|\biex\b|curl\b.*\|\s*(sh|bash))"
    )

    def __init__(self, allowed_operations: Optional[Set[str]] = None, workspace_root: Optional[str] = None, webhook_dispatcher: Optional[Any] = None):
        self.allowed_operations: Set[str] = allowed_operations or {
            "FILESYSTEM_READ", "FILESYSTEM_WRITE", "SUBPROCESS_EXEC",
            "NETWORK_EGRESS", "SANDBOX_EXEC", "LEDGER_MUTATE", "MODEL_DISPATCH",
            "AGENT_REACH_CLI"
        }
        self.workspace_root = os.path.realpath(workspace_root or os.getcwd())
        self.active_sessions: Set[str] = set()
        self.tainted_sessions: Set[str] = set()
        self.pending_pre_hooks: Dict[str, ReceiptEnvelope[LifecycleHookReceipt]] = {}
        self.completed_post_hooks: Dict[str, ReceiptEnvelope[LifecycleHookReceipt]] = {}
        self.webhook_dispatcher = webhook_dispatcher
        self.webhook_dispatch_receipts: List[Any] = []

    def _record_webhook_dispatch(self, dispatch_receipts: List[Any]) -> None:
        self.webhook_dispatch_receipts.extend(dispatch_receipts)

    def _dispatch_hook_event(self, hook_env: ReceiptEnvelope[LifecycleHookReceipt], event_type: str, extra_payload: Optional[Dict[str, Any]] = None) -> None:
        if self.webhook_dispatcher is None:
            return
        receipts = self.webhook_dispatcher.dispatch_lifecycle_hook(
            hook_env,
            event_type=event_type,
            extra_payload=extra_payload
        )
        self._record_webhook_dispatch(receipts)

    def _dispatch_security_veto(self, session_id: str, operation: str, reason: str, actor_id: str, arguments: Dict[str, Any]) -> None:
        if self.webhook_dispatcher is None:
            return
        args_str = json.dumps(arguments, sort_keys=True, default=str)
        args_sha = hashlib.sha256(args_str.encode("utf-8")).hexdigest()
        receipts = self.webhook_dispatcher.dispatch_event(
            "CRITICAL_SECURITY_VETO",
            {
                "session_id": session_id,
                "actor_id": actor_id,
                "operation": operation,
                "reason": reason,
                "canonical_arguments_sha256": args_sha
            }
        )
        self._record_webhook_dispatch(receipts)

    def _coerce_command_text(self, value: Any) -> str:
        if isinstance(value, list):
            return " ".join(str(v) for v in value)
        return str(value or "")

    def _validate_command_policy(self, operation: str, arguments: Dict[str, Any]) -> None:
        command = self._coerce_command_text(
            arguments.get("command")
            or arguments.get("cmd")
            or arguments.get("test_command")
            or arguments.get("tool_args")
        )
        if not command:
            return

        if self.DANGEROUS_COMMAND_RE.search(command):
            raise LifecycleHookError(f"{operation} rejected: dangerous command token detected")

        if operation == "SANDBOX_EXEC":
            network_mode = arguments.get("network_mode")
            if network_mode not in (None, "none"):
                raise LifecycleHookError(f"SANDBOX_EXEC rejected: network_mode '{network_mode}' is not allowed")

    def _validate_path_policy(self, operation: str, arguments: Dict[str, Any]) -> None:
        workspace_root = os.path.realpath(str(arguments.get("workspace_root") or self.workspace_root))
        for key in ("path", "file_path", "target_path", "workspace_host_path"):
            value = arguments.get(key)
            if not isinstance(value, str) or not value:
                continue
            if "\x00" in value:
                raise LifecycleHookError(f"{operation} rejected: null byte in {key}")

            resolved = os.path.realpath(value if os.path.isabs(value) else os.path.join(workspace_root, value))
            is_inside = resolved == workspace_root or resolved.startswith(workspace_root + os.sep)
            if operation in {"FILESYSTEM_WRITE", "SANDBOX_EXEC"} and not is_inside:
                raise LifecycleHookError(f"{operation} rejected: {key} escapes workspace root")

            normalized = resolved.replace("\\", "/").lower()
            if normalized in {"/", "c:/", "c:/windows", "c:/users/josh"}:
                raise LifecycleHookError(f"{operation} rejected: unsafe root-like {key}")

    def _validate_agent_reach_policy(self, arguments: Dict[str, Any]) -> None:
        allowed_tools = {"gh", "yt-dlp", "jina", "reddit-scout"}
        tool_name = arguments.get("tool_name")
        if tool_name not in allowed_tools:
            raise LifecycleHookError(f"AGENT_REACH_CLI rejected: unsupported tool '{tool_name}'")

        source_url = str(arguments.get("source_url") or "")
        if re.search(r"(?i)(file://|\\\\|localhost|127\.0\.0\.1|169\.254\.169\.254)", source_url):
            raise LifecycleHookError("AGENT_REACH_CLI rejected: local/private source URL")

    def _validate_policy(self, operation: str, arguments: Dict[str, Any]) -> None:
        if operation in {"SUBPROCESS_EXEC", "SANDBOX_EXEC", "MODEL_DISPATCH", "AGENT_REACH_CLI"}:
            self._validate_command_policy(operation, arguments)
        if operation in {"FILESYSTEM_READ", "FILESYSTEM_WRITE", "SANDBOX_EXEC"}:
            self._validate_path_policy(operation, arguments)
        if operation == "AGENT_REACH_CLI":
            self._validate_agent_reach_policy(arguments)

    def session_start(self, session_id: str, context: Dict[str, Any], actor_id: str = "orchestrator") -> ReceiptEnvelope[LifecycleHookReceipt]:
        self.active_sessions.add(session_id)
        args_str = json.dumps(context, sort_keys=True, default=str)
        args_sha = hashlib.sha256(args_str.encode("utf-8")).hexdigest()

        receipt = LifecycleHookReceipt(
            session_id=session_id,
            actor_id=actor_id,
            phase="SESSION_START",
            operation="SESSION_INIT",
            canonical_arguments_sha256=args_sha,
            decision="ALLOWED",
            timestamp=time.time()
        )
        return ReceiptEnvelope.seal(receipt)

    def pre_tool_use(self, session_id: str, operation: str, arguments: Dict[str, Any], actor_id: str = "agent") -> ReceiptEnvelope[LifecycleHookReceipt]:
        if session_id in self.tainted_sessions:
            reason = f"pre_tool_use rejected: session '{session_id}' is TAINTED"
            self._dispatch_security_veto(session_id, operation, reason, actor_id, arguments)
            raise LifecycleHookError(reason)

        if operation not in self.allowed_operations:
            reason = f"pre_tool_use rejected: operation '{operation}' not in allowlist"
            self._dispatch_security_veto(session_id, operation, reason, actor_id, arguments)
            raise LifecycleHookError(reason)

        try:
            self._validate_policy(operation, arguments)
        except LifecycleHookError as err:
            self._dispatch_security_veto(session_id, operation, str(err), actor_id, arguments)
            raise

        args_str = json.dumps(arguments, sort_keys=True, default=str)
        args_sha = hashlib.sha256(args_str.encode("utf-8")).hexdigest()

        receipt = LifecycleHookReceipt(
            session_id=session_id,
            actor_id=actor_id,
            phase="PRE_TOOL_USE",
            operation=operation,
            canonical_arguments_sha256=args_sha,
            decision="ALLOWED",
            timestamp=time.time()
        )
        env = ReceiptEnvelope.seal(receipt)
        self.pending_pre_hooks[env.payload_sha256] = env
        return env

    def post_tool_use(self, pre_receipt_env: ReceiptEnvelope[LifecycleHookReceipt], outcome: Dict[str, Any], is_success: bool = True) -> ReceiptEnvelope[LifecycleHookReceipt]:
        pre_sha = pre_receipt_env.payload_sha256
        if pre_sha not in self.pending_pre_hooks:
            raise LifecycleHookError(f"post_tool_use rejected: pre-hook '{pre_sha}' not found in active pending registry")

        pre = pre_receipt_env.payload
        outcome_str = json.dumps(outcome, sort_keys=True, default=str)
        outcome_sha = hashlib.sha256(outcome_str.encode("utf-8")).hexdigest()

        decision = "ALLOWED" if is_success else "TAINTED"
        if not is_success:
            self.tainted_sessions.add(pre.session_id)

        receipt = LifecycleHookReceipt(
            session_id=pre.session_id,
            actor_id=pre.actor_id,
            phase="POST_TOOL_USE",
            operation=pre.operation,
            canonical_arguments_sha256=pre.canonical_arguments_sha256,
            decision=decision,
            linked_pre_hook_sha256=pre_sha,
            outcome_effect_sha256=outcome_sha,
            timestamp=time.time()
        )
        env = ReceiptEnvelope.seal(receipt)
        del self.pending_pre_hooks[pre_sha]
        self.completed_post_hooks[env.payload_sha256] = env
        if not is_success:
            self._dispatch_hook_event(env, "TAINTED_SESSION")
        return env

    def stop(self, session_id: str, handoff_env: ReceiptEnvelope[RoundHandoffReceipt], actor_id: str = "orchestrator") -> ReceiptEnvelope[LifecycleHookReceipt]:
        if session_id in self.tainted_sessions:
            raise LifecycleHookError(f"stop rejected: session '{session_id}' is TAINTED; cannot seal successful termination")

        # Check for uncompleted pre-hooks in this session
        unclosed = [p for p in self.pending_pre_hooks.values() if p.payload.session_id == session_id]
        if unclosed:
            raise LifecycleHookError(f"stop rejected: session '{session_id}' has {len(unclosed)} unclosed pre-tool hooks")

        receipt = LifecycleHookReceipt(
            session_id=session_id,
            actor_id=actor_id,
            phase="STOP",
            operation="SESSION_STOP",
            canonical_arguments_sha256=handoff_env.payload_sha256,
            decision="ALLOWED",
            related_handoff_sha256=handoff_env.payload_sha256,
            timestamp=time.time()
        )
        if session_id in self.active_sessions:
            self.active_sessions.remove(session_id)
        env = ReceiptEnvelope.seal(receipt)
        self._dispatch_hook_event(env, "SESSION_STOP")
        return env

    def subagent_stop(self, parent_session_id: str, child_session_id: str, handoff_env: ReceiptEnvelope[RoundHandoffReceipt], actor_id: str = "subagent") -> ReceiptEnvelope[LifecycleHookReceipt]:
        if child_session_id in self.tainted_sessions:
            raise LifecycleHookError(f"subagent_stop rejected: child session '{child_session_id}' is TAINTED")

        unclosed = [p for p in self.pending_pre_hooks.values() if p.payload.session_id == child_session_id]
        if unclosed:
            raise LifecycleHookError(f"subagent_stop rejected: child session '{child_session_id}' has unclosed pre-hooks")

        receipt = LifecycleHookReceipt(
            session_id=child_session_id,
            actor_id=actor_id,
            phase="SUBAGENT_STOP",
            operation="SUBAGENT_TERMINATION",
            canonical_arguments_sha256=hashlib.sha256(f"{parent_session_id}:{child_session_id}".encode("utf-8")).hexdigest(),
            decision="ALLOWED",
            related_handoff_sha256=handoff_env.payload_sha256,
            timestamp=time.time()
        )
        env = ReceiptEnvelope.seal(receipt)
        self._dispatch_hook_event(env, "SUBAGENT_STOP", extra_payload={"parent_session_id": parent_session_id})
        return env
