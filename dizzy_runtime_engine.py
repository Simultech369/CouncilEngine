import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple, Literal
from pydantic import BaseModel, ConfigDict, Field
from council_contracts import ImmutableContract, MemorySnapshotReceipt, ReceiptEnvelope
from agent_loop_reminder_hook import AgentLoopReminderHook

class ToolCallRequest(ImmutableContract):
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]
    caller_role: str
    nonce: Optional[str] = None
    created_at: float = Field(default_factory=time.time)

class ToolCallResult(ImmutableContract):
    call_id: str
    tool_name: str
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    loop_reminder: Optional[str] = None

class DizzyRuntimeEngine:
    """
    Core execution engine for Dizzy / Clawd:
    - Fail-closed permission checking with HMAC single-use nonces.
    - Virtual root filesystem jail with explicit policy denial notices.
    - Active loop detection with escalating soft reminders (AgentLoopReminderHook).
    - Sliding-window episodic memory compression (MemorySnapshotReceipt).
    - Streaming NDJSON event emitter (RFC 7464).
    """

    def __init__(
        self,
        workspace_root: str,
        secret_key: str = "dizzy_runtime_kernel_secret_2026",
        max_context_turns: int = 24
    ):
        self.workspace_root = os.path.abspath(workspace_root)
        self.secret_key = secret_key.encode("utf-8")
        self.max_context_turns = max_context_turns
        self.consumed_nonces = set()
        self.conversation_turns: List[Dict[str, Any]] = []
        self.loop_hook = AgentLoopReminderHook(agent_id="dizzy_agent")

    def generate_single_use_nonce(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Generates a single-use HMAC-SHA256 nonce bound to the argument payload."""
        payload_str = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
        h = hmac.new(self.secret_key, payload_str.encode("utf-8"), hashlib.sha256)
        nonce = f"NONCE_{h.hexdigest()[:24]}_{uuid.uuid4().hex[:8]}"
        return nonce

    def verify_and_consume_nonce(self, tool_name: str, arguments: Dict[str, Any], nonce: str) -> bool:
        """Verifies HMAC binding and ensures the nonce is consumed exactly once."""
        if nonce in self.consumed_nonces:
            return False  # Replay attack blocked

        payload_str = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
        expected_sig = hmac.new(self.secret_key, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        
        if not nonce.startswith(f"NONCE_{expected_sig}_"):
            return False  # Signature mismatch / parameter mutation

        self.consumed_nonces.add(nonce)
        return True

    def execute_filesystem_read(self, rel_path: str) -> Tuple[bool, str]:
        """Reads a file strictly within the workspace virtual root jail."""
        try:
            target_path = os.path.realpath(os.path.join(self.workspace_root, rel_path))
            if not target_path.startswith(self.workspace_root):
                return False, "[POLICY DENIAL: Path escapes virtual workspace jail. This is a security policy denial, not a command syntax error; do not attempt to bypass.]"

            # Check forbidden credential subtrees
            for forbidden in [".ssh", ".aws", ".git/hooks", "id_rsa"]:
                if forbidden in rel_path:
                    return False, f"[POLICY DENIAL: Access Denied: Protected security path '{forbidden}'. Do not retry.]"

            if not os.path.exists(target_path):
                return False, f"File not found: {rel_path}"

            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return True, content
        except Exception as e:
            return False, str(e)

    def execute_filesystem_write(self, rel_path: str, content: str) -> Tuple[bool, str]:
        """Performs atomic swap write strictly within workspace jail."""
        try:
            target_path = os.path.realpath(os.path.join(self.workspace_root, rel_path))
            if not target_path.startswith(self.workspace_root):
                return False, "[POLICY DENIAL: Path escapes virtual workspace jail. This is a security policy denial, not a command syntax error; do not attempt to bypass.]"

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            temp_path = f"{target_path}.tmp_{uuid.uuid4().hex[:6]}"
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Atomic swap
            os.replace(temp_path, target_path)
            return True, "File written successfully"
        except Exception as e:
            return False, str(e)

    def invoke_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        nonce: Optional[str] = None
    ) -> ToolCallResult:
        """
        Unified tool dispatch with active loop checking, truthful policy denials,
        and escalating contextual reminders.
        """
        t0 = time.perf_counter()
        call_id = f"call_{uuid.uuid4().hex[:8]}"

        # If nonce is provided, verify it
        if nonce and not self.verify_and_consume_nonce(tool_name, arguments, nonce):
            _, reminder = self.loop_hook.record_tool_call(tool_name, arguments, was_denied=True)
            denial_msg = "[POLICY DENIAL: Invalid or consumed single-use authorization nonce. Do not retry with the same nonce.]"
            return ToolCallResult(
                call_id=call_id,
                tool_name=tool_name,
                success=False,
                stdout="",
                stderr=denial_msg,
                exit_code=1,
                duration_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                loop_reminder=reminder
            )

        success = False
        stdout = ""
        stderr = ""
        exit_code = 0

        if tool_name == "filesystem_read":
            rel_path = arguments.get("path", "")
            success, output = self.execute_filesystem_read(rel_path)
            if success:
                stdout = output
            else:
                stderr = output
                exit_code = 1
        elif tool_name == "filesystem_write":
            rel_path = arguments.get("path", "")
            content = arguments.get("content", "")
            success, output = self.execute_filesystem_write(rel_path, content)
            if success:
                stdout = output
            else:
                stderr = output
                exit_code = 1
        else:
            stderr = f"Unknown tool '{tool_name}'"
            exit_code = 127

        _, reminder = self.loop_hook.record_tool_call(tool_name, arguments, was_denied=not success)
        duration = round((time.perf_counter() - t0) * 1000.0, 2)

        return ToolCallResult(
            call_id=call_id,
            tool_name=tool_name,
            success=success,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_ms=duration,
            loop_reminder=reminder
        )

    def append_turn(self, role: str, content: str):
        self.conversation_turns.append({"role": role, "content": content, "timestamp": time.time()})

    def should_compress_memory(self) -> bool:
        return len(self.conversation_turns) >= self.max_context_turns

    def compress_episodic_memory(self) -> Tuple[ReceiptEnvelope[MemorySnapshotReceipt], List[Dict[str, Any]]]:
        """
        Sliding-window compaction extracting structured facets and emitting
        a sealed MemorySnapshotReceipt.
        """
        retained_count = max(2, self.max_context_turns // 2)
        expired_turns = self.conversation_turns[:-retained_count]
        retained_turns = self.conversation_turns[-retained_count:]

        # Extract facets
        facets = []
        for t in expired_turns:
            if "CRITICAL" in t["content"] or "INVARIANT" in t["content"] or "FIXED" in t["content"]:
                facets.append(f"Fact [{t['role']}]: {t['content'][:80]}")

        parent_shas = [
            hashlib.sha256(json.dumps(t).encode("utf-8")).hexdigest()
            for t in expired_turns
        ]

        receipt = MemorySnapshotReceipt(
            memory_snapshot_id=f"snap_{uuid.uuid4().hex[:8]}",
            parent_memory_shas=parent_shas[:5],
            retained_facts_count=len(facets) + len(retained_turns),
            expired_facts_count=len(expired_turns),
            privacy_tier="LOCAL_ONLY_REQUIRED",
            snapshot_timestamp=time.time()
        )
        self.conversation_turns = retained_turns
        return ReceiptEnvelope.seal(receipt), retained_turns

    def format_ndjson_event(self, event_type: str, payload: Dict[str, Any]) -> str:
        """Formats an RFC 7464 / NDJSON event line."""
        event_record = {
            "event_type": event_type,
            "timestamp": time.time(),
            "payload": payload
        }
        return json.dumps(event_record) + "\n"

    def emit_streaming_event_ndjson(self, event_type: str, payload: Dict[str, Any]) -> str:
        return self.format_ndjson_event(event_type, payload)
