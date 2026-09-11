import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Tuple

class ToolInvocationRecord:
    def __init__(self, tool_name: str, arguments: Dict[str, Any], was_denied: bool = False):
        self.tool_name = tool_name
        self.arguments = arguments
        self.was_denied = was_denied
        self.arg_hash = self._compute_canonical_arg_hash(arguments)
        self.timestamp = time.time()

    @staticmethod
    def _compute_canonical_arg_hash(args: Dict[str, Any]) -> str:
        """Computes order-invariant canonical SHA-256 hash of tool arguments."""
        try:
            serialized = json.dumps(args, sort_keys=True, separators=(',', ':'))
        except Exception:
            serialized = str(sorted(args.items()))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

class AgentLoopReminderHook:
    """
    Escalating Soft-Reminder Hook for Agent Loop Detection:
    - Counts consecutive identical tool calls using canonical argument hashing.
    - Counts policy-denied calls as repeats.
    - Ignores harmless intermediate calls (e.g., 'update_todo', 'heartbeat') to prevent loop hiding.
    - Injects soft, escalating context reminders at counts 3, 5, and 8 without hard-blocking execution.
    """

    TRANSPARENT_NOISE_TOOLS = {"update_todo", "status", "heartbeat", "set_scratch_pad"}
    CONTRACT_INVARIANT_REMINDER = (
        " Deterministic invariants still apply: verify receipt hashes, exact state paths, "
        "taint status, and policy-denied tool outputs before continuing."
    )

    def __init__(self, agent_id: str = "main_agent"):
        self.agent_id = agent_id
        self.call_history: List[ToolInvocationRecord] = []
        self.consecutive_repeat_count: int = 0
        self.last_tool_signature: Optional[Tuple[str, str]] = None  # (tool_name, arg_hash)

    def record_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        was_denied: bool = False
    ) -> Tuple[int, Optional[str]]:
        """
        Records a tool invocation and returns (current_repeat_count, optional_reminder_message).
        """
        # If this is a transparent status/todo update, do not reset loop counter
        if tool_name in self.TRANSPARENT_NOISE_TOOLS:
            return self.consecutive_repeat_count, None

        rec = ToolInvocationRecord(tool_name, arguments, was_denied)
        self.call_history.append(rec)

        current_sig = (tool_name, rec.arg_hash)

        if self.last_tool_signature == current_sig:
            self.consecutive_repeat_count += 1
        else:
            self.consecutive_repeat_count = 1
            self.last_tool_signature = current_sig

        reminder = self._generate_reminder_if_threshold_met(tool_name, self.consecutive_repeat_count, was_denied)
        return self.consecutive_repeat_count, reminder

    def _generate_reminder_if_threshold_met(
        self,
        tool_name: str,
        count: int,
        was_denied: bool
    ) -> Optional[str]:
        """Generates escalating context reminders at 3, 5, and 8 repeats."""
        denial_note = " (including policy-denied attempts)" if was_denied else ""

        if count == 3:
            return (
                f"[LOOP ADVISORY: You have called '{tool_name}' 3 consecutive times with identical arguments{denial_note}. "
                f"Please re-read the previous tool output carefully before repeating this action.]"
            )
        elif count == 5:
            return (
                f"[LOOP WARNING: 5 consecutive identical invocations of '{tool_name}'{denial_note}. "
                f"Your current trajectory is making no forward progress. Change strategy, inspect intermediate files, or break down the sub-goal."
                f"{self.CONTRACT_INVARIANT_REMINDER}]"
            )
        elif count >= 8:
            return (
                f"[LOOP CRITICAL: {count} repeated invocations of '{tool_name}'{denial_note}. "
                f"Execution is locked in a duplicate loop. Conclude this turn, summarize findings, or escalate to human review."
                f"{self.CONTRACT_INVARIANT_REMINDER}]"
            )
        return None
