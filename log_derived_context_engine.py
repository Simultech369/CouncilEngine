import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import (
    ImmutableContract, LogReconstructionReceipt, RouteAttestationReceipt, ReceiptEnvelope
)

class LogReconstructionDesyncError(Exception):
    """Raised when an outgoing LLM request context, route attestation, or wire payload does not strictly match a fresh derivation from the append-only event log."""
    pass

class SessionEvent(ImmutableContract):
    event_id: str
    event_type: str  # "SYSTEM_PROMPT", "USER_INPUT", "ASSISTANT_REPLY", "TOOL_CALL", "TOOL_OUTPUT", "HANDOFF", "CONFIG_SET"
    author: str
    payload: Dict[str, Any]
    timestamp: float

class LogDerivedContextEngine:
    """
    Append-Only Event Log & Context Derivation Engine:
    - Derives all model request contexts, tool schemas, route bindings, and wire payloads on-the-fly from the event log.
    - Intercepts outgoing LLM payloads and asserts bit-exact wire-payload equality across:
      (model, messages/prompt, temperature, max_tokens, response_format, tools, provider_parameters/options).
    - Asserts route attestation equality against the log's CONFIG_SET (route_id, provider).
    - Emits verifiable LogReconstructionReceipts.
    """

    def __init__(self, session_id: str = "default_session"):
        self.session_id = session_id
        self.event_log: List[SessionEvent] = []

    def append_event(self, event_type: str, author: str, payload: Dict[str, Any]) -> SessionEvent:
        """Appends a new immutable event to the log."""
        ev_id = f"ev_{len(self.event_log):05d}_{hashlib.sha256(json.dumps(payload, sort_keys=True).encode('utf-8')).hexdigest()[:8]}"
        ev = SessionEvent(
            event_id=ev_id,
            event_type=event_type,
            author=author,
            payload=payload,
            timestamp=time.time()
        )
        self.event_log.append(ev)
        return ev

    def derive_model_context(self) -> Dict[str, Any]:
        """Derives the exact model prompt context, system instructions, route, tools, and parameters from the event log."""
        system_prompt = ""
        messages = []
        cur_model_slug = "default-model"
        cur_model_family = "generic"
        cur_provider = "ollama_local"
        cur_route_id = "default-route"
        cur_temp = 0.1
        cur_max_tokens = 512
        cur_resp_format = {"type": "json_object"}
        cur_tool_schemas = []
        cur_provider_params = {}

        for ev in self.event_log:
            if ev.event_type == "SYSTEM_PROMPT":
                system_prompt = ev.payload.get("content", system_prompt)
            elif ev.event_type == "CONFIG_SET":
                if "model_slug" in ev.payload:
                    cur_model_slug = ev.payload["model_slug"]
                if "model_family" in ev.payload:
                    cur_model_family = ev.payload["model_family"]
                if "provider" in ev.payload:
                    cur_provider = ev.payload["provider"]
                if "route_id" in ev.payload:
                    cur_route_id = ev.payload["route_id"]
                if "temperature" in ev.payload:
                    cur_temp = ev.payload["temperature"]
                if "max_tokens" in ev.payload:
                    cur_max_tokens = ev.payload["max_tokens"]
                if "response_format" in ev.payload:
                    cur_resp_format = ev.payload["response_format"]
                if "tool_schemas" in ev.payload:
                    cur_tool_schemas = ev.payload["tool_schemas"]
                if "provider_parameters" in ev.payload:
                    cur_provider_params.update(ev.payload["provider_parameters"])
                if "system_prompt" in ev.payload:
                    system_prompt = ev.payload["system_prompt"]
                for k, v in ev.payload.items():
                    if k not in ["model_slug", "model_family", "provider", "route_id", "temperature", "max_tokens", "response_format", "tool_schemas", "provider_parameters", "system_prompt"]:
                        cur_provider_params[k] = v
            elif ev.event_type == "USER_INPUT":
                messages.append({"role": "user", "content": ev.payload.get("content", "")})
            elif ev.event_type == "ASSISTANT_REPLY":
                messages.append({"role": "assistant", "content": ev.payload.get("content", "")})
            elif ev.event_type == "TOOL_CALL":
                messages.append({
                    "role": "assistant",
                    "tool_calls": [{
                        "name": ev.payload.get("tool_name", ""),
                        "arguments": ev.payload.get("arguments", {})
                    }]
                })
            elif ev.event_type == "TOOL_OUTPUT":
                messages.append({
                    "role": "tool",
                    "name": ev.payload.get("tool_name", ""),
                    "content": ev.payload.get("output", "")
                })
            elif ev.event_type == "HANDOFF":
                handoff_text = (
                    f"--- ROUND HANDOFF (Round {ev.payload.get('round_index', 1)}) ---\n"
                    f"Status: {ev.payload.get('status', 'IN_PROGRESS')}\n"
                    f"Summary: {ev.payload.get('summary', '')}\n"
                    f"Next Steps: {', '.join(ev.payload.get('next_steps', []))}"
                )
                messages.append({"role": "system", "content": handoff_text})

        context_obj = {
            "session_id": self.session_id,
            "model_slug": cur_model_slug,
            "model_family": cur_model_family,
            "provider": cur_provider,
            "route_id": cur_route_id,
            "temperature": cur_temp,
            "max_tokens": cur_max_tokens,
            "response_format": cur_resp_format,
            "tool_schemas": cur_tool_schemas,
            "provider_parameters": cur_provider_params,
            "system_prompt": system_prompt,
            "messages": messages,
            "event_count": len(self.event_log)
        }
        return context_obj

    def derive_wire_payload(self, protocol_type: str = "openai") -> Dict[str, Any]:
        """Derives the exact serialized JSON payload expected on the wire for the given protocol."""
        context = self.derive_model_context()
        if protocol_type == "openai":
            all_messages = []
            if context["system_prompt"]:
                all_messages.append({"role": "system", "content": context["system_prompt"]})
            all_messages.extend(context["messages"])

            wire = {
                "model": context["model_slug"],
                "messages": all_messages,
                "temperature": context["temperature"],
                "response_format": context["response_format"]
            }
            if context.get("max_tokens"):
                wire["max_tokens"] = context["max_tokens"]
            if context.get("tool_schemas"):
                wire["tools"] = context["tool_schemas"]
            if context.get("provider_parameters"):
                for k, v in context["provider_parameters"].items():
                    wire[k] = v
            return wire
        else:
            # Ollama protocol
            prompt_parts = []
            if context["system_prompt"]:
                prompt_parts.append(f"System: {context['system_prompt']}")
            for m in context["messages"]:
                prompt_parts.append(m.get("content", ""))
            full_prompt = "\n\n".join(prompt_parts) if prompt_parts else ""
            options = {"temperature": context["temperature"], "num_predict": context["max_tokens"]}
            if context.get("provider_parameters"):
                options.update(context["provider_parameters"])
            wire = {
                "model": context["model_slug"],
                "prompt": full_prompt,
                "stream": False,
                "format": "json",
                "options": options
            }
            return wire

    def verify_and_guard_dispatch(
        self,
        actual_wire_payload: Dict[str, Any],
        route_env: Optional[ReceiptEnvelope[RouteAttestationReceipt]] = None,
        protocol_type: str = "openai",
        raise_on_desync: bool = True
    ) -> ReceiptEnvelope[LogReconstructionReceipt]:
        """
        Compares the actual outgoing wire payload and route attestation against a fresh derivation from the log.
        Throws LogReconstructionDesyncError on any field or route discrepancy.
        """
        context = self.derive_model_context()
        derived_wire = self.derive_wire_payload(protocol_type)

        derived_json = json.dumps(derived_wire, sort_keys=True)
        derived_sha = hashlib.sha256(derived_json.encode("utf-8")).hexdigest()

        actual_json = json.dumps(actual_wire_payload, sort_keys=True)
        actual_sha = hashlib.sha256(actual_json.encode("utf-8")).hexdigest()

        mismatches = []
        all_keys = set(derived_wire.keys()).union(set(actual_wire_payload.keys()))
        for k in all_keys:
            if derived_wire.get(k) != actual_wire_payload.get(k):
                mismatches.append(f"wire_field:{k} (expected {derived_wire.get(k)!r}, got {actual_wire_payload.get(k)!r})")

        # Route attestation verification
        if route_env:
            route = route_env.payload
            if context.get("route_id") and context["route_id"] not in ["default-route", ""]:
                if route.route_id != context["route_id"]:
                    mismatches.append(f"route_id_drift (expected {context['route_id']!r}, got {route.route_id!r})")
            if context.get("provider") and context["provider"] not in ["generic", ""]:
                if route.provider_name != context["provider"]:
                    mismatches.append(f"provider_drift (expected {context['provider']!r}, got {route.provider_name!r})")

        desync = len(mismatches) > 0 or (derived_sha != actual_sha)

        receipt = LogReconstructionReceipt(
            session_id=self.session_id,
            event_log_length=len(self.event_log),
            derived_messages_count=len(context["messages"]),
            derived_context_sha256=derived_sha,
            request_context_sha256=actual_sha,
            desync_detected=desync,
            desync_field_mismatches=mismatches,
            verified_at=time.time()
        )
        receipt_env = ReceiptEnvelope.seal(receipt)

        if desync and raise_on_desync:
            raise LogReconstructionDesyncError(
                f"Log-Reconstruction Desync Detected in session '{self.session_id}': "
                f"Mismatches: {mismatches} (Derived SHA: {derived_sha[:8]}, Actual SHA: {actual_sha[:8]})"
            )

        return receipt_env
