import json
import time
from typing import Dict, Any, List
from model_gateway import ModelGateway
from model_routes import create_route_attestation
from log_derived_context_engine import LogDerivedContextEngine

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

ROUTING_POLICY_BLOCK = """
### ROUTING POLICY
- Route by capability, not by aspirational name.
- Use the best available model on this surface.
- If the preferred model is unavailable, choose the best supported fallback and record the downgrade reason.
- Do not hardcode a model name unless this surface has explicitly confirmed it.
- Keep user intent, selected surface, selected model, and downgrade reason aligned to the same live capability registry.
- Treat partial scan excerpts and usage-limit outputs as provisional evidence, not a sealed receipt; refresh live truth before repeating status claims.
"""

ARCHITECTURE_SUMMARY = """
### SUMMARY OF PLANNING & ARCHITECTURE DECISIONS (MODULES 1 - 4)

1. THREE PROJECT LENSES:
   - Lens 1: Bounties (Exploit discovery, SWE-bench, PoC reversal in container sandbox with exit code 0).
   - Lens 2: PBM Rebate (Healthcare analytics, strict PHI air-gap LOCAL_ONLY/ZDR, deterministic financial math ledger).
   - Lens 3: Capability-matched reasoning surface selected by the live registry (autonomous terminal coding agent, MCP tool calling, prompt caching, low-latency streaming remain surface-dependent, not guaranteed).

2. 11-RECEIPT DUAL-CHAIN CRYPTOGRAPHIC ENGINE:
   - Immutable Pydantic v2 receipts (frozen=True, extra="forbid", SHA-256 payload and envelope hashing).
   - Chain A: Model Invocations -> Council Roster -> Vote Supermajority (N>=3 distinct families, ceil(2N/3)).
   - Chain B: Patch AST sanitization (no ../, C:\\, .gitmodules) -> OCI Sandbox (network=none) -> ApplyAuthorization.
   - Windows SQLite WAL spend ledger with SQL trigger enforcing actual_usd <= reserved_usd and hard caps.

3. HARNESS TO ARCHITECTURE MAPPING:
   - Aider / Gitlawb Zero -> Context Slicer & PacketSensitivityReceipt.
   - SWE-agent / OpenHands / free-code -> Sandboxed Patch Repair in container.
   - Promptfoo -> 4-gate Model Qualification Matrix (Benign controls, Grounded bugs, Prompt injection).
   - DSPy -> Family-specific prompt & assertion compiler.
   - Gitlawb openclaude -> Terminal MCP gateway.

4. ANOMALY DETECTION & VERIFICATION DRILLS:
   - AnomalyDetectionReceipt: Model flags an anomaly, but must attach exact line/byte evidence; verifier decides validity.
   - 6-drill fixture set: Authority shifts, stale memory conflicts, routing contradictions, comment injections.

5. DRIVER CAPABILITY REGISTRY & RUNTIME STREAM:
   - ProviderCapabilityRecord: Fail-closed capability registry (unavailable = deny); backend routing, frontend labels, and prompt copy stay aligned to the same live registry.
   - NDJSON/SSE Event Stream for lifecycle observability.
   - Approval Cards for risky actions (patch apply, paid apex calls).
"""

def query_oss_reviewer(model: str, role_lens: str, prompt_focus: str) -> Dict[str, Any]:
    prompt = (
        f"You are a specialized AI system architecture reviewer ({role_lens}).\n"
        f"{ROUTING_POLICY_BLOCK}\n"
        f"Review the following multi-agent system design decisions:\n\n"
        f"{ARCHITECTURE_SUMMARY}\n\n"
        f"Focus specifically on: {prompt_focus}.\n"
        "Identify any architectural blind spots, edge cases, or gaps in this plan.\n"
        "Output strictly a JSON object with this exact format:\n"
        "{\n"
        '  "reviewer_model": "' + model + '",\n'
        '  "verdict": "APPROVE" | "APPROVE_WITH_RESERVATIONS" | "NEEDS_REVISION",\n'
        '  "top_strengths": ["strength 1", "strength 2"],\n'
        '  "critical_blindspots": ["blind spot 1", "blind spot 2"],\n'
        '  "actionable_recommendations": ["recommendation 1", "recommendation 2"]\n'
        "}"
    )

    gateway = ModelGateway()
    route = create_route_attestation(
        route_id="route_oss_review_planning_local",
        provider_name="ollama_local",
        endpoint_url=OLLAMA_URL,
        compliance_tier="LOCAL_ONLY_VERIFIED",
        content_retention_days=0,
        zdr_verified=True,
        fallbacks_allowed=False,
        validity_sec=3500
    )

    ctx = LogDerivedContextEngine(session_id=f"plan_review_{model}_{int(time.time())}")
    ctx.append_event("CONFIG_SET", "system", {
        "model_slug": model,
        "model_family": "qwen" if "qwen" in model else "generic",
        "provider": "ollama_local",
        "route_id": "route_oss_review_planning_local",
        "temperature": 0.2,
        "max_tokens": 768
    })
    ctx.append_event("USER_INPUT", "user", {"content": prompt})

    t0 = time.perf_counter()
    try:
        probe_env, raw = gateway.dispatch_qualification_probe(
            model_slug=model,
            model_family="qwen" if "qwen" in model else "generic",
            provider="ollama_local",
            route_env=route,
            prompt_text=prompt,
            temperature=0.2,
            max_tokens=768,
            context_engine=ctx
        )
        if not raw:
            return {
                "reviewer_model": model,
                "verdict": "ERROR",
                "error": "gateway invocation failed",
                "elapsed_sec": round(time.perf_counter() - t0, 2)
            }
        if "<think>" in raw and "</think>" in raw:
            raw = raw.split("</think>", 1)[1].strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("\n", 1)[0].strip()
        data = json.loads(raw)
        data["elapsed_sec"] = round(time.perf_counter() - t0, 2)
        return data
    except Exception as e:
        return {
            "reviewer_model": model,
            "verdict": "ERROR",
            "error": str(e),
            "elapsed_sec": round(time.perf_counter() - t0, 2)
        }

if __name__ == "__main__":
    for m, l, f in [
        ("qwen2.5-coder:7b", "Lead SWE & Bounty Specialist", "AST verification, patch bounds, Docker sandbox"),
        ("glm4:latest", "Healthcare & Compliance Auditor", "Zero Data Retention (ZDR), spend ledger atomicity"),
        ("deepseek-r1:latest", "Adversarial Fuzzer & Anomaly Lead", "State machine manipulation, receipt forging")
    ]:
        print(f"\n[Querying {m} for {l}]...")
        res = query_oss_reviewer(m, l, f)
        print(json.dumps(res, indent=2))
