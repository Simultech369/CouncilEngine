import json
import time
from typing import Dict, Any
from model_gateway import ModelGateway
from model_routes import create_route_attestation
from log_derived_context_engine import LogDerivedContextEngine

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

BRIEFING = """
You are reviewing a multi-agent AI coding & verification architecture for:
1. Bounties (Exploit PoC generation in Docker sandbox, exit code 0)
2. PBM Rebates (Healthcare compliance, LOCAL_ONLY air-gap, SQLite spend ledger)
3. Dizzy (Autonomous agent, MCP tool gateway, fail-closed permissions)

Core Mechanism: 11 cryptographic immutable receipts (Pydantic v2 frozen=True, SHA256 payload and envelope hashes), dual-chain verifier (Chain A: Invocations -> Council Vote; Chain B: Patch AST -> Docker Sandbox -> Apply Auth).
"""

def get_critique(model: str, lens: str) -> Dict[str, Any]:
    prompt = (
        f"{BRIEFING}\n\n"
        f"Lens: {lens}.\n"
        "Critique this design. Output strictly JSON:\n"
        "{\n"
        '  "verdict": "APPROVE" | "APPROVE_WITH_RESERVATIONS",\n'
        '  "key_strength": "string",\n'
        '  "identified_risk": "string",\n'
        '  "concrete_recommendation": "string"\n'
        "}"
    )

    gateway = ModelGateway()
    route = create_route_attestation(
        route_id="route_oss_review_detailed_local",
        provider_name="ollama_local",
        endpoint_url=OLLAMA_URL,
        compliance_tier="LOCAL_ONLY_VERIFIED",
        content_retention_days=0,
        zdr_verified=True,
        fallbacks_allowed=False,
        validity_sec=3500
    )

    ctx = LogDerivedContextEngine(session_id=f"critique_{model}_{int(time.time())}")
    ctx.append_event("CONFIG_SET", "system", {
        "model_slug": model,
        "model_family": "qwen" if "qwen" in model else "generic",
        "provider": "ollama_local",
        "route_id": "route_oss_review_detailed_local",
        "temperature": 0.1,
        "max_tokens": 400
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
            temperature=0.1,
            max_tokens=400,
            context_engine=ctx
        )
        if not raw:
            return {"reviewer": model, "error": "gateway invocation failed", "elapsed_sec": round(time.perf_counter() - t0, 2)}
        if "<think>" in raw and "</think>" in raw:
            raw = raw.split("</think>", 1)[1].strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("\n", 1)[0].strip()
        data = json.loads(raw)
        data["reviewer"] = model
        data["elapsed_sec"] = round(time.perf_counter() - t0, 2)
        return data
    except Exception as e:
        return {"reviewer": model, "error": str(e), "elapsed_sec": round(time.perf_counter() - t0, 2)}

if __name__ == "__main__":
    for m, l in [("qwen2.5-coder:7b", "Code AST & Sandbox"), ("glm4:latest", "Security & Compliance")]:
        print(f"\n[Running critique for {m}]...")
        result = get_critique(m, l)
        print(json.dumps(result, indent=2))
