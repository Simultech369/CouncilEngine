import json
import re
import time
from typing import Dict, Any
from model_gateway import ModelGateway
from model_routes import create_route_attestation
from log_derived_context_engine import LogDerivedContextEngine

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

def query_reasoning_scout(model: str = "deepseek-r1:1.5b", prompt: str = "") -> dict:
    gateway = ModelGateway()
    route = create_route_attestation(
        route_id="route_probe_reasoning_local",
        provider_name="ollama_local",
        endpoint_url=OLLAMA_URL,
        compliance_tier="LOCAL_ONLY_VERIFIED",
        content_retention_days=0,
        zdr_verified=True,
        fallbacks_allowed=False,
        validity_sec=3500
    )

    ctx = LogDerivedContextEngine(session_id=f"reasoning_{model}_{int(time.time())}")
    ctx.append_event("CONFIG_SET", "system", {
        "model_slug": model,
        "model_family": "deepseek" if "deepseek" in model else "generic",
        "provider": "ollama_local",
        "route_id": "route_probe_reasoning_local",
        "temperature": 0.6,
        "max_tokens": 512,
        "provider_parameters": {"top_p": 0.95}
    })
    ctx.append_event("USER_INPUT", "user", {"content": prompt})

    t0 = time.perf_counter()
    try:
        probe_env, raw_output = gateway.dispatch_qualification_probe(
            model_slug=model,
            model_family="deepseek" if "deepseek" in model else "generic",
            provider="ollama_local",
            route_env=route,
            prompt_text=prompt,
            temperature=0.6,
            max_tokens=512,
            context_engine=ctx
        )
        elapsed = round(time.perf_counter() - t0, 2)
        raw_output = raw_output or ""
    except Exception as e:
        return {"model": model, "error": str(e), "elapsed_sec": round(time.perf_counter() - t0, 2)}

    thinking_trace = ""
    clean_body = raw_output
    if "<think>" in raw_output and "</think>" in raw_output:
        parts = raw_output.split("</think>", 1)
        thinking_trace = parts[0].replace("<think>", "").strip()
        clean_body = parts[1].strip()

    if clean_body.startswith("```"):
        clean_body = clean_body.split("\n", 1)[1].rsplit("\n", 1)[0].strip()

    json_match = re.search(r"(\{.*\})", clean_body, re.DOTALL)
    parsed_json = None
    if json_match:
        try:
            parsed_json = json.loads(json_match.group(1))
        except Exception as e:
            parsed_json = {"error": f"JSON decode error: {e}"}

    return {
        "model": model,
        "elapsed_sec": elapsed,
        "thinking_trace_len": len(thinking_trace),
        "thinking_preview": thinking_trace[:150] + "..." if len(thinking_trace) > 150 else thinking_trace,
        "parsed_json": parsed_json,
        "raw_clean_body": clean_body
    }

if __name__ == "__main__":
    task_prompt = (
        "Audit this snippet for SQL injection:\n"
        "1: def query_user(user_id):\n"
        "2:     sql = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "3:     return db.execute(sql)\n\n"
        "Output ONLY a JSON object formatted as:\n"
        "{\n"
        '  "vulnerability_found": true,\n'
        '  "vulnerable_line": 2,\n'
        '  "cwe": "CWE-89"\n'
        "}"
    )
    print(f"\n[Testing Reasoning Extraction on deepseek-r1:1.5b]...")
    res = query_reasoning_scout("deepseek-r1:1.5b", task_prompt)
    print(json.dumps(res, indent=2))
