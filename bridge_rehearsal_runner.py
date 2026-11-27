"""
Offline Node/Python Council Bridge Rehearsal Runner (`bridge_rehearsal_runner.py`).

Validates canonical `dizzy.node_python_council_bridge.request.v1` envelopes using
`dizzy.stable_json.sort_keys.no_whitespace.v1` SHA-256 integrity, classifies tasks via
`AgentTaskRouter`, sanitizes relative paths and verification commands, and emits a
bounded `rehearsal_receipt` (`dizzy.node_python_council_bridge.response.v1`).
"""

import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from task_router import AgentTaskRouter

BRIDGE_REQUEST_SCHEMA = "dizzy.node_python_council_bridge.request.v1"
BRIDGE_RESPONSE_SCHEMA = "dizzy.node_python_council_bridge.response.v1"
BRIDGE_CANONICALIZATION = "dizzy.stable_json.sort_keys.no_whitespace.v1"

ALLOWED_VERIFICATION_COMMANDS = {
    "npm test",
    "npm run check:next",
    "npm run check:docs",
    "npm run check:staging-boundary",
    "npm run test:safety",
    "npm run test:statem-runbook",
    "npm run test:streaming-response",
    "npm run test:bounty-hunter",
}


def _normalize_canonical_value(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"Non-finite float rejected at {path}")
        return value
    if isinstance(value, list):
        return [_normalize_canonical_value(item, f"{path}[{idx}]") for idx, item in enumerate(value)]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key in sorted(value.keys()):
            if not isinstance(key, str) or key == "__proto__":
                raise ValueError(f"Unsafe canonical key rejected at {path}.{key}")
            out[key] = _normalize_canonical_value(value[key], f"{path}.{key}")
        return out
    raise ValueError(f"Unsupported canonical JSON type {type(value).__name__} at {path}")


def canonical_json(value: Any) -> str:
    normalized = _normalize_canonical_value(value)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex_lower(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("sha256_hex_lower requires a string input")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sanitize_relative_paths(raw_paths: List[Any]) -> List[str]:
    sanitized: List[str] = []
    for item in raw_paths:
        rel = str(item or "").strip()
        if not rel or len(rel) > 260:
            raise ValueError(f"Invalid target file length: '{rel}'")
        if rel.startswith("/") or rel.startswith("\\") or "\\" in rel or ".." in rel or ":" in rel[:3]:
            raise ValueError(f"Unsafe target file path rejected: '{rel}'")
        sanitized.append(rel)
    return sanitized


def classify_assigned_lane(bounty_task: Dict[str, Any], router: AgentTaskRouter) -> str:
    title = str(bounty_task.get("title") or "")
    desc = str(bounty_task.get("description") or "")
    combined = f"{title} {desc}".lower()
    if any(tok in combined for tok in ("security", "ssrf", "traversal", "vulnerability", "injection", "cwe")):
        return "SECURITY_REVIEWER"
    route_env = router.route_task(
        objective=f"{title}: {desc}",
        candidate_files=bounty_task.get("target_files") or [],
    )
    if route_env.payload.assignments:
        first_role = route_env.payload.assignments[0].role_id
        if first_role in ("DEBUGGER", "TEST_WRITER"):
            return "BOUNTY_SCOUT"
        return first_role
    return "BOUNTY_SCOUT"


def execute_bridge_rehearsal(request_envelope: Dict[str, Any]) -> Dict[str, Any]:
    if request_envelope.get("schema_version") != BRIDGE_REQUEST_SCHEMA:
        raise ValueError(f"Invalid request schema_version: {request_envelope.get('schema_version')}")

    integrity = request_envelope.get("integrity") or {}
    if integrity.get("canonicalization") != BRIDGE_CANONICALIZATION:
        raise ValueError("Unsupported canonicalization scheme")

    payload = request_envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Bridge payload must be a JSON object")

    computed_sha = sha256_hex_lower(canonical_json(payload))
    expected_sha = str(integrity.get("payload_sha256") or "")
    if not expected_sha or not hmac.compare_digest(computed_sha, expected_sha):
        raise ValueError("Bridge payload SHA-256 integrity mismatch (tamper rejected)")

    bounty_task = payload.get("bounty_task") or {}
    task_sha = str(bounty_task.get("payload_sha256") or "")
    if task_sha and hmac.compare_digest(task_sha.lower(), computed_sha):
        raise ValueError("Hash-scope collision: bounty_task.payload_sha256 must not overload bridge payload hash")

    target_files = sanitize_relative_paths(bounty_task.get("target_files") or [])
    test_cmd = " ".join(str(bounty_task.get("test_command") or "npm test").split())
    if test_cmd not in ALLOWED_VERIFICATION_COMMANDS:
        raise ValueError(f"Disallowed verification command: {test_cmd}")

    router = AgentTaskRouter()
    assigned_lane = classify_assigned_lane(bounty_task, router)

    response_core = {
        "schema_version": BRIDGE_RESPONSE_SCHEMA,
        "request_id": str(request_envelope.get("request_id") or ""),
        "request_payload_sha256": computed_sha,
        "status": "VERIFIED_DISPATCH",
        "receipt_authority": "rehearsal_receipt",
        "runtime_promotion_allowed": False,
        "promotion_receipt_required": True,
        "public_claim_allowed": False,
        "assigned_lane": assigned_lane,
        "sanitized_target_files": target_files,
        "enforced_verification_command": test_cmd,
        "execution_environment": {
            "isolation_mode": "rehearsal_static",
            "execution_mode": "REHEARSAL_ONLY",
            "container_engine": "subprocess_mock",
            "network_isolated": True,
        },
        "proof_boundaries": [
            "sidecar_rehearsal_is_not_runtime_promotion",
            "bridge_payload_hash_verified_against_request",
            "response_stays_at_rehearsal_receipt_authority",
            "public_submission_requires_operator_approval",
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    response_sha = sha256_hex_lower(canonical_json(response_core))
    return {
        **response_core,
        "integrity": {
            "canonicalization": BRIDGE_CANONICALIZATION,
            "response_sha256": response_sha,
        },
    }


def main(argv: List[str]) -> int:
    if len(argv) < 3:
        print("Usage: python bridge_rehearsal_runner.py <input_json> <output_json>", file=sys.stderr)
        return 2
    input_path = Path(argv[1])
    output_path = Path(argv[2])
    request_data = json.loads(input_path.read_text(encoding="utf-8"))
    receipt = execute_bridge_rehearsal(request_data)
    os.makedirs(output_path.parent, exist_ok=True)
    output_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"[CouncilEngine Bridge] VERIFIED_DISPATCH lane={receipt['assigned_lane']} authority={receipt['receipt_authority']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
