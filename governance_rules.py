"""
Governance Rules & Working Best Practices Engine
Provides strict architectural distinction between:
  1. Formal Council Rules (governed with formal Re-evaluation & Amendment lifecycle)
  2. Working Best Practices (adaptive, lightweight internal developer tradecraft)
"""

import json
import os
import time
import hashlib
from typing import Dict, List, Any, Optional, Literal

RULES_FILE = os.path.join(os.path.dirname(__file__), "FORMAL_RULES_LEDGER.json")
PRACTICES_FILE = os.path.join(os.path.dirname(__file__), "WORKING_BEST_PRACTICES.json")

# ============================================================================
# 1. INITIAL FORMAL RULES SEED
# ============================================================================

INITIAL_FORMAL_RULES = {
    "RULE-SEC-001": {
        "rule_id": "RULE-SEC-001",
        "domain": "security_and_auth",
        "title": "Timing-Safe Webhook Signature Verification",
        "statement": "All incoming webhook signatures (Postmark, Stripe, Sentry, Lemon Squeezy) must be validated using constant-time comparison (crypto.timingSafeEqual) over raw request payloads to prevent side-channel timing attacks.",
        "rationale": "Prevents attacker ability to brute-force authentication signatures byte-by-byte via timing disparities.",
        "status": "ACTIVE",
        "version": 1,
        "created_at": 1787260000.0,
        "history": []
    },
    "RULE-SEC-002": {
        "rule_id": "RULE-SEC-002",
        "domain": "security_and_auth",
        "title": "Strict Public vs Private Secret Isolation",
        "statement": "Public client environment variables (NEXT_PUBLIC_*, VITE_*) must never contain private API keys, backend server tokens, or decryption secrets.",
        "rationale": "Client bundles are fully accessible to end users; any leaked private secret compromises infrastructure.",
        "status": "ACTIVE",
        "version": 1,
        "created_at": 1787260000.0,
        "history": []
    },
    "RULE-SEC-003": {
        "rule_id": "RULE-SEC-003",
        "domain": "security_and_auth",
        "title": "Mandatory Telemetry & Error Data Scrubbing",
        "statement": "Before sending events to external observability or analytics providers (Sentry, Plausible, Umami, PostHog), payloads must pass through recursive data scrubbers stripping prompts, conversation transcripts, authorization headers, cookies, and user PII.",
        "rationale": "Protects user privacy and complies with data protection regulations while preventing prompt leakage.",
        "status": "ACTIVE",
        "version": 1,
        "created_at": 1787260000.0,
        "history": []
    },
    "RULE-SEC-004": {
        "rule_id": "RULE-SEC-004",
        "domain": "security_and_auth",
        "title": "No Raw Tokens in Commands, Transcripts, Files, or Shell History",
        "statement": "Authentication tokens, API keys, and bearer credentials must never be inlined in command-line arguments, tool invocations, conversation transcripts, source code, unencrypted files, or persistent shell history. Credential access must use OS keyring/credential managers (e.g., gh auth login), memory-zeroed SecureString pointers, or runtime environment variables with automated transcript scrubbing.",
        "rationale": "Inlined credentials permanently leak into shell history logs, process table listings (/proc, tasklist), CI logs, and agent transcript records, rendering prompt-level privacy guarantees moot.",
        "status": "ACTIVE",
        "version": 1,
        "created_at": 1787260000.0,
        "history": []
    },
    "RULE-WEB3-001": {
        "rule_id": "RULE-WEB3-001",
        "domain": "web3_and_soroban",
        "title": "Soroban Stroop Precision & Decimal Drift Guard",
        "statement": "All token mathematics and health factor calculations must maintain integer stroop precision (1e-7 tolerance) with deterministic remainder attribution to prevent decimal rounding losses or contract desync.",
        "rationale": "Prevents cumulative rounding errors that could result in frozen funds or exploitable arbitrage.",
        "status": "ACTIVE",
        "version": 1,
        "created_at": 1787260000.0,
        "history": []
    },
    "RULE-WEB3-002": {
        "rule_id": "RULE-WEB3-002",
        "domain": "web3_and_soroban",
        "title": "State Archival and TTL Extension Invariant",
        "statement": "Every persistent or instance storage read/write in Soroban smart contracts must include TTL bump operations (MIN_TTL, BUMP_TTL) to prevent ledger archival of active contract data.",
        "rationale": "Soroban state archiving deletes un-bumped data from active ledger state, breaking contract execution.",
        "status": "ACTIVE",
        "version": 1,
        "created_at": 1787260000.0,
        "history": []
    },
    "RULE-WEB3-003": {
        "rule_id": "RULE-WEB3-003",
        "domain": "web3_and_soroban",
        "title": "Duplicate Settlement Anchoring Prevention",
        "statement": "Settlement references and transaction hashes must map 1:1 with invoice/order records in persistent storage, returning explicit DuplicateSettlementRef errors on duplicate reuse attempts.",
        "rationale": "Prevents double-spend and duplicate invoice settlement fraud across distinct payments.",
        "status": "ACTIVE",
        "version": 1,
        "created_at": 1787260000.0,
        "history": []
    },
    "RULE-MON-001": {
        "rule_id": "RULE-MON-001",
        "domain": "creator_monetization",
        "title": "Strict 10,000 Basis Points (100.00%) Royalty Summation",
        "statement": "Collaborator royalty splits must sum to exactly 10,000 basis points (100.00%) before contract submission, with pro-rata revenue calculated across individual recipients.",
        "rationale": "Ensures all revenue is accounted for with zero unallocated leakage or over-allocation claims.",
        "status": "ACTIVE",
        "version": 1,
        "created_at": 1787260000.0,
        "history": []
    }
}

# ============================================================================
# 2. INITIAL WORKING BEST PRACTICES SEED
# ============================================================================

INITIAL_WORKING_PRACTICES = {
    "PRAC-FE-001": {
        "practice_id": "PRAC-FE-001",
        "category": "frontend_architecture",
        "title": "Next.js App Router Client Boundary Isolation",
        "guideline": "When using `next/dynamic` with `{ ssr: false }`, always place the dynamic import inside a file marked with `'use client'` to satisfy Turbopack/Next.js 16 requirements.",
        "effectiveness_score": 0.98,
        "last_verified": "2026-08-20"
    },
    "PRAC-FE-002": {
        "practice_id": "PRAC-FE-002",
        "category": "resource_lifecycle",
        "title": "DOM and AudioContext Cleanup",
        "guideline": "Always dispose AudioContext nodes, abort controllers, canvas render loops, and window event listeners in React `useEffect` cleanup return functions.",
        "effectiveness_score": 0.95,
        "last_verified": "2026-08-20"
    },
    "PRAC-TEST-001": {
        "practice_id": "PRAC-TEST-001",
        "category": "testing_hygiene",
        "title": "Multi-File Verification Gate Execution",
        "guideline": "Always run both the unit test runner (`vitest run` / `cargo test`) and the full production bundle build (`next build` / `vite build`) before submitting pull requests.",
        "effectiveness_score": 1.0,
        "last_verified": "2026-08-20"
    },
    "PRAC-OPS-001": {
        "practice_id": "PRAC-OPS-001",
        "category": "campaign_diversification",
        "title": "Poly-Work Rail Alternation",
        "guideline": "Spread PR submissions across independent payout rails (Polar Cash, GrantFox FWC26, Dual-Campaign VeriNode) to prevent getting blocked by individual campaign tier caps.",
        "effectiveness_score": 0.99,
        "last_verified": "2026-08-20"
    }
}

# ============================================================================
# 3. LEDGER LOADERS & PERSISTENCE
# ============================================================================

def load_formal_rules() -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(INITIAL_FORMAL_RULES, f, indent=2)
        return INITIAL_FORMAL_RULES
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return INITIAL_FORMAL_RULES

def save_formal_rules(rules: Dict[str, Dict[str, Any]]):
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)

def load_working_practices() -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(PRACTICES_FILE):
        with open(PRACTICES_FILE, "w", encoding="utf-8") as f:
            json.dump(INITIAL_WORKING_PRACTICES, f, indent=2)
        return INITIAL_WORKING_PRACTICES
    try:
        with open(PRACTICES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return INITIAL_WORKING_PRACTICES

def save_working_practices(practices: Dict[str, Dict[str, Any]]):
    with open(PRACTICES_FILE, "w", encoding="utf-8") as f:
        json.dump(practices, f, indent=2)

# ============================================================================
# 4. FORMAL RULE RE-EVALUATION & AMENDMENT PROTOCOL
# ============================================================================

class RuleReevaluationProposal:
    def __init__(
        self,
        rule_id: str,
        proposed_action: Literal["AMEND", "DEPRECATE", "REINSTATE"],
        new_statement: Optional[str],
        justification: str,
        proposer: str
    ):
        self.proposal_id = hashlib.sha256(f"{rule_id}:{proposed_action}:{time.time()}:{justification}".encode()).hexdigest()[:16]
        self.rule_id = rule_id
        self.proposed_action = proposed_action
        self.new_statement = new_statement
        self.justification = justification
        self.proposer = proposer
        self.timestamp = time.time()

class FormalGovernanceEngine:
    """Manages the lifecycle, re-evaluation, and amendment of formal rules."""

    @staticmethod
    def propose_reevaluation(
        rule_id: str,
        proposed_action: Literal["AMEND", "DEPRECATE", "REINSTATE"],
        justification: str,
        proposer: str,
        new_statement: Optional[str] = None
    ) -> Dict[str, Any]:
        rules = load_formal_rules()
        if rule_id not in rules:
            raise ValueError(f"Rule ID '{rule_id}' not found in formal rules ledger.")

        rules[rule_id]["status"] = "UNDER_REEVALUATION"
        save_formal_rules(rules)

        proposal = RuleReevaluationProposal(
            rule_id=rule_id,
            proposed_action=proposed_action,
            new_statement=new_statement,
            justification=justification,
            proposer=proposer
        )

        return {
            "proposal_id": proposal.proposal_id,
            "rule_id": rule_id,
            "proposed_action": proposed_action,
            "new_statement": new_statement,
            "status": "PROPOSED_FOR_COUNCIL_VOTE",
            "justification": justification,
            "proposer": proposer,
            "timestamp": proposal.timestamp
        }

    @staticmethod
    def evaluate_and_seal_amendment(
        proposal_id: str,
        rule_id: str,
        proposed_action: Literal["AMEND", "DEPRECATE", "REINSTATE"],
        new_statement: Optional[str],
        justification: str,
        council_votes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Executes formal council vote on a rule amendment.
        Requires supermajority (>= 67% approvals) from qualified seats.
        """
        rules = load_formal_rules()
        if rule_id not in rules:
            raise ValueError(f"Rule ID '{rule_id}' not found.")

        approvals = sum(1 for v in council_votes if v.get("decision") == "approve")
        total_votes = len(council_votes)
        approval_rate = (approvals / total_votes) if total_votes > 0 else 0.0

        supermajority_met = approval_rate >= 0.667

        current_rule = rules[rule_id]
        old_statement = current_rule["statement"]
        old_version = current_rule["version"]

        if supermajority_met:
            new_status = "AMENDED" if proposed_action == "AMEND" else ("DEPRECATED" if proposed_action == "DEPRECATE" else "ACTIVE")
            new_ver = old_version + 1

            history_entry = {
                "proposal_id": proposal_id,
                "action": proposed_action,
                "previous_statement": old_statement,
                "previous_version": old_version,
                "justification": justification,
                "approval_rate": approval_rate,
                "amended_at": time.time(),
                "council_signatures": [v.get("model_slug") for v in council_votes if v.get("decision") == "approve"]
            }

            current_rule["status"] = "ACTIVE" if proposed_action in ["AMEND", "REINSTATE"] else "DEPRECATED"
            current_rule["version"] = new_ver
            if new_statement and proposed_action == "AMEND":
                current_rule["statement"] = new_statement
            current_rule["history"].append(history_entry)

            rules[rule_id] = current_rule
            save_formal_rules(rules)

            verdict = "AMENDMENT_PASSED_AND_SEALED"
        else:
            current_rule["status"] = "ACTIVE"
            rules[rule_id] = current_rule
            save_formal_rules(rules)
            verdict = "AMENDMENT_REJECTED_REVERTED_TO_ACTIVE"

        return {
            "verdict": verdict,
            "supermajority_met": supermajority_met,
            "approval_rate": approval_rate,
            "rule_id": rule_id,
            "new_version": current_rule["version"],
            "current_status": current_rule["status"]
        }

# ============================================================================
# 5. WORKING BEST PRACTICES API (Lightweight & Adaptive)
# ============================================================================

def record_working_practice(category: str, title: str, guideline: str) -> str:
    practices = load_working_practices()
    practice_id = f"PRAC-{category[:4].upper()}-{len(practices)+1:03d}"
    practices[practice_id] = {
        "practice_id": practice_id,
        "category": category,
        "title": title,
        "guideline": guideline,
        "effectiveness_score": 1.0,
        "last_verified": time.strftime("%Y-%m-%d")
    }
    save_working_practices(practices)
    return practice_id

def update_practice_effectiveness(practice_id: str, score_delta: float):
    practices = load_working_practices()
    if practice_id in practices:
        old_score = practices[practice_id].get("effectiveness_score", 1.0)
        practices[practice_id]["effectiveness_score"] = max(0.1, min(1.0, old_score + score_delta))
        save_working_practices(practices)

# ============================================================================
# 6. UNIFIED PROMPT CONTEXT GENERATOR
# ============================================================================

def get_complete_invariants_and_practices_context() -> str:
    """Formats active formal rules and working best practices with clear separation."""
    rules = load_formal_rules()
    practices = load_working_practices()

    lines = ["\n=================================================================="]
    lines.append("🏛️ SECTION I: FORMAL GOVERNANCE RULES (Active Invariants)")
    lines.append("   (These are formally binding rules governed by the Council)")
    lines.append("==================================================================")
    for rid, r in rules.items():
        if r.get("status") == "ACTIVE":
            lines.append(f"[{r['rule_id']} v{r['version']}] {r['title']} ({r['domain'].upper()}):")
            lines.append(f"   • Rule: {r['statement']}")
            lines.append(f"   • Rationale: {r['rationale']}\n")

    lines.append("==================================================================")
    lines.append("💡 SECTION II: WORKING BEST PRACTICES & AGENT TRADECRAFT")
    lines.append("   (Adaptive heuristics and operational guidelines)")
    lines.append("==================================================================")
    for pid, p in practices.items():
        lines.append(f"[{p['practice_id']}] {p['title']} ({p['category']}):")
        lines.append(f"   • Guideline: {p['guideline']}\n")

    return "\n".join(lines)
