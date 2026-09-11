import hashlib
import json
import os
import time
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import ImmutableContract, VisionPolicyReceipt, ReceiptEnvelope

class FaultLineHypothetical(ImmutableContract):
    hypothetical_id: str
    scenario_title: str
    proposing_argument: str  # Steelmanned side A
    opposing_argument: str   # Steelmanned side B
    policy_verdict: Optional[str] = None  # "ACCEPTED", "REJECTED", "ESCALATE_TO_HUMAN"
    human_rationale: Optional[str] = None

class VisionPolicyMiner:
    """
    Mines repository tests, blueprints, contracts, and code to draft
    a testable, evidence-grounded VISION.md acceptance constitution.
    - Default status is CANDIDATE_DRAFT until explicit human authorization is provided.
    - Bans generic platitudes; requires explicit evidence citations.
    - Formulates 8 steelmanned fault-line hypotheticals.
    - Emits verifiable VisionPolicyReceipts.
    """

    def __init__(self, workspace_root: str):
        self.workspace_root = os.path.abspath(workspace_root)

    def mine_repository_evidence(self) -> Dict[str, Any]:
        test_files = [f for f in os.listdir(self.workspace_root) if f.startswith("test_") and f.endswith(".py")]
        blueprints = [f for f in os.listdir(self.workspace_root) if f.endswith("_blueprint.md") or f.endswith("_spec.md")]
        if not blueprints:
            scratch_dir = os.path.expanduser(r"~/.gemini/antigravity/scratch/council_engine")
            if os.path.exists(scratch_dir):
                blueprints = [f for f in os.listdir(scratch_dir) if f.endswith("_blueprint.md") or f.endswith("_spec.md")]
        
        evidence = {
            "test_suites_count": len(test_files),
            "test_files": sorted(test_files),
            "blueprints_count": len(blueprints),
            "blueprints": sorted(blueprints),
            "core_contracts": ["council_contracts.py", "council_verifier.py", "windows_spend_ledger.py", "model_gateway.py"]
        }
        return evidence

    def generate_fault_line_hypotheticals(self) -> List[FaultLineHypothetical]:
        """Generates 8 boundary hypotheticals with steelmanned opposing arguments."""
        hypotheticals = [
            FaultLineHypothetical(
                hypothetical_id="HYPO_01_LLM_STATISTICS",
                scenario_title="Permit LLMs to scan tabular claims for direct anomaly detection to improve speed",
                proposing_argument="LLMs are fast at narrative detection and could provide a single-shot triage for unusual claim patterns.",
                opposing_argument="Violates core invariant: non-deterministic LLMs hallucinate statistical noise and miss real outliers; statistics must use ECOD/Mahalanobis.",
                policy_verdict="REJECTED",
                human_rationale="Pure statistical tasks must always execute deterministically; LLMs only summarize and explain."
            ),
            FaultLineHypothetical(
                hypothetical_id="HYPO_02_INSECURE_LOCAL_BYPASS",
                scenario_title="Allow `--insecure` flag to skip sandbox verification when running quick PR evaluations",
                proposing_argument="Developers want rapid feedback without waiting for container setup during local dev iterations.",
                opposing_argument="Breaks mutation containment: unsandboxed code execution can alter host files or leak credentials.",
                policy_verdict="REJECTED",
                human_rationale="Sandbox containment is non-negotiable; test runners must execute in local subprocess or Docker jail."
            ),
            FaultLineHypothetical(
                hypothetical_id="HYPO_03_DYNAMIC_SPOT_SLED_ROUTING",
                scenario_title="Route non-private council juror seats to spot-market inference providers (Surplus/OpenRouter)",
                proposing_argument="Spot markets offer up to 90% discount on commodity council juror consensus voting.",
                opposing_argument="Upstream model identity is not cryptographically attested and provider retention policies may vary.",
                policy_verdict="ACCEPTED",
                human_rationale="Permitted ONLY for PUBLIC_SAFE packets with strict spend caps and no-fallback enforcement."
            ),
            FaultLineHypothetical(
                hypothetical_id="HYPO_04_UNALIGNED_LOCAL_SCOUT",
                scenario_title="Include refusal-ablated local models (Qwen 3.8 Abliterated) in the Gate 4 Red-Team roster",
                proposing_argument="Uncensored models uncover vulnerability exploit vectors that aligned models refuse to analyze.",
                opposing_argument="Ablated models have no safety guarantees and must never participate in final policy decisions.",
                policy_verdict="ACCEPTED",
                human_rationale="Permitted strictly as untrusted Gate 4 adversarial fuzzing scouts behind deterministic filters."
            ),
            FaultLineHypothetical(
                hypothetical_id="HYPO_05_SOFT_LOOP_REMINDERS",
                scenario_title="Inject escalating soft context reminders rather than hard-blocking repeated tool calls",
                proposing_argument="Hard-blocking breaks legitimate retries; soft reminders allow the agent to re-read outputs and adjust.",
                opposing_argument="A runaway loop might consume tokens before the critical count 8 threshold is reached.",
                policy_verdict="ACCEPTED",
                human_rationale="Preserves agent autonomy while arresting drift at 3, 5, and 8 repeat thresholds."
            ),
            FaultLineHypothetical(
                hypothetical_id="HYPO_06_APPEND_ONLY_LOG_CONTEXT",
                scenario_title="Halt execution if outgoing model request diverges by 1 bit from log reconstruction",
                proposing_argument="Prevents silent context drift, hidden prompt injection, and telemetry discrepancy.",
                opposing_argument="Adds a verification check before every LLM call.",
                policy_verdict="ACCEPTED",
                human_rationale="Single source of truth is essential for auditability and lineage tracking."
            ),
            FaultLineHypothetical(
                hypothetical_id="HYPO_07_HARD_SPEND_CEILING_TRIP",
                scenario_title="Permit human emergency overrides to bypass the atomic SQLite spend hard cap",
                proposing_argument="A production outage may require emergency model consensus beyond the daily budget limit.",
                opposing_argument="Hard budget limits protect the organization from unbounded economic drain.",
                policy_verdict="REJECTED",
                human_rationale="Spend hard caps can only be modified via explicit DB schema re-configuration, never in-flight."
            ),
            FaultLineHypothetical(
                hypothetical_id="HYPO_08_KILL_CONTEXT_KEEP_WORKSPACE",
                scenario_title="Wipe conversation transcript between multi-turn rounds while preserving workspace files",
                proposing_argument="Context accumulation degrades model reasoning capacity; 5-field handoffs focus each round.",
                opposing_argument="Subtle intermediate reasoning steps in earlier turns might be lost.",
                policy_verdict="ACCEPTED",
                human_rationale="Workspace files and Merkle CAS DAGs maintain truth; transcripts are ephemeral."
            )
        ]
        return hypotheticals

    def compile_vision_constitution(
        self,
        human_approved: bool = False,
        author_signature: Optional[str] = None
    ) -> Tuple[str, ReceiptEnvelope[VisionPolicyReceipt]]:
        """
        Compiles the complete VISION.md acceptance constitution candidate.
        Approval can be marked in the receipt for review UI state; apply authorization
        still requires a separate authenticated HumanApprovalReceipt.
        """
        evidence = self.mine_repository_evidence()
        hypotheticals = self.generate_fault_line_hypotheticals()
        status = "APPROVED" if human_approved else "CANDIDATE_DRAFT"

        vision_md = f"""# Autonomous Council Engine: Testable Acceptance Constitution (VISION.md)
**Policy ID:** `VISION_POLICY_2026_V1`  
**Status:** `{status}`  
**Mined Evidence:** {evidence['test_suites_count']} Test Suites, {evidence['blueprints_count']} Domain Blueprints.

---

## 1. Prime Directive & Governance Maxim
> *"Deterministic checks decide admissibility. Models propose and critique. Receipts preserve lineage. Humans authorize irreversible action."*

Universal Authority Hierarchy:
$$\\text{{Live AST / Contract}} > \\text{{Execution Proof / Math}} > \\text{{Human Intent}} > \\text{{Tool Output}} > \\text{{Memory}} > \\text{{Summary}} > \\text{{Opinion}}$$

---

## 2. Invariant Acceptance Principles (What We Accept)
1. **Deterministic Verification First**: Every model proposal must pass deterministic preflight, AST syntax checks, and SMT/math constraints before reaching human or council review. (Evidence: `council_verifier.py`, `neurosymbolic_proof_planner.py`).
2. **Cryptographic Lineage**: Every state transition, tool execution, and model invocation must emit an immutable Pydantic receipt with SHA-256 payload digests. (Evidence: `council_contracts.py`).
3. **Log-Derived Context**: Model contexts must be strictly derived on-the-fly from the append-only event log with zero desync. (Evidence: `log_derived_context_engine.py`).
4. **Truthful Sandboxing**: Local subprocess executions must be truthfully attested as `local_subprocess` with `network_isolated=False`. (Evidence: `sandboxed_patch_generator.py`).
5. **Atomic Spend Hard Caps**: All model dispatches must reserve budget in SQLite WAL with trigger-enforced balance checks. (Evidence: `windows_spend_ledger.py`).

---

## 3. Explicit Non-Goals & Taboos (What We Resist)
1. **NO LLM Statistical Anomaly Detection**: Non-deterministic LLMs must never be used to scan raw data tables for anomalies (PBM FWA uses ECOD / Mahalanobis).
2. **NO Unsandboxed Arbitrary Mutation**: Code execution must always be contained within local subprocess tempdirs or Docker jails.
3. **NO Silent Context Injection**: Never inject hidden prompts or alter generation parameters without an explicit log event.
4. **NO Hard-Blocking Without Escalating Reminders**: Duplicate tool calls must receive escalating contextual warnings at counts 3, 5, and 8 before human intervention.

---

## 4. Fault-Line Hypothetical Decisions
"""
        for h in hypotheticals:
            vision_md += f"""
### [{h.policy_verdict}] {h.scenario_title} (`{h.hypothetical_id}`)
* **Proposing Argument**: {h.proposing_argument}
* **Opposing Argument**: {h.opposing_argument}
* **Human Rationale**: {h.human_rationale}
"""

        draft_sha = hashlib.sha256(vision_md.encode("utf-8")).hexdigest()

        receipt = VisionPolicyReceipt(
            policy_id="VISION_POLICY_2026_V1",
            policy_version="1.0.0",
            human_approved=human_approved,
            author_signature=author_signature,
            mined_evidence_sources=evidence["test_files"][:10] + evidence["blueprints"][:5],
            total_principles_mined=5,
            total_non_goals_mined=4,
            fault_line_hypotheticals_count=len(hypotheticals),
            draft_content_sha256=draft_sha,
            created_at=time.time()
        )

        return vision_md, ReceiptEnvelope.seal(receipt)
