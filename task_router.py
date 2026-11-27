"""
Agent Task Router for bounded multi-agent delegation.

The router turns broad operator intent into narrow, auditable specialist lanes.
It borrows the Delta-LoRA metaphor only as an orchestration pattern: small,
validated task deltas update shared project state; no model weights are trained
or modified by this module.
"""

import hashlib
import json
import re
import time
from typing import Any, Dict, List, Literal, Optional, Sequence

from council_contracts import ImmutableContract, ReceiptEnvelope

AgentRole = Literal[
    "A2A_PROTOCOL_REVIEWER",
    "ADVERSARIAL_RED_TEAM",
    "DEBUGGER",
    "FORMAL_PROVER",
    "INTEGRATOR",
    "LICENSE_REVIEWER",
    "SECURITY_REVIEWER",
    "SOLIDITY_SEMANTICS_REVIEWER",
    "TEST_WRITER",
    "UI_REVIEWER",
]

TaskRisk = Literal["LOW", "MEDIUM", "HIGH", "L3_HUMAN_REQUIRED"]

OutputContract = Literal[
    "A2A_INTEROP_REPORT",
    "DEBUG_TRACE",
    "FORMAL_PROOF_RECEIPT",
    "INTEGRATION_DECISION",
    "LICENSE_PROVENANCE_REPORT",
    "PATCH_PROPOSAL",
    "SECURITY_FINDING_REPORT",
    "TEST_FIXTURE_PATCH",
    "UI_REVIEW_REPORT",
]


class AgentRoleProfile(ImmutableContract):
    role_id: AgentRole
    responsibility_boundary: str
    non_scope: List[str]
    default_context_fields: List[str]
    output_contract: OutputContract
    validation_gate: str
    final_decision_owner: str


class TaskRouteAssignment(ImmutableContract):
    assignment_id: str
    role_id: AgentRole
    scope_files: List[str]
    context_payload_fields: List[str]
    non_scope: List[str]
    expected_output_contract: OutputContract
    validation_gate: str
    can_mutate_files: bool
    external_disclosure_allowed: bool
    escalation_triggers: List[str]


class AgentTaskRouteReceipt(ImmutableContract):
    task_id: str
    objective: str
    route_strategy: str
    task_classification: List[str]
    risk_tier: TaskRisk
    assignments: List[TaskRouteAssignment]
    integration_order: List[str]
    required_quorum_roles: List[AgentRole]
    final_decision_owner: str
    human_l3_required: bool
    higher_review_recommended: bool
    rejected_overbroad_context: bool
    context_digest_sha256: str
    route_digest_sha256: str
    created_at: float


class AgentTaskRouter:
    """
    Classifies project tasks into small expert lanes with explicit boundaries.

    The router is deterministic and local-only. It does not call external
    models, run shell commands, apply patches, stage files, or approve L3 work.
    """

    MAX_FILES_PER_ASSIGNMENT = 8

    ROLE_PROFILES: Dict[AgentRole, AgentRoleProfile] = {
        "A2A_PROTOCOL_REVIEWER": AgentRoleProfile(
            role_id="A2A_PROTOCOL_REVIEWER",
            responsibility_boundary="Review agent-card, envelope, JSON-RPC, redaction, nonce, and handoff protocol boundaries.",
            non_scope=["Do not grant remote execution authority.", "Do not decide Solidity treasury semantics."],
            default_context_fields=["a2a_schema", "redaction_rules", "allowed_methods", "handoff_manifest_sha256"],
            output_contract="A2A_INTEROP_REPORT",
            validation_gate="python -B -m unittest tools/council/test_external_a2a_adapter.py tools/council/test_a2a_protocol_engine.py",
            final_decision_owner="CouncilIntegrator",
        ),
        "ADVERSARIAL_RED_TEAM": AgentRoleProfile(
            role_id="ADVERSARIAL_RED_TEAM",
            responsibility_boundary="Attempt prompt injection, tool hijack, replay, path traversal, and CWE counterexamples against a narrow surface.",
            non_scope=["Do not patch production code.", "Do not exfiltrate private repo state."],
            default_context_fields=["attack_surface", "sanitized_payload", "expected_fail_closed_behavior"],
            output_contract="SECURITY_FINDING_REPORT",
            validation_gate="python -B -m unittest tools/council/test_adversarial_red_team_engine.py",
            final_decision_owner="CouncilIntegrator",
        ),
        "DEBUGGER": AgentRoleProfile(
            role_id="DEBUGGER",
            responsibility_boundary="Reproduce a failing behavior, isolate root cause, and produce a minimal debug trace.",
            non_scope=["Do not broaden scope after first reproduction.", "Do not make governance or release decisions."],
            default_context_fields=["failing_command", "stderr_excerpt", "touched_files", "last_good_receipt_sha256"],
            output_contract="DEBUG_TRACE",
            validation_gate="Focused failing test must reproduce before patch and pass after patch.",
            final_decision_owner="CouncilIntegrator",
        ),
        "FORMAL_PROVER": AgentRoleProfile(
            role_id="FORMAL_PROVER",
            responsibility_boundary="Encode mathematical invariants and verify solver/proof obligations under explicit assumptions.",
            non_scope=["Do not claim real-world business truth beyond encoded assumptions.", "Do not mutate contracts."],
            default_context_fields=["invariant_statement", "model_assumptions", "solver_constraints", "counterexample_policy"],
            output_contract="FORMAL_PROOF_RECEIPT",
            validation_gate="python -B -m unittest tools/council/test_formal_theorem_prover_engine.py tools/council/test_neurosymbolic_proof_planner.py",
            final_decision_owner="CouncilIntegrator",
        ),
        "INTEGRATOR": AgentRoleProfile(
            role_id="INTEGRATOR",
            responsibility_boundary="Combine validated deltas, check proof boundaries, and decide whether the slice is commit-ready.",
            non_scope=["Do not bypass L3 human authorization.", "Do not hide dissenting findings."],
            default_context_fields=["route_receipt", "validated_outputs", "git_status", "verification_receipt"],
            output_contract="INTEGRATION_DECISION",
            validation_gate="git diff --check plus focused tests for every assigned lane.",
            final_decision_owner="CouncilIntegrator",
        ),
        "LICENSE_REVIEWER": AgentRoleProfile(
            role_id="LICENSE_REVIEWER",
            responsibility_boundary="Check borrowed patterns, license compatibility, attribution, and provenance notes.",
            non_scope=["Do not copy upstream code.", "Do not approve incompatible license intake."],
            default_context_fields=["upstream_url", "license_text", "local_files_inspired", "copied_snippet_sha256"],
            output_contract="LICENSE_PROVENANCE_REPORT",
            validation_gate="License provenance ledger updated or explicit no-copy finding recorded.",
            final_decision_owner="HumanOwner",
        ),
        "SECURITY_REVIEWER": AgentRoleProfile(
            role_id="SECURITY_REVIEWER",
            responsibility_boundary="Review security properties, scanner findings, access boundaries, and privacy/secret handling.",
            non_scope=["Do not author large patches.", "Do not approve deployment or disclosure."],
            default_context_fields=["diff_summary", "scanner_report", "threat_model", "sensitive_data_boundary"],
            output_contract="SECURITY_FINDING_REPORT",
            validation_gate="Slither/Solhint or relevant local guardrail suite must be clean or triaged.",
            final_decision_owner="CouncilIntegrator",
        ),
        "SOLIDITY_SEMANTICS_REVIEWER": AgentRoleProfile(
            role_id="SOLIDITY_SEMANTICS_REVIEWER",
            responsibility_boundary="Review EVM state transitions, token accounting, CEI ordering, roles, and solvency invariants.",
            non_scope=["Do not change off-chain council logic.", "Do not treat style warnings as exploitable findings."],
            default_context_fields=["contract_functions", "state_variables", "scanner_trace", "invariant_tests"],
            output_contract="SECURITY_FINDING_REPORT",
            validation_gate="npx.cmd --no-install hardhat test test/PBMRebateTreasury.security.test.js test/PBMRebateTreasury.fuzz.test.js --no-compile",
            final_decision_owner="HumanOwner",
        ),
        "TEST_WRITER": AgentRoleProfile(
            role_id="TEST_WRITER",
            responsibility_boundary="Convert an accepted risk or bug hypothesis into focused regression, fuzz, or fixture tests.",
            non_scope=["Do not decide production acceptance.", "Do not weaken assertions to make a patch pass."],
            default_context_fields=["expected_behavior", "failure_mode", "target_test_file", "fixture_boundary"],
            output_contract="TEST_FIXTURE_PATCH",
            validation_gate="Focused test file passes alone and as part of its bridge suite.",
            final_decision_owner="CouncilIntegrator",
        ),
        "UI_REVIEWER": AgentRoleProfile(
            role_id="UI_REVIEWER",
            responsibility_boundary="Review dashboard ergonomics, accessibility, visual hierarchy, and lineage display states.",
            non_scope=["Do not invent governance claims in visible UI.", "Do not copy unlicensed visual assets."],
            default_context_fields=["screen_state", "component_paths", "accessibility_expectations", "visual_reference_boundary"],
            output_contract="UI_REVIEW_REPORT",
            validation_gate="Frontend check and viewport smoke verification must pass.",
            final_decision_owner="CouncilIntegrator",
        ),
    }

    KEYWORD_ROUTES: Dict[str, List[AgentRole]] = {
        "a2a": ["A2A_PROTOCOL_REVIEWER", "SECURITY_REVIEWER", "TEST_WRITER"],
        "agent": ["A2A_PROTOCOL_REVIEWER", "TEST_WRITER"],
        "handoff": ["A2A_PROTOCOL_REVIEWER", "INTEGRATOR"],
        "json-rpc": ["A2A_PROTOCOL_REVIEWER", "SECURITY_REVIEWER"],
        "license": ["LICENSE_REVIEWER", "INTEGRATOR"],
        "apache": ["LICENSE_REVIEWER", "INTEGRATOR"],
        "borrow": ["LICENSE_REVIEWER", "SECURITY_REVIEWER"],
        "slither": ["SECURITY_REVIEWER", "SOLIDITY_SEMANTICS_REVIEWER", "TEST_WRITER"],
        "reentrancy": ["SECURITY_REVIEWER", "SOLIDITY_SEMANTICS_REVIEWER", "ADVERSARIAL_RED_TEAM"],
        "cei": ["SOLIDITY_SEMANTICS_REVIEWER", "TEST_WRITER", "SECURITY_REVIEWER"],
        "solidity": ["SOLIDITY_SEMANTICS_REVIEWER", "TEST_WRITER", "SECURITY_REVIEWER"],
        "solvency": ["FORMAL_PROVER", "SOLIDITY_SEMANTICS_REVIEWER", "TEST_WRITER"],
        "mutual credit": ["FORMAL_PROVER", "TEST_WRITER", "SECURITY_REVIEWER"],
        "invariant": ["FORMAL_PROVER", "TEST_WRITER", "ADVERSARIAL_RED_TEAM"],
        "z3": ["FORMAL_PROVER", "TEST_WRITER"],
        "smt": ["FORMAL_PROVER", "TEST_WRITER"],
        "fuzz": ["TEST_WRITER", "ADVERSARIAL_RED_TEAM", "DEBUGGER"],
        "echidna": ["TEST_WRITER", "ADVERSARIAL_RED_TEAM", "SOLIDITY_SEMANTICS_REVIEWER"],
        "mythril": ["SOLIDITY_SEMANTICS_REVIEWER", "SECURITY_REVIEWER"],
        "debug": ["DEBUGGER", "TEST_WRITER"],
        "failing": ["DEBUGGER", "TEST_WRITER"],
        "ui": ["UI_REVIEWER", "TEST_WRITER"],
        "dashboard": ["UI_REVIEWER", "TEST_WRITER"],
    }

    FILE_ROLE_HINTS: Dict[AgentRole, Sequence[str]] = {
        "A2A_PROTOCOL_REVIEWER": ("a2a", "agent", "handoff", "distributed_merkle", "external_a2a"),
        "ADVERSARIAL_RED_TEAM": ("red_team", "chaos", "sandbox", "fuzz", "vulnerability"),
        "DEBUGGER": ("test", "receipt", "verify", "drill"),
        "FORMAL_PROVER": ("formal", "proof", "z3", "smt", "solvency", "foundry", "pbm_rebate"),
        "INTEGRATOR": ("review-context", "cache", "MODEL_INVENTORY", "verify_all", "handoff"),
        "LICENSE_REVIEWER": ("license", "NOTICE", "README", "package", "review-context"),
        "SECURITY_REVIEWER": ("security", "slither", "audit", "guard", "sandbox", "pre_commit", "contracts"),
        "SOLIDITY_SEMANTICS_REVIEWER": ("contracts", ".sol", "foundry", "PBMRebateTreasury", "PharmacyMutualCredit"),
        "TEST_WRITER": ("test", "spec", "fixture", "fuzz"),
        "UI_REVIEWER": ("frontend", "dashboard", "web", "ui", ".tsx", ".css"),
    }

    HIGH_REVIEW_TERMS = (
        "solidity",
        "pbmrebatetreasury",
        "pharmacymutualcredit",
        "cei",
        "reentrancy",
        "upgrade",
        "timelock",
        "mainnet",
        "deploy",
        "hsm",
        "ed25519",
        "external disclosure",
    )

    L3_TERMS = (
        "commit",
        "stage",
        "push",
        "deploy",
        "mainnet",
        "production apply",
        "constitution edit",
        "secret",
        "private key",
        "paid model",
    )

    def route_task(
        self,
        objective: str,
        candidate_files: Optional[List[str]] = None,
        evidence_surfaces: Optional[List[str]] = None,
        task_id: Optional[str] = None,
    ) -> ReceiptEnvelope[AgentTaskRouteReceipt]:
        normalized_objective = self._normalize_text(objective)
        files = self._normalize_paths(candidate_files or [])
        evidence = self._normalize_paths(evidence_surfaces or [])
        task_classes = self._classify(normalized_objective)
        roles = self._select_roles(normalized_objective, files)
        risk_tier = self._risk_tier(normalized_objective, files)
        human_l3_required = risk_tier == "L3_HUMAN_REQUIRED"
        higher_review_recommended = self._higher_review_recommended(normalized_objective, files)
        rejected_overbroad_context = (len(files) > self.MAX_FILES_PER_ASSIGNMENT * 3)

        assignments = [
            self._assignment_for_role(
                task_id=task_id or self._stable_task_id(objective),
                role=role,
                objective=objective,
                candidate_files=files,
                evidence_surfaces=evidence,
                human_l3_required=human_l3_required,
            )
            for role in roles
        ]

        context_digest = self._digest(
            {
                "objective": objective,
                "candidate_files": files,
                "evidence_surfaces": evidence,
                "task_classification": task_classes,
            }
        )
        route_digest = self._digest([assignment.model_dump() for assignment in assignments])

        receipt = AgentTaskRouteReceipt(
            task_id=task_id or self._stable_task_id(objective),
            objective=objective,
            route_strategy="DELTA_LORA_BOUNDED_DELEGATION",
            task_classification=task_classes,
            risk_tier=risk_tier,
            assignments=assignments,
            integration_order=[assignment.assignment_id for assignment in assignments],
            required_quorum_roles=self._required_quorum_roles(roles, higher_review_recommended),
            final_decision_owner="HumanOwner" if human_l3_required or higher_review_recommended else "CouncilIntegrator",
            human_l3_required=human_l3_required,
            higher_review_recommended=higher_review_recommended,
            rejected_overbroad_context=rejected_overbroad_context,
            context_digest_sha256=context_digest,
            route_digest_sha256=route_digest,
            created_at=time.time(),
        )
        return ReceiptEnvelope.seal(receipt)

    def role_profiles(self) -> Dict[AgentRole, AgentRoleProfile]:
        return dict(self.ROLE_PROFILES)

    def _assignment_for_role(
        self,
        *,
        task_id: str,
        role: AgentRole,
        objective: str,
        candidate_files: List[str],
        evidence_surfaces: List[str],
        human_l3_required: bool,
    ) -> TaskRouteAssignment:
        profile = self.ROLE_PROFILES[role]
        scoped_files = self._files_for_role(role, candidate_files, evidence_surfaces)
        assignment_id = f"{task_id}:{role.lower()}"
        external_allowed = role in {"LICENSE_REVIEWER", "UI_REVIEWER"} and not human_l3_required

        return TaskRouteAssignment(
            assignment_id=assignment_id,
            role_id=role,
            scope_files=scoped_files,
            context_payload_fields=profile.default_context_fields,
            non_scope=profile.non_scope,
            expected_output_contract=profile.output_contract,
            validation_gate=profile.validation_gate,
            can_mutate_files=role in {"TEST_WRITER", "DEBUGGER"} and not human_l3_required,
            external_disclosure_allowed=external_allowed,
            escalation_triggers=self._escalation_triggers(role, objective),
        )

    def _files_for_role(
        self,
        role: AgentRole,
        candidate_files: List[str],
        evidence_surfaces: List[str],
    ) -> List[str]:
        combined = candidate_files + evidence_surfaces
        if not combined:
            return []

        hints = self.FILE_ROLE_HINTS[role]
        selected = [
            path for path in combined
            if any(hint.lower() in path.lower() for hint in hints)
        ]

        if not selected and role == "INTEGRATOR":
            selected = combined

        if not selected:
            selected = evidence_surfaces[:]

        return selected[: self.MAX_FILES_PER_ASSIGNMENT]

    def _select_roles(self, normalized_objective: str, files: List[str]) -> List[AgentRole]:
        roles: List[AgentRole] = []

        for keyword, keyword_roles in self.KEYWORD_ROUTES.items():
            if keyword in normalized_objective:
                roles.extend(keyword_roles)

        for path in files:
            lower_path = path.lower()
            if lower_path.endswith(".sol") or "contracts/" in lower_path or "contracts\\" in lower_path:
                roles.extend(["SOLIDITY_SEMANTICS_REVIEWER", "SECURITY_REVIEWER", "TEST_WRITER"])
            if "tools/council" in lower_path or "tools\\council" in lower_path:
                roles.extend(["TEST_WRITER", "SECURITY_REVIEWER"])
            if "a2a" in lower_path:
                roles.append("A2A_PROTOCOL_REVIEWER")

        if not roles:
            roles = ["DEBUGGER", "TEST_WRITER"]

        roles.append("INTEGRATOR")
        return self._dedupe_roles(roles)

    def _classify(self, normalized_objective: str) -> List[str]:
        classes = []
        if any(term in normalized_objective for term in ("a2a", "agent", "handoff", "json-rpc")):
            classes.append("AGENT_INTEROP")
        if any(term in normalized_objective for term in ("solidity", "solvency", "cei", "reentrancy", "contract")):
            classes.append("EVM_TREASURY_SECURITY")
        if any(term in normalized_objective for term in ("z3", "smt", "formal", "proof", "invariant")):
            classes.append("FORMAL_VERIFICATION")
        if any(term in normalized_objective for term in ("license", "apache", "borrow", "upstream")):
            classes.append("LICENSE_PROVENANCE")
        if any(term in normalized_objective for term in ("ui", "dashboard", "beautifului")):
            classes.append("UI_OBSERVABILITY")
        if any(term in normalized_objective for term in ("debug", "failing", "timeout", "error")):
            classes.append("DEBUGGING")
        return classes or ["GENERAL_ENGINEERING"]

    def _risk_tier(self, normalized_objective: str, files: List[str]) -> TaskRisk:
        if any(term in normalized_objective for term in self.L3_TERMS):
            return "L3_HUMAN_REQUIRED"
        if self._higher_review_recommended(normalized_objective, files):
            return "HIGH"
        if any(term in normalized_objective for term in ("security", "privacy", "redaction", "auth", "sandbox", "fuzz")):
            return "MEDIUM"
        return "LOW"

    def _higher_review_recommended(self, normalized_objective: str, files: List[str]) -> bool:
        if any(term in normalized_objective for term in self.HIGH_REVIEW_TERMS):
            return True
        return any(path.lower().endswith(".sol") for path in files)

    def _required_quorum_roles(
        self,
        roles: List[AgentRole],
        higher_review_recommended: bool,
    ) -> List[AgentRole]:
        quorum = ["SECURITY_REVIEWER", "TEST_WRITER", "INTEGRATOR"]
        if higher_review_recommended:
            quorum.append("SOLIDITY_SEMANTICS_REVIEWER")
        for role in roles:
            if role in {"FORMAL_PROVER", "A2A_PROTOCOL_REVIEWER", "LICENSE_REVIEWER"}:
                quorum.append(role)
        return self._dedupe_roles(quorum)

    def _escalation_triggers(self, role: AgentRole, objective: str) -> List[str]:
        triggers = ["validation_gate_fails", "scope_files_exceeded", "output_contract_mismatch"]
        if role in {"SECURITY_REVIEWER", "ADVERSARIAL_RED_TEAM", "SOLIDITY_SEMANTICS_REVIEWER"}:
            triggers.append("possible_exploit_trace")
        if role == "FORMAL_PROVER":
            triggers.append("solver_counterexample_found")
        if role == "LICENSE_REVIEWER":
            triggers.append("copied_code_or_incompatible_license_detected")
        if any(term in self._normalize_text(objective) for term in self.L3_TERMS):
            triggers.append("human_l3_authorization_required")
        return triggers

    @staticmethod
    def _dedupe_roles(roles: Sequence[AgentRole]) -> List[AgentRole]:
        seen = set()
        ordered = []
        for role in roles:
            if role not in seen:
                seen.add(role)
                ordered.append(role)
        return ordered

    @staticmethod
    def _normalize_paths(paths: Sequence[str]) -> List[str]:
        normalized = []
        seen = set()
        for path in paths:
            clean = path.strip().replace("\\", "/")
            if clean and clean not in seen:
                seen.add(clean)
                normalized.append(clean)
        return normalized

    @staticmethod
    def _normalize_text(text: str) -> str:
        return re.sub(r"\s+", " ", text.strip().lower())

    @staticmethod
    def _digest(payload: Any) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def _stable_task_id(cls, objective: str) -> str:
        return "task_" + hashlib.sha256(cls._normalize_text(objective).encode("utf-8")).hexdigest()[:16]


VerificationJobStatus = Literal[
    "running",
    "waiting_for_approval",
    "approved",
    "rejected",
    "resumed",
    "cancelled",
]


class VerificationJobRecord(ImmutableContract):
    """Stateful offline verification job record (never a consumer chat session)."""

    job_id: str
    objective: str
    status: VerificationJobStatus
    risk_tier: TaskRisk
    assigned_roles: List[AgentRole]
    required_quorum_roles: List[AgentRole]
    completed_roles: List[AgentRole]
    tests_passed: bool
    live_container_verified: bool
    promotion_allowed: bool
    promotion_blockers: List[str]
    approval_checkpoint_id: Optional[str] = None
    resume_token: Optional[str] = None
    route_digest_sha256: str
    created_at: float
    updated_at: float


class VerificationJobRegistry:
    """
    Small stateful verification task router for CouncilEngine.
    Accepts offline verification jobs, computes specialist role lanes, tracks completion,
    and reports exact promotion blockers alongside HITL approval state.
    """

    def __init__(self, router: Optional[AgentTaskRouter] = None, approval_gate: Optional[Any] = None):
        self.router = router or AgentTaskRouter()
        self.approval_gate = approval_gate
        self._jobs: Dict[str, Dict[str, Any]] = {}

    def _compute_blockers(self, job: Dict[str, Any]) -> List[str]:
        blockers: List[str] = []
        completed = set(job["completed_roles"])
        for quorum_role in job["required_quorum_roles"]:
            if quorum_role not in completed:
                blockers.append(f"missing_quorum_role:{quorum_role}")
        if not job["tests_passed"]:
            blockers.append("deterministic_test_gate_not_passed")
        if not job["live_container_verified"]:
            blockers.append("live_container_isolation_unverified")
        if job["status"] == "waiting_for_approval":
            blockers.append("human_approval_pending")
        elif job["status"] == "rejected":
            blockers.append("human_approval_rejected")
        elif job["status"] == "cancelled":
            blockers.append("verification_job_cancelled")
        return blockers

    def submit_job(
        self,
        *,
        objective: str,
        candidate_files: Optional[List[str]] = None,
        evidence_surfaces: Optional[List[str]] = None,
        job_id: Optional[str] = None,
        require_promotion_approval: bool = False,
        tests_passed: bool = False,
        live_container_verified: bool = False,
        now: Optional[float] = None,
    ) -> VerificationJobRecord:
        ts = time.time() if now is None else float(now)
        route_env = self.router.route_task(
            objective=objective,
            candidate_files=candidate_files,
            evidence_surfaces=evidence_surfaces,
            task_id=job_id,
        )
        route = route_env.payload
        needs_hitl = bool(require_promotion_approval or route.human_l3_required or route.higher_review_recommended)

        status: VerificationJobStatus = "running"
        checkpoint_id: Optional[str] = None
        resume_token: Optional[str] = None

        if needs_hitl and self.approval_gate is not None:
            cp = self.approval_gate.request_approval(
                subject_type="COUNCIL_VERIFICATION_PROMOTION",
                subject_payload_sha256=route.route_digest_sha256,
                requested_authority="promotion_receipt",
                job_id=route.task_id,
                saved_progress={
                    "objective": objective,
                    "assigned_roles": [a.role_id for a in route.assignments],
                },
                reason=f"Risk tier {route.risk_tier} requires human promotion sign-off",
                now=ts,
            )
            status = cp.workflow_state
            checkpoint_id = cp.checkpoint_id
            resume_token = cp.resume_token
        elif needs_hitl:
            status = "waiting_for_approval"

        raw_job: Dict[str, Any] = {
            "job_id": route.task_id,
            "objective": objective,
            "status": status,
            "risk_tier": route.risk_tier,
            "assigned_roles": [a.role_id for a in route.assignments],
            "required_quorum_roles": list(route.required_quorum_roles),
            "completed_roles": [],
            "tests_passed": bool(tests_passed),
            "live_container_verified": bool(live_container_verified),
            "approval_checkpoint_id": checkpoint_id,
            "resume_token": resume_token,
            "route_digest_sha256": route.route_digest_sha256,
            "created_at": ts,
            "updated_at": ts,
        }
        blockers = self._compute_blockers(raw_job)
        raw_job["promotion_blockers"] = blockers
        raw_job["promotion_allowed"] = (len(blockers) == 0 and raw_job["status"] in ("approved", "resumed"))
        self._jobs[route.task_id] = raw_job
        return VerificationJobRecord(**raw_job)

    def update_job_evidence(
        self,
        job_id: str,
        *,
        completed_roles: Optional[Sequence[AgentRole]] = None,
        tests_passed: Optional[bool] = None,
        live_container_verified: Optional[bool] = None,
        now: Optional[float] = None,
    ) -> VerificationJobRecord:
        if job_id not in self._jobs:
            raise KeyError(f"Verification job '{job_id}' not found")
        ts = time.time() if now is None else float(now)
        job = dict(self._jobs[job_id])
        if completed_roles is not None:
            merged = list(job["completed_roles"]) + list(completed_roles)
            job["completed_roles"] = self.router._dedupe_roles(merged)
        if tests_passed is not None:
            job["tests_passed"] = bool(tests_passed)
        if live_container_verified is not None:
            job["live_container_verified"] = bool(live_container_verified)
        self._sync_approval_state(job)
        job["updated_at"] = ts
        job["promotion_blockers"] = self._compute_blockers(job)
        job["promotion_allowed"] = (len(job["promotion_blockers"]) == 0 and job["status"] in ("approved", "resumed"))
        self._jobs[job_id] = job
        return VerificationJobRecord(**job)

    def _sync_approval_state(self, job: Dict[str, Any]) -> None:
        cp_id = job.get("approval_checkpoint_id")
        if cp_id and self.approval_gate is not None and cp_id in self.approval_gate.checkpoints:
            cp = self.approval_gate.checkpoints[cp_id]
            job["status"] = cp["workflow_state"]

    def get_job(self, job_id: str) -> VerificationJobRecord:
        if job_id not in self._jobs:
            raise KeyError(f"Verification job '{job_id}' not found")
        job = dict(self._jobs[job_id])
        self._sync_approval_state(job)
        job["promotion_blockers"] = self._compute_blockers(job)
        job["promotion_allowed"] = (len(job["promotion_blockers"]) == 0 and job["status"] in ("approved", "resumed"))
        self._jobs[job_id] = job
        return VerificationJobRecord(**job)

    def list_jobs(self) -> List[VerificationJobRecord]:
        return [self.get_job(jid) for jid in self._jobs]


