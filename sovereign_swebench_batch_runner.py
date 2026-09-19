import hashlib
import json
import re
import time
from typing import Any, List, Literal, Optional

from council_contracts import (
    ImmutableContract,
    ReceiptEnvelope,
    SubcommitteeConvocationReceipt,
    SubcommitteeEvaluationRecord,
)
from rlvr_ruler_reward_engine import CouncilRLVRRewardEngine
from swebench_patch_synthesizer import SWEBenchPatchSynthesizer


SovereignTaskOutcome = Literal["STATIC_REHEARSAL_ACCEPTED", "REJECTED", "MANUAL_TRIAGE"]
SovereignAuthorityScope = Literal["STATIC_REHEARSAL_ONLY"]

SECRET_LIKE_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9_-]{12,}|gh[opsu]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|Bearer\s+\S+|PRIVATE KEY)",
    re.IGNORECASE,
)


class SovereignSWEBenchTask(ImmutableContract):
    """Minimal local SWE-style repair task for zero-credit batch rehearsal."""

    task_id: str
    source_label: str
    target_file: str
    original_code: str
    search_block: str
    replace_block: str
    objective: str


class SovereignSWEBenchTaskResult(ImmutableContract):
    task_ref: str
    task_id_sha256: str
    target_file_ref: str
    target_file_sha256: str
    outcome: SovereignTaskOutcome
    authority_scope: SovereignAuthorityScope
    rejection_reasons: List[str]
    patch_payload_sha256: Optional[str]
    patch_sha256: Optional[str]
    patch_integrity_score: float
    ast_valid: bool
    static_guardrails_held: bool
    tests_executed: Literal[False]
    model_invoked: Literal[False]
    target_repo_mutated: Literal[False]
    production_authority: Literal[False]
    execution_evidence_status: Literal["NOT_EXECUTED_STATIC_REHEARSAL"]
    subcommittee_payload_sha256: Optional[str]
    reward_payload_sha256: Optional[str]
    reward_signal_names: List[str]
    static_rehearsal_score: float


class SovereignSWEBenchBatchReceipt(ImmutableContract):
    batch_ref: str
    batch_id_sha256: str
    input_manifest_sha256: str
    total_tasks: int
    static_accept_count: int
    rejected_count: int
    manual_triage_count: int
    builder_model_ref: str
    builder_model_sha256: str
    breaker_model_ref: str
    breaker_model_sha256: str
    authority_scope: SovereignAuthorityScope
    local_only: Literal[True]
    network_calls_permitted: Literal[False]
    model_invocation_permitted: Literal[False]
    patch_application_permitted: Literal[False]
    target_repo_mutation_permitted: Literal[False]
    production_authority: Literal[False]
    tests_executed: Literal[False]
    reward_signal_mode: Literal["STATIC_REHEARSAL_SIGNALS_ONLY"]
    min_patch_integrity_score: float
    results: List[SovereignSWEBenchTaskResult]
    emitted_at: float


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_json(value) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return _sha256_text(canonical)


def _task_manifest_sha256(tasks: List[SovereignSWEBenchTask]) -> str:
    return _sha256_json([task.model_dump() for task in tasks])


def _hashed_ref(label: str, value: str) -> str:
    return f"{label}_sha256:{_sha256_text(str(value or ''))[:16]}"


def _bounded_ref(label: str, value: str, max_chars: int = 96) -> str:
    """Return a redacted reference for untrusted operator metadata.

    The current runner treats all external labels as untrusted across receipt
    boundaries, so the readable form is intentionally never preserved.
    """
    return _hashed_ref(label, value)


def _safe_path_ref(value: str, max_chars: int = 120) -> str:
    return _hashed_ref("target_file", value)


class StaticSubcommitteeReviewer:
    """Side-effect-free reviewer used by the static rehearsal runner."""

    DEFAULT_OSS_ROSTER = [
        "static_reviewer_no_model_invoked",
    ]

    def convene_subcommittees_and_seal(
        self,
        convocation_id: str,
        task_id: str,
        proposal: dict,
        rotation_round: int = 1,
    ) -> ReceiptEnvelope[SubcommitteeConvocationReceipt]:
        code = str(proposal.get("code", ""))
        has_secret = bool(SECRET_LIKE_PATTERN.search(code))
        has_path_escape = "../" in code or "..\\" in code
        has_shell = "shell=True" in code
        guardrails_held = not (has_secret or has_path_escape or has_shell)
        verdict = "APPROVE" if guardrails_held else "REJECT"
        summary = (
            "Static reviewer approved: no credential, path-escape, or shell=True marker detected."
            if guardrails_held
            else "Static reviewer rejected: credential, path-escape, or shell=True marker detected."
        )
        evaluations = [
            SubcommitteeEvaluationRecord(
                subcommittee_name="StaticCodeIntegrity",
                assigned_model_slug=self.DEFAULT_OSS_ROSTER[(rotation_round - 1) % len(self.DEFAULT_OSS_ROSTER)],
                evidence_surface_reviewed="Side-effect-free static rehearsal checks",
                verdict=verdict,
                confidence_score=0.75 if guardrails_held else 0.99,
                invariants_checked=[
                    "NO_MODEL_INVOCATION",
                    "NO_NETWORK_CALL",
                    "NO_PATCH_APPLICATION",
                    "NO_SECRET_OR_PATH_ESCAPE_MARKER",
                ],
                findings_summary=summary,
            )
        ]
        digest = _sha256_json({
            "convocation_id": convocation_id,
            "task_id_sha256": _sha256_text(task_id),
            "guardrails_held": guardrails_held,
            "evaluations": [e.model_dump() for e in evaluations],
        })
        receipt = SubcommitteeConvocationReceipt(
            convocation_id=_bounded_ref("convocation_id", convocation_id),
            task_id=_bounded_ref("task_id", task_id),
            subcommittees_convened=["StaticCodeIntegrity"],
            rotation_round=rotation_round,
            overall_verdict="UNANIMOUS_APPROVAL" if guardrails_held else "VETOED",
            guardrails_held=guardrails_held,
            evaluations=evaluations,
            composite_audit_digest_sha256=digest,
            convened_at=time.time(),
        )
        return ReceiptEnvelope.seal(receipt)


class SovereignSWEBenchBatchRunner:
    """
    Deterministic zero-credit rehearsal runner for small SWE-style batches.

    This runner does not download SWE-bench, call Ollama, apply patches to a repo,
    or claim production solve authority. It seals the local batch spine that live
    model generators can feed later: candidate patch -> static integrity -> local
    subcommittee guardrails -> RLVR scalar reward -> batch receipt.
    """

    def __init__(
        self,
        synthesizer: Optional[SWEBenchPatchSynthesizer] = None,
        subcommittee_engine: Optional[Any] = None,
        reward_engine: Optional[CouncilRLVRRewardEngine] = None,
    ):
        self.synthesizer = synthesizer or SWEBenchPatchSynthesizer()
        self.subcommittee_engine = subcommittee_engine or StaticSubcommitteeReviewer()
        self.reward_engine = reward_engine or CouncilRLVRRewardEngine()

    def run_batch(
        self,
        tasks: List[SovereignSWEBenchTask],
        batch_id: str = "local_oss_batch_rehearsal",
        builder_model_slug: str = "qwen2.5-coder:7b",
        breaker_model_slug: str = "mistral:latest",
        min_patch_integrity_score: float = 0.95,
    ) -> ReceiptEnvelope[SovereignSWEBenchBatchReceipt]:
        if not tasks:
            raise ValueError("at least one SWE-style task is required")
        if min_patch_integrity_score < 0.0 or min_patch_integrity_score > 1.0:
            raise ValueError("min_patch_integrity_score must be within [0, 1]")

        results = [
            self._run_task(
                task=task,
                batch_id=batch_id,
                index=index,
                min_patch_integrity_score=min_patch_integrity_score,
            )
            for index, task in enumerate(tasks)
        ]
        accepted = sum(1 for result in results if result.outcome == "STATIC_REHEARSAL_ACCEPTED")
        rejected = sum(1 for result in results if result.outcome == "REJECTED")
        manual = sum(1 for result in results if result.outcome == "MANUAL_TRIAGE")

        receipt = SovereignSWEBenchBatchReceipt(
            batch_ref=_bounded_ref("batch_id", batch_id),
            batch_id_sha256=_sha256_text(batch_id),
            input_manifest_sha256=_task_manifest_sha256(tasks),
            total_tasks=len(tasks),
            static_accept_count=accepted,
            rejected_count=rejected,
            manual_triage_count=manual,
            builder_model_ref=_bounded_ref("builder_model", builder_model_slug),
            builder_model_sha256=_sha256_text(builder_model_slug),
            breaker_model_ref=_bounded_ref("breaker_model", breaker_model_slug),
            breaker_model_sha256=_sha256_text(breaker_model_slug),
            authority_scope="STATIC_REHEARSAL_ONLY",
            local_only=True,
            network_calls_permitted=False,
            model_invocation_permitted=False,
            patch_application_permitted=False,
            target_repo_mutation_permitted=False,
            production_authority=False,
            tests_executed=False,
            reward_signal_mode="STATIC_REHEARSAL_SIGNALS_ONLY",
            min_patch_integrity_score=min_patch_integrity_score,
            results=results,
            emitted_at=time.time(),
        )
        return ReceiptEnvelope.seal(receipt)

    def _run_task(
        self,
        task: SovereignSWEBenchTask,
        batch_id: str,
        index: int,
        min_patch_integrity_score: float,
    ) -> SovereignSWEBenchTaskResult:
        reasons: List[str] = []
        ok, patched_code = self.synthesizer.apply_search_replace_block(
            task.original_code,
            task.search_block,
            task.replace_block,
        )
        if not ok:
            reasons.append("SEARCH_BLOCK_NOT_FOUND")
            return self._rejected_result(task, reasons)

        patch_result = self.synthesizer.evaluate_patch_integrity(
            target_file=task.target_file,
            original_code=task.original_code,
            patched_code=patched_code,
        )
        reasons.extend(patch_result.cwe_violations)
        reasons.extend(patch_result.anti_patterns_detected)
        if not patch_result.ast_valid:
            reasons.append("AST_PARSE_FAILED")
        if patch_result.patch_integrity_score < min_patch_integrity_score:
            reasons.append("PATCH_INTEGRITY_BELOW_THRESHOLD")

        subcommittee_env = self.subcommittee_engine.convene_subcommittees_and_seal(
            convocation_id=f"static_convocation:{_sha256_text(batch_id)[:16]}:{index}:{_sha256_text(task.task_id)[:16]}",
            task_id=f"task:{_sha256_text(task.task_id)[:16]}",
            proposal={"task": task.objective, "code": patched_code},
            rotation_round=index + 1,
        )
        guardrails_held = subcommittee_env.payload.guardrails_held
        if not guardrails_held:
            reasons.append(f"SUBCOMMITTEE_{subcommittee_env.payload.overall_verdict}")

        reward_checks = [
            {
                "name": "static_ast_parse_valid",
                "verifier_kind": "AST_PARSE",
                "passed": patch_result.ast_valid,
                "weight": 1.0,
                "evidence": {"ast_valid": patch_result.ast_valid},
            },
            {
                "name": "static_patch_integrity_threshold_met",
                "verifier_kind": "CUSTOM_CHECK",
                "passed": patch_result.patch_integrity_score >= min_patch_integrity_score,
                "score": patch_result.patch_integrity_score,
                "weight": 1.0,
                "evidence": {
                    "patch_integrity_score": patch_result.patch_integrity_score,
                    "min_patch_integrity_score": min_patch_integrity_score,
                },
            },
            {
                "name": "static_subcommittee_guardrails_held",
                "verifier_kind": "RECEIPT_VALIDATION",
                "passed": guardrails_held,
                "weight": 1.0,
                "evidence": {"subcommittee_payload_sha256": subcommittee_env.payload_sha256},
            },
            {
                "name": "static_rehearsal_boundary_bound",
                "verifier_kind": "CUSTOM_CHECK",
                "passed": True,
                "weight": 1.0,
                "evidence": {
                    "tests_executed": False,
                    "model_invoked": False,
                    "target_repo_mutated": False,
                    "production_authority": False,
                },
            },
        ]
        reward_env = self.reward_engine.score_verifiable_signals(
            trajectory_id=f"static_rehearsal:{_sha256_text(batch_id)[:16]}:{_sha256_text(task.task_id)[:16]}",
            objective_id=_sha256_text(task.objective),
            system_prompt="Local zero-credit SWE batch rehearsal",
            trajectory_text=patch_result.unified_diff,
            checks=reward_checks,
        )

        if not reasons and reward_env.payload.scalar_reward >= 0.8:
            outcome: SovereignTaskOutcome = "STATIC_REHEARSAL_ACCEPTED"
        elif patch_result.ast_valid:
            outcome = "MANUAL_TRIAGE"
        else:
            outcome = "REJECTED"

        return SovereignSWEBenchTaskResult(
            task_ref=_bounded_ref("task_id", task.task_id),
            task_id_sha256=_sha256_text(task.task_id),
            target_file_ref=_safe_path_ref(task.target_file),
            target_file_sha256=_sha256_text(task.target_file),
            outcome=outcome,
            authority_scope="STATIC_REHEARSAL_ONLY",
            rejection_reasons=reasons,
            patch_payload_sha256=patch_result.compute_canonical_sha256(),
            patch_sha256=patch_result.patch_sha256,
            patch_integrity_score=patch_result.patch_integrity_score,
            ast_valid=patch_result.ast_valid,
            static_guardrails_held=guardrails_held,
            tests_executed=False,
            model_invoked=False,
            target_repo_mutated=False,
            production_authority=False,
            execution_evidence_status="NOT_EXECUTED_STATIC_REHEARSAL",
            subcommittee_payload_sha256=subcommittee_env.payload_sha256,
            reward_payload_sha256=reward_env.payload_sha256,
            reward_signal_names=[str(check["name"]) for check in reward_checks],
            static_rehearsal_score=reward_env.payload.scalar_reward,
        )

    def _rejected_result(
        self,
        task: SovereignSWEBenchTask,
        reasons: List[str],
    ) -> SovereignSWEBenchTaskResult:
        return SovereignSWEBenchTaskResult(
            task_ref=_bounded_ref("task_id", task.task_id),
            task_id_sha256=_sha256_text(task.task_id),
            target_file_ref=_safe_path_ref(task.target_file),
            target_file_sha256=_sha256_text(task.target_file),
            outcome="REJECTED",
            authority_scope="STATIC_REHEARSAL_ONLY",
            rejection_reasons=reasons,
            patch_payload_sha256=None,
            patch_sha256=None,
            patch_integrity_score=0.0,
            ast_valid=False,
            static_guardrails_held=False,
            tests_executed=False,
            model_invoked=False,
            target_repo_mutated=False,
            production_authority=False,
            execution_evidence_status="NOT_EXECUTED_STATIC_REHEARSAL",
            subcommittee_payload_sha256=None,
            reward_payload_sha256=None,
            reward_signal_names=[],
            static_rehearsal_score=0.0,
        )
