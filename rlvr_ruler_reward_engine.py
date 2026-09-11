import hashlib
import json
import math
import time
from typing import Dict, List, Literal, Optional

from council_contracts import ImmutableContract, ReceiptEnvelope


VerifierKind = Literal[
    "TEST_EXIT_CODE",
    "AST_PARSE",
    "FORMAL_PROOF",
    "RECEIPT_VALIDATION",
    "CUSTOM_CHECK"
]


class VerifiableRewardSignal(ImmutableContract):
    signal_name: str
    verifier_kind: VerifierKind
    passed: bool
    weight: float
    score: float
    evidence_sha256: str


class TrajectoryRewardReceipt(ImmutableContract):
    trajectory_id: str
    objective_id: str
    reward_mode: Literal["RLVR", "RULER_RELATIVE"]
    scalar_reward: float
    normalized_group_reward: Optional[float]
    rank_in_group: Optional[int]
    group_size: Optional[int]
    system_prompt_sha256: str
    trajectory_sha256: str
    signals: List[VerifiableRewardSignal]
    judge_model_slug: Optional[str]
    judge_rationale_sha256: Optional[str]
    emitted_at: float


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_json(value) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return _sha256_text(payload)


def _ensure_unit_score(score: float) -> float:
    score = float(score)
    if score < 0.0 or score > 1.0:
        raise ValueError("reward score must be within [0.0, 1.0]")
    return round(score, 6)


def _ensure_positive_weight(weight: float) -> float:
    weight = float(weight)
    if weight <= 0.0:
        raise ValueError("reward signal weight must be positive")
    return weight


class CouncilRLVRRewardEngine:
    """
    Deterministic reward emitter for compiler/checker-style tasks.
    Produces one scalar reward receipt per trajectory without a learned reward model.
    """

    def score_verifiable_signals(
        self,
        trajectory_id: str,
        objective_id: str,
        system_prompt: str,
        trajectory_text: str,
        checks: List[Dict[str, object]]
    ) -> ReceiptEnvelope[TrajectoryRewardReceipt]:
        if not checks:
            raise ValueError("at least one verifiable reward check is required")

        signals: List[VerifiableRewardSignal] = []
        weighted_sum = 0.0
        total_weight = 0.0

        for check in checks:
            signal_name = str(check.get("name") or check.get("signal_name") or "").strip()
            if not signal_name:
                raise ValueError("reward check missing name")

            weight = _ensure_positive_weight(float(check.get("weight", 1.0)))
            if "score" in check:
                score = _ensure_unit_score(float(check["score"]))
                passed = bool(check.get("passed", score >= 1.0))
            else:
                passed = bool(check.get("passed", False))
                score = 1.0 if passed else 0.0

            verifier_kind = str(check.get("verifier_kind", "CUSTOM_CHECK"))
            if verifier_kind not in VerifierKind.__args__:
                raise ValueError(f"unsupported verifier_kind '{verifier_kind}'")

            evidence_material = check.get("evidence", check.get("evidence_sha256", ""))
            evidence_sha = _sha256_json(evidence_material)
            signal = VerifiableRewardSignal(
                signal_name=signal_name,
                verifier_kind=verifier_kind,
                passed=passed,
                weight=weight,
                score=score,
                evidence_sha256=evidence_sha
            )
            signals.append(signal)
            weighted_sum += score * weight
            total_weight += weight

        scalar_reward = round(weighted_sum / total_weight, 6)
        receipt = TrajectoryRewardReceipt(
            trajectory_id=trajectory_id,
            objective_id=objective_id,
            reward_mode="RLVR",
            scalar_reward=scalar_reward,
            normalized_group_reward=None,
            rank_in_group=None,
            group_size=None,
            system_prompt_sha256=_sha256_text(system_prompt),
            trajectory_sha256=_sha256_text(trajectory_text),
            signals=signals,
            judge_model_slug=None,
            judge_rationale_sha256=None,
            emitted_at=time.time()
        )
        return ReceiptEnvelope.seal(receipt)

    def score_from_execution(
        self,
        trajectory_id: str,
        objective_id: str,
        system_prompt: str,
        trajectory_text: str,
        test_exit_code: int,
        ast_valid: bool,
        receipt_valid: bool,
        formal_proof_verified: Optional[bool] = None
    ) -> ReceiptEnvelope[TrajectoryRewardReceipt]:
        checks: List[Dict[str, object]] = [
            {
                "name": "tests_passed",
                "verifier_kind": "TEST_EXIT_CODE",
                "passed": test_exit_code == 0,
                "weight": 2.0,
                "evidence": {"exit_code": test_exit_code}
            },
            {
                "name": "ast_valid",
                "verifier_kind": "AST_PARSE",
                "passed": ast_valid,
                "weight": 1.0,
                "evidence": {"ast_valid": ast_valid}
            },
            {
                "name": "receipt_valid",
                "verifier_kind": "RECEIPT_VALIDATION",
                "passed": receipt_valid,
                "weight": 1.0,
                "evidence": {"receipt_valid": receipt_valid}
            }
        ]
        if formal_proof_verified is not None:
            checks.append({
                "name": "formal_proof_verified",
                "verifier_kind": "FORMAL_PROOF",
                "passed": formal_proof_verified,
                "weight": 1.0,
                "evidence": {"formal_proof_verified": formal_proof_verified}
            })
        return self.score_verifiable_signals(
            trajectory_id=trajectory_id,
            objective_id=objective_id,
            system_prompt=system_prompt,
            trajectory_text=trajectory_text,
            checks=checks
        )


class CouncilRULERRewardEngine:
    """
    Receipt bridge for RULER-style grouped trajectory judging.
    A judge adapter supplies relative scores; this engine validates and seals one scalar reward per trajectory.
    """

    def score_judged_group(
        self,
        objective_id: str,
        system_prompt: str,
        trajectories_by_id: Dict[str, str],
        judge_scores_by_trajectory_id: Dict[str, float],
        judge_model_slug: str,
        judge_rationale: str = ""
    ) -> List[ReceiptEnvelope[TrajectoryRewardReceipt]]:
        if not trajectories_by_id:
            raise ValueError("at least one trajectory is required")
        if set(trajectories_by_id) != set(judge_scores_by_trajectory_id):
            raise ValueError("judge scores must cover exactly the submitted trajectory ids")

        scores_by_id = {
            trajectory_id: _ensure_unit_score(score)
            for trajectory_id, score in judge_scores_by_trajectory_id.items()
        }
        group_size = len(scores_by_id)
        scores = list(scores_by_id.values())
        mean_score = sum(scores) / group_size
        variance = sum((score - mean_score) ** 2 for score in scores) / group_size
        stddev = math.sqrt(variance)
        ranked_ids = sorted(scores_by_id, key=lambda item: (-scores_by_id[item], item))
        ranks_by_id = {trajectory_id: rank + 1 for rank, trajectory_id in enumerate(ranked_ids)}

        ranking_evidence_sha = _sha256_json({
            "objective_id": objective_id,
            "judge_scores_by_trajectory_id": scores_by_id,
            "judge_model_slug": judge_model_slug
        })
        judge_rationale_sha = _sha256_text(judge_rationale) if judge_rationale else None

        receipts: List[ReceiptEnvelope[TrajectoryRewardReceipt]] = []
        for trajectory_id in sorted(trajectories_by_id):
            score = scores_by_id[trajectory_id]
            normalized = 0.0 if stddev == 0.0 else round((score - mean_score) / stddev, 6)
            signal = VerifiableRewardSignal(
                signal_name="ruler_relative_judge_score",
                verifier_kind="CUSTOM_CHECK",
                passed=score > 0.0,
                weight=1.0,
                score=score,
                evidence_sha256=ranking_evidence_sha
            )
            receipt = TrajectoryRewardReceipt(
                trajectory_id=trajectory_id,
                objective_id=objective_id,
                reward_mode="RULER_RELATIVE",
                scalar_reward=score,
                normalized_group_reward=normalized,
                rank_in_group=ranks_by_id[trajectory_id],
                group_size=group_size,
                system_prompt_sha256=_sha256_text(system_prompt),
                trajectory_sha256=_sha256_text(trajectories_by_id[trajectory_id]),
                signals=[signal],
                judge_model_slug=judge_model_slug,
                judge_rationale_sha256=judge_rationale_sha,
                emitted_at=time.time()
            )
            receipts.append(ReceiptEnvelope.seal(receipt))
        return receipts

    def score_relative_rankings(
        self,
        objective_id: str,
        system_prompt: str,
        trajectories_by_id: Dict[str, str],
        ranked_trajectory_ids: List[str],
        judge_model_slug: str,
        judge_rationale: str = ""
    ) -> List[ReceiptEnvelope[TrajectoryRewardReceipt]]:
        if len(ranked_trajectory_ids) != len(set(ranked_trajectory_ids)):
            raise ValueError("ranked trajectory ids must not contain duplicates")
        if set(trajectories_by_id) != set(ranked_trajectory_ids):
            raise ValueError("ranked trajectory ids must cover exactly the submitted trajectory ids")

        group_size = len(ranked_trajectory_ids)
        if group_size == 1:
            judge_scores = {ranked_trajectory_ids[0]: 1.0}
        else:
            judge_scores = {
                trajectory_id: round((group_size - rank_index - 1) / (group_size - 1), 6)
                for rank_index, trajectory_id in enumerate(ranked_trajectory_ids)
            }
        return self.score_judged_group(
            objective_id=objective_id,
            system_prompt=system_prompt,
            trajectories_by_id=trajectories_by_id,
            judge_scores_by_trajectory_id=judge_scores,
            judge_model_slug=judge_model_slug,
            judge_rationale=judge_rationale
        )
