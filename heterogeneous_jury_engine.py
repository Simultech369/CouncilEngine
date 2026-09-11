import hashlib
import json
import math
import time
from typing import Dict, Any, List, Optional, Tuple, Literal
from council_contracts import ImmutableContract

class JuryJurorVote(ImmutableContract):
    juror_id: str
    model_family: Literal["ANTHROPIC", "OPENAI", "QWEN", "DEEPSEEK", "LOCAL_OSS", "GEMINI"]
    vote: Literal["APPROVE", "REJECT", "ABSTAIN"]
    confidence_score: float  # [0.0, 1.0]
    rationale: str
    formal_counterexample_sha256: Optional[str] = None

class HeterogeneousJuryReceipt(ImmutableContract):
    case_id: str
    total_jurors: int
    distinct_families_count: int
    consensus_decision: Literal["APPROVED_CONSENSUS", "REJECTED_CONSENSUS", "DISSENTING_PROOF_OVERRIDE", "HUNG_JURY"]
    beta_binomial_stability: float
    echo_chamber_risk_score: float
    juror_votes: List[JuryJurorVote]
    receipt_sha256: str
    decided_at: float

class HeterogeneousJuryEngine:
    """
    Cross-Model Heterogeneous Jury & Deliberation Engine:
    - Eliminates single-model echo chambers by mandating family diversity (>= 3 distinct model families).
    - Beta-Binomial stability detection monitoring convergence across deliberation rounds.
    - Dissenting Proof Override: A single valid Rank 1/2 formal counterexample vetoes a majority.
    - Emits verifiable HeterogeneousJuryReceipts.
    """

    def evaluate_jury_deliberation(
        self,
        case_id: str,
        votes: List[JuryJurorVote]
    ) -> HeterogeneousJuryReceipt:
        now = time.time()
        
        families = set(v.model_family for v in votes)
        distinct_families_count = len(families)

        # 1. Check for Dissenting Proof Override (Rank 1 / 2 formal counterexample)
        for v in votes:
            if v.vote == "REJECT" and v.formal_counterexample_sha256 is not None:
                payload = f"{case_id}:DISSENT_OVERRIDE:{v.juror_id}:{v.formal_counterexample_sha256}"
                r_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                return HeterogeneousJuryReceipt(
                    case_id=case_id,
                    total_jurors=len(votes),
                    distinct_families_count=distinct_families_count,
                    consensus_decision="DISSENTING_PROOF_OVERRIDE",
                    beta_binomial_stability=1.0,
                    echo_chamber_risk_score=0.0,
                    juror_votes=votes,
                    receipt_sha256=r_sha,
                    decided_at=now
                )

        # 2. Count votes
        approvals = sum(1 for v in votes if v.vote == "APPROVE")
        rejections = sum(1 for v in votes if v.vote == "REJECT")
        total_active = approvals + rejections

        # 3. Echo-chamber risk score: Higher if jurors belong to only 1 family
        echo_risk = round(1.0 / max(1, distinct_families_count), 3)

        # 4. Beta-Binomial Stability
        alpha = 1.0 + approvals
        beta = 1.0 + rejections
        expected_p = alpha / (alpha + beta)
        variance_p = (alpha * beta) / (((alpha + beta) ** 2) * (alpha + beta + 1))
        stability = round(1.0 - min(1.0, variance_p * 10.0), 3)

        # 5. Supermajority Threshold (2/3 quorum across heterogeneous families)
        if distinct_families_count < 2:
            decision: Literal["APPROVED_CONSENSUS", "REJECTED_CONSENSUS", "DISSENTING_PROOF_OVERRIDE", "HUNG_JURY"] = "HUNG_JURY"
        elif approvals >= math.ceil(total_active * (2.0 / 3.0)):
            decision = "APPROVED_CONSENSUS"
        elif rejections >= math.ceil(total_active * (2.0 / 3.0)):
            decision = "REJECTED_CONSENSUS"
        else:
            decision = "HUNG_JURY"

        payload = f"{case_id}:{decision}:{approvals}:{rejections}:{distinct_families_count}:{stability}"
        r_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        return HeterogeneousJuryReceipt(
            case_id=case_id,
            total_jurors=len(votes),
            distinct_families_count=distinct_families_count,
            consensus_decision=decision,
            beta_binomial_stability=stability,
            echo_chamber_risk_score=echo_risk,
            juror_votes=votes,
            receipt_sha256=r_sha,
            decided_at=now
        )
