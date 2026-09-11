import hashlib
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple, Literal
from council_contracts import (
    AuthorityOverrideRecord, DriftObservationReceipt, ReceiptEnvelope
)

class AuthorityRank:
    LIVE_AST_OR_CONTRACT = 1      # Absolute ground truth (raw bytes, git commit, signed MSA)
    VERIFIED_EXECUTION = 2        # Deterministic math, pytest sandbox exit code 0
    HUMAN_OPERATOR = 3            # Current explicit operator instruction
    TOOL_OUTPUT = 4               # Dynamic terminal/curl/MCP output
    SESSION_MEMORY = 5            # Prior turn facts & context memory
    LLM_SUMMARY = 6               # Compressed text representations
    MODEL_OPINION = 7             # Unverified heuristic guesses

class AuthorityConflictDetector:
    """
    Evaluates competing claims between different layers in the system,
    enforces the 7-Level Authority Hierarchy, and computes directional drift.
    """

    MAX_SAFE_DRIFT_VELOCITY_PER_HOUR = 15.0

    def __init__(self):
        self.override_history: List[AuthorityOverrideRecord] = []

    def resolve_conflict(
        self,
        claim_a_text: str,
        claim_a_rank: int,
        claim_b_text: str,
        claim_b_rank: int,
        drift_category: str,
        rationale: str
    ) -> Tuple[str, AuthorityOverrideRecord]:
        """
        Deterministically resolves conflict: strictly lower integer rank number wins.
        Logs the directional override.
        """
        now = time.time()
        conflict_id = f"conf_{uuid.uuid4().hex[:8]}"

        if claim_a_rank <= claim_b_rank:
            winning_text = claim_a_text
            winning_rank = claim_a_rank
            losing_text = claim_b_text
            losing_rank = claim_b_rank
        else:
            winning_text = claim_b_text
            winning_rank = claim_b_rank
            losing_text = claim_a_text
            losing_rank = claim_a_rank

        losing_sha = hashlib.sha256(losing_text.encode("utf-8")).hexdigest()

        record = AuthorityOverrideRecord(
            conflict_id=conflict_id,
            winning_rank=winning_rank,
            losing_rank=losing_rank,
            overridden_claim_sha256=losing_sha,
            resolution_rationale=f"Rank {winning_rank} overrides Rank {losing_rank}: {rationale}",
            drift_category=drift_category,
            timestamp=now
        )
        self.override_history.append(record)
        return winning_text, record

    def compute_drift_observation(self, window_sec: float = 3600.0) -> ReceiptEnvelope[DriftObservationReceipt]:
        now = time.time()
        cutoff = now - window_sec
        recent_records = [r for r in self.override_history if r.timestamp >= cutoff]

        total_conflicts = len(recent_records)
        drift_vector: Dict[str, float] = {}

        for r in recent_records:
            cat = r.drift_category
            drift_vector[cat] = drift_vector.get(cat, 0.0) + 1.0

        # Calculate velocity normalized per hour
        hours = max(window_sec / 3600.0, 0.1)
        velocity = total_conflicts / hours
        alarm_tripped = velocity > self.MAX_SAFE_DRIFT_VELOCITY_PER_HOUR

        receipt = DriftObservationReceipt(
            observation_window_sec=window_sec,
            total_conflicts_resolved=total_conflicts,
            net_drift_vector=drift_vector,
            drift_velocity_per_hour=velocity,
            tide_alarm_triggered=alarm_tripped
        )
        return ReceiptEnvelope.seal(receipt)
