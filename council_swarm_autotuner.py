import ast
import hashlib
import json
import math
import time
from typing import Dict, Any, List, Optional, Tuple, Literal
from council_contracts import ImmutableContract

class SeatHyperparameters(ImmutableContract):
    seat_id: str
    role_type: Literal["FORMAL_PROVER", "COUNCIL_LEADER", "ADVERSARIAL_SCOUT", "SYNTACTIC_PATCHER", "AUDITOR"]
    temperature: float
    top_p: float
    max_tokens: int
    frequency_penalty: float
    presence_penalty: float

class SwarmTuningReceipt(ImmutableContract):
    target_module: str
    ast_entropy_score: float
    difficulty_level: Literal["TRIVIAL", "STANDARD", "COMPLEX", "EXTREME"]
    calibrated_seats: List[SeatHyperparameters]
    receipt_sha256: str
    tuned_at: float

class CouncilSwarmAutoTuner:
    """
    Model Council Swarm Auto-Tuner & Dynamic Hyperparameter Scheduler:
    - Analyzes AST complexity & Shannon syntactic entropy.
    - Dynamically calibrates temperature/top-p per council seat:
        • Formal Provers: T = 0.00, Top-P = 0.95 (Deterministic rigor)
        • Syntactic Patchers: T = 0.10, Top-P = 0.90 (Precise AST edits)
        • Council Leaders: T = 0.20, Top-P = 0.85 (Balanced consensus)
        • Adversarial Scouts: T = 0.70, Top-P = 0.98 (Creative fuzzing / red-teaming)
    - Emits verifiable SwarmTuningReceipts.
    """

    def calculate_ast_entropy(self, source_code: str) -> float:
        """Calculates Shannon entropy over AST node type distribution."""
        try:
            tree = ast.parse(source_code)
            node_types: List[str] = [type(node).__name__ for node in ast.walk(tree)]
            if not node_types:
                return 0.0

            total_nodes = len(node_types)
            freqs = {}
            for t in node_types:
                freqs[t] = freqs.get(t, 0) + 1

            entropy = 0.0
            for count in freqs.values():
                p = count / total_nodes
                entropy -= p * math.log2(p)

            return round(entropy, 3)
        except Exception:
            return 2.500  # Default fallback entropy for unparseable snippets

    def calibrate_swarm(
        self,
        target_module: str,
        source_code: str
    ) -> SwarmTuningReceipt:
        """Calibrates hyperparameters for all Council seats based on AST entropy."""
        entropy = self.calculate_ast_entropy(source_code)

        if entropy < 1.5:
            diff = "TRIVIAL"
        elif entropy < 3.0:
            diff = "STANDARD"
        elif entropy < 4.5:
            diff = "COMPLEX"
        else:
            diff = "EXTREME"

        # Seat 1: Formal Prover (Dafny/Lean4)
        prover_hp = SeatHyperparameters(
            seat_id="seat_formal_prover",
            role_type="FORMAL_PROVER",
            temperature=0.00,
            top_p=0.95,
            max_tokens=4096,
            frequency_penalty=0.0,
            presence_penalty=0.0
        )

        # Seat 2: Syntactic Patcher (Qwen 3.8 / DeepSeek)
        patcher_hp = SeatHyperparameters(
            seat_id="seat_patch_synthesizer",
            role_type="SYNTACTIC_PATCHER",
            temperature=0.10 if diff != "EXTREME" else 0.15,
            top_p=0.90,
            max_tokens=8192,
            frequency_penalty=0.05,
            presence_penalty=0.0
        )

        # Seat 3: Council Leader (Claude 3.7 / GPT-5.5)
        leader_hp = SeatHyperparameters(
            seat_id="seat_council_leader",
            role_type="COUNCIL_LEADER",
            temperature=0.20,
            top_p=0.85,
            max_tokens=4096,
            frequency_penalty=0.0,
            presence_penalty=0.0
        )

        # Seat 4: Adversarial Scout (Jiunsong / Hermes / Phi-4)
        scout_hp = SeatHyperparameters(
            seat_id="seat_adversarial_scout",
            role_type="ADVERSARIAL_SCOUT",
            temperature=0.65 if diff in ("TRIVIAL", "STANDARD") else 0.80,
            top_p=0.98,
            max_tokens=4096,
            frequency_penalty=0.10,
            presence_penalty=0.10
        )

        seats = [prover_hp, patcher_hp, leader_hp, scout_hp]

        payload = f"{target_module}:{entropy}:{diff}:{len(seats)}"
        receipt_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        return SwarmTuningReceipt(
            target_module=target_module,
            ast_entropy_score=entropy,
            difficulty_level=diff,
            calibrated_seats=seats,
            receipt_sha256=receipt_sha,
            tuned_at=time.time()
        )
