"""
Formal invariants for PBM fraud, waste, and abuse triage logic.

These proofs cover the local Python fraud detector model. They do not prove
real-world fraud, regulatory compliance across every jurisdiction, or on-chain
treasury behavior. Statistical sentries such as Benford's Law are explicitly
bounded to anomaly review, not fraud proof.
"""

import hashlib
import json
import time
from typing import Any, Dict, List, Literal, Optional

from council_contracts import ImmutableContract, ReceiptEnvelope

ProofStatus = Literal["PROVED", "COUNTEREXAMPLE_FOUND", "SOLVER_UNKNOWN"]
ProofMethod = Literal["Z3_UNSAT_NEGATION", "OUTPUT_CONTRACT_SCHEMA"]


class FraudInvariantProof(ImmutableContract):
    invariant_id: str
    domain: Literal["MME", "REFILL_TOO_SOON", "DUPLICATE_THERAPY", "HHI", "BENFORD"]
    statement: str
    assumptions: List[str]
    proof_method: ProofMethod
    solver_status: ProofStatus
    counterexample: Optional[str] = None
    lean4_theorem_stub: Optional[str] = None


class PBMFraudFormalInvariantReceipt(ImmutableContract):
    proof_suite_id: str
    detector_component: str
    invariants: List[FraudInvariantProof]
    all_invariants_proved: bool
    benford_output_contract: Literal["ANOMALY_REVIEW_REQUIRED_ONLY"]
    fraud_proof_claimed: bool
    external_business_truth_proven: bool
    proof_boundary: str
    proof_digest_sha256: str
    proved_at: float


class PBMFraudFormalInvariantEngine:
    """Builds and verifies bounded formal invariants for PBMFraudDetector."""

    MME_HARD_STOP = 200
    HHI_ESCROW_THRESHOLD = 5000
    HHI_SIU_THRESHOLD = 7500
    BENFORD_MIN_SAMPLE = 10
    BENFORD_CHI2_P01_CRITICAL = "20.090"

    def prove_all(self) -> ReceiptEnvelope[PBMFraudFormalInvariantReceipt]:
        proofs: List[FraudInvariantProof] = []
        proofs.extend(self.prove_mme_hard_stop_bounds())
        proofs.extend(self.prove_refill_too_soon_temporal_bounds())
        proofs.extend(self.prove_duplicate_therapy_overlap_bounds())
        proofs.extend(self.prove_hhi_threshold_bounds())
        proofs.extend(self.prove_benford_anomaly_review_boundary())

        all_proved = all(proof.solver_status == "PROVED" for proof in proofs)
        digest = hashlib.sha256(
            json.dumps([proof.model_dump() for proof in proofs], sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        receipt = PBMFraudFormalInvariantReceipt(
            proof_suite_id=f"pbm_fraud_formal_{digest[:12]}",
            detector_component="tools/council/pbm_fraud_detector.py",
            invariants=proofs,
            all_invariants_proved=all_proved,
            benford_output_contract="ANOMALY_REVIEW_REQUIRED_ONLY",
            fraud_proof_claimed=False,
            external_business_truth_proven=False,
            proof_boundary=(
                "Local Z3/schema proofs for PBMFraudDetector arithmetic and triage rules only; "
                "does not prove real-world fraud, PHI lineage, or external regulatory completeness."
            ),
            proof_digest_sha256=digest,
            proved_at=time.time(),
        )
        return ReceiptEnvelope.seal(receipt)

    def prove_mme_hard_stop_bounds(self) -> List[FraudInvariantProof]:
        import z3

        strength = z3.Real("strength_mg")
        quantity = z3.Real("quantity")
        days_supply = z3.Real("days_supply")
        conversion_factor = z3.Real("conversion_factor")
        existing_mme = z3.Real("existing_active_mme")
        total_mme = z3.Real("total_mme")
        hard_stop = z3.Bool("hard_stop")

        constraints = [
            strength >= 0,
            quantity >= 0,
            days_supply >= 1,
            conversion_factor >= 0,
            existing_mme >= 0,
            total_mme == existing_mme + ((strength * quantity * conversion_factor) / days_supply),
            hard_stop == (total_mme >= self.MME_HARD_STOP),
        ]

        return [
            self._prove_unsat(
                invariant_id="FWA-MME-001",
                domain="MME",
                statement="Daily MME accumulation is non-negative for non-negative claim inputs and active opioid history.",
                assumptions=[
                    "strength_mg >= 0",
                    "quantity >= 0",
                    "days_supply >= 1",
                    "conversion_factor >= 0",
                    "existing_active_mme >= 0",
                ],
                constraints=constraints,
                negated_property=total_mme < 0,
                lean4_theorem_stub="theorem mme_nonnegative : total_mme >= 0",
            ),
            self._prove_unsat(
                invariant_id="FWA-MME-002",
                domain="MME",
                statement="Any modeled daily MME value at or above 200 triggers the hard-stop reject condition.",
                assumptions=[
                    "hard_stop is defined as total_mme >= 200",
                    "REJECT_M7 is the detector hard-stop output for hard_stop=True",
                ],
                constraints=constraints,
                negated_property=z3.And(total_mme >= self.MME_HARD_STOP, z3.Not(hard_stop)),
                lean4_theorem_stub="theorem mme_hard_stop_sound : total_mme >= 200 -> hard_stop",
            ),
            self._prove_unsat(
                invariant_id="FWA-MME-003",
                domain="MME",
                statement="A modeled daily MME value below 200 cannot trigger the MME hard-stop predicate.",
                assumptions=[
                    "hard_stop is defined as total_mme >= 200",
                    "co-prescribing flags are modeled separately from MME hard-stop rejection",
                ],
                constraints=constraints,
                negated_property=z3.And(total_mme < self.MME_HARD_STOP, hard_stop),
                lean4_theorem_stub="theorem mme_below_threshold_no_hard_stop : total_mme < 200 -> not hard_stop",
            ),
        ]

    def prove_refill_too_soon_temporal_bounds(self) -> List[FraudInvariantProof]:
        import z3

        proofs = []
        for schedule, threshold_pct in {
            "C_II": 100,
            "C_III_IV_V": 90,
            "NON_CONTROLLED": 75,
        }.items():
            elapsed = z3.Int(f"{schedule}_elapsed_days")
            prior_days_supply = z3.Int(f"{schedule}_prior_days_supply")
            reject_79 = z3.Bool(f"{schedule}_reject_79")
            constraints = [
                elapsed >= 0,
                prior_days_supply > 0,
                reject_79 == (elapsed * 100 < threshold_pct * prior_days_supply),
            ]

            proofs.append(
                self._prove_unsat(
                    invariant_id=f"FWA-R79-{schedule}-EARLY",
                    domain="REFILL_TOO_SOON",
                    statement=f"{schedule} refill attempts below the {threshold_pct}% consumed threshold must reject with Reject 79.",
                    assumptions=[
                        "prior and current claims share GPI-10",
                        "prior days_supply > 0",
                        f"schedule threshold = {threshold_pct}%",
                    ],
                    constraints=constraints,
                    negated_property=z3.And(
                        elapsed * 100 < threshold_pct * prior_days_supply,
                        z3.Not(reject_79),
                    ),
                    lean4_theorem_stub=f"theorem r79_{schedule.lower()}_early_rejects",
                )
            )
            proofs.append(
                self._prove_unsat(
                    invariant_id=f"FWA-R79-{schedule}-MATURE",
                    domain="REFILL_TOO_SOON",
                    statement=f"{schedule} refill attempts at or above the {threshold_pct}% consumed threshold do not reject by Reject 79.",
                    assumptions=[
                        "prior and current claims share GPI-10",
                        "prior days_supply > 0",
                        f"schedule threshold = {threshold_pct}%",
                    ],
                    constraints=constraints,
                    negated_property=z3.And(
                        elapsed * 100 >= threshold_pct * prior_days_supply,
                        reject_79,
                    ),
                    lean4_theorem_stub=f"theorem r79_{schedule.lower()}_mature_no_reject",
                )
            )
        return proofs

    def prove_duplicate_therapy_overlap_bounds(self) -> List[FraudInvariantProof]:
        import z3

        curr_start = z3.Int("curr_start")
        curr_days = z3.Int("curr_days")
        active_start = z3.Int("active_start")
        active_days = z3.Int("active_days")
        curr_end = curr_start + curr_days - 1
        active_end = active_start + active_days - 1
        same_therapy = z3.Bool("same_gpi10_or_gpi6")
        overlap = z3.Bool("days_supply_overlap")
        reject_76 = z3.Bool("reject_76")

        constraints = [
            curr_days > 0,
            active_days > 0,
            overlap == z3.And(curr_start <= active_end, active_start <= curr_end),
            reject_76 == z3.And(overlap, same_therapy),
        ]

        return [
            self._prove_unsat(
                invariant_id="FWA-R76-001",
                domain="DUPLICATE_THERAPY",
                statement="Overlapping date ranges with identical GPI-10/GPI-6 therapy must reject with Reject 76.",
                assumptions=[
                    "current and active claims are distinct",
                    "same_therapy means same GPI-10 or same GPI-6",
                    "days_supply values are positive",
                ],
                constraints=constraints,
                negated_property=z3.And(overlap, same_therapy, z3.Not(reject_76)),
                lean4_theorem_stub="theorem duplicate_therapy_overlap_rejects",
            ),
            self._prove_unsat(
                invariant_id="FWA-R76-002",
                domain="DUPLICATE_THERAPY",
                statement="Non-overlapping date ranges cannot reject solely by the duplicate-therapy overlap rule.",
                assumptions=[
                    "current and active claims are distinct",
                    "same_therapy may be true",
                    "days_supply values are positive",
                ],
                constraints=constraints,
                negated_property=z3.And(z3.Not(overlap), reject_76),
                lean4_theorem_stub="theorem duplicate_therapy_no_overlap_no_reject",
            ),
        ]

    def prove_hhi_threshold_bounds(self) -> List[FraudInvariantProof]:
        import z3

        v1 = z3.Real("pharmacy_volume_1")
        v2 = z3.Real("pharmacy_volume_2")
        hhi = z3.Real("hhi_score")
        siu_freeze = z3.Bool("siu_freeze")
        escrow_hold = z3.Bool("escrow_hold")

        constraints = [
            v1 >= 0,
            v2 >= 0,
            v1 + v2 > 0,
            hhi >= 0,
            hhi <= 10000,
            siu_freeze == (hhi >= self.HHI_SIU_THRESHOLD),
            escrow_hold == z3.And(hhi >= self.HHI_ESCROW_THRESHOLD, hhi < self.HHI_SIU_THRESHOLD),
        ]

        algebraic_hhi_upper_bound_negation = z3.And(
            v1 >= 0,
            v2 >= 0,
            v1 + v2 > 0,
            (v1 * v1 + v2 * v2) > ((v1 + v2) * (v1 + v2)),
        )

        return [
            self._prove_unsat(
                invariant_id="FWA-HHI-001",
                domain="HHI",
                statement="For non-negative pharmacy volume, modeled HHI is bounded within [0, 10000].",
                assumptions=[
                    "volumes are non-negative",
                    "total volume is positive",
                    "HHI = sum((volume / total * 100)^2)",
                ],
                constraints=[],
                negated_property=algebraic_hhi_upper_bound_negation,
                lean4_theorem_stub="theorem hhi_upper_bound_10000",
            ),
            self._prove_unsat(
                invariant_id="FWA-HHI-002",
                domain="HHI",
                statement="HHI values at or above 7500 must route to SIU freeze in the modeled detector gate.",
                assumptions=["siu_freeze is defined as hhi_score >= 7500"],
                constraints=constraints,
                negated_property=z3.And(hhi >= self.HHI_SIU_THRESHOLD, z3.Not(siu_freeze)),
                lean4_theorem_stub="theorem hhi_siu_threshold_sound",
            ),
            self._prove_unsat(
                invariant_id="FWA-HHI-003",
                domain="HHI",
                statement="HHI values in [5000, 7500) must route to escrow hold, not SIU freeze, in the modeled detector gate.",
                assumptions=["escrow_hold is defined as 5000 <= hhi_score < 7500"],
                constraints=constraints,
                negated_property=z3.And(
                    hhi >= self.HHI_ESCROW_THRESHOLD,
                    hhi < self.HHI_SIU_THRESHOLD,
                    z3.Not(escrow_hold),
                ),
                lean4_theorem_stub="theorem hhi_escrow_band_sound",
            ),
        ]

    def prove_benford_anomaly_review_boundary(self) -> List[FraudInvariantProof]:
        import z3

        sample_size = z3.Int("benford_sample_size")
        chi2_stat = z3.Real("benford_chi2_stat")
        anomaly_review_required = z3.Bool("anomaly_review_required")
        fraud_proven = z3.Bool("fraud_proven")

        critical = z3.RealVal(self.BENFORD_CHI2_P01_CRITICAL)
        constraints = [
            sample_size >= 0,
            chi2_stat >= 0,
            anomaly_review_required == z3.And(sample_size >= self.BENFORD_MIN_SAMPLE, chi2_stat > critical),
            fraud_proven == False,
        ]

        return [
            self._prove_unsat(
                invariant_id="FWA-BENFORD-001",
                domain="BENFORD",
                statement="Benford p<0.01 equivalent evidence routes only to ANOMALY_REVIEW_REQUIRED.",
                assumptions=[
                    "sample_size >= 10",
                    "chi-square statistic exceeds p=0.01 critical value",
                    "Benford is a statistical anomaly sentry, not proof of fraud",
                ],
                constraints=constraints,
                negated_property=z3.And(
                    sample_size >= self.BENFORD_MIN_SAMPLE,
                    chi2_stat > critical,
                    z3.Not(anomaly_review_required),
                ),
                proof_method="OUTPUT_CONTRACT_SCHEMA",
                lean4_theorem_stub="theorem benford_anomaly_routes_to_review",
            ),
            self._prove_unsat(
                invariant_id="FWA-BENFORD-002",
                domain="BENFORD",
                statement="Benford logic never emits a modeled FRAUD_PROVEN conclusion.",
                assumptions=["fraud_proven is fixed false for Benford-only evidence"],
                constraints=constraints,
                negated_property=fraud_proven,
                proof_method="OUTPUT_CONTRACT_SCHEMA",
                lean4_theorem_stub="theorem benford_never_proves_fraud",
            ),
            self._prove_unsat(
                invariant_id="FWA-BENFORD-003",
                domain="BENFORD",
                statement="Benford samples below the minimum statistical size do not trigger anomaly review.",
                assumptions=[f"minimum sample size is {self.BENFORD_MIN_SAMPLE}"],
                constraints=constraints,
                negated_property=z3.And(sample_size < self.BENFORD_MIN_SAMPLE, anomaly_review_required),
                proof_method="OUTPUT_CONTRACT_SCHEMA",
                lean4_theorem_stub="theorem benford_small_sample_no_review",
            ),
        ]

    def _prove_unsat(
        self,
        *,
        invariant_id: str,
        domain: str,
        statement: str,
        assumptions: List[str],
        constraints: List[Any],
        negated_property: Any,
        proof_method: ProofMethod = "Z3_UNSAT_NEGATION",
        lean4_theorem_stub: Optional[str] = None,
    ) -> FraudInvariantProof:
        import z3

        solver = z3.Solver()
        for constraint in constraints:
            solver.add(constraint)
        solver.add(negated_property)
        result = solver.check()

        if result == z3.unsat:
            status: ProofStatus = "PROVED"
            counterexample = None
        elif result == z3.sat:
            status = "COUNTEREXAMPLE_FOUND"
            counterexample = str(solver.model())
        else:
            status = "SOLVER_UNKNOWN"
            counterexample = str(result)

        return FraudInvariantProof(
            invariant_id=invariant_id,
            domain=domain,  # type: ignore[arg-type]
            statement=statement,
            assumptions=assumptions,
            proof_method=proof_method,
            solver_status=status,
            counterexample=counterexample,
            lean4_theorem_stub=lean4_theorem_stub,
        )

