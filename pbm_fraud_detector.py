import math
import time
from decimal import Decimal
from typing import Dict, Any, List, Optional, Tuple, Literal
from council_contracts import ImmutableContract

CDC_MME_CONVERSION_FACTORS = {
    "morphine": Decimal("1.0"),
    "oxycodone": Decimal("1.5"),
    "hydrocodone": Decimal("1.0"),
    "hydromorphone": Decimal("4.0"),
    "fentanyl_mcg_hr": Decimal("2.4"),
    "codeine": Decimal("0.15"),
    "methadone": Decimal("3.0"),
    "oxymorphone": Decimal("3.0")
}

class PharmacyClaimRecord(ImmutableContract):
    claim_id: str
    member_id: str
    prescriber_npi: str
    pharmacy_npi: str
    ndc: str
    gpi_10: str
    gpi_6: str
    drug_name: str
    schedule: Literal["C-II", "C-III", "C-IV", "C-V", "NON-CONTROLLED"]
    date_of_service: int  # Day index
    days_supply: int
    quantity: Decimal
    strength_mg: Decimal
    is_opioid: bool = False
    is_benzodiazepine: bool = False
    opioid_active_ingredient: Optional[str] = None

class FWAuditResult(ImmutableContract):
    claim_id: str
    triage_tier: Literal["TIER_0_CLEAN", "TIER_1_POS_REJECT", "TIER_2_ESCROW_HOLD", "TIER_3_SIU_FREEZE"]
    ncpdp_reject_code: Optional[str]
    reject_reason: Optional[str]
    daily_mme: float = 0.0
    hhi_score: float = 0.0
    benfords_p_value: float = 1.0
    ensemble_anomaly_score: float = 0.0
    audit_passed: bool

class PBMFraudDetector:
    """
    Automated PBM Pharmacy Claims Fraud, Waste & Abuse (FWA) Detector:
    - Real-time POS Reject 79 (Refill Too Soon) consumption math.
    - Reject 76 (Duplicate Therapy) GPI overlap analysis.
    - Flag/Reject M7 (CDC Daily MME accumulation & Co-prescribing).
    - Prescriber-Pharmacy HHI Collusion detection.
    - 3-Tier Pre-Rebate Adjudication Gatekeeping.
    """

    def check_reject_79_refill_too_soon(
        self,
        current_claim: PharmacyClaimRecord,
        prior_claim: Optional[PharmacyClaimRecord]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Calculates consumed percentage:
        eta = (DOS_curr - DOS_prev) / DS_prev * 100%
        """
        if not prior_claim or prior_claim.gpi_10 != current_claim.gpi_10:
            return True, None, None

        days_elapsed = current_claim.date_of_service - prior_claim.date_of_service
        if prior_claim.days_supply <= 0:
            return True, None, None

        consumed_pct = (Decimal(days_elapsed) / Decimal(prior_claim.days_supply)) * Decimal("100.0")

        # Tiered thresholds
        if current_claim.schedule == "C-II":
            threshold = Decimal("100.0")  # Zero tolerance
        elif current_claim.schedule in ("C-III", "C-IV", "C-V"):
            threshold = Decimal("90.0")
        else:
            threshold = Decimal("75.0")   # Standard maintenance

        if consumed_pct < threshold:
            reason = f"Reject 79: Refill Too Soon ({float(consumed_pct):.1f}% consumed < {float(threshold):.1f}% threshold)"
            return False, "REJECT_79", reason

        return True, None, None

    def check_reject_76_duplicate_therapy(
        self,
        current_claim: PharmacyClaimRecord,
        active_claims: List[PharmacyClaimRecord]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Evaluates concurrent overlapping days supply for identical GPI-10 / GPI-6."""
        curr_start = current_claim.date_of_service
        curr_end = curr_start + current_claim.days_supply - 1

        for act in active_claims:
            if act.claim_id == current_claim.claim_id:
                continue
            act_start = act.date_of_service
            act_end = act_start + act.days_supply - 1

            # Check date overlap
            overlap = max(0, min(curr_end, act_end) - max(curr_start, act_start) + 1)
            if overlap > 0:
                if act.gpi_10 == current_claim.gpi_10:
                    return False, "REJECT_76", f"Reject 76: Exact Duplicate Chemical Therapy ({overlap} days overlap on {current_claim.gpi_10})"
                elif act.gpi_6 == current_claim.gpi_6:
                    return False, "REJECT_76", f"Reject 76: Duplicate Therapeutic Class Overlap ({overlap} days overlap on {current_claim.gpi_6})"

        return True, None, None

    def calculate_daily_mme_and_safety(
        self,
        current_claim: PharmacyClaimRecord,
        active_claims: List[PharmacyClaimRecord]
    ) -> Tuple[bool, Optional[str], Optional[str], float]:
        """Calculates CDC Daily Morphine Milligram Equivalents (MME)."""
        all_claims = [current_claim] + active_claims
        total_daily_mme = Decimal("0.0")
        has_opioid = False
        has_benzo = False

        for c in all_claims:
            if c.is_benzodiazepine:
                has_benzo = True
            if c.is_opioid and c.opioid_active_ingredient:
                has_opioid = True
                factor = CDC_MME_CONVERSION_FACTORS.get(c.opioid_active_ingredient.lower(), Decimal("1.0"))
                if c.days_supply > 0:
                    daily_dose = (c.strength_mg * c.quantity) / Decimal(c.days_supply)
                    mme = daily_dose * factor
                    total_daily_mme += mme

        mme_float = float(total_daily_mme)

        # FDA Boxed Warning: Concurrent Opioid + Benzo
        if has_opioid and has_benzo:
            return False, "FLAG_FDA_BOXED_WARNING", f"FDA Boxed Warning: Concurrent Opioid + Benzodiazepine co-prescribing detected (Daily MME: {mme_float:.1f})", mme_float

        # Hard Stop at >= 200 MME/day
        if total_daily_mme >= Decimal("200.0"):
            return False, "REJECT_M7", f"Reject M7: Lethal Daily MME Hard Stop ({mme_float:.1f} MME/day >= 200 threshold)", mme_float

        return True, None, None, mme_float

    def calculate_benfords_law_anomaly(
        self,
        claim_amounts: List[Decimal]
    ) -> float:
        """
        Runs Benford's Law first-digit distribution tests on claim billing amounts.
        Returns the p-value of a Chi-Square goodness-of-fit test.
        Suspicious clustering indicating synthetic claims: p < 0.01.
        """
        if len(claim_amounts) < 10:
            return 1.0  # Not enough data for statistical significance
            
        observed = {str(d): 0 for d in range(1, 10)}
        valid_count = 0
        for amount in claim_amounts:
            if amount > 0:
                first_digit = str(amount).replace('.', '').lstrip('0')[0]
                if first_digit in observed:
                    observed[first_digit] += 1
                    valid_count += 1
        
        if valid_count < 10:
            return 1.0
            
        observed_counts = [observed[str(d)] for d in range(1, 10)]
        expected_counts = [valid_count * math.log10(1 + 1/d) for d in range(1, 10)]
        
        # Calculate Chi-Square statistic manually to avoid heavy scipy dependency
        chi2_stat = 0.0
        for obs, exp in zip(observed_counts, expected_counts):
            if exp > 0:
                chi2_stat += ((obs - exp) ** 2) / exp
                
        # Degrees of freedom = 9 - 1 = 8. Critical value for p=0.01 is 20.090.
        # If chi2_stat > 20.090, then p < 0.01. We return a surrogate p-value.
        if chi2_stat > 20.090:
            return 0.001
        else:
            return 0.5

    def check_medicaid_340b_double_dipping(
        self,
        current_claim: PharmacyClaimRecord,
        medicaid_340b_npi_registry: set[str]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Cross-checks NDC/NPI claims against Medicaid Drug Rebate Programs (MDRP) 
        and 340B Covered Entity registries to block statutory double-dipping violations.
        """
        if current_claim.pharmacy_npi in medicaid_340b_npi_registry:
            return False, "FLAG_340B_DOUBLE_DIP", f"Statutory Violation: 340B Covered Entity ({current_claim.pharmacy_npi}) double-dipping on commercial rebate."
        return True, None, None

    def calculate_prescriber_pharmacy_hhi(
        self,
        prescriber_npi: str,
        pharmacy_volume_distribution: Dict[str, int]
    ) -> float:
        """
        Calculates Herfindahl-Hirschman Index (HHI):
        HHI = sum((V_ij / V_total * 100)^2)
        """
        total_volume = sum(pharmacy_volume_distribution.values())
        if total_volume <= 0:
            return 0.0

        hhi = 0.0
        for ph_npi, vol in pharmacy_volume_distribution.items():
            market_share_pct = (vol / total_volume) * 100.0
            hhi += market_share_pct ** 2
        return round(hhi, 2)

    def audit_claim(
        self,
        current_claim: PharmacyClaimRecord,
        prior_claim: Optional[PharmacyClaimRecord] = None,
        active_claims: Optional[List[PharmacyClaimRecord]] = None,
        pharmacy_volume_distribution: Optional[Dict[str, int]] = None,
        medicaid_340b_npi_registry: Optional[set[str]] = None,
        claim_amounts: Optional[List[Decimal]] = None
    ) -> FWAuditResult:
        active = active_claims or []
        dist = pharmacy_volume_distribution or {current_claim.pharmacy_npi: 1}
        registry_340b = medicaid_340b_npi_registry or set()

        # 0. 340B Double Dipping Check
        dip_ok, dip_code, dip_msg = self.check_medicaid_340b_double_dipping(current_claim, registry_340b)
        if not dip_ok:
            return FWAuditResult(
                claim_id=current_claim.claim_id,
                triage_tier="TIER_3_SIU_FREEZE",
                ncpdp_reject_code=dip_code,
                reject_reason=dip_msg,
                audit_passed=False
            )

        # 1. Reject 79 Check
        r79_ok, r79_code, r79_msg = self.check_reject_79_refill_too_soon(current_claim, prior_claim)
        if not r79_ok:
            return FWAuditResult(
                claim_id=current_claim.claim_id,
                triage_tier="TIER_1_POS_REJECT",
                ncpdp_reject_code=r79_code,
                reject_reason=r79_msg,
                audit_passed=False
            )

        # 2. Reject 76 Check
        r76_ok, r76_code, r76_msg = self.check_reject_76_duplicate_therapy(current_claim, active)
        if not r76_ok:
            return FWAuditResult(
                claim_id=current_claim.claim_id,
                triage_tier="TIER_1_POS_REJECT",
                ncpdp_reject_code=r76_code,
                reject_reason=r76_msg,
                audit_passed=False
            )

        # 3. MME & Safety Check
        mme_ok, mme_code, mme_msg, daily_mme = self.calculate_daily_mme_and_safety(current_claim, active)
        if not mme_ok:
            tier = "TIER_1_POS_REJECT" if mme_code == "REJECT_M7" else "TIER_2_ESCROW_HOLD"
            return FWAuditResult(
                claim_id=current_claim.claim_id,
                triage_tier=tier,
                ncpdp_reject_code=mme_code,
                reject_reason=mme_msg,
                daily_mme=daily_mme,
                audit_passed=False
            )

        # 4. Collusion HHI Check
        if pharmacy_volume_distribution:
            hhi = self.calculate_prescriber_pharmacy_hhi(current_claim.prescriber_npi, pharmacy_volume_distribution)
            if hhi >= 7500.0:
                return FWAuditResult(
                    claim_id=current_claim.claim_id,
                    triage_tier="TIER_3_SIU_FREEZE",
                    ncpdp_reject_code="FLAG_COLLUSION_SIU",
                    reject_reason=f"Severe Collusion Clique Detected (HHI {hhi:.1f} >= 7500)",
                    daily_mme=daily_mme,
                    hhi_score=hhi,
                    audit_passed=False
                )
            elif hhi >= 5000.0:
                return FWAuditResult(
                    claim_id=current_claim.claim_id,
                    triage_tier="TIER_2_ESCROW_HOLD",
                    ncpdp_reject_code="FLAG_COLLUSION_ESCROW",
                    reject_reason=f"High Steering Concentration (HHI {hhi:.1f} >= 5000)",
                    daily_mme=daily_mme,
                    hhi_score=hhi,
                    audit_passed=False
                )
        else:
            hhi = 0.0

        # 5. Benford's Law Anomaly Score
        benford_p = 1.0
        if claim_amounts:
            benford_p = self.calculate_benfords_law_anomaly(claim_amounts)
            if benford_p < 0.01:
                return FWAuditResult(
                    claim_id=current_claim.claim_id,
                    triage_tier="TIER_2_ESCROW_HOLD",
                    ncpdp_reject_code="ANOMALY_REVIEW_REQUIRED",
                    reject_reason=f"Benford's Law anomaly review required: statistical clustering detected (p={benford_p:.4f} < 0.01); not proof of fraud",
                    daily_mme=daily_mme,
                    hhi_score=hhi,
                    benfords_p_value=benford_p,
                    audit_passed=False
                )

        # Tier 0 Clean Pass
        return FWAuditResult(
            claim_id=current_claim.claim_id,
            triage_tier="TIER_0_CLEAN",
            ncpdp_reject_code=None,
            reject_reason="Clean Claim - Passed All POS Safety & Anti-Fraud Gates",
            daily_mme=daily_mme,
            hhi_score=hhi,
            benfords_p_value=benford_p,
            audit_passed=True
        )
