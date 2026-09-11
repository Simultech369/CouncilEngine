import hashlib
import hmac
from decimal import Decimal, ROUND_HALF_EVEN
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field
from council_contracts import ImmutableContract

# Precision: 18 digits, scale of 6 decimal places for calculations
PRECISION_SCALE = Decimal("0.000001")
CENT_SCALE = Decimal("0.01")

class PrescriptionClaim(ImmutableContract):
    claim_id: str
    member_id_raw: str
    ndc: str
    drug_name: str
    is_brand: bool
    days_supply: int
    quantity_dispensed: Decimal
    unit_wac: Decimal
    adjudication_timestamp: float

class SanitizedPrescriptionClaim(ImmutableContract):
    claim_id: str
    tokenized_member_id: str
    ndc: str
    is_brand: bool
    normalized_30eq_scripts: Decimal
    total_wac: Decimal
    adjudication_timestamp: float

class RebateTierRule(ImmutableContract):
    tier_name: str
    min_market_share: Decimal
    max_market_share: Decimal
    base_rebate_rate: Decimal
    volume_adder_rate: Decimal

class PBMRebateEngine:
    """
    Deterministic PBM rebate calculation engine using Decimal(18, 6)
    Banker's rounding and HIPAA Safe Harbor tokenization.
    """

    def __init__(self, hmac_secret_key: str = "pbm_airgap_secret_salt_2026"):
        self.hmac_key = hmac_secret_key.encode("utf-8")

    def tokenize_member_id(self, member_id_raw: str) -> str:
        """Safe Harbor tokenization using Salted HMAC-SHA256."""
        h = hmac.new(self.hmac_key, member_id_raw.encode("utf-8"), hashlib.sha256)
        return f"TOK_MBR_{h.hexdigest()[:16]}"

    def sanitize_and_normalize_claim(self, claim: PrescriptionClaim) -> SanitizedPrescriptionClaim:
        """Normalizes to 30-Day Equivalent Script (S_30eq = Days Supply / 30)."""
        tokenized_id = self.tokenize_member_id(claim.member_id_raw)
        
        # S_30eq = Decimal(days_supply) / Decimal(30)
        s_30eq = (Decimal(claim.days_supply) / Decimal(30)).quantize(PRECISION_SCALE, rounding=ROUND_HALF_EVEN)
        
        # Total WAC = Quantity * Unit WAC
        total_wac = (claim.quantity_dispensed * claim.unit_wac).quantize(PRECISION_SCALE, rounding=ROUND_HALF_EVEN)

        return SanitizedPrescriptionClaim(
            claim_id=claim.claim_id,
            tokenized_member_id=tokenized_id,
            ndc=claim.ndc,
            is_brand=claim.is_brand,
            normalized_30eq_scripts=s_30eq,
            total_wac=total_wac,
            adjudication_timestamp=claim.adjudication_timestamp
        )

    def verify_tier_partition_non_overlap(self, tiers: List[RebateTierRule]) -> bool:
        """
        SMT-style interval verification ensuring volume tiers form a strictly
        non-overlapping, monotonic partition.
        """
        sorted_tiers = sorted(tiers, key=lambda t: t.min_market_share)
        
        # Check first tier starts at 0.0
        if sorted_tiers[0].min_market_share != Decimal("0.0"):
            return False

        # Check last tier reaches 1.0
        if sorted_tiers[-1].max_market_share != Decimal("1.0"):
            return False

        # Check continuous non-overlapping intervals: tier[i].max == tier[i+1].min
        for i in range(len(sorted_tiers) - 1):
            if sorted_tiers[i].max_market_share != sorted_tiers[i+1].min_market_share:
                return False
            # Check monotonicity of rebate rates
            if sorted_tiers[i+1].base_rebate_rate < sorted_tiers[i].base_rebate_rate:
                return False

        return True

    def calculate_quarterly_rebate(
        self,
        claims: List[SanitizedPrescriptionClaim],
        total_category_30eq_scripts: Decimal,
        tiers: List[RebateTierRule],
        pass_through_rate: Decimal = Decimal("1.000000"),
        admin_fee_rate: Decimal = Decimal("0.030000")
    ) -> Dict[str, Any]:
        """
        Calculates Base Rebate, Volume Tier Adders, and Plan Sponsor Pass-Through.
        """
        if not self.verify_tier_partition_non_overlap(tiers):
            raise ValueError("Rebate tiers fail SMT partition non-overlap or monotonicity invariant!")

        # 1. Total Brand Units & WAC
        total_brand_30eq = sum(c.normalized_30eq_scripts for c in claims if c.is_brand)
        total_brand_wac = sum(c.total_wac for c in claims if c.is_brand)

        # 2. Market Share = Brand Scripts / Category Scripts
        if total_category_30eq_scripts > Decimal("0"):
            market_share = (total_brand_30eq / total_category_30eq_scripts).quantize(PRECISION_SCALE, rounding=ROUND_HALF_EVEN)
        else:
            market_share = Decimal("0.000000")

        # 3. Match Tier
        matched_tier = None
        for t in tiers:
            if t.min_market_share <= market_share <= t.max_market_share:
                matched_tier = t
                break
        
        if not matched_tier:
            matched_tier = tiers[-1]

        # 4. Total Rebate Rate = Base Rate + Volume Adder Rate
        total_rebate_rate = matched_tier.base_rebate_rate + matched_tier.volume_adder_rate
        
        # 5. Gross Manufacturer Rebate = Total WAC * Total Rate
        gross_rebate = (total_brand_wac * total_rebate_rate).quantize(PRECISION_SCALE, rounding=ROUND_HALF_EVEN)

        # 6. Pass-Through to Plan Sponsor
        plan_sponsor_credit = (gross_rebate * pass_through_rate).quantize(CENT_SCALE, rounding=ROUND_HALF_EVEN)
        
        # 7. PBM Retained Admin Fee
        pbm_admin_fee = (total_brand_wac * admin_fee_rate).quantize(CENT_SCALE, rounding=ROUND_HALF_EVEN)

        return {
            "market_share": float(market_share),
            "matched_tier_name": matched_tier.tier_name,
            "total_brand_wac_usd": float(total_brand_wac),
            "gross_rebate_usd": float(gross_rebate),
            "plan_sponsor_credit_usd": float(plan_sponsor_credit),
            "pbm_admin_fee_usd": float(pbm_admin_fee),
            "effective_rebate_percentage": float(total_rebate_rate * Decimal("100.0"))
        }
