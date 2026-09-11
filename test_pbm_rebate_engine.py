import time
import unittest
from decimal import Decimal
from pbm_rebate_engine import PBMRebateEngine, PrescriptionClaim, RebateTierRule

class TestPBMRebateEngine(unittest.TestCase):

    def setUp(self):
        self.engine = PBMRebateEngine()
        self.tiers = [
            RebateTierRule(
                tier_name="Tier 1 (<20% MS)",
                min_market_share=Decimal("0.0"),
                max_market_share=Decimal("0.20"),
                base_rebate_rate=Decimal("0.100000"),
                volume_adder_rate=Decimal("0.000000")
            ),
            RebateTierRule(
                tier_name="Tier 2 (20%-50% MS)",
                min_market_share=Decimal("0.20"),
                max_market_share=Decimal("0.50"),
                base_rebate_rate=Decimal("0.150000"),
                volume_adder_rate=Decimal("0.020000")
            ),
            RebateTierRule(
                tier_name="Tier 3 (>50% MS)",
                min_market_share=Decimal("0.50"),
                max_market_share=Decimal("1.00"),
                base_rebate_rate=Decimal("0.200000"),
                volume_adder_rate=Decimal("0.050000")
            )
        ]

    def test_hipaa_safe_harbor_tokenization(self):
        token_a = self.engine.tokenize_member_id("PATIENT_SSN_12345")
        token_b = self.engine.tokenize_member_id("PATIENT_SSN_12345")
        token_c = self.engine.tokenize_member_id("PATIENT_SSN_99999")

        # Deterministic HMAC
        self.assertEqual(token_a, token_b)
        self.assertNotEqual(token_a, token_c)
        self.assertTrue(token_a.startswith("TOK_MBR_"))

    def test_script_normalization_and_wac(self):
        # 90-day supply -> 3.0 normalized scripts
        claim = PrescriptionClaim(
            claim_id="CLM_001",
            member_id_raw="MEM_101",
            ndc="00002-8215-01",
            drug_name="Trulicity 1.5mg",
            is_brand=True,
            days_supply=90,
            quantity_dispensed=Decimal("3.0"),
            unit_wac=Decimal("975.50"),
            adjudication_timestamp=time.time()
        )
        sanitized = self.engine.sanitize_and_normalize_claim(claim)
        self.assertEqual(sanitized.normalized_30eq_scripts, Decimal("3.000000"))
        self.assertEqual(sanitized.total_wac, Decimal("2926.500000"))

    def test_tier_partition_non_overlap_verification(self):
        # Valid tiers
        self.assertTrue(self.engine.verify_tier_partition_non_overlap(self.tiers))

        # Overlapping tiers (Invalid)
        broken_tiers = [
            RebateTierRule(tier_name="T1", min_market_share=Decimal("0.0"), max_market_share=Decimal("0.30"), base_rebate_rate=Decimal("0.10"), volume_adder_rate=Decimal("0.0")),
            RebateTierRule(tier_name="T2", min_market_share=Decimal("0.25"), max_market_share=Decimal("1.00"), base_rebate_rate=Decimal("0.20"), volume_adder_rate=Decimal("0.0"))
        ]
        self.assertFalse(self.engine.verify_tier_partition_non_overlap(broken_tiers))

    def test_quarterly_rebate_calculation(self):
        claims = [
            PrescriptionClaim(
                claim_id=f"CLM_{i}",
                member_id_raw=f"MEM_{i}",
                ndc="00002-8215-01",
                drug_name="Brand Drug",
                is_brand=True,
                days_supply=30,
                quantity_dispensed=Decimal("1.0"),
                unit_wac=Decimal("1000.00"),
                adjudication_timestamp=time.time()
            )
            for i in range(30)
        ]
        sanitized_claims = [self.engine.sanitize_and_normalize_claim(c) for c in claims]
        
        # 30 brand scripts out of 100 total category scripts = 30% Market Share (Tier 2)
        total_category_scripts = Decimal("100.000000")
        result = self.engine.calculate_quarterly_rebate(
            claims=sanitized_claims,
            total_category_30eq_scripts=total_category_scripts,
            tiers=self.tiers,
            pass_through_rate=Decimal("1.000000"),
            admin_fee_rate=Decimal("0.030000")
        )

        self.assertEqual(result["matched_tier_name"], "Tier 2 (20%-50% MS)")
        self.assertEqual(result["market_share"], 0.30)
        self.assertEqual(result["total_brand_wac_usd"], 30000.0)
        # Total rate = 15% base + 2% volume = 17% -> Gross = 30000 * 0.17 = 5100.0
        self.assertEqual(result["gross_rebate_usd"], 5100.0)
        self.assertEqual(result["plan_sponsor_credit_usd"], 5100.0)
        # PBM admin fee = 30000 * 0.03 = 900.0
        self.assertEqual(result["pbm_admin_fee_usd"], 900.0)

if __name__ == "__main__":
    unittest.main()
