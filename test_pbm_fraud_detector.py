import unittest
from decimal import Decimal
from pbm_fraud_detector import PBMFraudDetector, PharmacyClaimRecord

class TestPBMFraudDetector(unittest.TestCase):

    def setUp(self):
        self.detector = PBMFraudDetector()

    def test_reject_79_refill_too_soon(self):
        # Prior claim: 30-day supply on Day 1
        prior = PharmacyClaimRecord(
            claim_id="CLM_001",
            member_id="M_100",
            prescriber_npi="NPI_DOC_1",
            pharmacy_npi="NPI_PHARM_1",
            ndc="00002-8215-01",
            gpi_10="1234567890",
            gpi_6="123456",
            drug_name="Controlled Substance C-II",
            schedule="C-II",
            date_of_service=1,
            days_supply=30,
            quantity=Decimal("30.0"),
            strength_mg=Decimal("10.0")
        )

        # Current claim on Day 20 (only 63.3% consumed < 100% threshold for C-II)
        current = PharmacyClaimRecord(
            claim_id="CLM_002",
            member_id="M_100",
            prescriber_npi="NPI_DOC_1",
            pharmacy_npi="NPI_PHARM_1",
            ndc="00002-8215-01",
            gpi_10="1234567890",
            gpi_6="123456",
            drug_name="Controlled Substance C-II",
            schedule="C-II",
            date_of_service=20,
            days_supply=30,
            quantity=Decimal("30.0"),
            strength_mg=Decimal("10.0")
        )

        audit_res = self.detector.audit_claim(current, prior_claim=prior)
        self.assertFalse(audit_res.audit_passed)
        self.assertEqual(audit_res.triage_tier, "TIER_1_POS_REJECT")
        self.assertEqual(audit_res.ncpdp_reject_code, "REJECT_79")

    def test_reject_76_duplicate_therapy(self):
        # Claim 1 on Day 1 to 30
        active_claim = PharmacyClaimRecord(
            claim_id="CLM_001",
            member_id="M_100",
            prescriber_npi="NPI_DOC_1",
            pharmacy_npi="NPI_PHARM_1",
            ndc="00002-8215-01",
            gpi_10="1234567890",
            gpi_6="123456",
            drug_name="Drug A",
            schedule="NON-CONTROLLED",
            date_of_service=1,
            days_supply=30,
            quantity=Decimal("30.0"),
            strength_mg=Decimal("10.0")
        )

        # Duplicate claim on Day 15 for identical GPI-10
        current = PharmacyClaimRecord(
            claim_id="CLM_002",
            member_id="M_100",
            prescriber_npi="NPI_DOC_2",
            pharmacy_npi="NPI_PHARM_2",
            ndc="00002-8215-02",
            gpi_10="1234567890",
            gpi_6="123456",
            drug_name="Drug A Generic",
            schedule="NON-CONTROLLED",
            date_of_service=15,
            days_supply=30,
            quantity=Decimal("30.0"),
            strength_mg=Decimal("10.0")
        )

        audit_res = self.detector.audit_claim(current, active_claims=[active_claim])
        self.assertFalse(audit_res.audit_passed)
        self.assertEqual(audit_res.ncpdp_reject_code, "REJECT_76")

    def test_lethal_mme_hard_stop(self):
        # High-dose Oxycodone (80mg x 4 pills/day = 320mg/day * 1.5 CF = 480 MME/day >= 200 hard stop)
        high_dose_claim = PharmacyClaimRecord(
            claim_id="CLM_003",
            member_id="M_200",
            prescriber_npi="NPI_DOC_3",
            pharmacy_npi="NPI_PHARM_3",
            ndc="00002-9999-01",
            gpi_10="9988776655",
            gpi_6="998877",
            drug_name="Oxycodone 80mg",
            schedule="C-II",
            date_of_service=1,
            days_supply=30,
            quantity=Decimal("120.0"),
            strength_mg=Decimal("80.0"),
            is_opioid=True,
            opioid_active_ingredient="oxycodone"
        )

        audit_res = self.detector.audit_claim(high_dose_claim)
        self.assertFalse(audit_res.audit_passed)
        self.assertEqual(audit_res.ncpdp_reject_code, "REJECT_M7")
        self.assertGreaterEqual(audit_res.daily_mme, 200.0)

    def test_collusion_hhi_quarantine(self):
        # Prescriber sends 95% of volume to single pharmacy -> HHI ~ 9025 >= 7500 (Tier 3 SIU)
        claim = PharmacyClaimRecord(
            claim_id="CLM_004",
            member_id="M_300",
            prescriber_npi="NPI_DOC_COLLUDE",
            pharmacy_npi="NPI_PHARM_TARGET",
            ndc="00002-1111-01",
            gpi_10="1122334455",
            gpi_6="112233",
            drug_name="Maintenance Drug",
            schedule="NON-CONTROLLED",
            date_of_service=1,
            days_supply=30,
            quantity=Decimal("30.0"),
            strength_mg=Decimal("10.0")
        )
        dist = {"NPI_PHARM_TARGET": 95, "NPI_PHARM_OTHER": 5}

        audit_res = self.detector.audit_claim(claim, pharmacy_volume_distribution=dist)
        self.assertFalse(audit_res.audit_passed)
        self.assertEqual(audit_res.triage_tier, "TIER_3_SIU_FREEZE")
        self.assertEqual(audit_res.ncpdp_reject_code, "FLAG_COLLUSION_SIU")
        self.assertGreaterEqual(audit_res.hhi_score, 7500.0)

    def test_340b_double_dipping(self):
        claim = PharmacyClaimRecord(
            claim_id="CLM_340B",
            member_id="M_400",
            prescriber_npi="NPI_DOC_1",
            pharmacy_npi="NPI_340B_COVERED_ENTITY",
            ndc="00002-1111-01",
            gpi_10="1122334455",
            gpi_6="112233",
            drug_name="Insulin",
            schedule="NON-CONTROLLED",
            date_of_service=1,
            days_supply=30,
            quantity=Decimal("1.0"),
            strength_mg=Decimal("100.0")
        )
        registry = {"NPI_340B_COVERED_ENTITY"}
        
        audit_res = self.detector.audit_claim(claim, medicaid_340b_npi_registry=registry)
        self.assertFalse(audit_res.audit_passed)
        self.assertEqual(audit_res.triage_tier, "TIER_3_SIU_FREEZE")
        self.assertEqual(audit_res.ncpdp_reject_code, "FLAG_340B_DOUBLE_DIP")

    def test_benfords_law_anomaly(self):
        claim = PharmacyClaimRecord(
            claim_id="CLM_BENFORD",
            member_id="M_500",
            prescriber_npi="NPI_DOC_1",
            pharmacy_npi="NPI_PHARM_1",
            ndc="00002-1111-01",
            gpi_10="1122334455",
            gpi_6="112233",
            drug_name="Synthetic",
            schedule="NON-CONTROLLED",
            date_of_service=1,
            days_supply=30,
            quantity=Decimal("1.0"),
            strength_mg=Decimal("10.0")
        )
        # Synthetic claims all starting with '9' -> massive anomaly
        synthetic_amounts = [Decimal("999.0")] * 50
        
        audit_res = self.detector.audit_claim(claim, claim_amounts=synthetic_amounts)
        self.assertFalse(audit_res.audit_passed)
        self.assertEqual(audit_res.triage_tier, "TIER_2_ESCROW_HOLD")
        self.assertEqual(audit_res.ncpdp_reject_code, "ANOMALY_REVIEW_REQUIRED")
        self.assertIn("not proof of fraud", audit_res.reject_reason)
        self.assertLess(audit_res.benfords_p_value, 0.01)

if __name__ == "__main__":
    unittest.main()
