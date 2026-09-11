import unittest
from decimal import Decimal

from council_verifier import CouncilReceiptVerifier
from pbm_fraud_detector import PBMFraudDetector, PharmacyClaimRecord
from pbm_fraud_formal_invariants import (
    PBMFraudFormalInvariantEngine,
    PBMFraudFormalInvariantReceipt,
)


class TestPBMFraudFormalInvariants(unittest.TestCase):

    def setUp(self):
        self.engine = PBMFraudFormalInvariantEngine()

    def test_prove_all_fraud_invariants_and_seal_receipt(self):
        receipt_env = self.engine.prove_all()
        CouncilReceiptVerifier.verify_envelope(receipt_env, PBMFraudFormalInvariantReceipt)

        receipt = receipt_env.payload
        self.assertTrue(receipt.all_invariants_proved)
        self.assertFalse(receipt.fraud_proof_claimed)
        self.assertFalse(receipt.external_business_truth_proven)
        self.assertEqual(receipt.benford_output_contract, "ANOMALY_REVIEW_REQUIRED_ONLY")
        self.assertGreaterEqual(len(receipt.invariants), 10)
        self.assertEqual({proof.solver_status for proof in receipt.invariants}, {"PROVED"})

    def test_required_domains_are_covered(self):
        receipt = self.engine.prove_all().payload
        domains = {proof.domain for proof in receipt.invariants}
        self.assertEqual(
            domains,
            {"MME", "REFILL_TOO_SOON", "DUPLICATE_THERAPY", "HHI", "BENFORD"},
        )

    def test_benford_detector_output_is_review_not_fraud_proof(self):
        detector = PBMFraudDetector()
        claim = PharmacyClaimRecord(
            claim_id="CLM_BENFORD_FORMAL",
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

        result = detector.audit_claim(claim, claim_amounts=[Decimal("999.0")] * 50)
        self.assertFalse(result.audit_passed)
        self.assertEqual(result.triage_tier, "TIER_2_ESCROW_HOLD")
        self.assertEqual(result.ncpdp_reject_code, "ANOMALY_REVIEW_REQUIRED")
        self.assertIn("not proof of fraud", result.reject_reason)

    def test_mme_threshold_runtime_matches_formal_boundary(self):
        detector = PBMFraudDetector()
        below = PharmacyClaimRecord(
            claim_id="CLM_MME_BELOW",
            member_id="M_200",
            prescriber_npi="NPI_DOC_3",
            pharmacy_npi="NPI_PHARM_3",
            ndc="00002-9999-01",
            gpi_10="9988776655",
            gpi_6="998877",
            drug_name="Oxycodone 10mg",
            schedule="C-II",
            date_of_service=1,
            days_supply=30,
            quantity=Decimal("300.0"),
            strength_mg=Decimal("10.0"),
            is_opioid=True,
            opioid_active_ingredient="oxycodone"
        )
        at_threshold = below.model_copy(update={
            "claim_id": "CLM_MME_AT_THRESHOLD",
            "quantity": Decimal("400.0")
        })

        below_result = detector.audit_claim(below)
        at_result = detector.audit_claim(at_threshold)

        self.assertTrue(below_result.audit_passed)
        self.assertLess(below_result.daily_mme, 200.0)
        self.assertFalse(at_result.audit_passed)
        self.assertEqual(at_result.ncpdp_reject_code, "REJECT_M7")
        self.assertGreaterEqual(at_result.daily_mme, 200.0)


if __name__ == "__main__":
    unittest.main()

