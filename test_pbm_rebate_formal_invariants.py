"""
Unit tests for PBM Rebate Formal Invariant Engine.
"""

import unittest
from council_contracts import ReceiptEnvelope
from council_verifier import CouncilReceiptVerifier
from pbm_rebate_formal_invariants import (
    PBMRebateFormalInvariantEngine,
    PBMRebateFormalInvariantReceipt,
)


class TestPBMRebateFormalInvariants(unittest.TestCase):

    def setUp(self):
        self.engine = PBMRebateFormalInvariantEngine()

    def test_gross_net_non_negative(self):
        proofs = self.engine.prove_gross_net_non_negative()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0].solver_status, "PROVED")
        self.assertIsNone(proofs[0].counterexample)

    def test_solvency_debt_conservation(self):
        proofs = self.engine.prove_solvency_debt_conservation()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0].solver_status, "PROVED")
        self.assertIsNone(proofs[0].counterexample)
        self.assertTrue(
            any("d_new == d_out" in assumption for assumption in proofs[0].assumptions),
            "SMT debt model must track the Solidity current-outstanding-shortfall transition",
        )

    def test_dispute_escrow_cap_monotonicity(self):
        proofs = self.engine.prove_dispute_escrow_cap_monotonicity()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0].solver_status, "PROVED")
        self.assertIsNone(proofs[0].counterexample)

    def test_mutual_credit_zero_sum(self):
        proofs = self.engine.prove_mutual_credit_zero_sum()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0].solver_status, "PROVED")
        self.assertIsNone(proofs[0].counterexample)

    def test_fee_on_transfer_intake_integrity(self):
        proofs = self.engine.prove_fee_on_transfer_intake_integrity()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0].solver_status, "PROVED")
        self.assertIsNone(proofs[0].counterexample)

    def test_treasury_bucket_conservation(self):
        proofs = self.engine.prove_treasury_bucket_conservation()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0].solver_status, "PROVED")
        self.assertIsNone(proofs[0].counterexample)

    def test_patient_fund_recycle_sink_bound(self):
        proofs = self.engine.prove_patient_fund_recycle_sink_bound()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0].solver_status, "PROVED")
        self.assertIsNone(proofs[0].counterexample)

    def test_prove_all_receipt_envelope(self):
        envelope = self.engine.prove_all()
        CouncilReceiptVerifier.verify_envelope(envelope, PBMRebateFormalInvariantReceipt)

        receipt = envelope.payload
        self.assertTrue(receipt.all_invariants_proved)
        self.assertEqual(len(receipt.invariants), 7)
        self.assertFalse(receipt.audit_replacement_claimed)
        self.assertFalse(receipt.market_truth_claimed)
        self.assertTrue(receipt.proof_boundary.startswith("Local SMT Z3 proofs"))

        domains = {p.domain for p in receipt.invariants}
        self.assertEqual(
            domains,
            {
                "GROSS_NET_NON_NEGATIVE",
                "SOLVENCY_DEBT_CONSERVATION",
                "DISPUTE_ESCROW_CAP",
                "MUTUAL_CREDIT_ZERO_SUM",
                "FEE_ON_TRANSFER_INTEGRITY",
                "TREASURY_BUCKET_CONSERVATION",
                "PATIENT_FUND_RECYCLE_SINK_BOUND",
            },
        )

    def test_counterexample_detection_on_unsound_claim(self):
        """Verifies that an unsound claim properly returns COUNTEREXAMPLE_FOUND."""
        import z3
        x = z3.Real("x")
        # Unsound invariant: x >= 0 for unconstrained x
        proof = self.engine._prove_unsat(
            invariant_id="TEST-FAIL-001",
            domain="GROSS_NET_NON_NEGATIVE",
            statement="Unsound claim: unconstrained x is always non-negative",
            assumptions=[],
            constraints=[],
            negated_property=x < 0,
        )
        self.assertEqual(proof.solver_status, "COUNTEREXAMPLE_FOUND")
        self.assertIsNotNone(proof.counterexample)


if __name__ == "__main__":
    unittest.main()
