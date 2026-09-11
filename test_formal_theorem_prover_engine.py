import unittest
from formal_theorem_prover_engine import FormalTheoremProverEngine, DafnyMethodContract, Lean4ProofCertificate

class TestFormalTheoremProverEngine(unittest.TestCase):

    def setUp(self):
        self.prover = FormalTheoremProverEngine()

    def test_synthesize_dafny_contract(self):
        contract = self.prover.synthesize_dafny_contract(
            method_name="SumFirstN",
            parameters=["n: int"],
            returns=["sum: int"],
            preconditions=["n >= 0"],
            postconditions=["sum == (n * (n + 1)) / 2"]
        )
        self.assertIsInstance(contract, DafnyMethodContract)
        self.assertEqual(contract.method_name, "SumFirstN")
        self.assertEqual(contract.verification_status, "GENERATED_UNVERIFIED")
        self.assertFalse(contract.checker_invoked)
        self.assertIn("no Dafny verifier execution", contract.verification_boundary)
        self.assertIn("0 <= i <= n", contract.invariants)
        self.assertEqual(contract.decreases_clause, "n - i")

    def test_dafny_contract_does_not_verify_false_postcondition_without_checker(self):
        contract = self.prover.synthesize_dafny_contract(
            method_name="Impossible",
            parameters=["n: int"],
            returns=["sum: int"],
            preconditions=["n >= 0"],
            postconditions=["false"]
        )
        self.assertEqual(contract.verification_status, "GENERATED_UNVERIFIED")
        self.assertFalse(contract.checker_invoked)

    def test_generate_lean4_proof_certificate(self):
        cert = self.prover.generate_lean4_proof_certificate(
            theorem_name="nat_sum_formula",
            premises=["Nat.succ_eq_add_one", "linarith"]
        )
        self.assertIsInstance(cert, Lean4ProofCertificate)
        self.assertEqual(cert.theorem_name, "nat_sum_formula")
        self.assertFalse(cert.kernel_typecheck_verified)
        self.assertFalse(cert.checker_invoked)
        self.assertEqual(cert.certificate_status, "GENERATED_UNVERIFIED")
        self.assertIn("no Lean kernel execution", cert.verification_boundary)
        self.assertTrue(len(cert.certificate_sha256) == 64)
        self.assertGreaterEqual(cert.proof_tree_depth, 4)

    def test_lean_certificate_does_not_typecheck_invalid_theorem_without_checker(self):
        cert = self.prover.generate_lean4_proof_certificate(
            theorem_name="false_theorem",
            premises=["False.elim"]
        )
        self.assertFalse(cert.kernel_typecheck_verified)
        self.assertFalse(cert.checker_invoked)
        self.assertEqual(cert.certificate_status, "GENERATED_UNVERIFIED")

    def test_prove_rebate_invariant_z3(self):
        # Admin fee is 10%, Gross rebate is positive. R_net should be positive.
        success, cex = self.prover.prove_rebate_invariant_z3(
            gross_rebate_min=10.0,
            gross_rebate_max=100.0,
            admin_fee_pct=0.10
        )
        self.assertTrue(success, f"Z3 failed to prove invariant, counterexample: {cex}")

        # Pathological case: Admin fee is 110%. Net rebate will be negative. Z3 should find counterexample.
        success, cex = self.prover.prove_rebate_invariant_z3(
            gross_rebate_min=10.0,
            gross_rebate_max=100.0,
            admin_fee_pct=1.10
        )
        self.assertFalse(success, "Z3 should have found a counterexample for admin fee > 100%")
        self.assertIsNotNone(cex)
        self.assertIn("Counterexample", cex)

if __name__ == "__main__":
    unittest.main()
