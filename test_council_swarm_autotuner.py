import unittest
from council_swarm_autotuner import CouncilSwarmAutoTuner, SwarmTuningReceipt

class TestCouncilSwarmAutoTuner(unittest.TestCase):

    def setUp(self):
        self.autotuner = CouncilSwarmAutoTuner()

    def test_ast_entropy_calculation(self):
        simple_code = "x = 1"
        simple_entropy = self.autotuner.calculate_ast_entropy(simple_code)
        self.assertGreater(simple_entropy, 0.0)

        complex_code = """
import os
import sys

class DataProcessor:
    def __init__(self, items):
        self.items = [x * 2 for x in items if x > 0]

    async def process(self):
        try:
            for i, val in enumerate(self.items):
                if val % 2 == 0:
                    yield val ** 2
        except Exception as e:
            raise RuntimeError(e)
"""
        complex_entropy = self.autotuner.calculate_ast_entropy(complex_code)
        self.assertGreater(complex_entropy, simple_entropy)

    def test_calibrate_swarm_hyperparameters(self):
        code = "def authenticate(user, pwd): return user == 'admin'"
        receipt = self.autotuner.calibrate_swarm("auth_module", code)

        self.assertIsInstance(receipt, SwarmTuningReceipt)
        self.assertEqual(receipt.target_module, "auth_module")
        self.assertEqual(len(receipt.calibrated_seats), 4)
        self.assertTrue(len(receipt.receipt_sha256) == 64)

        # Verify seat-specific parameter bounds
        seats_by_id = {s.seat_id: s for s in receipt.calibrated_seats}
        
        # Formal Prover: Deterministic T = 0.00
        self.assertEqual(seats_by_id["seat_formal_prover"].temperature, 0.00)
        self.assertEqual(seats_by_id["seat_formal_prover"].top_p, 0.95)

        # Syntactic Patcher: Low T = 0.10
        self.assertEqual(seats_by_id["seat_patch_synthesizer"].temperature, 0.10)

        # Council Leader: Balanced T = 0.20
        self.assertEqual(seats_by_id["seat_council_leader"].temperature, 0.20)

        # Adversarial Scout: High T = 0.65+ for creative fuzzing
        self.assertGreaterEqual(seats_by_id["seat_adversarial_scout"].temperature, 0.65)
        self.assertEqual(seats_by_id["seat_adversarial_scout"].top_p, 0.98)

if __name__ == "__main__":
    unittest.main()
