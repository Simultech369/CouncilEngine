import unittest
from model_gateway import ModelGateway
from log_derived_context_engine import LogDerivedContextEngine

class TestModelGatewaySpendLimit(unittest.TestCase):
    def test_kill_switch_over_50_cents(self):
        gateway = ModelGateway()
        
        class MockPayload:
            reserved_cost_usd = 0.51
            
        class MockEnv:
            payload = MockPayload()

        with self.assertRaises(ValueError) as context:
            gateway.invoke_with_resilience(
                model_slug="test",
                model_family="test",
                provider="test",
                route_env=None,
                qual_env=None,
                packet_env=None,
                budget_env=MockEnv(),
                prompt_text="test",
                context_engine=LogDerivedContextEngine("test_db")
            )
            
        self.assertIn("crosses the strict $0.50 per query limit", str(context.exception))

if __name__ == "__main__":
    unittest.main()
