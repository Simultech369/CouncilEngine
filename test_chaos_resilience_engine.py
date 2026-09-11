import shutil
import tempfile
import unittest
from council_chaos_resilience_engine import CouncilChaosOrchestrator

class TestChaosResilienceEngine(unittest.TestCase):

    def setUp(self):
        self.test_state_dir = tempfile.mkdtemp()
        self.orchestrator = CouncilChaosOrchestrator(base_state_dir=self.test_state_dir)

    def tearDown(self):
        shutil.rmtree(self.test_state_dir, ignore_errors=True)

    def test_chaos_scenario_1_byzantine_model(self):
        res = self.orchestrator.run_scenario_1_byzantine_model()
        self.assertTrue(res.baseline_healthy)
        self.assertTrue(res.fail_closed_invariant_maintained)
        self.assertTrue(res.mttr_bound_satisfied)
        self.assertLessEqual(res.total_mttr_ms, 3000.0)

    def test_chaos_scenario_2_wal_contention(self):
        res = self.orchestrator.run_scenario_2_wal_contention()
        self.assertTrue(res.baseline_healthy)
        self.assertTrue(res.fail_closed_invariant_maintained)
        self.assertTrue(res.mttr_bound_satisfied)
        self.assertLessEqual(res.total_mttr_ms, 2500.0)

    def test_chaos_scenario_3_network_partition(self):
        res = self.orchestrator.run_scenario_3_network_partition()
        self.assertTrue(res.baseline_healthy)
        self.assertTrue(res.fail_closed_invariant_maintained)
        self.assertTrue(res.mttr_bound_satisfied)
        self.assertLessEqual(res.total_mttr_ms, 2000.0)

    def test_chaos_scenario_4_cas_corruption(self):
        res = self.orchestrator.run_scenario_4_cas_corruption()
        self.assertTrue(res.baseline_healthy)
        self.assertTrue(res.fail_closed_invariant_maintained)
        self.assertTrue(res.mttr_bound_satisfied)
        self.assertLessEqual(res.total_mttr_ms, 1500.0)

    def test_chaos_scenario_5_sandbox_oom(self):
        res = self.orchestrator.run_scenario_5_sandbox_oom()
        self.assertTrue(res.baseline_healthy)
        self.assertTrue(res.fail_closed_invariant_maintained)
        self.assertTrue(res.mttr_bound_satisfied)
        self.assertLessEqual(res.total_mttr_ms, 4000.0)

    def test_full_chaos_resilience_suite(self):
        results = self.orchestrator.run_all_scenarios()
        self.assertEqual(len(results), 5)
        for r in results:
            self.assertTrue(r.fail_closed_invariant_maintained, f"Failed invariant in {r.scenario_name}")
            self.assertTrue(r.mttr_bound_satisfied, f"Exceeded MTTR in {r.scenario_name}")

if __name__ == "__main__":
    unittest.main()
