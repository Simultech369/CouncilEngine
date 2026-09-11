import unittest
from council_web_dashboard import CouncilWebDashboard, DASHBOARD_HTML_TEMPLATE

class TestCouncilWebDashboard(unittest.TestCase):

    def setUp(self):
        self.dashboard = CouncilWebDashboard(port=8501)

    def test_html_template_integrity(self):
        html = self.dashboard.render_html_content()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Multi-Agent Council & Autonomous Verification Engine", html)
        self.assertIn("Authority Drift & Tide Velocity", html)
        self.assertIn("Windows Spend Ledger", html)
        self.assertIn("5-Gate Qualification Matrix", html)
        self.assertIn("4-Stage Admissibility Cage Execution Sequence", html)
        self.assertIn("268/268 TESTS PASSING", html)
        self.assertIn('"active_suites": 52', html)
        self.assertIn('"passing_tests": 268', html)

    def test_dashboard_port_config(self):
        d = CouncilWebDashboard(port=9000)
        self.assertEqual(d.port, 9000)

    def test_dashboard_wires_eventsource_stream(self):
        html = self.dashboard.render_html_content()
        self.assertIn("new EventSource(\"/api/v1/dizzy/stream\")", html)
        self.assertIn("council.health", html)
        self.assertIn("stream-log", html)

if __name__ == "__main__":
    unittest.main()
