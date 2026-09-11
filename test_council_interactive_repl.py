import os
import shutil
import tempfile
import unittest
from council_interactive_repl import CouncilInteractiveREPL

class TestCouncilInteractiveREPL(unittest.TestCase):

    def setUp(self):
        self.test_state_dir = tempfile.mkdtemp()
        self.previous_state_dir = os.environ.get("COUNCIL_STATE_DIR")
        os.environ["COUNCIL_STATE_DIR"] = self.test_state_dir
        self.repl = CouncilInteractiveREPL(session_id="test_session")

    def tearDown(self):
        if self.previous_state_dir is None:
            os.environ.pop("COUNCIL_STATE_DIR", None)
        else:
            os.environ["COUNCIL_STATE_DIR"] = self.previous_state_dir
        shutil.rmtree(self.test_state_dir, ignore_errors=True)

    def test_banner_and_help(self):
        banner = self.repl.print_banner()
        self.assertIn("[COUNCIL] MULTI-AGENT COUNCIL & AUTONOMOUS ENGINE INTERACTIVE REPL COCKPIT", banner)

        help_text = self.repl.get_help_text()
        self.assertIn("status", help_text)
        self.assertIn("drift", help_text)
        self.assertIn("bounty", help_text)
        self.assertIn("pbm", help_text)
        self.assertIn("pipeline", help_text)
        self.assertIn("chaos", help_text)
        self.assertIn("sync", help_text)

    def test_evaluate_commands(self):
        # 1. status
        cont, out = self.repl.evaluate_line("status")
        self.assertTrue(cont)
        self.assertIn("STATUS: HEALTHY", out)

        # 2. drift
        cont, out = self.repl.evaluate_line("drift")
        self.assertTrue(cont)
        self.assertIn("[DRIFT]", out)

        # 3. dlq
        cont, out = self.repl.evaluate_line("dlq")
        self.assertTrue(cont)
        self.assertIn("[DLQ]", out)

        # 4. bounty
        cont, out = self.repl.evaluate_line("bounty")
        self.assertTrue(cont)
        self.assertIn("[BOUNTY]", out)

        # 5. fwa
        cont, out = self.repl.evaluate_line("fwa")
        self.assertTrue(cont)
        self.assertIn("[FWA AUDIT]", out)

        # 6. proof
        cont, out = self.repl.evaluate_line("proof")
        self.assertTrue(cont)
        self.assertIn("[PROOF P3]", out)

        # 7. redteam
        cont, out = self.repl.evaluate_line("redteam")
        self.assertTrue(cont)
        self.assertIn("[RED-TEAM]", out)

        # 8. formal
        cont, out = self.repl.evaluate_line("formal")
        self.assertTrue(cont)
        self.assertIn("[FORMAL SCAFFOLD]", out)

        # 9. autotune
        cont, out = self.repl.evaluate_line("autotune")
        self.assertTrue(cont)
        self.assertIn("[AUTOTUNE]", out)

        # 10. jury
        cont, out = self.repl.evaluate_line("jury")
        self.assertTrue(cont)
        self.assertIn("[HETEROGENEOUS JURY]", out)

        # 11. pipeline
        cont, out = self.repl.evaluate_line("pipeline")
        self.assertTrue(cont)
        self.assertIn("[E2E PIPELINE]", out)

        # 12. chaos
        cont, out = self.repl.evaluate_line("chaos")
        self.assertTrue(cont)
        self.assertIn("[CHAOS]", out)

        # 13. sync
        cont, out = self.repl.evaluate_line("sync")
        self.assertTrue(cont)
        self.assertIn("[MERKLE SYNC]", out)

        # 14. multilang
        cont, out = self.repl.evaluate_line("multilang")
        self.assertTrue(cont)
        self.assertIn("[MULTILANG]", out)

        # 15. terminal
        cont, out = self.repl.evaluate_line("terminal")
        self.assertTrue(cont)
        self.assertIn("[TERMINAL]", out)

        # 16. empty
        cont, out = self.repl.evaluate_line("")
        self.assertTrue(cont)
        self.assertEqual(out, "")

    def test_exit_command(self):
        cont, out = self.repl.evaluate_line("exit")
        self.assertFalse(cont)
        self.assertIn("Exiting Council REPL session", out)

        cont, out = self.repl.evaluate_line("quit")
        self.assertFalse(cont)
        self.assertIn("Exiting Council REPL session", out)

if __name__ == "__main__":
    unittest.main()
