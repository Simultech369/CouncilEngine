import unittest
from long_horizon_terminal_runner import LongHorizonTerminalRunner, TerminalStateSnapshot
from lifecycle_hooks import LifecycleHookError

class TestLongHorizonTerminalRunner(unittest.TestCase):

    def setUp(self):
        self.runner = LongHorizonTerminalRunner()

    def test_vte_ansi_escape_filtering(self):
        raw_output = "\x1b[32m[SUCCESS]\x1b[0m All 48 tests passed \x1b[1;34mcleanly\x1b[0m"
        cleaned = self.runner.filter_vte_escape_sequences(raw_output)
        self.assertEqual(cleaned, "[SUCCESS] All 48 tests passed cleanly")

    def test_interactive_prompt_detection(self):
        prompt_out = "Do you want to continue? [y/N] "
        res = self.runner.detect_interactive_prompts(prompt_out)
        self.assertIsNotNone(res)
        self.assertEqual(res[0], "CONFIRMATION_PROMPT")

        clean_out = "Build succeeded with 0 errors."
        self.assertIsNone(self.runner.detect_interactive_prompts(clean_out))

    def test_execution_turn_and_merkle_checkpoint(self):
        snap1 = self.runner.execute_turn_transition(
            turn_index=1,
            command="git status",
            raw_output="\x1b[33mon branch main\x1b[0m",
            exit_code=0
        )
        self.assertEqual(snap1.turn_index, 1)
        self.assertEqual(snap1.current_state, "DECISION_GATE")
        self.assertTrue(len(snap1.checkpoint_merkle_root) == 64)
        self.assertEqual(self.runner.last_hook_receipts[-2].payload.phase, "PRE_TOOL_USE")
        self.assertEqual(self.runner.last_hook_receipts[-1].payload.phase, "POST_TOOL_USE")

        snap2 = self.runner.execute_turn_transition(
            turn_index=2,
            command="cargo test",
            raw_output="test result: ok. 12 passed",
            exit_code=0
        )
        self.assertEqual(snap2.turn_index, 2)
        self.assertNotEqual(snap1.checkpoint_merkle_root, snap2.checkpoint_merkle_root)

    def test_dangerous_terminal_command_rejected_before_state_transition(self):
        with self.assertRaises(LifecycleHookError):
            self.runner.execute_turn_transition(
                turn_index=1,
                command="Remove-Item C:\\ -Recurse -Force",
                raw_output="",
                exit_code=0
            )
        self.assertEqual(len(self.runner.turn_history), 0)

    def test_cas_state_rollback(self):
        for i in range(5):
            self.runner.execute_turn_transition(i, f"cmd_{i}", f"output_{i}", exit_code=0)

        self.assertEqual(len(self.runner.turn_history), 5)
        rolled_back_snap = self.runner.rollback_to_turn(2)
        self.assertIsNotNone(rolled_back_snap)
        self.assertEqual(rolled_back_snap.turn_index, 2)
        self.assertEqual(len(self.runner.turn_history), 3)
        self.assertEqual(self.runner.current_state, "ACTION_DISPATCH")

if __name__ == "__main__":
    unittest.main()
