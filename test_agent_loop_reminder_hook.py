import unittest
from agent_loop_reminder_hook import AgentLoopReminderHook

class TestAgentLoopReminderHook(unittest.TestCase):

    def setUp(self):
        self.hook = AgentLoopReminderHook(agent_id="test_subagent_01")

    def test_single_and_different_calls(self):
        count, reminder = self.hook.record_tool_call("grep_search", {"query": "auth", "path": "src/"})
        self.assertEqual(count, 1)
        self.assertIsNone(reminder)

        # Different query should reset count
        count, reminder = self.hook.record_tool_call("grep_search", {"query": "payment", "path": "src/"})
        self.assertEqual(count, 1)
        self.assertIsNone(reminder)

    def test_escalating_reminders_on_repeats(self):
        args = {"query": "auth", "path": "src/"}

        # Calls 1 and 2: no reminder
        self.hook.record_tool_call("grep_search", args)
        self.hook.record_tool_call("grep_search", args)

        # Call 3: Advisory reminder
        count, rem3 = self.hook.record_tool_call("grep_search", args)
        self.assertEqual(count, 3)
        self.assertIsNotNone(rem3)
        self.assertIn("LOOP ADVISORY", rem3)

        # Call 4: no new threshold
        count, rem4 = self.hook.record_tool_call("grep_search", args)
        self.assertEqual(count, 4)
        self.assertIsNone(rem4)

        # Call 5: Warning reminder
        count, rem5 = self.hook.record_tool_call("grep_search", args)
        self.assertEqual(count, 5)
        self.assertIsNotNone(rem5)
        self.assertIn("LOOP WARNING", rem5)

        # Call 8: Critical reminder
        self.hook.record_tool_call("grep_search", args)
        self.hook.record_tool_call("grep_search", args)
        count, rem8 = self.hook.record_tool_call("grep_search", args)
        self.assertEqual(count, 8)
        self.assertIsNotNone(rem8)
        self.assertIn("LOOP CRITICAL", rem8)

    def test_transparent_noise_tool_does_not_reset_loop(self):
        args = {"file": "main.py"}
        self.hook.record_tool_call("read_file", args)
        self.hook.record_tool_call("read_file", args)

        # Intermediate todo update
        self.hook.record_tool_call("update_todo", {"task": "in progress"})

        # Third read_file call should trigger 3-repeat advisory despite intermediate todo
        count, rem3 = self.hook.record_tool_call("read_file", args)
        self.assertEqual(count, 3)
        self.assertIsNotNone(rem3)
        self.assertIn("LOOP ADVISORY", rem3)

    def test_order_invariant_argument_hashing(self):
        # Different dictionary key ordering
        args1 = {"a": 1, "b": 2, "c": 3}
        args2 = {"c": 3, "a": 1, "b": 2}

        self.hook.record_tool_call("custom_tool", args1)
        self.hook.record_tool_call("custom_tool", args2)
        count, rem = self.hook.record_tool_call("custom_tool", args1)
        self.assertEqual(count, 3)
        self.assertIsNotNone(rem)

if __name__ == "__main__":
    unittest.main()
