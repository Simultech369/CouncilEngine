import unittest

from council_contracts import ReceiptEnvelope
from statem_runbook_bridge import StateMRunbookBridge, StateMRunbookExportReceipt


class TestStateMRunbookBridge(unittest.TestCase):

    def test_exported_runbook_contains_checked_transitions_and_receipt(self):
        bridge = StateMRunbookBridge()

        runbook_text, receipt_env = bridge.export_council_runbook()

        self.assertIn("initial: plan", runbook_text)
        self.assertIn("before_transfer:", runbook_text)
        self.assertIn('python -B -m unittest discover -p "test_*.py"', runbook_text)
        self.assertIn("from: verify", runbook_text)
        self.assertIn("to: handoff", runbook_text)
        self.assertIsInstance(receipt_env, ReceiptEnvelope)
        self.assertIsInstance(receipt_env.payload, StateMRunbookExportReceipt)
        self.assertEqual(receipt_env.payload.node_count, 4)
        self.assertTrue(receipt_env.payload.lifecycle_hooked)

    def test_validate_rejects_missing_required_node(self):
        bridge = StateMRunbookBridge()

        with self.assertRaises(ValueError) as ctx:
            bridge.validate_runbook_text("name: broken\ninitial: plan\nnodes:\n  plan:\nedges:\n")
        self.assertIn("node:execute", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
