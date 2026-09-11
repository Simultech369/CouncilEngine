import os
import tempfile
import unittest
from windows_spend_ledger import WindowsAtomicSpendLedger

class TestWindowsSpendLedger(unittest.TestCase):

    def test_reservation_and_settlement_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "test_ledger.db")
            ledger = WindowsAtomicSpendLedger(db_path=db_path, hard_cap_usd=2.00)

            # 1. Reserve $0.80
            res_id = ledger.reserve_budget("gpt-5.6-sol", 0.80)
            self.assertTrue(res_id.startswith("res_"))

            # 2. Exceeding $2.00 hard cap must fail
            with self.assertRaises(RuntimeError):
                ledger.reserve_budget("gemini-3.1-pro-preview", 1.50)

            # 3. Settle actual spend of $0.60
            ledger.settle_reservation(res_id, 0.60)

            # 4. Attempting to settle above reserved $0.80 fails via DB trigger
            res2 = ledger.reserve_budget("claude-3.7-sonnet", 0.50)
            with self.assertRaises(Exception): # SQLite trigger aborts
                ledger.settle_reservation(res2, 0.90)

            # 5. Double settlement on already settled reservation fails
            with self.assertRaises(RuntimeError):
                ledger.settle_reservation(res_id, 0.10)

    def test_cancellation_and_expiration_sweep(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "test_sweep.db")
            ledger = WindowsAtomicSpendLedger(db_path=db_path, hard_cap_usd=2.00)

            # 1. Reserve and Cancel
            res1 = ledger.reserve_budget("qwen2.5-coder:7b", 0.50)
            ledger.cancel_reservation(res1)
            with self.assertRaises(RuntimeError):
                ledger.settle_reservation(res1, 0.40)

            # 2. Reserve and Sweep Expired (timeout_sec=-1 forces immediate expiration)
            res2 = ledger.reserve_budget("deepseek-r1:7b", 0.75)
            expired_count = ledger.sweep_expired_reservations(timeout_sec=-1.0)
            self.assertEqual(expired_count, 1)

            # 3. Settling an EXPIRED reservation must fail
            with self.assertRaises(RuntimeError):
                ledger.settle_reservation(res2, 0.50)

if __name__ == "__main__":
    unittest.main()
