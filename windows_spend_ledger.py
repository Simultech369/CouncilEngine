import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Optional

class WindowsAtomicSpendLedger:
    def __init__(
        self,
        db_path: Optional[str] = None,
        hard_cap_usd: Optional[float] = None
    ):
        state_dir = os.environ.get("COUNCIL_STATE_DIR") or os.path.expanduser("~/.council_state")
        self.db_path = db_path or os.path.join(state_dir, "ledger.db")
        self.hard_cap_usd = hard_cap_usd if hard_cap_usd is not None else float(os.environ.get("COUNCIL_SPEND_HARD_CAP_USD", "100.00"))
        
        dir_name = os.path.dirname(self.db_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
            
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reservations (
                    reservation_id TEXT PRIMARY KEY,
                    model_slug TEXT NOT NULL,
                    reserved_usd REAL NOT NULL CHECK(reserved_usd > 0),
                    status TEXT NOT NULL CHECK(status IN ('PENDING', 'SETTLED', 'CANCELLED', 'EXPIRED')),
                    created_at REAL NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settlements (
                    settlement_id TEXT PRIMARY KEY,
                    reservation_id TEXT NOT NULL UNIQUE,
                    actual_usd REAL NOT NULL CHECK(actual_usd >= 0),
                    settled_at REAL NOT NULL,
                    FOREIGN KEY (reservation_id) REFERENCES reservations (reservation_id)
                );
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS check_settlement_bound
                BEFORE INSERT ON settlements
                BEGIN
                    SELECT CASE
                        WHEN NEW.actual_usd > (SELECT reserved_usd FROM reservations WHERE reservation_id = NEW.reservation_id)
                        THEN RAISE(ABORT, 'Settlement amount exceeds reserved budget')
                    END;
                END;
            """)

    def reserve_budget(self, model_slug: str, worst_case_usd: float) -> str:
        if worst_case_usd <= 0:
            raise ValueError("Reservation amount must be positive")

        reservation_id = f"res_{uuid.uuid4().hex[:8]}"
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            
            cursor.execute("SELECT COALESCE(SUM(reserved_usd), 0.0) FROM reservations WHERE status = 'PENDING';")
            pending_res = cursor.fetchone()[0]

            cursor.execute("SELECT COALESCE(SUM(actual_usd), 0.0) FROM settlements;")
            total_settled = cursor.fetchone()[0]

            total_liability = total_settled + pending_res + worst_case_usd
            if total_liability > self.hard_cap_usd:
                conn.rollback()
                raise RuntimeError(
                    f"Spend ceiling exceeded: Requested ${worst_case_usd:.4f}, "
                    f"Total Liability: ${total_liability:.4f}, Hard Cap: ${self.hard_cap_usd:.4f}"
                )

            cursor.execute(
                "INSERT INTO reservations VALUES (?, ?, ?, 'PENDING', ?);",
                (reservation_id, model_slug, worst_case_usd, time.time())
            )
            conn.commit()
            return reservation_id

    def settle_reservation(self, reservation_id: str, actual_spent_usd: float):
        if actual_spent_usd < 0:
            raise ValueError("Settlement cost cannot be negative")

        settlement_id = f"set_{uuid.uuid4().hex[:8]}"
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            
            cursor.execute("SELECT reserved_usd, status FROM reservations WHERE reservation_id = ?;", (reservation_id,))
            row = cursor.fetchone()
            if not row:
                conn.rollback()
                raise KeyError(f"Reservation '{reservation_id}' does not exist")
            
            reserved_usd, status = row
            if status != "PENDING":
                conn.rollback()
                raise RuntimeError(f"Reservation '{reservation_id}' is already {status}")

            cursor.execute("UPDATE reservations SET status = 'SETTLED' WHERE reservation_id = ?;", (reservation_id,))
            cursor.execute(
                "INSERT INTO settlements VALUES (?, ?, ?, ?);",
                (settlement_id, reservation_id, actual_spent_usd, time.time())
            )
            conn.commit()

    def cancel_reservation(self, reservation_id: str, reason: str = "CANCELLED"):
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM reservations WHERE reservation_id = ?;", (reservation_id,))
            row = cursor.fetchone()
            if not row:
                conn.rollback()
                raise KeyError(f"Reservation '{reservation_id}' does not exist")
            if row[0] != "PENDING":
                conn.rollback()
                raise RuntimeError(f"Cannot cancel reservation '{reservation_id}' with status '{row[0]}'")
            cursor.execute("UPDATE reservations SET status = 'CANCELLED' WHERE reservation_id = ?;", (reservation_id,))
            conn.commit()

    def sweep_expired_reservations(self, timeout_sec: float = 300.0) -> int:
        cutoff = time.time() - timeout_sec
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE reservations SET status = 'EXPIRED' WHERE status = 'PENDING' AND created_at < ?;",
                (cutoff,)
            )
            expired_count = cursor.rowcount
            conn.commit()
            return expired_count
