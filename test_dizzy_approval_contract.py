import tempfile
import unittest
from pathlib import Path

from council_api_server import CouncilAPIServer
from human_approval import (
    HUMAN_APPROVAL_STATES,
    HUMAN_APPROVAL_TRANSITIONS,
    CouncilApprovalGate,
    IllegalApprovalTransitionError,
)
from bridge_rehearsal_runner import (
    BRIDGE_CANONICALIZATION,
    BRIDGE_REQUEST_SCHEMA,
    BRIDGE_RESPONSE_SCHEMA,
    canonical_json,
    execute_bridge_rehearsal,
    sha256_hex_lower,
)


class TestDizzyCouncilApprovalAndRouterContract(unittest.TestCase):
    """Verifies CouncilEngine Phase 1 task router, HITL approval gate, and shared Dizzy state contract."""

    def test_canonical_approval_states_match_dizzy_contract(self):
        self.assertEqual(
            HUMAN_APPROVAL_STATES,
            ("running", "waiting_for_approval", "approved", "rejected", "resumed", "cancelled"),
        )
        self.assertEqual(HUMAN_APPROVAL_TRANSITIONS["running"], ("waiting_for_approval", "cancelled"))
        self.assertEqual(
            HUMAN_APPROVAL_TRANSITIONS["waiting_for_approval"],
            ("approved", "rejected", "cancelled"),
        )
        self.assertEqual(HUMAN_APPROVAL_TRANSITIONS["approved"], ("resumed", "cancelled"))
        self.assertEqual(HUMAN_APPROVAL_TRANSITIONS["rejected"], ("cancelled",))
        self.assertEqual(HUMAN_APPROVAL_TRANSITIONS["resumed"], ())
        self.assertEqual(HUMAN_APPROVAL_TRANSITIONS["cancelled"], ())

    def test_approval_gate_persistence_resume_and_illegal_jumps(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate1 = CouncilApprovalGate(secret_key="shared-test-secret-32b", ledger_dir=tmp)
            cp = gate1.request_approval(
                subject_type="COUNCIL_PROMOTION",
                subject_payload_sha256="a" * 64,
                saved_progress={"step": "quorum_verified"},
                now=1000.0,
            )
            self.assertEqual(cp.workflow_state, "waiting_for_approval")

            # Illegal jump: waiting_for_approval -> resumed must fail
            with self.assertRaises(IllegalApprovalTransitionError):
                gate1.resume_with_token(resume_token=cp.resume_token, now=1001.0)

            # Reload from disk to simulate crash recovery
            gate2 = CouncilApprovalGate(secret_key="shared-test-secret-32b", ledger_dir=tmp)
            self.assertEqual(len(gate2.list_pending(now=1001.0)), 1)

            approved = gate2.resolve_approval(
                resume_token=cp.resume_token,
                decision="approve",
                approver_identity="operator_josh",
                reason="Verified offline checks",
                now=1002.0,
            )
            self.assertEqual(approved.workflow_state, "approved")

            resumed = gate2.resume_with_token(
                resume_token=cp.resume_token,
                expected_subject_sha256="a" * 64,
                now=1003.0,
            )
            self.assertEqual(resumed.workflow_state, "resumed")
            self.assertEqual(resumed.saved_progress["step"], "quorum_verified")

            # Double-resume and rejected -> resumed must fail
            with self.assertRaises(IllegalApprovalTransitionError):
                gate2.resume_with_token(resume_token=cp.resume_token, now=1004.0)

            cp_rej = gate2.request_approval(
                subject_type="AUTHORITY_UPGRADE",
                subject_payload_sha256="b" * 64,
                now=1005.0,
            )
            rejected = gate2.resolve_approval(
                resume_token=cp_rej.resume_token,
                decision="reject",
                approver_identity="operator_josh",
                reason="Missing container proof",
                now=1006.0,
            )
            self.assertEqual(rejected.workflow_state, "rejected")
            with self.assertRaises(IllegalApprovalTransitionError):
                gate2.resume_with_token(resume_token=cp_rej.resume_token, now=1007.0)

            audit = gate2.verify_audit_log()
            self.assertTrue(audit["valid"])
            self.assertGreaterEqual(audit["entry_count"], 7)

    def test_api_server_verification_job_router_and_promotion_blockers(self):
        api = CouncilAPIServer()
        job = api.handle_submit_verification_job({
            "objective": "Deploy upgraded Ed25519 A2A verification boundary",
            "candidate_files": ["a2a_protocol_engine.py", "test_a2a_protocol_engine.py"],
            "require_promotion_approval": True,
        })
        self.assertEqual(job["status"], "waiting_for_approval")
        self.assertFalse(job["promotion_allowed"])
        self.assertIn("human_approval_pending", job["promotion_blockers"])
        self.assertIn("deterministic_test_gate_not_passed", job["promotion_blockers"])
        self.assertIn("live_container_isolation_unverified", job["promotion_blockers"])
        self.assertTrue(job["resume_token"].startswith("hitl_tok_"))

        # Approve HITL checkpoint and satisfy evidence gates
        resolved = api.handle_resolve_approval({
            "resume_token": job["resume_token"],
            "decision": "approve",
            "approver_identity": "operator_alice",
            "reason": "Reviewed diff and receipts",
        })
        self.assertEqual(resolved["workflow_state"], "approved")

        updated = api.verification_jobs.update_job_evidence(
            job["job_id"],
            completed_roles=job["required_quorum_roles"],
            tests_passed=True,
            live_container_verified=True,
        )
        self.assertEqual(updated.status, "approved")
        self.assertEqual(updated.promotion_blockers, [])
        self.assertTrue(updated.promotion_allowed)

    def test_bridge_rehearsal_runner_validates_and_rejects_tamper(self):
        payload = {
            "bounty_task": {
                "bounty_id": "bounty_1",
                "title": "Security: Fix traversal bug",
                "description": "Patch traversal in parser",
                "target_files": ["lib/bounty_hunter_engine.mjs"],
                "test_command": "npm test",
                "payload_sha256": "1" * 64,
            },
            "proof_boundaries": ["sidecar_rehearsal_is_not_runtime_promotion"],
        }
        digest = sha256_hex_lower(canonical_json(payload))
        req = {
            "schema_version": BRIDGE_REQUEST_SCHEMA,
            "request_id": "req_01",
            "payload": payload,
            "integrity": {
                "canonicalization": BRIDGE_CANONICALIZATION,
                "payload_sha256": digest,
            },
        }
        resp = execute_bridge_rehearsal(req)
        self.assertEqual(resp["schema_version"], BRIDGE_RESPONSE_SCHEMA)
        self.assertEqual(resp["receipt_authority"], "rehearsal_receipt")
        self.assertEqual(resp["assigned_lane"], "SECURITY_REVIEWER")
        self.assertFalse(resp["runtime_promotion_allowed"])

        # Tamper payload without updating hash -> must fail
        tampered = {**req, "payload": {**payload, "extra": "tampered"}}
        with self.assertRaises(ValueError):
            execute_bridge_rehearsal(tampered)


if __name__ == "__main__":
    unittest.main()
