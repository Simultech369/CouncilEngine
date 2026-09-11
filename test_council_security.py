import os
import hashlib
import time
import unittest
from windows_spend_ledger import WindowsAtomicSpendLedger
from council_contracts import (
    ReceiptEnvelope, SnapshotReceipt, PacketSensitivityReceipt, ArtifactProvenanceRecord,
    RouteAttestationReceipt, ModelQualificationReceipt, PaidBudgetReservationReceipt,
    ModelInvocationReceipt, CouncilRosterReceipt, CouncilVoteReceipt, RedactedVoteRecord,
    PatchReceipt, ExecutionSandboxReceipt, HumanApprovalReceipt, ApplyAuthorizationReceipt
)
from council_verifier import CouncilReceiptVerifier, VerificationError
from human_approval import HMACApprovalAuthenticator, DenyAllApprovalAuthenticator, Ed25519ApprovalAuthenticator

class TestCouncilV4_1Adversarial(unittest.TestCase):

    def setUp(self):
        self.now = time.time()
        self.raw_patch = b"--- a/src/main.py\n+++ b/src/main.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        self.patch_sha = hashlib.sha256(self.raw_patch).hexdigest()
        self.state_sha = "state_sha_999"

        # 1. Snapshot
        self.snapshot = SnapshotReceipt(
            head_commit="c", staged_diff_sha256="d1", unstaged_diff_sha256="d2",
            untracked_blobs=[], deleted_files=[], composite_state_sha256=self.state_sha, cas_storage_path="/cas"
        )
        self.snap_env = ReceiptEnvelope.seal(self.snapshot)

        # 2. Packet
        self.packet = PacketSensitivityReceipt(
            snapshot_composite_state_sha256=self.state_sha, sensitivity_tier="INTERNAL_NO_TRAIN_OK",
            public_safe_verified=False, private_artifact_count=1,
            artifacts=[ArtifactProvenanceRecord(artifact_id="a1", artifact_type="REPO_FILE", path_or_identifier="src/main.py", content_sha256="h", source_upstream_commit=None, source_upstream_url=None, provenance_verified=False, classification_reason="internal")]
        )
        self.pkt_env = ReceiptEnvelope.seal(self.packet)

        # 3. Patch
        self.patch = PatchReceipt(parent_snapshot_sha256=self.state_sha, patch_sha256=self.patch_sha, target_files_touched=["src/main.py"], hunks_count=1, sanitization_passed=True)
        self.patch_env = ReceiptEnvelope.seal(self.patch)

        # 4. Sandbox (Live Docker execution)
        self.sandbox = ExecutionSandboxReceipt(
            patch_payload_sha256=self.patch_env.payload_sha256,
            snapshot_composite_state_sha256=self.state_sha,
            isolation_mode="DOCKER_CONTAINER_ENFORCED",
            container_engine="docker",
            execution_mode="LIVE",
            container_image_digest=CouncilReceiptVerifier.TRUSTED_TOOLCHAIN_DIGEST,
            network_isolated=True, test_command=["pytest"], test_exit_code=0, test_passed=True,
            stdout_sha256="out_sha", stderr_sha256="err_sha", duration_sec=1.0
        )
        self.sandbox_env = ReceiptEnvelope.seal(self.sandbox)

        # 5. Qualifications, Routes, Invocations
        self.quals = {}
        self.routes = {}
        self.invs = {}
        self.budgets = {}

        voter_slugs = ["m1", "m2", "m3"]
        model_fams = ["qwen", "deepseek", "gpt"]

        for slug, fam in zip(voter_slugs, model_fams):
            q = ModelQualificationReceipt(composite_key=f"k_{slug}", model_slug=slug, model_family=fam, provider=f"p_{slug}", status="REVIEW_USABLE_FRESH", benign_control_passed=True, grounded_bug_passed=True, exact_line_quote_verified=True, json_schema_conformity=True, evaluated_at=self.now - 500, expires_at=self.now + 86400)
            q_env = ReceiptEnvelope.seal(q)
            self.quals[q_env.payload_sha256] = q_env

            r = RouteAttestationReceipt(route_id=f"route_{slug}", provider_name=f"p_{slug}", endpoint_url="url", account_hash="acc", compliance_tier="HOSTED_NO_TRAIN", content_retention_days=30, zdr_verified=False, fallbacks_allowed=False, issued_at=self.now - 500, expires_at=self.now + 3000)
            r_env = ReceiptEnvelope.seal(r)
            self.routes[r_env.payload_sha256] = r_env

            inv = ModelInvocationReceipt(
                packet_payload_sha256=self.pkt_env.payload_sha256,
                route_attestation_payload_sha256=r_env.payload_sha256,
                qualification_payload_sha256=q_env.payload_sha256,
                paid_budget_payload_sha256=None,
                model_slug=slug, model_family=fam, provider=f"p_{slug}", route_id=f"route_{slug}",
                request_payload_sha256="req", response_payload_sha256="resp", completed_at=self.now - 100
            )
            inv_env = ReceiptEnvelope.seal(inv)
            self.invs[inv_env.payload_sha256] = inv_env

        # 6. Roster
        self.roster = CouncilRosterReceipt(
            packet_payload_sha256=self.pkt_env.payload_sha256,
            patch_payload_sha256=self.patch_env.payload_sha256,
            frozen_voter_slugs=voter_slugs,
            frozen_model_families=model_fams,
            frozen_quorum_size=3
        )
        self.roster_env = ReceiptEnvelope.seal(self.roster)

        # 7. Vote
        self.vote = CouncilVoteReceipt(
            roster_payload_sha256=self.roster_env.payload_sha256,
            patch_payload_sha256=self.patch_env.payload_sha256,
            sandbox_payload_sha256=self.sandbox_env.payload_sha256,
            quorum_size=3, approvals_count=3, rejections_count=0,
            supermajority_achieved=True, critical_finding_veto=False, final_verdict="APPROVED",
            votes=[
                RedactedVoteRecord(voter_slug="m1", model_family="qwen", provider="p_m1", invocation_payload_sha256=list(self.invs.keys())[0], decision="approve", confidence=0.9, reasoning_sha256="h", redacted_summary="ok"),
                RedactedVoteRecord(voter_slug="m2", model_family="deepseek", provider="p_m2", invocation_payload_sha256=list(self.invs.keys())[1], decision="approve", confidence=0.9, reasoning_sha256="h", redacted_summary="ok"),
                RedactedVoteRecord(voter_slug="m3", model_family="gpt", provider="p_m3", invocation_payload_sha256=list(self.invs.keys())[2], decision="approve", confidence=0.9, reasoning_sha256="h", redacted_summary="ok"),
            ]
        )
        self.vote_env = ReceiptEnvelope.seal(self.vote)

        # 8. External Authenticated Human Approval
        self.authenticator = HMACApprovalAuthenticator()
        self.authenticator.register_key("key_operator_001", "operator_secret_123")

        self.human_approval_env = HMACApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.patch_env.payload_sha256,
            approver_identity="alice_lead",
            approver_key_id="key_operator_001",
            secret_key="operator_secret_123",
            validity_sec=3600
        )

        # 9. Apply Auth Receipt
        self.auth = ApplyAuthorizationReceipt(
            authorized_patch_sha256=self.patch_sha,
            target_composite_state_sha256=self.state_sha,
            council_vote_payload_sha256=self.vote_env.payload_sha256,
            auth_mode="INTERACTIVE_HUMAN_PROMPT",
            human_approval_payload_sha256=self.human_approval_env.payload_sha256
        )
        self.auth_env = ReceiptEnvelope.seal(self.auth)

    def test_full_chain_happy_path_passes(self):
        CouncilReceiptVerifier.verify_full_apply_chain(
            self.auth_env, self.vote_env, self.roster_env, self.invs, self.quals, self.routes,
            self.pkt_env, self.budgets, self.sandbox_env, self.patch_env, self.snap_env,
            self.human_approval_env, self.raw_patch, self.state_sha,
            authenticator=self.authenticator, current_time=self.now
        )

    def test_simulated_and_local_execution_cannot_authorize_apply(self):
        mock_sandbox = ExecutionSandboxReceipt(
            patch_payload_sha256=self.patch_env.payload_sha256,
            snapshot_composite_state_sha256=self.state_sha,
            isolation_mode="LOCAL_SUBPROCESS_MOCK",
            container_engine="docker_mock",
            execution_mode="SIMULATED",
            container_image_digest=CouncilReceiptVerifier.TRUSTED_TOOLCHAIN_DIGEST,
            network_isolated=False, test_command=["pytest"], test_exit_code=0, test_passed=True,
            stdout_sha256="out", stderr_sha256="err", duration_sec=0.1
        )
        mock_sandbox_env = ReceiptEnvelope.seal(mock_sandbox)
        
        linked_vote = CouncilVoteReceipt(
            roster_payload_sha256=self.roster_env.payload_sha256,
            patch_payload_sha256=self.patch_env.payload_sha256,
            sandbox_payload_sha256=mock_sandbox_env.payload_sha256,
            quorum_size=3, approvals_count=3, rejections_count=0,
            supermajority_achieved=True, critical_finding_veto=False, final_verdict="APPROVED",
            votes=self.vote.votes
        )
        linked_vote_env = ReceiptEnvelope.seal(linked_vote)
        linked_auth = ApplyAuthorizationReceipt(
            authorized_patch_sha256=self.patch_sha,
            target_composite_state_sha256=self.state_sha,
            council_vote_payload_sha256=linked_vote_env.payload_sha256,
            auth_mode="INTERACTIVE_HUMAN_PROMPT",
            human_approval_payload_sha256=self.human_approval_env.payload_sha256
        )
        linked_auth_env = ReceiptEnvelope.seal(linked_auth)

        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_full_apply_chain(
                linked_auth_env, linked_vote_env, self.roster_env, self.invs, self.quals, self.routes,
                self.pkt_env, self.budgets, mock_sandbox_env, self.patch_env, self.snap_env,
                self.human_approval_env, self.raw_patch, self.state_sha,
                authenticator=self.authenticator, current_time=self.now
            )
        self.assertIn("isolation_mode was 'LOCAL_SUBPROCESS_MOCK'", str(ctx.exception))

    def test_bot_or_invalid_signature_cannot_authorize_apply(self):
        forged_approval = HMACApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.patch_env.payload_sha256,
            approver_identity="forger_bot",
            approver_key_id="key_operator_001",
            secret_key="wrong_secret_key",
            validity_sec=3600
        )
        forged_auth = ApplyAuthorizationReceipt(
            authorized_patch_sha256=self.patch_sha,
            target_composite_state_sha256=self.state_sha,
            council_vote_payload_sha256=self.vote_env.payload_sha256,
            auth_mode="INTERACTIVE_HUMAN_PROMPT",
            human_approval_payload_sha256=forged_approval.payload_sha256
        )
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_full_apply_chain(
                ReceiptEnvelope.seal(forged_auth), self.vote_env, self.roster_env, self.invs, self.quals, self.routes,
                self.pkt_env, self.budgets, self.sandbox_env, self.patch_env, self.snap_env,
                forged_approval, self.raw_patch, self.state_sha,
                authenticator=self.authenticator, current_time=self.now
            )
        self.assertIn("Human approval signature verification failed", str(ctx.exception))

    def test_hmac_authenticator_rejects_mismatched_declared_algorithm(self):
        mislabeled_payload = self.human_approval_env.payload.model_copy(update={"signature_algorithm": "ED25519"})
        mislabeled_approval_env = ReceiptEnvelope.seal(mislabeled_payload)
        self.assertFalse(
            self.authenticator.authenticate_approval(
                mislabeled_approval_env,
                self.patch_env.payload_sha256
            )
        )

        mislabeled_auth = ApplyAuthorizationReceipt(
            authorized_patch_sha256=self.patch_sha,
            target_composite_state_sha256=self.state_sha,
            council_vote_payload_sha256=self.vote_env.payload_sha256,
            auth_mode="INTERACTIVE_HUMAN_PROMPT",
            human_approval_payload_sha256=mislabeled_approval_env.payload_sha256
        )
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_full_apply_chain(
                ReceiptEnvelope.seal(mislabeled_auth), self.vote_env, self.roster_env, self.invs, self.quals, self.routes,
                self.pkt_env, self.budgets, self.sandbox_env, self.patch_env, self.snap_env,
                mislabeled_approval_env, self.raw_patch, self.state_sha,
                authenticator=self.authenticator, current_time=self.now
            )
        self.assertIn("Human approval signature verification failed", str(ctx.exception))

    def test_ed25519_approval_can_authorize_full_apply_chain(self):
        private_key = "01" * 32
        public_key = Ed25519ApprovalAuthenticator.derive_public_key(private_key)
        authenticator = Ed25519ApprovalAuthenticator({"key_operator_ed25519": public_key})
        approval_env = Ed25519ApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.patch_env.payload_sha256,
            approver_identity="alice_ed25519_lead",
            approver_key_id="key_operator_ed25519",
            private_key=private_key,
            validity_sec=3600
        )
        auth_env = ReceiptEnvelope.seal(ApplyAuthorizationReceipt(
            authorized_patch_sha256=self.patch_sha,
            target_composite_state_sha256=self.state_sha,
            council_vote_payload_sha256=self.vote_env.payload_sha256,
            auth_mode="INTERACTIVE_HUMAN_PROMPT",
            human_approval_payload_sha256=approval_env.payload_sha256
        ))

        CouncilReceiptVerifier.verify_full_apply_chain(
            auth_env, self.vote_env, self.roster_env, self.invs, self.quals, self.routes,
            self.pkt_env, self.budgets, self.sandbox_env, self.patch_env, self.snap_env,
            approval_env, self.raw_patch, self.state_sha,
            authenticator=authenticator, current_time=self.now
        )

    def test_forged_public_safe_packet_rejected_in_route_compatibility(self):
        forged_pkt = PacketSensitivityReceipt(
            snapshot_composite_state_sha256=self.state_sha, sensitivity_tier="PUBLIC_SAFE",
            public_safe_verified=True, private_artifact_count=0,
            artifacts=[ArtifactProvenanceRecord(artifact_id="a1", artifact_type="TERMINAL_LOG", path_or_identifier="err.log", content_sha256="h", source_upstream_commit=None, source_upstream_url=None, provenance_verified=False, classification_reason="log")]
        )
        route_env = list(self.routes.values())[0]
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_route_packet_compatibility(ReceiptEnvelope.seal(forged_pkt), route_env, current_time=self.now)
        self.assertTrue("Contradiction" in str(ctx.exception) or "unverified private artifacts" in str(ctx.exception))

    def test_overlong_or_fallback_route_rejected_before_invocation(self):
        bad_route = RouteAttestationReceipt(route_id="r_bad", provider_name="p", endpoint_url="url", account_hash="acc", compliance_tier="HOSTED_NO_TRAIN", content_retention_days=30, zdr_verified=False, fallbacks_allowed=True, issued_at=self.now, expires_at=self.now + 1000)
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_route_attestation(ReceiptEnvelope.seal(bad_route), current_time=self.now)
        self.assertIn("Private/Paid route cannot allow third-party fallbacks", str(ctx.exception))

    def test_vote_patch_hash_must_match_actual_patch_receipt(self):
        mismatched_vote = CouncilVoteReceipt(
            roster_payload_sha256=self.roster_env.payload_sha256,
            patch_payload_sha256="different_patch_payload_sha",
            sandbox_payload_sha256=self.sandbox_env.payload_sha256,
            quorum_size=3, approvals_count=3, rejections_count=0,
            supermajority_achieved=True, critical_finding_veto=False, final_verdict="APPROVED",
            votes=self.vote.votes
        )
        bad_vote_env = ReceiptEnvelope.seal(mismatched_vote)
        bad_auth = ApplyAuthorizationReceipt(authorized_patch_sha256=self.patch_sha, target_composite_state_sha256=self.state_sha, council_vote_payload_sha256=bad_vote_env.payload_sha256, auth_mode="INTERACTIVE_HUMAN_PROMPT", human_approval_payload_sha256=self.human_approval_env.payload_sha256)
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_full_apply_chain(
                ReceiptEnvelope.seal(bad_auth), bad_vote_env, self.roster_env, self.invs, self.quals, self.routes,
                self.pkt_env, self.budgets, self.sandbox_env, self.patch_env, self.snap_env,
                self.human_approval_env, self.raw_patch, self.state_sha,
                authenticator=self.authenticator, current_time=self.now
            )
        self.assertIn("Council vote does not link to candidate patch receipt hash", str(ctx.exception))

    def test_vote_sandbox_hash_must_match_actual_sandbox_receipt(self):
        mismatched_vote = CouncilVoteReceipt(
            roster_payload_sha256=self.roster_env.payload_sha256,
            patch_payload_sha256=self.patch_env.payload_sha256,
            sandbox_payload_sha256="different_sandbox_payload_sha",
            quorum_size=3, approvals_count=3, rejections_count=0,
            supermajority_achieved=True, critical_finding_veto=False, final_verdict="APPROVED",
            votes=self.vote.votes
        )
        bad_vote_env = ReceiptEnvelope.seal(mismatched_vote)
        bad_auth = ApplyAuthorizationReceipt(authorized_patch_sha256=self.patch_sha, target_composite_state_sha256=self.state_sha, council_vote_payload_sha256=bad_vote_env.payload_sha256, auth_mode="INTERACTIVE_HUMAN_PROMPT", human_approval_payload_sha256=self.human_approval_env.payload_sha256)
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_full_apply_chain(
                ReceiptEnvelope.seal(bad_auth), bad_vote_env, self.roster_env, self.invs, self.quals, self.routes,
                self.pkt_env, self.budgets, self.sandbox_env, self.patch_env, self.snap_env,
                self.human_approval_env, self.raw_patch, self.state_sha,
                authenticator=self.authenticator, current_time=self.now
            )
        self.assertIn("Council vote does not link to sandbox receipt hash", str(ctx.exception))

    def test_roster_packet_and_patch_hashes_must_match_chain(self):
        mismatched_roster = CouncilRosterReceipt(
            packet_payload_sha256="mismatched_pkt_sha",
            patch_payload_sha256=self.patch_env.payload_sha256,
            frozen_voter_slugs=["m1", "m2", "m3"], frozen_model_families=["qwen", "deepseek", "gpt"], frozen_quorum_size=3
        )
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_full_apply_chain(
                self.auth_env, self.vote_env, ReceiptEnvelope.seal(mismatched_roster), self.invs, self.quals, self.routes,
                self.pkt_env, self.budgets, self.sandbox_env, self.patch_env, self.snap_env,
                self.human_approval_env, self.raw_patch, self.state_sha,
                authenticator=self.authenticator, current_time=self.now
            )
        self.assertIn("Roster packet hash does not match packet receipt hash", str(ctx.exception))

    def test_roster_entries_must_be_unique_and_match_quorum(self):
        duplicate_roster = CouncilRosterReceipt(
            packet_payload_sha256=self.pkt_env.payload_sha256,
            patch_payload_sha256=self.patch_env.payload_sha256,
            frozen_voter_slugs=["m1", "m1", "m3"],
            frozen_model_families=["qwen", "deepseek", "gpt"], frozen_quorum_size=3
        )
        dup_roster_env = ReceiptEnvelope.seal(duplicate_roster)
        dup_vote = CouncilVoteReceipt(
            roster_payload_sha256=dup_roster_env.payload_sha256,
            patch_payload_sha256=self.patch_env.payload_sha256,
            sandbox_payload_sha256=self.sandbox_env.payload_sha256,
            quorum_size=3, approvals_count=3, rejections_count=0,
            supermajority_achieved=True, critical_finding_veto=False, final_verdict="APPROVED",
            votes=self.vote.votes
        )
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_council_vote(
                ReceiptEnvelope.seal(dup_vote), dup_roster_env, self.invs, self.quals, self.routes, self.pkt_env, self.budgets, current_time=self.now
            )
        self.assertIn("Duplicate voter slug detected in frozen roster", str(ctx.exception))

    def test_invocation_route_id_and_provider_must_match_attestation(self):
        route_env = list(self.routes.values())[0]
        bad_inv = ModelInvocationReceipt(
            packet_payload_sha256=self.pkt_env.payload_sha256,
            route_attestation_payload_sha256=route_env.payload_sha256,
            qualification_payload_sha256=list(self.quals.keys())[0],
            paid_budget_payload_sha256=None,
            model_slug="m1", model_family="qwen", provider="rogue_provider", route_id="route_m1",
            request_payload_sha256="req", response_payload_sha256="resp", completed_at=self.now - 100
        )
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_model_invocation(
                ReceiptEnvelope.seal(bad_inv), self.pkt_env, route_env, list(self.quals.values())[0], None, current_time=self.now
            )
        self.assertIn("Invocation provider 'rogue_provider' != route provider 'p_m1'", str(ctx.exception))

    def test_patch_sanitization_passed_false_rejects_even_if_bytes_parse(self):
        unsanitized_patch = PatchReceipt(
            parent_snapshot_sha256=self.state_sha, patch_sha256=self.patch_sha,
            target_files_touched=["src/main.py"], hunks_count=1,
            sanitization_passed=False
        )
        unsanitized_patch_env = ReceiptEnvelope.seal(unsanitized_patch)

        unsanitized_approval = HMACApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=unsanitized_patch_env.payload_sha256,
            approver_identity="alice_lead",
            approver_key_id="key_operator_001",
            secret_key="operator_secret_123",
            validity_sec=3600
        )

        unsanitized_vote = CouncilVoteReceipt(
            roster_payload_sha256=self.roster_env.payload_sha256,
            patch_payload_sha256=unsanitized_patch_env.payload_sha256,
            sandbox_payload_sha256=self.sandbox_env.payload_sha256,
            quorum_size=3, approvals_count=3, rejections_count=0,
            supermajority_achieved=True, critical_finding_veto=False, final_verdict="APPROVED",
            votes=self.vote.votes
        )
        unsanitized_vote_env = ReceiptEnvelope.seal(unsanitized_vote)

        unsanitized_auth = ApplyAuthorizationReceipt(
            authorized_patch_sha256=self.patch_sha,
            target_composite_state_sha256=self.state_sha,
            council_vote_payload_sha256=unsanitized_vote_env.payload_sha256,
            auth_mode="INTERACTIVE_HUMAN_PROMPT",
            human_approval_payload_sha256=unsanitized_approval.payload_sha256
        )
        unsanitized_auth_env = ReceiptEnvelope.seal(unsanitized_auth)

        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_full_apply_chain(
                unsanitized_auth_env, unsanitized_vote_env, self.roster_env, self.invs, self.quals, self.routes,
                self.pkt_env, self.budgets, self.sandbox_env, unsanitized_patch_env, self.snap_env,
                unsanitized_approval, self.raw_patch, self.state_sha,
                authenticator=self.authenticator, current_time=self.now
            )
        self.assertIn("Apply rejected: PatchReceipt sanitization_passed is False", str(ctx.exception))

    def test_model_qualification_false_gates_rejected_even_if_status_fresh(self):
        route_env = list(self.routes.values())[0]
        bad_qual = ModelQualificationReceipt(
            composite_key="k_bad",
            model_slug="m1",
            model_family="qwen",
            provider="p_m1",
            status="REVIEW_USABLE_FRESH",
            benign_control_passed=False,
            grounded_bug_passed=False,
            exact_line_quote_verified=False,
            json_schema_conformity=False,
            evaluated_at=self.now - 500,
            expires_at=self.now + 86400
        )
        bad_qual_env = ReceiptEnvelope.seal(bad_qual)
        inv = ModelInvocationReceipt(
            packet_payload_sha256=self.pkt_env.payload_sha256,
            route_attestation_payload_sha256=route_env.payload_sha256,
            qualification_payload_sha256=bad_qual_env.payload_sha256,
            paid_budget_payload_sha256=None,
            model_slug="m1", model_family="qwen", provider="p_m1", route_id="route_m1",
            request_payload_sha256="req", response_payload_sha256="resp", completed_at=self.now - 100
        )
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_model_invocation(
                ReceiptEnvelope.seal(inv), self.pkt_env, route_env, bad_qual_env, None, current_time=self.now
            )
        self.assertIn("failed required qualification gates", str(ctx.exception))

    def test_path_traversal_patch_rejected_by_parser(self):
        traversal_patch = b"--- a/src/main.py\n+++ b/../../../etc/passwd\n@@ -1,1 +1,1 @@\n-old\n+root:x:0:0::/root:/bin/bash\n"
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.parse_and_sanitize_patch(traversal_patch)
        self.assertIn("Security violation", str(ctx.exception))

    def test_windows_drive_path_patch_rejected_by_parser(self):
        drive_patch = b"--- a/src/main.py\n+++ b/C:\\Windows\\System32\\cmd.exe\n@@ -1,1 +1,1 @@\n-old\n+evil\n"
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.parse_and_sanitize_patch(drive_patch)
        self.assertIn("Security violation", str(ctx.exception))

    def test_gitmodules_manipulation_patch_rejected_by_parser(self):
        gitmodules_patch = b"--- a/.gitmodules\n+++ b/.gitmodules\n@@ -1,3 +1,3 @@\n-[submodule]\n+[submodule \"evil\"]\n"
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.parse_and_sanitize_patch(gitmodules_patch)
        self.assertIn("forbidden construct", str(ctx.exception))

    def test_symlink_creation_patch_rejected_by_parser(self):
        symlink_patch = b"diff --git a/link b/link\nnew file mode 120000\nindex 0000000..1234567\n--- /dev/null\n+++ b/link\n@@ -0,0 +1,1 @@\n+/etc/shadow\n"
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.parse_and_sanitize_patch(symlink_patch)
        self.assertIn("forbidden construct", str(ctx.exception))

    def test_future_clock_skew_route_rejected(self):
        future_route = RouteAttestationReceipt(
            route_id="r_future", provider_name="p", endpoint_url="u", account_hash="a",
            compliance_tier="LOCAL_ONLY_VERIFIED", content_retention_days=0,
            zdr_verified=True, fallbacks_allowed=False,
            issued_at=self.now + 100.0, expires_at=self.now + 3600.0
        )
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_route_attestation(ReceiptEnvelope.seal(future_route), current_time=self.now)
        self.assertIn("Route attestation issued in future", str(ctx.exception))

    def test_expired_route_attestation_rejected(self):
        expired_route = RouteAttestationReceipt(
            route_id="r_expired", provider_name="p", endpoint_url="u", account_hash="a",
            compliance_tier="LOCAL_ONLY_VERIFIED", content_retention_days=0,
            zdr_verified=True, fallbacks_allowed=False,
            issued_at=self.now - 4000.0, expires_at=self.now - 500.0
        )
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_route_attestation(ReceiptEnvelope.seal(expired_route), current_time=self.now)
        self.assertIn("expired", str(ctx.exception))

    def test_settled_cost_exceeding_reserved_budget_rejected(self):
        apex_route = RouteAttestationReceipt(
            route_id="r_apex", provider_name="openai", endpoint_url="https://api.openai.com", account_hash="acc",
            compliance_tier="APEX_PAID", content_retention_days=0, zdr_verified=True, fallbacks_allowed=False,
            issued_at=self.now - 200, expires_at=self.now + 3000
        )
        apex_route_env = ReceiptEnvelope.seal(apex_route)
        
        overspent_budget = PaidBudgetReservationReceipt(
            model_slug="gpt-5.6-sol", max_input_tokens=4000, max_output_tokens=1000,
            reserved_cost_usd=0.05, settled_cost_usd=0.15, authorized_reason_code="APEX_AUDIT",
            allocated_at=self.now - 300, settled_at=self.now - 50
        )
        overspent_budget_env = ReceiptEnvelope.seal(overspent_budget)

        q = ModelQualificationReceipt(
            composite_key="k_apex", model_slug="gpt-5.6-sol", model_family="gpt", provider="openai",
            status="REVIEW_USABLE_FRESH", benign_control_passed=True, grounded_bug_passed=True,
            exact_line_quote_verified=True, json_schema_conformity=True,
            evaluated_at=self.now - 400, expires_at=self.now + 86400
        )
        q_env = ReceiptEnvelope.seal(q)

        inv = ModelInvocationReceipt(
            packet_payload_sha256=self.pkt_env.payload_sha256,
            route_attestation_payload_sha256=apex_route_env.payload_sha256,
            qualification_payload_sha256=q_env.payload_sha256,
            paid_budget_payload_sha256=overspent_budget_env.payload_sha256,
            model_slug="gpt-5.6-sol", model_family="gpt", provider="openai", route_id="r_apex",
            request_payload_sha256="req", response_payload_sha256="resp", completed_at=self.now - 100
        )
        inv_env = ReceiptEnvelope.seal(inv)

        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_model_invocation(
                inv_env, self.pkt_env, apex_route_env, q_env, overspent_budget_env, current_time=self.now
            )
        self.assertIn("settled cost exceeds reserved budget", str(ctx.exception))

    def test_mismatched_model_slug_in_budget_rejected(self):
        apex_route = RouteAttestationReceipt(
            route_id="r_apex", provider_name="openai", endpoint_url="https://api.openai.com", account_hash="acc",
            compliance_tier="APEX_PAID", content_retention_days=0, zdr_verified=True, fallbacks_allowed=False,
            issued_at=self.now - 200, expires_at=self.now + 3000
        )
        apex_route_env = ReceiptEnvelope.seal(apex_route)
        
        mismatched_budget = PaidBudgetReservationReceipt(
            model_slug="claude-3.7-sonnet", max_input_tokens=4000, max_output_tokens=1000,
            reserved_cost_usd=0.05, settled_cost_usd=0.04, authorized_reason_code="APEX_AUDIT",
            allocated_at=self.now - 300, settled_at=self.now - 50
        )
        mismatched_budget_env = ReceiptEnvelope.seal(mismatched_budget)

        q = ModelQualificationReceipt(
            composite_key="k_apex", model_slug="gpt-5.6-sol", model_family="gpt", provider="openai",
            status="REVIEW_USABLE_FRESH", benign_control_passed=True, grounded_bug_passed=True,
            exact_line_quote_verified=True, json_schema_conformity=True,
            evaluated_at=self.now - 400, expires_at=self.now + 86400
        )
        q_env = ReceiptEnvelope.seal(q)

        inv = ModelInvocationReceipt(
            packet_payload_sha256=self.pkt_env.payload_sha256,
            route_attestation_payload_sha256=apex_route_env.payload_sha256,
            qualification_payload_sha256=q_env.payload_sha256,
            paid_budget_payload_sha256=mismatched_budget_env.payload_sha256,
            model_slug="gpt-5.6-sol", model_family="gpt", provider="openai", route_id="r_apex",
            request_payload_sha256="req", response_payload_sha256="resp", completed_at=self.now - 100
        )
        inv_env = ReceiptEnvelope.seal(inv)

        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.verify_model_invocation(
                inv_env, self.pkt_env, apex_route_env, q_env, mismatched_budget_env, current_time=self.now
            )
        self.assertIn("Paid budget slug mismatch", str(ctx.exception))

    def test_sensitive_files_patch_rejected_by_parser(self):
        env_patch = b"--- a/.env\n+++ b/.env\n@@ -1,1 +1,1 @@\n-SECRET=1\n+SECRET=2\n"
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.parse_and_sanitize_patch(env_patch)
        self.assertIn("forbidden construct", str(ctx.exception))

        cred_patch = b"--- a/src/credentials.json\n+++ b/src/credentials.json\n@@ -1,1 +1,1 @@\n-1\n+2\n"
        with self.assertRaises(VerificationError) as ctx:
            CouncilReceiptVerifier.parse_and_sanitize_patch(cred_patch)
        self.assertIn("forbidden construct", str(ctx.exception))

    def test_spend_ledger_cancellation_and_sweep(self):
        import tempfile
        db_path = os.path.join(tempfile.gettempdir(), f"ledger_test_{int(time.time()*1000)}.db")
        try:
            ledger = WindowsAtomicSpendLedger(db_path=db_path, hard_cap_usd=1.0)
            
            res_id = ledger.reserve_budget("m_test", 0.20)
            ledger.cancel_reservation(res_id)
            
            with self.assertRaises(RuntimeError):
                ledger.settle_reservation(res_id, 0.10)

            res_id2 = ledger.reserve_budget("m_test2", 0.30)
            expired_count = ledger.sweep_expired_reservations(timeout_sec=-1.0)
            self.assertEqual(expired_count, 1)

            with self.assertRaises(RuntimeError):
                ledger.settle_reservation(res_id2, 0.20)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

if __name__ == "__main__":
    unittest.main()
