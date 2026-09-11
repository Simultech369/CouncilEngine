import hashlib
import json
import math
import os
import re
import time
from typing import Any, Optional, List, Dict, Type, Set, Tuple
from council_contracts import (
    CONTRACT_VERSION, ImmutableContract, ReceiptEnvelope, SnapshotReceipt,
    PacketSensitivityReceipt, RouteAttestationReceipt, ModelQualificationReceipt,
    PaidBudgetReservationReceipt, ModelInvocationReceipt, CouncilRosterReceipt,
    CouncilVoteReceipt, PatchReceipt, ExecutionSandboxReceipt, HumanApprovalReceipt,
    ApplyAuthorizationReceipt, ReviewHopTraceReceipt
)
from human_approval import ApprovalAuthenticator, DenyAllApprovalAuthenticator

class VerificationError(Exception):
    pass

class CouncilReceiptVerifier:
    MAX_PRIVATE_TTL_SEC = 3600
    MAX_PUBLIC_TTL_SEC = 86400
    TRUSTED_TOOLCHAIN_DIGEST = "sha256:69b4e54e4f9b8849ffb7deab04b126fb21f1d17fb6e1dbff50ec335c0ad9ab65"

    @classmethod
    def verify_envelope(cls, envelope: ReceiptEnvelope, expected_type: Type[ImmutableContract]) -> None:
        if envelope.contract_version != CONTRACT_VERSION:
            raise VerificationError(f"Contract version mismatch: {envelope.contract_version} != {CONTRACT_VERSION}")
        if envelope.receipt_type != expected_type.__name__:
            raise VerificationError(f"Receipt type mismatch: {envelope.receipt_type} != {expected_type.__name__}")
        if not isinstance(envelope.payload, expected_type):
            raise VerificationError(f"Payload instance mismatch for {expected_type.__name__}")
        if envelope.payload_sha256 != envelope.payload.compute_canonical_sha256():
            raise VerificationError(f"Payload digest corrupted for {envelope.receipt_type}")

        expected_envelope_data = f"{CONTRACT_VERSION}:{envelope.receipt_type}:{envelope.payload_sha256}:{envelope.created_at}"
        expected_envelope_digest = hashlib.sha256(expected_envelope_data.encode("utf-8")).hexdigest()
        if envelope.envelope_sha256 != expected_envelope_digest:
            raise VerificationError(f"Envelope digest corrupted for {envelope.receipt_type}")
        if expected_type is ReviewHopTraceReceipt:
            cls.verify_review_hop_trace(envelope)

    @staticmethod
    def _sha256_json(value: Any) -> str:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _is_sha256(value: str) -> bool:
        return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))

    @classmethod
    def verify_review_hop_trace(cls, envelope: ReceiptEnvelope[ReviewHopTraceReceipt]) -> None:
        receipt = envelope.payload

        if receipt.provenance_only is not True:
            raise VerificationError("Review hop trace must be provenance-only")
        if receipt.remote_execution_permitted is not False:
            raise VerificationError("Review hop trace cannot permit remote execution")
        if receipt.production_execution_claimed is not False:
            raise VerificationError("Review hop trace cannot claim production execution")
        if receipt.audit_replacement_claimed is not False:
            raise VerificationError("Review hop trace cannot claim audit replacement")
        if receipt.git_observation_status == "UNAVAILABLE" and receipt.dirty_files != ["UNKNOWN_GIT_STATUS"]:
            raise VerificationError("Unavailable Git observations must fail closed with UNKNOWN_GIT_STATUS")
        if receipt.isolation_mode == "LOCAL_SUBPROCESS_MOCK" and receipt.network_isolated:
            raise VerificationError("LOCAL_SUBPROCESS_MOCK cannot claim network isolation")
        if receipt.isolation_mode == "READ_ONLY_NO_EXECUTION" and any(cmd.executed for cmd in receipt.commands):
            raise VerificationError("READ_ONLY_NO_EXECUTION cannot include executed command records")
        if receipt.isolation_mode == "DOCKER_CONTAINER_ENFORCED":
            raise VerificationError("ReviewHopTraceReceipt lacks a linked sandbox receipt for DOCKER_CONTAINER_ENFORCED")

        for field_name in (
            "reviewed_content_sha256",
            "toolchain_manifest_sha256",
            "input_payload_sha256",
            "output_payload_sha256",
            "command_manifest_sha256",
            "execution_environment_hash_sha256",
        ):
            if not cls._is_sha256(getattr(receipt, field_name)):
                raise VerificationError(f"Review hop trace field {field_name} is not a canonical sha256 digest")

        expected_command_manifest = cls._sha256_json([cmd.model_dump() for cmd in receipt.commands])
        if receipt.command_manifest_sha256 != expected_command_manifest:
            raise VerificationError("Review hop command manifest hash mismatch")

        for cmd in receipt.commands:
            expected_cmd_sha = cls._sha256_json([str(part) for part in cmd.command_argv])
            if cmd.command_sha256 != expected_cmd_sha:
                raise VerificationError("Review hop command argv hash mismatch")
            if not cmd.executed:
                if any(value is not None for value in (cmd.exit_code, cmd.stdout_sha256, cmd.stderr_sha256, cmd.duration_sec)):
                    raise VerificationError("Non-executed review hop command contains execution artifacts")
            else:
                if cmd.exit_code is None:
                    raise VerificationError("Executed review hop command missing exit_code")
                if cmd.duration_sec is not None and cmd.duration_sec < 0:
                    raise VerificationError("Review hop command duration cannot be negative")
                if cmd.stdout_sha256 is not None and not cls._is_sha256(cmd.stdout_sha256):
                    raise VerificationError("Review hop stdout digest is not canonical sha256")
                if cmd.stderr_sha256 is not None and not cls._is_sha256(cmd.stderr_sha256):
                    raise VerificationError("Review hop stderr digest is not canonical sha256")

        expected_environment_hash = cls._sha256_json({
            "git_head_commit": receipt.git_head_commit,
            "git_branch": receipt.git_branch,
            "git_observation_status": receipt.git_observation_status,
            "working_tree_dirty": receipt.working_tree_dirty,
            "dirty_files": receipt.dirty_files,
            "reviewed_content_sha256": receipt.reviewed_content_sha256,
            "command_manifest_sha256": receipt.command_manifest_sha256,
            "toolchain_manifest_sha256": receipt.toolchain_manifest_sha256,
            "isolation_mode": receipt.isolation_mode,
            "network_isolated": receipt.network_isolated,
        })
        if receipt.execution_environment_hash_sha256 != expected_environment_hash:
            raise VerificationError("Review hop execution environment hash mismatch")

    @staticmethod
    def parse_and_sanitize_patch(raw_patch_bytes: bytes) -> Tuple[Set[str], int]:
        try:
            text = raw_patch_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise VerificationError("Patch rejected: Non-UTF8 binary content")

        touched_files = set()
        hunk_count = 0

        for line in text.splitlines():
            if line.startswith("@@ -") and " @@" in line:
                hunk_count += 1

            if any(forbidden in line for forbidden in [
                ".gitmodules", ".git/", ".github/", "hooks/", "new file mode 120000",
                ".env", "credentials", "id_rsa", "id_ed25519",
                "../", "..\\", "/..", "\\.."
            ]):
                raise VerificationError(f"Security violation in patch: forbidden construct '{line}'")

            if line.startswith("rename to ") or line.startswith("copy to "):
                target = line.split(" ", 2)[2].strip()
                if target.startswith("/") or target.startswith("\\") or ":" in target:
                    raise VerificationError(f"Security violation: Illegal rename target '{target}'")
                touched_files.add(os.path.normpath(target).replace("\\", "/"))

            if line.startswith("+++ b/"):
                target = line[6:].strip()
                if target == "/dev/null":
                    continue
                if target.startswith("/") or target.startswith("\\") or ":" in target or target.startswith('"'):
                    raise VerificationError(f"Security violation: Illegal path format '{target}'")
                norm_target = os.path.normpath(target).replace("\\", "/")
                if norm_target.startswith("../") or norm_target.startswith("/"):
                    raise VerificationError(f"Path traversal detected: '{norm_target}'")
                touched_files.add(norm_target)

            elif line.startswith("--- a/"):
                target = line[6:].strip()
                if target != "/dev/null":
                    if target.startswith("/") or target.startswith("\\") or ":" in target or target.startswith('"'):
                        raise VerificationError(f"Security violation: Illegal path format '{target}'")
                    norm_target = os.path.normpath(target).replace("\\", "/")
                    if norm_target.startswith("../") or norm_target.startswith("/"):
                        raise VerificationError(f"Path traversal detected: '{norm_target}'")
                    touched_files.add(norm_target)

        if not touched_files:
            raise VerificationError("Patch contains zero valid file modifications")
        if hunk_count == 0:
            raise VerificationError("Patch contains zero diff hunks")

        return touched_files, hunk_count

    @classmethod
    def verify_packet_sensitivity(cls, envelope: ReceiptEnvelope[PacketSensitivityReceipt]) -> None:
        cls.verify_envelope(envelope, PacketSensitivityReceipt)
        pkt = envelope.payload

        actual_unverified = sum(1 for a in pkt.artifacts if not a.provenance_verified)
        actual_is_public = (actual_unverified == 0) and (len(pkt.artifacts) > 0)

        if pkt.private_artifact_count != actual_unverified:
            raise VerificationError(f"Contradiction: private_artifact_count ({pkt.private_artifact_count}) != actual ({actual_unverified})")
        if pkt.public_safe_verified != actual_is_public:
            raise VerificationError(f"Contradiction: public_safe_verified ({pkt.public_safe_verified}) != actual ({actual_is_public})")

        if actual_is_public and pkt.sensitivity_tier != "PUBLIC_SAFE":
            raise VerificationError("100% verified artifacts must have sensitivity tier PUBLIC_SAFE")
        if not actual_is_public and pkt.sensitivity_tier == "PUBLIC_SAFE":
            raise VerificationError("Security violation: unverified private artifacts present in PUBLIC_SAFE packet")

    @classmethod
    def verify_route_attestation(cls, envelope: ReceiptEnvelope[RouteAttestationReceipt], current_time: Optional[float] = None) -> None:
        cls.verify_envelope(envelope, RouteAttestationReceipt)
        route = envelope.payload
        now = current_time if current_time is not None else time.time()

        if route.issued_at > now + 30.0:
            raise VerificationError(f"Route attestation issued in future: {route.issued_at} > now ({now})")
        if now >= route.expires_at:
            raise VerificationError(f"Route attestation for '{route.route_id}' expired at {route.expires_at} (now: {now})")

        ttl = route.expires_at - route.issued_at
        if ttl <= 0:
            raise VerificationError(f"Invalid route TTL: {ttl}s")

        max_allowed_ttl = cls.MAX_PUBLIC_TTL_SEC if route.compliance_tier == "PUBLIC_PROVENANCE_ONLY" else cls.MAX_PRIVATE_TTL_SEC
        if ttl > max_allowed_ttl:
            raise VerificationError(f"Route TTL {ttl}s exceeds max allowed {max_allowed_ttl}s")

        if route.compliance_tier in ["HOSTED_NO_TRAIN", "LOCAL_ONLY_VERIFIED", "APEX_PAID"] and route.fallbacks_allowed:
            raise VerificationError("Compliance violation: Private/Paid route cannot allow third-party fallbacks")

    @classmethod
    def verify_route_packet_compatibility(
        cls,
        packet_env: ReceiptEnvelope[PacketSensitivityReceipt],
        route_env: ReceiptEnvelope[RouteAttestationReceipt],
        current_time: Optional[float] = None
    ) -> None:
        cls.verify_packet_sensitivity(packet_env)
        cls.verify_route_attestation(route_env, current_time=current_time)

        tier = packet_env.payload.sensitivity_tier
        comp = route_env.payload.compliance_tier
        zdr = route_env.payload.zdr_verified

        if tier == "PUBLIC_SAFE":
            return
        elif tier == "INTERNAL_NO_TRAIN_OK":
            if comp == "PUBLIC_PROVENANCE_ONLY":
                raise VerificationError(f"Data leak: INTERNAL packet cannot use PUBLIC route '{route_env.payload.route_id}'")
        elif tier == "ZDR_REQUIRED":
            if comp != "LOCAL_ONLY_VERIFIED" and not zdr:
                raise VerificationError(f"Compliance breach: ZDR_REQUIRED packet requires verified ZDR on route '{route_env.payload.route_id}'")
        elif tier == "LOCAL_ONLY_REQUIRED":
            if comp != "LOCAL_ONLY_VERIFIED":
                raise VerificationError(f"Air-gap breach: LOCAL_ONLY_REQUIRED packet cannot use remote route '{route_env.payload.route_id}'")

    @classmethod
    def verify_model_predispatch(
        cls,
        route_env: ReceiptEnvelope[RouteAttestationReceipt],
        packet_env: ReceiptEnvelope[PacketSensitivityReceipt],
        qual_env: ReceiptEnvelope[ModelQualificationReceipt],
        budget_env: Optional[ReceiptEnvelope[PaidBudgetReservationReceipt]],
        model_slug: str,
        model_family: str,
        provider: str,
        current_time: Optional[float] = None
    ) -> None:
        """
        Deterministic pre-dispatch verification gate:
        - Validates route envelope, expiry, and TTL.
        - Validates packet sensitivity and route-packet compatibility.
        - Validates qualification receipt freshness, gates, and attribute matching.
        - Validates paid budget reservation if route is APEX_PAID.
        """
        now = current_time if current_time is not None else time.time()

        # 1. Route verification
        cls.verify_route_attestation(route_env, current_time=now)
        route = route_env.payload

        # 2. Packet & Compatibility verification
        cls.verify_packet_sensitivity(packet_env)
        cls.verify_route_packet_compatibility(packet_env, route_env, current_time=now)

        # 3. Qualification verification
        cls.verify_envelope(qual_env, ModelQualificationReceipt)
        qual = qual_env.payload

        if qual.status != "REVIEW_USABLE_FRESH":
            raise VerificationError(f"Model qualification is not REVIEW_USABLE_FRESH (status: '{qual.status}')")
        if not (qual.evaluated_at <= now <= qual.expires_at):
            raise VerificationError(f"Model qualification expired or evaluated in future (evaluated_at: {qual.evaluated_at}, expires_at: {qual.expires_at}, now: {now})")
        if not (
            qual.benign_control_passed
            and qual.grounded_bug_passed
            and qual.exact_line_quote_verified
            and qual.json_schema_conformity
        ):
            raise VerificationError("Model qualification failed one or more required verification gates")

        # 4. Attribute matching
        if model_slug != qual.model_slug or model_family != qual.model_family:
            raise VerificationError(f"Caller model '{model_slug}/{model_family}' does not match qualification '{qual.model_slug}/{qual.model_family}'")
        if provider != route.provider_name or provider != qual.provider:
            raise VerificationError(f"Caller provider '{provider}' does not match route '{route.provider_name}' or qualification '{qual.provider}'")

        # 5. Paid budget reservation check
        if route.compliance_tier == "APEX_PAID":
            if not budget_env:
                raise VerificationError(f"Paid route '{route.route_id}' requires a valid PaidBudgetReservationReceipt")
            cls.verify_envelope(budget_env, PaidBudgetReservationReceipt)
            budget = budget_env.payload
            if budget.route_attestation_payload_sha256 != route_env.payload_sha256:
                raise VerificationError("Budget reservation route hash mismatch")
            if budget.model_slug != model_slug:
                raise VerificationError("Budget reservation model slug mismatch")

    @classmethod
    def verify_model_invocation(
        cls,
        inv_env: ReceiptEnvelope[ModelInvocationReceipt],
        packet_env: ReceiptEnvelope[PacketSensitivityReceipt],
        route_env: ReceiptEnvelope[RouteAttestationReceipt],
        qual_env: ReceiptEnvelope[ModelQualificationReceipt],
        budget_env: Optional[ReceiptEnvelope[PaidBudgetReservationReceipt]],
        current_time: Optional[float] = None
    ) -> None:
        cls.verify_envelope(inv_env, ModelInvocationReceipt)
        cls.verify_envelope(qual_env, ModelQualificationReceipt)

        inv = inv_env.payload
        route = route_env.payload
        qual = qual_env.payload

        if inv.packet_payload_sha256 != packet_env.payload_sha256:
            raise VerificationError("Invocation packet hash mismatch")
        if inv.route_attestation_payload_sha256 != route_env.payload_sha256:
            raise VerificationError("Invocation route attestation hash mismatch")
        if inv.qualification_payload_sha256 != qual_env.payload_sha256:
            raise VerificationError("Invocation qualification hash mismatch")

        if inv.route_id != route.route_id:
            raise VerificationError(f"Invocation route_id '{inv.route_id}' != attestation '{route.route_id}'")
        if inv.provider != route.provider_name:
            raise VerificationError(f"Invocation provider '{inv.provider}' != route provider '{route.provider_name}'")
        if qual.model_slug != inv.model_slug or qual.model_family != inv.model_family or qual.provider != inv.provider:
            raise VerificationError("Invocation model attributes do not match qualification receipt")

        if not (route.issued_at <= inv.completed_at <= route.expires_at):
            raise VerificationError(f"Invocation occurred outside route validity window: {inv.completed_at}")
        if not (qual.evaluated_at <= inv.completed_at <= qual.expires_at):
            raise VerificationError(f"Invocation occurred outside qualification validity window: {inv.completed_at}")
        if qual.status != "REVIEW_USABLE_FRESH":
            raise VerificationError(f"Invocation model was not REVIEW_USABLE_FRESH (status: {qual.status})")
        if not (
            qual.benign_control_passed
            and qual.grounded_bug_passed
            and qual.exact_line_quote_verified
            and qual.json_schema_conformity
        ):
            raise VerificationError(
                f"Invocation model '{inv.model_slug}' failed required qualification gates"
            )

        cls.verify_route_packet_compatibility(packet_env, route_env, current_time=current_time)

        if route.compliance_tier == "APEX_PAID":
            if not budget_env or not inv.paid_budget_payload_sha256:
                raise VerificationError(f"Paid route '{route.route_id}' invoked without PaidBudgetReservationReceipt")
            cls.verify_envelope(budget_env, PaidBudgetReservationReceipt)
            
            budget = budget_env.payload
            if inv.paid_budget_payload_sha256 != budget_env.payload_sha256:
                raise VerificationError("Paid budget hash mismatch")
            if budget.model_slug != inv.model_slug:
                raise VerificationError("Paid budget slug mismatch")
            if budget.reserved_cost_usd <= 0:
                raise VerificationError("Paid budget reservation must be positive")
            if budget.allocated_at > inv.completed_at:
                raise VerificationError("Paid budget allocated after invocation completed")
            if budget.settled_cost_usd is not None and budget.settled_cost_usd > budget.reserved_cost_usd:
                raise VerificationError("Paid budget settled cost exceeds reserved budget")

    @classmethod
    def verify_council_vote(
        cls,
        vote_env: ReceiptEnvelope[CouncilVoteReceipt],
        roster_env: ReceiptEnvelope[CouncilRosterReceipt],
        inv_envelopes: Dict[str, ReceiptEnvelope[ModelInvocationReceipt]],
        qual_envelopes: Dict[str, ReceiptEnvelope[ModelQualificationReceipt]],
        route_envelopes: Dict[str, ReceiptEnvelope[RouteAttestationReceipt]],
        packet_env: ReceiptEnvelope[PacketSensitivityReceipt],
        budget_envelopes: Dict[str, ReceiptEnvelope[PaidBudgetReservationReceipt]],
        current_time: Optional[float] = None
    ) -> None:
        cls.verify_envelope(vote_env, CouncilVoteReceipt)
        cls.verify_envelope(roster_env, CouncilRosterReceipt)

        vote = vote_env.payload
        roster = roster_env.payload

        if vote.roster_payload_sha256 != roster_env.payload_sha256:
            raise VerificationError("Vote does not link to frozen council roster")
        if roster.frozen_quorum_size < 3:
            raise VerificationError("Quorum size violation: N >= 3 required")
        if len(roster.frozen_voter_slugs) != roster.frozen_quorum_size:
            raise VerificationError("Frozen roster slugs count != declared quorum size")
        if len(roster.frozen_voter_slugs) != len(set(roster.frozen_voter_slugs)):
            raise VerificationError("Duplicate voter slug detected in frozen roster")
        if len(set(roster.frozen_model_families)) < 3:
            raise VerificationError("Frozen roster lacks >= 3 independent model families")

        if vote.quorum_size != roster.frozen_quorum_size or len(vote.votes) != vote.quorum_size:
            raise VerificationError("Vote ballot size does not match frozen quorum")

        voter_slugs = []
        model_families = []

        for v in vote.votes:
            inv_env = inv_envelopes.get(v.invocation_payload_sha256)
            if not inv_env:
                raise VerificationError(f"Missing invocation receipt with hash '{v.invocation_payload_sha256}'")
            
            inv = inv_env.payload
            if v.voter_slug != inv.model_slug:
                raise VerificationError(f"Vote slug mismatch: ballot '{v.voter_slug}' != invocation '{inv.model_slug}'")
            if v.model_family != inv.model_family:
                raise VerificationError(f"Vote family mismatch: ballot '{v.model_family}' != invocation '{inv.model_family}'")
            if v.provider != inv.provider:
                raise VerificationError(f"Vote provider mismatch: ballot '{v.provider}' != invocation '{inv.provider}'")

            voter_slugs.append(v.voter_slug)
            model_families.append(v.model_family)

            qual_env = qual_envelopes[inv.qualification_payload_sha256]
            route_env = route_envelopes[inv.route_attestation_payload_sha256]
            budget_env = budget_envelopes.get(inv.paid_budget_payload_sha256) if inv.paid_budget_payload_sha256 else None
            cls.verify_model_invocation(inv_env, packet_env, route_env, qual_env, budget_env, current_time=current_time)

        if len(voter_slugs) != len(set(voter_slugs)):
            raise VerificationError("Duplicate voter detected in council ballot")
        if set(voter_slugs) != set(roster.frozen_voter_slugs):
            raise VerificationError("Ballot voters do not match pre-dispatch frozen roster")
        if len(set(model_families)) < 3:
            raise VerificationError("Council ballot lacks >= 3 independent model families")

        actual_approvals = sum(1 for v in vote.votes if v.decision == "approve")
        actual_rejections = sum(1 for v in vote.votes if v.decision == "reject")

        if vote.approvals_count != actual_approvals or vote.rejections_count != actual_rejections:
            raise VerificationError("Tally mismatch in vote receipt")

        required_approvals = math.ceil((2.0 * vote.quorum_size) / 3.0)
        expected_supermajority = (actual_approvals >= required_approvals) and (not vote.critical_finding_veto)

        if vote.supermajority_achieved != expected_supermajority:
            raise VerificationError(f"Supermajority violation: achieved={vote.supermajority_achieved} (required: {required_approvals})")
        if vote.final_verdict == "APPROVED" and not vote.supermajority_achieved:
            raise VerificationError("Illegal verdict: APPROVED without verified supermajority")

    @classmethod
    def verify_full_apply_chain(
        cls,
        auth_env: ReceiptEnvelope[ApplyAuthorizationReceipt],
        vote_env: ReceiptEnvelope[CouncilVoteReceipt],
        roster_env: ReceiptEnvelope[CouncilRosterReceipt],
        inv_envelopes: Dict[str, ReceiptEnvelope[ModelInvocationReceipt]],
        qual_envelopes: Dict[str, ReceiptEnvelope[ModelQualificationReceipt]],
        route_envelopes: Dict[str, ReceiptEnvelope[RouteAttestationReceipt]],
        packet_env: ReceiptEnvelope[PacketSensitivityReceipt],
        budget_envelopes: Dict[str, ReceiptEnvelope[PaidBudgetReservationReceipt]],
        sandbox_env: ReceiptEnvelope[ExecutionSandboxReceipt],
        patch_env: ReceiptEnvelope[PatchReceipt],
        snapshot_env: ReceiptEnvelope[SnapshotReceipt],
        human_approval_env: ReceiptEnvelope[HumanApprovalReceipt],
        raw_patch_bytes: bytes,
        live_repo_state_sha256: str,
        authenticator: Optional[ApprovalAuthenticator] = None,
        current_time: Optional[float] = None
    ) -> None:
        cls.verify_envelope(auth_env, ApplyAuthorizationReceipt)
        cls.verify_envelope(sandbox_env, ExecutionSandboxReceipt)
        cls.verify_envelope(patch_env, PatchReceipt)
        cls.verify_envelope(snapshot_env, SnapshotReceipt)
        cls.verify_envelope(packet_env, PacketSensitivityReceipt)
        cls.verify_envelope(human_approval_env, HumanApprovalReceipt)

        auth = auth_env.payload
        vote = vote_env.payload
        roster = roster_env.payload
        sandbox = sandbox_env.payload
        patch = patch_env.payload
        snapshot = snapshot_env.payload
        packet = packet_env.payload
        approval = human_approval_env.payload

        # 1. External Human Approval Authentication
        if auth.auth_mode != "INTERACTIVE_HUMAN_PROMPT":
            raise VerificationError(
                f"Apply rejected: auth_mode was '{auth.auth_mode}', must be 'INTERACTIVE_HUMAN_PROMPT'"
            )
        if auth.human_approval_payload_sha256 != human_approval_env.payload_sha256:
            raise VerificationError("Authorization does not link to HumanApprovalReceipt hash")
        if approval.subject_type != "PATCH_APPLY":
            raise VerificationError(f"HumanApproval subject_type '{approval.subject_type}' != 'PATCH_APPLY'")
        if approval.subject_payload_sha256 != patch_env.payload_sha256:
            raise VerificationError("HumanApproval subject payload does not bind to the candidate patch hash")

        auth_engine = authenticator or DenyAllApprovalAuthenticator()
        if not auth_engine.authenticate_approval(human_approval_env, patch_env.payload_sha256):
            raise VerificationError("Apply rejected: Human approval signature verification failed or expired")

        # 2. State & Snapshot Integrity
        if auth.target_composite_state_sha256 != live_repo_state_sha256 or snapshot.composite_state_sha256 != live_repo_state_sha256:
            raise VerificationError("State drift: Target state does not match live repository state")
        if packet.snapshot_composite_state_sha256 != snapshot.composite_state_sha256:
            raise VerificationError("Packet context was not generated from the target snapshot")

        # 3. Patch Sanitization & Bytes Hash Verification
        if not patch.sanitization_passed:
            raise VerificationError("Apply rejected: PatchReceipt sanitization_passed is False")

        computed_patch_sha256 = hashlib.sha256(raw_patch_bytes).hexdigest()
        if computed_patch_sha256 != patch.patch_sha256 or auth.authorized_patch_sha256 != patch.patch_sha256:
            raise VerificationError("Patch byte-hash mismatch")

        parsed_touched_files, parsed_hunk_count = cls.parse_and_sanitize_patch(raw_patch_bytes)
        if set(patch.target_files_touched) != parsed_touched_files:
            raise VerificationError("Patch target_files_touched mismatch with parsed patch bytes")
        if patch.hunks_count != parsed_hunk_count:
            raise VerificationError(f"Patch hunks_count mismatch ({patch.hunks_count} != {parsed_hunk_count})")

        # 4. Hash Chain Linkages
        if auth.council_vote_payload_sha256 != vote_env.payload_sha256:
            raise VerificationError("Authorization does not link to council vote receipt hash")
        if vote.patch_payload_sha256 != patch_env.payload_sha256:
            raise VerificationError("Council vote does not link to candidate patch receipt hash")
        if vote.sandbox_payload_sha256 != sandbox_env.payload_sha256:
            raise VerificationError("Council vote does not link to sandbox receipt hash")
        if roster.packet_payload_sha256 != packet_env.payload_sha256:
            raise VerificationError("Roster packet hash does not match packet receipt hash")
        if roster.patch_payload_sha256 != patch_env.payload_sha256:
            raise VerificationError("Roster patch hash does not match patch receipt hash")

        # 5. Council Vote Quorum & Supermajority Verification
        cls.verify_council_vote(vote_env, roster_env, inv_envelopes, qual_envelopes, route_envelopes, packet_env, budget_envelopes, current_time=current_time)

        # 6. Real Live Isolated Sandbox Execution Evidence Gate
        if sandbox.patch_payload_sha256 != patch_env.payload_sha256:
            raise VerificationError("Sandbox executed different patch receipt hash")
        if sandbox.snapshot_composite_state_sha256 != snapshot.composite_state_sha256:
            raise VerificationError("Sandbox executed against mismatched snapshot base")

        if sandbox.isolation_mode != "DOCKER_CONTAINER_ENFORCED":
            raise VerificationError(
                f"Apply rejected: Sandbox isolation_mode was '{sandbox.isolation_mode}', must be 'DOCKER_CONTAINER_ENFORCED'"
            )

        if sandbox.execution_mode != "LIVE":
            raise VerificationError(f"Apply rejected: Sandbox execution_mode was '{sandbox.execution_mode}', must be 'LIVE'")

        if sandbox.container_engine in ["docker_mock", "local_subprocess"]:
            raise VerificationError(f"Apply rejected: Simulated/local engine '{sandbox.container_engine}' cannot authorize apply")

        if sandbox.container_engine in ["docker", "podman"]:
            if not sandbox.network_isolated:
                raise VerificationError("Container sandbox was not network-isolated")
            if sandbox.container_image_digest != cls.TRUSTED_TOOLCHAIN_DIGEST:
                raise VerificationError("Sandbox did not execute on trusted toolchain image digest")
        else:
            raise VerificationError(f"Unsupported container engine '{sandbox.container_engine}'")

        if not sandbox.test_passed or sandbox.test_exit_code != 0:
            raise VerificationError(f"Sandbox test failed (exit code {sandbox.test_exit_code})")

        if patch.parent_snapshot_sha256 != snapshot.composite_state_sha256:
            raise VerificationError("Patch parent snapshot mismatch")
