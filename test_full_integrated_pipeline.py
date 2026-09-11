import hashlib
import json
import time
import unittest
from council_contracts import (
    CONTRACT_VERSION, ReceiptEnvelope, SnapshotReceipt, PacketSensitivityReceipt,
    ArtifactProvenanceRecord, RouteAttestationReceipt, ModelQualificationReceipt,
    ModelInvocationReceipt, CouncilRosterReceipt, CouncilVoteReceipt, RedactedVoteRecord,
    PatchReceipt, ExecutionSandboxReceipt, HumanApprovalReceipt, ApplyAuthorizationReceipt
)
from council_verifier import CouncilReceiptVerifier, VerificationError
from model_routes import RouteRegistry
from qualification_matrix import DeclarativeQualificationMatrix
from sandboxed_patch_generator import SandboxedPatchGenerator
from human_approval import HMACApprovalAuthenticator
from prompt_config_registry import PromptConfigRegistry
from rlvr_ruler_reward_engine import CouncilRLVRRewardEngine
from rlvr_dataset_exporter import RLVRDatasetExporter

class TestFullIntegratedCouncilPipeline(unittest.TestCase):
    """
    Comprehensive end-to-end integration test uniting all harness layers:
    1. Promptfoo-style declarative model qualification
    2. SWE-agent sandboxed patch generation and pytest validation
    3. Dual-chain cryptographic council convocation & verification
    """

    def test_full_pipeline_happy_path(self):
        now = time.time()
        state_sha = "state_repo_production_v4"

        # --- STEP 1: CONTEXT SLICING (Aider / Zero role) ---
        snapshot = SnapshotReceipt(
            head_commit="commit_prod_head_123",
            staged_diff_sha256="staged_sha_abc",
            unstaged_diff_sha256="unstaged_sha_def",
            untracked_blobs=[],
            deleted_files=[],
            composite_state_sha256=state_sha,
            cas_storage_path="/cas/snapshots"
        )
        snap_env = ReceiptEnvelope.seal(snapshot)

        packet = PacketSensitivityReceipt(
            snapshot_composite_state_sha256=state_sha,
            sensitivity_tier="INTERNAL_NO_TRAIN_OK",
            public_safe_verified=False,
            private_artifact_count=1,
            artifacts=[
                ArtifactProvenanceRecord(
                    artifact_id="art_1",
                    artifact_type="REPO_FILE",
                    path_or_identifier="src/crypto_utils.py",
                    content_sha256="sha_crypto_file",
                    source_upstream_commit=None,
                    source_upstream_url=None,
                    provenance_verified=False,
                    classification_reason="internal sensitive code"
                )
            ]
        )
        pkt_env = ReceiptEnvelope.seal(packet)

        # --- STEP 2: SANDBOXED PATCH GENERATION (SWE-agent role) ---
        raw_patch = (
            b"--- a/src/crypto_utils.py\n"
            b"+++ b/src/crypto_utils.py\n"
            b"@@ -5,3 +5,4 @@\n"
            b" def secure_compare(val1: str, val2: str) -> bool:\n"
            b"-    return val1 == val2\n"
            b"+    import hmac\n"
            b"+    return hmac.compare_digest(val1.encode(), val2.encode())\n"
        )
        test_suite_code = (
            "import hmac\n"
            "def secure_compare(val1: str, val2: str) -> bool:\n"
            "    return hmac.compare_digest(val1.encode(), val2.encode())\n\n"
            "def test_constant_time_comparison():\n"
            "    assert secure_compare('secret', 'secret') is True\n"
            "    assert secure_compare('secret', 'wrong') is False\n"
        )

        patch_gen = SandboxedPatchGenerator()
        patch_env, raw_sandbox_env = patch_gen.run_sandbox_verification(raw_patch, test_suite_code, state_sha)
        self.assertTrue(patch_env.payload.sanitization_passed)
        self.assertTrue(raw_sandbox_env.payload.test_passed)

        # Attest live container execution evidence for promotion authorization
        live_sandbox = ExecutionSandboxReceipt(
            patch_payload_sha256=patch_env.payload_sha256,
            snapshot_composite_state_sha256=state_sha,
            isolation_mode="DOCKER_CONTAINER_ENFORCED",
            container_engine="docker",
            execution_mode="LIVE",
            container_image_digest=CouncilReceiptVerifier.TRUSTED_TOOLCHAIN_DIGEST,
            network_isolated=True,
            test_command=["pytest", "test_crypto.py"],
            test_exit_code=0,
            test_passed=True,
            stdout_sha256=raw_sandbox_env.payload.stdout_sha256,
            stderr_sha256=raw_sandbox_env.payload.stderr_sha256,
            duration_sec=raw_sandbox_env.payload.duration_sec
        )
        sandbox_env = ReceiptEnvelope.seal(live_sandbox)

        # --- STEP 3: ROUTE ATTESTATIONS ---
        routes = RouteRegistry.get_standard_routes()
        local_route_env = list(routes.values())[0]

        # --- STEP 4: MODEL QUALIFICATION (Promptfoo role) ---
        voter_specs = [
            ("qwen2.5-coder:7b", "qwen", "ollama_local"),
            ("glm4:latest", "glm", "ollama_local"),
            ("mistral:latest", "mistral", "ollama_local")
        ]

        qual_envelopes = {}
        for slug, fam, prov in voter_specs:
            q_rec = ModelQualificationReceipt(
                composite_key=f"{prov}:{slug}",
                model_slug=slug,
                model_family=fam,
                provider=prov,
                status="REVIEW_USABLE_FRESH",
                benign_control_passed=True,
                grounded_bug_passed=True,
                exact_line_quote_verified=True,
                json_schema_conformity=True,
                evaluated_at=local_route_env.payload.issued_at - 100,
                expires_at=local_route_env.payload.issued_at + 86400
            )
            q_env = ReceiptEnvelope.seal(q_rec)
            qual_envelopes[q_env.payload_sha256] = q_env

        # --- STEP 5: COUNCIL ROSTER ---
        roster = CouncilRosterReceipt(
            packet_payload_sha256=pkt_env.payload_sha256,
            patch_payload_sha256=patch_env.payload_sha256,
            frozen_voter_slugs=[v[0] for v in voter_specs],
            frozen_model_families=[v[1] for v in voter_specs],
            frozen_quorum_size=len(voter_specs)
        )
        roster_env = ReceiptEnvelope.seal(roster)

        # --- STEP 6: INVOCATIONS & BALLOT ---
        inv_envelopes = {}
        route_envelopes = {local_route_env.payload_sha256: local_route_env}
        votes = []

        for (slug, fam, prov), q_env in zip(voter_specs, list(qual_envelopes.values())):
            completed_at = local_route_env.payload.issued_at + 10.0 # Valid window
            inv = ModelInvocationReceipt(
                packet_payload_sha256=pkt_env.payload_sha256,
                route_attestation_payload_sha256=local_route_env.payload_sha256,
                qualification_payload_sha256=q_env.payload_sha256,
                paid_budget_payload_sha256=None,
                model_slug=slug,
                model_family=fam,
                provider=prov,
                route_id=local_route_env.payload.route_id,
                request_payload_sha256=hashlib.sha256(b"req").hexdigest(),
                response_payload_sha256=hashlib.sha256(b"resp").hexdigest(),
                completed_at=completed_at
            )
            inv_env = ReceiptEnvelope.seal(inv)
            inv_envelopes[inv_env.payload_sha256] = inv_env

            vote_rec = RedactedVoteRecord(
                voter_slug=slug,
                model_family=fam,
                provider=prov,
                invocation_payload_sha256=inv_env.payload_sha256,
                decision="approve",
                confidence=0.95,
                reasoning_sha256=inv.response_payload_sha256,
                redacted_summary="Constant-time comparison validated"
            )
            votes.append(vote_rec)

        vote = CouncilVoteReceipt(
            roster_payload_sha256=roster_env.payload_sha256,
            patch_payload_sha256=patch_env.payload_sha256,
            sandbox_payload_sha256=sandbox_env.payload_sha256,
            quorum_size=3,
            approvals_count=3,
            rejections_count=0,
            supermajority_achieved=True,
            critical_finding_veto=False,
            final_verdict="APPROVED",
            votes=votes
        )
        vote_env = ReceiptEnvelope.seal(vote)

        # --- STEP 7: EXTERNAL AUTHENTICATED HUMAN APPROVAL & APPLY AUTHORIZATION ---
        authenticator = HMACApprovalAuthenticator()
        authenticator.register_key("key_operator_001", "operator_secret_prod_999")

        human_approval_env = HMACApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=patch_env.payload_sha256,
            approver_identity="lead_security_architect@prod",
            approver_key_id="key_operator_001",
            secret_key="operator_secret_prod_999",
            validity_sec=3600
        )

        auth = ApplyAuthorizationReceipt(
            authorized_patch_sha256=patch_env.payload.patch_sha256,
            target_composite_state_sha256=state_sha,
            council_vote_payload_sha256=vote_env.payload_sha256,
            auth_mode="INTERACTIVE_HUMAN_PROMPT",
            human_approval_payload_sha256=human_approval_env.payload_sha256
        )
        auth_env = ReceiptEnvelope.seal(auth)

        # --- STEP 8: CRYPTOGRAPHIC VERIFICATION ---
        verification_time = local_route_env.payload.issued_at + 20.0
        CouncilReceiptVerifier.verify_full_apply_chain(
            auth_env, vote_env, roster_env, inv_envelopes, qual_envelopes,
            route_envelopes, pkt_env, {}, sandbox_env, patch_env, snap_env,
            human_approval_env, raw_patch, state_sha,
            authenticator=authenticator, current_time=verification_time
        )

    def test_full_swebench_pipeline_with_prompt_registry_and_rlvr_export(self):
        # 1. Register prompt version
        registry = PromptConfigRegistry()
        prompt_record = registry.register_prompt_version(
            prompt_id="swebench.solver",
            version="1.0.0",
            system_prompt="You are an autonomous software engineer that writes minimal unified diffs.",
            stage="ACTIVE"
        )

        # 2. Setup patch & test
        sample_patch = (
            b"--- a/src/calc.py\n"
            b"+++ b/src/calc.py\n"
            b"@@ -1,2 +1,2 @@\n"
            b"-def add(a, b): return a - b\n"
            b"+def add(a, b): return a + b\n"
        )
        sample_test = (
            "def add(a, b): return a + b\n\n"
            "def test_add():\n"
            "    assert add(2, 3) == 5\n"
        )
        state_sha = "state_swebench_001"

        patch_gen = SandboxedPatchGenerator()
        patch_env, sandbox_env = patch_gen.run_sandbox_verification(sample_patch, sample_test, state_sha)

        self.assertTrue(patch_env.payload.sanitization_passed)
        self.assertTrue(sandbox_env.payload.test_passed)
        self.assertEqual(sandbox_env.payload.test_exit_code, 0)

        # 3. Score trajectory using deterministic RLVR engine
        rlvr_engine = CouncilRLVRRewardEngine()
        reward_env = rlvr_engine.score_from_execution(
            trajectory_id="traj_swebench_001",
            objective_id="SWE_ISSUE_42",
            system_prompt=prompt_record.system_prompt,
            trajectory_text="Generated valid patch passing pytest in sandbox.",
            test_exit_code=sandbox_env.payload.test_exit_code,
            ast_valid=True,
            receipt_valid=True
        )

        self.assertEqual(reward_env.payload.scalar_reward, 1.0)
        self.assertEqual(reward_env.payload.system_prompt_sha256, prompt_record.normalized_system_prompt_sha256)

        # 4. Export verified trajectory to RLVR training dataset
        exporter = RLVRDatasetExporter()
        messages = [
            {"role": "system", "content": prompt_record.system_prompt},
            {"role": "user", "content": "Fix bug in calc.py where add performs subtraction."},
            {"role": "assistant", "content": sample_patch.decode("utf-8")}
        ]
        jsonl_content, export_env = exporter.export_jsonl(
            reward_receipt_envs=[reward_env],
            messages_by_trajectory_id={"traj_swebench_001": messages},
            min_reward_threshold=0.8
        )

        self.assertEqual(export_env.payload.accepted_count, 1)
        self.assertEqual(export_env.payload.rejected_count, 0)
        self.assertIn("traj_swebench_001", jsonl_content)
        self.assertIn("reward_receipt_payload_sha256", jsonl_content)

if __name__ == "__main__":
    unittest.main()
