import math
import hashlib
import json
import os
import time
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import (
    CONTRACT_VERSION, ImmutableContract, ReceiptEnvelope, SnapshotReceipt,
    PacketSensitivityReceipt, ArtifactProvenanceRecord, RouteAttestationReceipt,
    ModelQualificationReceipt, PaidBudgetReservationReceipt, ModelInvocationReceipt,
    CouncilRosterReceipt, CouncilVoteReceipt, RedactedVoteRecord, PatchReceipt,
    ExecutionSandboxReceipt, ApplyAuthorizationReceipt, UntrackedBlobRecord
)
from council_verifier import CouncilReceiptVerifier, VerificationError
from model_routes import RouteRegistry
from model_qualification_runner import ModelQualificationRunner
from shared_memory import get_invariants_prompt_context, record_learned_invariant
from model_gateway import ModelGateway
from log_derived_context_engine import LogDerivedContextEngine
from prompt_config_registry import PromptConfigRegistry
from heterogeneous_jury_engine import HeterogeneousJuryEngine, JuryJurorVote

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

class LiveCouncilOrchestrator:
    def __init__(self, ollama_url: str = OLLAMA_URL, prompt_registry: Optional[PromptConfigRegistry] = None):
        self.ollama_url = ollama_url
        self.routes = RouteRegistry.get_standard_routes()
        self.qual_runner = ModelQualificationRunner(ollama_url=self.ollama_url)
        self.gateway = ModelGateway()
        self.prompt_registry = prompt_registry or PromptConfigRegistry(registry_id="council_juror_prompts")
        self._init_standard_prompts()
        self.jury_engine = HeterogeneousJuryEngine()

    def _init_standard_prompts(self):
        standard_prompts = {
            "council.juror.security": (
                "You are the Lead Security and State Invariant Auditor on an adversarial code review council.\n"
                "Your role is to rigorously inspect this patch for state corruption, unauthenticated operations, "
                "missing validation guards, re-entrancy, and duplicate key collisions."
            ),
            "council.juror.performance": (
                "You are the Performance, Concurrency, and Resource Lifecycle Profiler on an adversarial code review council.\n"
                "Your role is to verify non-blocking async operations, timer cleanup on teardown/error, "
                "memory leak prevention, and database indexing efficiency."
            ),
            "council.juror.architecture": (
                "You are the API Contract, Architecture, and Maintainer Compatibility Critic on an adversarial code review council.\n"
                "Your role is to verify schema consistency, type safety, error manifests, backward compatibility, "
                "and documentation clarity."
            ),
        }
        for prompt_id, text in standard_prompts.items():
            if not self.prompt_registry.has_prompt(prompt_id):
                self.prompt_registry.register_prompt_version(
                    prompt_id=prompt_id,
                    version="1.0.0",
                    system_prompt=text,
                    stage="ACTIVE",
                    provider_parameters={"temperature": 0.1, "max_tokens": 256}
                )

    def dispatch_model_vote(
        self,
        model_slug: str,
        model_family: str,
        provider: str,
        route_env: ReceiptEnvelope[RouteAttestationReceipt],
        qual_env: ReceiptEnvelope[ModelQualificationReceipt],
        packet_env: ReceiptEnvelope[PacketSensitivityReceipt],
        raw_patch_text: str
    ) -> Tuple[ReceiptEnvelope[ModelInvocationReceipt], RedactedVoteRecord]:
        if "qwen" in model_family.lower() or "qwen" in model_slug.lower():
            prompt_id = "council.juror.security"
        elif "glm" in model_family.lower() or "glm" in model_slug.lower():
            prompt_id = "council.juror.performance"
        else:
            prompt_id = "council.juror.architecture"

        role_desc = self.prompt_registry.get_active_prompt(prompt_id) if self.prompt_registry.has_prompt(prompt_id) else (
            "You are a code review council juror evaluating this patch."
        )

        learned_context = get_invariants_prompt_context()

        prompt = (
            f"{role_desc}\n\n"
            f"{learned_context}\n\n"
            f"Review this proposed patch:\n```diff\n{raw_patch_text}\n```\n\n"
            "Evaluate if this patch is safe, robust, and correctly meets all requirements.\n"
            "Output strictly a JSON object with this exact schema:\n"
            "{\n"
            '  "decision": "approve" | "reject",\n'
            '  "confidence": 0.0 to 1.0,\n'
            '  "summary": "one sentence verdict tailored to your specialized role"\n'
            "}"
        )
        
        ctx = LogDerivedContextEngine(session_id=f"council_vote_{model_slug}_{int(time.time()*1000)}")
        ctx.append_event("CONFIG_SET", "system", {
            "model_slug": model_slug,
            "model_family": model_family,
            "provider": provider,
            "route_id": route_env.payload.route_id,
            "temperature": 0.1,
            "max_tokens": 256
        })
        ctx.append_event("USER_INPUT", "user", {"content": prompt})

        inv_env, raw_resp = self.gateway.invoke_with_resilience(
            model_slug=model_slug,
            model_family=model_family,
            provider=provider,
            route_env=route_env,
            qual_env=qual_env,
            packet_env=packet_env,
            budget_env=None,
            prompt_text=prompt,
            prompt_id=prompt_id,
            prompt_registry=self.prompt_registry,
            temperature=0.1,
            max_tokens=256,
            context_engine=ctx
        )

        if not raw_resp:
            raw_resp = json.dumps({
                "decision": "abstain",
                "confidence": 0.0,
                "summary": "Abstain: gateway invocation unreachable or failed"
            })
            now = time.time()
            inv = ModelInvocationReceipt(
                packet_payload_sha256=packet_env.payload_sha256,
                route_attestation_payload_sha256=route_env.payload_sha256,
                qualification_payload_sha256=qual_env.payload_sha256,
                paid_budget_payload_sha256=None,
                model_slug=model_slug,
                model_family=model_family,
                provider=provider,
                route_id=route_env.payload.route_id,
                request_payload_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                response_payload_sha256=hashlib.sha256(raw_resp.encode("utf-8")).hexdigest(),
                prompt_tokens=len(prompt) // 4,
                completion_tokens=len(raw_resp) // 4,
                latency_ms=10.0,
                completed_at=now
            )
            inv_env = ReceiptEnvelope.seal(inv)

        resp_hash = hashlib.sha256(raw_resp.encode("utf-8")).hexdigest()

        try:
            vote_data = json.loads(raw_resp)
            decision = vote_data.get("decision", "abstain").lower()
            if decision not in ["approve", "reject", "abstain"]:
                decision = "abstain"
            confidence = float(vote_data.get("confidence", 0.0))
            summary = vote_data.get("summary", "Reviewed cleanly")
        except Exception:
            decision = "abstain"
            confidence = 0.0
            summary = "Abstain: unparseable model response"

        vote_record = RedactedVoteRecord(
            voter_slug=model_slug,
            model_family=model_family,
            provider=provider,
            invocation_payload_sha256=inv_env.payload_sha256,
            decision=decision,
            confidence=confidence,
            reasoning_sha256=resp_hash,
            redacted_summary=summary
        )

        return inv_env, vote_record

    def run_live_council(
        self,
        raw_patch_bytes: bytes,
        repo_state_sha256: str
    ) -> Dict[str, Any]:
        now = time.time()
        print("================================================================================")
        print("INITIATING SIMULATED DUAL-CHAIN MULTI-AGENT COUNCIL CONVOCATION")
        print("================================================================================")

        # 1. Snapshot Receipt
        snapshot = SnapshotReceipt(
            head_commit="commit_prod_live",
            staged_diff_sha256=hashlib.sha256(b"staged").hexdigest(),
            unstaged_diff_sha256=hashlib.sha256(b"unstaged").hexdigest(),
            untracked_blobs=[],
            deleted_files=[],
            composite_state_sha256=repo_state_sha256,
            cas_storage_path="/cas/snapshots"
        )
        snap_env = ReceiptEnvelope.seal(snapshot)
        print(f"[Step 1] Sealed SnapshotReceipt (State: {repo_state_sha256[:16]}...)")

        # 2. Packet Sensitivity Receipt
        packet = PacketSensitivityReceipt(
            snapshot_composite_state_sha256=repo_state_sha256,
            sensitivity_tier="INTERNAL_NO_TRAIN_OK",
            public_safe_verified=False,
            private_artifact_count=1,
            artifacts=[
                ArtifactProvenanceRecord(
                    artifact_id="art_main",
                    artifact_type="REPO_FILE",
                    path_or_identifier="src/auth.py",
                    content_sha256=hashlib.sha256(b"content").hexdigest(),
                    source_upstream_commit=None,
                    source_upstream_url=None,
                    provenance_verified=False,
                    classification_reason="internal repo file"
                )
            ]
        )
        pkt_env = ReceiptEnvelope.seal(packet)
        print(f"[Step 2] Sealed PacketSensitivityReceipt (Tier: {packet.sensitivity_tier})")

        # 3. Patch Receipt & Sanitization
        touched_files, hunk_count = CouncilReceiptVerifier.parse_and_sanitize_patch(raw_patch_bytes)
        patch_sha = hashlib.sha256(raw_patch_bytes).hexdigest()
        patch = PatchReceipt(
            parent_snapshot_sha256=repo_state_sha256,
            patch_sha256=patch_sha,
            target_files_touched=sorted(list(touched_files)),
            hunks_count=hunk_count,
            sanitization_passed=True
        )
        patch_env = ReceiptEnvelope.seal(patch)
        print(f"[Step 3] Sealed PatchReceipt (Files: {patch.target_files_touched}, Hunks: {hunk_count})")

        # 4. Sandbox Execution Receipt
        sandbox = ExecutionSandboxReceipt(
            patch_payload_sha256=patch_env.payload_sha256,
            snapshot_composite_state_sha256=repo_state_sha256,
            isolation_mode="LOCAL_SUBPROCESS_MOCK",
            container_engine="docker_mock",
            execution_mode="SIMULATED",
            container_image_digest=CouncilReceiptVerifier.TRUSTED_TOOLCHAIN_DIGEST,
            network_isolated=False,
            test_command=["pytest", "tests/test_auth.py"],
            test_exit_code=0,
            test_passed=True,
            stdout_sha256="out_sha",
            stderr_sha256="err_sha",
            duration_sec=2.15
        )
        sandbox_env = ReceiptEnvelope.seal(sandbox)
        print(f"[Step 4] Sealed ExecutionSandboxReceipt (Mode: {sandbox.isolation_mode}, no live container claim)")

        # 5. Qualify Candidate Models
        candidate_configs = [
            ("qwen2.5-coder:7b", "qwen", "ollama_local"),
            ("glm4:latest", "glm", "ollama_local"),
            ("mistral:latest", "mistral", "ollama_local")
        ]

        inv_envelopes = {}
        qual_envelopes = {}
        route_envelopes = {}
        budget_envelopes = {}
        votes = []
        qualified_voters = []

        local_route_env = list(self.routes.values())[0]

        print("\n[Step 5 & 6] Evaluating Qualification Ladder and Dispatching Prompts...")
        for slug, fam, prov in candidate_configs:
            qual_env = self.qual_runner.qualify_model(slug, fam, prov)
            qual_envelopes[qual_env.payload_sha256] = qual_env
            route_envelopes[local_route_env.payload_sha256] = local_route_env

            qual_payload = qual_env.payload
            is_qualified = (
                qual_payload.status == "REVIEW_USABLE_FRESH" and
                qual_payload.benign_control_passed and
                qual_payload.grounded_bug_passed and
                qual_payload.exact_line_quote_verified and
                qual_payload.json_schema_conformity
            )

            if is_qualified:
                qualified_voters.append((slug, fam, prov))
                inv_env, vote_record = self.dispatch_model_vote(
                    slug, fam, prov, local_route_env, qual_env, pkt_env, raw_patch_bytes.decode("utf-8")
                )
                inv_envelopes[inv_env.payload_sha256] = inv_env
                votes.append(vote_record)
                print(f"  - [{slug}] Decision: {vote_record.decision.upper()} (Confidence: {vote_record.confidence:.2f})")
            else:
                print(f"  - [{slug}] Disqualified ({qual_payload.status}), seat skipped.")

        # Seal Frozen CouncilRosterReceipt with qualified voters
        roster = CouncilRosterReceipt(
            packet_payload_sha256=pkt_env.payload_sha256,
            patch_payload_sha256=patch_env.payload_sha256,
            frozen_voter_slugs=[v[0] for v in qualified_voters],
            frozen_model_families=[v[1] for v in qualified_voters],
            frozen_quorum_size=len(qualified_voters)
        )
        roster_env = ReceiptEnvelope.seal(roster)
        print(f"[Step 6b] Sealed Frozen CouncilRosterReceipt (N={roster.frozen_quorum_size} qualified voters)")

        # 7. Tally Ballot and Seal CouncilVoteReceipt
        approvals = sum(1 for v in votes if v.decision == "approve")
        rejections = sum(1 for v in votes if v.decision == "reject")
        required_approvals = math.ceil((2.0 * len(votes)) / 3.0) if len(votes) > 0 else 1
        supermajority = (approvals >= required_approvals) and (approvals > 0)

        council_vote = CouncilVoteReceipt(
            roster_payload_sha256=roster_env.payload_sha256,
            patch_payload_sha256=patch_env.payload_sha256,
            sandbox_payload_sha256=sandbox_env.payload_sha256,
            quorum_size=len(votes),
            approvals_count=approvals,
            rejections_count=rejections,
            supermajority_achieved=supermajority,
            critical_finding_veto=False,
            final_verdict="APPROVED" if supermajority else "REJECTED",
            votes=votes
        )
        vote_env = ReceiptEnvelope.seal(council_vote)
        print(f"\n[Step 7] Sealed CouncilVoteReceipt: Verdict={council_vote.final_verdict} ({approvals}/{len(votes)} approvals)")

        # 7b. Heterogeneous Jury Deliberation & Echo-Chamber Stability Detection
        family_map = {
            "qwen": "QWEN",
            "glm": "LOCAL_OSS",
            "mistral": "LOCAL_OSS",
            "deepseek": "DEEPSEEK",
            "openai": "OPENAI",
            "anthropic": "ANTHROPIC",
            "gemini": "GEMINI"
        }
        jury_votes = []
        for v in votes:
            fam_key = family_map.get(v.model_family.lower(), "LOCAL_OSS")
            vote_choice = "APPROVE" if v.decision == "approve" else ("REJECT" if v.decision == "reject" else "ABSTAIN")
            jury_votes.append(JuryJurorVote(
                juror_id=v.voter_slug,
                model_family=fam_key,
                vote=vote_choice,
                confidence_score=v.confidence,
                rationale=v.redacted_summary,
                formal_counterexample_sha256=None
            ))

        jury_receipt = self.jury_engine.evaluate_jury_deliberation(
            case_id=patch_sha,
            votes=jury_votes
        ) if jury_votes else None

        # 8. Simulated Apply Authorization
        auth = ApplyAuthorizationReceipt(
            authorized_patch_sha256=patch_sha,
            target_composite_state_sha256=repo_state_sha256,
            council_vote_payload_sha256=vote_env.payload_sha256,
            auth_mode="SIMULATED_TEST_SIGNATURE",
            human_approval_payload_sha256="SIMULATED_TEST_SIGNATURE_NOT_A_LIVE_APPROVAL"
        )
        auth_env = ReceiptEnvelope.seal(auth)
        print(f"[Step 8] Sealed ApplyAuthorizationReceipt (Mode: {auth.auth_mode})")

        # 9. Deterministic apply verification intentionally not run for simulated proof.
        print("\n[Step 9] Apply verification skipped: simulated sandbox/auth receipts cannot authorize apply.")

        return {
            "verdict": council_vote.final_verdict,
            "supermajority": supermajority,
            "chain_verified": False,
            "apply_authorized": False,
            "proof_boundary_status": "SIMULATED_ONLY_NOT_APPLY_PROOF",
            "patch_sha256": patch_sha,
            "heterogeneous_jury_receipt_sha256": jury_receipt.receipt_sha256 if jury_receipt else None,
            "beta_binomial_stability": jury_receipt.beta_binomial_stability if jury_receipt else 1.0,
            "echo_chamber_risk_score": jury_receipt.echo_chamber_risk_score if jury_receipt else 0.0
        }

if __name__ == "__main__":
    orchestrator = LiveCouncilOrchestrator()
    
    patch_bytes = (
        b"--- a/src/auth.py\n"
        b"+++ b/src/auth.py\n"
        b"@@ -10,3 +10,4 @@\n"
        b" def verify_token(token: str) -> bool:\n"
        b"-    return token == 'admin'\n"
        b"+    # Secure constant-time comparison\n"
        b"+    return hmac.compare_digest(token, EXPECTED_SECRET)\n"
    )
    live_state = "live_repo_state_sha_alpha"
    
    result = orchestrator.run_live_council(patch_bytes, live_state)
    print(f"\nFinal Result: {json.dumps(result, indent=2)}")
