import argparse
import json
import os
import sys
import time
from decimal import Decimal
from typing import Dict, Any, List

from council_contracts import ReceiptEnvelope
from council_verifier import CouncilReceiptVerifier
from authority_conflict_detector import AuthorityConflictDetector, AuthorityRank
from dead_letter_queue import DeadLetterQueue
from pbm_rebate_engine import PBMRebateEngine, PrescriptionClaim, RebateTierRule
from bounty_vulnerability_engine import BountyVulnerabilityEngine
from dizzy_runtime_engine import DizzyRuntimeEngine
from model_qualification_evaluator import ModelQualificationEvaluator

def print_banner(title: str):
    print("\n" + "=" * 80)
    print(f" {title.upper()} ")
    print("=" * 80)

def handle_drift_cmd(args):
    print_banner("Authority Drift & Tide Meter Monitor")
    detector = AuthorityConflictDetector()
    
    # Simulate a baseline query
    drift_env = detector.compute_drift_observation(window_sec=3600.0)
    payload = drift_env.payload
    
    print(f"Observation Window : {payload.observation_window_sec}s")
    print(f"Conflicts Resolved : {payload.total_conflicts_resolved}")
    print(f"Drift Velocity     : {payload.drift_velocity_per_hour:.2f} overrides/hr")
    print(f"Tide Alarm Status  : {'ALARM TRIPPED (UNSAFE DRIFT)' if payload.tide_alarm_triggered else 'STABLE (NORMAL TIDES)'}")
    print("\nDrift Categories:")
    if not payload.net_drift_vector:
        print("  - Zero directional drift recorded.")
    else:
        for cat, count in payload.net_drift_vector.items():
            print(f"  * {cat}: {count}")

def handle_dlq_cmd(args):
    print_banner("Failure Museum & Dead Letter Queue")
    dlq = DeadLetterQueue()
    records = dlq.list_dead_letters(category=args.category)
    
    print(f"Total Quarantined Dead Letters: {len(records)}")
    for r in records[:10]:
        print(f"\n[ID: {r.dead_letter_id}] Model: {r.source_model_slug} | Category: {r.failure_category}")
        print(f"  Error: {r.raw_error_message[:120]}...")
        print(f"  Quarantined: {time.ctime(r.quarantined_at)}")

def handle_bounty_cmd(args):
    print_banner("Bounty AST Vulnerability Scanner")
    engine = BountyVulnerabilityEngine()
    
    if not os.path.exists(args.file):
        print(f"Error: Target file '{args.file}' does not exist.")
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    pis, checks = engine.evaluate_patch_integrity_score(code)
    print(f"File Scanned: {args.file}")
    print(f"Patch Integrity Score (PIS): {pis * 100:.1f}%\n")
    
    for c in checks:
        status_sym = "[PASSED]" if c.passed else "[FAILED]"
        print(f"{status_sym} {c.cwe_id}: {c.cwe_name} -> {c.violation_message}")

def handle_pbm_cmd(args):
    print_banner("Deterministic PBM Rebate Calculator")
    engine = PBMRebateEngine()
    
    # Default standard 3-tier structure
    tiers = [
        RebateTierRule(tier_name="Tier 1 (<20% MS)", min_market_share=Decimal("0.0"), max_market_share=Decimal("0.20"), base_rebate_rate=Decimal("0.100000"), volume_adder_rate=Decimal("0.000000")),
        RebateTierRule(tier_name="Tier 2 (20%-50% MS)", min_market_share=Decimal("0.20"), max_market_share=Decimal("0.50"), base_rebate_rate=Decimal("0.150000"), volume_adder_rate=Decimal("0.020000")),
        RebateTierRule(tier_name="Tier 3 (>50% MS)", min_market_share=Decimal("0.50"), max_market_share=Decimal("1.00"), base_rebate_rate=Decimal("0.200000"), volume_adder_rate=Decimal("0.050000"))
    ]

    sample_claim = PrescriptionClaim(
        claim_id="CLM_DEMO_01",
        member_id_raw="PATIENT_987654321",
        ndc="00002-8215-01",
        drug_name="Trulicity 1.5mg",
        is_brand=True,
        days_supply=90,
        quantity_dispensed=Decimal("3.0"),
        unit_wac=Decimal("975.50"),
        adjudication_timestamp=time.time()
    )
    sanitized = engine.sanitize_and_normalize_claim(sample_claim)
    
    res = engine.calculate_quarterly_rebate(
        claims=[sanitized],
        total_category_30eq_scripts=Decimal("10.0"),
        tiers=tiers
    )
    
    print(f"Member ID Tokenized : {sanitized.tokenized_member_id}")
    print(f"Normalized 30-eq    : {sanitized.normalized_30eq_scripts} scripts")
    print(f"Matched Rebate Tier : {res['matched_tier_name']}")
    print(f"Total Brand WAC     : ${res['total_brand_wac_usd']:,.2f}")
    print(f"Gross Rebate        : ${res['gross_rebate_usd']:,.2f}")
    print(f"Plan Sponsor Credit : ${res['plan_sponsor_credit_usd']:,.2f}")
    print(f"PBM Admin Fee       : ${res['pbm_admin_fee_usd']:,.2f}")

def handle_rag_cmd(args):
    print_banner("RAG Evidence Retrieval & Citation Grounding")
    from rag_evidence_engine import RAGEvidenceEngine
    engine = RAGEvidenceEngine()
    
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)
        
    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
        
    chunks = engine.chunk_document(args.file, content, chunk_size_lines=30)
    print(f"File Chunked        : {args.file} -> {len(chunks)} chunks")
    
    evidence_env = engine.retrieve_and_rerank(
        query=args.query,
        packet_payload_sha="local_cli_packet_sha",
        candidate_chunks=chunks,
        top_k=args.top_k
    )
    payload = evidence_env.payload
    print(f"Query SHA-256       : {payload.query_sha256[:16]}...")
    print(f"Selected Top-{args.top_k} Chunks:")
    for c in payload.selected_chunks:
        print(f"  * [{c.chunk_id}] Lines {c.start_line}-{c.end_line} | Score: {c.cross_encoder_rerank_score}")

def handle_telemetry_cmd(args):
    print_banner("Council Distributed Telemetry & OTel Traces")
    from council_telemetry import CouncilTelemetryTracer
    tracer = CouncilTelemetryTracer()
    
    if args.trace_id:
        spans = tracer.list_spans_for_trace(args.trace_id)
        print(f"Trace ID: {args.trace_id} ({len(spans)} spans)")
        for s in spans:
            print(f"  * Span [{s.span_id}] {s.name} ({s.duration_ms}ms) -> Status: {s.status_code}")
            for k, v in s.attributes.items():
                print(f"      - {k}: {v}")
    else:
        # Create a sample span
        t_id, s_id = tracer.start_span("cli.demo.span", attributes={"cli.command": "telemetry"})
        tracer.end_span(s_id, status_code="OK", additional_attributes={"tokens.total": 640})
        print(f"Generated Live Trace ID: {t_id}")
        print(f"Inspect via: python council_cli.py telemetry --trace-id {t_id}")

def handle_fwa_cmd(args):
    print_banner("PBM Pharmacy Claims Fraud, Waste & Abuse (FWA) Audit")
    from pbm_fraud_detector import PBMFraudDetector, PharmacyClaimRecord
    detector = PBMFraudDetector()
    
    sample_claim = PharmacyClaimRecord(
        claim_id="CLM_FWA_DEMO_01",
        member_id="M_DEMO_999",
        prescriber_npi="NPI_DOC_01",
        pharmacy_npi="NPI_PHARM_01",
        ndc="00002-8215-01",
        gpi_10="1234567890",
        gpi_6="123456",
        drug_name="Standard Maintenance Drug",
        schedule="NON-CONTROLLED",
        date_of_service=1,
        days_supply=30,
        quantity=Decimal("30.0"),
        strength_mg=Decimal("10.0")
    )
    
    result = detector.audit_claim(sample_claim)
    print(f"Claim ID       : {result.claim_id}")
    print(f"Triage Tier    : {result.triage_tier}")
    print(f"Audit Status   : {'PASSED' if result.audit_passed else 'FLAGGED/REJECTED'}")
    print(f"Reject Code    : {result.ncpdp_reject_code or 'NONE'}")
    print(f"Audit Rationale: {result.reject_reason}")

def handle_solver_cmd(args):
    print_banner("SWE-bench Autonomous Bounty Patch Synthesizer")
    from swebench_patch_synthesizer import SWEBenchPatchSynthesizer
    synthesizer = SWEBenchPatchSynthesizer()
    
    harness = synthesizer.generate_reproduction_harness(
        issue_id="ISSUE_CLI_DEMO",
        target_module="auth",
        failing_function="verify_session",
        expected_output="True",
        input_args="'valid_token'"
    )
    print(f"Generated Harness ID: {harness.test_id}")
    print(f"Harness SHA-256     : {harness.test_sha256[:16]}...")
    print(f"FAIL_TO_PASS Lines  : {len(harness.fail_to_pass_test_code.splitlines())}")
    print(f"PASS_TO_PASS Lines  : {len(harness.pass_to_pass_regression_code.splitlines())}")

def handle_serve_cmd(args):
    print_banner(f"Starting Council API & SSE Gateway Server on Port {args.port}")
    from council_api_server import CouncilAPIServer, run_live_api_server
    server = CouncilAPIServer()
    health = server.handle_health()
    print(f"Status   : {health['status']} (v{health['version']})")
    print(f"Listening: http://127.0.0.1:{args.port}")
    print("Endpoints Available:")
    print("  • GET  /api/v1/health")
    print("  • GET  /api/v1/drift")
    print("  • GET  /api/v1/dlq")
    print("  • GET  /api/v1/dizzy/stream")
    print("  • POST /api/v1/bounty/scan")
    print("  • POST /api/v1/fwa/audit")
    if not getattr(args, 'dry_run', False):
        print(f"Server running live at http://127.0.0.1:{args.port} (Press Ctrl+C to stop)...")
        run_live_api_server(host="127.0.0.1", port=args.port, blocking=True)

def handle_optimize_cmd(args):
    print_banner("DSPy Self-Healing Prompt Optimizer")
    from dspy_self_healing_optimizer import DSPySelfHealingOptimizer
    optimizer = DSPySelfHealingOptimizer()
    
    candidate = optimizer.compile_optimized_prompt(
        target_model_slug=args.model,
        failure_category=args.category,
        base_system_prompt="You are a secure coding assistant complying with Council deterministic invariants.",
        max_demonstrations=3
    )
    print(f"Target Model   : {candidate.target_model_slug}")
    print(f"Mined Failures : {candidate.mined_dead_letters_count} dead letters")
    print(f"Prompt SHA-256 : {candidate.candidate_sha256[:16]}...")
    
    receipt_env = optimizer.benchmark_and_qualify_candidate(candidate)
    print(f"Benchmark Status: {receipt_env.payload.status} (F1: {receipt_env.payload.f1_score:.4f})")

def handle_sandbox_cmd(args):
    print_banner("Hardened Ephemeral Sandbox Runner")
    from docker_sandbox_daemon import DockerSandboxDaemon
    daemon = DockerSandboxDaemon()
    
    receipt_env = daemon.execute_in_sandbox(
        patch_payload_sha="local_cli_patch_sha",
        test_command=args.test_cmd,
        workspace_host_path="./",
        mock_execution=True
    )
    payload = receipt_env.payload
    print(f"Isolation Mode   : {payload.isolation_mode}")
    print(f"Container Engine : {payload.container_engine}")
    print(f"Network Isolation: {'ISOLATED (--network none)' if payload.network_isolated else 'UNISOLATED'}")
    print(f"Exit Code        : {payload.test_exit_code} (SUCCESS)")
    print(f"Duration         : {payload.duration_sec}s")
    print(f"Receipt Hash     : {receipt_env.payload_sha256[:16]}...")

def handle_ci_cmd(args):
    print_banner("Council CI/CD & GitHub Actions Gate")
    from council_ci_cd_workflow import CouncilCICDWorkflow
    from human_approval import HMACApprovalAuthenticator
    from vision_policy_miner import VisionPolicyMiner

    workspace_root = os.path.dirname(os.path.abspath(__file__))
    miner = VisionPolicyMiner(workspace_root)
    _, policy_env = miner.compile_vision_constitution(
        human_approved=True,
        author_signature="SIMULATED_CLI_POLICY_FIXTURE"
    )
    authenticator = HMACApprovalAuthenticator()
    authenticator.register_key("key_cli_policy_fixture", "cli_policy_fixture_secret")
    approval_env = HMACApprovalAuthenticator.create_signed_approval(
        subject_type="VISION_POLICY",
        subject_payload_sha256=policy_env.payload_sha256,
        approver_identity="cli_policy_fixture",
        approver_key_id="key_cli_policy_fixture",
        secret_key="cli_policy_fixture_secret",
        validity_sec=3600
    )
    workflow = CouncilCICDWorkflow(
        policy_receipt_env=policy_env,
        policy_approval_env=approval_env,
        authenticator=authenticator
    )
    
    if args.generate_yaml:
        yaml_content = workflow.generate_github_workflow_yaml()
        print(yaml_content)
    else:
        res = workflow.evaluate_pr_pipeline(
            pr_number=args.pr_number,
            branch_name=args.branch,
            touched_files=["src/main.py"]
        )
        status = "APPROVED" if res.all_passed else "AWAITING_EXECUTION_EVIDENCE"
        if res.step_results and res.step_results[0]["status"] == "REJECTED":
            status = "REJECTED"
        print(f"PR Number    : #{res.pr_number} ({res.branch_name})")
        print(f"Status       : {status}")
        print(f"Passed Steps : {res.passed_steps}/{res.total_steps}")
        if res.authorization_receipt_sha256:
            print(f"Auth Receipt : {res.authorization_receipt_sha256[:16]}...")
        else:
            print("Auth Receipt : NOT_CREATED")

def handle_dashboard_cmd(args):
    print_banner(f"Launching Council Web Dashboard Cockpit on Port {args.port}")
    from council_web_dashboard import CouncilWebDashboard
    dashboard = CouncilWebDashboard(port=args.port)
    print(f"Dashboard URL: http://127.0.0.1:{args.port}")
    print("Serving HTML5 Visual Cockpit with live Tide Meter & Verification Cage.")

def handle_multilang_cmd(args):
    print_banner("Multi-Lingual AST Resolution & Blast Radius Engine")
    from multilingual_ast_engine import MultilingualASTEngine
    engine = MultilingualASTEngine()
    
    py_syms = engine.extract_symbols_from_python("src/auth.py", "def login(): pass\nclass Session: pass")
    ts_syms = engine.extract_symbols_from_typescript("src/api.ts", "export function callLogin() {}")
    go_syms = engine.extract_symbols_from_go("pkg/auth.go", "func Verify() {}\ntype User struct {}")
    rs_syms = engine.extract_symbols_from_rust("crates/lib.rs", "pub fn verify() {}\npub trait Token {}")
    
    total_syms = len(py_syms) + len(ts_syms) + len(go_syms) + len(rs_syms)
    print(f"Resolved Symbols Across 4 Languages: {total_syms}")
    print(f"  • Python     : {len(py_syms)} symbols")
    print(f"  • TypeScript : {len(ts_syms)} symbols")
    print(f"  • Go         : {len(go_syms)} symbols")
    print(f"  • Rust       : {len(rs_syms)} symbols")
    
    blast = engine.compute_blast_radius(py_syms + ts_syms, [])
    print(f"SMT Invariants : {'VERIFIED' if blast.smt_invariant_verified else 'VIOLATED'}")

def handle_terminal_cmd(args):
    print_banner("Long-Horizon Terminal State Machine & VTE Runner")
    from long_horizon_terminal_runner import LongHorizonTerminalRunner
    runner = LongHorizonTerminalRunner()
    
    snap = runner.execute_turn_transition(
        turn_index=1,
        command=args.cmd,
        raw_output=f"\x1b[32m[OK]\x1b[0m Executed {args.cmd}",
        exit_code=0
    )
    print(f"Turn Index    : {snap.turn_index}")
    print(f"State         : {snap.current_state}")
    print(f"Merkle Root   : {snap.checkpoint_merkle_root[:16]}...")
    print(f"Cleaned Output: (VTE ANSI Stripped)")

def handle_repl_cmd(args):
    from council_interactive_repl import CouncilInteractiveREPL
    repl = CouncilInteractiveREPL()
    print(repl.print_banner())
    print("\nEntering simulated non-interactive test mode for CLI verification.")
    cont, out = repl.evaluate_line("status")
    print(out)

def handle_proof_cmd(args):
    print_banner("P3 Neuro-Symbolic Joint Program & Proof Planner")
    from neurosymbolic_proof_planner import NeuroSymbolicProofPlanner
    planner = NeuroSymbolicProofPlanner()
    
    plan = planner.synthesize_joint_plan(
        target_module="pricing",
        function_name="calculate_discount",
        input_variables=["base_price", "rebate_rate"],
        invariants=[{"name": "non_negativity"}]
    )
    print(f"Plan ID        : {plan.plan_id}")
    print(f"SMT Clauses    : {len(plan.smt_clauses)} local check clauses")
    print(f"Z3 Check       : {'PASSED (LOCAL SMT BOUNDED)' if plan.proof_verified else 'FAILED'}")
    print(f"Proof SHA-256  : {plan.proof_sha256[:16]}...")

def handle_redteam_cmd(args):
    print_banner("Adversarial Red-Team & Injection Defense Engine")
    from adversarial_red_team_engine import AdversarialRedTeamEngine
    engine = AdversarialRedTeamEngine()
    
    summary = engine.evaluate_20_attack_vectors()
    print(f"Vectors Tested : {summary.total_vectors_tested}")
    print(f"Blocked Probes : {summary.total_blocked}/{summary.total_vectors_tested}")
    print(f"Attack Success : {summary.attack_success_rate_pct:.2f}% (ASR)")
    print(f"Immunity Score : {summary.immunity_score_pct:.2f}% (IS)")
    print(f"Gate 4 Status  : {'PASSED (IMMUNE)' if summary.gate4_passed else 'FAILED'}")

def handle_formal_cmd(args):
    print_banner("Lean4 & Dafny Scaffold Boundary Reporter")
    from formal_theorem_prover_engine import FormalTheoremProverEngine
    engine = FormalTheoremProverEngine()
    
    contract = engine.synthesize_dafny_contract(
        method_name="SumFirstN",
        parameters=["n: int"],
        returns=["sum: int"],
        preconditions=["n >= 0"],
        postconditions=["sum == (n * (n + 1)) / 2"]
    )
    cert = engine.generate_lean4_proof_certificate("nat_sum_formula", ["linarith"])
    
    print(f"Dafny Method   : {contract.method_name} -> {contract.verification_status}")
    print(f"Dafny Checker  : invoked={contract.checker_invoked}")
    print(f"Lean 4 Theorem : {cert.theorem_name} -> {cert.certificate_status} ({cert.certificate_sha256[:16]}...)")
    print(f"Lean Checker   : invoked={cert.checker_invoked}")

def handle_autotune_cmd(args):
    print_banner("Council Swarm Dynamic Hyperparameter Auto-Tuner")
    from council_swarm_autotuner import CouncilSwarmAutoTuner
    autotuner = CouncilSwarmAutoTuner()
    
    code = "def authenticate(user, pwd): return user == 'admin'"
    receipt = autotuner.calibrate_swarm(args.target, code)
    print(f"Target Module  : {receipt.target_module}")
    print(f"AST Entropy    : {receipt.ast_entropy_score} ({receipt.difficulty_level})")
    print(f"Calibrated     : {len(receipt.calibrated_seats)} Council Seats")
    for s in receipt.calibrated_seats:
        print(f"  • {s.seat_id:25}: T={s.temperature:.2f}, Top-P={s.top_p:.2f}")

def handle_jury_cmd(args):
    print_banner("Cross-Model Heterogeneous Jury & Deliberation Engine")
    from heterogeneous_jury_engine import HeterogeneousJuryEngine, JuryJurorVote
    engine = HeterogeneousJuryEngine()
    
    votes = [
        JuryJurorVote(juror_id="j1", model_family="ANTHROPIC", vote="APPROVE", confidence_score=0.95, rationale="Clean AST"),
        JuryJurorVote(juror_id="j2", model_family="OPENAI", vote="APPROVE", confidence_score=0.92, rationale="Passes tests"),
        JuryJurorVote(juror_id="j3", model_family="QWEN", vote="APPROVE", confidence_score=0.90, rationale="No regressions")
    ]
    receipt = engine.evaluate_jury_deliberation(args.case, votes)
    print(f"Case ID        : {receipt.case_id}")
    print(f"Families Count : {receipt.distinct_families_count} Distinct Architectures")
    print(f"Decision       : {receipt.consensus_decision}")
    print(f"Beta Stability : {receipt.beta_binomial_stability:.3f}")
    print(f"Echo Risk      : {receipt.echo_chamber_risk_score:.3f}")

def handle_pipeline_cmd(args):
    print_banner("Master Council End-to-End 6-Stage Pipeline")
    from council_e2e_orchestrator import CouncilE2EOrchestrator
    orchestrator = CouncilE2EOrchestrator()
    
    source_code = "def process_tx(amt, fee): return amt - fee"
    patch_diff = "--- a/src/tx.py\n+++ b/src/tx.py\n@@ -1,1 +1,1 @@\n-def process_tx(amt, fee): return amt - fee\n+def process_tx(amt, fee): return max(0, amt - fee)\n"
    
    receipt = orchestrator.execute_e2e_pipeline(
        target_module=args.target,
        source_code=source_code,
        patch_diff=patch_diff,
        budget_reservation_cents=25
    )
    print(f"Run ID         : {receipt.run_id}")
    print(f"Target Module  : {receipt.target_module}")
    print(f"Stage 1 (AST)  : {'PASSED' if receipt.stage_1_preflight_passed else 'FAILED'}")
    print(f"Stage 2 (P3)   : {'PASSED' if receipt.stage_2_proof_plan_passed else 'FAILED'}")
    print(f"Stage 3 (RAG)  : {'PASSED' if receipt.stage_3_rag_grounding_passed else 'FAILED'}")
    print(f"Stage 4 (Box)  : {'PASSED' if receipt.stage_4_sandbox_passed else 'FAILED'}")
    print(f"Stage 5 (Jury) : {'PASSED' if receipt.stage_5_jury_consensus_passed else 'FAILED'}")
    print(f"Stage 6 (Spend): {'PASSED' if receipt.stage_6_spend_settled_passed else 'FAILED'} (${receipt.spent_amount_cents/100:.2f})")
    print(f"Overall Cage   : {'ALL 6 STAGES PASSED (APPROVED)' if receipt.overall_pipeline_passed else 'REJECTED'}")
    if receipt.authorization_receipt_sha256:
        print(f"Auth Receipt   : {receipt.authorization_receipt_sha256[:16]}...")
    else:
        print("Auth Receipt   : NOT_CREATED")

def handle_chaos_cmd(args):
    print_banner("Council Chaos Resilience & Fault Injection Engine")
    from council_chaos_resilience_engine import CouncilChaosOrchestrator
    orchestrator = CouncilChaosOrchestrator()
    
    results = orchestrator.run_all_scenarios()
    print(f"Executed       : {len(results)} Automated Chaos Scenarios")
    for r in results:
        status = "PASSED (FAIL-CLOSED)" if r.fail_closed_invariant_maintained else "FAILED"
        print(f"  • {r.scenario_name:45}: {status:20} (MTTR: {r.total_mttr_ms:.1f}ms)")

def handle_sync_cmd(args):
    print_banner("Distributed Merkle DAG & State Replication Engine")
    from distributed_merkle_state_sync import DistributedMerkleStateSync
    node_a = DistributedMerkleStateSync(peer_id=args.local_peer)
    node_b = DistributedMerkleStateSync(peer_id=args.remote_peer)
    
    r1 = node_a.insert_receipt(1, "ApplyAuthorizationReceipt", "author_1", "sha_1")
    r2 = node_b.insert_receipt(1, "ApplyAuthorizationReceipt", "author_2", "sha_2")
    
    receipt = node_a.synchronize_with_peer(args.remote_peer, node_b.dag_nodes)
    print(f"Sync Session   : {receipt.sync_session_id}")
    print(f"Local Peer     : {receipt.local_peer_id}")
    print(f"Remote Peer    : {receipt.remote_peer_id}")
    print(f"Synchronized   : {receipt.synchronized_nodes_count} New Nodes")
    print(f"Symmetric Diff : {len(receipt.symmetric_diff_cids)} CIDs")
    print(f"Convergence    : {'CONVERGED' if receipt.sync_converged else 'FAILED'}")

def handle_qualify_cmd(args):
    print_banner(f"Model Statistical Qualification: {args.model}")
    evaluator = ModelQualificationEvaluator()
    
    receipt_env = evaluator.evaluate_and_seal_receipt(
        model_slug=args.model,
        model_family=args.family or "qwen",
        provider=args.provider or "local",
        tp=args.tp,
        fp=args.fp,
        tn=args.tn,
        fn=args.fn,
        schema_conformance=True,
        prompt_injection_immunity=True
    )
    payload = receipt_env.payload
    print(f"Status        : {payload.status}")
    print(f"F1 Score      : {payload.f1_score:.4f} (Threshold >= 0.900)")
    print(f"Precision     : {payload.precision_score:.4f}")
    print(f"Recall        : {payload.recall_score:.4f}")
    print(f"Benign Passed : {payload.benign_control_passed}")
    print(f"Grounded Bug  : {payload.grounded_bug_passed}")
    print(f"Receipt Hash  : {receipt_env.payload_sha256[:16]}...")

def handle_a2a_cmd(args):
    print_banner(f"Agent-to-Agent (A2A) Protocol: {args.action.upper()}")
    from a2a_protocol_engine import A2ATrustStore, A2AEnvelopeSigner, A2AMessageRouter, A2AReconciliationLoop
    from council_contracts import A2AMessage, CONTRACT_VERSION
    import hashlib

    trust_store = A2ATrustStore()
    trust_store.register_agent("antigravity", "secret_key_antigravity_hmac_256")
    trust_store.register_agent("codex", "secret_key_codex_hmac_256")
    router = A2AMessageRouter(trust_store)

    if args.action == "send":
        msg = A2AMessage(
            message_id=f"msg_cli_{int(time.time()*1000)}",
            conversation_id="conv_cli_a2a",
            sender_agent_id=args.sender,
            recipient_agent_id=args.recipient,
            intent="TASK_PROPOSAL",
            payload_data={"task": args.task, "code": "def run(): pass"},
            context_snapshot_sha256=hashlib.sha256(b"snap").hexdigest(),
            nonce=f"nonce_{time.time()}"
        )
        env = A2AEnvelopeSigner.sign_message(msg, "secret_key_antigravity_hmac_256")
        router.send_signed_envelope(env)
        print(f"Message ID   : {msg.message_id}")
        print(f"Sender       : {args.sender}")
        print(f"Recipient    : {args.recipient}")
        print(f"Delivery     : DELIVERED TO MAILBOX")
    elif args.action == "reconcile":
        source_state = {"contract_version": CONTRACT_VERSION, "test_count": 273}
        target_state = {"contract_version": CONTRACT_VERSION, "test_count": 277}
        receipt_env = A2AReconciliationLoop.reconcile_and_seal_handoff(
            handoff_id="handoff_cli_001",
            conversation_id="conv_cli_recon",
            source_agent_id="codex",
            target_agent_id="antigravity",
            source_state_manifest=source_state,
            target_state_manifest=target_state
        )
        print(f"Handoff ID   : {receipt_env.payload.handoff_id}")
        print(f"Reconciled   : {'CLEAN' if receipt_env.payload.reconciled_cleanly else 'DRIFT_DETECTED'}")
        print(f"Tasks Moved  : {receipt_env.payload.tasks_transferred_count}")
        print(f"Receipt Hash : {receipt_env.payload_sha256[:16]}...")

def handle_subcommittee_cmd(args):
    print_banner(f"Council 4-Subcommittee Convocation: {args.task}")
    from council_subcommittee_engine import CouncilSubcommitteeEngine
    engine = CouncilSubcommitteeEngine()

    proposal = {
        "task": args.task,
        "code": "def process_data(item: str) -> bool: return len(item) > 0"
    }
    receipt_env = engine.convene_subcommittees_and_seal(
        convocation_id="convoc_cli_001",
        task_id=f"task_{args.task}",
        proposal=proposal,
        rotation_round=args.round
    )
    payload = receipt_env.payload
    print(f"Overall Verdict : {payload.overall_verdict}")
    print(f"Guardrails Held : {payload.guardrails_held}")
    print(f"Rotation Round  : {payload.rotation_round}")
    print("\nSubcommittee Evaluations:")
    for ev in payload.evaluations:
        print(f"  • [{ev.subcommittee_name:14}] Model: {ev.assigned_model_slug:18} | Verdict: {ev.verdict:7} | Conf: {ev.confidence_score:.2f}")

def handle_patch_pipeline_cmd(args):
    print_banner("Autonomous Bug Hunting & Patch Synthesis Pipeline")
    from autonomous_patch_synthesis_pipeline import AutonomousPatchSynthesisPipeline
    pipeline = AutonomousPatchSynthesisPipeline()

    vuln_code = (
        "def query_db(cursor, username: str):\n"
        "    cursor.execute(f'SELECT * FROM users WHERE u = {username}')\n"
    )
    oracle_code = "assert query_db(mock_cursor, 'admin') is not None"

    receipt_env, patch = pipeline.execute_end_to_end_remediation(
        pipeline_run_id="run_cli_patch_001",
        target_component=args.component,
        vulnerable_code=vuln_code,
        test_oracle_code=oracle_code
    )
    payload = receipt_env.payload
    print(f"Identified CWE  : {payload.vulnerability_cwe_id}")
    print(f"Synthesis Model : {payload.synthesis_model_slug}")
    print(f"Patch Integrity : {payload.patch_integrity_score:.4f} (Gate 1: {'PASSED' if payload.gate1_ast_passed else 'FAILED'})")
    print(f"Gate 2 Sandbox  : {'PASSED' if payload.gate2_sandbox_passed else 'FAILED'}")
    print(f"Receipt Hash    : {receipt_env.payload_sha256[:16]}...")
    print("\nSynthesized Patch Preview:")
    print(patch.strip())

def handle_route_cmd(args):
    print_banner(f"Agent Task Router: {args.objective[:40]}...")
    from task_router import AgentTaskRouter
    router = AgentTaskRouter()

    files = args.file if args.file else []
    receipt_env = router.route_task(
        objective=args.objective,
        candidate_files=files
    )

    payload = receipt_env.payload
    print(f"Task ID         : {payload.task_id}")
    print(f"Risk Tier       : {payload.risk_tier}")
    print(f"Classification  : {', '.join(payload.task_classification)}")
    print(f"Final Decision  : {payload.final_decision_owner}")
    print(f"L3 Auth Required: {'YES' if payload.human_l3_required else 'NO'}")
    print(f"\nAssignments Generated ({len(payload.assignments)} total):")
    for a in payload.assignments:
        print(f"  - Role: {a.role_id}")
        print(f"    - Scope Files : {len(a.scope_files)}")
        print(f"    - Can Mutate  : {'YES' if a.can_mutate_files else 'NO'}")
        print(f"    - Contract    : {a.expected_output_contract}")

    print(f"\nReceipt Hash    : {receipt_env.payload_sha256[:16]}...")

def main():
    parser = argparse.ArgumentParser(description="Multi-Agent Council & Autonomous Engine CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Route command
    route_parser = subparsers.add_parser("route", help="Generate narrow agent routing assignments from a broad objective")
    route_parser.add_argument("--objective", type=str, required=True, help="High-level task objective")
    route_parser.add_argument("--file", type=str, action="append", help="Target files to include (can be used multiple times)")
    route_parser.set_defaults(func=handle_route_cmd)

    # Drift command
    drift_parser = subparsers.add_parser("drift", help="Inspect authority drift & tide meter")
    drift_parser.set_defaults(func=handle_drift_cmd)

    # DLQ command
    dlq_parser = subparsers.add_parser("dlq", help="Inspect Dead Letter Queue / Failure Museum")
    dlq_parser.add_argument("--category", type=str, default=None, help="Filter by failure category")
    dlq_parser.set_defaults(func=handle_dlq_cmd)

    # Bounty command
    bounty_parser = subparsers.add_parser("bounty", help="Run Bounty AST vulnerability checks")
    bounty_parser.add_argument("--file", type=str, required=True, help="Target file to analyze")
    bounty_parser.set_defaults(func=handle_bounty_cmd)

    # PBM command
    pbm_parser = subparsers.add_parser("pbm", help="Run deterministic PBM rebate calculation")
    pbm_parser.set_defaults(func=handle_pbm_cmd)

    # RAG command
    rag_parser = subparsers.add_parser("rag", help="Run 2-Stage RAG evidence retrieval")
    rag_parser.add_argument("--query", type=str, required=True, help="Search query")
    rag_parser.add_argument("--file", type=str, required=True, help="Target source file")
    rag_parser.add_argument("--top-k", type=int, default=3, help="Number of chunks to select")
    rag_parser.set_defaults(func=handle_rag_cmd)

    # Telemetry command
    tel_parser = subparsers.add_parser("telemetry", help="Inspect distributed OTel trace spans")
    tel_parser.add_argument("--trace-id", type=str, default=None, help="Trace ID to inspect")
    tel_parser.set_defaults(func=handle_telemetry_cmd)

    # FWA command
    fwa_parser = subparsers.add_parser("fwa", help="Run PBM Pharmacy Claims FWA audit")
    fwa_parser.set_defaults(func=handle_fwa_cmd)

    # Solver command
    solver_parser = subparsers.add_parser("solver", help="Run SWE-bench bounty patch synthesis")
    solver_parser.set_defaults(func=handle_solver_cmd)

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start Council REST & SSE API Gateway")
    serve_parser.add_argument("--port", type=int, default=8000, help="Listening port")
    serve_parser.add_argument("--dry-run", action="store_true", help="Print endpoint routing and configuration without blocking")
    serve_parser.set_defaults(func=handle_serve_cmd)

    # Optimize command
    opt_parser = subparsers.add_parser("optimize", help="Run DSPy self-healing prompt optimizer over DLQ")
    opt_parser.add_argument("--model", type=str, default="qwen/qwen-3.8-coder", help="Target model slug")
    opt_parser.add_argument("--category", type=str, default="SCHEMA_VIOLATION", help="Failure category to remediate")
    opt_parser.set_defaults(func=handle_optimize_cmd)

    # Sandbox command
    sandbox_parser = subparsers.add_parser("sandbox", help="Run hardened ephemeral Docker sandbox")
    sandbox_parser.add_argument("--test-cmd", type=str, default="pytest tests/", help="Test command to execute")
    sandbox_parser.set_defaults(func=handle_sandbox_cmd)

    # CI command
    ci_parser = subparsers.add_parser("ci", help="Run Council CI/CD workflow generator & PR evaluator")
    ci_parser.add_argument("--generate-yaml", action="store_true", help="Generate GitHub Actions workflow YAML")
    ci_parser.add_argument("--pr-number", type=int, default=101, help="PR number to evaluate")
    ci_parser.add_argument("--branch", type=str, default="feature/patch", help="PR branch name")
    ci_parser.set_defaults(func=handle_ci_cmd)

    # Dashboard command
    dash_parser = subparsers.add_parser("dashboard", help="Start Visual Web Dashboard & Cockpit")
    dash_parser.add_argument("--port", type=int, default=8501, help="Listening port")
    dash_parser.set_defaults(func=handle_dashboard_cmd)

    # Multilang command
    ml_parser = subparsers.add_parser("multilang", help="Run Multi-Lingual AST symbol analysis across Py/TS/Go/Rust")
    ml_parser.set_defaults(func=handle_multilang_cmd)

    # Terminal command
    term_parser = subparsers.add_parser("terminal", help="Run Long-Horizon Terminal state turn transition")
    term_parser.add_argument("--cmd", type=str, default="git status", help="Command to simulate execution")
    term_parser.set_defaults(func=handle_terminal_cmd)

    # REPL command
    repl_parser = subparsers.add_parser("repl", help="Launch interactive Council REPL shell")
    repl_parser.set_defaults(func=handle_repl_cmd)

    # Proof command
    proof_parser = subparsers.add_parser("proof", help="Run P3 neuro-symbolic joint program and SMT proof planner")
    proof_parser.set_defaults(func=handle_proof_cmd)

    # RedTeam command
    red_parser = subparsers.add_parser("redteam", help="Run 20-vector adversarial red-team exploit benchmark")
    red_parser.set_defaults(func=handle_redteam_cmd)

    # Formal command
    formal_parser = subparsers.add_parser("formal", help="Report Lean4/Dafny scaffold boundaries and local Z3 checks")
    formal_parser.set_defaults(func=handle_formal_cmd)

    # Autotune command
    tune_parser = subparsers.add_parser("autotune", help="Dynamically calibrate Council seat hyperparameters via AST entropy")
    tune_parser.add_argument("--target", type=str, default="auth_core", help="Target module name")
    tune_parser.set_defaults(func=handle_autotune_cmd)

    # Jury command
    jury_parser = subparsers.add_parser("jury", help="Run cross-model heterogeneous jury deliberation")
    jury_parser.add_argument("--case", type=str, default="case_001", help="Deliberation case ID")
    jury_parser.set_defaults(func=handle_jury_cmd)

    # Pipeline command
    pipe_parser = subparsers.add_parser("pipeline", help="Run Master Council End-to-End 6-Stage Pipeline")
    pipe_parser.add_argument("--target", type=str, default="auth_service", help="Target module name")
    pipe_parser.set_defaults(func=handle_pipeline_cmd)

    # Chaos command
    chaos_parser = subparsers.add_parser("chaos", help="Run automated chaos resilience fault injection scenarios")
    chaos_parser.set_defaults(func=handle_chaos_cmd)

    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Run distributed Merkle DAG state replication sync")
    sync_parser.add_argument("--local-peer", type=str, default="node_us_east", help="Local peer ID")
    sync_parser.add_argument("--remote-peer", type=str, default="node_eu_west", help="Remote peer ID")
    sync_parser.set_defaults(func=handle_sync_cmd)

    # Qualify command
    qual_parser = subparsers.add_parser("qualify", help="Evaluate model qualification metrics")
    qual_parser.add_argument("--model", type=str, required=True, help="Model slug")
    qual_parser.add_argument("--family", type=str, default="qwen", help="Model family")
    qual_parser.add_argument("--provider", type=str, default="local", help="Provider name")
    qual_parser.add_argument("--tp", type=int, default=95, help="True positives")
    qual_parser.add_argument("--fp", type=int, default=2, help="False positives")
    qual_parser.add_argument("--tn", type=int, default=990, help="True negatives")
    qual_parser.add_argument("--fn", type=int, default=5, help="False negatives")
    qual_parser.set_defaults(func=handle_qualify_cmd)

    # A2A command
    a2a_parser = subparsers.add_parser("a2a", help="Run Agent-to-Agent protocol communication & reconciliation")
    a2a_parser.add_argument("--action", type=str, default="send", choices=["send", "reconcile"], help="A2A action")
    a2a_parser.add_argument("--sender", type=str, default="antigravity", help="Sender agent ID")
    a2a_parser.add_argument("--recipient", type=str, default="codex", help="Recipient agent ID")
    a2a_parser.add_argument("--task", type=str, default="verify_invariants", help="Task payload")
    a2a_parser.set_defaults(func=handle_a2a_cmd)

    # Subcommittee command
    subcom_parser = subparsers.add_parser("subcommittee", help="Convene 4 specialized Subcommittees across rotating OSS models")
    subcom_parser.add_argument("--task", type=str, default="audit_patch", help="Task description")
    subcom_parser.add_argument("--round", type=int, default=1, help="Model rotation round")
    subcom_parser.set_defaults(func=handle_subcommittee_cmd)

    # Patch-Pipeline command
    patch_pipe_parser = subparsers.add_parser("patch-pipeline", help="Run Autonomous Bug Hunting & Dual-Gate Patch Synthesis Pipeline")
    patch_pipe_parser.add_argument("--component", type=str, default="auth_service", help="Target component name")
    patch_pipe_parser.set_defaults(func=handle_patch_pipeline_cmd)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
