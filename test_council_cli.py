import os
import shutil
import subprocess
import sys
import tempfile
import unittest

class TestCouncilCLI(unittest.TestCase):

    def setUp(self):
        self.test_state_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_state_dir, ignore_errors=True)

    def run_cli(self, args: list) -> subprocess.CompletedProcess:
        council_dir = os.path.dirname(os.path.abspath(__file__))
        cli_path = os.path.join(council_dir, "council_cli.py")
        cmd = [sys.executable, cli_path] + args
        env = os.environ.copy()
        env["COUNCIL_STATE_DIR"] = self.test_state_dir
        return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=council_dir)

    def test_drift_subcommand(self):
        res = self.run_cli(["drift"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("AUTHORITY DRIFT & TIDE METER MONITOR", res.stdout)
        self.assertIn("Observation Window", res.stdout)

    def test_dlq_subcommand(self):
        res = self.run_cli(["dlq"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("FAILURE MUSEUM & DEAD LETTER QUEUE", res.stdout)
        self.assertIn("Total Quarantined Dead Letters", res.stdout)

    def test_bounty_subcommand(self):
        # Scan own file
        res = self.run_cli(["bounty", "--file", "bounty_vulnerability_engine.py"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("BOUNTY AST VULNERABILITY SCANNER", res.stdout)
        self.assertIn("Patch Integrity Score (PIS)", res.stdout)

    def test_pbm_subcommand(self):
        res = self.run_cli(["pbm"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("DETERMINISTIC PBM REBATE CALCULATOR", res.stdout)
        self.assertIn("Gross Rebate", res.stdout)

    def test_rag_subcommand(self):
        res = self.run_cli(["rag", "--query", "authenticate", "--file", "bounty_vulnerability_engine.py", "--top-k", "2"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("RAG EVIDENCE RETRIEVAL & CITATION GROUNDING", res.stdout)
        self.assertIn("Selected Top-2 Chunks", res.stdout)

    def test_telemetry_subcommand(self):
        res = self.run_cli(["telemetry"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("COUNCIL DISTRIBUTED TELEMETRY & OTEL TRACES", res.stdout)
        self.assertIn("Generated Live Trace ID", res.stdout)

    def test_fwa_subcommand(self):
        res = self.run_cli(["fwa"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("PBM PHARMACY CLAIMS FRAUD, WASTE & ABUSE (FWA) AUDIT", res.stdout)
        self.assertIn("Audit Status", res.stdout)

    def test_solver_subcommand(self):
        res = self.run_cli(["solver"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("SWE-BENCH AUTONOMOUS BOUNTY PATCH SYNTHESIZER", res.stdout)
        self.assertIn("Generated Harness ID", res.stdout)

    def test_serve_subcommand(self):
        res = self.run_cli(["serve", "--port", "8000", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("STARTING COUNCIL API & SSE GATEWAY SERVER ON PORT 8000", res.stdout)
        self.assertIn("http://127.0.0.1:8000", res.stdout)

    def test_optimize_subcommand(self):
        res = self.run_cli(["optimize", "--model", "qwen/qwen-3.8-coder", "--category", "SCHEMA_VIOLATION"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("DSPY SELF-HEALING PROMPT OPTIMIZER", res.stdout)
        self.assertIn("Target Model", res.stdout)

    def test_sandbox_subcommand(self):
        res = self.run_cli(["sandbox", "--test-cmd", "pytest tests/"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("HARDENED EPHEMERAL SANDBOX RUNNER", res.stdout)
        self.assertIn("Isolation Mode   : LOCAL_SUBPROCESS_MOCK", res.stdout)
        self.assertIn("Container Engine : docker_mock", res.stdout)
        self.assertIn("UNISOLATED", res.stdout)

    def test_ci_subcommand(self):
        res = self.run_cli(["ci", "--pr-number", "101"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("COUNCIL CI/CD & GITHUB ACTIONS GATE", res.stdout)
        self.assertIn("PR Number    : #101", res.stdout)
        self.assertIn("Status       : AWAITING_EXECUTION_EVIDENCE", res.stdout)
        self.assertIn("Passed Steps : 1/6", res.stdout)
        self.assertIn("Auth Receipt : NOT_CREATED", res.stdout)

    def test_dashboard_subcommand(self):
        res = self.run_cli(["dashboard", "--port", "8501"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("LAUNCHING COUNCIL WEB DASHBOARD COCKPIT ON PORT 8501", res.stdout)
        self.assertIn("http://127.0.0.1:8501", res.stdout)

    def test_multilang_subcommand(self):
        res = self.run_cli(["multilang"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("MULTI-LINGUAL AST RESOLUTION & BLAST RADIUS ENGINE", res.stdout)
        self.assertIn("Resolved Symbols Across 4 Languages", res.stdout)

    def test_terminal_subcommand(self):
        res = self.run_cli(["terminal", "--cmd", "cargo test"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("LONG-HORIZON TERMINAL STATE MACHINE & VTE RUNNER", res.stdout)
        self.assertIn("Turn Index    : 1", res.stdout)

    def test_repl_subcommand(self):
        res = self.run_cli(["repl"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("[COUNCIL] MULTI-AGENT COUNCIL & AUTONOMOUS ENGINE INTERACTIVE REPL COCKPIT", res.stdout)
        self.assertIn("STATUS: HEALTHY", res.stdout)

    def test_proof_subcommand(self):
        res = self.run_cli(["proof"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("P3 NEURO-SYMBOLIC JOINT PROGRAM & PROOF PLANNER", res.stdout)
        self.assertIn("Z3 Check       : PASSED (LOCAL SMT BOUNDED)", res.stdout)

    def test_redteam_subcommand(self):
        res = self.run_cli(["redteam"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("ADVERSARIAL RED-TEAM & INJECTION DEFENSE ENGINE", res.stdout)
        self.assertIn("Gate 4 Status  : PASSED (IMMUNE)", res.stdout)

    def test_formal_subcommand(self):
        res = self.run_cli(["formal"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("LEAN4 & DAFNY SCAFFOLD BOUNDARY REPORTER", res.stdout)
        self.assertIn("Dafny Method   : SumFirstN -> GENERATED_UNVERIFIED", res.stdout)
        self.assertIn("Dafny Checker  : invoked=False", res.stdout)
        self.assertIn("Lean Checker   : invoked=False", res.stdout)

    def test_autotune_subcommand(self):
        res = self.run_cli(["autotune", "--target", "auth_engine"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("COUNCIL SWARM DYNAMIC HYPERPARAMETER AUTO-TUNER", res.stdout)
        self.assertIn("Target Module  : auth_engine", res.stdout)
        self.assertIn("Calibrated     : 4 Council Seats", res.stdout)

    def test_jury_subcommand(self):
        res = self.run_cli(["jury", "--case", "case_999"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("CROSS-MODEL HETEROGENEOUS JURY & DELIBERATION ENGINE", res.stdout)
        self.assertIn("Case ID        : case_999", res.stdout)
        self.assertIn("Decision       : APPROVED_CONSENSUS", res.stdout)

    def test_pipeline_subcommand(self):
        res = self.run_cli(["pipeline", "--target", "payment_core"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("MASTER COUNCIL END-TO-END 6-STAGE PIPELINE", res.stdout)
        self.assertIn("Target Module  : payment_core", res.stdout)
        self.assertIn("Stage 4 (Box)  : FAILED", res.stdout)
        self.assertIn("Overall Cage   : REJECTED", res.stdout)
        self.assertIn("Auth Receipt   : NOT_CREATED", res.stdout)

    def test_chaos_subcommand(self):
        res = self.run_cli(["chaos"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("COUNCIL CHAOS RESILIENCE & FAULT INJECTION ENGINE", res.stdout)
        self.assertIn("Executed       : 5 Automated Chaos Scenarios", res.stdout)

    def test_sync_subcommand(self):
        res = self.run_cli(["sync", "--local-peer", "node_us", "--remote-peer", "node_eu"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("DISTRIBUTED MERKLE DAG & STATE REPLICATION ENGINE", res.stdout)
        self.assertIn("Local Peer     : node_us", res.stdout)
        self.assertIn("Convergence    : FAILED", res.stdout)

    def test_qualify_subcommand(self):
        res = self.run_cli(["qualify", "--model", "qwen/qwen-3.8-coder", "--tp", "95", "--fp", "2", "--tn", "990", "--fn", "5"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("MODEL STATISTICAL QUALIFICATION", res.stdout)
        self.assertIn("REVIEW_USABLE_FRESH", res.stdout)

    def test_a2a_send_and_reconcile_subcommands(self):
        # 1. a2a send
        res_send = self.run_cli(["a2a", "--action", "send", "--sender", "antigravity", "--recipient", "codex", "--task", "verify_contracts"])
        self.assertEqual(res_send.returncode, 0)
        self.assertIn("AGENT-TO-AGENT (A2A) PROTOCOL: SEND", res_send.stdout)
        self.assertIn("Delivery     : DELIVERED TO MAILBOX", res_send.stdout)

        # 2. a2a reconcile
        res_recon = self.run_cli(["a2a", "--action", "reconcile"])
        self.assertEqual(res_recon.returncode, 0)
        self.assertIn("AGENT-TO-AGENT (A2A) PROTOCOL: RECONCILE", res_recon.stdout)
        self.assertIn("Reconciled   : CLEAN", res_recon.stdout)

    def test_subcommittee_subcommand(self):
        res = self.run_cli(["subcommittee", "--task", "pbm_claim_validator", "--round", "1"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("COUNCIL 4-SUBCOMMITTEE CONVOCATION", res.stdout)
        self.assertIn("Overall Verdict : UNANIMOUS_APPROVAL", res.stdout)
        self.assertIn("SecOps", res.stdout)
        self.assertIn("Consensus", res.stdout)

    def test_patch_pipeline_subcommand(self):
        res = self.run_cli(["patch-pipeline", "--component", "user_auth"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("AUTONOMOUS BUG HUNTING & PATCH SYNTHESIS PIPELINE", res.stdout)
        self.assertIn("Identified CWE  : CWE-89", res.stdout)
        self.assertIn("Gate 1: PASSED", res.stdout)
        self.assertIn("Gate 2 Sandbox  : PASSED", res.stdout)

    def test_route_subcommand(self):
        res = self.run_cli(["route", "--objective", "reentrancy check on depositRebate in PBMRebateTreasury", "--file", "contracts/PBMRebateTreasury.sol"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("AGENT TASK ROUTER:", res.stdout.upper())
        self.assertIn("Task ID", res.stdout)
        self.assertIn("Risk Tier", res.stdout)
        self.assertIn("SOLIDITY_SEMANTICS_REVIEWER", res.stdout)
        self.assertIn("SECURITY_REVIEWER", res.stdout)

if __name__ == "__main__":
    unittest.main()
