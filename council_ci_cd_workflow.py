import hashlib
import json
import os
import time
from typing import Dict, Any, List, Optional
from council_contracts import (
    ImmutableContract, ReceiptEnvelope, VisionPolicyReceipt, Gate0PreflightReceipt,
    HumanApprovalReceipt, ApplyAuthorizationReceipt
)
from vision_policy_miner import VisionPolicyMiner
from gate0_policy_preflight import Gate0PolicyPreflight
from human_approval import ApprovalAuthenticator, DenyAllApprovalAuthenticator

class CIWorkflowStep(ImmutableContract):
    step_id: str
    name: str
    command: str
    timeout_minutes: int = 5

class CICDEvaluationResult(ImmutableContract):
    pr_number: int
    branch_name: str
    total_steps: int
    passed_steps: int
    all_passed: bool
    step_results: List[Dict[str, Any]]
    gate0_receipt_sha256: str
    authorization_receipt_sha256: Optional[str]
    pr_comment_markdown: str

class CouncilCICDWorkflow:
    """
    Autonomous CI/CD & GitHub Actions Workflow Orchestrator:
    - Requires externally supplied VisionPolicyReceipt and authenticated HumanApprovalReceipt.
    - Evaluates PR candidate diffs through Gate 0 Policy Preflight.
    - Emits execution verification reports and awaits external human approval.
    """

    def __init__(
        self,
        policy_receipt_env: ReceiptEnvelope[VisionPolicyReceipt],
        policy_approval_env: ReceiptEnvelope[HumanApprovalReceipt],
        authenticator: Optional[ApprovalAuthenticator] = None,
        workspace_root: Optional[str] = None
    ):
        self.workspace_root = workspace_root or os.path.dirname(os.path.abspath(__file__))
        self.policy_env = policy_receipt_env
        self.approval_env = policy_approval_env
        self.authenticator = authenticator or DenyAllApprovalAuthenticator()
        self.gate0 = Gate0PolicyPreflight(
            vision_policy_receipt=self.policy_env,
            approval_receipt=self.approval_env,
            authenticator=self.authenticator
        )

    def generate_github_workflow_yaml(self) -> str:
        """Generates standard GitHub Actions YAML for the Council Admissibility Gate."""
        yaml_content = """name: Council Admissibility & Verification Gate

on:
  pull_request:
    branches: [ main, staging ]
  push:
    branches: [ main ]

jobs:
  council-verification-cage:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code & Provenance Snapshot
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python 3.12
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Pure Dependencies & Pydantic v2
        run: |
          python -m pip install --upgrade pip
          pip install pydantic==2.10.6

      - name: Gate 0 - Constitution & Policy Acceptance Preflight
        run: |
          python -m unittest test_gate0_policy_preflight.py

      - name: Stage 1 - Deterministic Static AST & CWE Preflight
        run: |
          python -m unittest test_bounty_vulnerability_engine.py
          python -m unittest test_council_security.py

      - name: Stage 2 - Deterministic Decimal Pricing & PBM Invariants
        run: |
          python -m unittest test_pbm_rebate_engine.py
          python -m unittest test_pbm_fraud_detector.py

      - name: Stage 3 - 2-Stage RAG Evidence & Byte-Grounding Checks
        run: |
          python -m unittest test_rag_evidence_engine.py

      - name: Stage 4 - Ephemeral Zero-Network Docker Sandbox Execution
        run: |
          python -m unittest test_docker_sandbox_daemon.py
          python -m unittest test_swebench_patch_synthesizer.py

      - name: Stage 5 - Multi-Family Council Convocation & Spend Settlement
        run: |
          python -m unittest test_full_integrated_pipeline.py
          python -m unittest test_windows_spend_ledger.py

      - name: Master Test Discovery (All Test Suites)
        run: |
          python -m unittest discover -p "test_*.py"
"""
        return yaml_content

    def evaluate_pr_pipeline(
        self,
        pr_number: int,
        branch_name: str,
        touched_files: List[str],
        candidate_diff: str = "",
        stage_execution_receipts: Optional[List[Dict[str, Any]]] = None
    ) -> CICDEvaluationResult:
        """
        Evaluates PR pipeline steps including Gate 0 Preflight and synthesizes verification report.
        If stage_execution_receipts are not provided, subsequent steps are marked NOT_RUN / SIMULATED.
        """
        step_results = []

        # 1. Execute Gate 0 Policy Preflight
        target_comp = touched_files[0] if touched_files else "generic_module"
        gate0_env = self.gate0.evaluate_proposal(
            proposal_id=f"pr_{pr_number}",
            target_component=target_comp,
            diff_text=candidate_diff
        )
        gate0_receipt = gate0_env.payload
        gate0_sha = gate0_env.payload_sha256

        gate0_status = "PASSED" if gate0_receipt.passed_preflight else "REJECTED"
        step_results.append({
            "step_id": "gate_0_policy",
            "name": "Gate 0 Acceptance Policy Preflight",
            "status": gate0_status,
            "duration_sec": 0.05,
            "exit_code": 0 if gate0_receipt.passed_preflight else 1
        })

        if not gate0_receipt.passed_preflight:
            comment_md = (
                f"## 🏛️ Autonomous Council Verification Gate — PR #{pr_number}\n\n"
                f"**Status:** `REJECTED AT GATE 0 (POLICY CONSTITUTION VIOLATION)`  \n"
                f"**Branch:** `{branch_name}`  \n"
                f"**Touched Files:** `{', '.join(touched_files)}`  \n"
                f"**Rejection Reasons:**\n"
            )
            for r in gate0_receipt.rejection_reasons:
                comment_md += f"- ❌ {r}\n"

            return CICDEvaluationResult(
                pr_number=pr_number,
                branch_name=branch_name,
                total_steps=6,
                passed_steps=0,
                all_passed=False,
                step_results=step_results,
                gate0_receipt_sha256=gate0_sha,
                authorization_receipt_sha256=None,
                pr_comment_markdown=comment_md
            )

        # 2. Subsequent Verification Steps
        steps = [
            CIWorkflowStep(step_id="step_ast", name="AST CWE Sanitizer", command="python -m unittest test_bounty_vulnerability_engine.py"),
            CIWorkflowStep(step_id="step_pbm", name="Decimal Math & HIPAA Tokenizer", command="python -m unittest test_pbm_rebate_engine.py"),
            CIWorkflowStep(step_id="step_rag", name="Two-Stage RAG & Citation Grounding", command="python -m unittest test_rag_evidence_engine.py"),
            CIWorkflowStep(step_id="step_sandbox", name="Zero-Network Docker Sandbox", command="python -m unittest test_docker_sandbox_daemon.py"),
            CIWorkflowStep(step_id="step_council", name="Multi-Family Council Quorum", command="python -m unittest test_full_integrated_pipeline.py"),
        ]

        if stage_execution_receipts:
            passed_count = 1
            for res in stage_execution_receipts:
                step_results.append(res)
                if res.get("status") == "PASSED":
                    passed_count += 1
            all_passed = (passed_count == len(steps) + 1)
        else:
            # Dry-run / unexecuted stages
            for s in steps:
                step_results.append({
                    "step_id": s.step_id,
                    "name": s.name,
                    "status": "NOT_RUN",
                    "duration_sec": 0.0,
                    "exit_code": 0
                })
            all_passed = False

        comment_md = (
            f"## 🏛️ Autonomous Council Verification Gate — PR #{pr_number}\n\n"
            f"**Overall Status:** `{'PASSED (ALL GATES CLEAN)' if all_passed else 'AWAITING_EXECUTION_EVIDENCE'}`  \n"
            f"**Branch:** `{branch_name}`  \n"
            f"**Gate 0 Policy Preflight:** `PASSED` (Receipt SHA: `{gate0_sha[:16]}...`)  \n\n"
            f"### Stage Execution Breakdown:\n"
        )
        for res in step_results:
            icon = "✅" if res["status"] == "PASSED" else ("⏳" if res["status"] == "NOT_RUN" else "❌")
            comment_md += f"- {icon} **{res['name']}**: `{res['status']}`\n"

        return CICDEvaluationResult(
            pr_number=pr_number,
            branch_name=branch_name,
            total_steps=len(steps) + 1,
            passed_steps=sum(1 for s in step_results if s["status"] == "PASSED"),
            all_passed=all_passed,
            step_results=step_results,
            gate0_receipt_sha256=gate0_sha,
            authorization_receipt_sha256=None,
            pr_comment_markdown=comment_md
        )
