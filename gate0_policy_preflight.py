import hashlib
import json
import re
import time
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import (
    ImmutableContract, Gate0PreflightReceipt, VisionPolicyReceipt,
    HumanApprovalReceipt, ReceiptEnvelope
)
from human_approval import ApprovalAuthenticator, DenyAllApprovalAuthenticator

class Gate0PolicyPreflight:
    """
    Gate 0 Policy Preflight Evaluator:
    - Evaluates proposed code patches, PR diffs, or task requests against the approved VISION.md constitution.
    - Uses semantic regex scanners to reject taboo violations (e.g. LLM prompts for raw numerical anomaly detection or sandbox bypasses).
    - Emits verifiable Gate0PreflightReceipts.
    """

    def __init__(
        self,
        vision_policy_receipt: ReceiptEnvelope[VisionPolicyReceipt],
        approval_receipt: ReceiptEnvelope[HumanApprovalReceipt],
        authenticator: Optional[ApprovalAuthenticator] = None
    ):
        self.policy_env = vision_policy_receipt
        self.policy = vision_policy_receipt.payload
        self.approval_env = approval_receipt

        # 1. Validate approval envelope & subject binding
        if approval_receipt.payload.subject_type != "VISION_POLICY":
            raise ValueError(f"Approval receipt subject_type '{approval_receipt.payload.subject_type}' != 'VISION_POLICY'")
        if approval_receipt.payload.subject_payload_sha256 != vision_policy_receipt.payload_sha256:
            raise ValueError("Approval receipt does not bind to the VisionPolicyReceipt hash")

        # 2. Authenticate signature / key
        auth_engine = authenticator or DenyAllApprovalAuthenticator()
        if not auth_engine.authenticate_approval(approval_receipt, vision_policy_receipt.payload_sha256):
            raise ValueError("Gate 0 Preflight requires an authenticated, non-expired HumanApprovalReceipt for VISION.md policy")

    def evaluate_proposal(
        self,
        proposal_id: str,
        target_component: str,
        diff_text: str
    ) -> ReceiptEnvelope[Gate0PreflightReceipt]:
        """
        Evaluates diff_text against explicit acceptance principles and non-goals.
        """
        diff_sha = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()
        diff_lower = diff_text.lower()
        target_lower = target_component.lower()
        rejections = []
        matched_principles = []
        matched_non_goals = []

        # Rule 1: Semantic Taboo against LLM-based raw statistical anomaly / risk detection
        is_fraud_domain = any(k in target_lower for k in ["fraud", "fwa", "claims", "rebate", "audit", "pos_check"])
        has_llm_invocation = any(k in diff_lower for k in ["llm", "language_model", "model.generate", "prompt", "chat_completion", "predict_risk"])
        has_statistical_concept = any(k in diff_lower for k in ["anomaly", "outlier", "risk pattern", "fraud score", "statistical", "claims scan", "suspicious"])

        if is_fraud_domain and has_llm_invocation and has_statistical_concept:
            rejections.append("Violation of Non-Goal #1: Cannot use language models/prompts for raw numerical anomaly or risk detection; use deterministic statistics (ECOD/Mahalanobis).")
            matched_non_goals.append("NO LLM Statistical Anomaly Detection")

        # Rule 2: Taboo against unsandboxed execution / insecure bypasses
        if any(k in diff_lower for k in ["--insecure", "skip_sandbox", "disable_jail", "bypass_isolation"]):
            rejections.append("Violation of Non-Goal #2: Insecure bypass or sandbox disabling detected.")
            matched_non_goals.append("NO Unsandboxed Arbitrary Mutation")

        # Rule 3: Taboo against bypassing spend ledger caps
        if any(k in diff_lower for k in ["bypass_spend_limit", "council_spend_hard_cap = none", "disable_spend_trigger"]):
            rejections.append("Violation of Principle #5: Attempted to bypass atomic spend ledger hard caps.")
            matched_non_goals.append("NO Spend Ledger Bypass")

        # Rule 4: Match positive principles
        if "ReceiptEnvelope.seal" in diff_text or "council_contracts" in diff_text:
            matched_principles.append("Principle #2: Cryptographic Lineage Enforcement")
        if "LogDerivedContextEngine" in diff_text or "verify_and_guard_dispatch" in diff_text:
            matched_principles.append("Principle #3: Log-Derived Context")
        if "container_engine" in diff_text or "local_subprocess" in diff_text:
            matched_principles.append("Principle #4: Truthful Sandboxing")

        passed = len(rejections) == 0

        receipt = Gate0PreflightReceipt(
            proposal_id=proposal_id,
            target_component=target_component,
            proposal_diff_sha256=diff_sha,
            vision_policy_id=self.policy.policy_id,
            policy_version=self.policy.policy_version,
            passed_preflight=passed,
            rejection_reasons=rejections,
            matched_principles=matched_principles,
            matched_non_goals=matched_non_goals,
            evaluated_at=time.time()
        )
        return ReceiptEnvelope.seal(receipt)
