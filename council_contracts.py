import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Literal, Generic, TypeVar
from pydantic import BaseModel, ConfigDict, Field

CONTRACT_VERSION = "4.6.0"

class ImmutableContract(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    def compute_canonical_sha256(self) -> str:
        canonical_json = self.model_dump_json()
        payload = json.dumps(json.loads(canonical_json), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

T = TypeVar("T", bound=ImmutableContract)

class ReceiptEnvelope(ImmutableContract, Generic[T]):
    receipt_type: str
    contract_version: str = CONTRACT_VERSION
    payload_sha256: str
    envelope_sha256: str
    payload: T
    created_at: float = Field(default_factory=time.time)

    @classmethod
    def seal(cls, payload: T) -> "ReceiptEnvelope[T]":
        payload_digest = payload.compute_canonical_sha256()
        receipt_type = payload.__class__.__name__
        now = time.time()
        envelope_data = f"{CONTRACT_VERSION}:{receipt_type}:{payload_digest}:{now}"
        envelope_digest = hashlib.sha256(envelope_data.encode("utf-8")).hexdigest()
        return cls(
            receipt_type=receipt_type,
            contract_version=CONTRACT_VERSION,
            payload_sha256=payload_digest,
            envelope_sha256=envelope_digest,
            payload=payload,
            created_at=now
        )


# --- 1. Snapshot Receipt ---

class UntrackedBlobRecord(ImmutableContract):
    rel_path: str
    content_sha256: str
    size_bytes: int

class SnapshotReceipt(ImmutableContract):
    head_commit: str
    staged_diff_sha256: str
    unstaged_diff_sha256: str
    untracked_blobs: List[UntrackedBlobRecord]
    deleted_files: List[str]
    composite_state_sha256: str
    cas_storage_path: str


# --- 2. Packet Sensitivity Receipt ---

class ArtifactProvenanceRecord(ImmutableContract):
    artifact_id: str
    artifact_type: Literal["REPO_FILE", "ISSUE_TEXT", "TERMINAL_LOG", "STACK_TRACE", "USER_PROMPT", "FORMULARY_TABLE", "DOM_SCREENSHOT"]
    path_or_identifier: str
    content_sha256: str
    source_upstream_commit: Optional[str]
    source_upstream_url: Optional[str]
    provenance_verified: bool
    classification_reason: str

class PacketSensitivityReceipt(ImmutableContract):
    snapshot_composite_state_sha256: str
    sensitivity_tier: Literal["PUBLIC_SAFE", "INTERNAL_NO_TRAIN_OK", "ZDR_REQUIRED", "LOCAL_ONLY_REQUIRED"]
    public_safe_verified: bool
    private_artifact_count: int
    artifacts: List[ArtifactProvenanceRecord]


# --- 3. Evidence Selection & Citation Grounding Receipts (RAG Layer) ---

class EvidenceChunkRecord(ImmutableContract):
    chunk_id: str
    file_path: str
    start_line: int
    end_line: int
    content_sha256: str
    bi_encoder_score: float
    cross_encoder_rerank_score: float
    freshness_timestamp: float

class EvidenceSelectionReceipt(ImmutableContract):
    query_sha256: str
    packet_payload_sha256: str
    selected_chunks: List[EvidenceChunkRecord]
    missing_context_detected: bool
    missing_context_files: List[str]
    selection_timestamp: float

class CitationGroundingReceipt(ImmutableContract):
    evidence_selection_payload_sha256: str
    model_slug: str
    cited_line_numbers: List[int]
    grounding_verified: bool
    unverified_claims_count: int


# --- 4. Route Attestation Receipt ---

class RouteAttestationReceipt(ImmutableContract):
    route_id: str
    provider_name: str
    endpoint_url: str
    account_hash: str
    compliance_tier: Literal["LOCAL_ONLY_VERIFIED", "HOSTED_NO_TRAIN", "PUBLIC_PROVENANCE_ONLY", "APEX_PAID"]
    content_retention_days: int
    zdr_verified: bool
    fallbacks_allowed: bool
    issued_at: float
    expires_at: float


# --- 5. Provider Capability Record ---

class ProviderCapabilityRecord(ImmutableContract):
    provider_name: str
    model_slug: str
    supports_structured_json: bool
    supports_tools: bool
    supports_vision: bool
    max_context_window: int
    cost_per_million_input_usd: float
    cost_per_million_output_usd: float
    cost_tier: Literal["FREE_LOCAL", "FREE_CLOUD", "STANDARD_PAID", "APEX_PAID"]


# --- 6. Model Qualification Receipt ---

class ModelQualificationReceipt(ImmutableContract):
    composite_key: str
    model_slug: str
    model_family: str
    provider: str
    status: Literal["REVIEW_USABLE_FRESH", "REVIEW_USABLE_STALE", "QUARANTINED"]
    benign_control_passed: bool
    grounded_bug_passed: bool
    exact_line_quote_verified: bool
    json_schema_conformity: bool
    precision_score: Optional[float] = None
    recall_score: Optional[float] = None
    f1_score: Optional[float] = None
    evaluated_at: float
    expires_at: float


# --- 7. Paid Budget Reservation Receipt ---

class PaidBudgetReservationReceipt(ImmutableContract):
    model_slug: str
    max_input_tokens: int
    max_output_tokens: int
    reserved_cost_usd: float
    settled_cost_usd: Optional[float]
    authorized_reason_code: str
    allocated_at: float
    settled_at: Optional[float] = None


# --- 8. Model Invocation Receipt ---

class ModelInvocationReceipt(ImmutableContract):
    packet_payload_sha256: str
    route_attestation_payload_sha256: str
    qualification_payload_sha256: str
    paid_budget_payload_sha256: Optional[str]
    model_slug: str
    model_family: str
    provider: str
    route_id: str
    request_payload_sha256: str
    response_payload_sha256: str
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_ms: Optional[float] = None
    completed_at: float

class QualificationProbeInvocationReceipt(ImmutableContract):
    route_attestation_payload_sha256: str
    model_slug: str
    model_family: str
    provider: str
    route_id: str
    request_payload_sha256: str
    response_payload_sha256: str
    is_qualification_probe: bool = True
    completed_at: float


# --- 9. Council Roster Receipt ---

class CouncilRosterReceipt(ImmutableContract):
    packet_payload_sha256: str
    patch_payload_sha256: str
    frozen_voter_slugs: List[str]
    frozen_model_families: List[str]
    frozen_quorum_size: int
    created_at: float = Field(default_factory=time.time)


# --- 10. Council Vote Receipt ---

class RedactedVoteRecord(ImmutableContract):
    voter_slug: str
    model_family: str
    provider: str
    invocation_payload_sha256: str
    decision: Literal["approve", "reject", "abstain"]
    confidence: float
    calibrated_weight: float = 1.0
    reasoning_sha256: str
    redacted_summary: str

class CouncilVoteReceipt(ImmutableContract):
    roster_payload_sha256: str
    patch_payload_sha256: str
    sandbox_payload_sha256: str
    quorum_size: int
    approvals_count: int
    rejections_count: int
    supermajority_achieved: bool
    critical_finding_veto: bool
    final_verdict: Literal["APPROVED", "REJECTED", "ESCALATE_TO_APEX"]
    votes: List[RedactedVoteRecord]


# --- 11. Patch Receipt ---

class PatchReceipt(ImmutableContract):
    parent_snapshot_sha256: str
    patch_sha256: str
    target_files_touched: List[str]
    hunks_count: int
    sanitization_passed: bool


# --- 12. Execution Sandbox Receipt ---

class ExecutionSandboxReceipt(ImmutableContract):
    patch_payload_sha256: str
    snapshot_composite_state_sha256: str
    isolation_mode: Literal["LOCAL_SUBPROCESS_MOCK", "DOCKER_CONTAINER_ENFORCED"]
    container_engine: Literal["docker", "podman", "local_subprocess", "docker_mock"]
    execution_mode: Literal["LIVE", "SIMULATED"] = "LIVE"
    container_image_digest: Optional[str] = None
    network_isolated: bool
    test_command: List[str]
    test_exit_code: int
    test_passed: bool
    stdout_sha256: str
    stderr_sha256: str
    duration_sec: float


# --- 12b. Review-Hop Trace Receipts ---

class ReviewHopCommandRecord(ImmutableContract):
    command_argv: List[str]
    command_sha256: str
    executed: bool
    exit_code: Optional[int] = None
    stdout_sha256: Optional[str] = None
    stderr_sha256: Optional[str] = None
    duration_sec: Optional[float] = None


class ReviewHopTraceReceipt(ImmutableContract):
    trace_id: str
    hop_id: str
    source_agent_id: str
    target_agent_id: str
    hop_kind: Literal["A2A_HANDOFF", "REVIEW_DISPOSITION", "LOCAL_GATE", "ATTESTATION_QUERY"]
    git_head_commit: str
    git_branch: str
    git_observation_status: Literal["OBSERVED", "UNAVAILABLE"]
    working_tree_dirty: bool
    dirty_files: List[str]
    reviewed_content_sha256: str
    toolchain_manifest_sha256: str
    input_payload_sha256: str
    output_payload_sha256: str
    command_manifest_sha256: str
    commands: List[ReviewHopCommandRecord]
    isolation_mode: Literal["READ_ONLY_NO_EXECUTION", "LOCAL_SUBPROCESS_MOCK", "DOCKER_CONTAINER_ENFORCED"]
    network_isolated: bool
    execution_environment_hash_sha256: str
    provenance_only: Literal[True] = True
    remote_execution_permitted: Literal[False] = False
    production_execution_claimed: Literal[False] = False
    audit_replacement_claimed: Literal[False] = False
    proof_boundary: str
    traced_at: float = Field(default_factory=time.time)


# --- 13. External Human Approval & Apply Authorization Receipts ---

class HumanApprovalReceipt(ImmutableContract):
    subject_type: Literal["PATCH_APPLY", "VISION_POLICY", "PAID_SPEND_OVERRIDE", "EMERGENCY_HALT"]
    subject_payload_sha256: str
    approver_identity: str
    approver_key_id: str
    signature_algorithm: Literal["ED25519", "ECDSA_P256", "HMAC_SHA256"]
    detached_signature: str
    issued_at: float
    expires_at: float

class ApplyAuthorizationReceipt(ImmutableContract):
    authorized_patch_sha256: str
    target_composite_state_sha256: str
    council_vote_payload_sha256: str
    auth_mode: Literal["SIMULATED_TEST_SIGNATURE", "INTERACTIVE_HUMAN_PROMPT"]
    human_approval_payload_sha256: str


# --- 14. Anomaly Detection & Authority Drift Receipts ---

class AnomalyDetectionReceipt(ImmutableContract):
    claimed_anomaly: bool
    anomaly_type: Optional[Literal[
        "PROMPT_INJECTION",
        "AUTHORITY_SHIFT_FORGERY",
        "STALE_MEMORY_CONTRADICTION",
        "ROUTE_PRIVACY_MISMATCH",
        "RECEIPT_DIGEST_CORRUPTION",
        "EVIDENCE_FABRICATION"
    ]] = None
    evidence_payload_sha256: Optional[str] = None
    quoted_evidence_snippet: Optional[str] = None
    anomaly_line_number: Optional[int] = None
    confidence: float
    verified_by_deterministic_checker: bool
    escalation_required: bool

class AuthorityOverrideRecord(ImmutableContract):
    conflict_id: str
    winning_rank: int          # 1=AST/Contract, 2=Execution/Math, 3=Human, 4=Tool, 5=Memory, 6=Summary, 7=Opinion
    losing_rank: int
    overridden_claim_sha256: str
    resolution_rationale: str
    drift_category: Literal[
        "SECURITY_RELAXATION_PRESSURE",
        "STALE_MEMORY_PURGE",
        "OPERATOR_POLICY_OVERRIDE",
        "PROMPT_INJECTION_REPELLED"
    ]
    timestamp: float

class DriftObservationReceipt(ImmutableContract):
    observation_window_sec: float
    total_conflicts_resolved: int
    net_drift_vector: Dict[str, float]
    drift_velocity_per_hour: float
    tide_alarm_triggered: bool


# --- 15. Dead Letter & Memory Snapshot Records ---

class DeadLetterRecord(ImmutableContract):
    dead_letter_id: str
    source_model_slug: str
    failure_category: Literal[
        "SCHEMA_VIOLATION",
        "TIMEOUT",
        "PROMPT_INJECTION_DETECTED",
        "SANDBOX_NONZERO_EXIT",
        "ROUTE_DENIED",
        "BUDGET_EXCEEDED"
    ]
    raw_prompt_sha256: str
    raw_error_message: str
    raw_response_snippet: Optional[str]
    retry_count: int
    quarantined_at: float

class MemorySnapshotReceipt(ImmutableContract):
    memory_snapshot_id: str
    parent_memory_shas: List[str]
    retained_facts_count: int
    expired_facts_count: int
    privacy_tier: Literal["PUBLIC_SAFE", "LOCAL_ONLY_REQUIRED"]
    snapshot_timestamp: float


# --- 16. Log Reconstruction & Round Handoff Receipts ---

class LogReconstructionReceipt(ImmutableContract):
    session_id: str
    event_log_length: int
    derived_messages_count: int
    derived_context_sha256: str
    request_context_sha256: str
    desync_detected: bool
    desync_field_mismatches: List[str]
    verified_at: float

class RoundHandoffReceipt(ImmutableContract):
    round_index: int
    objective_id: str
    status: Literal["IN_PROGRESS", "BLOCKED", "COMPLETED", "RETRY_REQUIRED"]
    summary: str
    evidence_uris: List[str]
    next_steps: List[str]
    blocker_description: Optional[str] = None
    transcript_discarded_turns: int
    workspace_state_sha256: str
    handoff_timestamp: float


# --- 17. Vision Acceptance Policy & Gate 0 Preflight Receipts ---

class VisionPolicyReceipt(ImmutableContract):
    policy_id: str
    policy_version: str
    human_approved: bool = False
    author_signature: Optional[str] = None
    mined_evidence_sources: List[str]
    total_principles_mined: int
    total_non_goals_mined: int
    fault_line_hypotheticals_count: int
    draft_content_sha256: str
    created_at: float

class Gate0PreflightReceipt(ImmutableContract):
    proposal_id: str
    target_component: str
    proposal_diff_sha256: str
    vision_policy_id: str
    policy_version: str
    passed_preflight: bool
    rejection_reasons: List[str]
    matched_principles: List[str]
    matched_non_goals: List[str]
    evaluated_at: float


# --- 18. Web & Document Evidence Acquisition Receipts ---

class DocumentConversionReceipt(ImmutableContract):
    source_file_path: str
    source_mime_type: str
    source_file_sha256: str
    converter_engine: Literal["MARKITDOWN_LOCAL", "STRUCTURED_PARSER", "PURE_TEXT_FALLBACK"]
    extracted_markdown_sha256: str
    extracted_char_count: int
    extracted_headings_count: int
    extracted_tables_count: int
    conversion_timestamp: float

class WebEvidenceReceipt(ImmutableContract):
    source_url: str
    final_url: str
    fetch_mode: Literal["LOCAL_HTTP", "CRAWL4AI_DOM", "FIRECRAWL_API", "PROXIED_SCRAPLING"]
    http_status: int
    raw_content_sha256: str
    markdown_sha256: str
    screenshot_sha256: Optional[str] = None
    is_truncated: bool
    total_raw_bytes: int
    cas_artifact_path: str
    privacy_tier: Literal["PUBLIC_SAFE", "INTERNAL_NO_TRAIN_OK", "LOCAL_ONLY_REQUIRED"]
    fetched_at: float


# --- 19. Deterministic Lifecycle Hook Receipts ---

class LifecycleHookReceipt(ImmutableContract):
    session_id: str
    actor_id: str
    phase: Literal["SESSION_START", "PRE_TOOL_USE", "POST_TOOL_USE", "STOP", "SUBAGENT_STOP"]
    operation: str
    canonical_arguments_sha256: str
    decision: Literal["ALLOWED", "DENIED", "TAINTED"]
    linked_pre_hook_sha256: Optional[str] = None
    outcome_effect_sha256: Optional[str] = None
    related_handoff_sha256: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)


# --- 20. Signed Webhook Fan-Out Receipts ---

class WebhookDispatchReceipt(ImmutableContract):
    event_id: str
    event_type: str
    endpoint_name: str
    target_url_sha256: str
    payload_sha256: str
    source_receipt_sha256: Optional[str] = None
    signature_header_name: str
    signature_sha256: str
    idempotency_key: str
    attempt_count: int
    delivered: bool
    http_status_code: Optional[int] = None
    error_message: Optional[str] = None
    next_retry_at: Optional[float] = None
    dispatched_at: float = Field(default_factory=time.time)


# --- 21. Prompt & Config Registry Receipts ---

class PromptConfigRegistryReceipt(ImmutableContract):
    registry_id: str
    active_prompt_id: str
    active_version: str
    active_system_prompt_sha256: str
    active_config_sha256: str
    version_manifest_sha256: str
    version_count: int
    prompt_ids: List[str]
    exported_at: float = Field(default_factory=time.time)


# --- 22. Red Team Adversarial Campaign Receipts ---

class RedTeamCampaignReceipt(ImmutableContract):
    campaign_id: str
    target_component: str
    scout_model_slug: str
    total_probes_generated: int
    total_blocked: int
    attack_success_rate_pct: float
    immunity_score_pct: float
    gate4_passed: bool
    findings_manifest_sha256: str
    evaluated_at: float = Field(default_factory=time.time)


# --- 23. Agent-to-Agent (A2A) Protocol & Handoff Receipts ---

class A2AMessage(ImmutableContract):
    message_id: str
    conversation_id: str
    sender_agent_id: str
    recipient_agent_id: str
    intent: Literal["TASK_PROPOSAL", "CRITIQUE", "REVISION", "CONSENSUS_VOTE", "EVIDENCE_SHARE", "HANDOFF"]
    payload_data: Dict[str, Any]
    context_snapshot_sha256: str
    nonce: str
    timestamp: float = Field(default_factory=time.time)

class A2ASignedEnvelope(ImmutableContract):
    envelope_type: str = "A2A_SIGNED_MESSAGE"
    message_id: str
    sender_agent_id: str
    signature_algorithm: str = "ED25519"
    signed_payload_sha256: str
    detached_signature: str
    message: A2AMessage
    created_at: float = Field(default_factory=time.time)

class A2AHandoffReceipt(ImmutableContract):
    handoff_id: str
    conversation_id: str
    source_agent_id: str
    target_agent_id: str
    before_state_sha256: str
    after_state_sha256: str
    tasks_transferred_count: int
    delta_manifest_sha256: str
    reconciled_cleanly: bool
    handed_off_at: float = Field(default_factory=time.time)

class A2AConsensusReceipt(ImmutableContract):
    session_id: str
    topic_or_task: str
    participating_agents: List[str]
    rounds_count: int
    consensus_decision: Literal["AGREED", "DISSENT_VETOED", "DEADLOCKED"]
    final_verdict_sha256: str
    dissenting_agent_id: Optional[str] = None
    decided_at: float = Field(default_factory=time.time)


# --- 24. OSS Model / Harness Subcommittee Convocation Receipts ---

class SubcommitteeEvaluationRecord(ImmutableContract):
    subcommittee_name: str
    assigned_model_slug: str
    evidence_surface_reviewed: str
    verdict: Literal["APPROVE", "REJECT", "NEEDS_REVISION"]
    confidence_score: float
    invariants_checked: List[str]
    findings_summary: str

class SubcommitteeConvocationReceipt(ImmutableContract):
    convocation_id: str
    task_id: str
    subcommittees_convened: List[str]
    rotation_round: int
    overall_verdict: Literal["UNANIMOUS_APPROVAL", "MAJORITY_APPROVAL", "VETOED", "DEADLOCKED"]
    guardrails_held: bool
    evaluations: List[SubcommitteeEvaluationRecord]
    composite_audit_digest_sha256: str
    convened_at: float = Field(default_factory=time.time)


# --- 25. Autonomous Patch Synthesis & Dual-Gate Pipeline Receipts ---

class AutonomousPatchSynthesisReceipt(ImmutableContract):
    pipeline_run_id: str
    vulnerability_cwe_id: str
    target_component: str
    synthesis_model_slug: str
    patch_integrity_score: float
    gate1_ast_passed: bool
    gate2_sandbox_passed: bool
    subcommittee_convocation_sha256: str
    self_healing_iterations: int
    final_patch_sha256: str
    completed_at: float = Field(default_factory=time.time)


# --- 26. Dual-Agent Handoff Bundle & Return Manifest Receipts ---

class HandoffBundleRecord(ImmutableContract):
    bundle_id: str
    source_lead_agent: str
    target_review_agent: str
    baseline_test_count: int
    baseline_test_suite_count: int
    non_test_file_count: int
    delta_files_created: List[str]
    delta_files_modified: List[str]
    rule_invariants_count: int
    contract_version: str = CONTRACT_VERSION
    return_prompt_sha256: str
    bundle_sha256: str
    packaged_at: float = Field(default_factory=time.time)

class HandoffBundleReceipt(ImmutableContract):
    bundle_id: str
    manifest: HandoffBundleRecord
    receipt_chain_tail_sha256: str
    reconciliation_clean: bool
    sealed_at: float = Field(default_factory=time.time)


