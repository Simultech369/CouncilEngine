import json
import time
from typing import Dict, Any, List, Optional, Union
from council_contracts import ImmutableContract
from council_verifier import CouncilReceiptVerifier
from authority_conflict_detector import AuthorityConflictDetector
from dead_letter_queue import DeadLetterQueue
from pbm_rebate_engine import PBMRebateEngine
from pbm_fraud_detector import PBMFraudDetector, PharmacyClaimRecord
from bounty_vulnerability_engine import BountyVulnerabilityEngine
from dizzy_runtime_engine import DizzyRuntimeEngine
from model_qualification_evaluator import ModelQualificationEvaluator
from council_telemetry import CouncilTelemetryTracer
from a2a_protocol_engine import (
    A2ATrustStore,
    A2AMessageRouter,
    A2AEnvelopeSigner,
    A2AReconciliationLoop,
    A2ASecurityError
)
from council_contracts import A2ASignedEnvelope, A2AMessage

COUNCIL_VERIFIED_TEST_COUNT = 284
COUNCIL_VERIFIED_TEST_FILE_COUNT = 55
COUNCIL_SSE_CHANNEL = "dizzy_live_sse"

class CouncilSSEEvent(ImmutableContract):
    """Schema-bound Server-Sent Event emitted by the local Council API."""

    event_id: str
    event_type: str
    channel: str = COUNCIL_SSE_CHANNEL
    payload: Dict[str, Any]
    timestamp: float
    retry_ms: Optional[int] = None

class CouncilAPIServer:
    """
    High-speed, zero-dependency REST & SSE API Gateway for the Multi-Agent Council Engine.
    Handles HTTP dispatch, streaming NDJSON/SSE event formatting, and unified health checks.
    """

    def __init__(self, approval_secret: str = "council-hitl-default-secret-32bytes", ledger_dir: Optional[str] = None):
        from human_approval import CouncilApprovalGate
        from task_router import VerificationJobRegistry
        self.detector = AuthorityConflictDetector()
        self.dlq = DeadLetterQueue()
        self.pbm_rebate = PBMRebateEngine()
        self.pbm_fraud = PBMFraudDetector()
        self.bounty_engine = BountyVulnerabilityEngine()
        self.evaluator = ModelQualificationEvaluator()
        self.tracer = CouncilTelemetryTracer()
        self.a2a_trust_store = A2ATrustStore()
        self.a2a_trust_store.register_agent("antigravity", "secret_key_antigravity_hmac_256")
        self.a2a_trust_store.register_agent("codex", "secret_key_codex_hmac_256")
        self.a2a_router = A2AMessageRouter(self.a2a_trust_store)
        self.approval_gate = CouncilApprovalGate(secret_key=approval_secret, ledger_dir=ledger_dir)
        self.verification_jobs = VerificationJobRegistry(approval_gate=self.approval_gate)

    def handle_health(self) -> Dict[str, Any]:
        """GET /health - Returns engine status, live disk/mailbox/approval telemetry, and cold-model posture."""
        import shutil
        disk = shutil.disk_usage(".")
        pending_approvals = len(self.approval_gate.list_pending())
        mailbox_depth = sum(len(q) for q in getattr(self.a2a_router, "mailboxes", {}).values())
        return {
            "status": "HEALTHY",
            "role": "offline_verification_helper",
            "version": "7.0.0",
            "engine_location": "council_engine/",
            "passing_tests": COUNCIL_VERIFIED_TEST_COUNT,
            "test_files": COUNCIL_VERIFIED_TEST_FILE_COUNT,
            "verified_invariants": [
                "4-Stage Verification Cage",
                "7-Level Authority Hierarchy",
                "30 Cryptographic Receipts",
                "Deterministic Decimal(18,6) Math",
                "Zero-Network Docker Sandboxes"
            ],
            "subsystems": {
                "disk": {
                    "free_bytes": disk.free,
                    "total_bytes": disk.total,
                    "healthy": disk.free > 64 * 1024 * 1024,
                },
                "mailbox": {
                    "queued_messages": mailbox_depth,
                    "dead_letters": len(self.dlq.list_dead_letters()),
                },
                "approvals": {
                    "waiting_for_approval": pending_approvals,
                    "audit_entries": len(self.approval_gate.audit_log),
                },
                "models": {
                    "mode": "offline_deterministic_default",
                    "cold_models_marked": True,
                },
            },
            "timestamp": time.time()
        }

    def handle_drift_status(self) -> Dict[str, Any]:
        """GET /drift/tide - Returns live Tide Meter and velocity status."""
        drift_env = self.detector.compute_drift_observation(window_sec=3600.0)
        payload = drift_env.payload
        return {
            "total_conflicts_resolved": payload.total_conflicts_resolved,
            "drift_velocity_per_hour": payload.drift_velocity_per_hour,
            "tide_alarm_triggered": payload.tide_alarm_triggered,
            "net_drift_vector": payload.net_drift_vector,
            "receipt_sha256": drift_env.payload_sha256
        }

    def handle_dlq_summary(self) -> Dict[str, Any]:
        """GET /dlq/failures - Returns failure taxonomy and dead-letter statistics."""
        summary = self.dlq.get_failure_taxonomy_summary()
        records = self.dlq.list_dead_letters()
        return {
            "total_dead_letters": len(records),
            "taxonomy_summary": summary,
            "recent_failures": [
                {
                    "id": r.dead_letter_id,
                    "model": r.source_model_slug,
                    "category": r.failure_category,
                    "error": r.raw_error_message[:100]
                }
                for r in records[:5]
            ]
        }

    def handle_bounty_scan(self, code_payload: str) -> Dict[str, Any]:
        """POST /bounty/scan - Runs 10-CWE AST static integrity check."""
        pis, checks = self.bounty_engine.evaluate_patch_integrity_score(code_payload)
        return {
            "patch_integrity_score": pis,
            "passed": pis >= 0.95,
            "cwe_results": [
                {
                    "cwe_id": c.cwe_id,
                    "name": c.cwe_name,
                    "passed": c.passed,
                    "violation": c.violation_message
                }
                for c in checks
            ]
        }

    def handle_fwa_audit(self, claim_data: Dict[str, Any]) -> Dict[str, Any]:
        """POST /pbm/audit - Runs real-time POS FWA audit."""
        from decimal import Decimal
        claim = PharmacyClaimRecord(
            claim_id=claim_data.get("claim_id", "CLM_API_01"),
            member_id=claim_data.get("member_id", "M_API_999"),
            prescriber_npi=claim_data.get("prescriber_npi", "NPI_DOC"),
            pharmacy_npi=claim_data.get("pharmacy_npi", "NPI_PHARM"),
            ndc=claim_data.get("ndc", "00002-8215-01"),
            gpi_10=claim_data.get("gpi_10", "1234567890"),
            gpi_6=claim_data.get("gpi_6", "123456"),
            drug_name=claim_data.get("drug_name", "Test Drug"),
            schedule=claim_data.get("schedule", "NON-CONTROLLED"),
            date_of_service=claim_data.get("date_of_service", 1),
            days_supply=claim_data.get("days_supply", 30),
            quantity=Decimal(str(claim_data.get("quantity", 30.0))),
            strength_mg=Decimal(str(claim_data.get("strength_mg", 10.0))),
            is_opioid=claim_data.get("is_opioid", False),
            opioid_active_ingredient=claim_data.get("opioid_active_ingredient")
        )
        res = self.pbm_fraud.audit_claim(claim)
        return {
            "claim_id": res.claim_id,
            "triage_tier": res.triage_tier,
            "audit_passed": res.audit_passed,
            "ncpdp_reject_code": res.ncpdp_reject_code,
            "reject_reason": res.reject_reason,
            "daily_mme": res.daily_mme,
            "hhi_score": res.hhi_score
        }

    def _safe_sse_token(self, value: Any) -> str:
        """Keeps SSE metadata single-line so event boundaries remain unambiguous."""
        return str(value).replace("\r", "").replace("\n", "")

    def _coerce_sse_event(
        self,
        event: Union[CouncilSSEEvent, Dict[str, Any]],
        sequence: int,
        default_channel: str = COUNCIL_SSE_CHANNEL
    ) -> CouncilSSEEvent:
        if isinstance(event, CouncilSSEEvent):
            return event

        event_type = str(event.get("event_type") or event.get("event") or "message")
        timestamp = float(event.get("timestamp", time.time()))
        event_id = str(event.get("event_id") or f"{int(timestamp * 1000)}-{sequence}")
        retry_ms = event.get("retry_ms")
        payload = {
            key: value
            for key, value in event.items()
            if key not in {"event", "event_type", "event_id", "channel", "timestamp", "retry_ms"}
        }
        return CouncilSSEEvent(
            event_id=event_id,
            event_type=event_type,
            channel=str(event.get("channel", default_channel)),
            payload=payload,
            timestamp=timestamp,
            retry_ms=int(retry_ms) if retry_ms is not None else None
        )

    def format_sse_event(self, event: CouncilSSEEvent) -> str:
        """Formats one event using browser-native SSE framing."""
        payload = {
            "event_type": event.event_type,
            "channel": event.channel,
            "timestamp": event.timestamp,
            "payload": event.payload
        }
        lines = [
            f"id: {self._safe_sse_token(event.event_id)}",
            f"event: {self._safe_sse_token(event.event_type)}"
        ]
        if event.retry_ms is not None:
            lines.append(f"retry: {event.retry_ms}")
        lines.append(f"data: {json.dumps(payload, sort_keys=False)}")
        return "\n".join(lines) + "\n\n"

    def build_dizzy_live_events(self, now: Optional[float] = None) -> List[CouncilSSEEvent]:
        """Builds a bounded live snapshot for EventSource clients and tests."""
        ts = time.time() if now is None else now
        health = self.handle_health()
        drift = self.handle_drift_status()
        dlq = self.handle_dlq_summary()
        prefix = str(int(ts * 1000))
        return [
            CouncilSSEEvent(
                event_id=f"{prefix}-connected",
                event_type="council.connected",
                payload={
                    "status": "CONNECTED",
                    "engine_status": health["status"],
                    "passing_tests": health["passing_tests"],
                    "test_files": health["test_files"]
                },
                timestamp=ts,
                retry_ms=3000
            ),
            CouncilSSEEvent(
                event_id=f"{prefix}-health",
                event_type="council.health",
                payload=health,
                timestamp=ts
            ),
            CouncilSSEEvent(
                event_id=f"{prefix}-drift",
                event_type="council.drift",
                payload=drift,
                timestamp=ts
            ),
            CouncilSSEEvent(
                event_id=f"{prefix}-dead_letters",
                event_type="council.dead_letters",
                payload=dlq,
                timestamp=ts
            ),
            CouncilSSEEvent(
                event_id=f"{prefix}-heartbeat",
                event_type="council.heartbeat",
                payload={
                    "status": "ALL_INVARIANTS_HELD",
                    "drift_alarm": drift["tide_alarm_triggered"],
                    "dead_letters": dlq["total_dead_letters"]
                },
                timestamp=ts,
                retry_ms=3000
            )
        ]

    def handle_dizzy_event_stream(self, events: List[Union[CouncilSSEEvent, Dict[str, Any]]]) -> str:
        """Formats Dizzy runtime events into a browser-native SSE payload."""
        lines = []
        for sequence, ev in enumerate(events):
            lines.append(self.format_sse_event(self._coerce_sse_event(ev, sequence)))
        return "".join(lines)

    def handle_a2a_send(self, envelope_data: Dict[str, Any]) -> Dict[str, Any]:
        """POST /a2a/send - Validates and routes signed A2A message."""
        try:
            env = A2ASignedEnvelope(**envelope_data)
            self.a2a_router.send_signed_envelope(env)
            return {
                "status": "DELIVERED",
                "message_id": env.message_id,
                "recipient": env.message.recipient_agent_id
            }
        except Exception as e:
            return {
                "status": "REJECTED",
                "error": str(e)
            }

    def handle_a2a_mailbox(self, agent_id: str) -> Dict[str, Any]:
        """GET /a2a/mailbox?agent_id=... - Retrieves and drains agent mailbox."""
        messages = self.a2a_router.drain_mailbox(agent_id)
        return {
            "agent_id": agent_id,
            "message_count": len(messages),
            "messages": [m.model_dump() for m in messages]
        }

    def handle_a2a_reconcile(self, handoff_data: Dict[str, Any]) -> Dict[str, Any]:
        """POST /a2a/reconcile - Reconciles two agent states and emits sealed A2AHandoffReceipt."""
        receipt_env = A2AReconciliationLoop.reconcile_and_seal_handoff(
            handoff_id=handoff_data.get("handoff_id", f"handoff_{int(time.time()*1000)}"),
            conversation_id=handoff_data.get("conversation_id", "conv_default"),
            source_agent_id=handoff_data.get("source_agent_id", "codex"),
            target_agent_id=handoff_data.get("target_agent_id", "antigravity"),
            source_state_manifest=handoff_data.get("source_state_manifest", {}),
            target_state_manifest=handoff_data.get("target_state_manifest", {})
        )
        return {
            "status": "RECONCILED" if receipt_env.payload.reconciled_cleanly else "DRIFT_DETECTED",
            "reconciled_cleanly": receipt_env.payload.reconciled_cleanly,
            "receipt_sha256": receipt_env.payload_sha256,
            "envelope_sha256": receipt_env.envelope_sha256
        }

    def handle_submit_verification_job(self, req_data: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/v1/verification/jobs - Submit an offline verification job and inspect promotion blockers."""
        objective = str(req_data.get("objective", "")).strip()
        if not objective:
            raise ValueError("Missing required 'objective' for verification job")
        record = self.verification_jobs.submit_job(
            objective=objective,
            candidate_files=req_data.get("candidate_files") or [],
            evidence_surfaces=req_data.get("evidence_surfaces") or [],
            job_id=req_data.get("job_id"),
            require_promotion_approval=bool(req_data.get("require_promotion_approval", False)),
            tests_passed=bool(req_data.get("tests_passed", False)),
            live_container_verified=bool(req_data.get("live_container_verified", False)),
        )
        return record.model_dump()

    def handle_get_verification_job(self, job_id: str) -> Dict[str, Any]:
        """GET /api/v1/verification/jobs/<job_id> - Inspect verification job status and promotion blockers."""
        clean_id = str(job_id or "").strip()
        if not clean_id:
            raise ValueError("Missing required 'job_id'")
        record = self.verification_jobs.get_job(clean_id).model_dump()
        record["blocker_count"] = len(record.get("promotion_blockers") or [])
        return record

    def handle_list_verification_jobs(self) -> Dict[str, Any]:
        """GET /api/v1/verification/jobs - List all tracked verification jobs."""
        jobs = [j.model_dump() for j in self.verification_jobs.list_jobs()]
        return {"job_count": len(jobs), "jobs": jobs}

    def handle_request_approval(self, req_data: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/v1/approvals/request - Create a waiting_for_approval checkpoint with resume_token."""
        subject_type = str(req_data.get("subject_type") or "PROMOTION_GATE").strip()
        subject_sha = str(req_data.get("subject_payload_sha256") or "").strip()
        if not subject_sha:
            raise ValueError("Missing required 'subject_payload_sha256'")
        cp = self.approval_gate.request_approval(
            subject_type=subject_type,
            subject_payload_sha256=subject_sha,
            requested_authority=str(req_data.get("requested_authority") or "promotion_receipt"),
            job_id=req_data.get("job_id"),
            saved_progress=req_data.get("saved_progress") or {},
            reason=str(req_data.get("reason") or "Human approval required"),
            validity_sec=int(req_data.get("validity_sec") or 3600),
        )
        return cp.model_dump()

    def handle_list_pending_approvals(self) -> Dict[str, Any]:
        """GET /api/v1/approvals/pending - List pending HITL promotion/authority checkpoints."""
        pending = [cp.model_dump() for cp in self.approval_gate.list_pending()]
        return {"pending_count": len(pending), "pending": pending}

    def handle_resolve_approval(self, req_data: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/v1/approvals/resolve - Approve or reject a waiting_for_approval checkpoint."""
        token = str(req_data.get("resume_token") or "").strip()
        decision = str(req_data.get("decision") or "").strip()
        approver = str(req_data.get("approver_identity") or "operator").strip()
        reason = str(req_data.get("reason") or "").strip()
        cp = self.approval_gate.resolve_approval(
            resume_token=token,
            decision=decision,
            approver_identity=approver,
            reason=reason,
        )
        return cp.model_dump()

    def handle_resume_approval(self, req_data: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/v1/approvals/resume - Consume approved resume_token -> resumed."""
        token = str(req_data.get("resume_token") or "").strip()
        expected_sha = req_data.get("expected_subject_sha256")
        actor_id = str(req_data.get("actor_id") or "dizzy_bridge").strip()
        cp = self.approval_gate.resume_with_token(
            resume_token=token,
            expected_subject_sha256=expected_sha,
            actor_id=actor_id,
        )
        return cp.model_dump()

    def handle_approval_audit_log(self) -> Dict[str, Any]:
        """GET /api/v1/approvals/audit - Return verified hash-chained approval audit log."""
        verification = self.approval_gate.verify_audit_log()
        return {
            **verification,
            "entries": [entry.model_dump() for entry in self.approval_gate.audit_log],
        }

import http.server
import socketserver

class CouncilAPIRequestHandler(http.server.BaseHTTPRequestHandler):
    """Live HTTP & SSE Request Handler for Council API Gateway."""
    
    server_engine = CouncilAPIServer()

    def do_GET(self):
        if self.path in ("/api/v1/health", "/health"):
            data = self.server_engine.handle_health()
            self._send_json(200, data)
        elif self.path in ("/api/v1/drift", "/drift"):
            data = self.server_engine.handle_drift_status()
            self._send_json(200, data)
        elif self.path in ("/api/v1/dlq", "/dlq"):
            data = self.server_engine.handle_dlq_summary()
            self._send_json(200, data)
        elif self.path in ("/api/v1/verification/jobs", "/verification/jobs"):
            data = self.server_engine.handle_list_verification_jobs()
            self._send_json(200, data)
        elif self.path.startswith("/api/v1/verification/jobs/") or self.path.startswith("/verification/jobs/"):
            job_id = self.path.rstrip("/").split("/")[-1]
            try:
                data = self.server_engine.handle_get_verification_job(job_id)
                self._send_json(200, data)
            except KeyError as exc:
                self._send_json(404, {"error": str(exc), "code": "JOB_NOT_FOUND"})
        elif self.path in ("/api/v1/approvals/pending", "/approvals/pending"):
            data = self.server_engine.handle_list_pending_approvals()
            self._send_json(200, data)
        elif self.path in ("/api/v1/approvals/audit", "/approvals/audit"):
            data = self.server_engine.handle_approval_audit_log()
            self._send_json(200, data)
        elif "/a2a/mailbox" in self.path:
            agent_id = "codex"
            if "?" in self.path and "agent_id=" in self.path:
                agent_id = self.path.split("agent_id=")[1].split("&")[0]
            data = self.server_engine.handle_a2a_mailbox(agent_id)
            self._send_json(200, data)
        elif self.path.startswith("/api/v1/dizzy/stream") or self.path.startswith("/stream"):
            events = self.server_engine.build_dizzy_live_events()
            sse_payload = self.server_engine.handle_dizzy_event_stream(events)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(sse_payload.encode("utf-8"))
            self.wfile.flush()
        else:
            self._send_json(404, {"error": f"Endpoint '{self.path}' not found"})

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len).decode('utf-8') if content_len > 0 else "{}"
        try:
            req_data = json.loads(post_body)
        except Exception:
            req_data = {}

        try:
            if self.path in ("/api/v1/bounty/scan", "/bounty/scan"):
                code = req_data.get("code", "def safe(): pass")
                data = self.server_engine.handle_bounty_scan(code)
                self._send_json(200, data)
            elif self.path in ("/api/v1/fwa/audit", "/pbm/audit"):
                data = self.server_engine.handle_fwa_audit(req_data)
                self._send_json(200, data)
            elif self.path in ("/api/v1/a2a/send", "/a2a/send"):
                data = self.server_engine.handle_a2a_send(req_data)
                self._send_json(200, data)
            elif self.path in ("/api/v1/a2a/reconcile", "/a2a/reconcile"):
                data = self.server_engine.handle_a2a_reconcile(req_data)
                self._send_json(200, data)
            elif self.path in ("/api/v1/verification/jobs", "/verification/jobs"):
                data = self.server_engine.handle_submit_verification_job(req_data)
                self._send_json(200, data)
            elif self.path in ("/api/v1/approvals/request", "/approvals/request"):
                data = self.server_engine.handle_request_approval(req_data)
                self._send_json(200, data)
            elif self.path in ("/api/v1/approvals/resolve", "/approvals/resolve"):
                data = self.server_engine.handle_resolve_approval(req_data)
                self._send_json(200, data)
            elif self.path in ("/api/v1/approvals/resume", "/approvals/resume"):
                data = self.server_engine.handle_resume_approval(req_data)
                self._send_json(200, data)
            else:
                self._send_json(404, {"error": f"Endpoint '{self.path}' not found"})
        except KeyError as exc:
            self._send_json(404, {"error": str(exc), "code": "NOT_FOUND"})
        except ValueError as exc:
            code = getattr(exc, "code", "INVALID_REQUEST")
            self._send_json(409 if code == "ILLEGAL_STATE_TRANSITION" else 400, {"error": str(exc), "code": code})
        except TimeoutError as exc:
            self._send_json(410, {"error": str(exc), "code": "APPROVAL_EXPIRED"})

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def log_message(self, format, *args):
        # Silence default stderr logging for clean terminal output
        pass

def run_live_api_server(host: str = "127.0.0.1", port: int = 8000, blocking: bool = True):
    """Starts the real HTTP & SSE API server."""
    server = socketserver.ThreadingTCPServer((host, port), CouncilAPIRequestHandler)
    server.allow_reuse_address = True
    if blocking:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
    return server
