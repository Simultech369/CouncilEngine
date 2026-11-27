import hashlib
import hmac
import time
import base64
import binascii
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from council_contracts import HumanApprovalReceipt, ReceiptEnvelope

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except Exception:  # pragma: no cover - exercised only when PyNaCl is absent
    BadSignatureError = None
    SigningKey = None
    VerifyKey = None

class ApprovalAuthenticator(ABC):
    @abstractmethod
    def authenticate_approval(self, approval_env: ReceiptEnvelope[HumanApprovalReceipt], expected_subject_sha256: str) -> bool:
        """Authenticates signature, key identity, subject binding, and validity window."""
        pass

class DenyAllApprovalAuthenticator(ApprovalAuthenticator):
    """Default fail-closed authenticator when no trusted human key store is configured."""
    def authenticate_approval(self, approval_env: ReceiptEnvelope[HumanApprovalReceipt], expected_subject_sha256: str) -> bool:
        return False

def _approval_payload_data(receipt: HumanApprovalReceipt) -> str:
    return (
        f"{receipt.subject_type}:{receipt.subject_payload_sha256}:"
        f"{receipt.approver_identity}:{receipt.approver_key_id}:"
        f"{receipt.issued_at}:{receipt.expires_at}"
    )

def _decode_key_material(key_material: str) -> bytes:
    cleaned = key_material.strip()
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        pass

    try:
        return base64.b64decode(cleaned.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        pass

    return cleaned.encode("utf-8")

def _require_pynacl() -> None:
    if SigningKey is None or VerifyKey is None:
        raise RuntimeError("PyNaCl is required for Ed25519 approval signatures")

class HMACApprovalAuthenticator(ApprovalAuthenticator):
    """
    Cryptographic HMAC-SHA256 human approval authenticator for production/test trust stores.
    Verifies detached signature against registered approver keys.
    """
    def __init__(self, key_store: Optional[Dict[str, str]] = None):
        self.key_store = key_store or {}

    def register_key(self, key_id: str, secret_key: str):
        self.key_store[key_id] = secret_key

    def authenticate_approval(self, approval_env: ReceiptEnvelope[HumanApprovalReceipt], expected_subject_sha256: str) -> bool:
        receipt = approval_env.payload
        now = time.time()

        # 1. Check algorithm binding
        if receipt.signature_algorithm != "HMAC_SHA256":
            return False

        # 2. Check validity window
        if not (receipt.issued_at <= now <= receipt.expires_at):
            return False

        # 3. Check subject binding
        if receipt.subject_payload_sha256 != expected_subject_sha256:
            return False

        # 4. Check key existence
        secret = self.key_store.get(receipt.approver_key_id)
        if not secret:
            return False

        # 5. Verify signature
        payload_data = _approval_payload_data(receipt)
        expected_sig = hmac.new(secret.encode("utf-8"), payload_data.encode("utf-8"), hashlib.sha256).hexdigest()
        
        return hmac.compare_digest(receipt.detached_signature, expected_sig)

    @classmethod
    def create_signed_approval(
        cls,
        subject_type: str,
        subject_payload_sha256: str,
        approver_identity: str,
        approver_key_id: str,
        secret_key: str,
        validity_sec: int = 3600
    ) -> ReceiptEnvelope[HumanApprovalReceipt]:
        """Utility for authorized operators/tests to produce a valid signed HumanApprovalReceipt."""
        now = time.time()
        expires = now + validity_sec
        receipt_for_signing = HumanApprovalReceipt(
            subject_type=subject_type,
            subject_payload_sha256=subject_payload_sha256,
            approver_identity=approver_identity,
            approver_key_id=approver_key_id,
            signature_algorithm="HMAC_SHA256",
            detached_signature="",
            issued_at=now,
            expires_at=expires
        )
        payload_data = _approval_payload_data(receipt_for_signing)
        sig = hmac.new(secret_key.encode("utf-8"), payload_data.encode("utf-8"), hashlib.sha256).hexdigest()

        receipt = receipt_for_signing.model_copy(update={"detached_signature": sig})
        return ReceiptEnvelope.seal(receipt)

class Ed25519ApprovalAuthenticator(ApprovalAuthenticator):
    """
    Ed25519 detached-signature authenticator backed by a public-key trust store.
    Private signing keys are only used by create_signed_approval for tests/operator tooling.
    """
    def __init__(self, public_key_store: Optional[Dict[str, str]] = None):
        self.public_key_store = public_key_store or {}

    def register_public_key(self, key_id: str, public_key: str):
        self.public_key_store[key_id] = public_key

    def authenticate_approval(self, approval_env: ReceiptEnvelope[HumanApprovalReceipt], expected_subject_sha256: str) -> bool:
        _require_pynacl()
        receipt = approval_env.payload
        now = time.time()

        if receipt.signature_algorithm != "ED25519":
            return False

        if not (receipt.issued_at <= now <= receipt.expires_at):
            return False

        if receipt.subject_payload_sha256 != expected_subject_sha256:
            return False

        public_key = self.public_key_store.get(receipt.approver_key_id)
        if not public_key:
            return False

        try:
            verify_key_bytes = _decode_key_material(public_key)
            signature_bytes = bytes.fromhex(receipt.detached_signature)
            VerifyKey(verify_key_bytes).verify(_approval_payload_data(receipt).encode("utf-8"), signature_bytes)
            return True
        except (BadSignatureError, ValueError, binascii.Error):
            return False

    @staticmethod
    def derive_public_key(private_key: str) -> str:
        _require_pynacl()
        private_bytes = _decode_key_material(private_key)
        if len(private_bytes) == 64:
            private_bytes = private_bytes[:32]
        return SigningKey(private_bytes).verify_key.encode().hex()

    @classmethod
    def create_signed_approval(
        cls,
        subject_type: str,
        subject_payload_sha256: str,
        approver_identity: str,
        approver_key_id: str,
        private_key: str,
        validity_sec: int = 3600
    ) -> ReceiptEnvelope[HumanApprovalReceipt]:
        """Utility for authorized operators/tests to produce an Ed25519 HumanApprovalReceipt."""
        _require_pynacl()
        now = time.time()
        expires = now + validity_sec
        receipt_for_signing = HumanApprovalReceipt(
            subject_type=subject_type,
            subject_payload_sha256=subject_payload_sha256,
            approver_identity=approver_identity,
            approver_key_id=approver_key_id,
            signature_algorithm="ED25519",
            detached_signature="",
            issued_at=now,
            expires_at=expires
        )
        private_bytes = _decode_key_material(private_key)
        if len(private_bytes) == 64:
            private_bytes = private_bytes[:32]
        signature = SigningKey(private_bytes).sign(_approval_payload_data(receipt_for_signing).encode("utf-8")).signature.hex()
        receipt = receipt_for_signing.model_copy(update={"detached_signature": signature})
        return ReceiptEnvelope.seal(receipt)

import subprocess
import tempfile
import os

class SSHApprovalAuthenticator(ApprovalAuthenticator):
    """
    SSH approval authenticator leveraging standard library/system openSSH (ssh-keygen -Y).
    Requires no heavy C-compiled dependencies like cryptography.
    """
    def __init__(self, allowed_signers_file: Optional[str] = None):
        if allowed_signers_file is None:
            allowed_signers_file = os.path.expanduser("~/.ssh/council_allowed_signers")
        self.allowed_signers_file = allowed_signers_file

    def authenticate_approval(self, approval_env: ReceiptEnvelope[HumanApprovalReceipt], expected_subject_sha256: str) -> bool:
        receipt = approval_env.payload
        now = time.time()

        if receipt.signature_algorithm != "SSH":
            return False

        if not (receipt.issued_at <= now <= receipt.expires_at):
            return False

        if receipt.subject_payload_sha256 != expected_subject_sha256:
            return False

        if not os.path.isfile(self.allowed_signers_file):
            return False

        payload_data = _approval_payload_data(receipt).encode("utf-8")

        with tempfile.NamedTemporaryFile(delete=False) as data_file, \
             tempfile.NamedTemporaryFile(delete=False) as sig_file:
            data_file.write(payload_data)
            data_file.flush()
            
            sig_file.write(receipt.detached_signature.encode("utf-8"))
            sig_file.flush()

            data_path = data_file.name
            sig_path = sig_file.name

        try:
            with open(data_path, 'rb') as stdin_file:
                proc = subprocess.run(
                    [
                        "ssh-keygen", "-Y", "verify",
                        "-f", self.allowed_signers_file,
                        "-I", receipt.approver_identity,
                        "-n", "council",
                        "-s", sig_path
                    ],
                    stdin=stdin_file,
                    capture_output=True,
                    text=True
                )
            return proc.returncode == 0
        finally:
            if os.path.exists(data_path):
                os.remove(data_path)
            if os.path.exists(sig_path):
                os.remove(sig_path)

    @classmethod
    def create_signed_approval(
        cls,
        subject_type: str,
        subject_payload_sha256: str,
        approver_identity: str,
        approver_key_id: str,
        private_key_path: str,
        validity_sec: int = 3600
    ) -> ReceiptEnvelope[HumanApprovalReceipt]:
        now = time.time()
        expires = now + validity_sec
        receipt_for_signing = HumanApprovalReceipt(
            subject_type=subject_type,
            subject_payload_sha256=subject_payload_sha256,
            approver_identity=approver_identity,
            approver_key_id=approver_key_id,
            signature_algorithm="SSH",
            detached_signature="",
            issued_at=now,
            expires_at=expires
        )
        payload_data = _approval_payload_data(receipt_for_signing).encode("utf-8")

        with tempfile.NamedTemporaryFile(delete=False) as data_file:
            data_file.write(payload_data)
            data_file.flush()
            data_path = data_file.name

        try:
            proc = subprocess.run(
                [
                    "ssh-keygen", "-Y", "sign",
                    "-f", private_key_path,
                    "-n", "council",
                    data_path
                ],
                capture_output=True,
                text=True
            )
            if proc.returncode != 0:
                raise RuntimeError(f"Failed to sign: {proc.stderr}")

            with open(data_path + ".sig", "r", encoding="utf-8") as f:
                sig = f.read()
            os.remove(data_path + ".sig")

            receipt = receipt_for_signing.model_copy(update={"detached_signature": sig})
            return ReceiptEnvelope.seal(receipt)
        finally:
            if os.path.exists(data_path):
                os.remove(data_path)

class CompositeApprovalAuthenticator(ApprovalAuthenticator):
    """
    Algorithm-pinned authenticator registry for deployments carrying multiple human key types.
    """
    def __init__(self, authenticators: Optional[Dict[str, ApprovalAuthenticator]] = None):
        self.authenticators = authenticators or {}

    def register_authenticator(self, signature_algorithm: str, authenticator: ApprovalAuthenticator) -> None:
        self.authenticators[signature_algorithm] = authenticator

    def authenticate_approval(self, approval_env: ReceiptEnvelope[HumanApprovalReceipt], expected_subject_sha256: str) -> bool:
        authenticator = self.authenticators.get(approval_env.payload.signature_algorithm)
        if authenticator is None:
            return False
        return authenticator.authenticate_approval(approval_env, expected_subject_sha256)


import json
from pathlib import Path
from typing import List, Literal, Tuple
from council_contracts import ImmutableContract

ApprovalWorkflowState = Literal[
    "running",
    "waiting_for_approval",
    "approved",
    "rejected",
    "resumed",
    "cancelled",
]

HUMAN_APPROVAL_STATES: Tuple[ApprovalWorkflowState, ...] = (
    "running",
    "waiting_for_approval",
    "approved",
    "rejected",
    "resumed",
    "cancelled",
)

HUMAN_APPROVAL_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    "running": ("waiting_for_approval", "cancelled"),
    "waiting_for_approval": ("approved", "rejected", "cancelled"),
    "approved": ("resumed", "cancelled"),
    "rejected": ("cancelled",),
    "resumed": (),
    "cancelled": (),
}

GENESIS_AUDIT_PREV_HASH = "0" * 64


class IllegalApprovalTransitionError(ValueError):
    """Raised when an approval or run attempts an illegal state jump."""

    def __init__(self, from_state: str, to_state: str, allowed_next: Tuple[str, ...]):
        self.code = "ILLEGAL_STATE_TRANSITION"
        self.from_state = from_state
        self.to_state = to_state
        self.allowed_next = list(allowed_next)
        super().__init__(
            f"Illegal human_approval state transition '{from_state}' -> '{to_state}'. "
            f"Allowed next states: {list(allowed_next)}"
        )


def validate_approval_transition(from_state: str, to_state: str) -> Tuple[str, ...]:
    if from_state not in HUMAN_APPROVAL_TRANSITIONS:
        raise IllegalApprovalTransitionError(from_state, to_state, ())
    allowed = HUMAN_APPROVAL_TRANSITIONS[from_state]
    if to_state not in allowed:
        raise IllegalApprovalTransitionError(from_state, to_state, allowed)
    return HUMAN_APPROVAL_TRANSITIONS[to_state]


class CouncilApprovalAuditRecord(ImmutableContract):
    schema_version: str = "council.hitl_audit_entry.v1"
    timestamp: float
    event_type: str
    checkpoint_id: str
    workflow_state: ApprovalWorkflowState
    actor_id: str
    subject_payload_sha256: str
    reason: str
    prev_hash: str
    entry_hash: str


class CouncilApprovalCheckpoint(ImmutableContract):
    schema_version: str = "council.hitl_checkpoint.v1"
    checkpoint_id: str
    job_id: Optional[str] = None
    subject_type: str
    subject_payload_sha256: str
    requested_authority: str
    workflow_state: ApprovalWorkflowState
    allowed_next_states: List[str]
    resume_token: str
    saved_progress: Dict[str, Any]
    created_at: float
    expires_at: float
    resolved_at: Optional[float] = None
    resumed_at: Optional[float] = None
    approver_identity: Optional[str] = None
    decision_reason: Optional[str] = None
    audit_entry_hash: str


class CouncilApprovalGate:
    """
    Stateful human-approval gate for offline CouncilEngine promotion and authority upgrades.
    Shares the exact state vocabulary with Dizzy (`lib/hitl_approval_gateway.mjs`):
      running -> waiting_for_approval -> approved | rejected -> resumed | cancelled
    """

    def __init__(
        self,
        secret_key: str = "council-hitl-default-secret-32bytes",
        ledger_dir: Optional[str] = None,
    ):
        self.secret_key = secret_key
        self.ledger_dir = Path(ledger_dir) if ledger_dir else None
        self.checkpoints: Dict[str, Dict[str, Any]] = {}
        self.audit_log: List[CouncilApprovalAuditRecord] = []
        self.last_audit_hash = GENESIS_AUDIT_PREV_HASH
        if self.ledger_dir is not None:
            self.ledger_dir.mkdir(parents=True, exist_ok=True)
            self._load_persisted_state()

    def _load_persisted_state(self) -> None:
        if self.ledger_dir is None:
            return
        cp_file = self.ledger_dir / "checkpoints.jsonl"
        audit_file = self.ledger_dir / "audit_log.jsonl"
        if cp_file.is_file():
            for line in cp_file.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    item = json.loads(line)
                    self.checkpoints[item["checkpoint_id"]] = item
        if audit_file.is_file():
            for line in audit_file.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = CouncilApprovalAuditRecord(**json.loads(line))
                    self.audit_log.append(rec)
                    self.last_audit_hash = rec.entry_hash

    def _persist_checkpoint(self, cp: Dict[str, Any]) -> None:
        self.checkpoints[cp["checkpoint_id"]] = cp
        if self.ledger_dir is not None:
            with open(self.ledger_dir / "checkpoints.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(cp, sort_keys=True) + "\n")

    def _append_audit(
        self,
        *,
        event_type: str,
        checkpoint_id: str,
        workflow_state: ApprovalWorkflowState,
        actor_id: str,
        subject_payload_sha256: str,
        reason: str,
        now: float,
    ) -> CouncilApprovalAuditRecord:
        core = {
            "schema_version": "council.hitl_audit_entry.v1",
            "timestamp": now,
            "event_type": event_type,
            "checkpoint_id": checkpoint_id,
            "workflow_state": workflow_state,
            "actor_id": actor_id,
            "subject_payload_sha256": subject_payload_sha256,
            "reason": reason,
            "prev_hash": self.last_audit_hash,
        }
        canonical = json.dumps(core, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        record = CouncilApprovalAuditRecord(**core, entry_hash=entry_hash)
        self.audit_log.append(record)
        self.last_audit_hash = entry_hash
        if self.ledger_dir is not None:
            with open(self.ledger_dir / "audit_log.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record.model_dump(), sort_keys=True) + "\n")
        return record

    def _compute_token(self, checkpoint_id: str, subject_type: str, subject_sha: str, expires_at: float) -> str:
        msg = f"{checkpoint_id}:{subject_type}:{subject_sha}:{expires_at:.6f}"
        digest = hmac.new(self.secret_key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        return f"hitl_tok_{digest}"

    def _find_by_token(self, resume_token: str) -> Optional[Dict[str, Any]]:
        for cp in self.checkpoints.values():
            if hmac.compare_digest(cp["resume_token"], resume_token):
                return cp
        return None

    def start_run(
        self,
        *,
        subject_type: str,
        subject_payload_sha256: str,
        requested_authority: str = "promotion_receipt",
        job_id: Optional[str] = None,
        saved_progress: Optional[Dict[str, Any]] = None,
        validity_sec: int = 3600,
        now: Optional[float] = None,
    ) -> CouncilApprovalCheckpoint:
        ts = time.time() if now is None else float(now)
        expires_at = ts + max(1, int(validity_sec))
        cp_id = f"council_chk_{int(ts * 1000)}_{subject_payload_sha256[:8]}"
        token = self._compute_token(cp_id, subject_type, subject_payload_sha256, expires_at)
        audit = self._append_audit(
            event_type="RUN_STARTED",
            checkpoint_id=cp_id,
            workflow_state="running",
            actor_id="council_router",
            subject_payload_sha256=subject_payload_sha256,
            reason="Verification run initialized",
            now=ts,
        )
        cp = {
            "schema_version": "council.hitl_checkpoint.v1",
            "checkpoint_id": cp_id,
            "job_id": job_id,
            "subject_type": subject_type,
            "subject_payload_sha256": subject_payload_sha256,
            "requested_authority": requested_authority,
            "workflow_state": "running",
            "allowed_next_states": list(HUMAN_APPROVAL_TRANSITIONS["running"]),
            "resume_token": token,
            "saved_progress": dict(saved_progress or {}),
            "created_at": ts,
            "expires_at": expires_at,
            "resolved_at": None,
            "resumed_at": None,
            "approver_identity": None,
            "decision_reason": None,
            "audit_entry_hash": audit.entry_hash,
        }
        self._persist_checkpoint(cp)
        return CouncilApprovalCheckpoint(**cp)

    def request_approval(
        self,
        *,
        subject_type: str,
        subject_payload_sha256: str,
        requested_authority: str = "promotion_receipt",
        job_id: Optional[str] = None,
        checkpoint_id: Optional[str] = None,
        saved_progress: Optional[Dict[str, Any]] = None,
        reason: str = "Human approval required for promotion or authority upgrade",
        validity_sec: int = 3600,
        now: Optional[float] = None,
    ) -> CouncilApprovalCheckpoint:
        ts = time.time() if now is None else float(now)
        if checkpoint_id and checkpoint_id in self.checkpoints:
            cp = dict(self.checkpoints[checkpoint_id])
            allowed_next = validate_approval_transition(cp["workflow_state"], "waiting_for_approval")
            if saved_progress:
                cp["saved_progress"] = {**cp.get("saved_progress", {}), **saved_progress}
        else:
            started = self.start_run(
                subject_type=subject_type,
                subject_payload_sha256=subject_payload_sha256,
                requested_authority=requested_authority,
                job_id=job_id,
                saved_progress=saved_progress,
                validity_sec=validity_sec,
                now=ts,
            )
            cp = started.model_dump()
            allowed_next = validate_approval_transition(cp["workflow_state"], "waiting_for_approval")

        audit = self._append_audit(
            event_type="WAITING_FOR_APPROVAL",
            checkpoint_id=cp["checkpoint_id"],
            workflow_state="waiting_for_approval",
            actor_id="council_gate",
            subject_payload_sha256=cp["subject_payload_sha256"],
            reason=reason,
            now=ts,
        )
        cp["workflow_state"] = "waiting_for_approval"
        cp["allowed_next_states"] = list(allowed_next)
        cp["audit_entry_hash"] = audit.entry_hash
        self._persist_checkpoint(cp)
        return CouncilApprovalCheckpoint(**cp)

    def resolve_approval(
        self,
        *,
        resume_token: str,
        decision: str,
        approver_identity: str,
        reason: str = "",
        now: Optional[float] = None,
    ) -> CouncilApprovalCheckpoint:
        ts = time.time() if now is None else float(now)
        normalized = decision.strip().lower()
        if normalized in ("approve", "approved"):
            target_state: ApprovalWorkflowState = "approved"
        elif normalized in ("reject", "rejected"):
            target_state = "rejected"
        else:
            raise ValueError(f"Unsupported approval decision '{decision}'. Expected 'approve' or 'reject'.")

        cp = self._find_by_token(resume_token)
        if cp is None:
            raise KeyError("Checkpoint not found for resume_token")

        expected_token = self._compute_token(
            cp["checkpoint_id"], cp["subject_type"], cp["subject_payload_sha256"], float(cp["expires_at"])
        )
        if not hmac.compare_digest(expected_token, resume_token):
            raise ValueError("Invalid resume_token signature")

        if ts >= float(cp["expires_at"]):
            validate_approval_transition(cp["workflow_state"], "cancelled")
            expired_cp = dict(cp)
            expired_cp["workflow_state"] = "cancelled"
            expired_cp["allowed_next_states"] = []
            expired_cp["decision_reason"] = "checkpoint_expired"
            self._append_audit(
                event_type="CHECKPOINT_EXPIRED",
                checkpoint_id=cp["checkpoint_id"],
                workflow_state="cancelled",
                actor_id="system_clock",
                subject_payload_sha256=cp["subject_payload_sha256"],
                reason="Checkpoint expired before human decision",
                now=ts,
            )
            self._persist_checkpoint(expired_cp)
            raise TimeoutError(f"Checkpoint '{cp['checkpoint_id']}' expired")

        allowed_next = validate_approval_transition(cp["workflow_state"], target_state)
        resolved_reason = reason or (
            "Approved by human operator" if target_state == "approved" else "Rejected by human operator"
        )
        audit = self._append_audit(
            event_type="APPROVAL_GRANTED" if target_state == "approved" else "APPROVAL_REJECTED",
            checkpoint_id=cp["checkpoint_id"],
            workflow_state=target_state,
            actor_id=approver_identity.strip() or "operator",
            subject_payload_sha256=cp["subject_payload_sha256"],
            reason=resolved_reason,
            now=ts,
        )
        updated = dict(cp)
        updated["workflow_state"] = target_state
        updated["allowed_next_states"] = list(allowed_next)
        updated["resolved_at"] = ts
        updated["approver_identity"] = approver_identity.strip() or "operator"
        updated["decision_reason"] = resolved_reason
        updated["audit_entry_hash"] = audit.entry_hash
        self._persist_checkpoint(updated)
        return CouncilApprovalCheckpoint(**updated)

    def resume_with_token(
        self,
        *,
        resume_token: str,
        expected_subject_sha256: Optional[str] = None,
        actor_id: str = "dizzy_bridge",
        now: Optional[float] = None,
    ) -> CouncilApprovalCheckpoint:
        ts = time.time() if now is None else float(now)
        cp = self._find_by_token(resume_token)
        if cp is None:
            raise KeyError("Checkpoint not found for resume_token")

        allowed_next = validate_approval_transition(cp["workflow_state"], "resumed")
        if ts >= float(cp["expires_at"]):
            raise TimeoutError("Cannot resume expired approval token")
        if expected_subject_sha256 and cp["subject_payload_sha256"] != expected_subject_sha256:
            raise ValueError("Subject SHA-256 mismatch on resume")

        audit = self._append_audit(
            event_type="APPROVAL_RESUMED",
            checkpoint_id=cp["checkpoint_id"],
            workflow_state="resumed",
            actor_id=actor_id,
            subject_payload_sha256=cp["subject_payload_sha256"],
            reason="Resumed execution with verified human approval token",
            now=ts,
        )
        updated = dict(cp)
        updated["workflow_state"] = "resumed"
        updated["allowed_next_states"] = list(allowed_next)
        updated["resumed_at"] = ts
        updated["audit_entry_hash"] = audit.entry_hash
        self._persist_checkpoint(updated)
        return CouncilApprovalCheckpoint(**updated)

    def cancel_checkpoint(
        self,
        *,
        checkpoint_id: str,
        actor_id: str = "operator",
        reason: str = "Cancelled",
        now: Optional[float] = None,
    ) -> CouncilApprovalCheckpoint:
        ts = time.time() if now is None else float(now)
        if checkpoint_id not in self.checkpoints:
            raise KeyError(f"Checkpoint '{checkpoint_id}' not found")
        cp = self.checkpoints[checkpoint_id]
        allowed_next = validate_approval_transition(cp["workflow_state"], "cancelled")
        audit = self._append_audit(
            event_type="APPROVAL_CANCELLED",
            checkpoint_id=checkpoint_id,
            workflow_state="cancelled",
            actor_id=actor_id,
            subject_payload_sha256=cp["subject_payload_sha256"],
            reason=reason,
            now=ts,
        )
        updated = dict(cp)
        updated["workflow_state"] = "cancelled"
        updated["allowed_next_states"] = list(allowed_next)
        updated["decision_reason"] = reason
        updated["audit_entry_hash"] = audit.entry_hash
        self._persist_checkpoint(updated)
        return CouncilApprovalCheckpoint(**updated)

    def list_pending(self, now: Optional[float] = None) -> List[CouncilApprovalCheckpoint]:
        ts = time.time() if now is None else float(now)
        return [
            CouncilApprovalCheckpoint(**cp)
            for cp in self.checkpoints.values()
            if cp["workflow_state"] == "waiting_for_approval" and float(cp["expires_at"]) > ts
        ]

    def verify_audit_log(self) -> Dict[str, Any]:
        expected_prev = GENESIS_AUDIT_PREV_HASH
        for idx, entry in enumerate(self.audit_log, start=1):
            if entry.prev_hash != expected_prev:
                raise ValueError(f"Audit chain broken at entry {idx}")
            core = {
                "schema_version": entry.schema_version,
                "timestamp": entry.timestamp,
                "event_type": entry.event_type,
                "checkpoint_id": entry.checkpoint_id,
                "workflow_state": entry.workflow_state,
                "actor_id": entry.actor_id,
                "subject_payload_sha256": entry.subject_payload_sha256,
                "reason": entry.reason,
                "prev_hash": entry.prev_hash,
            }
            canonical = json.dumps(core, sort_keys=True, separators=(",", ":"))
            computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(computed, entry.entry_hash):
                raise ValueError(f"Audit hash tamper detected at entry {idx}")
            expected_prev = entry.entry_hash
        return {
            "valid": True,
            "entry_count": len(self.audit_log),
            "head_hash": expected_prev,
        }

