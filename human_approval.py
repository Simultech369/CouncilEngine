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
