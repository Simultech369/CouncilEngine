"""
Agent-to-Agent (A2A) Protocol, Router, and Reconciliation Engine
Provides secure, cryptographically signed, replay-resistant, and injection-guarded
communication and state handoffs between autonomous agents (e.g. Antigravity <-> Codex).
"""

import binascii
import hashlib
import hmac
import json
import time
from typing import Dict, Any, List, Optional, Tuple, Set, Callable
from council_contracts import (
    ImmutableContract,
    ReceiptEnvelope,
    A2AMessage,
    A2ASignedEnvelope,
    A2AHandoffReceipt,
    A2AConsensusReceipt,
    CONTRACT_VERSION
)
from council_verifier import CouncilReceiptVerifier, VerificationError
from lifecycle_hooks import sanitize_untrusted_text

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except Exception:  # pragma: no cover
    BadSignatureError = None
    SigningKey = None
    VerifyKey = None

class A2ASecurityError(Exception):
    pass

def _decode_key(key_str: str) -> bytes:
    cleaned = key_str.strip()
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return cleaned.encode("utf-8")


class A2ATrustStore:
    """Stores verified public keys and metadata for registered peer agents."""

    def __init__(self):
        self._public_keys: Dict[str, str] = {}
        self._agent_metadata: Dict[str, Dict[str, Any]] = {}

    def register_agent(self, agent_id: str, public_key_hex_or_str: str, metadata: Optional[Dict[str, Any]] = None):
        if not agent_id:
            raise ValueError("agent_id cannot be empty")
        self._public_keys[agent_id] = public_key_hex_or_str.strip()
        self._agent_metadata[agent_id] = metadata or {}

    def get_public_key(self, agent_id: str) -> Optional[str]:
        return self._public_keys.get(agent_id)

    def is_registered(self, agent_id: str) -> bool:
        return agent_id in self._public_keys

    def list_agents(self) -> List[str]:
        return sorted(list(self._public_keys.keys()))


class A2AEnvelopeSigner:
    """Signs A2AMessage payloads using Ed25519 private keys or SHA256 HMAC."""

    @staticmethod
    def sign_message(message: A2AMessage, private_key_hex_or_str: str) -> A2ASignedEnvelope:
        payload_digest = message.compute_canonical_sha256()
        payload_bytes = payload_digest.encode("utf-8")
        now = time.time()

        raw_key = _decode_key(private_key_hex_or_str)
        if SigningKey is not None and len(raw_key) == 32:
            signer = SigningKey(raw_key)
            sig_bytes = signer.sign(payload_bytes).signature
            detached_sig = sig_bytes.hex()
            algo = "ED25519"
        else:
            # Deterministic HMAC fallback when raw shared-secret key is used.
            detached_sig = hmac.new(raw_key, payload_bytes, hashlib.sha256).hexdigest()
            algo = "HMAC_SHA256"

        return A2ASignedEnvelope(
            envelope_type="A2A_SIGNED_MESSAGE",
            message_id=message.message_id,
            sender_agent_id=message.sender_agent_id,
            signature_algorithm=algo,
            signed_payload_sha256=payload_digest,
            detached_signature=detached_sig,
            message=message,
            created_at=now
        )


class A2AEnvelopeVerifier:
    """Verifies A2ASignedEnvelope signatures and enforces anti-replay nonces."""

    def __init__(self, trust_store: A2ATrustStore, max_clock_skew_sec: float = 300.0):
        self.trust_store = trust_store
        self.max_clock_skew_sec = max_clock_skew_sec
        self._seen_nonces: Set[str] = set()

    def verify_envelope(self, envelope: A2ASignedEnvelope) -> A2AMessage:
        msg = envelope.message

        if envelope.sender_agent_id != msg.sender_agent_id:
            raise A2ASecurityError("A2A envelope sender does not match message sender")
        if envelope.message_id != msg.message_id:
            raise A2ASecurityError("A2A envelope message_id does not match message payload")
        now = time.time()
        if abs(now - envelope.created_at) > self.max_clock_skew_sec:
            raise A2ASecurityError("A2A envelope timestamp outside allowed clock skew")
        if abs(now - msg.timestamp) > self.max_clock_skew_sec:
            raise A2ASecurityError("A2A message timestamp outside allowed clock skew")

        # 1. Check registration
        pub_key = self.trust_store.get_public_key(envelope.sender_agent_id)
        if not pub_key:
            raise A2ASecurityError(f"Untrusted sender agent: '{envelope.sender_agent_id}' is not in trust store")

        # 2. Check payload integrity
        expected_digest = msg.compute_canonical_sha256()
        if envelope.signed_payload_sha256 != expected_digest:
            raise A2ASecurityError("A2A payload digest mismatch - message has been modified")

        # 3. Check anti-replay nonce
        nonce_key = f"{msg.sender_agent_id}:{msg.nonce}"
        if nonce_key in self._seen_nonces:
            raise A2ASecurityError(f"Replay attack detected: duplicate nonce '{msg.nonce}' for agent '{msg.sender_agent_id}'")

        # 4. Check signature
        payload_bytes = expected_digest.encode("utf-8")
        raw_pub = _decode_key(pub_key)

        if envelope.signature_algorithm == "ED25519" and VerifyKey is not None and len(raw_pub) == 32:
            try:
                verifier = VerifyKey(raw_pub)
                verifier.verify(payload_bytes, bytes.fromhex(envelope.detached_signature))
            except Exception as e:
                raise A2ASecurityError(f"Ed25519 signature verification failed: {str(e)}") from e
        elif envelope.signature_algorithm == "HMAC_SHA256":
            expected_sig = hmac.new(raw_pub, payload_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(envelope.detached_signature, expected_sig):
                raise A2ASecurityError("HMAC_SHA256 signature verification failed")
        else:
            raise A2ASecurityError(f"Unsupported signature algorithm: {envelope.signature_algorithm}")

        self._seen_nonces.add(nonce_key)
        return msg


class A2AMessageRouter:
    """Routes verified A2A messages between agent inboxes with prompt-injection sanitization."""

    def __init__(self, trust_store: A2ATrustStore):
        self.trust_store = trust_store
        self.verifier = A2AEnvelopeVerifier(trust_store)
        self._mailboxes: Dict[str, List[A2AMessage]] = {}
        self._dead_letter_queue: List[Dict[str, Any]] = []

    def send_signed_envelope(self, envelope: A2ASignedEnvelope) -> bool:
        try:
            verified_msg = self.verifier.verify_envelope(envelope)
        except A2ASecurityError as e:
            self._dead_letter_queue.append({
                "envelope": envelope.model_dump(),
                "error": str(e),
                "timestamp": time.time()
            })
            raise

        # Sanitize incoming payload text to prevent prompt injection between agents
        sanitized_payload = self._sanitize_payload(verified_msg.payload_data)
        sanitized_msg = verified_msg.model_copy(update={"payload_data": sanitized_payload})

        recipient = sanitized_msg.recipient_agent_id
        if recipient not in self._mailboxes:
            self._mailboxes[recipient] = []
        self._mailboxes[recipient].append(sanitized_msg)
        return True

    def _sanitize_payload(self, data: Any) -> Any:
        if isinstance(data, str):
            import re
            cleaned = re.sub(r"<!--[\s\S]*?-->", "[REMOVED_COMMENT]", data)
            cleaned, _ = sanitize_untrusted_text(cleaned)
            cleaned = re.sub(r"(?i)(ignore\s+(all\s+)?(rules|directives|instructions)|system\s*override)", "[REMOVED_INSTRUCTION]", cleaned)
            return cleaned
        elif isinstance(data, dict):
            return {k: self._sanitize_payload(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_payload(item) for item in data]
        return data

    def get_mailbox(self, agent_id: str) -> List[A2AMessage]:
        return self._mailboxes.get(agent_id, [])

    def drain_mailbox(self, agent_id: str) -> List[A2AMessage]:
        box = self._mailboxes.get(agent_id, [])
        self._mailboxes[agent_id] = []
        return box

    def get_dead_letters(self) -> List[Dict[str, Any]]:
        return self._dead_letter_queue


class A2ANegotiationSession:
    """
    Orchestrates multi-agent deliberative negotiation loops:
    Proposer -> Critic -> Reviser -> Quorum Consensus -> Sealed A2AConsensusReceipt.
    """

    def __init__(self, session_id: str, topic: str, required_quorum_pct: float = 0.66):
        self.session_id = session_id
        self.topic = topic
        self.required_quorum_pct = required_quorum_pct
        self.participating_agents: List[str] = []
        self.rounds: List[Dict[str, Any]] = []
        self.votes: Dict[str, str] = {}
        self.is_sealed = False

    def add_round(self, agent_id: str, phase: str, content: str, vote: Optional[str] = None):
        if self.is_sealed:
            raise RuntimeError("Cannot add round to sealed negotiation session")
        if agent_id not in self.participating_agents:
            self.participating_agents.append(agent_id)
        
        self.rounds.append({
            "agent_id": agent_id,
            "phase": phase,
            "content": content,
            "timestamp": time.time()
        })
        if vote is not None:
            self.votes[agent_id] = vote.upper()

    def seal_consensus(self) -> ReceiptEnvelope[A2AConsensusReceipt]:
        import math
        total_voters = len(self.participating_agents)
        approvals = sum(1 for v in self.votes.values() if v == "APPROVE")
        rejections = sum(1 for v in self.votes.values() if v == "REJECT")

        required = math.ceil(total_voters * self.required_quorum_pct) if total_voters > 0 else 1
        dissenting_agent = None

        if rejections > 0:
            decision = "DISSENT_VETOED"
            for ag, v in self.votes.items():
                if v == "REJECT":
                    dissenting_agent = ag
                    break
        elif approvals >= required and approvals > 0:
            decision = "AGREED"
        else:
            decision = "DEADLOCKED"

        rounds_data = json.dumps(self.rounds, sort_keys=True)
        verdict_hash = hashlib.sha256(f"{self.session_id}:{decision}:{rounds_data}".encode("utf-8")).hexdigest()

        receipt = A2AConsensusReceipt(
            session_id=self.session_id,
            topic_or_task=self.topic,
            participating_agents=self.participating_agents,
            rounds_count=len(self.rounds),
            consensus_decision=decision,
            final_verdict_sha256=verdict_hash,
            dissenting_agent_id=dissenting_agent,
            decided_at=time.time()
        )
        self.is_sealed = True
        return ReceiptEnvelope.seal(receipt)


class A2AReconciliationLoop:
    """
    Codifies the two-agent reconciliation loop between primary agents (e.g. Antigravity <-> Codex).
    Compares test counts, contract versions, and state hashes, generating verified A2AHandoffReceipts.
    """

    @staticmethod
    def reconcile_and_seal_handoff(
        handoff_id: str,
        conversation_id: str,
        source_agent_id: str,
        target_agent_id: str,
        source_state_manifest: Dict[str, Any],
        target_state_manifest: Dict[str, Any]
    ) -> ReceiptEnvelope[A2AHandoffReceipt]:
        before_sha = hashlib.sha256(json.dumps(source_state_manifest, sort_keys=True).encode("utf-8")).hexdigest()
        after_sha = hashlib.sha256(json.dumps(target_state_manifest, sort_keys=True).encode("utf-8")).hexdigest()

        # Check critical invariants
        source_ver = source_state_manifest.get("contract_version")
        target_ver = target_state_manifest.get("contract_version")
        version_match = (source_ver == target_ver == CONTRACT_VERSION)

        source_tests = source_state_manifest.get("test_count", 0)
        target_tests = target_state_manifest.get("test_count", 0)
        tests_monotonic = (target_tests >= source_tests)

        reconciled_cleanly = bool(version_match and tests_monotonic)

        delta_info = {
            "version_match": version_match,
            "tests_delta": target_tests - source_tests,
            "tasks_transferred": target_state_manifest.get("tasks_transferred_count", 1)
        }
        delta_sha = hashlib.sha256(json.dumps(delta_info, sort_keys=True).encode("utf-8")).hexdigest()

        receipt = A2AHandoffReceipt(
            handoff_id=handoff_id,
            conversation_id=conversation_id,
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            before_state_sha256=before_sha,
            after_state_sha256=after_sha,
            tasks_transferred_count=target_state_manifest.get("tasks_transferred_count", 1),
            delta_manifest_sha256=delta_sha,
            reconciled_cleanly=reconciled_cleanly,
            handed_off_at=time.time()
        )
        return ReceiptEnvelope.seal(receipt)
