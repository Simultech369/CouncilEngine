"""
External Agent-to-Agent (A2A) Adapter & Agent Card Gateway
Provides standard, read-only Agent Card fixtures, JSON-RPC 2.0 message schemas,
and strict privacy/PHI redaction guards. Does not grant remote execution authority.
"""

import json
import re
import time
from typing import Dict, Any, List, Optional, Tuple, Literal, Set
from council_contracts import CONTRACT_VERSION, ImmutableContract, A2AMessage, ReceiptEnvelope, ReviewHopTraceReceipt
from council_verifier import CouncilReceiptVerifier, VerificationError
from lifecycle_hooks import sanitize_untrusted_text
import unicodedata
import uuid

# Sensitive pattern regular expressions for redaction
PRIVATE_PATH_REGEX = re.compile(
    r"([A-Za-z]:\\[^\r\n\"'<>]+|/(?:Users|home|root|var|tmp)/[^\r\n\"'<>]+)"
)
PRIVATE_KEY_REGEX = re.compile(
    r"(?:(?:private[_-]?key|secret(?:[_-]?token|[_-]?key)?|password|api[_-]?key)\s*[:=]\s*[^\s,\"'}]+|"
    r"\b(?:private[_-]?key|secret(?:[_-]?token|[_-]?key)?|password|api[_-]?key)\b|"
    r"\bbearer\s+[A-Za-z0-9_\-\.]+)",
    re.IGNORECASE,
)
PHI_PII_REGEX = re.compile(
    r"\b\d{3}-\d{2}-\d{4}\b|"
    r"\b(?:ssn|npi|patient|dob)\b[^\r\n\d]{0,32}\b\d{10}\b|"
    r"\b\d{10}\b[^\r\n]{0,32}\b(?:ssn|npi|patient|dob)\b",
    re.IGNORECASE,
)
MARKDOWN_COMMENT_REGEX = re.compile(r"<!--[\s\S]*?-->")
CHAT_TEMPLATE_REGEX = re.compile(r"<\|(?:im_start|im_end|system|user|assistant)\|>", re.IGNORECASE)
INSTRUCTION_OVERRIDE_REGEX = re.compile(
    r"(?i)(ignore\s+(all\s+)?(rules|directives|instructions)|"
    r"system\s*override|bypass\s+gate\s+0|developer\s*:|system\s*:)"
)
SAFE_EXTERNAL_KEY_REGEX = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")
MAX_EXTERNAL_STRING_CHARS = 4096

class AgentCard(ImmutableContract):
    """
    Standardized, public-safe metadata descriptor for a Council Agent.
    Strictly contains no private storage paths, internal secrets, or execution bindings.
    """
    agent_id: str
    name: str
    description: str
    version: str
    protocol_version: str = "A2A-v1.0"
    capabilities: List[str]
    supported_transports: List[str] = ["jsonrpc_http", "signed_envelope"]
    authentication_methods: List[str] = ["ed25519", "hmac_sha256"]
    security_clearance: Literal["PUBLIC_SAFE", "INTERNAL_NO_TRAIN_OK"] = "PUBLIC_SAFE"
    read_only_mode: bool = True
    remote_execution_permitted: bool = False

class JSONRPCRequest(ImmutableContract):
    """Standard JSON-RPC 2.0 request envelope."""
    jsonrpc: str = "2.0"
    method: str
    params: Dict[str, Any]
    id: Optional[str] = None

class JSONRPCResponse(ImmutableContract):
    """Standard JSON-RPC 2.0 response envelope."""
    jsonrpc: str = "2.0"
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[str] = None

class ExternalA2ASecurityError(Exception):
    """Raised when an external A2A payload violates privacy, PHI, or remote execution rules."""
    pass

class PIIUUIDSwapper:
    """
    Stateful swapper to map detected PHI/PII strings to UUIDs before the model sees them,
    allowing unmasking after the generation without exposing the sensitive data.
    """
    def __init__(self):
        self.mapping = {}

    def mask(self, text: str) -> str:
        def replace(match):
            val = match.group(0)
            if val not in self.mapping:
                self.mapping[val] = f"UUID-{uuid.uuid4()}"
            return self.mapping[val]
        return PHI_PII_REGEX.sub(replace, text)

    def unmask(self, text: str) -> str:
        for pii_val, mask_val in self.mapping.items():
            text = text.replace(mask_val, pii_val)
        return text

class ExternalA2AAdapter:
    """
    Converts Council-native messages to and from external A2A shapes,
    enforcing zero-trust privacy boundaries and blocking remote execution.
    """

    ALLOWED_EXTERNAL_METHODS: Set[str] = {
        "council.getAgentCard",
        "council.verifyReceipt",
        "council.querySolvencyAttestation",
        "council.queryFraudInvariantAttestation",
        "council.inspectHandoffSchema",
        "council.ping"
    }

    @staticmethod
    def create_agent_card(
        agent_id: str,
        name: str,
        description: str,
        capabilities: List[str],
        version: str = "1.0.0"
    ) -> AgentCard:
        """Constructs a certified read-only Agent Card."""
        return AgentCard(
            agent_id=agent_id,
            name=name,
            description=description,
            version=version,
            capabilities=capabilities,
            read_only_mode=True,
            remote_execution_permitted=False
        )

    @classmethod
    def sanitize_external_payload(cls, data: Any, swapper: Optional[PIIUUIDSwapper] = None, is_top_level_string: bool = False) -> Any:
        """
        Recursively sanitizes dictionary or string payloads to eliminate:
        1. Local absolute filesystem paths (C:\\... or /Users/...)
        2. Private keys, secret tokens, or API credentials
        3. Potential PHI/PII markers (using swapper if provided, else REDACTED)
        4. Applies NFKC Normalization and TR39 structural separation bounds.
        """
        if isinstance(data, dict):
            sanitized = {}
            for k, v in data.items():
                key = str(k)
                if cls._is_unsafe_external_key(key):
                    continue
                sanitized[key] = cls.sanitize_external_payload(v, swapper=swapper)
            return sanitized
        elif isinstance(data, list):
            return [cls.sanitize_external_payload(item, swapper=swapper) for item in data]
        elif isinstance(data, str):
            # NFKC Normalization (TR39)
            redacted = unicodedata.normalize("NFKC", data)
            
            # Redact file system paths
            redacted = PRIVATE_PATH_REGEX.sub("[REDACTED_LOCAL_PATH]", redacted)
            # Redact secret phrases
            redacted = PRIVATE_KEY_REGEX.sub("[REDACTED_SECRET]", redacted)
            
            # Swap or Redact direct PHI/PII patterns
            if swapper:
                redacted = swapper.mask(redacted)
            else:
                redacted = PHI_PII_REGEX.sub("[REDACTED_PHI_PII]", redacted)
                
            redacted = MARKDOWN_COMMENT_REGEX.sub("[REMOVED_UNTRUSTED_COMMENT]", redacted)
            if CHAT_TEMPLATE_REGEX.search(redacted):
                redacted = "[REMOVED_UNTRUSTED_INSTRUCTION]"
            redacted, _ = sanitize_untrusted_text(redacted)
            redacted = INSTRUCTION_OVERRIDE_REGEX.sub("[REMOVED_UNTRUSTED_INSTRUCTION]", redacted)
            
            if len(redacted) > MAX_EXTERNAL_STRING_CHARS:
                redacted = redacted[:MAX_EXTERNAL_STRING_CHARS] + "[TRUNCATED]"
                
            if is_top_level_string:
                redacted = f"<A2A_PAYLOAD_BOUNDARY>\n{redacted}\n</A2A_PAYLOAD_BOUNDARY>"
                
            return redacted
        else:
            return data

    @classmethod
    def _is_unsafe_external_key(cls, key: str) -> bool:
        if not SAFE_EXTERNAL_KEY_REGEX.fullmatch(key):
            return True
        return any(regex.search(key) for regex in (
            PRIVATE_PATH_REGEX,
            PRIVATE_KEY_REGEX,
            PHI_PII_REGEX,
            CHAT_TEMPLATE_REGEX,
            INSTRUCTION_OVERRIDE_REGEX,
        ))

    @classmethod
    def to_jsonrpc_request(cls, message: A2AMessage) -> JSONRPCRequest:
        """Converts an internal A2AMessage into a sanitized external JSON-RPC request."""
        sanitized_payload = cls.sanitize_external_payload(message.payload_data)
        return JSONRPCRequest(
            jsonrpc="2.0",
            method=f"council.{message.intent.lower()}",
            params={
                "sender": message.sender_agent_id,
                "recipient": message.recipient_agent_id,
                "data": sanitized_payload,
                "context_snapshot_sha256": message.context_snapshot_sha256,
                "timestamp": message.timestamp
            },
            id=message.message_id
        )

    @classmethod
    def handle_external_request(
        cls,
        request: JSONRPCRequest,
        local_agent_card: AgentCard
    ) -> JSONRPCResponse:
        """
        Processes inbound external JSON-RPC requests under strict read-only rules.
        Rejects any mutating or code-execution methods.
        """
        if request.method not in cls.ALLOWED_EXTERNAL_METHODS:
            return JSONRPCResponse(
                jsonrpc="2.0",
                error={
                    "code": -32601,
                    "message": f"Method '{request.method}' not allowed. Council A2A gateway is read-only and prohibits remote code execution."
                },
                id=request.id
            )

        if request.method == "council.getAgentCard":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result=local_agent_card.model_dump(),
                id=request.id
            )

        if request.method == "council.ping":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result={"status": "PONG", "timestamp": time.time()},
                id=request.id
            )

        if request.method == "council.verifyReceipt":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result=cls._verify_receipt_envelope(request.params),
                id=request.id
            )

        if request.method == "council.inspectHandoffSchema":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result={
                    "schema_version": "A2A-v1.0",
                    "supported_methods": sorted(list(cls.ALLOWED_EXTERNAL_METHODS)),
                    "receipt_types": [
                        "PBMRebateFormalInvariantReceipt",
                        "PBMFraudFormalInvariantReceipt",
                        "SubcommitteeConvocationReceipt",
                        "ReviewHopTraceReceipt",
                    ],
                    "trace_receipts_supported": True,
                    "trace_receipt_boundary": "provenance_only_not_sandbox_or_audit_proof",
                    "read_only_mode": True,
                    "remote_execution_permitted": False,
                    "timestamp": time.time(),
                },
                id=request.id
            )

        if request.method == "council.querySolvencyAttestation":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result=cls._build_solvency_attestation(),
                id=request.id
            )

        if request.method == "council.queryFraudInvariantAttestation":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result=cls._build_fraud_invariant_attestation(),
                id=request.id
            )

        return JSONRPCResponse(
            jsonrpc="2.0",
            result={"status": "RECEIVED_READ_ONLY"},
            id=request.id
        )

    @classmethod
    def _build_solvency_attestation(cls) -> Dict[str, Any]:
        """
        Builds a public-safe solvency proof summary for external A2A callers.
        Exposes hashes, SMT proof domains, and proof-boundary flags only;
        it does not expose raw local evidence, PHI, or any remote execution capability.
        """
        from pbm_rebate_formal_invariants import PBMRebateFormalInvariantEngine

        receipt_envelope = PBMRebateFormalInvariantEngine().prove_all()
        receipt = receipt_envelope.payload
        attestation = {
            "attestation_status": "ARITHMETIC_MODEL_CHECKS_PASSED" if receipt.all_invariants_proved else "REVIEW_REQUIRED",
            "proof_status": "LOCAL_Z3_UNSAT_NEGATION_CHECKS_PASSED" if receipt.all_invariants_proved else "REVIEW_REQUIRED",
            "runtime_solvency_status": "UNASSESSED_NO_LIVE_BALANCE_OR_LIABILITY_READ",
            "proof_suite_id": receipt.proof_suite_id,
            "proof_digest_sha256": receipt.proof_digest_sha256,
            "receipt_payload_sha256": receipt_envelope.payload_sha256,
            "domains_verified": sorted({proof.domain for proof in receipt.invariants}),
            "invariant_count": len(receipt.invariants),
            "target_contracts": receipt.target_contracts,
            "audit_replacement_claimed": receipt.audit_replacement_claimed,
            "market_truth_claimed": receipt.market_truth_claimed,
            "proof_boundary": receipt.proof_boundary,
            "remote_execution_permitted": False,
            "timestamp": time.time(),
        }
        return cls.sanitize_external_payload(attestation)

    @classmethod
    def _verify_receipt_envelope(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verifies checksum and known semantic constraints in read-only mode.

        NON-CLAIM: this does not authenticate issuer trust, signatures, or full provenance.
        """
        import hashlib
        envelope_data = params.get("envelope") or params.get("receipt_envelope") or params
        if not isinstance(envelope_data, dict):
            return {"verified": False, "reason": "Missing or invalid envelope object"}
        payload_data = envelope_data.get("payload")
        payload_sha256 = envelope_data.get("payload_sha256")
        receipt_type = envelope_data.get("receipt_type")
        contract_version = envelope_data.get("contract_version")
        envelope_sha256 = envelope_data.get("envelope_sha256")
        created_at = envelope_data.get("created_at")
        if not payload_data or not payload_sha256:
            return {"verified": False, "reason": "Envelope missing payload or payload_sha256"}
        computed = hashlib.sha256(
            json.dumps(payload_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        payload_match = (computed == payload_sha256)
        contract_version_match = (contract_version == CONTRACT_VERSION)
        receipt_type_supported = isinstance(receipt_type, str) and bool(receipt_type)
        envelope_match = False
        if receipt_type_supported and contract_version_match and envelope_sha256 and created_at is not None:
            expected_envelope_data = f"{CONTRACT_VERSION}:{receipt_type}:{payload_sha256}:{created_at}"
            envelope_match = hashlib.sha256(expected_envelope_data.encode("utf-8")).hexdigest() == envelope_sha256

        semantic_valid = False
        semantic_reason = "semantic verifier unavailable for receipt type"
        if receipt_type == "ReviewHopTraceReceipt" and payload_match and envelope_match and contract_version_match:
            try:
                typed_env = ReceiptEnvelope[ReviewHopTraceReceipt](**envelope_data)
                CouncilReceiptVerifier.verify_envelope(typed_env, ReviewHopTraceReceipt)
                semantic_valid = True
                semantic_reason = "ReviewHopTraceReceipt semantic checks passed"
            except (VerificationError, ValueError, TypeError) as err:
                semantic_reason = str(err)
        elif receipt_type != "ReviewHopTraceReceipt":
            semantic_valid = payload_match and envelope_match and contract_version_match
            semantic_reason = "generic envelope checksum checks passed" if semantic_valid else "generic envelope checksum checks failed"

        is_valid = payload_match and envelope_match and contract_version_match and semantic_valid
        return {
            "verified": is_valid,
            "contract_version": contract_version or "unknown",
            "receipt_type": receipt_type or "unknown",
            "payload_sha256_match": payload_match,
            "envelope_sha256_match": envelope_match,
            "contract_version_match": contract_version_match,
            "semantic_valid": semantic_valid,
            "semantic_reason": semantic_reason,
            "authenticated_provenance": False,
            "remote_execution_permitted": False,
            "timestamp": time.time(),
        }

    @classmethod
    def _build_fraud_invariant_attestation(cls) -> Dict[str, Any]:
        """
        Builds a public-safe proof summary for external A2A callers.
        This exposes hashes and proof-boundary flags only; it does not expose
        raw local evidence, PHI, or any remote execution capability.
        """
        from pbm_fraud_formal_invariants import PBMFraudFormalInvariantEngine

        receipt_envelope = PBMFraudFormalInvariantEngine().prove_all()
        receipt = receipt_envelope.payload
        attestation = {
            "attestation_status": "LOCAL_Z3_AND_SCHEMA_CHECKS_PASSED" if receipt.all_invariants_proved else "REVIEW_REQUIRED",
            "external_business_truth_status": "UNASSESSED_NO_REAL_WORLD_FRAUD_OR_REGULATORY_TRUTH_READ",
            "proof_suite_id": receipt.proof_suite_id,
            "proof_digest_sha256": receipt.proof_digest_sha256,
            "receipt_payload_sha256": receipt_envelope.payload_sha256,
            "domains_verified": sorted({proof.domain for proof in receipt.invariants}),
            "invariant_count": len(receipt.invariants),
            "benford_output_contract": receipt.benford_output_contract,
            "fraud_proof_claimed": receipt.fraud_proof_claimed,
            "external_business_truth_proven": receipt.external_business_truth_proven,
            "proof_boundary": receipt.proof_boundary,
            "remote_execution_permitted": False,
            "timestamp": time.time(),
        }
        return cls.sanitize_external_payload(attestation)
