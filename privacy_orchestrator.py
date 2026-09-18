#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons - Vitalik Privacy Orchestrator
tools/council/privacy_orchestrator.py

Implements the Vitalik Buterin privacy pattern:
"Use your local model to orchestrate queries to powerful models
 so your queries don't leak your personal information."
"""

import hashlib
import json
import re
import time
import uuid
import unicodedata
from typing import Dict, Any, List, Optional, Callable, Set, Tuple
from pydantic import Field

try:
    from council_contracts import ImmutableContract, ReceiptEnvelope, CONTRACT_VERSION
    from external_a2a_adapter import (
        PIIUUIDSwapper,
        PHI_PII_REGEX,
        PRIVATE_KEY_REGEX,
        CHAT_TEMPLATE_REGEX,
        MARKDOWN_COMMENT_REGEX,
        INSTRUCTION_OVERRIDE_REGEX,
        sanitize_untrusted_text,
    )
except ImportError:
    from .council_contracts import ImmutableContract, ReceiptEnvelope, CONTRACT_VERSION
    from .external_a2a_adapter import (
        PIIUUIDSwapper,
        PHI_PII_REGEX,
        PRIVATE_KEY_REGEX,
        CHAT_TEMPLATE_REGEX,
        MARKDOWN_COMMENT_REGEX,
        INSTRUCTION_OVERRIDE_REGEX,
        sanitize_untrusted_text,
    )

# Strict path regex that stops at whitespace or quotes
STRICT_LOCAL_PATH_REGEX = re.compile(
    r"([A-Za-z]:\\[^\s\r\n\"'<>,;]+|/(?:Users|home|root|var|tmp)/[^\s\r\n\"'<>,;]+)"
)

HEALTHCARE_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:NPI|provider\s*(?:id|#)?)\s*[:#]?\s*([12]\d{9})\b", re.IGNORECASE),
    re.compile(r"\b(?:DOB|birthdate|born)\s*[:#]?\s*(\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})\b", re.IGNORECASE),
    re.compile(r"\b(?:Rx|prescription)\s*[:#]?\s*([A-Za-z0-9]{6,12})\b", re.IGNORECASE),
    re.compile(r"\b[A-Z]{2}\d{7}\b"),
    re.compile(r"\b(?:patient|patient\s*name)\s*[:=]?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b", re.IGNORECASE),
    re.compile(r"\b(?:pharmacy|pharmacy\s*name)\s*[:=]?\s+([A-Z][a-z0-9]+(?:\s+[A-Z][a-z0-9]+)*\s*(?:Pharmacy|Rx|Drugs|Apothecary))\b", re.IGNORECASE),
]


class PrivacyLeakViolationError(Exception):
    """Raised when an outbound payload contains raw PII/PHI that should have been masked."""
    pass


class PrivacySanitizationRecord(ImmutableContract):
    """Details of the local edge sanitization step."""
    original_query_sha256: str
    sanitized_query_sha256: str
    redacted_entity_count: int
    masked_categories: List[str]
    zero_leak_verified: bool
    sanitized_at: float


class PrivacyOrchestrationReceipt(ImmutableContract):
    """
    Immutable sealed receipt attesting that a query was orchestrated through
    a powerful external model without leaking private information.
    """
    receipt_id: str
    orchestrator_version: str = "1.0.0"
    sanitization: PrivacySanitizationRecord
    upstream_target_model: str
    tokens_masked: int
    unmasked_occurrences: int
    outbound_payload_sha256: str
    final_response_sha256: str
    duration_ms: float
    created_at: float = Field(default_factory=time.time)


class LocalPrivacyOrchestrator:
    """
    Local edge orchestrator that shields personal data from frontier models.
    """

    def __init__(self, upstream_model_slug: str = "external/frontier-model"):
        self.upstream_model_slug = upstream_model_slug

    def extract_and_mask_entities(
        self, raw_text: str
    ) -> Tuple[str, PIIUUIDSwapper, List[str], Set[str]]:
        swapper = PIIUUIDSwapper()
        categories = []
        raw_tokens: Set[str] = set()

        text = unicodedata.normalize("NFKC", raw_text)

        # 1. Extract healthcare identifiers
        for pattern in HEALTHCARE_PII_PATTERNS:
            matches = list(pattern.finditer(text))
            if matches:
                categories.append(pattern.pattern[:20])
                for m in matches:
                    val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    val = val.strip()
                    if val and len(val) >= 3:
                        raw_tokens.add(val)
                        if val not in swapper.mapping:
                            swapper.mapping[val] = f"[PII_UUID_{uuid.uuid4().hex[:12]}]"

        # 2. Generic PHI/PII regex
        for m in PHI_PII_REGEX.finditer(text):
            val = m.group(0).strip()
            if val and len(val) >= 4:
                raw_tokens.add(val)
                if val not in swapper.mapping:
                    swapper.mapping[val] = f"[PHI_UUID_{uuid.uuid4().hex[:12]}]"

        # 3. Path stripping with whitespace boundaries
        for m in STRICT_LOCAL_PATH_REGEX.finditer(text):
            val = m.group(0).strip()
            if val:
                raw_tokens.add(val)
                if val not in swapper.mapping:
                    swapper.mapping[val] = f"[LOCAL_PATH_{uuid.uuid4().hex[:8]}]"

        # 4. Secret stripping
        for m in PRIVATE_KEY_REGEX.finditer(text):
            val = m.group(0).strip()
            if val:
                raw_tokens.add(val)
                if val not in swapper.mapping:
                    swapper.mapping[val] = f"[SECRET_{uuid.uuid4().hex[:8]}]"

        # 5. Substitute in text
        masked_text = text
        sorted_tokens = sorted(swapper.mapping.keys(), key=len, reverse=True)
        for tok in sorted_tokens:
            pseudonym = swapper.mapping[tok]
            masked_text = masked_text.replace(tok, pseudonym)

        # 6. Injection & hidden comment stripping
        masked_text = MARKDOWN_COMMENT_REGEX.sub("[REMOVED_COMMENT]", masked_text)
        if CHAT_TEMPLATE_REGEX.search(masked_text):
            masked_text = "[REMOVED_UNTRUSTED_INSTRUCTION]"
        masked_text, _ = sanitize_untrusted_text(masked_text)
        masked_text = INSTRUCTION_OVERRIDE_REGEX.sub("[REMOVED_UNTRUSTED_INSTRUCTION]", masked_text)

        return masked_text, swapper, categories, raw_tokens

    def assert_zero_leak_egress(self, outbound_payload: str, raw_sensitive_tokens: Set[str]) -> None:
        for token in raw_sensitive_tokens:
            if token in outbound_payload:
                raise PrivacyLeakViolationError(
                    f"CRITICAL PRIVACY LEAK: Sensitive token '{token}' detected in outbound payload!"
                )

    def orchestrate_query(
        self,
        raw_user_query: str,
        upstream_invoker: Callable[[str], str],
    ) -> Tuple[str, ReceiptEnvelope[PrivacyOrchestrationReceipt]]:
        t0 = time.time()
        orig_sha = hashlib.sha256(raw_user_query.encode("utf-8")).hexdigest()

        sanitized_query, swapper, categories, raw_tokens = self.extract_and_mask_entities(raw_user_query)
        sanitized_sha = hashlib.sha256(sanitized_query.encode("utf-8")).hexdigest()

        self.assert_zero_leak_egress(sanitized_query, raw_tokens)

        upstream_response = upstream_invoker(sanitized_query)

        unmasked_response = swapper.unmask(upstream_response)
        final_sha = hashlib.sha256(unmasked_response.encode("utf-8")).hexdigest()

        unmasked_occurrences = 0
        for pseudonym in swapper.mapping.values():
            unmasked_occurrences += upstream_response.count(pseudonym)

        t1 = time.time()
        duration_ms = round((t1 - t0) * 1000.0, 3)

        sanitization_record = PrivacySanitizationRecord(
            original_query_sha256=orig_sha,
            sanitized_query_sha256=sanitized_sha,
            redacted_entity_count=len(swapper.mapping),
            masked_categories=categories,
            zero_leak_verified=True,
            sanitized_at=t0,
        )

        receipt_payload = PrivacyOrchestrationReceipt(
            receipt_id=f"priv-orch-{uuid.uuid4().hex[:12]}",
            sanitization=sanitization_record,
            upstream_target_model=self.upstream_model_slug,
            tokens_masked=len(swapper.mapping),
            unmasked_occurrences=unmasked_occurrences,
            outbound_payload_sha256=sanitized_sha,
            final_response_sha256=final_sha,
            duration_ms=duration_ms,
            created_at=t1,
        )

        sealed_envelope = ReceiptEnvelope.seal(receipt_payload)
        return unmasked_response, sealed_envelope
