import hashlib
import hmac
import ipaddress
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from council_contracts import (
    ImmutableContract,
    LifecycleHookReceipt,
    ReceiptEnvelope,
    WebhookDispatchReceipt,
)

HttpPostCallable = Callable[[str, bytes, Dict[str, str], float], Tuple[int, bytes]]


class WebhookDispatchError(Exception):
    pass


@dataclass(frozen=True)
class WebhookEndpointConfig:
    name: str
    target_url: str
    secret: str
    allowed_event_types: Optional[Set[str]] = None
    max_attempts: int = 3
    timeout_sec: float = 5.0
    retry_backoff_sec: float = 1.0


class SignedWebhookDispatcher:
    """
    HMAC-signed, receipt-emitting fan-out for critical Council events.
    """

    SIGNATURE_HEADER = "X-Council-Signature"
    TIMESTAMP_HEADER = "X-Council-Timestamp"
    EVENT_HEADER = "X-Council-Event"
    IDEMPOTENCY_HEADER = "X-Council-Idempotency-Key"

    def __init__(
        self,
        endpoints: Optional[Iterable[WebhookEndpointConfig]] = None,
        http_post: Optional[HttpPostCallable] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.endpoints = list(endpoints or [])
        self.http_post = http_post or self._urllib_post
        self.clock = clock

    def _urllib_post(self, url: str, body: bytes, headers: Dict[str, str], timeout_sec: float) -> Tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout_sec) as response:
                return int(response.status), response.read()
        except urllib.error.HTTPError as err:
            return int(err.code), err.read()

    def _validate_endpoint(self, endpoint: WebhookEndpointConfig) -> None:
        if not endpoint.name:
            raise WebhookDispatchError("webhook endpoint name is required")
        if not endpoint.secret:
            raise WebhookDispatchError(f"webhook endpoint '{endpoint.name}' is missing a signing secret")
        if endpoint.max_attempts < 1:
            raise WebhookDispatchError(f"webhook endpoint '{endpoint.name}' max_attempts must be >= 1")

        parsed = urllib.parse.urlparse(endpoint.target_url)
        if parsed.scheme != "https":
            raise WebhookDispatchError(f"webhook endpoint '{endpoint.name}' must use https")
        if not parsed.hostname:
            raise WebhookDispatchError(f"webhook endpoint '{endpoint.name}' target host is missing")

        try:
            ip = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            lowered = parsed.hostname.lower()
            if lowered in {"localhost", "metadata.google.internal"} or lowered.endswith(".local"):
                raise WebhookDispatchError(f"webhook endpoint '{endpoint.name}' targets a local/private host")
            return

        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise WebhookDispatchError(f"webhook endpoint '{endpoint.name}' targets a local/private address")

    def _canonical_body(
        self,
        event_type: str,
        payload: Dict[str, Any],
        event_id: str,
        created_at: float,
        source_receipt_sha256: Optional[str],
    ) -> bytes:
        envelope = {
            "event_id": event_id,
            "event_type": event_type,
            "payload": payload,
            "source_receipt_sha256": source_receipt_sha256,
            "created_at": created_at,
        }
        return json.dumps(envelope, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    def _sign(self, secret: str, timestamp: str, body: bytes) -> str:
        signed = timestamp.encode("utf-8") + b"." + body
        return hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()

    def verify_signature(self, secret: str, timestamp: str, body: bytes, signature_hex: str) -> bool:
        expected = self._sign(secret, timestamp, body)
        return hmac.compare_digest(expected, str(signature_hex))

    def _headers(self, event_type: str, event_id: str, timestamp: str, signature: str) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            self.SIGNATURE_HEADER: f"v1={signature}",
            self.TIMESTAMP_HEADER: timestamp,
            self.EVENT_HEADER: event_type,
            self.IDEMPOTENCY_HEADER: event_id,
        }

    def dispatch_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        source_receipt_env: Optional[ReceiptEnvelope[ImmutableContract]] = None,
        event_id: Optional[str] = None,
    ) -> List[ReceiptEnvelope[WebhookDispatchReceipt]]:
        created_at = self.clock()
        event_id = event_id or f"evt_{uuid.uuid4().hex}"
        source_sha = source_receipt_env.payload_sha256 if source_receipt_env is not None else None
        body = self._canonical_body(event_type, payload, event_id, created_at, source_sha)
        payload_sha = hashlib.sha256(body).hexdigest()

        receipt_envs: List[ReceiptEnvelope[WebhookDispatchReceipt]] = []
        for endpoint in self.endpoints:
            if endpoint.allowed_event_types is not None and event_type not in endpoint.allowed_event_types:
                continue

            self._validate_endpoint(endpoint)
            timestamp = str(int(created_at))
            signature = self._sign(endpoint.secret, timestamp, body)
            headers = self._headers(event_type, event_id, timestamp, signature)

            delivered = False
            status_code: Optional[int] = None
            error_message: Optional[str] = None
            attempts = 0
            for attempts in range(1, endpoint.max_attempts + 1):
                try:
                    status_code, _ = self.http_post(endpoint.target_url, body, headers, endpoint.timeout_sec)
                    delivered = 200 <= int(status_code) < 300
                    error_message = None if delivered else f"HTTP {status_code}"
                except Exception as err:
                    status_code = None
                    error_message = str(err)

                if delivered:
                    break

            receipt = WebhookDispatchReceipt(
                event_id=event_id,
                event_type=event_type,
                endpoint_name=endpoint.name,
                target_url_sha256=hashlib.sha256(endpoint.target_url.encode("utf-8")).hexdigest(),
                payload_sha256=payload_sha,
                source_receipt_sha256=source_sha,
                signature_header_name=self.SIGNATURE_HEADER,
                signature_sha256=hashlib.sha256(signature.encode("utf-8")).hexdigest(),
                idempotency_key=event_id,
                attempt_count=attempts,
                delivered=delivered,
                http_status_code=status_code,
                error_message=error_message,
                next_retry_at=None if delivered else created_at + endpoint.retry_backoff_sec,
                dispatched_at=created_at,
            )
            receipt_envs.append(ReceiptEnvelope.seal(receipt))

        return receipt_envs

    def dispatch_lifecycle_hook(
        self,
        hook_env: ReceiptEnvelope[LifecycleHookReceipt],
        event_type: Optional[str] = None,
        extra_payload: Optional[Dict[str, Any]] = None,
    ) -> List[ReceiptEnvelope[WebhookDispatchReceipt]]:
        hook = hook_env.payload
        resolved_event_type = event_type or self.lifecycle_event_type(hook)
        payload = {
            "session_id": hook.session_id,
            "actor_id": hook.actor_id,
            "phase": hook.phase,
            "operation": hook.operation,
            "decision": hook.decision,
            "canonical_arguments_sha256": hook.canonical_arguments_sha256,
            "linked_pre_hook_sha256": hook.linked_pre_hook_sha256,
            "outcome_effect_sha256": hook.outcome_effect_sha256,
            "related_handoff_sha256": hook.related_handoff_sha256,
            "hook_payload_sha256": hook_env.payload_sha256,
        }
        if extra_payload:
            payload.update(extra_payload)
        return self.dispatch_event(resolved_event_type, payload, source_receipt_env=hook_env)

    def lifecycle_event_type(self, hook: LifecycleHookReceipt) -> str:
        if hook.phase == "STOP":
            return "SESSION_STOP"
        if hook.phase == "SUBAGENT_STOP":
            return "SUBAGENT_STOP"
        if hook.decision == "TAINTED":
            return "TAINTED_SESSION"
        if hook.decision == "DENIED":
            return "CRITICAL_SECURITY_VETO"
        return f"LIFECYCLE_{hook.phase}"
