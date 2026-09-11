import hashlib
import os
import time
import requests
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import (
    ReceiptEnvelope, RouteAttestationReceipt, ModelQualificationReceipt,
    PaidBudgetReservationReceipt, PacketSensitivityReceipt, ModelInvocationReceipt,
    QualificationProbeInvocationReceipt, DeadLetterRecord
)
from dead_letter_queue import DeadLetterQueue
from log_derived_context_engine import LogDerivedContextEngine, LogReconstructionDesyncError
from council_verifier import CouncilReceiptVerifier, VerificationError
from semantic_ast_cache import SemanticASTCache
from prompt_config_registry import (
    PromptConfigRegistry,
    PromptConfigVersionRecord,
    normalize_system_prompt,
    sha256_text,
)

class TokenBucketRateLimiter:
    def __init__(self, requests_per_minute: float = 60.0, burst_limit: int = 5):
        self.rate = requests_per_minute / 60.0
        self.capacity = burst_limit
        self.tokens = float(burst_limit)
        self.last_update = time.time()

    def acquire(self) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, reset_timeout_sec: float = 30.0):
        self.threshold = failure_threshold
        self.reset_timeout = reset_timeout_sec
        self.consecutive_failures = 0
        self.last_failure_time = 0.0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def record_success(self):
        self.consecutive_failures = 0
        self.state = "CLOSED"

    def record_failure(self):
        self.consecutive_failures += 1
        self.last_failure_time = time.time()
        if self.consecutive_failures >= self.threshold:
            self.state = "OPEN"

    def can_attempt(self) -> bool:
        if self.state == "CLOSED":
            return True
        elif self.state == "OPEN":
            if time.time() - self.last_failure_time >= self.reset_timeout:
                self.state = "HALF_OPEN"
                return True
            return False
        elif self.state == "HALF_OPEN":
            return True
        return False

class ModelGateway:
    """
    Fault-tolerant dispatch gateway managing:
    - Pure deterministic pre-dispatch verification (CouncilReceiptVerifier.verify_model_predispatch).
    - Log-derived wire-payload & route attestation context verification.
    - Token-bucket rate limiting and circuit breakers.
    - Automatic dead-letter recording on verification or invocation failure.
    """

    def __init__(
        self,
        dlq: Optional[DeadLetterQueue] = None,
        semantic_cache: Optional[SemanticASTCache] = None,
        prompt_registry: Optional[PromptConfigRegistry] = None
    ):
        self.dlq = dlq or DeadLetterQueue()
        self.semantic_cache = semantic_cache or SemanticASTCache()
        self.prompt_registry = prompt_registry
        self.rate_limiters: Dict[str, TokenBucketRateLimiter] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}

    def resolve_prompt_config(
        self,
        prompt_id: Optional[str] = None,
        prompt_version: Optional[str] = None,
        prompt_registry: Optional[PromptConfigRegistry] = None,
        system_prompt: str = "",
        response_format: Optional[Dict[str, Any]] = None,
        tool_schemas: Optional[List[Dict[str, Any]]] = None,
        provider_parameters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Optional[Dict[str, Any]], Optional[List[Dict[str, Any]]], Optional[Dict[str, Any]], Optional[PromptConfigVersionRecord]]:
        if not prompt_id:
            return system_prompt, response_format, tool_schemas, provider_parameters, None

        registry = prompt_registry or self.prompt_registry
        if registry is None:
            raise ValueError(f"prompt_id '{prompt_id}' supplied but no PromptConfigRegistry provided")

        if prompt_version is not None:
            record = registry.get_version(prompt_id, prompt_version)
        else:
            record = registry.get_active(prompt_id)

        if system_prompt:
            norm_given = normalize_system_prompt(system_prompt)
            if sha256_text(norm_given) != record.normalized_system_prompt_sha256:
                raise VerificationError(
                    f"Given system_prompt does not match registered prompt hash for {prompt_id}@{record.version}"
                )
            effective_prompt = system_prompt
        else:
            effective_prompt = record.system_prompt

        return effective_prompt, response_format, tool_schemas, provider_parameters, record

    def _get_limiter(self, route_id: str) -> TokenBucketRateLimiter:
        if route_id not in self.rate_limiters:
            self.rate_limiters[route_id] = TokenBucketRateLimiter(requests_per_minute=120, burst_limit=10)
        return self.rate_limiters[route_id]

    def _get_breaker(self, route_id: str) -> CircuitBreaker:
        if route_id not in self.circuit_breakers:
            self.circuit_breakers[route_id] = CircuitBreaker(failure_threshold=3, reset_timeout_sec=20.0)
        return self.circuit_breakers[route_id]

    def _format_request(
        self,
        route_url: str,
        provider: str,
        model_slug: str,
        prompt_text: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 512,
        response_format: Optional[Dict[str, Any]] = None,
        tool_schemas: Optional[List[Dict[str, Any]]] = None,
        provider_parameters: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, Dict[str, str], Dict[str, Any], str]:
        """
        Returns (target_url, headers, payload, protocol_type)
        protocol_type: "openai" or "ollama"
        """
        provider_lower = provider.lower()
        url_lower = route_url.lower()
        resp_fmt = response_format or {"type": "json_object"}
        extra_params = provider_parameters or {}

        # Check if OpenAI-compatible chat completion endpoint
        if (
            "chat/completions" in url_lower
            or "/v1" in url_lower
            or provider_lower in ["openai", "siliconflow", "openrouter", "groq", "stepfun", "z.ai", "minimax"]
        ):
            target_url = route_url
            if not target_url.endswith("/chat/completions") and "/v1" in target_url:
                target_url = target_url.rstrip("/") + "/chat/completions"
            elif not target_url.endswith("/chat/completions") and "/v1" not in target_url:
                target_url = target_url.rstrip("/") + "/v1/chat/completions"

            headers = {"Content-Type": "application/json"}
            api_key = os.environ.get(f"{provider_lower.upper()}_API_KEY") or os.environ.get("OPENAI_API_KEY")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt_text})

            payload = {
                "model": model_slug,
                "messages": messages,
                "temperature": temperature,
                "response_format": resp_fmt
            }
            if max_tokens:
                payload["max_tokens"] = max_tokens
            if tool_schemas:
                payload["tools"] = tool_schemas
            if extra_params:
                for k, v in extra_params.items():
                    payload[k] = v

            return target_url, headers, payload, "openai"
        else:
            # Default to Ollama native generate endpoint
            target_url = route_url if route_url.endswith("/api/generate") else route_url.rstrip("/") + "/api/generate"
            headers = {"Content-Type": "application/json"}
            options = {"temperature": temperature, "num_predict": max_tokens}
            if extra_params:
                options.update(extra_params)

            full_prompt = f"System: {system_prompt}\n\n{prompt_text}" if system_prompt else prompt_text

            payload = {
                "model": model_slug,
                "prompt": full_prompt,
                "stream": False,
                "format": "json",
                "options": options
            }
            return target_url, headers, payload, "ollama"

    def _extract_response_text(self, resp_json: Dict[str, Any], protocol_type: str) -> str:
        if protocol_type == "openai":
            choices = resp_json.get("choices", [])
            if choices and isinstance(choices, list):
                msg = choices[0].get("message", {})
                return msg.get("content", "")
            return ""
        else:
            return resp_json.get("response", "")

    def _seal_invocation_receipt(
        self,
        model_slug: str,
        model_family: str,
        provider: str,
        route_id: str,
        route_env: ReceiptEnvelope[RouteAttestationReceipt],
        qual_env: ReceiptEnvelope[ModelQualificationReceipt],
        packet_env: ReceiptEnvelope[PacketSensitivityReceipt],
        budget_env: Optional[ReceiptEnvelope[PaidBudgetReservationReceipt]],
        request_payload_sha256: str,
        raw_response: str,
        prompt_text: str,
        latency_ms: float
    ) -> ReceiptEnvelope[ModelInvocationReceipt]:
        inv = ModelInvocationReceipt(
            packet_payload_sha256=packet_env.payload_sha256,
            route_attestation_payload_sha256=route_env.payload_sha256,
            qualification_payload_sha256=qual_env.payload_sha256,
            paid_budget_payload_sha256=budget_env.payload_sha256 if budget_env else None,
            model_slug=model_slug,
            model_family=model_family,
            provider=provider,
            route_id=route_id,
            request_payload_sha256=request_payload_sha256,
            response_payload_sha256=hashlib.sha256(raw_response.encode("utf-8")).hexdigest(),
            prompt_tokens=len(prompt_text) // 4,
            completion_tokens=len(raw_response) // 4,
            latency_ms=latency_ms,
            completed_at=time.time()
        )
        return ReceiptEnvelope.seal(inv)

    def dispatch_call(self, *args, **kwargs):
        """
        Backward-compatible adapter. New production callers should use
        invoke_with_resilience so the gateway boundary is visible at call sites.
        """
        return self.invoke_with_resilience(*args, **kwargs)

    def invoke_with_resilience(
        self,
        model_slug: str,
        model_family: str,
        provider: str,
        route_env: ReceiptEnvelope[RouteAttestationReceipt],
        qual_env: ReceiptEnvelope[ModelQualificationReceipt],
        packet_env: ReceiptEnvelope[PacketSensitivityReceipt],
        budget_env: Optional[ReceiptEnvelope[PaidBudgetReservationReceipt]],
        prompt_text: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 512,
        response_format: Optional[Dict[str, Any]] = None,
        tool_schemas: Optional[List[Dict[str, Any]]] = None,
        provider_parameters: Optional[Dict[str, Any]] = None,
        context_engine: Optional[LogDerivedContextEngine] = None,
        timeout_sec: float = 60.0,
        prompt_id: Optional[str] = None,
        prompt_version: Optional[str] = None,
        prompt_registry: Optional[PromptConfigRegistry] = None
    ) -> Tuple[Optional[ReceiptEnvelope[ModelInvocationReceipt]], Optional[str]]:
        """
        Dispatches model request through:
        1. Mandatory context engine presence check.
        2. Prompt & Config Registry resolution (if prompt_id provided).
        3. Format request using attested route endpoint and provider.
        4. Context log-derived wire-payload & route verification (throws LogReconstructionDesyncError).
        5. Pure deterministic pre-dispatch verification gate (throws VerificationError).
        6. Circuit breaker & rate limiter checks.
        7. Network HTTP dispatch.
        8. Model invocation receipt sealing.
        """
        if context_engine is None:
            raise ValueError(
                "Mandatory LogDerivedContextEngine must be supplied for model dispatch to guarantee append-only provenance."
            )

        # Step 0: Resolve & verify registered prompt config if specified
        system_prompt, response_format, tool_schemas, provider_parameters, _ = self.resolve_prompt_config(
            prompt_id=prompt_id,
            prompt_version=prompt_version,
            prompt_registry=prompt_registry,
            system_prompt=system_prompt,
            response_format=response_format,
            tool_schemas=tool_schemas,
            provider_parameters=provider_parameters,
        )

        route = route_env.payload
        route_id = route.route_id

        # Step 1: Format Request per Protocol using attested route parameters
        target_url, headers, payload, protocol_type = self._format_request(
            route.endpoint_url,
            route.provider_name,
            model_slug,
            prompt_text,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
            tool_schemas=tool_schemas,
            provider_parameters=provider_parameters
        )

        # Step 2: Context Log-Derived Wire-Payload & Route Attestation Guard
        try:
            context_engine.verify_and_guard_dispatch(
                actual_wire_payload=payload,
                route_env=route_env,
                protocol_type=protocol_type,
                raise_on_desync=True
            )
        except LogReconstructionDesyncError as desync_err:
            self._get_breaker(route_id).record_failure()
            self.dlq.record_failure(model_slug, "SCHEMA_VIOLATION", prompt_text, str(desync_err))
            raise desync_err

        # Step 3: Pure Deterministic Pre-Dispatch Verification Gate (CouncilReceiptVerifier)
        try:
            CouncilReceiptVerifier.verify_model_predispatch(
                route_env=route_env,
                packet_env=packet_env,
                qual_env=qual_env,
                budget_env=budget_env,
                model_slug=model_slug,
                model_family=model_family,
                provider=provider
            )
        except VerificationError as v_err:
            self._get_breaker(route_id).record_failure()
            self.dlq.record_failure(model_slug, "ROUTE_DENIED", prompt_text, str(v_err))
            raise v_err

        req_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()

        # Step 4: Semantic / AST Cache Check
        cache_hit = self.semantic_cache.lookup(
            model_slug=model_slug,
            provider=provider,
            route_id=route_id,
            system_prompt=system_prompt,
            prompt_text=prompt_text,
            sensitivity_tier=packet_env.payload.sensitivity_tier,
            response_format=response_format,
            tool_schemas=tool_schemas,
            provider_parameters=provider_parameters
        )
        if cache_hit:
            raw_resp = cache_hit.entry.response_text
            inv_env = self._seal_invocation_receipt(
                model_slug=model_slug,
                model_family=model_family,
                provider=provider,
                route_id=route_id,
                route_env=route_env,
                qual_env=qual_env,
                packet_env=packet_env,
                budget_env=budget_env,
                request_payload_sha256=req_hash,
                raw_response=raw_resp,
                prompt_text=prompt_text,
                latency_ms=0.0
            )
            return inv_env, raw_resp

        # Step 5: Circuit Breaker & Rate Limiter Checks
        limiter = self._get_limiter(route_id)
        breaker = self._get_breaker(route_id)

        if not breaker.can_attempt():
            err_msg = f"Circuit breaker OPEN for route '{route_id}'"
            self.dlq.record_failure(model_slug, "ROUTE_DENIED", prompt_text, err_msg)
            return None, err_msg

        if not limiter.acquire():
            err_msg = f"Rate limit exceeded on route '{route_id}' (429 Backpressure)"
            self.dlq.record_failure(model_slug, "TIMEOUT", prompt_text, err_msg)
            return None, err_msg

        # Step 6: Network HTTP Call
        t0 = time.perf_counter()

        try:
            res = requests.post(target_url, headers=headers, json=payload, timeout=timeout_sec)
            res.raise_for_status()
            raw_resp = self._extract_response_text(res.json(), protocol_type)
            latency = round((time.perf_counter() - t0) * 1000.0, 2)

            breaker.record_success()
            self.semantic_cache.store(
                model_slug=model_slug,
                provider=provider,
                route_id=route_id,
                system_prompt=system_prompt,
                prompt_text=prompt_text,
                sensitivity_tier=packet_env.payload.sensitivity_tier,
                response_text=raw_resp,
                response_format=response_format,
                tool_schemas=tool_schemas,
                provider_parameters=provider_parameters,
                metadata={"source": "model_gateway.invoke_with_resilience"}
            )

            return self._seal_invocation_receipt(
                model_slug=model_slug,
                model_family=model_family,
                provider=provider,
                route_id=route_id,
                route_env=route_env,
                qual_env=qual_env,
                packet_env=packet_env,
                budget_env=budget_env,
                request_payload_sha256=req_hash,
                raw_response=raw_resp,
                prompt_text=prompt_text,
                latency_ms=latency
            ), raw_resp

        except Exception as e:
            breaker.record_failure()
            err_msg = f"Invocation failed on '{route_id}': {str(e)}"
            self.dlq.record_failure(model_slug, "SCHEMA_VIOLATION", prompt_text, err_msg)
            return None, None

    def dispatch_qualification_probe(
        self,
        model_slug: str,
        model_family: str,
        provider: str,
        route_env: ReceiptEnvelope[RouteAttestationReceipt],
        prompt_text: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 512,
        context_engine: Optional[LogDerivedContextEngine] = None,
        timeout_sec: float = 60.0,
        prompt_id: Optional[str] = None,
        prompt_version: Optional[str] = None,
        prompt_registry: Optional[PromptConfigRegistry] = None
    ) -> Tuple[Optional[ReceiptEnvelope[QualificationProbeInvocationReceipt]], Optional[str]]:
        """
        Specialized bootstrap probe dispatch for model qualification and benchmark evaluation.
        Emits a distinct QualificationProbeInvocationReceipt that CANNOT enter a council vote.
        """
        route = route_env.payload
        CouncilReceiptVerifier.verify_route_attestation(route_env)

        system_prompt, _, _, _, _ = self.resolve_prompt_config(
            prompt_id=prompt_id,
            prompt_version=prompt_version,
            prompt_registry=prompt_registry,
            system_prompt=system_prompt,
        )

        target_url, headers, payload, protocol_type = self._format_request(
            route.endpoint_url,
            route.provider_name,
            model_slug,
            prompt_text,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens
        )

        if context_engine is None:
            raise ValueError(
                "Mandatory LogDerivedContextEngine must be supplied for qualification probe dispatch."
            )

        try:
            context_engine.verify_and_guard_dispatch(
                actual_wire_payload=payload,
                route_env=route_env,
                protocol_type=protocol_type,
                raise_on_desync=True
            )
        except LogReconstructionDesyncError as desync_err:
            self._get_breaker(route.route_id).record_failure()
            self.dlq.record_failure(model_slug, "SCHEMA_VIOLATION", prompt_text, str(desync_err))
            raise desync_err

        req_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
        try:
            res = requests.post(target_url, headers=headers, json=payload, timeout=timeout_sec)
            res.raise_for_status()
            raw_resp = self._extract_response_text(res.json(), protocol_type)
            completed_at = time.time()
            resp_hash = hashlib.sha256(raw_resp.encode("utf-8")).hexdigest()

            probe = QualificationProbeInvocationReceipt(
                route_attestation_payload_sha256=route_env.payload_sha256,
                model_slug=model_slug,
                model_family=model_family,
                provider=provider,
                route_id=route.route_id,
                request_payload_sha256=req_hash,
                response_payload_sha256=resp_hash,
                is_qualification_probe=True,
                completed_at=completed_at
            )
            return ReceiptEnvelope.seal(probe), raw_resp
        except Exception as e:
            return None, None
