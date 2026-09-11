"""Deterministic prompt and model-config registry with cryptographic hashes."""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Dict, List, Literal, Optional, Tuple

from council_contracts import (
    ImmutableContract,
    PromptConfigRegistryReceipt,
    ReceiptEnvelope,
)

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def normalize_system_prompt(system_prompt: str) -> str:
    """Normalize line endings and trailing whitespace before prompt hashing."""

    normalized = system_prompt.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.strip().split("\n"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PromptConfigVersionRecord(ImmutableContract):
    prompt_id: str
    version: str
    stage: Literal["DRAFT", "CANDIDATE", "ACTIVE", "DEPRECATED"]
    system_prompt: str
    system_prompt_sha256: str
    normalized_system_prompt_sha256: str
    response_format_sha256: str
    tool_schemas_sha256: str
    provider_parameters_sha256: str
    config_sha256: str
    parent_version_sha256: Optional[str] = None
    rationale: str = ""
    created_by: str = "operator"
    created_at: float


class PromptConfigRegistry:
    """Append-only in-memory registry for trusted system prompts and configs."""

    def __init__(self, registry_id: str = "council_prompt_registry") -> None:
        _validate_identifier("registry_id", registry_id)
        self.registry_id = registry_id
        self._versions: Dict[Tuple[str, str], PromptConfigVersionRecord] = {}
        self._active: Dict[str, str] = {}

    def register_prompt_version(
        self,
        *,
        prompt_id: str,
        version: str,
        system_prompt: str,
        response_format: Optional[Any] = None,
        tool_schemas: Optional[List[Dict[str, Any]]] = None,
        provider_parameters: Optional[Dict[str, Any]] = None,
        rationale: str = "",
        created_by: str = "operator",
        stage: Literal["DRAFT", "CANDIDATE", "ACTIVE"] = "CANDIDATE",
        parent_version: Optional[str] = None,
        created_at: Optional[float] = None,
    ) -> PromptConfigVersionRecord:
        _validate_identifier("prompt_id", prompt_id)
        _validate_identifier("version", version)
        if not system_prompt or not system_prompt.strip():
            raise ValueError("system_prompt must be non-empty")
        if (prompt_id, version) in self._versions:
            raise ValueError(f"prompt version already exists: {prompt_id}@{version}")

        parent_hash = None
        if parent_version is not None:
            parent = self.get_version(prompt_id, parent_version)
            parent_hash = parent.compute_canonical_sha256()

        normalized_prompt = normalize_system_prompt(system_prompt)
        response_hash = sha256_json(response_format or {})
        tools_hash = sha256_json(tool_schemas or [])
        provider_hash = sha256_json(provider_parameters or {})
        config_hash = sha256_json(
            {
                "provider_parameters_sha256": provider_hash,
                "response_format_sha256": response_hash,
                "tool_schemas_sha256": tools_hash,
            }
        )

        record = PromptConfigVersionRecord(
            prompt_id=prompt_id,
            version=version,
            stage=stage,
            system_prompt=system_prompt,
            system_prompt_sha256=sha256_text(system_prompt),
            normalized_system_prompt_sha256=sha256_text(normalized_prompt),
            response_format_sha256=response_hash,
            tool_schemas_sha256=tools_hash,
            provider_parameters_sha256=provider_hash,
            config_sha256=config_hash,
            parent_version_sha256=parent_hash,
            rationale=rationale,
            created_by=created_by,
            created_at=time.time() if created_at is None else created_at,
        )
        self._versions[(prompt_id, version)] = record
        if stage == "ACTIVE":
            self._activate_record(prompt_id, version)
        return self._versions[(prompt_id, version)]

    def activate_prompt_version(self, *, prompt_id: str, version: str) -> ReceiptEnvelope:
        self.get_version(prompt_id, version)
        self._activate_record(prompt_id, version)
        return self.export_registry_receipt(active_prompt_id=prompt_id)

    def rollback_prompt_version(self, *, prompt_id: str, target_version: str) -> ReceiptEnvelope:
        return self.activate_prompt_version(prompt_id=prompt_id, version=target_version)

    def get_version(self, prompt_id: str, version: str) -> PromptConfigVersionRecord:
        try:
            return self._versions[(prompt_id, version)]
        except KeyError as exc:
            raise KeyError(f"unknown prompt version: {prompt_id}@{version}") from exc

    def get_active(self, prompt_id: str) -> PromptConfigVersionRecord:
        try:
            version = self._active[prompt_id]
        except KeyError as exc:
            raise KeyError(f"no active prompt version for: {prompt_id}") from exc
        return self.get_version(prompt_id, version)

    def has_prompt(self, prompt_id: str) -> bool:
        return prompt_id in self._active

    def has_version(self, prompt_id: str, version: str) -> bool:
        return (prompt_id, version) in self._versions

    def get_active_prompt(self, prompt_id: str) -> str:
        return self.get_active(prompt_id).system_prompt

    def list_versions(self, prompt_id: Optional[str] = None) -> List[PromptConfigVersionRecord]:
        records = [
            record
            for (record_prompt_id, _), record in self._versions.items()
            if prompt_id is None or record_prompt_id == prompt_id
        ]
        return sorted(records, key=lambda record: (record.prompt_id, record.version))

    def export_registry_receipt(self, *, active_prompt_id: str) -> ReceiptEnvelope:
        active = self.get_active(active_prompt_id)
        prompt_ids = sorted({prompt_id for prompt_id, _ in self._versions})
        receipt = PromptConfigRegistryReceipt(
            registry_id=self.registry_id,
            active_prompt_id=active.prompt_id,
            active_version=active.version,
            active_system_prompt_sha256=active.normalized_system_prompt_sha256,
            active_config_sha256=active.config_sha256,
            version_manifest_sha256=self._manifest_sha256(),
            version_count=len(self._versions),
            prompt_ids=prompt_ids,
        )
        return ReceiptEnvelope.seal(receipt)

    def _activate_record(self, prompt_id: str, version: str) -> None:
        previous_version = self._active.get(prompt_id)
        if previous_version is not None and previous_version != version:
            previous = self.get_version(prompt_id, previous_version)
            self._versions[(prompt_id, previous_version)] = previous.model_copy(
                update={"stage": "DEPRECATED"}
            )
        target = self.get_version(prompt_id, version)
        self._versions[(prompt_id, version)] = target.model_copy(update={"stage": "ACTIVE"})
        self._active[prompt_id] = version

    def _manifest_sha256(self) -> str:
        manifest = [
            {
                "prompt_id": record.prompt_id,
                "record_sha256": record.compute_canonical_sha256(),
                "stage": record.stage,
                "version": record.version,
            }
            for record in self.list_versions()
        ]
        return sha256_json(manifest)


def _validate_identifier(field_name: str, value: str) -> None:
    if not value or not _SAFE_ID_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a safe non-empty identifier")
