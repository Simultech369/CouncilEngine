import ast
import hashlib
import json
import os
import re
import time
from typing import Dict, List, Literal, Optional, Set

from council_contracts import ImmutableContract


class SemanticPromptFingerprint(ImmutableContract):
    prompt_sha256: str
    normalized_prompt_sha256: str
    ast_sha256: Optional[str]
    lexical_signature_sha256: str
    semantic_terms: List[str]


class SemanticCacheEntry(ImmutableContract):
    cache_key: str
    model_slug: str
    provider: str
    route_id: str
    sensitivity_tier: str
    system_prompt_sha256: str
    response_format_sha256: str
    tool_schemas_sha256: str
    provider_parameters_sha256: str
    fingerprint: SemanticPromptFingerprint
    response_sha256: str
    response_text: str
    metadata: Dict[str, str]
    created_at: float
    last_hit_at: Optional[float] = None
    hit_count: int = 0


class SemanticCacheHit(ImmutableContract):
    entry: SemanticCacheEntry
    hit_type: Literal["EXACT", "AST_SEMANTIC", "LEXICAL_SEMANTIC"]
    similarity_score: float
    hit_at: float


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_json(value) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return _sha256_text(payload)


class SemanticASTCache:
    """
    Deterministic semantic cache for model prompts.
    Exact hits use canonical request fields; semantic hits require the same route context plus AST or lexical similarity.
    """

    CODE_FENCE_RE = re.compile(r"```(?:python|py)?\s*([\s\S]*?)```", re.IGNORECASE)
    TOKEN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{1,}|[0-9]+")

    def __init__(
        self,
        storage_path: Optional[str] = None,
        similarity_threshold: float = 0.92,
        cacheable_sensitivity_tiers: Optional[Set[str]] = None
    ):
        if similarity_threshold < 0.0 or similarity_threshold > 1.0:
            raise ValueError("similarity_threshold must be within [0.0, 1.0]")
        self.storage_path = storage_path
        self.similarity_threshold = similarity_threshold
        self.cacheable_sensitivity_tiers = cacheable_sensitivity_tiers or {"PUBLIC_SAFE"}
        self.entries: Dict[str, SemanticCacheEntry] = {}
        self._load()

    def _load(self) -> None:
        if not self.storage_path or not os.path.exists(self.storage_path):
            return
        with open(self.storage_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.entries = {
            item["cache_key"]: SemanticCacheEntry(**item)
            for item in data.get("entries", [])
        }

    def _persist(self) -> None:
        if not self.storage_path:
            return
        parent = os.path.dirname(os.path.abspath(self.storage_path))
        os.makedirs(parent, exist_ok=True)
        tmp_path = self.storage_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump({"entries": [entry.model_dump() for entry in self.entries.values()]}, f, sort_keys=True)
        os.replace(tmp_path, self.storage_path)

    def _extract_code_candidates(self, prompt_text: str) -> List[str]:
        fenced = [match.group(1).strip() for match in self.CODE_FENCE_RE.finditer(prompt_text) if match.group(1).strip()]
        return fenced + [prompt_text]

    def _compute_ast_sha256(self, prompt_text: str) -> Optional[str]:
        ast_dumps = []
        for candidate in self._extract_code_candidates(prompt_text):
            try:
                tree = ast.parse(candidate)
                ast_dumps.append(ast.dump(tree, annotate_fields=True, include_attributes=False))
            except SyntaxError:
                continue
        if not ast_dumps:
            return None
        return _sha256_json(sorted(ast_dumps))

    def compute_fingerprint(self, prompt_text: str) -> SemanticPromptFingerprint:
        normalized = " ".join(prompt_text.split()).lower()
        terms = sorted(set(term.lower() for term in self.TOKEN_RE.findall(normalized)))
        return SemanticPromptFingerprint(
            prompt_sha256=_sha256_text(prompt_text),
            normalized_prompt_sha256=_sha256_text(normalized),
            ast_sha256=self._compute_ast_sha256(prompt_text),
            lexical_signature_sha256=_sha256_json(terms),
            semantic_terms=terms
        )

    def _cache_key(
        self,
        model_slug: str,
        provider: str,
        route_id: str,
        system_prompt: str,
        prompt_text: str,
        response_format=None,
        tool_schemas=None,
        provider_parameters=None
    ) -> str:
        return _sha256_json({
            "model_slug": model_slug,
            "provider": provider,
            "route_id": route_id,
            "system_prompt_sha256": _sha256_text(system_prompt),
            "prompt_sha256": _sha256_text(prompt_text),
            "response_format_sha256": _sha256_json(response_format or {}),
            "tool_schemas_sha256": _sha256_json(tool_schemas or []),
            "provider_parameters_sha256": _sha256_json(provider_parameters or {})
        })

    def _same_context(
        self,
        entry: SemanticCacheEntry,
        model_slug: str,
        provider: str,
        route_id: str,
        system_prompt: str,
        response_format=None,
        tool_schemas=None,
        provider_parameters=None
    ) -> bool:
        return (
            entry.model_slug == model_slug and
            entry.provider == provider and
            entry.route_id == route_id and
            entry.system_prompt_sha256 == _sha256_text(system_prompt) and
            entry.response_format_sha256 == _sha256_json(response_format or {}) and
            entry.tool_schemas_sha256 == _sha256_json(tool_schemas or []) and
            entry.provider_parameters_sha256 == _sha256_json(provider_parameters or {})
        )

    @staticmethod
    def _jaccard(left: List[str], right: List[str]) -> float:
        left_set = set(left)
        right_set = set(right)
        if not left_set and not right_set:
            return 1.0
        if not left_set or not right_set:
            return 0.0
        return len(left_set & right_set) / len(left_set | right_set)

    def lookup(
        self,
        model_slug: str,
        provider: str,
        route_id: str,
        system_prompt: str,
        prompt_text: str,
        sensitivity_tier: str,
        response_format=None,
        tool_schemas=None,
        provider_parameters=None
    ) -> Optional[SemanticCacheHit]:
        if sensitivity_tier not in self.cacheable_sensitivity_tiers:
            return None

        cache_key = self._cache_key(
            model_slug, provider, route_id, system_prompt, prompt_text,
            response_format=response_format,
            tool_schemas=tool_schemas,
            provider_parameters=provider_parameters
        )
        now = time.time()
        if cache_key in self.entries:
            return self._mark_hit(cache_key, "EXACT", 1.0, now)

        fingerprint = self.compute_fingerprint(prompt_text)
        best_key = None
        best_hit_type = None
        best_score = 0.0
        for key, entry in self.entries.items():
            if entry.sensitivity_tier != sensitivity_tier:
                continue
            if not self._same_context(
                entry, model_slug, provider, route_id, system_prompt,
                response_format=response_format,
                tool_schemas=tool_schemas,
                provider_parameters=provider_parameters
            ):
                continue
            if entry.fingerprint.ast_sha256 and entry.fingerprint.ast_sha256 == fingerprint.ast_sha256:
                best_key = key
                best_hit_type = "AST_SEMANTIC"
                best_score = 1.0
                break
            lexical_score = self._jaccard(entry.fingerprint.semantic_terms, fingerprint.semantic_terms)
            if lexical_score >= self.similarity_threshold and lexical_score > best_score:
                best_key = key
                best_hit_type = "LEXICAL_SEMANTIC"
                best_score = lexical_score

        if best_key and best_hit_type:
            return self._mark_hit(best_key, best_hit_type, round(best_score, 6), now)
        return None

    def _mark_hit(self, cache_key: str, hit_type: str, score: float, hit_at: float) -> SemanticCacheHit:
        entry = self.entries[cache_key]
        updated = entry.model_copy(update={
            "last_hit_at": hit_at,
            "hit_count": entry.hit_count + 1
        })
        self.entries[cache_key] = updated
        self._persist()
        return SemanticCacheHit(entry=updated, hit_type=hit_type, similarity_score=score, hit_at=hit_at)

    def store(
        self,
        model_slug: str,
        provider: str,
        route_id: str,
        system_prompt: str,
        prompt_text: str,
        sensitivity_tier: str,
        response_text: str,
        response_format=None,
        tool_schemas=None,
        provider_parameters=None,
        metadata: Optional[Dict[str, str]] = None
    ) -> Optional[SemanticCacheEntry]:
        if sensitivity_tier not in self.cacheable_sensitivity_tiers:
            return None

        cache_key = self._cache_key(
            model_slug, provider, route_id, system_prompt, prompt_text,
            response_format=response_format,
            tool_schemas=tool_schemas,
            provider_parameters=provider_parameters
        )
        entry = SemanticCacheEntry(
            cache_key=cache_key,
            model_slug=model_slug,
            provider=provider,
            route_id=route_id,
            sensitivity_tier=sensitivity_tier,
            system_prompt_sha256=_sha256_text(system_prompt),
            response_format_sha256=_sha256_json(response_format or {}),
            tool_schemas_sha256=_sha256_json(tool_schemas or []),
            provider_parameters_sha256=_sha256_json(provider_parameters or {}),
            fingerprint=self.compute_fingerprint(prompt_text),
            response_sha256=_sha256_text(response_text),
            response_text=response_text,
            metadata=metadata or {},
            created_at=time.time()
        )
        self.entries[cache_key] = entry
        self._persist()
        return entry
