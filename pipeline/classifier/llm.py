"""Synchronous LLM clients for offline setup only (never the proxy path)."""

from dataclasses import dataclass, field
import os
import time
from typing import Any

import httpx

from pipeline.classifier.schema import ClassificationResult
from common.features import enabled

TIMEOUT_SECONDS = 60.0
MAX_RETRIES = 2


class LLMError(RuntimeError):
    """Sanitized provider failure; never includes response bodies or API keys."""


class LLMConfigurationError(LLMError):
    pass


@dataclass(frozen=True)
class Settings:
    provider: str
    model: str
    api_key: str = field(default="", repr=False)
    ollama_url: str = "http://127.0.0.1:11434"
    timeout: float = TIMEOUT_SECONDS


def settings_from_env() -> Settings:
    provider = os.getenv("BLADE_LLM_PROVIDER", "").strip().lower()
    if provider not in {"openai", "anthropic", "ollama"}:
        raise LLMConfigurationError("Set BLADE_LLM_PROVIDER to openai, anthropic or ollama")
    model = os.getenv("BLADE_LLM_MODEL", "").strip()
    if not model:
        raise LLMConfigurationError("Set BLADE_LLM_MODEL")
    key_name = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}.get(provider)
    key = os.getenv(key_name, "").strip() if key_name else ""
    if key_name and not key:
        raise LLMConfigurationError(f"Set {key_name}")
    try:
        timeout = float(os.getenv("BLADE_LLM_TIMEOUT", str(TIMEOUT_SECONDS)))
    except ValueError:
        raise LLMConfigurationError("BLADE_LLM_TIMEOUT must be a number of seconds") from None
    return Settings(provider, model, key, os.getenv("BLADE_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/"), timeout)


def _request(settings: Settings, system: str, user: str, response_schema: dict | None = None,
             json_format: bool = True) -> tuple[str, dict[str, str], dict[str, Any]]:
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    if settings.provider == "openai":
        return "https://api.openai.com/v1/responses", {"Authorization": f"Bearer {settings.api_key}"}, {
            "model": settings.model, "instructions": system, "input": user,
            "text": {"format": {"type": "json_object"}}, "store": False,
        }
    if settings.provider == "anthropic":
        return "https://api.anthropic.com/v1/messages", {
            "x-api-key": settings.api_key, "anthropic-version": "2023-06-01",
        }, {"model": settings.model, "system": system, "messages": messages[1:], "max_tokens": 2048}
    if settings.provider == "ollama":
        body = {"model": settings.model, "messages": messages, "stream": False, "options": {"temperature": 0}}
        if json_format:
            body["format"] = response_schema or _ollama_schema()
        return f"{settings.ollama_url}/api/chat", {}, body
    raise LLMConfigurationError("Provider adapter is not implemented")


def _ollama_schema() -> dict[str, Any]:
    """Constrain object-policy outputs to include a lookup, without choosing labels."""
    schema = ClassificationResult.model_json_schema()
    if not enabled('BLADE_RAG_ENABLED'):
        schema['properties'].pop('evidence_refs', None)
        schema['$defs'].pop('EvidenceRef', None)
    branches = []
    for labels, object_policy in (
        (["owner_match", "owner_or_admin", "tenant_match"], True),
        (["public", "role_required", "membership_required", "manual_review_required"], False),
    ):
        properties = {**schema["properties"], "label": {"type": "string", "enum": labels},
                      "object_param": {"type": "string" if object_policy else "null"},
                      "owner_lookup": {"$ref": "#/$defs/OwnerLookup"} if object_policy else {"type": "null"}}
        branches.append({"type": "object", "properties": properties,
                         "required": schema["required"], "additionalProperties": False})
    return {"type": "object", "$defs": schema["$defs"], "oneOf": branches}


def _text(provider: str, data: Any, allow_truncated: bool = False) -> str:
    try:
        if provider == "openai":
            if data.get("status") != "completed":
                raise ValueError("Incomplete response")
            result = "".join(part["text"] for item in data["output"] if item.get("type") == "message"
                             for part in item["content"] if part.get("type") == "output_text")
        elif provider == "anthropic":
            if data.get("stop_reason") != "end_turn":
                raise ValueError("Incomplete response")
            result = "".join(part["text"] for part in data["content"] if part.get("type") == "text")
        elif provider == "ollama":
            if data.get("done") is not True or (data.get("done_reason") == "length" and not allow_truncated):
                raise ValueError("Incomplete response")
            result = data["message"]["content"]
        else:
            raise LLMConfigurationError("Provider adapter is not implemented")
        if not isinstance(result, str) or not result.strip():
            raise ValueError("Empty response")
        return result
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise LLMError("Provider returned no complete text response") from exc


def complete(system: str, user: str, *, response_schema: dict | None = None, settings: Settings | None = None,
             json_format: bool = True, allow_truncated: bool = False) -> str:
    """One initial request plus up to two retries for transport/429/5xx errors.

    HTTPX connect/read/write/pool timeouts are each settings.timeout (default 60) seconds per attempt.
    Non-transient 4xx and malformed provider responses fail immediately.
    settings overrides BLADE_LLM_* (the LoRA classifier names its own Ollama model). json_format=False sends
    no Ollama format constraint and allow_truncated returns text cut at num_predict instead of failing.
    """
    settings = settings or settings_from_env()
    url, headers, body = _request(settings, system, user, response_schema, json_format)
    with httpx.Client(timeout=settings.timeout) as client:
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = client.post(url, headers=headers, json=body)
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                code = exc.response.status_code
                if (code != 429 and code < 500) or attempt == MAX_RETRIES:
                    raise LLMError(f"{settings.provider} HTTP {code}") from None
            except httpx.TransportError:
                if attempt == MAX_RETRIES:
                    raise LLMError(f"{settings.provider} transport failure after 3 attempts") from None
            else:
                try:
                    data = response.json()
                except ValueError:
                    raise LLMError("Provider returned invalid response JSON") from None
                return _text(settings.provider, data, allow_truncated)
            time.sleep(2 ** attempt)
    raise AssertionError("Unreachable retry state")
