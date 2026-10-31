"""Model providers. Every call returns JSON shaped by a schema, plus what the AI-in-action panel shows."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

DEFAULT_OLLAMA = "http://127.0.0.1:11434"


@dataclass(frozen=True)
class Call:
    """One model call as the glass-box panel and the eval cache record it."""

    role: str
    model: str
    system: str
    user: str
    schema: Mapping[str, Any]
    raw: str
    parsed: dict[str, Any] | None
    ms: int
    prompt_tokens: int = 0
    output_tokens: int = 0
    error: str | None = None

    @property
    def valid_json(self) -> bool:
        return self.parsed is not None


class ModelDown(Exception):
    """The model endpoint did not answer; the agent switches to questionnaire mode."""


class Provider(Protocol):
    name: str

    def complete(self, role: str, system: str, user: str, schema: Mapping[str, Any]) -> Call: ...


def _parse(raw: str) -> dict[str, Any] | None:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


@dataclass
class OllamaProvider:
    """Local Ollama chat with structured output (the ``format`` JSON schema), temperature 0."""

    model: str
    host: str = DEFAULT_OLLAMA
    timeout: float = 60.0
    num_ctx: int = 4096
    think: bool | str = False
    name: str = field(init=False)

    def __post_init__(self) -> None:
        self.name = self.model

    def complete(self, role: str, system: str, user: str, schema: Mapping[str, Any]) -> Call:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": dict(schema),
            "options": {"temperature": 0, "seed": 1337, "num_ctx": self.num_ctx},
        }
        if self.think is not None:
            body["think"] = self.think
        start = time.perf_counter()
        try:
            response = httpx.post(f"{self.host}/api/chat", json=body, timeout=self.timeout, trust_env=False)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelDown(f"{self.model}: {type(exc).__name__}") from exc
        data = response.json()
        raw = str(data.get("message", {}).get("content", ""))
        return Call(
            role=role,
            model=self.model,
            system=system,
            user=user,
            schema=schema,
            raw=raw,
            parsed=_parse(raw),
            ms=int((time.perf_counter() - start) * 1000),
            prompt_tokens=int(data.get("prompt_eval_count", 0)),
            output_tokens=int(data.get("eval_count", 0)),
        )


@dataclass
class ScriptedProvider:
    """Deterministic stand-in for tests and the offline demo: a function from (role, user) to JSON."""

    script: Callable[[str, str], Mapping[str, Any] | str]
    name: str = "scripted"

    def complete(self, role: str, system: str, user: str, schema: Mapping[str, Any]) -> Call:
        out = self.script(role, user)
        raw = out if isinstance(out, str) else json.dumps(out, ensure_ascii=False)
        return Call(role, self.name, system, user, schema, raw, _parse(raw), ms=0)


@dataclass
class DownProvider:
    """A model that is not there (robustness tests)."""

    name: str = "down"

    def complete(self, role: str, system: str, user: str, schema: Mapping[str, Any]) -> Call:
        raise ModelDown(self.name)


def provider_from_spec(spec: str, script: Callable[[str, str], Mapping[str, Any] | str] | None = None) -> Provider:
    """``ollama:<model>``, ``scripted`` or ``down``."""
    if spec.startswith("ollama:"):
        model = spec.removeprefix("ollama:")
        think: bool | str = "low" if model.startswith("gpt-oss") else False
        return OllamaProvider(model=model, think=think)
    if spec == "scripted":
        if script is None:
            raise ValueError("scripted provider needs a script")
        return ScriptedProvider(script)
    if spec == "down":
        return DownProvider()
    raise ValueError(f"unknown model spec {spec!r}")
