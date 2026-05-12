"""Unified LLM-call interface for AgentForge.

Routes each agent role to the correct model + backend (OpenRouter or local Ollama),
handles fallback chains, exponential-backoff retries, cost accounting, and a hard
budget ceiling guard.

Usage::

    from agentforge.llm import chat, chat_json, Role

    result = chat([{"role": "user", "content": "Hello"}], role=Role.JUDGE)
    result, parsed = chat_json([{"role": "user", "content": "Return {\"ok\": true}"}], role=Role.JUDGE)

Backend routing
---------------
* ``RED_TEAM`` + ``model_backend == "ollama"`` → local Ollama at
  ``ollama_base_url``/v1 using ``ollama_red_team_model``.
* Every other combination → OpenRouter. In particular, JUDGE / MUTATION /
  ORCHESTRATOR / DOCUMENTATION always use OpenRouter regardless of
  ``model_backend``, because those roles need a more-capable model family
  than the local 7B.

Retry policy
------------
Transient errors (HTTP 429, 5xx, timeouts, connection errors) are retried up to
3 times with exponential back-off: 1 s → 2 s → 4 s, each with ±25% jitter.
After all retries are exhausted ``LLMCallError`` is raised.

For ``RED_TEAM`` on OpenRouter the primary model is tried first; if it raises
any error (including non-transient ones such as 403 / model-not-found) the
fallback model ``openrouter_red_team_fallback`` is used with the same retry
policy.

Cost accounting
---------------
A module-level running total is kept. ``chat()`` accepts an optional
``budget_ceiling_usd`` guard: if ``get_cost_total() + estimated_cost`` would
exceed the ceiling, ``BudgetExceededError`` is raised *before* the call is made.

Prices in ``_PRICE_TABLE`` are in USD per million tokens (input, output).
They are indicative/placeholder values — verify against openrouter.ai/models
before any real budget run.
"""

from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI

from agentforge.config import Settings, get_settings

logger = logging.getLogger("agentforge.llm")

# --------------------------------------------------------------------------- #
# Price table — USD per *million* tokens (input_per_mtok, output_per_mtok).
# These are placeholder values; verify at openrouter.ai/models before any
# real budget-sensitive run.
# --------------------------------------------------------------------------- #
_PRICE_TABLE: dict[str, tuple[float, float]] = {
    # WhiteRabbitNeo-70B (Llama-3-based, authorized-security-testing fine-tune)
    "cognitivecomputations/whiterabbitneo-70b": (0.90, 0.90),
    # Dolphin-3-Llama-70B (RED_TEAM fallback)
    "cognitivecomputations/dolphin-3.0-llama3.1-70b": (0.90, 0.90),
    # Qwen3-32B (MUTATION + ORCHESTRATOR)
    "qwen/qwen3-32b": (0.10, 0.30),
    # Mistral-Large-2411 (JUDGE)
    "mistralai/mistral-large-2411": (2.00, 6.00),
    # Llama-3.1-8B-Instruct (DOCUMENTATION)
    "meta-llama/llama-3.1-8b-instruct": (0.06, 0.06),
}

# --------------------------------------------------------------------------- #
# Module-level running cost total
# --------------------------------------------------------------------------- #
_cost_total: float = 0.0


def get_cost_total() -> float:
    """Return the accumulated cost (USD) across all ``chat()`` calls in this process."""
    return _cost_total


def reset_cost_total() -> None:
    """Reset the running cost total to zero (useful between test runs / campaigns)."""
    global _cost_total
    _cost_total = 0.0


# --------------------------------------------------------------------------- #
# Public enums and dataclasses
# --------------------------------------------------------------------------- #
class Role(StrEnum):
    """The logical role of an LLM call within AgentForge.

    Maps to a specific model (and possibly a different backend) as documented
    in ``ARCHITECTURE.md`` — "Model strategy" section.
    """

    RED_TEAM = "red_team"
    MUTATION = "mutation"
    JUDGE = "judge"
    DOCUMENTATION = "documentation"
    ORCHESTRATOR = "orchestrator"


@dataclass(frozen=True, slots=True)
class ChatResult:
    """The result of a single :func:`chat` call."""

    text: str
    model_used: str
    backend: str  # "openrouter" | "ollama"
    usage: dict[str, int]  # {"input": ..., "output": ...}
    cost_usd: float


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class LLMCallError(RuntimeError):
    """Raised when an LLM call fails after all retries, or when JSON parsing fails."""


class BudgetExceededError(RuntimeError):
    """Raised *before* a call is made when it would push the running total past the ceiling."""


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
_MAX_RETRIES = 3
_BASE_BACKOFF_S = 1.0
_JITTER_FRACTION = 0.25


def _is_transient(exc: Exception) -> bool:
    """Return True for errors that are worth retrying."""
    if isinstance(exc, APIConnectionError | APITimeoutError):
        return True
    if isinstance(exc, APIStatusError):
        return exc.status_code in {429, 500, 502, 503, 504}
    return False


def _backoff(attempt: int) -> float:
    """Exponential back-off with ±25% jitter. attempt is 0-indexed."""
    base = _BASE_BACKOFF_S * (2**attempt)
    jitter = base * _JITTER_FRACTION * (2 * random.random() - 1)
    return max(0.0, base + jitter)


def _make_client(base_url: str, api_key: str) -> OpenAI:
    """Build an ``OpenAI`` client pointed at the given endpoint."""
    return OpenAI(
        base_url=base_url,
        api_key=api_key,
        default_headers={
            "HTTP-Referer": "https://github.com/Hvoegeli/agentforge",
            "X-Title": "AgentForge",
        },
    )


def _resolve_routing(role: Role, settings: Settings) -> tuple[str, str, str]:
    """Return (base_url, api_key, model_name) for a given role + settings.

    RED_TEAM is the only role that may use the Ollama backend. All other roles
    always use OpenRouter regardless of ``model_backend``, because the Judge,
    Mutation, Orchestrator, and Documentation roles need a different (and often
    more capable) model family than the local 7B.
    """
    if role is Role.RED_TEAM and settings.model_backend == "ollama":
        base_url = settings.ollama_base_url.rstrip("/") + "/v1"
        api_key = "ollama"
        model = settings.ollama_red_team_model
        return base_url, api_key, model

    # All other cases → OpenRouter
    base_url = _OPENROUTER_BASE_URL
    api_key = settings.openrouter_api_key
    model = _openrouter_model(role, settings)
    return base_url, api_key, model


def _openrouter_model(role: Role, settings: Settings) -> str:
    """Return the OpenRouter model slug for a given role."""
    match role:
        case Role.RED_TEAM:
            return settings.openrouter_red_team_model
        case Role.MUTATION | Role.ORCHESTRATOR:
            return settings.openrouter_mutation_model
        case Role.JUDGE:
            return settings.openrouter_judge_model
        case Role.DOCUMENTATION:
            return settings.openrouter_docs_model


def _compute_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in USD using the price table.

    Logs a warning and returns 0.0 if the model is not in the table.
    """
    if model not in _PRICE_TABLE:
        logger.warning(
            "Model not in price table — cost will be 0.0. Verify price at openrouter.ai/models.",
            extra={"model": model},
        )
        return 0.0
    in_per_mtok, out_per_mtok = _PRICE_TABLE[model]
    return (input_tokens * in_per_mtok + output_tokens * out_per_mtok) / 1_000_000.0


def _estimate_tokens_from_messages(messages: list[dict[str, str]]) -> int:
    """Rough token estimate: 1 token ≈ 4 chars. Used only when the API returns no usage."""
    total_chars = sum(len(m.get("content", "")) for m in messages)
    return max(1, total_chars // 4)


def _estimate_output_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _call_with_retries(
    client: OpenAI,
    model: str,
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int,
    extra_kwargs: dict[str, Any],
) -> Any:
    """Call ``client.chat.completions.create`` with exponential-backoff retries.

    Retries on transient errors (429, 5xx, timeouts, connection errors).
    Raises ``LLMCallError`` after ``_MAX_RETRIES`` failed attempts.
    """
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            return client.chat.completions.create(
                model=model,
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
                **extra_kwargs,
            )
        except Exception as exc:
            last_exc = exc
            if not _is_transient(exc):
                raise LLMCallError(f"Non-transient error calling model '{model}'") from exc
            wait = _backoff(attempt)
            logger.warning(
                "Transient LLM error; retrying after %.2fs (attempt %d/%d)",
                wait,
                attempt + 1,
                _MAX_RETRIES,
                extra={"model": model, "error": str(exc)},
            )
            time.sleep(wait)
    raise LLMCallError(f"LLM call to '{model}' failed after {_MAX_RETRIES} retries") from last_exc


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def chat(
    messages: list[dict[str, str]],
    *,
    role: Role,
    settings: Settings | None = None,
    temperature: float = 0.7,
    max_tokens: int = 2048,
    json_mode: bool = False,
    budget_ceiling_usd: float | None = None,
) -> ChatResult:
    """Make a chat-completion call routed to the correct model + backend for ``role``.

    Parameters
    ----------
    messages:
        OpenAI-style message list, e.g. ``[{"role": "user", "content": "..."}]``.
    role:
        The logical agent role. Determines which model and backend to use.
    settings:
        Settings snapshot. Defaults to ``get_settings()`` if omitted.
    temperature:
        Sampling temperature passed to the provider.
    max_tokens:
        Maximum tokens in the completion.
    json_mode:
        If ``True``, request structured JSON output. Uses
        ``response_format={"type": "json_object"}`` on OpenRouter; for Ollama
        (which may not support the parameter), appends a plain-English
        instruction to the last message instead.
    budget_ceiling_usd:
        If set, raises ``BudgetExceededError`` *before* the call is made when
        the running cost total would exceed this value.

    Returns
    -------
    ChatResult
        The completion text, metadata, token counts, and cost.

    Raises
    ------
    LLMCallError
        On exhausted retries or non-transient provider errors.
    BudgetExceededError
        When the budget ceiling would be breached.
    """
    global _cost_total

    s = settings or get_settings()
    base_url, api_key, model = _resolve_routing(role, s)
    backend = "ollama" if api_key == "ollama" else "openrouter"

    # Estimate cost for budget guard (rough — real cost computed after the call)
    if budget_ceiling_usd is not None:
        estimated_input = _estimate_tokens_from_messages(messages)
        estimated_output = max_tokens
        estimated_cost = _compute_cost(model, estimated_input, estimated_output)
        if _cost_total + estimated_cost > budget_ceiling_usd:
            raise BudgetExceededError(
                f"Budget ceiling ${budget_ceiling_usd:.4f} would be exceeded "
                f"(current total ${_cost_total:.4f}, estimated call ${estimated_cost:.4f})"
            )

    # Build extra kwargs
    extra_kwargs: dict[str, Any] = {}
    effective_messages = list(messages)
    if json_mode:
        if backend == "openrouter":
            extra_kwargs["response_format"] = {"type": "json_object"}
        else:
            # Ollama may not support response_format; append a plain instruction.
            effective_messages = list(messages)
            if effective_messages:
                last = dict(effective_messages[-1])
                last["content"] = last.get("content", "") + "\nRespond with valid JSON only."
                effective_messages[-1] = last

    client = _make_client(base_url, api_key)

    # For RED_TEAM on OpenRouter: try the primary model, fall back on any error.
    if role is Role.RED_TEAM and backend == "openrouter":
        try:
            response = _call_with_retries(
                client, model, effective_messages, temperature, max_tokens, extra_kwargs
            )
        except (LLMCallError, Exception):
            fallback_model = s.openrouter_red_team_fallback
            logger.warning(
                "RED_TEAM primary model failed; switching to fallback.",
                extra={"primary": model, "fallback": fallback_model},
            )
            try:
                response = _call_with_retries(
                    client,
                    fallback_model,
                    effective_messages,
                    temperature,
                    max_tokens,
                    extra_kwargs,
                )
                model = fallback_model
            except Exception as fb_exc:
                raise LLMCallError(
                    f"RED_TEAM call failed on both primary '{model}' and fallback '{fallback_model}'"
                ) from fb_exc
    else:
        response = _call_with_retries(
            client, model, effective_messages, temperature, max_tokens, extra_kwargs
        )

    # Extract text
    text: str = response.choices[0].message.content or ""

    # Extract token usage
    usage_obj = getattr(response, "usage", None)
    if usage_obj is not None:
        input_tokens = int(getattr(usage_obj, "prompt_tokens", 0) or 0)
        output_tokens = int(getattr(usage_obj, "completion_tokens", 0) or 0)
    else:
        input_tokens = _estimate_tokens_from_messages(messages)
        output_tokens = _estimate_output_tokens(text)

    usage: dict[str, int] = {"input": input_tokens, "output": output_tokens}
    cost = _compute_cost(model, input_tokens, output_tokens)

    _cost_total += cost

    logger.debug(
        "LLM call complete",
        extra={
            "role": role,
            "model": model,
            "backend": backend,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost,
        },
    )

    return ChatResult(
        text=text,
        model_used=model,
        backend=backend,
        usage=usage,
        cost_usd=cost,
    )


def chat_json(
    messages: list[dict[str, str]],
    *,
    role: Role,
    settings: Settings | None = None,
    temperature: float = 0.7,
    max_tokens: int = 2048,
    budget_ceiling_usd: float | None = None,
) -> tuple[ChatResult, dict[str, Any] | list[Any]]:
    """Convenience wrapper: calls :func:`chat` with ``json_mode=True`` and parses the result.

    Returns
    -------
    tuple[ChatResult, dict | list]
        The raw ``ChatResult`` and the parsed JSON object.

    Raises
    ------
    LLMCallError
        If the LLM call fails, or if the response text is not valid JSON.
    """
    result = chat(
        messages,
        role=role,
        settings=settings,
        temperature=temperature,
        max_tokens=max_tokens,
        json_mode=True,
        budget_ceiling_usd=budget_ceiling_usd,
    )
    try:
        parsed = json.loads(result.text)
    except json.JSONDecodeError as exc:
        raise LLMCallError(f"LLM returned invalid JSON for role '{role}': {exc!s}") from exc
    return result, parsed
