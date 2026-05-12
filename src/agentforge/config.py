"""Environment-backed configuration for AgentForge.

Loads ``.env`` (if present) at import time, then exposes a frozen ``Settings``
snapshot. Business logic should take a ``Settings`` (or the specific values it
needs) rather than reading ``os.environ`` directly — that keeps the env-read at
the edge and makes the rest testable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()  # no-op if there's no .env; never overrides already-set env vars


def _str(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _float(key: str, default: float) -> float:
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    return float(raw)


# Hosts AgentForge is permitted to attack. The Target Adapter refuses to
# construct against anything not on this list (or matching an allowed suffix
# below) — the "no third-party targets" guarantee. (localhost / 127.0.0.1 for the
# dev docker stack; the Hetzner box for the deployed target.)
ALLOWED_TARGET_HOSTS: frozenset[str] = frozenset(
    {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "178.156.242.153"}
)
# Domain suffixes that are also permitted. The deployed Co-Pilot is exposed over a
# Cloudflare quick tunnel (`*.trycloudflare.com`), whose subdomain rotates on every
# `cloudflared` restart, so we allow the suffix rather than pinning an ephemeral
# host. This stays within "no third-party targets" in spirit: the tunnel operator
# (us) controls which trycloudflare URL is live, and `COPILOT_BASE_URL` /
# `--target-url` remains the only way to point the adapter at anything.
ALLOWED_TARGET_HOST_SUFFIXES: frozenset[str] = frozenset({"trycloudflare.com"})


def is_allowed_target_host(host: str | None) -> bool:
    """True if *host* is an explicitly-allowed target host, or a sub-host of one of
    the allowed suffix domains (e.g. ``*.trycloudflare.com``)."""
    host = (host or "").lower()
    if host in ALLOWED_TARGET_HOSTS:
        return True
    return any(host == suffix or host.endswith("." + suffix) for suffix in ALLOWED_TARGET_HOST_SUFFIXES)


@dataclass(frozen=True, slots=True)
class Settings:
    # --- LLM access ---
    openrouter_api_key: str = field(default_factory=lambda: _str("OPENROUTER_API_KEY"))
    together_api_key: str = field(default_factory=lambda: _str("TOGETHER_API_KEY"))
    model_backend: str = field(default_factory=lambda: _str("MODEL_BACKEND", "ollama"))
    ollama_base_url: str = field(
        default_factory=lambda: _str("OLLAMA_BASE_URL", "http://localhost:11434")
    )
    ollama_red_team_model: str = field(
        default_factory=lambda: _str("OLLAMA_RED_TEAM_MODEL", "mistral:7b-instruct")
    )
    openrouter_red_team_model: str = field(
        default_factory=lambda: _str(
            "OPENROUTER_RED_TEAM_MODEL", "cognitivecomputations/whiterabbitneo-70b"
        )
    )
    openrouter_red_team_fallback: str = field(
        default_factory=lambda: _str(
            "OPENROUTER_RED_TEAM_FALLBACK", "cognitivecomputations/dolphin-3.0-llama3.1-70b"
        )
    )
    openrouter_mutation_model: str = field(
        default_factory=lambda: _str("OPENROUTER_MUTATION_MODEL", "qwen/qwen3-32b")
    )
    openrouter_judge_model: str = field(
        default_factory=lambda: _str("OPENROUTER_JUDGE_MODEL", "mistralai/mistral-large-2411")
    )
    openrouter_docs_model: str = field(
        default_factory=lambda: _str("OPENROUTER_DOCS_MODEL", "meta-llama/llama-3.1-8b-instruct")
    )

    # --- target Co-Pilot ---
    copilot_base_url: str = field(
        default_factory=lambda: _str("COPILOT_BASE_URL", "http://localhost:7300")
    )
    copilot_username: str = field(
        default_factory=lambda: _str("COPILOT_USERNAME", "agentforge_test")
    )
    copilot_password: str = field(default_factory=lambda: _str("COPILOT_PASSWORD"))
    copilot_target_sha: str = field(default_factory=lambda: _str("COPILOT_TARGET_SHA"))

    # --- dashboard ---
    dashboard_basic_auth_user: str = field(
        default_factory=lambda: _str("DASHBOARD_BASIC_AUTH_USER", "demo")
    )
    dashboard_basic_auth_pass: str = field(
        default_factory=lambda: _str("DASHBOARD_BASIC_AUTH_PASS")
    )

    # --- storage ---
    sqlite_db_path: str = field(
        default_factory=lambda: _str("SQLITE_DB_PATH", "data/agentforge.sqlite")
    )
    trace_log_path: str = field(
        default_factory=lambda: _str("TRACE_LOG_PATH", "logs/agentforge-trace.jsonl")
    )

    # --- rate limits / budget guards ---
    rate_limit_rpm: int = field(default_factory=lambda: _int("RATE_LIMIT_RPM", 20))
    cost_no_signal_ceiling_usd: float = field(
        default_factory=lambda: _float("COST_NO_SIGNAL_CEILING_USD", 0.50)
    )
    run_timeout_single_turn: int = field(
        default_factory=lambda: _int("RUN_TIMEOUT_SINGLE_TURN", 120)
    )
    run_timeout_multi_turn: int = field(default_factory=lambda: _int("RUN_TIMEOUT_MULTI_TURN", 300))

    # --- judge thresholds ---
    judge_autofile_confidence: float = field(
        default_factory=lambda: _float("JUDGE_AUTOFILE_CONFIDENCE", 0.85)
    )
    judge_lead_floor_confidence: float = field(
        default_factory=lambda: _float("JUDGE_LEAD_FLOOR_CONFIDENCE", 0.50)
    )

    # --- logging ---
    log_level: str = field(default_factory=lambda: _str("LOG_LEVEL", "INFO"))


def get_settings() -> Settings:
    """Build a fresh Settings snapshot from the current environment."""
    return Settings()


# A convenience module-level snapshot for callers that don't need per-call freshness.
settings = get_settings()
