"""Target Adapter — the only thing in AgentForge that talks to the Co-Pilot.

Guarantees enforced here (the "responsible testing posture" from THREAT_MODEL.md §8):

* **Allowlist** — refuses to construct against any host not in
  ``config.ALLOWED_TARGET_HOSTS``. No third-party targets, ever.
* **Rate cap** — at most ``RATE_LIMIT_RPM`` requests/minute against the target
  (the Co-Pilot box is ~3.7 GB RAM; we don't take down our own demo and we don't
  trip provider abuse-detection).
* **Per-run timeout** — hard kill at ``RUN_TIMEOUT_SINGLE_TURN`` /
  ``RUN_TIMEOUT_MULTI_TURN`` seconds.
* **Health gate** — ``is_healthy()`` (GET ``/healthz``) before each batch.
* **Transcript redaction** — every response is run through :class:`PHIRedactor`
  before it leaves this module (synthetic data today, HIPAA-safe pipeline tomorrow).

NOTE: the exact request/response shapes of the Co-Pilot's ``/api/login``,
``/chat`` and ``/api/traces`` endpoints are taken from the W1/W2 attack-surface
map; the few places marked ``# TODO: verify vs the local docker stack`` should be
confirmed against a running Co-Pilot during the C1 closed-loop build.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from agentforge.config import ALLOWED_TARGET_HOSTS, Settings, get_settings
from agentforge.models import AttackAttempt, AttackCase, ToolCallTrace

# --------------------------------------------------------------------------- #
# PHI / transcript redaction
# --------------------------------------------------------------------------- #
# Synthetic-but-realistic OpenEMR demo patient family names (from the W1/W2
# ACTIVE_PATIENT_NAMES allowlist). We redact these in transcripts so screenshots,
# the findings DB, the demo video and committed fixtures never carry name-shaped
# strings — even though the data is synthetic. Keeps the pipeline HIPAA-safe if
# the data ever becomes real.
_DEMO_PATIENT_FAMILY_NAMES = frozenset(
    {
        "chen",
        "cohen",
        "kowalski",
        "reyes",
        "hale",
        "patel",
        "roberts",
        "binder",
        "buckley",
        "dickey",
        "johnson",
        "nguyen",
    }
)

_RE_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# US phone: leading "\b" doesn't work before "(", so bound with digit lookarounds.
_RE_PHONE = re.compile(r"(?<!\d)(?:\(\d{3}\)[\s.-]*|\d{3}[\s.-]+)\d{3}[\s.-]+\d{4}(?!\d)")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# date-of-birth only when it appears near a DOB-ish key (avoid nuking every ISO date)
_RE_DOB = re.compile(
    r"(?i)(?P<key>\b(?:dob|date[ _]of[ _]birth|birth[ _]?date|d\.o\.b\.)\b\s*[:=]?\s*)(?P<dob>\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})"
)
# MRN / medical-record-number only in context
_RE_MRN = re.compile(
    r"(?i)(?P<key>\b(?:mrn|medical[ _]record[ _](?:number|no\.?|#)|patient[ _]id)\b\s*[:=#]?\s*)(?P<mrn>[A-Za-z0-9-]{4,})"
)
_RE_NAME = re.compile(
    r"(?i)\b(?:" + "|".join(re.escape(n) for n in _DEMO_PATIENT_FAMILY_NAMES) + r")\b"
)


class PHIRedactor:
    """Conservative, pattern-based PHI redaction for transcripts. Mirrors the
    Co-Pilot's ``safe_log.py`` approach (SSN / phone / DOB-in-context) and adds
    e-mail, MRN-in-context, and the known synthetic patient family names."""

    @staticmethod
    def redact(text: str) -> str:
        if not text:
            return text
        text = _RE_SSN.sub("[REDACTED-SSN]", text)
        text = _RE_PHONE.sub("[REDACTED-PHONE]", text)
        text = _RE_EMAIL.sub("[REDACTED-EMAIL]", text)
        text = _RE_DOB.sub(lambda m: m.group("key") + "[REDACTED-DOB]", text)
        text = _RE_MRN.sub(lambda m: m.group("key") + "[REDACTED-MRN]", text)
        text = _RE_NAME.sub("[REDACTED-NAME]", text)
        return text


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Simple min-interval rate limiter: ensures at least ``60 / rpm`` seconds
    between successive :meth:`wait` calls."""

    def __init__(self, requests_per_minute: int) -> None:
        self.min_interval = 60.0 / max(1, requests_per_minute)
        self._last: float | None = None

    def wait(self) -> None:
        now = time.monotonic()
        if self._last is not None:
            elapsed = now - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
        self._last = time.monotonic()


# --------------------------------------------------------------------------- #
# Target Adapter
# --------------------------------------------------------------------------- #
class TargetNotAllowedError(RuntimeError):
    """Raised when something tries to point the adapter at a non-allowlisted host."""


class TargetUnavailableError(RuntimeError):
    """Raised when the target's /healthz is not OK."""


@dataclass
class TargetAdapter:
    """HTTP client for the Clinical Co-Pilot, with the allowlist / rate cap /
    timeout / health-gate / redaction guarantees baked in."""

    base_url: str
    target_sha: str = ""
    username: str = ""
    password: str = ""
    rate_limit_rpm: int = 20
    timeout_single_turn: float = 120.0
    timeout_multi_turn: float = 300.0
    _client: httpx.Client = field(init=False, repr=False)
    _rl: RateLimiter = field(init=False, repr=False)
    _session_active: bool = field(default=False, init=False, repr=False)

    @classmethod
    def from_settings(cls, s: Settings | None = None) -> TargetAdapter:
        s = s or get_settings()
        return cls(
            base_url=s.copilot_base_url,
            target_sha=s.copilot_target_sha,
            username=s.copilot_username,
            password=s.copilot_password,
            rate_limit_rpm=s.rate_limit_rpm,
            timeout_single_turn=float(s.run_timeout_single_turn),
            timeout_multi_turn=float(s.run_timeout_multi_turn),
        )

    def __post_init__(self) -> None:
        host = (urlparse(self.base_url).hostname or "").lower()
        if host not in ALLOWED_TARGET_HOSTS:
            raise TargetNotAllowedError(
                f"refusing to attack '{host}' — not in ALLOWED_TARGET_HOSTS "
                f"({sorted(ALLOWED_TARGET_HOSTS)}). AgentForge only attacks the authorised Co-Pilot target."
            )
        self._client = httpx.Client(
            base_url=self.base_url.rstrip("/"), timeout=self.timeout_single_turn
        )
        self._rl = RateLimiter(self.rate_limit_rpm)

    # -- lifecycle ---------------------------------------------------------- #
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> TargetAdapter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- health ------------------------------------------------------------- #
    def is_healthy(self) -> bool:
        try:
            r = self._client.get("/healthz", timeout=10.0)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def require_healthy(self) -> None:
        if not self.is_healthy():
            raise TargetUnavailableError(f"target {self.base_url} /healthz is not OK")

    # -- auth --------------------------------------------------------------- #
    def login(self) -> None:
        """Authenticate against the Co-Pilot's session model (OpenEMR password
        grant under the hood). Use a dedicated test account — never a real
        clinician account."""
        self._rl.wait()
        # TODO: verify the request shape vs the local docker stack — the W1/W2 map
        # has POST /api/login validating credentials via the OpenEMR password grant
        # and setting a server-side session cookie.
        r = self._client.post(
            "/api/login", json={"username": self.username, "password": self.password}
        )
        r.raise_for_status()
        self._session_active = True

    def ensure_logged_in(self) -> None:
        if not self._session_active:
            self.login()

    # -- chat --------------------------------------------------------------- #
    def chat(
        self, message: str, *, advisor_mode: bool = False, extra: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """One atomic chat turn. Returns the raw response payload (parsed JSON if
        possible, else ``{"text": <body>}``). Does NOT redact — callers that store
        the result should run it through :meth:`PHIRedactor.redact` first; the
        :meth:`attack` path does this for you."""
        self.ensure_logged_in()
        self._rl.wait()
        body: dict[str, Any] = {"message": message, "advisor_mode": advisor_mode}
        if extra:
            body.update(extra)
        # TODO: verify endpoint + body shape vs the local docker stack (POST /chat
        # = "atomic chat turn, return response text"; /chat/stream is the SSE variant).
        r = self._client.post("/chat", json=body, timeout=self.timeout_single_turn)
        r.raise_for_status()
        try:
            return r.json()
        except ValueError:
            return {"text": r.text}

    def latest_trace(self) -> dict[str, Any] | None:
        """Fetch the most recent request trace from /api/traces (same session).
        Used to recover the target's tool-call trace, token usage, cost, and
        supervisor-hop count after a chat turn."""
        try:
            self._rl.wait()
            r = self._client.get("/api/traces", timeout=15.0)
            r.raise_for_status()
            data = r.json()
            traces = data if isinstance(data, list) else data.get("traces", [])
            # TODO: match by request_id if /chat returns one; for now take the newest.
            return traces[0] if traces else None
        except (httpx.HTTPError, ValueError, IndexError):
            return None

    # -- the main entry point ---------------------------------------------- #
    def attack(self, case: AttackCase) -> AttackAttempt:
        """Execute one AttackCase against the target and return a populated,
        redacted AttackAttempt. Errors are captured (never raised) as
        ``error`` on the AttackAttempt so the run loop keeps going."""
        is_multi_turn = len(case.prompt_or_sequence) > 1
        timeout = self.timeout_multi_turn if is_multi_turn else self.timeout_single_turn
        responses: list[str] = []
        error: str | None = None
        started = time.monotonic()
        try:
            self.require_healthy()
            for turn in case.prompt_or_sequence:
                payload = self.chat(turn, advisor_mode=False)
                # Co-Pilot may return {"response": ...} or {"text": ...} or a bare string-ish JSON
                text = (
                    payload.get("response")
                    or payload.get("text")
                    or payload.get("answer")
                    or str(payload)
                )
                responses.append(text)
                if time.monotonic() - started > timeout:
                    error = "timeout"
                    break
        except TargetUnavailableError:
            error = "target_unavailable"
        except httpx.TimeoutException:
            error = "timeout"
        except httpx.HTTPError as e:
            error = f"http_error: {type(e).__name__}"
        latency_ms = (time.monotonic() - started) * 1000.0

        # recover the trace (best-effort)
        tool_trace: list[ToolCallTrace] = []
        token_usage: dict[str, int] = {}
        cost_usd = 0.0
        n_hops: int | None = None
        trace = self.latest_trace() if error is None else None
        if trace:
            for ev in trace.get("tool_events", []) or []:
                tool_trace.append(
                    ToolCallTrace(
                        name=str(ev.get("name", "")),
                        args_redacted={
                            k: PHIRedactor.redact(str(v)) for k, v in (ev.get("args") or {}).items()
                        },
                        ok=bool(ev.get("ok", True)),
                        latency_ms=ev.get("duration_ms"),
                        error=ev.get("error"),
                    )
                )
            usage = trace.get("total_usage") or {}
            if isinstance(usage, dict):
                token_usage = {k: int(v) for k, v in usage.items() if isinstance(v, int | float)}
            cost_usd = float(trace.get("cost_usd", 0.0) or 0.0)
            # supervisor hop count: count tool_events / or a dedicated field if present
            n_hops = trace.get("supervisor_routes") or trace.get("route_count")

        response_blob = "\n---\n".join(responses)
        return AttackAttempt(
            attack_case_id=case.id,
            target_sha=self.target_sha,
            target_base_url=self.base_url,
            request_summary=f"{case.category.value}/{case.subcategory} "
            f"({'multi-turn x' + str(len(case.prompt_or_sequence)) if is_multi_turn else 'single-turn'})",
            response_redacted=PHIRedactor.redact(response_blob),
            tool_trace=tool_trace,
            token_usage=token_usage,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            n_supervisor_hops=int(n_hops) if isinstance(n_hops, int | float) else None,
            error=error,
        )
