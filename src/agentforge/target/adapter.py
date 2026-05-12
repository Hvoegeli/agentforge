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

Endpoint contracts (verified against ``clinical-copilot/app/main.py``):

* ``POST /api/login`` — body ``{"username", "password"}`` → ``200 {"ok": true, "username"}``
  on success, ``401`` on bad creds; sets a signed session cookie (Starlette
  ``SessionMiddleware``) which ``httpx.Client`` persists across requests.
* ``GET /healthz`` — ``200 {"status": "ok"}`` (no auth).
* ``POST /chat`` — body ``{"session_id": str|null, "message": str, "advisor_mode": bool}``
  (requires the session cookie) → ``{"session_id", "response", "patient_id", "sources",
  "validation_warning"}``. ``session_id`` is echoed back; reuse it for a multi-turn
  conversation. (``/chat/stream`` is the SSE variant — not used here.)
* ``GET /api/traces?limit=N`` — ``{"count", "items": [trace, ...]}``, newest-first;
  each trace has ``request_id``, ``session_id``, ``tool_events`` (``name``/``args``/
  ``ok``/``duration_ms``/``error``), ``total_usage`` (``input_tokens``/``output_tokens``/
  ``cache_read_tokens``/``cache_creation_tokens``), ``cost_usd``, ``duration_ms``,
  ``validator_attempts``/``validator_failed``, ``error``. (No ``route_count`` /
  supervisor-hop field today — see :meth:`attack`.)
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from agentforge.attacks.red_team import context_from_case
from agentforge.config import ALLOWED_TARGET_HOSTS, Settings, get_settings
from agentforge.models import AttackAttempt, AttackCase, ToolCallTrace

logger = logging.getLogger("agentforge.target.adapter")

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
        """Authenticate against the Co-Pilot (``POST /api/login`` — credentials are
        verified against OpenEMR server-side; a signed session cookie is set, which
        ``httpx.Client`` persists for us). Use a dedicated test account — never a
        real clinician account."""
        self._rl.wait()
        r = self._client.post(
            "/api/login", json={"username": self.username, "password": self.password}
        )
        r.raise_for_status()  # 401 → bad creds
        self._session_active = True

    def ensure_logged_in(self) -> None:
        if not self._session_active:
            self.login()

    # -- chat --------------------------------------------------------------- #
    def chat(
        self,
        message: str,
        *,
        session_id: str | None = None,
        advisor_mode: bool = False,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """One chat turn. Pass ``session_id`` (from a prior turn's response) to
        continue a conversation; ``None`` starts a fresh one (the server allocates
        an id and echoes it back). Returns the parsed ``ChatResponse`` JSON
        (``{"session_id", "response", "patient_id", "sources", "validation_warning"}``).
        Does NOT redact — the :meth:`attack` path does that for you. Re-logs-in once
        on a 401 (the session cookie may have expired)."""
        self.ensure_logged_in()
        body: dict[str, Any] = {
            "message": message,
            "advisor_mode": advisor_mode,
            "session_id": session_id,
        }
        if extra:
            body.update(extra)
        self._rl.wait()
        r = self._client.post("/chat", json=body, timeout=self.timeout_single_turn)
        if r.status_code == 401:
            # cookie expired / not yet established — re-auth and retry once
            self._session_active = False
            self.login()
            self._rl.wait()
            r = self._client.post("/chat", json=body, timeout=self.timeout_single_turn)
        r.raise_for_status()
        try:
            return r.json()
        except ValueError:
            return {"session_id": session_id, "response": r.text}

    def latest_trace(self, session_id: str | None = None) -> dict[str, Any] | None:
        """Fetch the newest ``/api/traces`` entry, optionally restricted to a
        ``session_id``. ``/chat`` does not return its ``request_id``, so we match on
        the session and take the newest (turns are sent strictly sequentially, so
        the newest trace for our session is the turn we just sent — including the
        jailbreak-guard / intent-router short-circuit traces, which also carry the
        session id)."""
        try:
            self._rl.wait()
            r = self._client.get("/api/traces", params={"limit": 50}, timeout=15.0)
            r.raise_for_status()
            data = r.json()
            items = data.get("items", []) if isinstance(data, dict) else (data or [])
        except (httpx.HTTPError, ValueError):
            return None
        if not items:
            return None
        if session_id is None:
            return items[0]  # newest overall
        for item in items:  # newest-first
            if isinstance(item, dict) and item.get("session_id") == session_id:
                return item
        return None

    # -- panel introspection ------------------------------------------------ #
    def resolved_panel(self) -> set[str]:
        """Return the FHIR Patient UUIDs the current session is scoped to (its
        panel) — by reading ``/api/upload/patients``, which the Co-Pilot filters to
        the user's panel (admins get every patient). Returns ``set()`` on any error.
        Used by the run loop to give the C2/C4 checkers the authorized-panel context.
        """
        try:
            self.ensure_logged_in()
            self._rl.wait()
            r = self._client.get("/api/upload/patients", timeout=15.0)
            r.raise_for_status()
            items = (r.json() or {}).get("items") or []
        except (httpx.HTTPError, ValueError):
            return set()
        return {str(i["id"]) for i in items if isinstance(i, dict) and i.get("id")}

    # -- upload-doc setup (indirect-via-image attack) ---------------------- #
    def _resolve_upload_patient(self) -> tuple[str, str]:
        """Pick a patient the current session may write to (for the upload-doc setup
        step). Returns ``(patient_uuid, label)``. Raises ``RuntimeError`` if none."""
        self.ensure_logged_in()
        self._rl.wait()
        r = self._client.get("/api/upload/patients", timeout=15.0)
        r.raise_for_status()
        items = (r.json() or {}).get("items") or []
        if not items:
            raise RuntimeError("no patients available for upload (empty panel?)")
        first = items[0]
        return str(first["id"]), str(first.get("label") or first["id"])

    def _upload_document(
        self, payload_text: str, *, patient_uuid: str, doc_type: str = "intake_form"
    ) -> str:
        """Render ``payload_text`` to a PNG and ``POST /api/upload`` it for
        ``patient_uuid``. Returns the created ``reference_id`` (or ``""``). The PNG
        carries the injection text as *pixels*, so it reaches the Co-Pilot's vision
        model via the rendered-image channel the jailbreak quarantine doesn't scan.
        """
        from agentforge.attacks.poison_doc import render_text_to_png

        png = render_text_to_png(payload_text or "(empty document)")
        self.ensure_logged_in()
        self._rl.wait()
        r = self._client.post(
            "/api/upload",
            files={"file": ("agentforge-probe.png", png, "image/png")},
            data={
                "doc_type": doc_type,
                "patient_uuid": patient_uuid,
                "acknowledge_existing": "true",  # skip the SHA-256 dedup prompt
            },
            timeout=self.timeout_multi_turn,
        )
        r.raise_for_status()
        try:
            return str((r.json() or {}).get("reference_id") or "")
        except ValueError:
            return ""

    # -- the main entry point ---------------------------------------------- #
    def attack(self, case: AttackCase) -> AttackAttempt:
        """Execute one AttackCase against the target and return a populated,
        redacted AttackAttempt. Errors are captured (never raised) as ``error`` on
        the AttackAttempt so the run loop keeps going. A multi-turn case is sent as
        one conversation — the ``session_id`` from the first turn's response is
        threaded into the rest. If the case carries ``needs_setup=upload_doc`` in its
        notes, a poisoned document is uploaded for a panel patient first and
        ``{uploaded_patient}`` / ``{uploaded_patient_id}`` are substituted into the
        turns. (``needs_setup=write_fhir_field`` and ``raw_http_get`` are not yet
        implemented — those seeds run as bare chat turns until then.)"""
        is_multi_turn = len(case.prompt_or_sequence) > 1
        timeout = self.timeout_multi_turn if is_multi_turn else self.timeout_single_turn
        advisor_mode = "advisor_mode=true" in (case.notes or "").lower()
        ctx = context_from_case(case)
        turns: list[str] = list(case.prompt_or_sequence)
        setup_note = ""
        responses: list[str] = []
        error: str | None = None
        session_id: str | None = None
        started = time.monotonic()
        try:
            self.require_healthy()
            if ctx.get("needs_setup") == "upload_doc":
                try:
                    pid, label = self._resolve_upload_patient()
                    ref = self._upload_document(str(ctx.get("setup_payload") or ""), patient_uuid=pid)
                    turns = [
                        t.replace("{uploaded_patient}", label).replace("{uploaded_patient_id}", pid)
                        for t in turns
                    ]
                    setup_note = f"; setup=poisoned-doc->{label}"
                    logger.info("adapter: uploaded poisoned doc for %s (ref=%s) before %s", label, ref, case.subcategory)
                except (httpx.HTTPError, RuntimeError, OSError, KeyError) as e:
                    error = f"setup_failed: {type(e).__name__}"
            if error is None:
                for turn in turns:
                    payload = self.chat(turn, session_id=session_id, advisor_mode=advisor_mode)
                    session_id = payload.get("session_id") or session_id
                    responses.append(str(payload.get("response") or payload.get("text") or ""))
                    if time.monotonic() - started > timeout:
                        error = "timeout"
                        break
        except TargetUnavailableError:
            error = "target_unavailable"
        except httpx.TimeoutException:
            error = "timeout"
        except httpx.HTTPError as e:
            error = f"http_error: {type(e).__name__}"

        # recover the trace (best-effort — even on a timeout the partial trace is useful)
        tool_trace: list[ToolCallTrace] = []
        token_usage: dict[str, int] = {}
        cost_usd = 0.0
        n_hops: int | None = None
        trace = self.latest_trace(session_id) if error != "target_unavailable" else None
        if trace:
            for ev in trace.get("tool_events", []) or []:
                if not isinstance(ev, dict):
                    continue
                name = str(ev.get("name", ""))
                # `supervisor.route` (and any other `supervisor.*`) is an internal
                # routing-decision event the Co-Pilot records in tool_events — not a
                # tool invocation. It appears in every trace; the supervisor-hop count
                # is captured separately as n_supervisor_hops. Drop it so it doesn't
                # show up as an "out-of-binding tool" to the C4 checker (false positive)
                # or clutter the vuln-report tool-trace table.
                if name.startswith("supervisor."):
                    continue
                tool_trace.append(
                    ToolCallTrace(
                        name=name,
                        args_redacted={
                            str(k): PHIRedactor.redact(str(v))
                            for k, v in (ev.get("args") or {}).items()
                        },
                        ok=bool(ev.get("ok", True)),
                        latency_ms=ev.get("duration_ms"),
                        error=ev.get("error"),
                    )
                )
            usage = trace.get("total_usage") or {}
            if isinstance(usage, dict):
                token_usage = {
                    str(k): int(v) for k, v in usage.items() if isinstance(v, int | float)
                }
            cost_usd = float(trace.get("cost_usd", 0.0) or 0.0)
            # Supervisor routing-hop count: the Co-Pilot's RequestTrace now carries
            # `route_count` (added 2026-05-11). Use .get with a fallback so a real 0
            # is recorded as 0 (not coerced to None by `0 or …`); only when neither
            # key is present do the C4/C5 hop checks see None ("not checkable").
            n_hops = trace.get("route_count", trace.get("supervisor_routes"))

        # latency: prefer the target's own measured turn latency when we have a
        # single-turn trace; otherwise the wall-clock around our request(s).
        if trace and not is_multi_turn and isinstance(trace.get("duration_ms"), int | float):
            latency_ms = float(trace["duration_ms"])
        else:
            latency_ms = (time.monotonic() - started) * 1000.0

        response_blob = "\n---\n".join(responses)
        return AttackAttempt(
            attack_case_id=case.id,
            target_sha=self.target_sha,
            target_base_url=self.base_url,
            request_summary=(
                f"{case.category.value}/{case.subcategory} "
                f"({'multi-turn x' + str(len(case.prompt_or_sequence)) if is_multi_turn else 'single-turn'}"
                f"{', advisor_mode' if advisor_mode else ''}"
                f"{setup_note}"
                f"{'; session=' + session_id[:8] if session_id else ''})"
            ),
            response_redacted=PHIRedactor.redact(response_blob),
            tool_trace=tool_trace,
            token_usage=token_usage,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            n_supervisor_hops=int(n_hops) if isinstance(n_hops, int | float) else None,
            error=error,
        )
