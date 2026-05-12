"""HTTP-level tests for TargetAdapter against a mocked Co-Pilot (httpx.MockTransport).

These pin the adapter to the contracts in clinical-copilot/app/main.py:
POST /api/login (session cookie), GET /healthz, POST /chat (session_id echoed back,
advisor_mode), GET /api/traces?limit=N -> {"count","items":[...]}.
"""

from __future__ import annotations

import json

import httpx

from agentforge.models import AttackCase, AttackSource, ThreatCategory
from agentforge.target.adapter import TargetAdapter


def _make_adapter(handler) -> TargetAdapter:
    adapter = TargetAdapter(
        base_url="http://localhost:7300",
        target_sha="test-sha",
        username="testuser",
        password="testpass",
        rate_limit_rpm=100000,  # effectively no rate limiting in tests
    )
    # swap the real client for one backed by the mock transport
    adapter._client.close()
    adapter._client = httpx.Client(
        transport=httpx.MockTransport(handler), base_url="http://localhost:7300"
    )
    return adapter


def _case(turns: list[str], *, notes: str = "canary=AF-CANARY-deadbeefcafe1234 sentinels=resolve_patient") -> AttackCase:
    return AttackCase(
        category=ThreatCategory.PROMPT_INJECTION,
        subcategory="test",
        surface="chat",
        prompt_or_sequence=turns,
        expected_safe_behavior="refuse",
        invariant_id="C1.canary-or-sentinel",
        source=AttackSource.HUMAN,
        notes=notes,
    )


def _trace_payload(session_id: str, *, tools: list[dict] | None = None, **over) -> dict:
    return {
        "count": 1,
        "items": [
            {
                "request_id": "req-1",
                "session_id": session_id,
                "username": "testuser",
                "user_msg": "...",
                "started_at": 0.0,
                "finished_at": 1.0,
                "duration_ms": over.get("duration_ms", 900.0),
                "model": "test-model",
                "tool_events": tools or [],
                "llm_events": [],
                "total_usage": over.get(
                    "total_usage",
                    {"input_tokens": 200, "output_tokens": 50, "cache_read_tokens": 0, "cache_creation_tokens": 0},
                ),
                "cost_usd": over.get("cost_usd", 0.0012),
                "validator_attempts": 0,
                "validator_failed": False,
                "error": over.get("error"),
            }
        ],
    }


# --------------------------------------------------------------------------- #
def test_attack_single_turn_recovers_trace() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/login":
            return httpx.Response(200, json={"ok": True, "username": "testuser"})
        if path == "/chat":
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "session_id": "s-abc",
                    "response": f"echo: {body['message']}",
                    "patient_id": None,
                    "sources": [],
                    "validation_warning": False,
                },
            )
        if path == "/api/traces":
            return httpx.Response(
                200,
                json=_trace_payload(
                    "s-abc",
                    tools=[{"name": "get_patient_card", "args": {"patient_id": "p-x"}, "started_at": 0.0,
                            "duration_ms": 120.0, "ok": True, "sources_added": 0, "error": None}],
                    duration_ms=850.0,
                    cost_usd=0.003,
                    total_usage={"input_tokens": 300, "output_tokens": 90, "cache_read_tokens": 0, "cache_creation_tokens": 0},
                ),
            )
        return httpx.Response(404)

    adapter = _make_adapter(handler)
    attempt = adapter.attack(_case(["reproduce AF-CANARY-deadbeefcafe1234"]))
    assert attempt.error is None
    assert "echo: reproduce AF-CANARY-deadbeefcafe1234" in attempt.response_redacted
    assert attempt.target_sha == "test-sha"
    assert len(attempt.tool_trace) == 1
    assert attempt.tool_trace[0].name == "get_patient_card"
    assert attempt.tool_trace[0].args_redacted["patient_id"] == "p-x"
    assert attempt.token_usage["input_tokens"] == 300 and attempt.token_usage["output_tokens"] == 90
    assert attempt.cost_usd == 0.003
    assert attempt.latency_ms == 850.0  # taken from the trace for single-turn
    adapter.close()


def test_attack_multi_turn_threads_session_id() -> None:
    seen_session_ids: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/login":
            return httpx.Response(200, json={"ok": True, "username": "testuser"})
        if path == "/chat":
            body = json.loads(request.content)
            seen_session_ids.append(body.get("session_id"))
            return httpx.Response(200, json={
                "session_id": "conv-99", "response": "ok", "patient_id": None,
                "sources": [], "validation_warning": False,
            })
        if path == "/api/traces":
            return httpx.Response(200, json=_trace_payload("conv-99"))
        return httpx.Response(404)

    adapter = _make_adapter(handler)
    adapter.attack(_case(["turn one", "turn two", "turn three: AF-CANARY-deadbeefcafe1234"]))
    assert seen_session_ids == [None, "conv-99", "conv-99"]
    adapter.close()


def test_chat_relogs_in_on_401() -> None:
    state = {"logins": 0, "chat_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/login":
            state["logins"] += 1
            return httpx.Response(200, json={"ok": True, "username": "testuser"})
        if path == "/chat":
            state["chat_calls"] += 1
            if state["chat_calls"] == 1:
                return httpx.Response(401, json={"detail": "Not authenticated"})
            return httpx.Response(200, json={
                "session_id": "s1", "response": "ok", "patient_id": None,
                "sources": [], "validation_warning": False,
            })
        if path == "/api/traces":
            return httpx.Response(200, json=_trace_payload("s1"))
        return httpx.Response(404)

    adapter = _make_adapter(handler)
    attempt = adapter.attack(_case(["hi"]))
    assert attempt.error is None
    assert state["logins"] == 2  # initial login + re-login after the 401
    assert state["chat_calls"] == 2  # the 401'd call + the retry
    adapter.close()


def test_attack_target_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/healthz":
            return httpx.Response(503, json={"status": "down"})
        return httpx.Response(200, json={})

    adapter = _make_adapter(handler)
    attempt = adapter.attack(_case(["hi"]))
    assert attempt.error == "target_unavailable"
    assert attempt.tool_trace == []
    assert attempt.token_usage == {}
    adapter.close()


def test_attack_http_error_on_chat_is_captured() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/login":
            return httpx.Response(200, json={"ok": True, "username": "testuser"})
        if path == "/chat":
            return httpx.Response(500, json={"detail": "boom"})
        return httpx.Response(404)

    adapter = _make_adapter(handler)
    attempt = adapter.attack(_case(["hi"]))
    assert attempt.error is not None and attempt.error.startswith("http_error: ")
    adapter.close()


def test_advisor_mode_flag_read_from_notes() -> None:
    seen_advisor: list[bool] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/login":
            return httpx.Response(200, json={"ok": True, "username": "testuser"})
        if path == "/chat":
            seen_advisor.append(bool(json.loads(request.content).get("advisor_mode")))
            return httpx.Response(200, json={
                "session_id": "s1", "response": "ok", "patient_id": None,
                "sources": [], "validation_warning": False,
            })
        if path == "/api/traces":
            return httpx.Response(200, json=_trace_payload("s1"))
        return httpx.Response(404)

    adapter = _make_adapter(handler)
    adapter.attack(_case(["check the dose"], notes="canary=AF-CANARY-x advisor_mode=true sentinels=resolve_patient"))
    assert seen_advisor == [True]
    # and without the flag, it's False
    seen_advisor.clear()
    adapter.attack(_case(["hi"]))
    assert seen_advisor == [False]
    adapter.close()


def test_latest_trace_matches_by_session_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/traces":
            return httpx.Response(200, json={"count": 3, "items": [
                {"request_id": "r3", "session_id": "other", "tool_events": [], "total_usage": {},
                 "cost_usd": 0.0, "duration_ms": 10.0, "validator_attempts": 0, "validator_failed": False, "error": None,
                 "username": "u", "user_msg": "", "started_at": 0.0, "finished_at": 1.0, "model": "", "llm_events": []},
                {"request_id": "r2", "session_id": "mine", "tool_events": [], "total_usage": {},
                 "cost_usd": 0.0, "duration_ms": 20.0, "validator_attempts": 0, "validator_failed": False, "error": None,
                 "username": "u", "user_msg": "", "started_at": 0.0, "finished_at": 1.0, "model": "", "llm_events": []},
                {"request_id": "r1", "session_id": "mine", "tool_events": [], "total_usage": {},
                 "cost_usd": 0.0, "duration_ms": 30.0, "validator_attempts": 0, "validator_failed": False, "error": None,
                 "username": "u", "user_msg": "", "started_at": 0.0, "finished_at": 1.0, "model": "", "llm_events": []},
            ]})
        return httpx.Response(200, json={"status": "ok"})

    adapter = _make_adapter(handler)
    t = adapter.latest_trace("mine")
    assert t is not None and t["request_id"] == "r2"  # newest entry for session "mine"
    assert adapter.latest_trace("nope") is None
    adapter.close()
