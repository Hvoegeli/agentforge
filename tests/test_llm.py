"""Unit tests for agentforge.llm — role routing, retry, fallback, cost, budget guard.

All tests use ``unittest.mock`` to patch the ``OpenAI`` client; no real network
calls are made.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agentforge.config import Settings
from agentforge.llm import (
    _PRICE_TABLE,
    BudgetExceededError,
    ChatResult,
    LLMCallError,
    Role,
    chat,
    chat_json,
    get_cost_total,
    reset_cost_total,
)


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def _make_settings(**overrides: Any) -> Settings:
    """Build a Settings instance with sensible test defaults."""
    defaults: dict[str, Any] = {
        "openrouter_api_key": "test-or-key",
        "together_api_key": "",
        "model_backend": "openrouter",
        "ollama_base_url": "http://localhost:11434",
        "ollama_red_team_model": "mistral:7b-instruct",
        "openrouter_red_team_model": "cognitivecomputations/whiterabbitneo-70b",
        "openrouter_red_team_fallback": "cognitivecomputations/dolphin-3.0-llama3.1-70b",
        "openrouter_mutation_model": "qwen/qwen3-32b",
        "openrouter_judge_model": "mistralai/mistral-large-2411",
        "openrouter_docs_model": "meta-llama/llama-3.1-8b-instruct",
        # supply required fields with defaults
        "copilot_base_url": "http://localhost:7300",
        "copilot_username": "test",
        "copilot_password": "",
        "copilot_target_sha": "",
        "dashboard_basic_auth_user": "demo",
        "dashboard_basic_auth_pass": "",
        "sqlite_db_path": "data/agentforge.sqlite",
        "trace_log_path": "logs/agentforge-trace.jsonl",
        "rate_limit_rpm": 20,
        "cost_no_signal_ceiling_usd": 0.50,
        "run_timeout_single_turn": 120,
        "run_timeout_multi_turn": 300,
        "judge_autofile_confidence": 0.85,
        "judge_lead_floor_confidence": 0.50,
        "log_level": "INFO",
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _fake_response(
    text: str = "hello", input_tokens: int = 10, output_tokens: int = 5
) -> MagicMock:
    """Build a mock ``openai.ChatCompletion`` response object."""
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message.content = text
    resp.usage = MagicMock()
    resp.usage.prompt_tokens = input_tokens
    resp.usage.completion_tokens = output_tokens
    return resp


def _messages() -> list[dict[str, str]]:
    return [{"role": "user", "content": "Hello"}]


# --------------------------------------------------------------------------- #
# (a) Role → model + backend routing
# --------------------------------------------------------------------------- #
class TestRoleRouting:
    """Verify that each role routes to the correct model and backend."""

    @pytest.fixture(autouse=True)
    def reset(self) -> None:  # type: ignore[return]
        reset_cost_total()

    def _call_and_capture(self, role: Role, settings: Settings) -> tuple[ChatResult, str, str]:
        """Return (result, model_passed_to_create, base_url_of_client)."""
        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response()
            result = chat(_messages(), role=role, settings=settings)
            # Extract the model argument
            create_kwargs = mock_client.chat.completions.create.call_args
            model_used = (
                create_kwargs[1]["model"] if "model" in create_kwargs[1] else create_kwargs[0][0]
            )
            base_url = mock_cls.call_args[1]["base_url"]
        return result, model_used, base_url

    def test_red_team_openrouter_backend(self) -> None:
        s = _make_settings(model_backend="openrouter")
        result, model, base_url = self._call_and_capture(Role.RED_TEAM, s)
        assert model == s.openrouter_red_team_model
        assert "openrouter.ai" in base_url
        assert result.backend == "openrouter"

    def test_red_team_ollama_backend(self) -> None:
        s = _make_settings(model_backend="ollama")
        result, model, base_url = self._call_and_capture(Role.RED_TEAM, s)
        assert model == s.ollama_red_team_model
        assert "11434" in base_url  # ollama port
        assert result.backend == "ollama"

    def test_mutation_always_openrouter(self) -> None:
        for backend in ("ollama", "openrouter"):
            s = _make_settings(model_backend=backend)
            result, model, base_url = self._call_and_capture(Role.MUTATION, s)
            assert model == s.openrouter_mutation_model
            assert "openrouter.ai" in base_url
            assert result.backend == "openrouter"

    def test_judge_always_openrouter(self) -> None:
        for backend in ("ollama", "openrouter"):
            s = _make_settings(model_backend=backend)
            result, model, base_url = self._call_and_capture(Role.JUDGE, s)
            assert model == s.openrouter_judge_model
            assert "openrouter.ai" in base_url
            assert result.backend == "openrouter"

    def test_documentation_always_openrouter(self) -> None:
        for backend in ("ollama", "openrouter"):
            s = _make_settings(model_backend=backend)
            result, model, _base_url = self._call_and_capture(Role.DOCUMENTATION, s)
            assert model == s.openrouter_docs_model
            assert result.backend == "openrouter"

    def test_orchestrator_always_openrouter(self) -> None:
        for backend in ("ollama", "openrouter"):
            s = _make_settings(model_backend=backend)
            result, model, _base_url = self._call_and_capture(Role.ORCHESTRATOR, s)
            # Orchestrator shares the mutation model
            assert model == s.openrouter_mutation_model
            assert result.backend == "openrouter"

    def test_result_has_correct_model_field(self) -> None:
        s = _make_settings(model_backend="openrouter")
        result, _model, _base_url = self._call_and_capture(Role.JUDGE, s)
        assert result.model_used == s.openrouter_judge_model


# --------------------------------------------------------------------------- #
# (b) RED_TEAM fallback fires on primary-model error
# --------------------------------------------------------------------------- #
class TestRedTeamFallback:
    @pytest.fixture(autouse=True)
    def reset(self) -> None:  # type: ignore[return]
        reset_cost_total()

    def test_fallback_used_when_primary_fails(self) -> None:
        s = _make_settings(model_backend="openrouter")
        fallback_model = s.openrouter_red_team_fallback

        calls: list[str] = []

        def fake_create(**kwargs: Any) -> Any:
            model = kwargs["model"]
            calls.append(model)
            if model == s.openrouter_red_team_model:
                raise Exception("primary unavailable")
            return _fake_response(text="fallback response")

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.side_effect = fake_create
            result = chat(_messages(), role=Role.RED_TEAM, settings=s)

        assert result.text == "fallback response"
        assert result.model_used == fallback_model
        # Primary was attempted at least once
        assert s.openrouter_red_team_model in calls
        assert fallback_model in calls

    def test_fallback_result_has_correct_backend(self) -> None:
        s = _make_settings(model_backend="openrouter")

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            call_count = 0

            def fake_create(**kwargs: Any) -> Any:
                nonlocal call_count
                call_count += 1
                if kwargs["model"] == s.openrouter_red_team_model:
                    raise Exception("primary down")
                return _fake_response(text="ok from fallback")

            mock_client.chat.completions.create.side_effect = fake_create
            result = chat(_messages(), role=Role.RED_TEAM, settings=s)

        assert result.backend == "openrouter"
        assert result.text == "ok from fallback"


# --------------------------------------------------------------------------- #
# (c) Retry-then-success on a transient error
# --------------------------------------------------------------------------- #
class TestRetryOnTransientError:
    @pytest.fixture(autouse=True)
    def reset(self) -> None:  # type: ignore[return]
        reset_cost_total()

    def test_succeeds_after_one_transient_failure(self) -> None:
        import httpx
        from openai import APIStatusError

        s = _make_settings(model_backend="openrouter")
        attempt = 0

        def fake_create(**kwargs: Any) -> Any:
            nonlocal attempt
            attempt += 1
            if attempt == 1:
                raw = httpx.Response(429, request=httpx.Request("POST", "http://test"))
                raise APIStatusError("rate limited", response=raw, body={})
            return _fake_response(text="success after retry")

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.side_effect = fake_create
            with patch("agentforge.llm.time.sleep"):  # don't actually sleep in tests
                result = chat(_messages(), role=Role.JUDGE, settings=s)

        assert result.text == "success after retry"
        assert attempt == 2

    def test_succeeds_on_third_attempt(self) -> None:
        import httpx
        from openai import APIStatusError

        s = _make_settings()
        attempt = 0

        def fake_create(**kwargs: Any) -> Any:
            nonlocal attempt
            attempt += 1
            if attempt < 3:
                raw = httpx.Response(503, request=httpx.Request("POST", "http://test"))
                raise APIStatusError("service unavailable", response=raw, body={})
            return _fake_response(text="third time lucky")

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.side_effect = fake_create
            with patch("agentforge.llm.time.sleep"):
                result = chat(_messages(), role=Role.MUTATION, settings=s)

        assert result.text == "third time lucky"
        assert attempt == 3


# --------------------------------------------------------------------------- #
# (d) LLMCallError raised after exhausting retries
# --------------------------------------------------------------------------- #
class TestExhaustedRetries:
    @pytest.fixture(autouse=True)
    def reset(self) -> None:  # type: ignore[return]
        reset_cost_total()

    def test_raises_llm_call_error_after_max_retries(self) -> None:
        import httpx
        from openai import APIStatusError

        s = _make_settings()

        def always_fail(**kwargs: Any) -> Any:
            raw = httpx.Response(503, request=httpx.Request("POST", "http://test"))
            raise APIStatusError("always down", response=raw, body={})

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.side_effect = always_fail
            with patch("agentforge.llm.time.sleep"):
                with pytest.raises(LLMCallError):
                    chat(_messages(), role=Role.JUDGE, settings=s)

    def test_non_transient_error_raises_immediately(self) -> None:
        import httpx
        from openai import APIStatusError

        s = _make_settings()
        attempt = 0

        def forbidden(**kwargs: Any) -> Any:
            nonlocal attempt
            attempt += 1
            raw = httpx.Response(403, request=httpx.Request("POST", "http://test"))
            raise APIStatusError("forbidden", response=raw, body={})

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.side_effect = forbidden
            with pytest.raises(LLMCallError):
                chat(_messages(), role=Role.DOCUMENTATION, settings=s)

        # Non-transient → no retries, called exactly once
        assert attempt == 1


# --------------------------------------------------------------------------- #
# (e) Cost computed from price table
# --------------------------------------------------------------------------- #
class TestCostComputation:
    @pytest.fixture(autouse=True)
    def reset(self) -> None:  # type: ignore[return]
        reset_cost_total()

    def test_cost_computed_for_known_model(self) -> None:
        s = _make_settings()
        model = s.openrouter_judge_model  # mistralai/mistral-large-2411
        in_per_mtok, out_per_mtok = _PRICE_TABLE[model]
        input_tok, output_tok = 1000, 500

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response(
                input_tokens=input_tok, output_tokens=output_tok
            )
            result = chat(_messages(), role=Role.JUDGE, settings=s)

        expected = (input_tok * in_per_mtok + output_tok * out_per_mtok) / 1_000_000
        assert abs(result.cost_usd - expected) < 1e-9

    def test_cost_zero_for_unknown_model(self) -> None:
        s = _make_settings(openrouter_judge_model="unknown/mystery-model")

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response()
            result = chat(_messages(), role=Role.JUDGE, settings=s)

        assert result.cost_usd == 0.0

    def test_cost_accumulates_across_calls(self) -> None:
        s = _make_settings()
        model = s.openrouter_judge_model
        in_per_mtok, out_per_mtok = _PRICE_TABLE[model]
        input_tok, output_tok = 100, 50
        single_cost = (input_tok * in_per_mtok + output_tok * out_per_mtok) / 1_000_000

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response(
                input_tokens=input_tok, output_tokens=output_tok
            )
            chat(_messages(), role=Role.JUDGE, settings=s)
            chat(_messages(), role=Role.JUDGE, settings=s)

        assert abs(get_cost_total() - 2 * single_cost) < 1e-9


# --------------------------------------------------------------------------- #
# (f) chat_json — valid parse and bad-JSON error
# --------------------------------------------------------------------------- #
class TestChatJson:
    @pytest.fixture(autouse=True)
    def reset(self) -> None:  # type: ignore[return]
        reset_cost_total()

    def test_parses_valid_json(self) -> None:
        s = _make_settings()
        payload = {"verdict": "pass", "confidence": 0.95}

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response(
                text=json.dumps(payload)
            )
            result, parsed = chat_json(_messages(), role=Role.JUDGE, settings=s)

        assert isinstance(result, ChatResult)
        assert parsed == payload

    def test_raises_on_invalid_json(self) -> None:
        s = _make_settings()

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response(
                text="this is not json {{"
            )
            with pytest.raises(LLMCallError, match="invalid JSON"):
                chat_json(_messages(), role=Role.JUDGE, settings=s)

    def test_json_mode_passes_response_format_on_openrouter(self) -> None:
        s = _make_settings()

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response(text="{}")
            chat_json(_messages(), role=Role.JUDGE, settings=s)
            kwargs = mock_client.chat.completions.create.call_args[1]
            assert kwargs.get("response_format") == {"type": "json_object"}

    def test_json_mode_appends_instruction_on_ollama(self) -> None:
        """For Ollama backend, json_mode appends a plain-English instruction instead."""
        s = _make_settings(model_backend="ollama")

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response(text="{}")
            chat(_messages(), role=Role.RED_TEAM, settings=s, json_mode=True)
            kwargs = mock_client.chat.completions.create.call_args[1]
            last_msg = kwargs["messages"][-1]
            assert "JSON" in last_msg["content"]
            # response_format should NOT be set for ollama
            assert "response_format" not in kwargs


# --------------------------------------------------------------------------- #
# (g) BudgetExceededError + reset_cost_total
# --------------------------------------------------------------------------- #
class TestBudgetGuard:
    @pytest.fixture(autouse=True)
    def reset(self) -> None:  # type: ignore[return]
        reset_cost_total()

    def test_raises_before_call_when_ceiling_exceeded(self) -> None:
        s = _make_settings()
        ceiling = 0.000001  # tiny ceiling — virtually any estimate will exceed it

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response()
            with pytest.raises(BudgetExceededError):
                # Force the estimate to be large by using a long message
                long_msg = [{"role": "user", "content": "x" * 10_000}]
                chat(long_msg, role=Role.JUDGE, settings=s, budget_ceiling_usd=ceiling)
            # Confirm the underlying API was NOT called
            mock_client.chat.completions.create.assert_not_called()

    def test_call_succeeds_when_under_ceiling(self) -> None:
        s = _make_settings()
        ceiling = 10.0  # generous ceiling

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response()
            result = chat(_messages(), role=Role.JUDGE, settings=s, budget_ceiling_usd=ceiling)

        assert isinstance(result, ChatResult)

    def test_reset_cost_total_clears_accumulator(self) -> None:
        s = _make_settings()

        with patch("agentforge.llm.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = _fake_response(
                input_tokens=1000, output_tokens=500
            )
            chat(_messages(), role=Role.JUDGE, settings=s)

        assert get_cost_total() > 0.0
        reset_cost_total()
        assert get_cost_total() == 0.0

    def test_budget_error_does_not_increment_cost(self) -> None:
        """If a BudgetExceededError fires, the cost total must not change."""
        s = _make_settings()
        ceiling = 0.0  # always exceeded

        with patch("agentforge.llm.OpenAI"):
            with pytest.raises(BudgetExceededError):
                chat(_messages(), role=Role.JUDGE, settings=s, budget_ceiling_usd=ceiling)

        assert get_cost_total() == 0.0
