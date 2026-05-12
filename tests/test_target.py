"""Unit tests for the Target Adapter's deterministic bits — redaction, the
rate limiter, and the allowlist guard. No live target needed."""

from __future__ import annotations

import time

import pytest

from agentforge.target.adapter import (
    PHIRedactor,
    RateLimiter,
    TargetAdapter,
    TargetNotAllowedError,
)


class TestPHIRedactor:
    def test_redacts_ssn_phone_email(self) -> None:
        text = "SSN 123-45-6789, call (555) 123-4567, email jane.doe@example.com"
        out = PHIRedactor.redact(text)
        assert "123-45-6789" not in out
        assert "555" not in out
        assert "jane.doe@example.com" not in out
        assert "[REDACTED-SSN]" in out
        assert "[REDACTED-PHONE]" in out
        assert "[REDACTED-EMAIL]" in out

    def test_redacts_dob_in_context_only(self) -> None:
        out = PHIRedactor.redact("DOB: 1985-03-14. Encounter on 2026-05-11.")
        assert "1985-03-14" not in out
        assert "[REDACTED-DOB]" in out
        # a bare ISO date NOT in a DOB context is left alone
        assert "2026-05-11" in out

    def test_redacts_mrn_in_context_only(self) -> None:
        out = PHIRedactor.redact("MRN: A1234567 — order #42 placed")
        assert "A1234567" not in out
        assert "[REDACTED-MRN]" in out
        assert "#42" in out  # not an MRN context

    def test_redacts_demo_patient_family_names(self) -> None:
        out = PHIRedactor.redact("Patient Chen reports chest pain; Mr. Nguyen is stable.")
        assert "Chen" not in out and "Nguyen" not in out
        assert out.count("[REDACTED-NAME]") == 2

    def test_empty_passthrough(self) -> None:
        assert PHIRedactor.redact("") == ""


class TestRateLimiter:
    def test_enforces_min_interval(self) -> None:
        rl = RateLimiter(requests_per_minute=600)  # 0.1s min interval
        rl.wait()  # first call: no delay
        t0 = time.monotonic()
        rl.wait()  # second call: should sleep ~0.1s
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.09  # allow a little slack

    def test_first_call_no_delay(self) -> None:
        rl = RateLimiter(
            requests_per_minute=1
        )  # 60s min interval — but the first call must not block
        t0 = time.monotonic()
        rl.wait()
        assert time.monotonic() - t0 < 0.5


class TestAllowlist:
    def test_rejects_non_allowlisted_host(self) -> None:
        with pytest.raises(TargetNotAllowedError):
            TargetAdapter(base_url="https://evil.example.com")

    def test_rejects_arbitrary_third_party(self) -> None:
        with pytest.raises(TargetNotAllowedError):
            TargetAdapter(base_url="https://api.openai.com")

    def test_accepts_localhost(self) -> None:
        a = TargetAdapter(base_url="http://localhost:7300")
        assert a.base_url == "http://localhost:7300"
        a.close()

    def test_accepts_127_0_0_1(self) -> None:
        a = TargetAdapter(base_url="http://127.0.0.1:8300")
        a.close()
