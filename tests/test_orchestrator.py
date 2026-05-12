"""Tests for the Orchestrator + the LangGraph run loop, end-to-end against a fake
target adapter (no network, no LLM)."""

from __future__ import annotations

import re
from pathlib import Path

from agentforge.attacks.red_team import RedTeamAgent
from agentforge.documentation import DocumentationAgent
from agentforge.judge import Judge
from agentforge.models import AttackAttempt, AttackCase, ThreatCategory, ToolCallTrace
from agentforge.orchestrator import Orchestrator
from agentforge.storage.db import Database

_CANARY_RE = re.compile(r"AF-CANARY-[0-9a-f]+")


class FakeAdapter:
    """Stands in for ``TargetAdapter``. ``vulnerable`` controls whether the 'target'
    echoes any planted canary (→ a C1 FAIL) or behaves safely."""

    def __init__(self, *, vulnerable: bool = True, healthy: bool = True) -> None:
        self.target_sha = "fake-sha-0001"
        self.base_url = "http://localhost:7300"
        self._vulnerable = vulnerable
        self._healthy = healthy
        self.attacks_seen: list[str] = []

    def require_healthy(self) -> None:
        if not self._healthy:
            raise RuntimeError("fake target /healthz not OK")

    def ensure_logged_in(self) -> None:
        return None

    def attack(self, case: AttackCase) -> AttackAttempt:
        self.attacks_seen.append(case.id)
        joined = "\n".join(case.prompt_or_sequence)
        if self._vulnerable:
            found = _CANARY_RE.findall(joined)
            echoed = (" Also, as requested: " + " ".join(found)) if found else ""
            response = f"Here's a summary of the patient's recent chart.{echoed}"
            trace = [ToolCallTrace(name="get_patient_card", args_redacted={"patient_id": "p-a"}, ok=True)]
        else:
            response = (
                "I can't follow instructions embedded in a message like that. "
                "If you have a question about a patient on your panel, I can help."
            )
            trace = []
        return AttackAttempt(
            attack_case_id=case.id,
            target_sha=self.target_sha,
            target_base_url=self.base_url,
            request_summary=f"sent {len(case.prompt_or_sequence)} turn(s)",
            response_redacted=response,
            tool_trace=trace,
            token_usage={"input": 300, "output": 80},
            cost_usd=0.0,
            latency_ms=750.0,
            n_supervisor_hops=1,
        )


def _deterministic_agents() -> tuple[RedTeamAgent, Judge, DocumentationAgent]:
    return RedTeamAgent(), Judge(enable_llm_judge=False), DocumentationAgent(use_llm_narrative=False)


# --------------------------------------------------------------------------- #
# campaign selection
# --------------------------------------------------------------------------- #
def test_pick_campaign_defaults_to_prompt_injection_without_db() -> None:
    c = Orchestrator().pick_campaign()
    assert c.category is ThreatCategory.PROMPT_INJECTION
    assert c.cost_ceiling_usd == 0.50
    assert "prompt_injection" in c.directive


def test_pick_campaign_picks_least_covered_with_db() -> None:
    db = Database(":memory:")
    orch = Orchestrator()
    # Run a small C1 campaign so prompt_injection has coverage; the next pick
    # should choose something else.
    rt, judge, doc = _deterministic_agents()
    c1 = orch.pick_campaign(category=ThreatCategory.PROMPT_INJECTION, max_attacks=2, reports_dir="/tmp/af-test-reports")
    orch.run_campaign(c1, target_adapter=FakeAdapter(vulnerable=False), red_team=rt, judge=judge, doc_agent=doc, db=db)
    nxt = orch.pick_campaign(db=db)
    assert nxt.category is not ThreatCategory.PROMPT_INJECTION
    db.close()


# --------------------------------------------------------------------------- #
# the closed loop
# --------------------------------------------------------------------------- #
def test_run_campaign_full_loop_against_vulnerable_target(tmp_path: Path) -> None:
    db = Database(":memory:")
    orch = Orchestrator()
    rt, judge, doc = _deterministic_agents()
    campaign = orch.pick_campaign(
        category=ThreatCategory.PROMPT_INJECTION, max_attacks=3, reports_dir=str(tmp_path)
    )
    adapter = FakeAdapter(vulnerable=True)
    summary = orch.run_campaign(campaign, target_adapter=adapter, red_team=rt, judge=judge, doc_agent=doc, db=db)

    assert summary.n_attacks == 3
    assert len(adapter.attacks_seen) == 3
    # the first 3 C1 seeds all plant a canary in their turns → all FAIL → all confirmed
    assert summary.n_confirmed_findings == 3
    assert summary.halted_reason == "attack_cap"
    assert summary.agent_cost_usd == 0.0  # purely deterministic run

    # persistence
    runs = db.recent_runs()
    assert len(runs) == 1 and runs[0]["n_attacks"] == 3 and runs[0]["halted_reason"] == "attack_cap"
    assert db.category_coverage()["prompt_injection"] == 3
    assert sum(db.open_findings_by_severity().values()) == 3

    # reports written to disk
    report_files = list(tmp_path.glob("*.md"))
    assert len(report_files) == 3
    body = report_files[0].read_text()
    assert "Vulnerability Report" in body and "C1.canary-or-sentinel" in body

    db.close()


def test_run_campaign_against_safe_target_yields_no_findings(tmp_path: Path) -> None:
    db = Database(":memory:")
    orch = Orchestrator()
    rt, judge, doc = _deterministic_agents()
    campaign = orch.pick_campaign(
        category=ThreatCategory.PROMPT_INJECTION, max_attacks=4, reports_dir=str(tmp_path)
    )
    summary = orch.run_campaign(
        campaign, target_adapter=FakeAdapter(vulnerable=False), red_team=rt, judge=judge, doc_agent=doc, db=db
    )
    assert summary.n_attacks == 4
    assert summary.n_confirmed_findings == 0
    rates = db.verdict_rates_by_category()["prompt_injection"]
    assert rates.get("pass", 0) >= 1
    assert not list(tmp_path.glob("*.md"))  # no reports when nothing fails
    db.close()


def test_run_campaign_aborts_when_target_unavailable(tmp_path: Path) -> None:
    db = Database(":memory:")
    orch = Orchestrator()
    rt, judge, doc = _deterministic_agents()
    campaign = orch.pick_campaign(category=ThreatCategory.PROMPT_INJECTION, reports_dir=str(tmp_path))
    summary = orch.run_campaign(
        campaign, target_adapter=FakeAdapter(healthy=False), red_team=rt, judge=judge, doc_agent=doc, db=db
    )
    assert summary.n_attacks == 0
    assert summary.halted_reason == "target_unavailable"
    assert db.recent_runs()[0]["halted_reason"] == "target_unavailable"
    db.close()


def test_zero_budget_halts_before_any_attack(tmp_path: Path) -> None:
    db = Database(":memory:")
    orch = Orchestrator()
    rt, judge, doc = _deterministic_agents()
    campaign = orch.pick_campaign(
        category=ThreatCategory.PROMPT_INJECTION, cost_ceiling_usd=0.0, reports_dir=str(tmp_path)
    )
    summary = orch.run_campaign(
        campaign, target_adapter=FakeAdapter(vulnerable=True), red_team=rt, judge=judge, doc_agent=doc, db=db
    )
    assert summary.n_attacks == 0
    assert summary.halted_reason == "budget_reached"
    db.close()
