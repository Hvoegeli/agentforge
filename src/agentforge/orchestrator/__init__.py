"""The Orchestrator Agent — coverage-driven campaign selection, cost control, and
driving the closed-loop run graph (:mod:`agentforge.orchestrator.graph`).

Responsibilities, per ``ARCHITECTURE.md``:

* **Pick the next campaign** — given the findings DB, target the *least-covered*
  threat category (so the platform spreads attention rather than hammering one
  area). Without a DB it defaults to ``C1`` (prompt injection — the MVP full-loop
  category).
* **Set the budget** — every campaign carries a ``cost_ceiling_usd``; the run loop
  halts the moment agent-side LLM spend would breach it.
* **Run the loop** — health-check + log in to the target, build the LangGraph
  graph, invoke it, write the ``RunRecord``, and return a :class:`RunSummary`.

The Orchestrator never adjudicates and never authors reports — it sequences the
other agents. It is also the only component that talks to the target's *health*
endpoint before a run (the ``attack`` node only uses ``TargetAdapter.attack()``,
which never raises).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agentforge.attacks.red_team import RedTeamAgent
from agentforge.attacks.seeds import SEEDS_BY_CATEGORY
from agentforge.config import Settings, get_settings
from agentforge.documentation import DocumentationAgent
from agentforge.judge import Judge
from agentforge.models import Finding, RunRecord, Severity, TargetSurface, ThreatCategory
from agentforge.orchestrator.graph import (
    GraphDeps,
    build_graph,
    initial_state,
    recursion_limit_for,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agentforge.storage.db import Database

logger = logging.getLogger("agentforge.orchestrator")

# Categories that ship with a deterministic seed corpus today (so a campaign on
# them produces real attacks without an LLM). Used for coverage-driven selection.
_SEEDED_CATEGORIES: tuple[ThreatCategory, ...] = tuple(
    c for c in ThreatCategory if SEEDS_BY_CATEGORY.get(c.value)
)
# MVP priority order when coverage is tied / there is no DB.
_PRIORITY: tuple[ThreatCategory, ...] = (
    ThreatCategory.PROMPT_INJECTION,
    ThreatCategory.DATA_EXFILTRATION,
    ThreatCategory.TOOL_MISUSE,
    ThreatCategory.IDENTITY_ROLE_EXPLOITATION,
    ThreatCategory.DENIAL_OF_SERVICE,
)


@dataclass(slots=True)
class Campaign:
    """One Orchestrator-directed run unit — the cost/coverage accounting boundary."""

    category: ThreatCategory
    directive: str
    cost_ceiling_usd: float = 0.50
    max_attacks: int | None = None  # None = run the whole deterministic floor
    surfaces: set[TargetSurface] | None = None
    include_multi_turn: bool = True
    include_external_attacks: bool = False  # also pull agentforge.attacks.external (curated public-dataset corpus)
    include_external_engines: bool = False  # + garak/PyRIT/promptfoo wrappers, if installed
    extra_subs: dict[str, str] = field(default_factory=dict)
    judge_context: dict = field(default_factory=dict)  # authorized_patient_ids, system_prompt_fragments, …
    mutate_near_misses: bool = False
    mutate_with_llm: bool = False
    max_variants_per_near_miss: int = 3
    severity_override: Severity | None = None
    # Set True only once agentforge.judge.corpus has validated the LLM-Judge for
    # the current prompt version — then an LLM-Judge FAIL above the auto-file
    # confidence becomes a confirmed finding; otherwise it is filed as a lead.
    llm_judge_validated: bool = False
    reports_dir: str = "findings"


@dataclass(slots=True)
class RunSummary:
    """The outcome of one campaign run."""

    run_id: str
    category: str
    directive: str
    target_sha: str
    target_base_url: str
    n_attacks: int
    n_confirmed_findings: int
    n_leads: int
    n_uncertain: int
    agent_cost_usd: float
    target_llm_cost_usd: float
    halted_reason: str | None
    findings: list[Finding] = field(default_factory=list)

    def describe(self) -> str:
        halt = self.halted_reason or "completed (queue exhausted)"
        return (
            f"run {self.run_id[:12]} — {self.category}: "
            f"{self.n_attacks} attacks, {self.n_confirmed_findings} confirmed finding(s), "
            f"{self.n_leads} lead(s), {self.n_uncertain} uncertain; "
            f"agent cost ${self.agent_cost_usd:.4f}; halt: {halt}"
        )


class Orchestrator:
    def __init__(self, *, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    # -- campaign selection ------------------------------------------------ #
    def pick_campaign(
        self,
        *,
        category: ThreatCategory | None = None,
        db: Database | None = None,
        cost_ceiling_usd: float | None = None,
        max_attacks: int | None = None,
        **campaign_overrides: object,
    ) -> Campaign:
        """Return the next :class:`Campaign`.

        If *category* is given, use it. Otherwise, if *db* is given, pick the
        seeded category with the fewest attempts so far (ties broken by
        :data:`_PRIORITY`); with no DB, default to the first priority category.
        """
        if category is None:
            category = self._least_covered(db)
        directive = (
            f"probe {category.value} against the target"
            + (f" (≤{max_attacks} attacks" if max_attacks else " (full deterministic floor")
            + f", budget ${cost_ceiling_usd if cost_ceiling_usd is not None else 0.50:.2f})"
        )
        kwargs: dict[str, object] = dict(category=category, directive=directive)
        if cost_ceiling_usd is not None:
            kwargs["cost_ceiling_usd"] = cost_ceiling_usd
        if max_attacks is not None:
            kwargs["max_attacks"] = max_attacks
        kwargs.update(campaign_overrides)
        return Campaign(**kwargs)  # type: ignore[arg-type]

    def _least_covered(self, db: Database | None) -> ThreatCategory:
        if db is None:
            return _PRIORITY[0]
        try:
            coverage = db.category_coverage()
        except Exception:
            return _PRIORITY[0]
        candidates = _SEEDED_CATEGORIES or _PRIORITY
        # min by (attempt count, priority index)
        def _key(c: ThreatCategory) -> tuple[int, int]:
            try:
                pidx = _PRIORITY.index(c)
            except ValueError:
                pidx = len(_PRIORITY)
            return (coverage.get(c.value, 0), pidx)

        return min(candidates, key=_key)

    # -- running ----------------------------------------------------------- #
    def run_campaign(
        self,
        campaign: Campaign,
        *,
        target_adapter: object,
        red_team: RedTeamAgent | None = None,
        judge: Judge | None = None,
        doc_agent: DocumentationAgent | None = None,
        db: Database | None = None,
    ) -> RunSummary:
        """Execute *campaign* end-to-end and return a :class:`RunSummary`."""
        red_team = red_team or RedTeamAgent()
        judge = judge or Judge(settings=self._settings, default_context=campaign.judge_context or None)
        doc_agent = doc_agent or DocumentationAgent(settings=self._settings)

        target_sha = str(getattr(target_adapter, "target_sha", None) or "unknown")
        target_base_url = str(getattr(target_adapter, "base_url", None) or "unknown")

        run = RunRecord(
            orchestrator_directive=campaign.directive,
            categories_targeted=[campaign.category],
            target_sha=target_sha,
            target_base_url=target_base_url,
        )
        if db is not None:
            try:
                db.insert(run)
            except Exception as exc:
                logger.warning("orchestrator: could not persist RunRecord: %s", exc)

        # Health-gate + login (best-effort; fakes/adapters without these are skipped).
        if not self._target_ready(target_adapter):
            logger.error("orchestrator: target %s is not ready — aborting run", target_base_url)
            if db is not None:
                try:
                    db.finish_run(
                        run.id,
                        halted_reason="target_unavailable",
                        totals={"n_attacks": 0, "n_confirmed_findings": 0, "n_uncertain": 0, "total_cost_usd": 0.0},
                    )
                except Exception:
                    pass
            return RunSummary(
                run_id=run.id,
                category=campaign.category.value,
                directive=campaign.directive,
                target_sha=target_sha,
                target_base_url=target_base_url,
                n_attacks=0,
                n_confirmed_findings=0,
                n_leads=0,
                n_uncertain=0,
                agent_cost_usd=0.0,
                target_llm_cost_usd=0.0,
                halted_reason="target_unavailable",
                findings=[],
            )

        deps = GraphDeps(
            campaign=campaign,
            red_team=red_team,
            judge=judge,
            doc_agent=doc_agent,
            target_adapter=target_adapter,
            db=db,
            settings=self._settings,
        )
        graph = build_graph(deps)

        # Pre-plan the deterministic floor so we can size the recursion budget; the
        # `plan` node will reuse this queue rather than regenerate it.
        planned = red_team.generate_attack_cases(
            campaign.category,
            limit=campaign.max_attacks,
            surfaces=campaign.surfaces,
            include_multi_turn=campaign.include_multi_turn,
            extra_subs=campaign.extra_subs or None,
            include_external=campaign.include_external_attacks,
            include_external_engines=campaign.include_external_engines,
        )
        state = initial_state(run.id)
        state["queue"] = planned
        rl = recursion_limit_for(campaign, len(planned))

        final = graph.invoke(state, config={"recursion_limit": rl})

        summary = RunSummary(
            run_id=run.id,
            category=campaign.category.value,
            directive=campaign.directive,
            target_sha=target_sha,
            target_base_url=target_base_url,
            n_attacks=int(final["n_attacks"]),
            n_confirmed_findings=int(final["n_findings"]),
            n_leads=int(final["n_leads"]),
            n_uncertain=int(final["n_uncertain"]),
            agent_cost_usd=float(final["total_cost_usd"]),
            target_llm_cost_usd=float(final["target_llm_cost_usd"]),
            halted_reason=final.get("halt_reason"),
            findings=list(final["findings"]),
        )
        if db is not None:
            try:
                db.finish_run(
                    run.id,
                    halted_reason=summary.halted_reason,
                    totals={
                        "n_attacks": summary.n_attacks,
                        "n_confirmed_findings": summary.n_confirmed_findings,
                        "n_uncertain": summary.n_uncertain,
                        "total_cost_usd": summary.agent_cost_usd,
                    },
                )
            except Exception as exc:
                logger.warning("orchestrator: could not finalise RunRecord: %s", exc)
        logger.info("orchestrator: %s", summary.describe())
        return summary

    @staticmethod
    def _target_ready(adapter: object) -> bool:
        ok = True
        req = getattr(adapter, "require_healthy", None)
        if callable(req):
            try:
                req()
            except Exception as exc:
                logger.error("orchestrator: target health check failed: %s", exc)
                ok = False
        if ok:
            login = getattr(adapter, "ensure_logged_in", None)
            if callable(login):
                try:
                    login()
                except Exception as exc:
                    logger.error("orchestrator: target login failed: %s", exc)
                    ok = False
        return ok


__all__ = ["Campaign", "Orchestrator", "RunSummary"]
