"""The AgentForge run graph (LangGraph).

This is the closed loop the PRD asks for, expressed as a LangGraph ``StateGraph``:

    START → plan → pop ⇄ attack → judge → (document) → pop … → END

Nodes (each is one agent / component doing one step):

* **plan** (Orchestrator) — turn the campaign into a work queue of ``AttackCase``s
  (the deterministic seed floor for the campaign's category, optionally filtered
  by surface / single-turn-only).
* **pop** (Orchestrator) — the loop head: check the halt conditions (budget
  ceiling, attack cap, queue empty), and if clear, take the next case off the
  queue.
* **attack** (Target Adapter) — execute the case against the target; persist the
  ``AttackCase`` and the resulting ``AttackAttempt``.
* **judge** (Judge) — adjudicate the attempt against its invariant; persist the
  ``JudgeVerdict``. A ``PARTIAL`` ("near-miss") result, when the campaign asks for
  it, feeds the case back to the Red Team's mutator and appends the variants to
  the queue.
* **document** (Documentation) — only reached on a ``FAIL`` verdict: build a
  ``Finding`` (or, for an un-validated LLM-Judge verdict, a *lead*), write the
  vuln report, persist the finding.

The graph holds no I/O credentials — :func:`run_campaign` health-checks and logs
in to the target *before* invoking the graph, and the ``attack`` node uses
``TargetAdapter.attack()`` which never raises (it records per-attempt errors on
the ``AttackAttempt``). The Judge then returns ``UNCERTAIN`` for an errored
attempt, so a flaky target degrades coverage rather than crashing the run.

Cost accounting: ``AttackAttempt.cost_usd`` is the *target's* inference cost
(informational — not AgentForge's budget). The budget that the ``cost_ceiling_usd``
guards is the *agent-side* LLM spend (Red-Team LLM mutation, LLM-Judge, LLM report
narrative), read as the delta of :func:`agentforge.llm.get_cost_total` around the
``judge`` / ``document`` nodes. A purely-deterministic campaign therefore costs
``$0`` — the free, reproducible floor.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypedDict

from langgraph.graph import END, START, StateGraph

from agentforge import llm
from agentforge.config import Settings, get_settings
from agentforge.documentation import new_finding, severity_baseline
from agentforge.models import (
    AttackAttempt,
    AttackCase,
    CheckType,
    Finding,
    FindingStatus,
    ObservedBehavior,
    Severity,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agentforge.attacks.red_team import RedTeamAgent
    from agentforge.documentation import DocumentationAgent
    from agentforge.judge import Judge
    from agentforge.orchestrator import Campaign
    from agentforge.storage.db import Database

logger = logging.getLogger("agentforge.orchestrator.graph")


# --------------------------------------------------------------------------- #
# Graph state + dependency bundle
# --------------------------------------------------------------------------- #
class GraphState(TypedDict):
    run_id: str
    queue: list[AttackCase]  # cases not yet executed
    current_case: AttackCase | None  # the case in flight (attack → judge → document)
    last_attempt: AttackAttempt | None
    last_verdict: Any  # JudgeVerdict | None  (loosely typed to keep the TypedDict importable cheaply)
    total_cost_usd: float  # agent-side LLM spend (the budgeted cost)
    target_llm_cost_usd: float  # target-side inference cost (informational)
    n_attacks: int
    n_findings: int  # confirmed findings
    n_leads: int  # un-validated LLM-Judge FAILs surfaced as leads
    n_uncertain: int
    halt_reason: str | None
    findings: list[Finding]


@dataclass(slots=True)
class GraphDeps:
    """Everything the graph nodes need, bound into the compiled graph by :func:`build_graph`."""

    campaign: Campaign
    red_team: RedTeamAgent
    judge: Judge
    doc_agent: DocumentationAgent
    target_adapter: Any  # TargetAdapter (or any object with .attack(AttackCase) -> AttackAttempt)
    db: Database | None = None
    settings: Settings | None = None


# --------------------------------------------------------------------------- #
# Graph builder
# --------------------------------------------------------------------------- #
def build_graph(deps: GraphDeps):  # -> CompiledStateGraph
    """Build and compile the AgentForge run graph for *deps* (one campaign)."""
    campaign = deps.campaign
    settings = deps.settings or get_settings()
    autofile = float(settings.judge_autofile_confidence)

    def _persist(model: Any, *, run_id: str | None = None) -> None:
        if deps.db is not None:
            try:
                deps.db.insert(model, run_id=run_id)
            except Exception as exc:  # storage hiccups must not kill the run
                logger.warning("orchestrator: failed to persist %s: %s", type(model).__name__, exc)

    # -- nodes ------------------------------------------------------------- #
    def plan(state: GraphState) -> dict[str, Any]:
        if state.get("queue"):
            # run_campaign() pre-populated the work queue (so it could size the
            # recursion budget) — reuse it rather than regenerate.
            return {}
        cases = deps.red_team.generate_attack_cases(
            campaign.category,
            limit=campaign.max_attacks,
            surfaces=campaign.surfaces,
            include_multi_turn=campaign.include_multi_turn,
            extra_subs=campaign.extra_subs or None,
        )
        logger.info(
            "orchestrator: campaign %r — planned %d attack cases for %s",
            campaign.directive,
            len(cases),
            campaign.category.value,
        )
        return {"queue": cases}

    def pop(state: GraphState) -> dict[str, Any]:
        if state.get("halt_reason"):
            return {"current_case": None}
        if state["total_cost_usd"] >= campaign.cost_ceiling_usd:
            logger.info("orchestrator: budget ceiling $%.4f reached — halting", campaign.cost_ceiling_usd)
            return {"current_case": None, "halt_reason": "budget_reached"}
        if campaign.max_attacks is not None and state["n_attacks"] >= campaign.max_attacks:
            return {"current_case": None, "halt_reason": "attack_cap"}
        queue = state["queue"]
        if not queue:
            return {"current_case": None}  # natural completion (halt_reason stays None)
        return {"current_case": queue[0], "queue": queue[1:]}

    def attack(state: GraphState) -> dict[str, Any]:
        case = state["current_case"]
        assert case is not None  # the router only routes here when current_case is set
        _persist(case, run_id=state["run_id"])
        attempt: AttackAttempt = deps.target_adapter.attack(case)
        _persist(attempt, run_id=state["run_id"])
        return {
            "last_attempt": attempt,
            "n_attacks": state["n_attacks"] + 1,
            "target_llm_cost_usd": state["target_llm_cost_usd"] + float(attempt.cost_usd or 0.0),
        }

    def judge(state: GraphState) -> dict[str, Any]:
        case = state["current_case"]
        attempt = state["last_attempt"]
        assert case is not None and attempt is not None
        before = llm.get_cost_total()
        verdict = deps.judge.adjudicate(case, attempt, context=campaign.judge_context or None)
        agent_cost = max(0.0, llm.get_cost_total() - before)
        _persist(verdict)
        updates: dict[str, Any] = {
            "last_verdict": verdict,
            "total_cost_usd": state["total_cost_usd"] + agent_cost,
        }
        if verdict.observed_behavior is ObservedBehavior.UNCERTAIN:
            updates["n_uncertain"] = state["n_uncertain"] + 1
        elif verdict.observed_behavior is ObservedBehavior.PARTIAL and campaign.mutate_near_misses:
            before_m = llm.get_cost_total()
            variants = deps.red_team.mutate(
                case,
                n=campaign.max_variants_per_near_miss,
                use_llm=campaign.mutate_with_llm,
            )
            updates["total_cost_usd"] = updates["total_cost_usd"] + max(0.0, llm.get_cost_total() - before_m)
            updates["queue"] = state["queue"] + variants
            logger.info("orchestrator: near-miss on %s — queued %d mutated variants", case.id, len(variants))
        return updates

    def document(state: GraphState) -> dict[str, Any]:
        case = state["current_case"]
        attempt = state["last_attempt"]
        verdict = state["last_verdict"]
        assert case is not None and attempt is not None and verdict is not None

        is_deterministic = verdict.check_type is CheckType.DETERMINISTIC
        confirmed = is_deterministic or (
            campaign.llm_judge_validated and (verdict.confidence or 0.0) >= autofile
        )
        if confirmed:
            severity = campaign.severity_override or severity_baseline(case)
            finding = new_finding(
                case, attempt, verdict, severity=severity, status=FindingStatus.OPEN
            )
        else:
            finding = new_finding(
                case, attempt, verdict, severity=Severity.LEAD, status=FindingStatus.LEAD
            )

        before = llm.get_cost_total()
        try:
            path, is_draft = deps.doc_agent.document(
                finding,
                case,
                attempt,
                verdict,
                reports_dir=campaign.reports_dir,
                llm_judge_validated=campaign.llm_judge_validated,
            )
            finding = finding.model_copy(update={"report_path": str(path)})
            logger.info(
                "orchestrator: %s finding %s (%s/%s) -> %s%s",
                "confirmed" if confirmed else "LEAD",
                finding.id,
                case.category.value,
                finding.severity.value,
                path,
                " [DRAFT]" if is_draft else "",
            )
        except Exception as exc:
            logger.warning("orchestrator: report generation failed for %s: %s", finding.id, exc)
        doc_cost = max(0.0, llm.get_cost_total() - before)
        _persist(finding)
        return {
            "findings": state["findings"] + [finding],
            "n_findings": state["n_findings"] + (1 if confirmed else 0),
            "n_leads": state["n_leads"] + (0 if confirmed else 1),
            "total_cost_usd": state["total_cost_usd"] + doc_cost,
        }

    # -- routers ----------------------------------------------------------- #
    def route_after_pop(state: GraphState) -> str:
        return "attack" if state.get("current_case") is not None else "end"

    def route_after_judge(state: GraphState) -> str:
        v = state["last_verdict"]
        return "document" if v is not None and v.observed_behavior is ObservedBehavior.FAIL else "pop"

    # -- wire it ----------------------------------------------------------- #
    g: StateGraph = StateGraph(GraphState)
    g.add_node("plan", plan)
    g.add_node("pop", pop)
    g.add_node("attack", attack)
    g.add_node("judge", judge)
    g.add_node("document", document)
    g.add_edge(START, "plan")
    g.add_edge("plan", "pop")
    g.add_conditional_edges("pop", route_after_pop, {"attack": "attack", "end": END})
    g.add_edge("attack", "judge")
    g.add_conditional_edges("judge", route_after_judge, {"document": "document", "pop": "pop"})
    g.add_edge("document", "pop")
    return g.compile()


# --------------------------------------------------------------------------- #
# Convenience: initial state + recursion budget
# --------------------------------------------------------------------------- #
def initial_state(run_id: str) -> GraphState:
    return GraphState(
        run_id=run_id,
        queue=[],
        current_case=None,
        last_attempt=None,
        last_verdict=None,
        total_cost_usd=0.0,
        target_llm_cost_usd=0.0,
        n_attacks=0,
        n_findings=0,
        n_leads=0,
        n_uncertain=0,
        halt_reason=None,
        findings=[],
    )


def recursion_limit_for(campaign: Campaign, n_planned_cases: int) -> int:
    """A LangGraph recursion limit large enough for the worst case of this campaign.

    Each case costs up to 4 super-steps (pop → attack → judge → document); add the
    fan-out from near-miss mutation if enabled, plus headroom for plan + the final
    pop.
    """
    if campaign.max_attacks is not None:
        effective = campaign.max_attacks
    elif campaign.mutate_near_misses:
        effective = n_planned_cases * (campaign.max_variants_per_near_miss + 1)
    else:
        effective = n_planned_cases
    return 4 * max(1, effective) + 25


__all__ = [
    "GraphDeps",
    "GraphState",
    "build_graph",
    "initial_state",
    "recursion_limit_for",
]
