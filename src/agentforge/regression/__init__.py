"""Regression replay harness.

A regression test in AgentForge asserts the **invariant**, not the model's output
string (the target is non-deterministic). :func:`replay_case` re-runs a pinned
``AttackCase`` against the target *N* times and reports how many of those replays
*cleared* the invariant. Because the target is stochastic, "N replays all-clear"
is an honest **confidence interval** — N, the clear rate, the target SHA, the
date — not a proof; :class:`ReplayResult` carries exactly that.

Two uses:

* **Before a fix** — replay a confirmed finding's case to confirm the
  vulnerability mechanism is still live (the clear rate is low / zero).
* **After a fix** — replay the same case at the new target SHA; ``holds`` becomes
  ``True`` iff every replay cleared, which (with enough N) is the regression
  passing. AgentForge then promotes the case into the regression suite
  (``mark_in_regression``) so future runs replay it automatically.

:func:`replay_case` performs no campaign accounting and writes no files — it is
the narrow "does this one invariant hold across N replays" primitive.
:func:`run_regression_suite` builds on it: replay every regression case at the
current target SHA, look up the finding(s) each case produced, and report (and,
with ``update_status=True``, apply) the status transition the replay implies —
``resolved`` when the invariant now holds, ``regression`` when a previously-fixed
hole reappeared. It returns the result as a serialisable dict; the
``agentforge regression-suite`` CLI command renders it and (with ``--out``) writes
it under ``evals/results/`` as the committable post-fix artifact.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentforge.judge import Judge
from agentforge.models import (
    AttackAttempt,
    AttackCase,
    FindingStatus,
    JudgeVerdict,
    ObservedBehavior,
)

logger = logging.getLogger("agentforge.regression")


@dataclass(slots=True)
class ReplayResult:
    case_id: str
    invariant_id: str
    n: int
    n_clear: int  # replays where the invariant held (PASS, or invariant_passed True)
    n_pass: int
    n_fail: int
    n_partial: int
    n_uncertain: int
    n_error: int  # replays whose attempt errored at the target
    target_sha: str
    target_base_url: str
    attempts: list[AttackAttempt] = field(default_factory=list)
    verdicts: list[JudgeVerdict] = field(default_factory=list)

    @property
    def clear_rate(self) -> float:
        return self.n_clear / self.n if self.n else 0.0

    @property
    def holds(self) -> bool:
        """True iff *every* replay cleared the invariant (no FAIL/PARTIAL/UNCERTAIN/error)."""
        return self.n > 0 and self.n_clear == self.n

    def describe(self) -> str:
        verdict = "HOLDS" if self.holds else "DOES NOT HOLD"
        return (
            f"regression replay — case {self.case_id[:12]} / {self.invariant_id}: "
            f"{verdict} ({self.n_clear}/{self.n} replays clear, rate {self.clear_rate:.0%}) "
            f"against {self.target_base_url}@{self.target_sha} — "
            f"pass={self.n_pass} fail={self.n_fail} partial={self.n_partial} "
            f"uncertain={self.n_uncertain} error={self.n_error}"
        )


def _cleared(verdict: JudgeVerdict) -> bool:
    if verdict.observed_behavior is ObservedBehavior.PASS:
        return True
    # A deterministic check that explicitly passed also counts as clear.
    return verdict.invariant_passed is True and verdict.observed_behavior is not ObservedBehavior.FAIL


def replay_case(
    case: AttackCase,
    *,
    n: int,
    adapter: object,
    judge: Judge | None = None,
    context: dict | None = None,
) -> ReplayResult:
    """Replay *case* against the target *n* times and adjudicate each run.

    *adapter* is any object with ``.attack(AttackCase) -> AttackAttempt`` (the real
    ``TargetAdapter`` or a fake). *judge* defaults to a deterministic-only
    :class:`~agentforge.judge.Judge`.
    """
    if n < 1:
        raise ValueError("n must be >= 1")
    judge = judge or Judge(enable_llm_judge=False)
    target_sha = str(getattr(adapter, "target_sha", None) or "unknown")
    target_base_url = str(getattr(adapter, "base_url", None) or "unknown")

    attempts: list[AttackAttempt] = []
    verdicts: list[JudgeVerdict] = []
    counts = {ObservedBehavior.PASS: 0, ObservedBehavior.FAIL: 0, ObservedBehavior.PARTIAL: 0, ObservedBehavior.UNCERTAIN: 0}
    n_error = 0
    n_clear = 0

    for i in range(n):
        attempt: AttackAttempt = adapter.attack(case)
        verdict = judge.adjudicate(case, attempt, context=context)
        attempts.append(attempt)
        verdicts.append(verdict)
        counts[verdict.observed_behavior] = counts.get(verdict.observed_behavior, 0) + 1
        if attempt.error:
            n_error += 1
        if _cleared(verdict):
            n_clear += 1
        logger.debug("regression replay %d/%d for %s: %s", i + 1, n, case.id, verdict.observed_behavior)

    result = ReplayResult(
        case_id=case.id,
        invariant_id=case.invariant_id,
        n=n,
        n_clear=n_clear,
        n_pass=counts[ObservedBehavior.PASS],
        n_fail=counts[ObservedBehavior.FAIL],
        n_partial=counts[ObservedBehavior.PARTIAL],
        n_uncertain=counts[ObservedBehavior.UNCERTAIN],
        n_error=n_error,
        target_sha=target_sha,
        target_base_url=target_base_url,
        attempts=attempts,
        verdicts=verdicts,
    )
    logger.info("%s", result.describe())
    return result


def replay_finding(
    finding_id: str,
    *,
    db: object,
    adapter: object,
    n: int,
    judge: Judge | None = None,
    context: dict | None = None,
) -> ReplayResult:
    """Load the ``AttackCase`` behind *finding_id* from *db* and replay it *n* times.

    Raises ``KeyError`` if the finding or its attack case is not in the DB.
    """
    finding = db.get_finding(finding_id)  # type: ignore[attr-defined]
    if finding is None:
        raise KeyError(f"no finding with id {finding_id!r}")
    case = db.get_attack_case(finding.attack_case_id)  # type: ignore[attr-defined]
    if case is None:
        raise KeyError(f"finding {finding_id!r} references missing attack case {finding.attack_case_id!r}")
    return replay_case(case, n=n, adapter=adapter, judge=judge, context=context)


# --------------------------------------------------------------------------- #
# Suite-level replay: many cases, optional finding-status update + JSON artifact
# --------------------------------------------------------------------------- #
# These statuses mean "the work list still has this open"; a holding replay
# closes them. (``lead`` is human-triage, not a confirmed finding — leave it.)
_OPEN_STATES = (FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.REGRESSION)


def _status_after_replay(current: FindingStatus, *, holds: bool) -> FindingStatus | None:
    """The status a finding should move to after a regression replay — or ``None`` for no change.

    - the invariant now holds across every replay → ``resolved`` (it was open / in-progress /
      a prior regression);
    - it does *not* hold but the finding was ``resolved`` → ``regression`` (a fixed hole
      reappeared — exactly the case the PRD's regression harness must detect);
    - otherwise the status already reflects reality, so leave it.
    """
    if holds and current in _OPEN_STATES:
        return FindingStatus.RESOLVED
    if not holds and current is FindingStatus.RESOLVED:
        return FindingStatus.REGRESSION
    return None


def run_regression_suite(
    cases: list[AttackCase],
    *,
    adapter: object,
    n: int,
    db: object | None = None,
    judge: Judge | None = None,
    update_status: bool = False,
) -> dict[str, Any]:
    """Replay every case in *cases* *n* times and return a serialisable suite report.

    The report is the committable "found → reported → fixed → regression-verified"
    artifact: per-case hold/clear counts at the current target SHA, plus — for each
    case's linked findings (looked up in *db* if given) — the status transition the
    replay implies (``resolved`` when the invariant now holds, ``regression`` when a
    previously-resolved hole reappeared). Pass ``update_status=True`` to actually
    write those transitions to *db*.

    *db* must expose ``findings_for_case(case_id) -> list[Finding]`` and
    ``update_finding_status(finding_id, FindingStatus)`` (the real
    :class:`~agentforge.storage.db.Database`); pass ``None`` to skip the
    finding-status side entirely (a pure "does the suite hold at this SHA" run).
    """
    judge = judge or Judge(enable_llm_judge=False)
    target_sha = str(getattr(adapter, "target_sha", None) or "unknown")
    target_base_url = str(getattr(adapter, "base_url", None) or "unknown")

    case_reports: list[dict[str, Any]] = []
    n_holding = 0
    n_regressions_detected = 0
    for case in cases:
        res = replay_case(case, n=n, adapter=adapter, judge=judge)
        if res.holds:
            n_holding += 1

        finding_reports: list[dict[str, Any]] = []
        if db is not None:
            for finding in db.findings_for_case(case.id):  # type: ignore[attr-defined]
                cur = finding.status if isinstance(finding.status, FindingStatus) else FindingStatus(finding.status)
                new = _status_after_replay(cur, holds=res.holds)
                if new is FindingStatus.REGRESSION:
                    n_regressions_detected += 1
                if new is not None and update_status:
                    db.update_finding_status(finding.id, new)  # type: ignore[attr-defined]
                finding_reports.append(
                    {
                        "finding_id": finding.id,
                        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                        "previous_status": cur.value,
                        "new_status": (new.value if new is not None else cur.value),
                        "changed": new is not None,
                        "applied": new is not None and update_status,
                    }
                )

        case_reports.append(
            {
                "case_id": case.id,
                "subcategory": case.subcategory,
                "category": case.category.value if hasattr(case.category, "value") else str(case.category),
                "invariant_id": case.invariant_id,
                "holds": res.holds,
                "n_clear": res.n_clear,
                "n": res.n,
                "clear_rate": round(res.clear_rate, 4),
                "counts": {
                    "pass": res.n_pass,
                    "fail": res.n_fail,
                    "partial": res.n_partial,
                    "uncertain": res.n_uncertain,
                    "error": res.n_error,
                },
                "linked_findings": finding_reports,
            }
        )

    return {
        "_about": (
            "AgentForge regression suite — every in_regression_suite case replayed N times against the "
            "target. A case 'holds' iff every replay cleared its invariant; that's a confidence interval "
            "(N, clear rate, target SHA), not a proof. update_status applied: " + str(update_status) + "."
        ),
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "target_sha": target_sha,
        "target_base_url": target_base_url,
        "n_replays_per_case": n,
        "summary": {
            "n_cases": len(cases),
            "n_holding": n_holding,
            "n_failing": len(cases) - n_holding,
            "n_regressions_detected": n_regressions_detected,
            "status_updates_written": update_status,
        },
        "cases": case_reports,
    }


__all__ = [
    "ReplayResult",
    "replay_case",
    "replay_finding",
    "run_regression_suite",
]
