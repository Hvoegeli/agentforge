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

This module performs no campaign accounting and writes no reports — it is the
narrow "does this one invariant hold across N replays" primitive that the
``agentforge replay`` CLI command and the Orchestrator's regression step build on.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from agentforge.judge import Judge
from agentforge.models import AttackAttempt, AttackCase, JudgeVerdict, ObservedBehavior

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


__all__ = ["ReplayResult", "replay_case", "replay_finding"]
