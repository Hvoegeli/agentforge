"""AgentForge invariants package.

This package implements the deterministic invariant checkers described in
``evals/success_criteria.md``.  Each checker corresponds to one invariant ID
and returns an :class:`InvariantResult` without calling any LLM.

Public surface
--------------
InvariantResult
    The structured result of one invariant check.

InvariantChecker
    ``Protocol`` / ``Callable`` type for all checker functions:
    ``(AttackAttempt, dict) -> InvariantResult``.

INVARIANT_CHECKERS
    Registry mapping invariant ID strings to their checker callables.

check(invariant_id, attempt, *, context)
    Dispatcher — looks up the checker by ID and calls it.

Invariant IDs
-------------
The IDs below correspond to the invariants defined in ``evals/success_criteria.md``.
Use these strings as the ``invariant_id`` field on an ``AttackCase``.

  ``"C1.canary-or-sentinel"``   — prompt injection (deterministic canary/sentinel)
  ``"C2.cross-patient"``        — cross-patient data exfiltration (ID-set membership)
  ``"C3.provenance"``           — state/context corruption (STUB — UNCERTAIN)
  ``"C4.tool-misuse"``          — tool misuse (binding/allowlist/ACL check)
  ``"C5.unbounded-consumption"``— DoS / unbounded consumption (trace meters)
  ``"C6.identity-role"``        — identity/role exploitation (partial deterministic)
  ``"B1.zero-citation"``        — misinformation / zero-citation bypass (heuristic)
  ``"B2.improper-output"``      — improper output handling (active-payload pattern match)
  ``"B3.system-prompt-leakage"``— system prompt leakage (LCS match)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from agentforge.models import AttackAttempt, ObservedBehavior


# --------------------------------------------------------------------------- #
# Result type
# --------------------------------------------------------------------------- #
@dataclass
class InvariantResult:
    """The verdict returned by every invariant checker.

    Attributes
    ----------
    passed:
        ``True`` iff the invariant holds (the target behaved safely).
        ``False`` means either the invariant was violated (FAIL / PARTIAL)
        or the checker could not decide (UNCERTAIN — still ``False`` because
        "unknown" is not a confirmed pass).
    observed_behavior:
        The :class:`~agentforge.models.ObservedBehavior` enum value:
        PASS / FAIL / PARTIAL / UNCERTAIN.
    rationale:
        A human-readable explanation of why this result was produced.
        Written to be included verbatim in the ``JudgeVerdict.rationale``
        field without further editing.
    evidence:
        A list of short strings quoting the specific spans / field values
        that justify the verdict.  Empty for PASS / UNCERTAIN.
    """

    passed: bool
    observed_behavior: ObservedBehavior
    rationale: str
    evidence: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Checker Protocol
# --------------------------------------------------------------------------- #
class InvariantChecker(Protocol):
    """Callable type for all deterministic invariant checker functions.

    Each checker takes an :class:`~agentforge.models.AttackAttempt` and a
    *context* dict (carrying per-attack metadata such as canaries, authorized
    patient ID sets, allowed tool sets, system prompt fragments, etc.) and
    returns an :class:`InvariantResult`.
    """

    def __call__(self, attempt: AttackAttempt, context: dict) -> InvariantResult: ...


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
# Import checker modules lazily-at-module-load (not inside the dispatch
# function) so import errors surface at startup, not at first use.
from agentforge.invariants import (  # noqa: E402
    b1_misinformation,
    b2_improper_output,
    b3_system_prompt_leakage,
    c1_prompt_injection,
    c2_data_exfil,
    c3_state_corruption,
    c4_tool_misuse,
    c5_dos,
    c6_identity,
)

INVARIANT_CHECKERS: dict[str, InvariantChecker] = {
    "C1.canary-or-sentinel": c1_prompt_injection.check,
    "C2.cross-patient": c2_data_exfil.check,
    "C3.provenance": c3_state_corruption.check,
    "C4.tool-misuse": c4_tool_misuse.check,
    "C5.unbounded-consumption": c5_dos.check,
    "C6.identity-role": c6_identity.check,
    "B1.zero-citation": b1_misinformation.check,
    "B2.improper-output": b2_improper_output.check,
    "B3.system-prompt-leakage": b3_system_prompt_leakage.check,
}


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #
def check(
    invariant_id: str,
    attempt: AttackAttempt,
    *,
    context: dict,
) -> InvariantResult:
    """Dispatch to the appropriate checker and return its :class:`InvariantResult`.

    Parameters
    ----------
    invariant_id:
        One of the IDs listed in :data:`INVARIANT_CHECKERS`.
    attempt:
        The :class:`~agentforge.models.AttackAttempt` to evaluate.
    context:
        Per-attack metadata dict.  Required keys vary by checker — see each
        module's docstring for details.

    Raises
    ------
    KeyError
        If *invariant_id* is not registered in :data:`INVARIANT_CHECKERS`.
    """
    if invariant_id not in INVARIANT_CHECKERS:
        registered = sorted(INVARIANT_CHECKERS)
        raise KeyError(f"Unknown invariant_id {invariant_id!r}.  Registered IDs: {registered}")
    return INVARIANT_CHECKERS[invariant_id](attempt, context)


__all__ = [
    "INVARIANT_CHECKERS",
    "InvariantChecker",
    "InvariantResult",
    "check",
]
