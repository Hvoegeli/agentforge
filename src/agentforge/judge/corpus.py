"""Judge corpus-validation harness.

``evals/success_criteria.md`` makes this load-bearing: *"Where a category
genuinely needs semantic judgment, the verdict is rendered by an LLM-Judge that
is itself validated against a labeled ground-truth corpus with a measured
agreement / false-positive / false-negative rate, re-measured on every
Judge-prompt change."*

This module loads that labeled corpus (``evals/judge_corpus/*.json``), runs every
case through the :class:`agentforge.judge.Judge`, and reports the agreement rate
and the confusion matrix overall and per invariant. It works for both the
deterministic checkers (which should agree ~100% by construction) and the
LLM-Judge (whose rate is the number that actually matters and must clear the bar
in ``evals/success_criteria.md`` before its verdicts are treated as findings).

Corpus file format — one JSON object per file (or a JSON list of them)::

    {
      "id": "c1-direct-canary-echo-001",
      "label": "fail",                       # the ground-truth ObservedBehavior
      "case": { ...AttackCase fields... },    # at minimum: category, subcategory,
                                              #   surface, prompt_or_sequence,
                                              #   expected_safe_behavior, invariant_id,
                                              #   source, and (for C1) notes with the
                                              #   packed canary=/sentinels=
      "attempt": { ...AttackAttempt fields... },  # at minimum: response_redacted;
                                              #   plus tool_trace / token_usage /
                                              #   latency_ms / n_supervisor_hops as needed
      "context": { ... },                     # optional extra invariant context
      "notes": "why this case is labeled this way"
    }

A note on "label": ``PARTIAL`` ground-truth labels count as a disagreement only
against ``PASS``/the wrong direction — see :func:`_classify`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentforge.models import AttackAttempt, AttackCase, ObservedBehavior

logger = logging.getLogger("agentforge.judge.corpus")

# Default location of the labeled corpus.
DEFAULT_CORPUS_DIR = Path(__file__).resolve().parents[3] / "evals" / "judge_corpus"

# Verdicts we treat as "the attack succeeded" (for the FP/FN confusion matrix).
_VIOLATION = {ObservedBehavior.FAIL, ObservedBehavior.PARTIAL}


@dataclass(frozen=True)
class CorpusCase:
    """One labeled ground-truth case."""

    id: str
    label: ObservedBehavior
    case: AttackCase
    attempt: AttackAttempt
    context: dict = field(default_factory=dict)
    notes: str = ""


@dataclass
class InvariantStats:
    invariant_id: str
    n: int = 0
    agree: int = 0
    false_positive: int = 0  # labeled PASS, judged a violation
    false_negative: int = 0  # labeled a violation, judged PASS
    uncertain: int = 0  # judge returned UNCERTAIN on a labeled (non-uncertain) case

    @property
    def agreement_rate(self) -> float:
        return self.agree / self.n if self.n else 0.0


@dataclass
class CorpusReport:
    n_total: int = 0
    n_agree: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    uncertain: int = 0
    by_invariant: dict[str, InvariantStats] = field(default_factory=dict)
    disagreements: list[str] = field(default_factory=list)

    @property
    def agreement_rate(self) -> float:
        return self.n_agree / self.n_total if self.n_total else 0.0

    def summary(self) -> str:
        lines = [
            "Judge corpus validation",
            f"  cases:           {self.n_total}",
            f"  agreement:       {self.n_agree}/{self.n_total} ({self.agreement_rate:.1%})",
            f"  false positives: {self.false_positives}  (labeled safe, judged a violation)",
            f"  false negatives: {self.false_negatives}  (labeled a violation, judged safe)",
            f"  uncertain:       {self.uncertain}  (judge could not decide)",
            "",
            "  per invariant:",
        ]
        for inv_id in sorted(self.by_invariant):
            st = self.by_invariant[inv_id]
            lines.append(
                f"    {inv_id:<28} {st.agree}/{st.n} ({st.agreement_rate:.1%})  "
                f"FP={st.false_positive} FN={st.false_negative} U={st.uncertain}"
            )
        if self.disagreements:
            lines.append("")
            lines.append("  disagreements:")
            lines.extend(f"    - {d}" for d in self.disagreements)
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _coerce_case(raw: dict[str, Any]) -> AttackCase:
    return AttackCase.model_validate(raw)


def _coerce_attempt(raw: dict[str, Any]) -> AttackAttempt:
    # Fill the structural fields a hand-written corpus entry usually omits.
    data = dict(raw)
    data.setdefault("attack_case_id", "corpus")
    data.setdefault("target_sha", "corpus")
    data.setdefault("target_base_url", "corpus")
    data.setdefault("request_summary", "corpus fixture")
    data.setdefault("response_redacted", "")
    return AttackAttempt.model_validate(data)


def _load_one(obj: dict[str, Any], *, source: str) -> CorpusCase:
    label = ObservedBehavior(str(obj["label"]).strip().lower())
    case = _coerce_case(obj["case"])
    attempt = _coerce_attempt(obj.get("attempt", {}))
    return CorpusCase(
        id=str(obj.get("id") or source),
        label=label,
        case=case,
        attempt=attempt,
        context=dict(obj.get("context") or {}),
        notes=str(obj.get("notes") or ""),
    )


def load_corpus(path: str | Path | None = None) -> list[CorpusCase]:
    """Load every ``*.json`` corpus file under *path* (default ``evals/judge_corpus/``).

    A file may contain a single case object or a JSON list of them. Returns ``[]``
    (with a warning) if the directory does not exist or is empty.
    """
    root = Path(path) if path else DEFAULT_CORPUS_DIR
    if not root.exists():
        logger.warning("judge corpus dir %s does not exist — returning no cases", root)
        return []
    out: list[CorpusCase] = []
    for fp in sorted(root.glob("*.json")):
        try:
            payload = json.loads(fp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("skipping corpus file %s: %s", fp, exc)
            continue
        records = payload if isinstance(payload, list) else [payload]
        for i, rec in enumerate(records):
            try:
                out.append(_load_one(rec, source=f"{fp.stem}[{i}]"))
            except Exception as exc:
                logger.error("skipping corpus record %s[%d]: %s", fp.stem, i, exc)
    logger.info("loaded %d judge-corpus cases from %s", len(out), root)
    return out


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def _classify(label: ObservedBehavior, verdict: ObservedBehavior) -> str:
    """Return one of 'agree' | 'false_positive' | 'false_negative' | 'uncertain' | 'disagree'."""
    if verdict is ObservedBehavior.UNCERTAIN and label is not ObservedBehavior.UNCERTAIN:
        return "uncertain"
    if verdict is label:
        return "agree"
    label_violation = label in _VIOLATION
    verdict_violation = verdict in _VIOLATION
    if verdict_violation and not label_violation:
        return "false_positive"
    if label_violation and not verdict_violation:
        return "false_negative"
    # both are violations but PARTIAL vs FAIL, or both PASS/UNCERTAIN mismatch
    return "agree" if label_violation == verdict_violation else "disagree"


def validate_judge(judge: Any, corpus: list[CorpusCase] | None = None) -> CorpusReport:
    """Run every corpus case through *judge* and report agreement + confusion matrix.

    *judge* is a :class:`agentforge.judge.Judge` (typed loosely to avoid a circular
    import). If *corpus* is omitted it is loaded from :data:`DEFAULT_CORPUS_DIR`.
    """
    cases = corpus if corpus is not None else load_corpus()
    report = CorpusReport()
    for cc in cases:
        verdict = judge.adjudicate(cc.case, cc.attempt, context=cc.context or None)
        report.n_total += 1
        st = report.by_invariant.setdefault(
            cc.case.invariant_id, InvariantStats(invariant_id=cc.case.invariant_id)
        )
        st.n += 1
        kind = _classify(cc.label, verdict.observed_behavior)
        if kind == "agree":
            report.n_agree += 1
            st.agree += 1
        elif kind == "false_positive":
            report.false_positives += 1
            st.false_positive += 1
            report.disagreements.append(
                f"[{cc.id}] {cc.case.invariant_id}: labeled {cc.label.value}, "
                f"judged {verdict.observed_behavior.value} (FALSE POSITIVE) — {verdict.rationale[:160]}"
            )
        elif kind == "false_negative":
            report.false_negatives += 1
            st.false_negative += 1
            report.disagreements.append(
                f"[{cc.id}] {cc.case.invariant_id}: labeled {cc.label.value}, "
                f"judged {verdict.observed_behavior.value} (FALSE NEGATIVE) — {verdict.rationale[:160]}"
            )
        elif kind == "uncertain":
            report.uncertain += 1
            st.uncertain += 1
            report.disagreements.append(
                f"[{cc.id}] {cc.case.invariant_id}: labeled {cc.label.value}, "
                f"judged UNCERTAIN — {verdict.rationale[:160]}"
            )
        else:  # "disagree"
            report.disagreements.append(
                f"[{cc.id}] {cc.case.invariant_id}: labeled {cc.label.value}, "
                f"judged {verdict.observed_behavior.value} — {verdict.rationale[:160]}"
            )
    return report


__all__ = [
    "DEFAULT_CORPUS_DIR",
    "CorpusCase",
    "CorpusReport",
    "InvariantStats",
    "load_corpus",
    "validate_judge",
]
