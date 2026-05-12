"""AgentForge Observability Dashboard.

Renders a self-contained HTML briefing document from the SQLite findings DB.
The rendered page answers the six PRD observability questions:

  1. Coverage     — which attack categories have been tested and how many cases each.
  2. Resilience   — pass/fail/partial/uncertain rates per category and target SHA.
  3. Trend        — is the target getting more or less resilient over time?
  4. Findings     — open / in-progress / resolved / lead / regression counts.
  5. Cost         — total + per-run + projected-at-scale table.
  6. Timeline     — per-agent activity: recent runs with directive, categories,
                    n_attacks, n_findings, halt reason — plus a collapsible
                    "confirmed findings — detail" panel.

The page also carries a styled STOP button (``<form action="/stop" method="post">``)
whose deployed counterpart writes a sentinel file the Orchestrator polls before
each attack batch.

Alongside the HTML, :func:`render_resilience_md` produces ``RESILIENCE.md`` — a
hand-off document for whoever maintains the target: per-category pass/fail plus
every confirmed finding (reproducible attack, expected vs observed behaviour,
violated invariant, framework refs, link to the full vuln report under
``reports/``).

Public API::

    render_dashboard(db)              -> str (full HTML)
    write_dashboard(db_path, out)     -> Path (writes the HTML file, returns the path)
    render_resilience_md(db)          -> str (RESILIENCE.md markdown)
    write_resilience_md(db_path, out) -> Path (writes RESILIENCE.md, returns the path)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from agentforge.models import ThreatCategory
from agentforge.storage.db import Database

# --------------------------------------------------------------------------- #
# Jinja2 environment — FileSystemLoader with __file__ keeps it packaging-free
# --------------------------------------------------------------------------- #
_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=False,
    keep_trailing_newline=True,
)
_env.filters["from_json"] = json.loads


def _report_rel(p: str | None) -> str | None:
    """Repo-relative link target for a generated vuln report.

    ``report_path`` as stored is whatever ``--reports-dir`` the run used (often a
    throwaway ``/tmp`` path); in the repo the reports always live under
    ``reports/`` (filed) or ``reports/drafts/`` (CRITICAL findings held for
    human sign-off). Map the stored path onto that committed layout by basename +
    whether it sits under a ``drafts/`` segment. Returns ``None`` for an empty
    path so the template can fall back to "not generated yet".
    """
    if not p:
        return None
    parts = Path(p).parts
    return f"reports/drafts/{parts[-1]}" if "drafts" in parts else f"reports/{parts[-1]}"


_env.filters["report_rel"] = _report_rel


# --------------------------------------------------------------------------- #
# Category → short PRD ID + plain-language description (used by §1 + RESILIENCE.md)
# --------------------------------------------------------------------------- #
_CATEGORY_ID: dict[str, str] = {
    ThreatCategory.PROMPT_INJECTION.value: "C1",
    ThreatCategory.DATA_EXFILTRATION.value: "C2",
    ThreatCategory.STATE_CORRUPTION.value: "C3",
    ThreatCategory.TOOL_MISUSE.value: "C4",
    ThreatCategory.DENIAL_OF_SERVICE.value: "C5",
    ThreatCategory.IDENTITY_ROLE_EXPLOITATION.value: "C6",
    ThreatCategory.MISINFORMATION.value: "B1",
    ThreatCategory.IMPROPER_OUTPUT_HANDLING.value: "B2",
    ThreatCategory.SYSTEM_PROMPT_LEAKAGE.value: "B3",
}

_CATEGORY_DESC: dict[str, str] = {
    ThreatCategory.PROMPT_INJECTION.value: (
        "Does the Co-Pilot keep its system and safety rules when a user — or text it "
        "reads from a document or a chart field — directly tells it to ignore them?"
    ),
    ThreatCategory.DATA_EXFILTRATION.value: (
        "Does the Co-Pilot stay bound to the active patient and refuse requests for "
        "another patient's chart, documents, or PHI (cross-patient access, IDOR)?"
    ),
    ThreatCategory.STATE_CORRUPTION.value: (
        "Can conversation history or retrieved context be poisoned so the Co-Pilot "
        "carries a planted instruction or fact into later turns?"
    ),
    ThreatCategory.TOOL_MISUSE.value: (
        "Can the Co-Pilot be steered into calling the wrong tool, on the wrong "
        "patient, or in a recursive loop that never settles?"
    ),
    ThreatCategory.DENIAL_OF_SERVICE.value: (
        "Can a single request drive token, cost, or time use far outside the normal "
        "envelope — “read every page”, infinite loops, cost amplification?"
    ),
    ThreatCategory.IDENTITY_ROLE_EXPLOITATION.value: (
        "Can a claimed role or authority (“I'm an administrator now”) make the "
        "Co-Pilot exceed its clinical or access boundaries?"
    ),
    ThreatCategory.MISINFORMATION.value: (
        "Will the Co-Pilot state a clinical fact with no citation, or strip its safety "
        "disclaimer when a confident user asks it to?"
    ),
    ThreatCategory.IMPROPER_OUTPUT_HANDLING.value: (
        "Does the Co-Pilot emit unescaped or unsafe content (markdown, HTML, links) "
        "that a downstream renderer would mishandle?"
    ),
    ThreatCategory.SYSTEM_PROMPT_LEAKAGE.value: (
        "Can the Co-Pilot be made to reveal its system prompt or internal instructions "
        "verbatim?"
    ),
}


def _seed_floor_sizes() -> dict[str, int]:
    """``{category: n_seed_cases}`` for the deterministic seed floor.

    Categories with no curated seeds yet (their attacks come from the external-tool
    wrappers / public datasets — ``attacks/external.py``, TODO) map to 0, which the
    dashboard renders as a "no seeds yet (roadmap)" badge so a viewer never reads a
    zero coverage row as "tested and clean".
    """
    try:
        from agentforge.attacks.seeds import SEEDS_BY_CATEGORY

        sizes = {cat: len(seeds) for cat, seeds in SEEDS_BY_CATEGORY.items()}
    except Exception:  # pragma: no cover - defensive; never break the render
        sizes = {}
    return {c.value: sizes.get(c.value, 0) for c in ThreatCategory}


# --------------------------------------------------------------------------- #
# Small data containers for template rendering
# --------------------------------------------------------------------------- #
@dataclass
class _ShaStats:
    """Aggregated stats for a single target SHA across all its runs."""

    n_runs: int = 0
    n_attacks: int = 0
    n_findings: int = 0
    n_uncertain: int = 0

    @property
    def finding_rate(self) -> float:
        """Fraction of attacks that produced a confirmed finding (lower = more resilient)."""
        return self.n_findings / self.n_attacks if self.n_attacks > 0 else 0.0


@dataclass
class _TrendEntry:
    """One point on the per-SHA resilience trend line."""

    sha: str
    first_run: str
    n_attacks: int
    pass_rate: float  # estimated pass-rate (%)
    trend: str  # 'up' | 'down' | 'flat' | 'baseline'


# --------------------------------------------------------------------------- #
# Data assembly helpers
# --------------------------------------------------------------------------- #
def _build_sha_stats(runs: list[dict[str, Any]]) -> dict[str, _ShaStats]:
    """Group runs by target SHA and aggregate totals."""
    stats: dict[str, _ShaStats] = {}
    for run in runs:
        sha: str = run.get("target_sha") or "unknown"
        if sha not in stats:
            stats[sha] = _ShaStats()
        s = stats[sha]
        s.n_runs += 1
        s.n_attacks += run.get("n_attacks") or 0
        s.n_findings += run.get("n_confirmed_findings") or 0
        s.n_uncertain += run.get("n_uncertain") or 0
    return stats


def _build_trend_series(
    runs: list[dict[str, Any]],
    sha_stats: dict[str, _ShaStats],
) -> list[_TrendEntry]:
    """Build a chronological trend series (one entry per unique target SHA).

    The runs list is assumed to be in reverse-chronological order (as returned
    by ``Database.recent_runs``), so we reverse it to get oldest-first order for
    the trend line.
    """
    # Collect first_run timestamp per SHA in oldest-first order
    seen: dict[str, str] = {}
    for run in reversed(runs):
        sha = run.get("target_sha") or "unknown"
        if sha not in seen:
            seen[sha] = run.get("started_at") or ""

    entries: list[_TrendEntry] = []
    prev_pass_rate: float | None = None

    for sha, first_run in seen.items():
        s = sha_stats.get(sha, _ShaStats())
        pass_rate = round((1.0 - s.finding_rate) * 100, 1) if s.n_attacks > 0 else 0.0

        if prev_pass_rate is None:
            trend = "baseline"
        elif pass_rate > prev_pass_rate + 0.5:
            trend = "up"
        elif pass_rate < prev_pass_rate - 0.5:
            trend = "down"
        else:
            trend = "flat"

        entries.append(
            _TrendEntry(
                sha=sha,
                first_run=first_run[:19] if len(first_run) > 19 else first_run,
                n_attacks=s.n_attacks,
                pass_rate=pass_rate,
                trend=trend,
            )
        )
        prev_pass_rate = pass_rate

    return entries


def _verdict_totals(verdict_rates: dict[str, dict[str, int]]) -> dict[str, int]:
    """Sum pass/fail/partial/uncertain across every category."""
    totals = {"pass": 0, "fail": 0, "partial": 0, "uncertain": 0}
    for verdicts in verdict_rates.values():
        for k in totals:
            totals[k] += verdicts.get(k, 0)
    return totals


def _judge_agreement() -> tuple[str, str]:
    """Return ``(short, long)`` strings describing the Judge's measured agreement.

    Runs the labeled ground-truth corpus (``evals/judge_corpus/``) through the
    Judge with **only the deterministic checkers** enabled — no LLM calls, no
    cost, fully reproducible at render time. ``short`` is e.g. ``"100.0%"`` (for
    the KPI strip); ``long`` is the full footer sentence with FP/FN counts and
    the pointer to ``agentforge validate-judge --llm`` for the LLM-Judge rate.

    Never raises: a missing/broken corpus degrades to an explanatory string.
    """
    try:
        from agentforge.judge import Judge
        from agentforge.judge.corpus import load_corpus, validate_judge

        corpus = load_corpus()
        if not corpus:
            return "n/a", "no labeled corpus cases found — run `agentforge validate-judge`"
        report = validate_judge(Judge(enable_llm_judge=False), corpus)
        short = f"{report.agreement_rate:.1%}"
        long = (
            f"{report.agreement_rate:.1%} on {report.n_total} labeled corpus cases "
            f"(FP={report.false_positives}, FN={report.false_negatives}; deterministic "
            f"checkers — run `agentforge validate-judge --llm` for the LLM-Judge rate)"
        )
        return short, long
    except Exception as exc:  # pragma: no cover - defensive; corpus issues must not break the render
        return "n/a", f"unavailable — corpus validation failed: {exc}"


def _projected_costs(avg_cost: float) -> tuple[float, float, float, float]:
    """Return projected total costs at (100, 1K, 10K, 100K) runs.

    Methodology (see ARCHITECTURE.md §"Orchestration strategy at scale"):
    - ~100 runs: avg_cost × 100 (full model set, no caching).
    - ~1K runs:  avg_cost × 1000 × 0.6 (caching + dedup reduces marginal ~40%).
    - ~10K runs: bandit picks from cached templates; LLM only for novel signal (~5%).
                 Simplified: avg_cost × 10000 × 0.12 (effective rate at this scale).
    - ~100K runs: avg_cost × 100000 × 0.04 (thin exploration slice + worker parallelism).

    These are NOT cost-per-token × n — they model regime changes.
    """
    proj_100 = avg_cost * 100
    proj_1k = avg_cost * 1000 * 0.6
    proj_10k = avg_cost * 10000 * 0.12
    proj_100k = avg_cost * 100000 * 0.04
    return proj_100, proj_1k, proj_10k, proj_100k


def _gather(db: Database) -> dict[str, Any]:
    """Read every DB query once and assemble the shared template context.

    Both :func:`render_dashboard` and :func:`render_resilience_md` build on this
    so the HTML page and ``RESILIENCE.md`` always agree on the numbers.
    """
    category_coverage: dict[str, int] = db.category_coverage()
    open_findings: dict[str, int] = db.open_findings_by_severity()
    findings_status: dict[str, int] = db.findings_status_summary()
    verdict_rates: dict[str, dict[str, int]] = db.verdict_rates_by_category()
    findings_detail: list[dict[str, Any]] = db.findings_detail()
    total_cost: float = db.total_cost()
    recent_runs: list[dict[str, Any]] = db.recent_runs(limit=50)

    sha_stats = _build_sha_stats(recent_runs)
    trend_series = _build_trend_series(recent_runs, sha_stats)

    n_runs = len(recent_runs)
    avg_cost_per_run = total_cost / n_runs if n_runs > 0 else 0.0
    proj_100, proj_1k, proj_10k, proj_100k = _projected_costs(avg_cost_per_run)

    seed_floor = _seed_floor_sizes()
    n_categories_exercised = sum(1 for n in category_coverage.values() if n > 0)
    n_open_findings = sum(open_findings.values())
    judge_short, judge_long = _judge_agreement()

    return {
        "rendered_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        # §1 coverage
        "category_coverage": category_coverage,
        "category_id_map": _CATEGORY_ID,
        "category_desc": _CATEGORY_DESC,
        "seed_floor": seed_floor,
        # §2 resilience
        "verdict_rates": verdict_rates,
        "verdict_totals": _verdict_totals(verdict_rates),
        "sha_stats": sha_stats,
        # §3 trend
        "trend_series": trend_series,
        # §4 findings
        "open_findings": open_findings,
        "findings_status": findings_status,
        "findings_detail": findings_detail,
        # §5 cost
        "total_cost": total_cost,
        "recent_runs": recent_runs,
        "avg_cost_per_run": avg_cost_per_run,
        "proj_100": proj_100,
        "proj_1k": proj_1k,
        "proj_10k": proj_10k,
        "proj_100k": proj_100k,
        # KPI strip + footer
        "summary": {
            "n_runs": n_runs,
            "n_categories_exercised": n_categories_exercised,
            "n_categories_total": len(ThreatCategory),
            "n_open_findings": n_open_findings,
            "n_findings_total": sum(findings_status.values()),
            "judge_agreement_short": judge_short,
        },
        "judge_agreement_rate": judge_long,
    }


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def render_dashboard(db: Database) -> str:
    """Render the AgentForge observability dashboard from the given Database.

    Calls the ``Database`` read methods (``category_coverage``,
    ``open_findings_by_severity``, ``findings_status_summary``,
    ``verdict_rates_by_category``, ``findings_detail``, ``total_cost``,
    ``recent_runs``) and renders ``templates/dashboard.html.j2`` into a
    self-contained HTML string (no external CSS/JS dependencies).
    """
    ctx = _gather(db)
    return _env.get_template("dashboard.html.j2").render(**ctx)


def render_resilience_md(db: Database) -> str:
    """Render ``RESILIENCE.md`` — the target-hardening hand-off document.

    Per-category pass/fail plus every confirmed finding (reproducible attack,
    expected vs observed behaviour, violated invariant, framework refs, link to
    the full vuln report under ``reports/``). Built from the same data as the
    HTML dashboard so the two never disagree.
    """
    ctx = _gather(db)
    return _env.get_template("resilience.md.j2").render(**ctx)


def write_dashboard(db_path: str | Path, out_path: str | Path) -> Path:
    """Open the SQLite DB at *db_path*, render the dashboard, write HTML to *out_path*.

    Parent directories are created if they do not exist. Returns the resolved
    path of the written HTML file.
    """
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with Database(db_path) as db:
        html = render_dashboard(db)
    out.write_text(html, encoding="utf-8")
    return out


def write_resilience_md(db_path: str | Path, out_path: str | Path) -> Path:
    """Open the SQLite DB at *db_path*, render ``RESILIENCE.md``, write it to *out_path*.

    Parent directories are created if they do not exist. Returns the resolved path.
    """
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with Database(db_path) as db:
        md = render_resilience_md(db)
    out.write_text(md, encoding="utf-8")
    return out


__all__ = [
    "render_dashboard",
    "render_resilience_md",
    "write_dashboard",
    "write_resilience_md",
]
