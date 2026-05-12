"""AgentForge CLI — drive the closed loop, replay regressions, validate the Judge,
render the dashboard, and seed the known day-one findings.

    agentforge run --category C1 --max-attacks 5      # one campaign, end-to-end
    agentforge status                                  # summary of the findings DB
    agentforge replay --finding <id> --n 10            # regression replay of a finding's case
    agentforge validate-judge                          # corpus-validate the Judge
    agentforge dashboard --out dashboard.html          # render the static HTML dashboard
    agentforge seed-findings                            # load the 3 known seeded findings + reports

The target host is taken from ``COPILOT_BASE_URL`` (and must be on the adapter's
allowlist — AgentForge only attacks the authorised Co-Pilot); ``--target-url`` /
``--target-sha`` override it for a one-off run (e.g. against the deployed instance).
"""

from __future__ import annotations

import json
import logging

import typer
from rich.console import Console
from rich.table import Table

from agentforge import __version__
from agentforge.config import get_settings
from agentforge.models import ThreatCategory

app = typer.Typer(
    name="agentforge",
    help="Autonomous multi-agent adversarial-evaluation platform.",
    no_args_is_help=True,
)
console = Console()

_CATEGORY_ALIASES: dict[str, ThreatCategory] = {
    "c1": ThreatCategory.PROMPT_INJECTION,
    "c2": ThreatCategory.DATA_EXFILTRATION,
    "c3": ThreatCategory.STATE_CORRUPTION,
    "c4": ThreatCategory.TOOL_MISUSE,
    "c5": ThreatCategory.DENIAL_OF_SERVICE,
    "c6": ThreatCategory.IDENTITY_ROLE_EXPLOITATION,
    "b1": ThreatCategory.MISINFORMATION,
    "b2": ThreatCategory.IMPROPER_OUTPUT_HANDLING,
    "b3": ThreatCategory.SYSTEM_PROMPT_LEAKAGE,
}


def _parse_category(raw: str) -> ThreatCategory:
    key = raw.strip().lower()
    if key in _CATEGORY_ALIASES:
        return _CATEGORY_ALIASES[key]
    try:
        return ThreatCategory(key)
    except ValueError as exc:
        choices = ", ".join(sorted({c.value for c in ThreatCategory}) | set(_CATEGORY_ALIASES))
        raise typer.BadParameter(f"unknown category {raw!r}; try one of: {choices}") from exc


def _setup_logging() -> None:
    level = getattr(logging, str(get_settings().log_level).upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _build_adapter(target_url: str | None, target_sha: str | None):
    from agentforge.target.adapter import TargetAdapter, TargetNotAllowedError

    s = get_settings()
    try:
        if target_url:
            return TargetAdapter(
                base_url=target_url,
                target_sha=target_sha or s.copilot_target_sha,
                username=s.copilot_username,
                password=s.copilot_password,
                rate_limit_rpm=s.rate_limit_rpm,
                timeout_single_turn=float(s.run_timeout_single_turn),
                timeout_multi_turn=float(s.run_timeout_multi_turn),
            )
        adapter = TargetAdapter.from_settings(s)
        if target_sha:
            adapter.target_sha = target_sha
        return adapter
    except TargetNotAllowedError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc


def _open_db(db_path: str | None):
    from agentforge.storage.db import Database

    return Database(db_path or get_settings().sqlite_db_path)


# --------------------------------------------------------------------------- #
@app.command()
def version() -> None:
    """Print the AgentForge version."""
    console.print(f"agentforge {__version__}")


@app.command()
def run(
    category: str = typer.Option("C1", "--category", "-c", help="Threat category (C1..C6/B1..B3 or the value)."),
    max_attacks: int | None = typer.Option(None, "--max-attacks", "-n", help="Cap attacks this run (default: full seed floor)."),
    budget: float = typer.Option(0.50, "--budget", help="Agent-side LLM cost ceiling for the run (USD)."),
    single_turn_only: bool = typer.Option(False, "--single-turn-only", help="Skip multi-turn seeds."),
    mutate: bool = typer.Option(False, "--mutate", help="Mutate near-misses (deterministic mutators)."),
    external: bool = typer.Option(False, "--external", help="Also run the curated public-dataset attack corpus (attacks/external.py)."),
    db_path: str | None = typer.Option(None, "--db", help="SQLite findings DB (default from settings)."),
    reports_dir: str = typer.Option("findings", "--reports-dir", help="Where vuln reports are written."),
    target_url: str | None = typer.Option(None, "--target-url", help="Override the target base URL for this run."),
    target_sha: str | None = typer.Option(None, "--target-sha", help="Override the recorded target git SHA."),
) -> None:
    """Run one Orchestrator-directed campaign end-to-end against the target."""
    _setup_logging()
    from agentforge.orchestrator import Orchestrator

    cat = _parse_category(category)
    db = _open_db(db_path)
    adapter = _build_adapter(target_url, target_sha)
    try:
        orch = Orchestrator()
        campaign = orch.pick_campaign(
            category=cat,
            cost_ceiling_usd=budget,
            max_attacks=max_attacks,
            include_multi_turn=not single_turn_only,
            mutate_near_misses=mutate,
            include_external_attacks=external,
            reports_dir=reports_dir,
        )
        console.print(f"[bold]Campaign:[/bold] {campaign.directive}")
        summary = orch.run_campaign(campaign, target_adapter=adapter, db=db)
    finally:
        close = getattr(adapter, "close", None)
        if callable(close):
            close()
        db.close()
    console.print(f"[bold green]{summary.describe()}[/bold green]")
    if summary.findings:
        for f in summary.findings:
            tag = "FINDING" if f.severity.value != "lead" else "lead"
            console.print(f"  • [{tag}] {f.severity.value.upper()} {f.category.value} — {f.report_path or '(no report)'}")


@app.command()
def status(db_path: str | None = typer.Option(None, "--db", help="SQLite findings DB.")) -> None:
    """Show a summary of the findings DB — coverage, verdict rates, open findings, runs."""
    db = _open_db(db_path)
    try:
        cov = db.category_coverage()
        rates = db.verdict_rates_by_category()
        sev = db.open_findings_by_severity()
        runs = db.recent_runs(limit=10)
    finally:
        db.close()

    t = Table(title="Coverage & verdicts by category")
    t.add_column("category")
    t.add_column("attempts", justify="right")
    for k in ("pass", "fail", "partial", "uncertain"):
        t.add_column(k, justify="right")
    for cat, n in cov.items():
        r = rates.get(cat, {})
        t.add_row(cat, str(n), *[str(r.get(k, 0)) for k in ("pass", "fail", "partial", "uncertain")])
    console.print(t)

    console.print(f"[bold]Open findings by severity:[/bold] {sev or '(none)'}")
    console.print(f"[bold]Recent runs:[/bold] {len(runs)}")
    for run_row in runs:
        cats = ",".join(json.loads(run_row["categories_targeted"]))
        console.print(
            f"  {run_row['id'][:12]}  {cats}"
            f"  attacks={run_row['n_attacks']}  findings={run_row['n_confirmed_findings']}"
            f"  cost=${run_row['total_cost_usd']:.4f}  halt={run_row['halted_reason'] or 'completed'}"
        )


@app.command()
def replay(
    finding: str | None = typer.Option(None, "--finding", help="Finding ID to replay (its attack case)."),
    case: str | None = typer.Option(None, "--case", help="AttackCase ID to replay directly."),
    n: int = typer.Option(5, "--n", help="Number of replays."),
    promote: bool = typer.Option(False, "--promote", help="If the invariant holds, promote the case into the regression suite."),
    db_path: str | None = typer.Option(None, "--db", help="SQLite findings DB."),
    target_url: str | None = typer.Option(None, "--target-url", help="Override the target base URL."),
    target_sha: str | None = typer.Option(None, "--target-sha", help="Override the recorded target git SHA."),
) -> None:
    """Regression replay: re-run a pinned attack case N times and report whether the invariant holds."""
    _setup_logging()
    from agentforge.regression import replay_case, replay_finding

    if not finding and not case:
        raise typer.BadParameter("pass either --finding <id> or --case <id>")
    db = _open_db(db_path)
    adapter = _build_adapter(target_url, target_sha)
    try:
        ok = getattr(adapter, "require_healthy", None)
        if callable(ok):
            try:
                ok()
            except Exception as exc:
                console.print(f"[red]target not available: {exc}[/red]")
                raise typer.Exit(code=2) from exc
        login = getattr(adapter, "ensure_logged_in", None)
        if callable(login):
            login()
        if finding:
            result = replay_finding(finding, db=db, adapter=adapter, n=n)
            case_id = result.case_id
        else:
            ac = db.get_attack_case(case)  # type: ignore[arg-type]
            if ac is None:
                console.print(f"[red]no attack case with id {case!r}[/red]")
                raise typer.Exit(code=1)
            result = replay_case(ac, n=n, adapter=adapter)
            case_id = ac.id
        console.print(("[green]" if result.holds else "[yellow]") + result.describe() + ("[/green]" if result.holds else "[/yellow]"))
        if promote and result.holds:
            db.mark_in_regression(case_id)
            console.print(f"[green]promoted case {case_id[:12]} into the regression suite[/green]")
    finally:
        close = getattr(adapter, "close", None)
        if callable(close):
            close()
        db.close()


@app.command(name="regression-suite")
def regression_suite_cmd(
    n: int = typer.Option(5, "--n", help="Replays per case (the clear rate is a confidence interval, not a proof)."),
    db_path: str | None = typer.Option(None, "--db", help="SQLite findings DB."),
    target_url: str | None = typer.Option(None, "--target-url", help="Override the target base URL."),
    target_sha: str | None = typer.Option(None, "--target-sha", help="Override the recorded target git SHA (e.g. the post-fix SHA)."),
) -> None:
    """Replay every case in the regression suite (in_regression_suite=1) N times against the
    target and report, per case, whether its invariant still holds. Exits non-zero if any
    case does not hold across all N replays — usable as a post-fix CI gate."""
    _setup_logging()
    from agentforge.regression import replay_case

    db = _open_db(db_path)
    adapter = _build_adapter(target_url, target_sha)
    try:
        cases = db.regression_cases()
        if not cases:
            console.print("[yellow]regression suite is empty (no cases with in_regression_suite=1).[/yellow]")
            raise typer.Exit(code=0)
        ok = getattr(adapter, "require_healthy", None)
        if callable(ok):
            try:
                ok()
            except Exception as exc:
                console.print(f"[red]target not available: {exc}[/red]")
                raise typer.Exit(code=2) from exc
        login = getattr(adapter, "ensure_logged_in", None)
        if callable(login):
            login()

        t = Table(title=f"Regression suite — {len(cases)} case(s) × {n} replay(s) each")
        t.add_column("case")
        t.add_column("invariant")
        t.add_column("holds?", justify="center")
        t.add_column("clear", justify="right")
        for col in ("pass", "fail", "partial", "uncertain", "error"):
            t.add_column(col, justify="right")
        n_failing = 0
        for case in cases:
            res = replay_case(case, n=n, adapter=adapter)
            if not res.holds:
                n_failing += 1
            t.add_row(
                f"{case.id[:10]} {case.subcategory[:24]}",
                case.invariant_id,
                "[green]✓[/green]" if res.holds else "[red]✗[/red]",
                f"{res.n_clear}/{res.n}",
                str(res.n_pass), str(res.n_fail), str(res.n_partial), str(res.n_uncertain), str(res.n_error),
            )
        console.print(t)
        target_label = getattr(adapter, "target_sha", None) or target_sha or "?"
        if n_failing == 0:
            console.print(f"[green]regression suite HOLDS across all {len(cases)} case(s) at target {target_label}[/green]")
        else:
            console.print(f"[red]{n_failing}/{len(cases)} regression case(s) do NOT hold at target {target_label}[/red]")
            raise typer.Exit(code=1)
    finally:
        close = getattr(adapter, "close", None)
        if callable(close):
            close()
        db.close()


@app.command(name="validate-judge")
def validate_judge_cmd(
    corpus_dir: str | None = typer.Option(None, "--corpus-dir", help="Judge corpus directory (default evals/judge_corpus)."),
    llm: bool = typer.Option(False, "--llm", help="Exercise the LLM-Judge path too (requires OPENROUTER_API_KEY)."),
) -> None:
    """Validate the Judge against the labeled ground-truth corpus and print the report."""
    _setup_logging()
    from agentforge.judge import Judge
    from agentforge.judge.corpus import load_corpus, validate_judge

    corpus = load_corpus(corpus_dir) if corpus_dir else load_corpus()
    if not corpus:
        console.print("[yellow]no corpus cases found[/yellow]")
        raise typer.Exit(code=1)
    judge = Judge(enable_llm_judge=llm)
    report = validate_judge(judge, corpus)
    console.print(report.summary())
    # non-zero exit if there were false positives/negatives — useful as a CI gate
    raise typer.Exit(code=0 if (report.false_positives == 0 and report.false_negatives == 0) else 1)


@app.command()
def dashboard(
    db_path: str | None = typer.Option(None, "--db", help="SQLite findings DB."),
    out: str = typer.Option("dashboard.html", "--out", help="Output HTML file."),
) -> None:
    """Render the static observability dashboard from the findings DB."""
    from agentforge.dashboard import write_dashboard

    db_file = db_path or get_settings().sqlite_db_path
    path = write_dashboard(db_file, out)
    console.print(f"[green]wrote dashboard → {path}[/green]")


@app.command(name="seed-findings")
def seed_findings_cmd(
    db_path: str | None = typer.Option(None, "--db", help="SQLite findings DB."),
    reports_dir: str = typer.Option("findings", "--reports-dir", help="Where vuln reports are written."),
) -> None:
    """Load the three known day-one Co-Pilot findings into the DB and write their vuln reports."""
    _setup_logging()
    from agentforge.known_findings import seed_known_findings

    db = _open_db(db_path)
    try:
        written = seed_known_findings(db, reports_dir=reports_dir)
    finally:
        db.close()
    for fid, path in written:
        console.print(f"[green]seeded finding {fid[:12]} → {path}[/green]")


if __name__ == "__main__":
    app()
