"""Smoke tests for the CLI (no network, no LLM)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from agentforge.cli import app

runner = CliRunner()


def test_version() -> None:
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0
    assert "agentforge" in r.stdout


def test_validate_judge_on_seed_corpus() -> None:
    r = runner.invoke(app, ["validate-judge"])
    assert r.exit_code == 0  # deterministic seed corpus → no FP/FN
    assert "agreement" in r.stdout.lower()


def test_seed_findings_then_status_then_dashboard(tmp_path: Path) -> None:
    db = tmp_path / "af.sqlite"
    reports = tmp_path / "findings"
    r = runner.invoke(app, ["seed-findings", "--db", str(db), "--reports-dir", str(reports)])
    assert r.exit_code == 0, r.output
    assert "seeded finding" in r.stdout
    assert db.exists()
    assert len(list(reports.glob("*.md"))) == 4  # 4 HIGH filed; 2 CRITICAL go to reports/drafts/

    r = runner.invoke(app, ["status", "--db", str(db)])
    assert r.exit_code == 0
    assert "prompt_injection" in r.stdout

    out = tmp_path / "dash.html"
    r = runner.invoke(app, ["dashboard", "--db", str(db), "--out", str(out)])
    assert r.exit_code == 0
    assert out.exists() and "<html" in out.read_text().lower()


def test_run_against_unreachable_target_exits_cleanly(tmp_path: Path) -> None:
    db = tmp_path / "af.sqlite"
    r = runner.invoke(
        app,
        ["run", "--category", "C1", "--max-attacks", "1", "--db", str(db),
         "--reports-dir", str(tmp_path / "rep"), "--target-url", "http://127.0.0.1:1"],
    )
    # the target isn't running → the run aborts gracefully (no traceback), exit 0
    assert r.exit_code == 0, r.output
    assert "target_unavailable" in r.stdout or "not ready" in r.stdout.lower()


def test_replay_against_unreachable_target_exits_2(tmp_path: Path) -> None:
    db = tmp_path / "af.sqlite"
    # seed a finding first so --finding has something to reference
    runner.invoke(app, ["seed-findings", "--db", str(db), "--reports-dir", str(tmp_path / "rep")])
    # grab one finding id from the db
    from agentforge.storage.db import Database

    d = Database(str(db))
    fid = d.open_findings()[0].id
    d.close()
    r = runner.invoke(app, ["replay", "--finding", fid, "--n", "2", "--db", str(db), "--target-url", "http://127.0.0.1:1"])
    assert r.exit_code == 2  # target not available
    assert "not available" in r.stdout.lower() or "target" in r.stdout.lower()


def test_regression_suite_empty_then_populated(tmp_path: Path) -> None:
    db = tmp_path / "af.sqlite"
    # empty DB → empty regression suite → exit 0 with a notice
    r = runner.invoke(app, ["regression-suite", "--db", str(db)])
    assert r.exit_code == 0
    assert "empty" in r.stdout.lower()
    # seed the known findings (their cases are in_regression_suite=1), then the suite is
    # non-empty — but the target is unreachable, so it exits 2 before replaying.
    runner.invoke(app, ["seed-findings", "--db", str(db), "--reports-dir", str(tmp_path / "rep")])
    r = runner.invoke(app, ["regression-suite", "--db", str(db), "--target-url", "http://127.0.0.1:1"])
    assert r.exit_code == 2
    assert "not available" in r.stdout.lower() or "target" in r.stdout.lower()
