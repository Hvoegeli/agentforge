"""SQLite storage for AgentForge — the findings/coverage DB that is also the
observability substrate the Orchestrator reads.

One table per ``models.py`` Pydantic class. Complex fields (lists, dicts) are
stored as JSON text columns. Plain stdlib ``sqlite3`` — no extra dependency for
the basics; ``sqlite-utils`` is available in the project if richer ergonomics
are wanted later.

The schema is intentionally append-mostly: attack cases, attempts, and verdicts
are immutable once written; findings carry a ``status`` that changes over time
(open -> in_progress -> resolved / regression); runs get a ``finished_at`` set
when they complete.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agentforge.models import (
    AttackAttempt,
    AttackCase,
    Finding,
    FindingStatus,
    JudgeVerdict,
    RunRecord,
    ThreatCategory,
)

# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id                    TEXT PRIMARY KEY,
    orchestrator_directive TEXT NOT NULL,
    categories_targeted   TEXT NOT NULL,            -- JSON list[str]
    target_sha            TEXT NOT NULL,
    target_base_url       TEXT NOT NULL,
    n_attacks             INTEGER NOT NULL DEFAULT 0,
    n_confirmed_findings  INTEGER NOT NULL DEFAULT 0,
    n_uncertain           INTEGER NOT NULL DEFAULT 0,
    total_cost_usd        REAL NOT NULL DEFAULT 0.0,
    halted_reason         TEXT,
    started_at            TEXT NOT NULL,
    finished_at           TEXT
);

CREATE TABLE IF NOT EXISTS attack_cases (
    id                     TEXT PRIMARY KEY,
    run_id                 TEXT,                    -- the run that produced/used this case (nullable for seeds)
    category               TEXT NOT NULL,
    subcategory            TEXT NOT NULL,
    surface                TEXT NOT NULL,
    prompt_or_sequence     TEXT NOT NULL,           -- JSON list[str]
    expected_safe_behavior TEXT NOT NULL,
    invariant_id           TEXT NOT NULL,
    framework_refs         TEXT NOT NULL,           -- JSON list[str]
    source                 TEXT NOT NULL,
    in_regression_suite    INTEGER NOT NULL DEFAULT 0,
    severity_hint          TEXT,
    notes                  TEXT NOT NULL DEFAULT '',
    created_at             TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs (id)
);
CREATE INDEX IF NOT EXISTS idx_attack_cases_category ON attack_cases (category);
CREATE INDEX IF NOT EXISTS idx_attack_cases_regression ON attack_cases (in_regression_suite);

CREATE TABLE IF NOT EXISTS attack_attempts (
    id                 TEXT PRIMARY KEY,
    attack_case_id     TEXT NOT NULL,
    run_id             TEXT,
    target_sha         TEXT NOT NULL,
    target_base_url    TEXT NOT NULL,
    request_summary    TEXT NOT NULL,
    response_redacted  TEXT NOT NULL,
    tool_trace         TEXT NOT NULL,               -- JSON list[ToolCallTrace]
    token_usage        TEXT NOT NULL,               -- JSON dict[str, int]
    cost_usd           REAL NOT NULL DEFAULT 0.0,
    latency_ms         REAL,
    n_supervisor_hops  INTEGER,
    error              TEXT,
    executed_at        TEXT NOT NULL,
    FOREIGN KEY (attack_case_id) REFERENCES attack_cases (id),
    FOREIGN KEY (run_id) REFERENCES runs (id)
);
CREATE INDEX IF NOT EXISTS idx_attempts_case ON attack_attempts (attack_case_id);
CREATE INDEX IF NOT EXISTS idx_attempts_sha ON attack_attempts (target_sha);

CREATE TABLE IF NOT EXISTS judge_verdicts (
    id                  TEXT PRIMARY KEY,
    attack_attempt_id   TEXT NOT NULL,
    check_type          TEXT NOT NULL,
    observed_behavior   TEXT NOT NULL,
    invariant_passed    INTEGER,                    -- 0/1/NULL
    confidence          REAL,
    rationale           TEXT NOT NULL,
    evidence_links      TEXT NOT NULL,              -- JSON list[str]
    judge_model         TEXT,
    judge_prompt_version TEXT,
    judged_at           TEXT NOT NULL,
    FOREIGN KEY (attack_attempt_id) REFERENCES attack_attempts (id)
);
CREATE INDEX IF NOT EXISTS idx_verdicts_attempt ON judge_verdicts (attack_attempt_id);
CREATE INDEX IF NOT EXISTS idx_verdicts_behavior ON judge_verdicts (observed_behavior);

CREATE TABLE IF NOT EXISTS findings (
    id                 TEXT PRIMARY KEY,
    attack_case_id     TEXT NOT NULL,
    attack_attempt_id  TEXT NOT NULL,
    judge_verdict_id   TEXT NOT NULL,
    category           TEXT NOT NULL,
    severity           TEXT NOT NULL,
    exploitability     TEXT NOT NULL,
    clinical_impact    TEXT NOT NULL,
    framework_mapping  TEXT NOT NULL,               -- JSON list[str]
    evidence_links     TEXT NOT NULL,               -- JSON list[str]
    status             TEXT NOT NULL,
    human_approved     INTEGER NOT NULL DEFAULT 0,
    report_path        TEXT,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    FOREIGN KEY (attack_case_id) REFERENCES attack_cases (id),
    FOREIGN KEY (attack_attempt_id) REFERENCES attack_attempts (id),
    FOREIGN KEY (judge_verdict_id) REFERENCES judge_verdicts (id)
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings (category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
"""

_TABLE_BY_MODEL: dict[type[BaseModel], str] = {
    RunRecord: "runs",
    AttackCase: "attack_cases",
    AttackAttempt: "attack_attempts",
    JudgeVerdict: "judge_verdicts",
    Finding: "findings",
}

# columns that are stored as JSON text in SQLite
_JSON_COLUMNS: dict[str, set[str]] = {
    "runs": {"categories_targeted"},
    "attack_cases": {"prompt_or_sequence", "framework_refs"},
    "attack_attempts": {"tool_trace", "token_usage"},
    "judge_verdicts": {"evidence_links"},
    "findings": {"framework_mapping", "evidence_links"},
}


def default_db_path() -> Path:
    return Path(os.environ.get("SQLITE_DB_PATH", "data/agentforge.sqlite"))


def _encode(value: Any) -> Any:
    """Serialise a Python value into something SQLite can store."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bool):
        return int(value)
    if value is None or isinstance(value, str | int | float):
        return value
    # lists / dicts / enums-in-containers -> JSON
    return json.dumps(value, default=str)


def _row_for(model: BaseModel, table: str) -> dict[str, Any]:
    raw = model.model_dump(mode="json")  # enums -> str, datetimes -> isoformat
    json_cols = _JSON_COLUMNS.get(table, set())
    row: dict[str, Any] = {}
    for k, v in raw.items():
        if k in json_cols:
            row[k] = json.dumps(v)
        elif isinstance(v, bool):
            row[k] = int(v)
        else:
            row[k] = v
    return row


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
class Database:
    """Thin SQLite wrapper. Use as a context manager or call ``close()`` yourself."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self.init_schema()

    # -- lifecycle ---------------------------------------------------------- #
    def init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _tx(self):
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # -- writes ------------------------------------------------------------- #
    def insert(self, model: BaseModel, *, run_id: str | None = None) -> str:
        """Insert one model row. ``run_id`` is attached for AttackCase / AttackAttempt."""
        table = _TABLE_BY_MODEL[type(model)]
        row = _row_for(model, table)
        if run_id is not None and "run_id" in self._columns(table):
            row["run_id"] = run_id
        cols = ", ".join(row)
        placeholders = ", ".join(f":{c}" for c in row)
        with self._tx() as conn:
            conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({placeholders})", row)
        return str(row["id"])

    def insert_many(self, models: Iterable[BaseModel], *, run_id: str | None = None) -> list[str]:
        return [self.insert(m, run_id=run_id) for m in models]

    def update_finding_status(
        self,
        finding_id: str,
        status: FindingStatus,
        *,
        human_approved: bool | None = None,
        report_path: str | None = None,
    ) -> None:
        from agentforge.models import _now  # local import to avoid cycle at module load

        sets = ["status = :status", "updated_at = :updated_at"]
        params: dict[str, Any] = {
            "status": status.value,
            "updated_at": _now().isoformat(),
            "id": finding_id,
        }
        if human_approved is not None:
            sets.append("human_approved = :human_approved")
            params["human_approved"] = int(human_approved)
        if report_path is not None:
            sets.append("report_path = :report_path")
            params["report_path"] = report_path
        with self._tx() as conn:
            conn.execute(f"UPDATE findings SET {', '.join(sets)} WHERE id = :id", params)

    def finish_run(self, run_id: str, *, halted_reason: str | None, totals: dict[str, Any]) -> None:
        from agentforge.models import _now

        params: dict[str, Any] = {
            "finished_at": _now().isoformat(),
            "halted_reason": halted_reason,
            "id": run_id,
            **totals,
        }
        set_clause = ", ".join(
            ["finished_at = :finished_at", "halted_reason = :halted_reason"]
            + [f"{k} = :{k}" for k in totals]
        )
        with self._tx() as conn:
            conn.execute(f"UPDATE runs SET {set_clause} WHERE id = :id", params)

    # -- reads (used by the Orchestrator + the dashboard) ------------------- #
    def category_coverage(self) -> dict[str, int]:
        """attempts-so-far per ThreatCategory (categories with zero attempts are 0)."""
        rows = self._conn.execute(
            """
            SELECT ac.category AS category, COUNT(*) AS n
            FROM attack_attempts at JOIN attack_cases ac ON ac.id = at.attack_case_id
            GROUP BY ac.category
            """
        ).fetchall()
        counts = {r["category"]: r["n"] for r in rows}
        return {c.value: counts.get(c.value, 0) for c in ThreatCategory}

    def open_findings_by_severity(self) -> dict[str, int]:
        rows = self._conn.execute(
            """
            SELECT severity, COUNT(*) AS n FROM findings
            WHERE status IN ('open', 'in_progress', 'regression')
            GROUP BY severity
            """
        ).fetchall()
        return {r["severity"]: r["n"] for r in rows}

    def verdict_rates_by_category(self) -> dict[str, dict[str, int]]:
        """{category: {pass: n, fail: n, partial: n, uncertain: n}} over all attempts."""
        rows = self._conn.execute(
            """
            SELECT ac.category AS category, jv.observed_behavior AS ob, COUNT(*) AS n
            FROM judge_verdicts jv
            JOIN attack_attempts at ON at.id = jv.attack_attempt_id
            JOIN attack_cases ac ON ac.id = at.attack_case_id
            GROUP BY ac.category, jv.observed_behavior
            """
        ).fetchall()
        out: dict[str, dict[str, int]] = {c.value: {} for c in ThreatCategory}
        for r in rows:
            out.setdefault(r["category"], {})[r["ob"]] = r["n"]
        return out

    def total_cost(self) -> float:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0.0) AS c FROM attack_attempts"
        ).fetchone()
        return float(row["c"])

    def regression_cases(self) -> list[AttackCase]:
        rows = self._conn.execute(
            "SELECT * FROM attack_cases WHERE in_regression_suite = 1"
        ).fetchall()
        return [self._attack_case_from_row(r) for r in rows]

    def recent_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # -- row -> model helpers ---------------------------------------------- #
    def _columns(self, table: str) -> set[str]:
        return {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})").fetchall()}

    @staticmethod
    def _attack_case_from_row(row: sqlite3.Row) -> AttackCase:
        d = dict(row)
        d.pop("run_id", None)
        d["prompt_or_sequence"] = json.loads(d["prompt_or_sequence"])
        d["framework_refs"] = json.loads(d["framework_refs"])
        d["in_regression_suite"] = bool(d["in_regression_suite"])
        return AttackCase.model_validate(d)
