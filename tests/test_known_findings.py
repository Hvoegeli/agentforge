"""Tests for the three day-one seeded findings."""

from __future__ import annotations

from pathlib import Path

from agentforge.known_findings import known_seeded_findings, seed_known_findings
from agentforge.models import ObservedBehavior, Severity, ThreatCategory
from agentforge.storage.db import Database


def test_three_known_findings_are_well_formed() -> None:
    seeds = known_seeded_findings()
    assert len(seeds) == 3
    cats = {s.case.category for s in seeds}
    assert ThreatCategory.PROMPT_INJECTION in cats
    assert ThreatCategory.MISINFORMATION in cats
    assert ThreatCategory.DENIAL_OF_SERVICE in cats
    for s in seeds:
        assert s.case.invariant_id
        assert s.exploitability and s.clinical_impact
        assert s.case.in_regression_suite is True


def test_seed_known_findings_persists_and_reports(tmp_path: Path) -> None:
    db = Database(":memory:")
    written = seed_known_findings(db, reports_dir=tmp_path)
    assert len(written) == 3

    # every seeded verdict is a deterministic FAIL (the real checker produced it)
    cov = db.category_coverage()
    assert cov["prompt_injection"] == 1 and cov["misinformation"] == 1 and cov["denial_of_service"] == 1
    rates = db.verdict_rates_by_category()
    assert rates["misinformation"].get("fail", 0) == 1
    assert rates["denial_of_service"].get("fail", 0) == 1
    assert rates["prompt_injection"].get("fail", 0) == 1

    # findings recorded; the C1 doc-image one is CRITICAL and held as a draft
    open_sev = db.open_findings_by_severity()
    assert sum(open_sev.values()) == 3
    assert open_sev.get(Severity.CRITICAL.value, 0) == 1

    # reports written; the CRITICAL one is a draft, the two HIGH ones are filed
    filed = list(tmp_path.glob("*.md"))
    drafts = list((tmp_path / "drafts").glob("*.md")) if (tmp_path / "drafts").exists() else []
    assert len(filed) == 2
    assert len(drafts) == 1
    assert "DRAFT — PENDING HUMAN SIGN-OFF" in drafts[0].read_text()

    # the findings carry their report paths
    for fid, path in written:
        f = db.get_finding(fid)
        assert f is not None and f.report_path == path and Path(path).exists()
    db.close()


def test_seeded_b1_verdict_is_fail() -> None:
    """Sanity: the zero-citation seed actually trips the B1 checker."""
    from agentforge.judge import Judge

    b1 = next(s for s in known_seeded_findings() if s.case.category is ThreatCategory.MISINFORMATION)
    verdict = Judge(enable_llm_judge=False).adjudicate(b1.case, b1.attempt)
    assert verdict.observed_behavior is ObservedBehavior.FAIL
    assert verdict.invariant_passed is False
