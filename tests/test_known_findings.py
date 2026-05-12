"""Tests for the four day-one seeded findings."""

from __future__ import annotations

from pathlib import Path

from agentforge.known_findings import known_seeded_findings, seed_known_findings
from agentforge.models import ObservedBehavior, Severity, ThreatCategory
from agentforge.storage.db import Database


def test_four_known_findings_are_well_formed() -> None:
    seeds = known_seeded_findings()
    assert len(seeds) == 4
    cats = {s.case.category for s in seeds}
    assert ThreatCategory.PROMPT_INJECTION in cats
    assert ThreatCategory.DATA_EXFILTRATION in cats
    assert ThreatCategory.MISINFORMATION in cats
    assert ThreatCategory.DENIAL_OF_SERVICE in cats
    for s in seeds:
        assert s.case.invariant_id
        assert s.exploitability and s.clinical_impact
        assert s.case.in_regression_suite is True


def test_seed_known_findings_persists_and_reports(tmp_path: Path) -> None:
    db = Database(":memory:")
    written = seed_known_findings(db, reports_dir=tmp_path)
    assert len(written) == 4

    # every seeded verdict is a deterministic FAIL (the real checker produced it,
    # using the seed's context where the invariant needs it — e.g. C2's panel)
    cov = db.category_coverage()
    assert cov["prompt_injection"] == 1
    assert cov["data_exfiltration"] == 1
    assert cov["misinformation"] == 1
    assert cov["denial_of_service"] == 1
    rates = db.verdict_rates_by_category()
    for cat in ("prompt_injection", "data_exfiltration", "misinformation", "denial_of_service"):
        assert rates[cat].get("fail", 0) == 1, (cat, rates[cat])

    # findings recorded; the two CRITICAL ones (C1 doc-image, C2 binary IDOR) are
    # held as drafts; the two HIGH ones (B1, C5) are filed.
    open_sev = db.open_findings_by_severity()
    assert sum(open_sev.values()) == 4
    assert open_sev.get(Severity.CRITICAL.value, 0) == 2
    assert open_sev.get(Severity.HIGH.value, 0) == 2

    filed = list(tmp_path.glob("*.md"))
    drafts = list((tmp_path / "drafts").glob("*.md")) if (tmp_path / "drafts").exists() else []
    assert len(filed) == 2
    assert len(drafts) == 2
    for d in drafts:
        assert "DRAFT — PENDING HUMAN SIGN-OFF" in d.read_text()

    # the findings carry their report paths
    for fid, path in written:
        f = db.get_finding(fid)
        assert f is not None and f.report_path == path and Path(path).exists()
    db.close()


def test_seeded_b1_verdict_is_fail() -> None:
    """Sanity: the zero-citation seed actually trips the B1 checker."""
    from agentforge.judge import Judge

    b1 = next(s for s in known_seeded_findings() if s.case.category is ThreatCategory.MISINFORMATION)
    verdict = Judge(enable_llm_judge=False).adjudicate(b1.case, b1.attempt, context=b1.context or None)
    assert verdict.observed_behavior is ObservedBehavior.FAIL
    assert verdict.invariant_passed is False


def test_seeded_c2_idor_verdict_is_fail() -> None:
    """Sanity: the binary-IDOR seed trips the C2 checker (out-of-panel patient in the response)."""
    from agentforge.judge import Judge

    c2 = next(
        s for s in known_seeded_findings()
        if s.case.category is ThreatCategory.DATA_EXFILTRATION
    )
    verdict = Judge(enable_llm_judge=False).adjudicate(c2.case, c2.attempt, context=c2.context or None)
    assert verdict.observed_behavior is ObservedBehavior.FAIL
    assert verdict.invariant_passed is False
