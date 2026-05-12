"""Tests for the seeded known findings — 4 day-one + 2 from the 2026-05-12 manual pass."""

from __future__ import annotations

from pathlib import Path

from agentforge.judge import Judge
from agentforge.known_findings import known_seeded_findings, seed_known_findings
from agentforge.models import ObservedBehavior, Severity, ThreatCategory
from agentforge.storage.db import Database


def test_known_findings_are_well_formed() -> None:
    seeds = known_seeded_findings()
    assert len(seeds) == 6
    cats = {s.case.category for s in seeds}
    assert ThreatCategory.PROMPT_INJECTION in cats
    assert ThreatCategory.DATA_EXFILTRATION in cats
    assert ThreatCategory.MISINFORMATION in cats
    assert ThreatCategory.DENIAL_OF_SERVICE in cats
    # the three C2 sub-findings are distinct (binary IDOR + the two from the manual pass)
    c2_subs = {
        s.case.subcategory for s in seeds if s.case.category is ThreatCategory.DATA_EXFILTRATION
    }
    assert c2_subs == {
        "binary-idor-by-id",
        "session-adoption-cross-panel-replay",
        "traces-endpoint-not-admin-gated",
    }
    for s in seeds:
        assert s.case.invariant_id
        assert s.exploitability and s.clinical_impact
        assert s.case.in_regression_suite is True
        assert s.case.id and s.attempt.attack_case_id == s.case.id


def test_every_seeded_verdict_is_a_deterministic_fail() -> None:
    """Each seed's recorded attempt trips its invariant checker — a deterministic FAIL.

    (The seeded verdict in the DB is produced exactly this way, so a later
    ``agentforge replay`` reproduces it.)
    """
    judge = Judge(enable_llm_judge=False)
    for s in known_seeded_findings():
        verdict = judge.adjudicate(s.case, s.attempt, context=s.context or None)
        assert verdict.observed_behavior is ObservedBehavior.FAIL, (s.case.subcategory, verdict)
        assert verdict.invariant_passed is False, s.case.subcategory


def test_seed_known_findings_persists_and_reports(tmp_path: Path) -> None:
    db = Database(":memory:")
    written = seed_known_findings(db, reports_dir=tmp_path)
    assert len(written) == 6

    cov = db.category_coverage()
    for cat in ("prompt_injection", "misinformation", "denial_of_service"):
        assert cov.get(cat, 0) == 1, (cat, cov)
    assert cov["data_exfiltration"] == 3  # binary-IDOR + session-adoption + traces-not-admin-gated

    rates = db.verdict_rates_by_category()
    for cat in ("prompt_injection", "misinformation", "denial_of_service"):
        assert rates[cat].get("fail", 0) == 1, (cat, rates[cat])
    assert rates["data_exfiltration"].get("fail", 0) == 3, rates["data_exfiltration"]

    # 2 CRITICAL (C1 doc-image, C2 binary-IDOR) + 4 HIGH (the two new C2 findings,
    # B1 zero-citation, C5 no-token-cap) — all open.
    open_sev = db.open_findings_by_severity()
    assert sum(open_sev.values()) == 6
    assert open_sev.get(Severity.CRITICAL.value, 0) == 2
    assert open_sev.get(Severity.HIGH.value, 0) == 4

    # The 2 CRITICALs were reviewed & signed off (human_approved=True in the seed
    # set), so all 6 reports are filed and reports/drafts/ is empty.
    filed = list(tmp_path.glob("*.md"))
    drafts = list((tmp_path / "drafts").glob("*.md")) if (tmp_path / "drafts").exists() else []
    assert len(filed) == 6
    assert len(drafts) == 0
    for f in filed:
        assert "DRAFT — PENDING HUMAN SIGN-OFF" not in f.read_text()

    # the findings carry their report paths
    for fid, path in written:
        f = db.get_finding(fid)
        assert f is not None and f.report_path == path and Path(path).exists()
    db.close()


def test_critical_seeds_are_human_approved_others_not() -> None:
    """The two CRITICAL seeds were reviewed & signed off; everything else stays gated."""
    seeds = {s.case.subcategory: s for s in known_seeded_findings()}
    assert seeds["indirect-via-document-image"].human_approved is True
    assert seeds["binary-idor-by-id"].human_approved is True
    for sub, s in seeds.items():
        if sub not in ("indirect-via-document-image", "binary-idor-by-id"):
            assert s.human_approved is False, sub
            assert s.severity is not Severity.CRITICAL, sub  # only CRITICALs need the gate


def test_manual_pass_findings_are_provenance_tagged() -> None:
    """The two findings from the 2026-05-12 manual pass carry provenance + fix SHA in notes."""
    seeds = {s.case.subcategory: s for s in known_seeded_findings()}
    for sub in ("session-adoption-cross-panel-replay", "traces-endpoint-not-admin-gated"):
        notes = seeds[sub].case.notes
        assert "provenance=manual-security-review-2026-05-12" in notes, sub
        assert "fixed-in=copilot@1055abd71" in notes, sub


def test_seeded_b1_verdict_is_fail() -> None:
    """Sanity: the zero-citation seed actually trips the B1 checker."""
    b1 = next(s for s in known_seeded_findings() if s.case.category is ThreatCategory.MISINFORMATION)
    verdict = Judge(enable_llm_judge=False).adjudicate(b1.case, b1.attempt, context=b1.context or None)
    assert verdict.observed_behavior is ObservedBehavior.FAIL
    assert verdict.invariant_passed is False


def test_seeded_c2_idor_verdict_is_fail() -> None:
    """Sanity: the binary-IDOR seed trips the C2 checker (out-of-panel patient in the response)."""
    c2 = next(
        s for s in known_seeded_findings() if s.case.subcategory == "binary-idor-by-id"
    )
    verdict = Judge(enable_llm_judge=False).adjudicate(c2.case, c2.attempt, context=c2.context or None)
    assert verdict.observed_behavior is ObservedBehavior.FAIL
    assert verdict.invariant_passed is False
