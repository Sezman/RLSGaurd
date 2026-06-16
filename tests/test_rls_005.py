"""Tests for SUPA-RLS-005 (ownership column not protected)."""

from pathlib import Path

from rlsguard.engine import scan_project

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_public_select_is_contextual_review_warning():
    # The social/public SELECT read pattern is a contextual review item, not a
    # prescriptive owner-only fix.
    findings = scan_project(FIXTURES / "ownership-not-protected")

    f = next((f for f in findings if f.rule_id == "SUPA-RLS-005"), None)
    assert f is not None
    assert f.severity == "low"
    assert f.confidence == "low"
    assert "public.documents" in f.title
    assert "review" in f.title.lower()
    # Remediation must NOT prescribe owner-only; it should present it as a choice.
    rem = f.remediation.lower()
    assert "intentionally public" in rem
    assert "no change is needed" in rem


def test_owner_scoped_policy_is_not_flagged():
    findings = scan_project(FIXTURES / "secure-ownership-policy")

    assert not any(f.rule_id == "SUPA-RLS-005" for f in findings)
