"""Tests for SUPA-RLS-004 (UPDATE policy missing WITH CHECK)."""

from pathlib import Path

from rlsguard.engine import scan_project

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_update_missing_with_check_is_detected():
    findings = scan_project(FIXTURES / "update-missing-with-check")

    f = next((f for f in findings if f.rule_id == "SUPA-RLS-004"), None)
    assert f is not None
    # Hardening-level only: PostgreSQL applies USING as the implicit WITH CHECK.
    assert f.severity == "low"
    assert "public.profiles" in f.title
    # The suggested fix should add a WITH CHECK clause.
    assert "with check" in f.remediation.lower()
    # Explanation must make clear this is not a vulnerability.
    assert "implicit with check" in f.explanation.lower()
    assert "not a vulnerability" in f.explanation.lower()


def test_secure_update_policy_is_not_flagged():
    findings = scan_project(FIXTURES / "secure-update-policy")

    assert not any(f.rule_id == "SUPA-RLS-004" for f in findings)
