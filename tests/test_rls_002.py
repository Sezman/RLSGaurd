"""Tests for SUPA-RLS-002 (RLS enabled but no policies)."""

from pathlib import Path

from rlsguard.engine import scan_project

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_rls_without_policies_is_detected():
    findings = scan_project(FIXTURES / "rls-without-policies")

    assert any(f.rule_id == "SUPA-RLS-002" for f in findings)

    f = next(f for f in findings if f.rule_id == "SUPA-RLS-002")
    assert f.severity == "medium"
    assert "public.profiles" in f.title
    # RLS is on, so this must NOT also be reported as RLS-disabled.
    assert not any(g.rule_id == "SUPA-RLS-001" for g in findings)


def test_rls_002_explanation_is_not_a_leak_claim():
    findings = scan_project(FIXTURES / "rls-without-policies")
    f = next(f for f in findings if f.rule_id == "SUPA-RLS-002")
    # Per spec: this should not be described as a data leak.
    assert "leak" not in f.explanation.lower()


def test_table_with_policy_is_not_flagged_002():
    findings = scan_project(FIXTURES / "table-with-correct-rls")

    assert not any(f.rule_id == "SUPA-RLS-002" for f in findings)
