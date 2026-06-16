"""Tests for SUPA-RLS-001 (public table without RLS)."""

from pathlib import Path

from rlsguard.engine import scan_project

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_table_without_rls_is_detected():
    findings = scan_project(FIXTURES / "table-without-rls")

    assert any(f.rule_id == "SUPA-RLS-001" for f in findings)

    rls = next(f for f in findings if f.rule_id == "SUPA-RLS-001")
    assert rls.severity == "critical"
    assert "public.messages" in rls.title
    assert rls.file is not None and rls.file.endswith(".sql")
    assert rls.line is not None


def test_table_with_rls_is_not_flagged():
    findings = scan_project(FIXTURES / "table-with-correct-rls")

    assert not any(f.rule_id == "SUPA-RLS-001" for f in findings)
