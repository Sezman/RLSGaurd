"""Tests for SUPA-FUNC-001 (SECURITY DEFINER function review)."""

from pathlib import Path

from rlsguard.engine import scan_project

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_unsafe_security_definer_is_high():
    findings = scan_project(FIXTURES / "unsafe-security-definer")

    f = next((f for f in findings if f.rule_id == "SUPA-FUNC-001"), None)
    assert f is not None
    assert f.severity == "high"  # directly callable + no search_path
    assert f.confidence == "medium"
    assert "public.delete_user_data" in f.title
    assert "callable function" in f.title
    assert "search_path" in f.explanation


def test_trigger_security_definer_is_downgraded():
    # A SECURITY DEFINER *trigger* function (no search_path) is downgraded from
    # high because it is not directly callable through the API/RPC.
    findings = scan_project(FIXTURES / "trigger-security-definer")

    f = next((f for f in findings if f.rule_id == "SUPA-FUNC-001"), None)
    assert f is not None
    assert f.severity == "medium"
    assert "trigger function" in f.title
    assert "trigger" in f.explanation.lower()


def test_hardened_security_definer_is_lower_severity():
    # Still surfaced for manual review (spec), but with a pinned search_path, an
    # auth check and no other signals it is low severity.
    findings = scan_project(FIXTURES / "secure-security-definer")

    f = next((f for f in findings if f.rule_id == "SUPA-FUNC-001"), None)
    assert f is not None
    assert f.severity == "low"
    assert f.confidence == "low"
