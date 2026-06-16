"""Tests for SUPA-RLS-003 (unrestricted `true` policy)."""

from pathlib import Path

from rlsguard.engine import scan_project

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_unrestricted_select_on_sensitive_table_is_high():
    findings = scan_project(FIXTURES / "unrestricted-select-policy")

    f = next((f for f in findings if f.rule_id == "SUPA-RLS-003"), None)
    assert f is not None
    assert f.severity == "high"
    assert "public.messages" in f.title


def test_unrestricted_select_on_non_sensitive_table_is_medium():
    # Conservative behavior: a public read of non-sensitive data is review-worthy
    # (medium), not automatically a high-severity vulnerability.
    findings = scan_project(FIXTURES / "public-read-non-sensitive")

    f = next((f for f in findings if f.rule_id == "SUPA-RLS-003"), None)
    assert f is not None
    assert f.severity == "medium"
    assert f.confidence == "medium"


def test_ownership_policy_is_not_flagged_003():
    # Uses `auth.uid() = user_id`, not `true` -> must not be flagged.
    findings = scan_project(FIXTURES / "table-with-correct-rls")

    assert not any(f.rule_id == "SUPA-RLS-003" for f in findings)
