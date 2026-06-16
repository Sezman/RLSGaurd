"""Tests for SUPA-STORAGE-001 (unsafe storage.objects policy)."""

from pathlib import Path

from rlsguard.engine import scan_project

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_bucket_only_storage_policy_is_detected():
    findings = scan_project(FIXTURES / "unsafe-storage-policy")

    f = next((f for f in findings if f.rule_id == "SUPA-STORAGE-001"), None)
    assert f is not None
    assert f.severity == "medium"
    assert "storage.objects" in f.title


def test_folder_scoped_storage_policy_is_not_flagged():
    findings = scan_project(FIXTURES / "secure-storage-policy")

    assert not any(f.rule_id == "SUPA-STORAGE-001" for f in findings)
