"""Tests for SUPA-KEY-001 (privileged credential exposure)."""

from pathlib import Path

from rlsguard.engine import scan_project
from rlsguard.rules.secrets import find_secret_matches

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_service_role_key_in_frontend_is_critical():
    findings = scan_project(FIXTURES / "frontend-service-role-key")

    f = next((f for f in findings if f.rule_id == "SUPA-KEY-001"), None)
    assert f is not None
    assert f.severity == "critical"  # client-accessible folder (src/)
    assert f.file == "src/supabaseClient.ts"
    # The actual secret must not appear verbatim in the report.
    assert "redacted" in f.evidence.lower()


def test_anon_and_publishable_keys_are_not_flagged():
    findings = scan_project(FIXTURES / "safe-publishable-key")

    assert not any(f.rule_id == "SUPA-KEY-001" for f in findings)


def test_env_reference_is_not_flagged():
    # Referencing the env var (not the value) must not trip the scanner.
    matches = find_secret_matches(
        "const key = process.env.SUPABASE_SERVICE_ROLE_KEY;"
    )
    assert matches == []


def test_postgres_connection_string_is_detected():
    matches = find_secret_matches(
        "DATABASE_URL=postgresql://postgres:s3cretP4ss@db.abc.supabase.co:5432/postgres"
    )
    assert len(matches) == 1
    assert "connection string" in matches[0].secret_type.lower()
