"""Regression tests: SUPA-RLS-001 is conditional on GRANT/REVOKE info."""

from tests._helpers import state_from_sql

from rlsguard.rules.rls import supa_rls_001


def _has_rls_001(state) -> bool:
    return any(f.rule_id == "SUPA-RLS-001" for f in supa_rls_001(state))


def test_no_grant_info_assumes_exposed_and_flags():
    # Default Supabase behavior: with no grant info, a public no-RLS table is
    # assumed exposed and flagged.
    state = state_from_sql("create table public.messages (id bigint primary key);")
    assert _has_rls_001(state)


def test_access_revoked_from_api_roles_is_not_flagged():
    # API-role privileges revoked -> not reachable through the API -> no finding.
    state = state_from_sql(
        """
        create table public.internal_logs (id bigint primary key, msg text);
        revoke all on public.internal_logs from anon, authenticated;
        """
    )
    table = state.tables[("public", "internal_logs")]
    assert table.has_grant_info is True
    assert not (table.api_roles & {"anon", "authenticated"})
    assert not _has_rls_001(state)


def test_explicit_grant_to_api_role_is_flagged():
    # Grant info present AND access granted -> still exposed -> flagged.
    state = state_from_sql(
        """
        create table public.notes (id bigint primary key, body text);
        grant select on public.notes to anon, authenticated;
        """
    )
    table = state.tables[("public", "notes")]
    assert "anon" in table.api_roles
    assert _has_rls_001(state)


def test_schema_wide_revoke_is_respected():
    # `revoke ... on all tables in schema` applies to existing tables.
    state = state_from_sql(
        """
        create table public.secrets (id bigint primary key);
        revoke all on all tables in schema public from anon, authenticated;
        """
    )
    assert not _has_rls_001(state)
