"""Row Level Security rules (SUPA-RLS-*)."""

from __future__ import annotations

from rlsguard.models.finding import Finding
from rlsguard.rules.base import API_EXPOSED_SCHEMAS
from rlsguard.scanner.sql_analyzer import SchemaState

_RLS_DOCS = "https://supabase.com/docs/guides/database/postgres/row-level-security"


def supa_rls_001(state: SchemaState) -> list[Finding]:
    """SUPA-RLS-001 — table in an API-exposed schema with RLS disabled.

    When GRANT/REVOKE information is available for a table, this only fires if
    anon or authenticated actually retains access — a table whose API-role
    privileges were revoked is not reachable through the API, so a missing RLS
    policy on it is not exposed. When no grant information is present, Supabase's
    permissive defaults are assumed and the table is treated as exposed.
    """
    findings: list[Finding] = []
    for table in state.tables.values():
        if table.schema_name not in API_EXPOSED_SCHEMAS:
            continue
        if table.rls_enabled:
            continue
        if table.has_grant_info and not (table.api_roles & {"anon", "authenticated"}):
            continue  # API roles have no access; not exposed.

        if table.has_grant_info:
            exposure = (
                "The anon/authenticated role has been granted access to this table "
                "and no RLS restrictions were found, "
            )
        else:
            exposure = (
                "The table exists in an API-accessible schema and no RLS restrictions "
                "were found, "
            )
        findings.append(
            Finding(
                rule_id="SUPA-RLS-001",
                title=f"{table.qualified_name} has RLS disabled",
                severity="critical",
                confidence="high",
                file=table.file,
                line=table.line,
                evidence=f"CREATE TABLE {table.qualified_name} (...)",
                explanation=(
                    f"{exposure}so any client using the anon or authenticated key can "
                    "read and write every row through the auto-generated Supabase API."
                ),
                remediation=(
                    f"ALTER TABLE {table.qualified_name} ENABLE ROW LEVEL SECURITY;\n\n"
                    "Then create explicit policies for each operation the app needs."
                ),
                references=[_RLS_DOCS],
            )
        )
    return findings


def supa_rls_002(state: SchemaState) -> list[Finding]:
    """SUPA-RLS-002 — RLS enabled on a table but no policies defined.

    This is a MEDIUM availability/correctness issue, not a data leak: with RLS
    on and zero policies, Postgres denies all access to non-owner roles, which
    usually breaks the feature rather than exposing data. The wording below is
    deliberately careful not to call it a leak.
    """
    findings: list[Finding] = []
    for table in state.tables.values():
        if table.schema_name not in API_EXPOSED_SCHEMAS:
            continue
        if not table.rls_enabled:
            continue
        if table.policies:
            continue
        findings.append(
            Finding(
                rule_id="SUPA-RLS-002",
                title=f"{table.qualified_name} has RLS enabled but no policies",
                severity="medium",
                confidence="high",
                file=table.file,
                line=table.line,
                evidence=f"ALTER TABLE {table.qualified_name} ENABLE ROW LEVEL SECURITY;",
                explanation=(
                    f"RLS is enabled on {table.qualified_name} but no policies were "
                    "found. With RLS on and no policies, PostgreSQL denies all rows to "
                    "anon and authenticated roles, so queries return nothing. This is "
                    "most likely to break the feature that reads this table rather than "
                    "to expose data - but it means no intended access path is defined."
                ),
                remediation=(
                    "Add explicit policies for each operation the app performs, e.g.:\n\n"
                    f'CREATE POLICY "select own rows" ON {table.qualified_name}\n'
                    "  FOR SELECT USING (auth.uid() = user_id);"
                ),
                references=[_RLS_DOCS],
            )
        )
    return findings


RULES = [supa_rls_001, supa_rls_002]
