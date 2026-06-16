"""Policy-content rules (SUPA-RLS-003 and later policy-shape checks)."""

from __future__ import annotations

import re

from rlsguard.models.finding import Finding
from rlsguard.models.policy import Policy
from rlsguard.models.table_state import TableState
from rlsguard.rules.base import API_EXPOSED_SCHEMAS
from rlsguard.scanner.sql_analyzer import SchemaState

_RLS_DOCS = "https://supabase.com/docs/guides/database/postgres/row-level-security"

# Operations that can change data. An unrestricted policy on any of these lets
# any role write/modify/delete arbitrary rows, so it is always high severity.
_WRITE_OPS = {"INSERT", "UPDATE", "DELETE", "ALL"}

# Substrings that suggest a table holds sensitive data. Used only to *raise*
# severity for unrestricted reads — never to claim a read is definitely a vuln.
_SENSITIVE_HINTS = (
    "email",
    "token",
    "secret",
    "password",
    "passwd",
    "address",
    "payment",
    "card",
    "ssn",
    "phone",
    "message",
    "body",
    "dob",
    "birth",
)


def _is_unrestricted(expr: str | None) -> bool:
    """True if a policy expression is effectively just ``true``."""
    if expr is None:
        return False
    e = expr.strip().lower().rstrip(";").strip()
    while e.startswith("(") and e.endswith(")"):
        e = e[1:-1].strip()
    return e == "true"


def _sensitive_columns(table: TableState) -> list[str]:
    """Return columns (or the table name) that look like sensitive data."""
    hits = [c for c in table.columns if any(h in c.lower() for h in _SENSITIVE_HINTS)]
    if any(h in table.name.lower() for h in _SENSITIVE_HINTS):
        hits.append(f"(table name: {table.name})")
    return hits


def supa_rls_003(state: SchemaState) -> list[Finding]:
    """SUPA-RLS-003 — policy with an unrestricted ``true`` expression."""
    findings: list[Finding] = []
    for table in state.tables.values():
        if table.schema_name not in API_EXPOSED_SCHEMAS:
            continue
        for policy in table.policies:
            finding = _evaluate(table, policy)
            if finding is not None:
                findings.append(finding)
    return findings


def _evaluate(table: TableState, policy: Policy) -> Finding | None:
    using_open = _is_unrestricted(policy.using_expression)
    check_open = _is_unrestricted(policy.check_expression)
    if not (using_open or check_open):
        return None

    op = (policy.operation or "ALL").upper()
    qualified = table.qualified_name

    clauses = []
    if using_open:
        clauses.append("USING (true)")
    if check_open:
        clauses.append("WITH CHECK (true)")
    evidence = f'CREATE POLICY "{policy.name}" ON {qualified} FOR {op} ' + " ".join(clauses)

    if op in _WRITE_OPS:
        severity = "high"
        confidence = "high"
        explanation = (
            f"The {op} policy \"{policy.name}\" on {qualified} places no restriction "
            "on which rows it applies to (the expression is simply `true`). Any client "
            "using the anon or authenticated key can perform this write on arbitrary "
            "rows, regardless of ownership."
        )
    else:  # SELECT / read-only
        sensitive = _sensitive_columns(table)
        if sensitive:
            severity = "high"
            confidence = "high"
            explanation = (
                f"The SELECT policy \"{policy.name}\" on {qualified} exposes every row "
                "to any anon or authenticated client (the expression is simply `true`). "
                "This table appears to hold sensitive data "
                f"({', '.join(sensitive)}), so unrestricted read access is likely a "
                "data-exposure risk."
            )
        else:
            severity = "medium"
            confidence = "medium"
            explanation = (
                f"The SELECT policy \"{policy.name}\" on {qualified} allows any anon or "
                "authenticated client to read every row (the expression is simply "
                "`true`). This may be intentional for public data - review whether "
                "every row in this table is safe to expose."
            )

    return Finding(
        rule_id="SUPA-RLS-003",
        title=f"{qualified} has an unrestricted {op} policy",
        severity=severity,
        confidence=confidence,
        file=policy.file or table.file,
        line=policy.line or table.line,
        evidence=evidence,
        explanation=explanation,
        remediation=(
            "Replace the `true` expression with a condition that restricts access, "
            "e.g.:\n\n"
            f'CREATE POLICY "{policy.name}" ON {qualified}\n'
            f"  FOR {op} USING (auth.uid() = user_id);"
        ),
        references=[_RLS_DOCS],
    )


def supa_rls_004(state: SchemaState) -> list[Finding]:
    """SUPA-RLS-004 — UPDATE policy with a USING clause but no WITH CHECK.

    This is a hardening-level finding, not a vulnerability. An UPDATE policy's
    USING clause decides *which rows* may be updated; its WITH CHECK clause
    validates the *new* row values. When WITH CHECK is omitted, PostgreSQL
    automatically applies the USING expression as the implicit WITH CHECK, so the
    policy is already enforced on the new row. Making the check explicit is a
    clarity/robustness improvement (it keeps intent obvious and survives later
    edits to USING), which is why this is reported at low severity.
    """
    findings: list[Finding] = []
    for table in state.tables.values():
        if table.schema_name not in API_EXPOSED_SCHEMAS:
            continue
        for policy in table.policies:
            if (policy.operation or "").upper() != "UPDATE":
                continue
            if policy.using_expression is None or policy.check_expression is not None:
                continue
            findings.append(_missing_check_finding(table, policy))
    return findings


def _missing_check_finding(table: TableState, policy: Policy) -> Finding:
    qualified = table.qualified_name
    using = policy.using_expression or ""
    return Finding(
        rule_id="SUPA-RLS-004",
        title=f"{qualified} UPDATE policy has no explicit WITH CHECK (hardening)",
        severity="low",
        confidence="medium",
        file=policy.file or table.file,
        line=policy.line or table.line,
        evidence=(
            f'CREATE POLICY "{policy.name}" ON {qualified} FOR UPDATE '
            f"USING ({using})  -- no explicit WITH CHECK"
        ),
        explanation=(
            f"The UPDATE policy \"{policy.name}\" on {qualified} defines USING but no "
            "explicit WITH CHECK. PostgreSQL automatically applies the USING expression "
            "as the implicit WITH CHECK, so the new row values are already validated "
            "against the same condition - this is not a vulnerability. Stating WITH "
            "CHECK explicitly is a hardening improvement: it makes the intent obvious "
            "and keeps the new-row constraint correct if USING is later changed."
        ),
        remediation=(
            "Optional hardening - add an explicit WITH CHECK, typically matching "
            "USING:\n\n"
            f'CREATE POLICY "{policy.name}" ON {qualified}\n'
            "  FOR UPDATE\n"
            f"  USING ({using})\n"
            f"  WITH CHECK ({using});"
        ),
        references=[_RLS_DOCS],
    )


# Column names that conventionally identify the owner of a row.
_OWNERSHIP_NAMES = {"user_id", "owner_id", "created_by", "author_id", "account_id"}

_AUTH_UID_RE = re.compile(r"auth\s*\.\s*uid\s*\(\s*\)", re.IGNORECASE)


def _mentions_auth_uid(expr: str) -> bool:
    return bool(_AUTH_UID_RE.search(expr))


def _mentions_column(expr: str, column: str) -> bool:
    return re.search(rf"\b{re.escape(column)}\b", expr, re.IGNORECASE) is not None


def _governing_expression(policy: Policy) -> str:
    """The expression(s) that decide row access for the policy's operation."""
    op = (policy.operation or "ALL").upper()
    using = policy.using_expression or ""
    check = policy.check_expression or ""
    if op == "SELECT" or op == "DELETE":
        return using
    if op == "INSERT":
        return check
    # UPDATE / ALL / unknown -> both clauses govern access.
    return f"{using} {check}".strip()


def supa_rls_005(state: SchemaState) -> list[Finding]:
    """SUPA-RLS-005 — policy on an owned table that doesn't scope to the owner.

    For tables that have a conventional ownership column, a policy that does not
    reference *both* ``auth.uid()`` and that column may let a user reach other
    users' rows. This is reported as a *likely* authorization weakness with
    graded confidence (higher when the ownership column is a FK to auth.users),
    never as a confirmed vulnerability — public-feed designs are legitimate.
    """
    findings: list[Finding] = []
    for table in state.tables.values():
        if table.schema_name not in API_EXPOSED_SCHEMAS:
            continue
        owner_cols = [c for c in table.columns if c.lower() in _OWNERSHIP_NAMES]
        if not owner_cols:
            continue
        fk_to_auth = any(c.lower() in table.auth_users_columns for c in owner_cols)

        for policy in table.policies:
            # Unrestricted `true` policies are SUPA-RLS-003's job; don't duplicate.
            if _is_unrestricted(policy.using_expression) or _is_unrestricted(
                policy.check_expression
            ):
                continue
            finding = _ownership_finding(table, policy, owner_cols, fk_to_auth)
            if finding is not None:
                findings.append(finding)
    return findings


def _ownership_finding(
    table: TableState, policy: Policy, owner_cols: list[str], fk_to_auth: bool
) -> Finding | None:
    expr = _governing_expression(policy)
    has_uid = _mentions_auth_uid(expr)
    has_owner = any(_mentions_column(expr, c) for c in owner_cols)
    if has_uid and has_owner:
        return None  # properly scoped to the owner

    qualified = table.qualified_name
    op = (policy.operation or "ALL").upper()
    owner_label = "/".join(owner_cols)
    fk_note = ", a foreign key to auth.users" if fk_to_auth else ""
    evidence = (
        f'CREATE POLICY "{policy.name}" ON {qualified} FOR {op} '
        f"-- expression: {expr or '(none)'}"
    )
    scope_remediation = (
        "Scope the policy to the row owner, e.g.:\n\n"
        f'CREATE POLICY "{policy.name}" ON {qualified}\n'
        f"  FOR {op} USING (auth.uid() = {owner_cols[0]});"
    )

    if has_uid and not has_owner:
        # Uses auth.uid() but compares against something other than the owner
        # column — possibly the wrong identifier. Worth verifying.
        return Finding(
            rule_id="SUPA-RLS-005",
            title=f"{qualified} {op} policy may scope by the wrong identifier",
            severity="medium",
            confidence="high" if fk_to_auth else "medium",
            file=policy.file or table.file,
            line=policy.line or table.line,
            evidence=evidence,
            explanation=(
                f"{qualified} has an ownership column ({owner_label}{fk_note}), but the "
                f"{op} policy \"{policy.name}\" references auth.uid() without referencing "
                "that column, so it may be scoping access by the wrong identifier. "
                "Verify the comparison restricts each user to their own rows."
            ),
            remediation=scope_remediation,
            references=[_RLS_DOCS],
        )

    if op != "SELECT":
        # Write/ALL with no ownership check: any permitted role can modify or
        # delete rows they do not own.
        return Finding(
            rule_id="SUPA-RLS-005",
            title=f"{qualified} {op} policy does not restrict writes to the owner",
            severity="medium",
            confidence="medium" if fk_to_auth else "low",
            file=policy.file or table.file,
            line=policy.line or table.line,
            evidence=evidence,
            explanation=(
                f"{qualified} has an ownership column ({owner_label}{fk_note}), but the "
                f"{op} policy \"{policy.name}\" references neither auth.uid() nor that "
                "column, so it does not restrict the operation to the row's owner. Any "
                "role the policy applies to could modify or delete other users' rows."
            ),
            remediation=scope_remediation,
            references=[_RLS_DOCS],
        )

    # SELECT with no ownership check: this is the social/public-read pattern.
    # Surface it as a contextual review item, NOT a prescriptive owner-only fix,
    # since broad reads are legitimate for public/social data.
    return Finding(
        rule_id="SUPA-RLS-005",
        title=f"{qualified} SELECT policy allows reads beyond the row owner (review)",
        severity="low",
        confidence="low",
        file=policy.file or table.file,
        line=policy.line or table.line,
        evidence=evidence,
        explanation=(
            f"{qualified} has an ownership column ({owner_label}{fk_note}), and the "
            f"SELECT policy \"{policy.name}\" lets any role it applies to read every "
            "row, not just the user's own. This is expected for intentionally shared "
            "data (for example a social or discovery feed) and is a problem only if "
            "these rows are meant to be private. Review the intent for this table."
        ),
        remediation=(
            "Decide whether this data is meant to be shared:\n"
            "- If it should be private, scope reads to the owner, e.g. "
            f"USING (auth.uid() = {owner_cols[0]}).\n"
            "- If it is intentionally public (e.g. a social feed), no change is "
            "needed - consider documenting that the broad read is deliberate."
        ),
        references=[_RLS_DOCS],
    )


RULES = [supa_rls_003, supa_rls_004, supa_rls_005]
