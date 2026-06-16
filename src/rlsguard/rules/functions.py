"""Database function rules (SUPA-FUNC-001)."""

from __future__ import annotations

import re

from rlsguard.models.finding import Finding
from rlsguard.models.function import FunctionDef
from rlsguard.scanner.sql_analyzer import SchemaState

_FUNC_DOCS = "https://supabase.com/docs/guides/database/functions"

_DYNAMIC_SQL_RE = re.compile(r"\bexecute\b|\bformat\s*\(", re.IGNORECASE)
_MODIFIES_RE = re.compile(
    r"\b(insert|update|delete|truncate|drop|alter|grant|revoke)\b", re.IGNORECASE
)
_AUTH_CHECK_RE = re.compile(r"auth\s*\.\s*(uid|role|jwt)\s*\(", re.IGNORECASE)


_API_ROLES = {"anon", "authenticated"}
# severity by combined risk-signal count, for a directly reachable RPC function.
_REACHABLE_SEVERITY = {0: "low", 1: "medium", 2: "high"}  # 3+ -> high
# Capped scale for functions that aren't reachable via the API (trigger, or
# EXECUTE revoked): the API attack surface is gone, so cap at medium.
_LOW_SURFACE_SEVERITY = {0: "low", 1: "low"}  # 2+ -> medium


def supa_func_001(state: SchemaState) -> list[Finding]:
    """SUPA-FUNC-001 — SECURITY DEFINER function needing manual review.

    Every SECURITY DEFINER function is surfaced for review, but severity is
    derived from combined risk signals (missing search_path, dynamic SQL, data
    modification, no visible auth check) and from how the function can be reached:
    trigger functions and functions whose EXECUTE has been revoked from the API
    roles have a much smaller attack surface and are scored lower.
    """
    findings: list[Finding] = []
    for func in state.functions:
        if not func.security_definer:
            continue
        findings.append(_evaluate(func))
    return findings


def _is_reachable_via_api(func: FunctionDef) -> bool:
    """Whether anon/authenticated can call the function directly (RPC)."""
    if func.returns_trigger:
        return False  # invoked by triggers, not callable through the API
    if func.has_exec_grant_info:
        return bool(func.exec_api_roles & _API_ROLES)
    return True  # PostgreSQL grants EXECUTE to PUBLIC by default


def _evaluate(func: FunctionDef) -> Finding:
    body = func.body
    is_trigger = func.returns_trigger
    reachable = _is_reachable_via_api(func)

    no_search_path = func.search_path is None
    dynamic_sql = bool(_DYNAMIC_SQL_RE.search(body))
    modifies = bool(_MODIFIES_RE.search(body))
    # An authorization check only matters for functions reachable by callers.
    no_auth_check = reachable and not _AUTH_CHECK_RE.search(body)

    signals: list[str] = []
    if no_search_path:
        signals.append(
            "no explicit `SET search_path` (search-path / schema injection risk)"
        )
    if dynamic_sql:
        signals.append("contains dynamic SQL (EXECUTE/format)")
    if modifies:
        signals.append("modifies data (INSERT/UPDATE/DELETE/DDL)")
    if no_auth_check:
        signals.append("no visible authorization check (auth.uid()/auth.role())")
    n = len(signals)

    # Severity comes from the combined signals, scaled by reachability. A missing
    # search_path alone (n == 1) is therefore medium, not high.
    if reachable:
        severity = _REACHABLE_SEVERITY.get(n, "high")
        confidence = "medium" if severity == "high" else "low"
    else:
        severity = _LOW_SURFACE_SEVERITY.get(n, "medium")
        confidence = "low"

    return Finding(
        rule_id="SUPA-FUNC-001",
        title=(
            f"{func.qualified_name} is a SECURITY DEFINER "
            f"{'trigger function' if is_trigger else 'callable function'} "
            "(manual review required)"
        ),
        severity=severity,
        confidence=confidence,
        file=func.file,
        line=func.line,
        evidence=f"CREATE FUNCTION {func.qualified_name}(...) ... SECURITY DEFINER",
        explanation=_explanation(func, reachable, signals),
        remediation=_remediation(func, is_trigger),
        references=[_FUNC_DOCS],
    )


def _explanation(func: FunctionDef, reachable: bool, signals: list[str]) -> str:
    intro = (
        f"{func.qualified_name} is declared SECURITY DEFINER, so it runs with the "
        "privileges of its owner. Depending on that owner and what the function does, "
        "it may be able to bypass Row Level Security, so it warrants review."
    )

    if func.returns_trigger:
        reach = (
            "It is a trigger function (returns trigger), invoked by table triggers "
            "rather than called directly, so it is not exposed through the API/RPC."
        )
    elif not reachable:
        reach = (
            "EXECUTE has been revoked from the anon/authenticated roles, so it does "
            "not appear to be callable directly through the API/RPC."
        )
    elif func.has_exec_grant_info:
        roles = ", ".join(sorted(func.exec_api_roles & _API_ROLES)) or "an API role"
        reach = (
            f"EXECUTE has been granted to {roles}, so it can be called directly "
            "through the API (PostgREST RPC)."
        )
    else:
        reach = (
            "Unless EXECUTE has been revoked, PostgreSQL grants it to PUBLIC by "
            "default, so it may be callable directly through the API (RPC)."
        )

    signal_text = (
        "Detected risk signals:\n- " + "\n- ".join(signals)
        if signals
        else "No specific risk signals were detected, but review is still advised."
    )
    return f"{intro} {reach}\n\n{signal_text}"


def _remediation(func: FunctionDef, is_trigger: bool) -> str:
    pin = (
        f"- Pin the search path: ALTER FUNCTION {func.qualified_name} "
        "SET search_path = '' (reference objects fully-qualified, e.g. public.table)."
    )
    no_dynamic = (
        "- Avoid dynamic SQL; if unavoidable, use format() with %I/%L and validate "
        "inputs."
    )
    if is_trigger:
        return (
            "Harden this trigger function:\n"
            f"{pin}\n"
            "- Confirm it genuinely needs SECURITY DEFINER; if it only touches tables "
            "the triggering user may access, SECURITY INVOKER is safer.\n"
            "- Keep the body minimal and validate the NEW/OLD row values it writes.\n"
            f"{no_dynamic}"
        )
    return (
        "Harden this callable function:\n"
        f"{pin}\n"
        "- Restrict execution: REVOKE EXECUTE ON FUNCTION "
        f"{func.qualified_name} FROM public; then GRANT EXECUTE only to the roles that "
        "need it.\n"
        "- Add an explicit authorization check inside the function (e.g. compare "
        "auth.uid() to the owner of the affected rows).\n"
        f"{no_dynamic}"
    )


RULES = [supa_func_001]
