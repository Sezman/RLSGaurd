"""Classify SQL statements and reconstruct the expected final schema.

Hybrid strategy:
- ``CREATE TABLE`` is parsed with SQLGlot (Postgres dialect) to extract the
  schema-qualified name and columns, with a regex fallback if SQLGlot raises.
- RLS-specific statements that SQLGlot models poorly (``ENABLE/DISABLE ROW LEVEL
  SECURITY``) are matched with targeted regexes.
- ``CREATE/ALTER/DROP POLICY`` are parsed with targeted regexes into Policy
  objects (SQLGlot does not model Postgres RLS policy syntax).
- Anything unrecognized is recorded as a warning and skipped — never a crash.

More statement kinds (GRANT, CREATE FUNCTION, ...) will be added here as the
rules that consume them come online.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import sqlglot
from sqlglot import expressions as exp

from rlsguard.models.function import FunctionDef
from rlsguard.models.policy import Policy
from rlsguard.models.table_state import TableState

DEFAULT_SCHEMA = "public"

_CREATE_TABLE_RE = re.compile(
    r"""create\s+table\s+(?:if\s+not\s+exists\s+)?
        (?:"?(?P<schema>\w+)"?\s*\.\s*)?
        "?(?P<name>\w+)"?""",
    re.IGNORECASE | re.VERBOSE,
)

_RLS_RE = re.compile(
    r"""alter\s+table\s+(?:only\s+)?
        (?:"?(?P<schema>\w+)"?\s*\.\s*)?
        "?(?P<name>\w+)"?
        .*?(?P<action>enable|disable)\s+row\s+level\s+security""",
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# CREATE POLICY <name> ON <schema.table> ... / DROP POLICY ... ON <table>
# Matches the leading "<verb> policy <name> on <table>" common to all three.
_POLICY_HEAD_RE = re.compile(
    r"""(?P<verb>create|alter|drop)\s+policy\s+
        (?:if\s+exists\s+)?
        (?:"(?P<qname>[^"]+)"|(?P<name>\w+))\s+
        on\s+(?:only\s+)?
        (?:"?(?P<schema>\w+)"?\s*\.\s*)?
        "?(?P<table>\w+)"?""",
    re.IGNORECASE | re.VERBOSE,
)

# Column-level FK: `user_id uuid ... references auth.users`. The `[^,]*?` keeps
# the match inside a single column definition (does not cross a comma).
_AUTH_FK_COL_RE = re.compile(
    r'(?P<col>"?\w+"?)\s+[^,]*?\breferences\s+"?auth"?\s*\.\s*"?users"?',
    re.IGNORECASE,
)
# Table-level FK: `foreign key (user_id) references auth.users`.
_AUTH_FK_CONSTRAINT_RE = re.compile(
    r'foreign\s+key\s*\(\s*"?(?P<col>\w+)"?\s*\)\s*references\s+"?auth"?\s*\.\s*"?users"?',
    re.IGNORECASE,
)

_CREATE_FUNCTION_RE = re.compile(
    r"""create\s+(?:or\s+replace\s+)?function\s+
        (?:"?(?P<schema>\w+)"?\s*\.\s*)?
        "?(?P<name>\w+)"?""",
    re.IGNORECASE | re.VERBOSE,
)
_SECURITY_DEFINER_RE = re.compile(r"\bsecurity\s+definer\b", re.IGNORECASE)
_RETURNS_TRIGGER_RE = re.compile(r"\breturns\s+trigger\b", re.IGNORECASE)
_SEARCH_PATH_RE = re.compile(
    r"\bset\s+search_path\s*(?:=|to)\s*(?P<val>[^\n;]+)", re.IGNORECASE
)
_DOLLAR_BODY_RE = re.compile(r"\$(?P<tag>\w*)\$(?P<body>.*?)\$(?P=tag)\$", re.DOTALL)

_FOR_RE = re.compile(r"\bfor\s+(?P<op>all|select|insert|update|delete)\b", re.IGNORECASE)

# GRANT/REVOKE <privs> ON <target> {TO|FROM} <roles>
_GRANT_RE = re.compile(
    r"""(?P<action>grant|revoke)\s+
        (?:grant\s+option\s+for\s+)?
        (?P<privs>.+?)\s+on\s+
        (?P<target>.+?)\s+
        (?:to|from)\s+
        (?P<roles>.+?)
        (?:\s+with\s+grant\s+option)?\s*$""",
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
_GRANT_ALL_TABLES_RE = re.compile(
    r"all\s+tables\s+in\s+schema\s+(?P<schema>\w+)", re.IGNORECASE
)
_GRANT_ALL_FUNCS_RE = re.compile(
    r"all\s+(?:functions|routines)\s+in\s+schema\s+(?P<schema>\w+)", re.IGNORECASE
)
_GRANT_FUNCTION_RE = re.compile(
    r"""^(?:function|routine|procedure)\s+
        (?:"?(?P<schema>\w+)"?\s*\.\s*)?
        "?(?P<name>\w+)"?""",
    re.IGNORECASE | re.VERBOSE,
)
# Targets that are not table DML grants (schema usage, sequences, functions...).
_GRANT_NON_TABLE_RE = re.compile(
    r"^\s*(?:schema|sequence|function|routine|procedure|all\s+sequences|"
    r"all\s+functions|all\s+routines|all\s+procedures|database|"
    r"large\s+object|foreign|type|domain|language|tablespace)\b",
    re.IGNORECASE,
)
_GRANT_TABLE_RE = re.compile(
    r"""^(?:table\s+)?
        (?:"?(?P<schema>\w+)"?\s*\.\s*)?
        "?(?P<name>\w+)"?\s*$""",
    re.IGNORECASE | re.VERBOSE,
)
_API_ROLES = {"anon", "authenticated"}
_TO_RE = re.compile(
    r"\bto\s+(?P<roles>.+?)(?=\busing\b|\bwith\s+check\b|$)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class SchemaState:
    """The reconstructed schema plus any non-fatal parser warnings."""

    tables: dict[tuple[str, str], TableState] = field(default_factory=dict)
    functions: list[FunctionDef] = field(default_factory=list)
    # API roles granted to all tables in a schema (from schema-wide grants),
    # inherited by tables created after the grant.
    schema_api_roles: dict[str, set[str]] = field(default_factory=dict)
    # Same, for EXECUTE on all functions in a schema.
    schema_func_api_roles: dict[str, set[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def get_or_create(
        self, schema: str, name: str, *, file: str | None, line: int | None
    ) -> TableState:
        key = (schema, name)
        table = self.tables.get(key)
        if table is None:
            table = TableState(schema_name=schema, name=name, file=file, line=line)
            self.tables[key] = table
        return table


def _auth_users_columns(stmt: str) -> list[str]:
    """Columns in a CREATE TABLE that are foreign keys to auth.users."""
    cols: list[str] = []
    for m in _AUTH_FK_COL_RE.finditer(stmt):
        token = m.group("col").strip('"').lower()
        if token not in ("references", "constraint"):  # avoid keyword false hits
            cols.append(token)
    for m in _AUTH_FK_CONSTRAINT_RE.finditer(stmt):
        cols.append(m.group("col").strip('"').lower())
    return list(dict.fromkeys(cols))  # de-dup, preserve order


def _parse_create_table(stmt: str) -> tuple[str, str, list[str], list[str]] | None:
    """Return (schema, name, columns, auth_user_cols) for CREATE TABLE, or None."""
    auth_cols = _auth_users_columns(stmt)

    try:
        parsed = sqlglot.parse_one(stmt, dialect="postgres")
    except Exception:
        parsed = None

    if isinstance(parsed, exp.Create) and (parsed.kind or "").upper() == "TABLE":
        table = parsed.find(exp.Table)
        if table is not None:
            schema = table.db or DEFAULT_SCHEMA
            name = table.name
            columns = [c.name for c in parsed.find_all(exp.ColumnDef)]
            if name:
                return schema, name, columns, auth_cols

    # Regex fallback (handles syntax SQLGlot may reject).
    m = _CREATE_TABLE_RE.search(stmt)
    if m:
        return m.group("schema") or DEFAULT_SCHEMA, m.group("name"), [], auth_cols
    return None


def _extract_paren_group(text: str, search_from: int) -> str | None:
    """Return the contents of the first balanced ``(...)`` at/after an index.

    Best-effort: does not account for parentheses inside string literals, which
    are rare in policy expressions. Returns the inner text without the outer
    parens, or None if no balanced group is found.
    """
    open_idx = text.find("(", search_from)
    if open_idx == -1:
        return None
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i].strip()
    return None


def _clause_expression(stmt: str, pattern: str) -> str | None:
    """Find ``pattern`` (e.g. 'using', 'with check') and return its (...) body."""
    m = re.search(pattern, stmt, re.IGNORECASE)
    if m is None:
        return None
    return _extract_paren_group(stmt, m.end() - 1)


def _parse_policy(stmt: str) -> tuple[str, Policy] | None:
    """Parse a CREATE/ALTER/DROP POLICY statement.

    Returns ``(verb, Policy)`` where verb is 'create'|'alter'|'drop'. For DROP
    only the identifying fields (name/schema/table) are meaningful.
    """
    head = _POLICY_HEAD_RE.search(stmt)
    if head is None:
        return None

    verb = head.group("verb").lower()
    name = head.group("qname") or head.group("name") or ""
    schema = head.group("schema") or DEFAULT_SCHEMA
    table = head.group("table")

    operation = "ALL"
    roles: list[str] = []
    if verb != "drop":
        for_m = _FOR_RE.search(stmt)
        if for_m:
            operation = for_m.group("op").upper()
        to_m = _TO_RE.search(stmt)
        if to_m:
            roles = [r.strip().strip('"') for r in to_m.group("roles").split(",") if r.strip()]

    policy = Policy(
        name=name,
        schema_name=schema,
        table=table,
        operation=operation,
        roles=roles,
        using_expression=_clause_expression(stmt, r"\busing\s*\("),
        check_expression=_clause_expression(stmt, r"\bwith\s+check\s*\("),
    )
    return verb, policy


def _parse_function(stmt: str, *, file: str | None, line: int | None) -> FunctionDef | None:
    """Parse a CREATE FUNCTION statement into a FunctionDef, or None."""
    head = _CREATE_FUNCTION_RE.search(stmt)
    if head is None:
        return None

    body_m = _DOLLAR_BODY_RE.search(stmt)
    body = body_m.group("body") if body_m else ""

    # A search_path option set outside the body counts as "configured".
    preamble = stmt[: body_m.start()] if body_m else stmt
    sp_m = _SEARCH_PATH_RE.search(preamble) or _SEARCH_PATH_RE.search(stmt)

    return FunctionDef(
        schema_name=head.group("schema") or DEFAULT_SCHEMA,
        name=head.group("name"),
        security_definer=bool(_SECURITY_DEFINER_RE.search(preamble)),
        returns_trigger=bool(_RETURNS_TRIGGER_RE.search(preamble)),
        search_path=sp_m.group("val").strip() if sp_m else None,
        body=body,
        file=file,
        line=line,
    )


def _grant_api_roles(roles_clause: str) -> set[str]:
    """Map a GRANT/REVOKE role list to the API roles it affects.

    ``public`` is treated as covering anon + authenticated, since those roles
    inherit privileges granted to PUBLIC.
    """
    roles = {r.strip().strip('"').lower() for r in roles_clause.split(",")}
    result: set[str] = set()
    if "public" in roles:
        result |= _API_ROLES
    result |= roles & _API_ROLES
    return result


def _apply_exec_roles(func: FunctionDef, roles: set[str], *, is_grant: bool) -> None:
    """Record an EXECUTE grant/revoke of ``roles`` on a function."""
    func.has_exec_grant_info = True
    if is_grant:
        func.exec_api_roles |= roles
    else:
        func.exec_api_roles -= roles


def _apply_grant(state: SchemaState, stmt: str, *, file: str | None, line: int | None) -> None:
    """Apply a GRANT/REVOKE statement to per-table API-role exposure."""
    m = _GRANT_RE.match(stmt.strip())
    if m is None:
        return  # unrecognized grant shape; ignore silently (not a schema change)

    is_grant = m.group("action").lower() == "grant"
    roles = _grant_api_roles(m.group("roles"))
    if not roles:
        return  # doesn't touch anon/authenticated/public; irrelevant to exposure

    target = m.group("target").strip()

    # EXECUTE exposure on functions (handled before the non-table early return).
    all_funcs = _GRANT_ALL_FUNCS_RE.search(target)
    if all_funcs:
        schema = all_funcs.group("schema")
        default = state.schema_func_api_roles.setdefault(schema, set())
        if is_grant:
            default |= roles
        else:
            default -= roles
        for fn in state.functions:
            if fn.schema_name == schema:
                _apply_exec_roles(fn, roles, is_grant=is_grant)
        return
    fn_m = _GRANT_FUNCTION_RE.match(target)
    if fn_m:
        schema = fn_m.group("schema") or DEFAULT_SCHEMA
        name = fn_m.group("name")
        for fn in state.functions:
            if fn.schema_name == schema and fn.name == name:
                _apply_exec_roles(fn, roles, is_grant=is_grant)
        return

    if _GRANT_NON_TABLE_RE.match(target):
        return  # schema usage / sequence grant, not table DML

    all_tables = _GRANT_ALL_TABLES_RE.search(target)
    if all_tables:
        schema = all_tables.group("schema")
        default = state.schema_api_roles.setdefault(schema, set())
        if is_grant:
            default |= roles
        else:
            default -= roles
        for tbl in state.tables.values():
            if tbl.schema_name == schema:
                tbl.has_grant_info = True
                if is_grant:
                    tbl.api_roles |= roles
                else:
                    tbl.api_roles -= roles
        return

    # Specific table target (possibly a comma-separated list of tables).
    for piece in target.split(","):
        tm = _GRANT_TABLE_RE.match(piece.strip())
        if tm is None:
            continue
        schema = tm.group("schema") or DEFAULT_SCHEMA
        table = state.get_or_create(schema, tm.group("name"), file=file, line=line)
        table.has_grant_info = True
        if is_grant:
            table.api_roles |= roles
        else:
            table.api_roles -= roles


def _statement_kind(stmt: str) -> str:
    """Cheap leading-keyword classification for routing/warnings."""
    s = stmt.lstrip().lower()
    if s.startswith("create table"):
        return "create_table"
    if s.startswith("alter table") and "row level security" in s:
        return "rls_toggle"
    if s.startswith("create policy") or s.startswith("alter policy") or s.startswith("drop policy"):
        return "policy"
    # Match only a real CREATE FUNCTION, not `CREATE TRIGGER ... EXECUTE FUNCTION`.
    if re.match(r"create\s+(?:or\s+replace\s+)?function\b", s):
        return "function"
    if s.startswith("grant"):
        return "grant"
    if s.startswith("revoke"):
        return "revoke"
    return "other"


def apply_statement(
    state: SchemaState, stmt: str, *, file: str | None, line: int | None
) -> None:
    """Apply one SQL statement's effect to the schema state."""
    kind = _statement_kind(stmt)

    if kind == "create_table":
        parsed = _parse_create_table(stmt)
        if parsed is None:
            state.warnings.append(f"{file}:{line}: could not parse CREATE TABLE")
            return
        schema, name, columns, auth_cols = parsed
        table = state.get_or_create(schema, name, file=file, line=line)
        if columns:
            table.columns = columns
        if auth_cols:
            table.auth_users_columns = auth_cols
        # Inherit any schema-wide grant that preceded this table's creation.
        schema_default = state.schema_api_roles.get(schema)
        if schema_default is not None:
            table.has_grant_info = True
            table.api_roles |= schema_default
        return

    if kind == "rls_toggle":
        m = _RLS_RE.search(stmt)
        if not m:
            state.warnings.append(f"{file}:{line}: could not parse RLS toggle")
            return
        schema = m.group("schema") or DEFAULT_SCHEMA
        name = m.group("name")
        table = state.get_or_create(schema, name, file=file, line=line)
        table.rls_enabled = m.group("action").lower() == "enable"
        return

    if kind == "policy":
        parsed = _parse_policy(stmt)
        if parsed is None:
            state.warnings.append(f"{file}:{line}: could not parse POLICY statement")
            return
        verb, policy = parsed
        policy.file, policy.line = file, line
        table = state.get_or_create(policy.schema_name, policy.table, file=file, line=line)

        if verb == "drop":
            table.policies = [p for p in table.policies if p.name != policy.name]
        elif verb == "alter":
            # Update the existing policy in place; if unknown, treat as create.
            existing = next((p for p in table.policies if p.name == policy.name), None)
            if existing is None:
                table.policies.append(policy)
            else:
                if policy.using_expression is not None:
                    existing.using_expression = policy.using_expression
                if policy.check_expression is not None:
                    existing.check_expression = policy.check_expression
                if policy.roles:
                    existing.roles = policy.roles
        else:  # create
            table.policies.append(policy)
        return

    if kind == "function":
        func = _parse_function(stmt, file=file, line=line)
        if func is None:
            state.warnings.append(f"{file}:{line}: could not parse CREATE FUNCTION")
            return
        # Inherit any schema-wide function grant that preceded this definition.
        schema_default = state.schema_func_api_roles.get(func.schema_name)
        if schema_default is not None:
            func.has_exec_grant_info = True
            func.exec_api_roles |= schema_default
        state.functions.append(func)
        return

    if kind in ("grant", "revoke"):
        _apply_grant(state, stmt, file=file, line=line)
        return

    # Statement kinds not yet consumed by a rule. Not an error; just skipped.
    return
