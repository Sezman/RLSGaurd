"""Shared test helpers."""

from __future__ import annotations

from rlsguard.scanner.sql_analyzer import SchemaState, apply_statement
from rlsguard.scanner.sql_splitter import split_statements


def state_from_sql(sql: str, *, file: str = "test.sql") -> SchemaState:
    """Build a SchemaState by applying every statement in ``sql`` in order."""
    state = SchemaState()
    for stmt in split_statements(sql):
        apply_statement(state, stmt.text, file=file, line=stmt.start_line)
    return state
