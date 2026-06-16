"""Split a SQL file into top-level statements, tracking line numbers.

This is a small hand-written scanner rather than a full SQL parser. It only
needs to know enough lexical structure to find statement-terminating semicolons
that are *not* inside a string, comment, or dollar-quoted body (e.g. a
``CREATE FUNCTION ... $$ ... ; ... $$`` body). Getting this right is what lets
the higher-level analyzer treat each statement independently and report an
accurate line number for every finding.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SqlStatement:
    """A single SQL statement and the 1-based line where it begins."""

    text: str
    start_line: int


def _dollar_tag_at(sql: str, i: int) -> str | None:
    """If a dollar-quote tag (``$$`` or ``$tag$``) starts at ``i``, return it."""
    if sql[i] != "$":
        return None
    j = i + 1
    while j < len(sql) and (sql[j].isalnum() or sql[j] == "_"):
        j += 1
    if j < len(sql) and sql[j] == "$":
        return sql[i : j + 1]
    return None


def split_statements(sql: str) -> list[SqlStatement]:
    """Split ``sql`` into statements, skipping comments/strings/dollar-bodies."""
    statements: list[SqlStatement] = []
    n = len(sql)
    i = 0
    line = 1
    stmt_start_index = 0
    stmt_start_line = 1
    seen_content = False  # has the current statement got non-whitespace yet?

    def flush(end_index: int) -> None:
        nonlocal stmt_start_index, stmt_start_line, seen_content
        chunk = sql[stmt_start_index:end_index].strip()
        if chunk:
            statements.append(SqlStatement(text=chunk, start_line=stmt_start_line))
        stmt_start_index = end_index
        seen_content = False

    while i < n:
        ch = sql[i]

        # Comments are skipped first so that a statement's recorded start point
        # lands on real SQL, not a leading comment line.
        # Line comment: -- ... \n
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            while i < n and sql[i] != "\n":
                i += 1
            continue

        # Block comment: /* ... */ (not nested)
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            i += 2
            while i + 1 < n and not (sql[i] == "*" and sql[i + 1] == "/"):
                if sql[i] == "\n":
                    line += 1
                i += 1
            i += 2
            continue

        # Track the line where the *content* of the next statement begins.
        if not seen_content and not ch.isspace():
            stmt_start_line = line
            stmt_start_index = i
            seen_content = True

        # Single-quoted string: '...' with '' escaping
        if ch == "'":
            i += 1
            while i < n:
                if sql[i] == "\n":
                    line += 1
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":  # escaped quote
                        i += 2
                        continue
                    break
                i += 1
            i += 1
            continue

        # Dollar-quoted body: $$ ... $$ or $tag$ ... $tag$
        tag = _dollar_tag_at(sql, i)
        if tag is not None:
            i += len(tag)
            while i < n:
                if sql[i] == "\n":
                    line += 1
                if sql.startswith(tag, i):
                    i += len(tag)
                    break
                i += 1
            continue

        # Statement terminator
        if ch == ";":
            flush(i)  # exclude the semicolon itself
            i += 1
            stmt_start_index = i
            continue

        if ch == "\n":
            line += 1
        i += 1

    # Trailing statement with no terminating semicolon.
    flush(n)
    return statements
