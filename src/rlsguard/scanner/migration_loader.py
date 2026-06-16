"""Read SQL files and reconstruct schema state from their statements."""

from __future__ import annotations

from pathlib import Path

from rlsguard.scanner.sql_analyzer import SchemaState, apply_statement
from rlsguard.scanner.sql_splitter import split_statements


def build_schema_state(files: list[Path], root: Path) -> SchemaState:
    """Apply every statement in ``files`` (already in order) to a SchemaState.

    File paths in warnings/findings are recorded relative to ``root`` so reports
    are stable regardless of where the project lives on disk.
    """
    state = SchemaState()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            state.warnings.append(f"{path}: could not read file ({exc})")
            continue

        rel = _relative(path, root)
        for stmt in split_statements(text):
            apply_statement(state, stmt.text, file=rel, line=stmt.start_line)
    return state


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
