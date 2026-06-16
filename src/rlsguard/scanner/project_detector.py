"""Locate the SQL sources inside a Supabase project on disk."""

from __future__ import annotations

from pathlib import Path


class InvalidProjectError(Exception):
    """Raised when the given path is not a usable project directory."""


def find_migration_files(root: Path) -> list[Path]:
    """Return SQL files that define schema, sorted into apply order.

    Migration files under ``supabase/migrations/`` are timestamp-prefixed, so
    sorting by filename yields the order Supabase would apply them. Stand-alone
    ``schema.sql`` / ``seed.sql`` files are appended afterwards.
    """
    migrations_dir = root / "supabase" / "migrations"
    files: list[Path] = []
    if migrations_dir.is_dir():
        files.extend(sorted(migrations_dir.glob("*.sql"), key=lambda p: p.name))

    for extra in ("schema.sql", "seed.sql"):
        candidate = root / extra
        if candidate.is_file():
            files.append(candidate)

    return files


def validate_project(path: Path) -> Path:
    """Validate and normalize the scan target, returning the resolved root."""
    root = path.expanduser().resolve()
    if not root.exists():
        raise InvalidProjectError(f"path does not exist: {path}")
    if not root.is_dir():
        raise InvalidProjectError(f"path is not a directory: {path}")
    return root
