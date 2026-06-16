"""Walk a project's source/env files and detect exposed credentials."""

from __future__ import annotations

import os
from pathlib import Path

from rlsguard.models.finding import Finding
from rlsguard.rules.secrets import build_finding, find_secret_matches

_SCAN_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_SKIP_DIRS = {
    "node_modules", ".git", ".expo", ".next", "dist", "build", ".venv", "venv",
    "__pycache__", ".claude", ".turbo", "coverage", ".idea", ".vscode",
}
_MAX_BYTES = 2_000_000


def _is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def find_source_files(root: Path):
    """Yield JS/TS and .env files under ``root``, skipping vendored dirs."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if _is_env_file(name) or Path(name).suffix.lower() in _SCAN_EXTS:
                yield Path(dirpath) / name


def scan_secrets(root: Path) -> list[Finding]:
    """Return SUPA-KEY-001 findings for credentials exposed in source/env files."""
    findings: list[Finding] = []
    for path in find_source_files(root):
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        for match in find_secret_matches(text):
            findings.append(build_finding(rel, match))
    return findings
