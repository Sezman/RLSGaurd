"""The scan engine: the stable seam that ties discovery, parsing, and rules.

``scan_project`` is what both the CLI and the test-suite call. Keeping it free
of any Typer/Rich dependency makes it trivial to assert on findings in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rlsguard.models.finding import Finding
from rlsguard.rules import ALL_RULES
from rlsguard.scanner.migration_loader import build_schema_state
from rlsguard.scanner.project_detector import find_migration_files, validate_project
from rlsguard.scanner.secret_scanner import scan_secrets


@dataclass
class ScanResult:
    """Everything a caller needs to report on a completed scan."""

    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0


def scan_project(path: str | Path) -> list[Finding]:
    """Scan a project and return its findings (convenience for tests)."""
    return run_scan(path).findings


def run_scan(path: str | Path, *, explain: bool = False) -> ScanResult:
    """Scan a project, returning findings, parser warnings, and file count.

    When ``explain`` is set, findings are enriched by the RAG layer with
    documentation citations (offline) and, if an API key is available, a
    generated explanation.
    """
    root = validate_project(Path(path))
    files = find_migration_files(root)
    state = build_schema_state(files, root)

    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(state))

    # File-based scanners (source/env credential exposure).
    findings.extend(scan_secrets(root))

    # Worst findings first, then by rule id for stable output.
    findings.sort(key=lambda f: (-f.severity_rank, f.rule_id))

    if explain:
        # Imported lazily so the RAG layer is only loaded when requested.
        from rlsguard.rag.explainer import explain_findings

        findings = explain_findings(findings)

    return ScanResult(
        findings=findings,
        warnings=state.warnings,
        files_scanned=len(files),
    )
