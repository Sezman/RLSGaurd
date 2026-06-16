"""Render scan results as human-readable text (Rich), JSON, or SARIF."""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from rlsguard import __version__
from rlsguard.engine import ScanResult

_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def render_text(result: ScanResult, console: Console) -> None:
    """Print a Rich report of the scan to ``console``."""
    findings = result.findings

    if not findings:
        console.print("[bold green]No findings.[/] Scanned "
                      f"{result.files_scanned} file(s).")
        _print_warnings(result, console)
        return

    for f in findings:
        style = _SEVERITY_STYLE.get(f.severity, "white")
        header = Text()
        header.append(f"{f.rule_id} - {f.severity.upper()}", style=style)
        body = Text()
        body.append(f"{f.title}\n\n", style="bold")
        if f.file:
            loc = f.file + (f":{f.line}" if f.line is not None else "")
            body.append("Location:\n", style="bold")
            body.append(f"{loc}\n\n")
        if f.evidence:
            body.append("Evidence:\n", style="bold")
            body.append(f"{f.evidence}\n\n")
        if f.explanation:
            body.append("Why this matters:\n", style="bold")
            body.append(f"{f.explanation}\n\n")
        if f.generated_explanation:
            body.append("In plain terms (AI-generated):\n", style="bold")
            body.append(f"{f.generated_explanation}\n\n")
        if f.remediation:
            body.append("Suggested remediation:\n", style="bold")
            body.append(f"{f.remediation}\n\n")
        if f.citations:
            body.append("Learn more:\n", style="bold")
            for c in f.citations:
                body.append(f"- {c.title}\n  {c.url}\n")
            body.append("\n")
        body.append(f"Confidence: {f.confidence.capitalize()}")
        console.print(Panel(body, title=header, title_align="left", border_style=style))

    console.print(_summary_line(result))
    _print_warnings(result, console)


def _summary_line(result: ScanResult) -> Text:
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    total = len(result.findings)
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if s in counts]
    return Text(f"\n{total} finding(s): " + ", ".join(parts), style="bold")


def _print_warnings(result: ScanResult, console: Console) -> None:
    for w in result.warnings:
        console.print(f"[dim]warning: {w}[/]")


def render_json(result: ScanResult) -> str:
    """Serialize the scan result to a JSON string."""
    payload = {
        "files_scanned": result.files_scanned,
        "summary": _severity_counts(result),
        "findings": [f.model_dump() for f in result.findings],
        "warnings": result.warnings,
    }
    return json.dumps(payload, indent=2)


def _severity_counts(result: ScanResult) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


# SARIF level expected by GitHub code scanning, plus a numeric security-severity
# (CVSS-like) used to bucket findings in the Security tab.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
_SECURITY_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}
_INFO_URI = "https://github.com/Sezman/RLSGuard"


def render_sarif(result: ScanResult) -> str:
    """Serialize findings to SARIF 2.1.0 for GitHub code scanning."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title},
                "helpUri": f.references[0] if f.references else _INFO_URI,
                "properties": {"security-severity": _SECURITY_SCORE[f.severity]},
            }

        result_entry: dict = {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}\n\n{f.explanation}".strip()},
            "properties": {"severity": f.severity, "confidence": f.confidence},
        }
        if f.file:
            location: dict = {
                "physicalLocation": {"artifactLocation": {"uri": f.file}}
            }
            if f.line is not None:
                location["physicalLocation"]["region"] = {"startLine": f.line}
            result_entry["locations"] = [location]
        results.append(result_entry)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RLSGuard",
                        "informationUri": _INFO_URI,
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
