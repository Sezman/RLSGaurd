"""Typer CLI entrypoint: ``rlsguard scan PATH``."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from rlsguard.engine import run_scan
from rlsguard.models.finding import SEVERITY_ORDER
from rlsguard.scanner.project_detector import InvalidProjectError
from rlsguard.scanner.reporter import render_json, render_sarif, render_text

app = typer.Typer(
    add_completion=False,
    help="Static security scanner for Supabase projects.",
)


class OutputFormat(str, Enum):
    text = "text"
    json = "json"
    sarif = "sarif"


class Threshold(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# Exit codes (per spec): 0 = clean, 1 = findings at/above threshold, 2 = error.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@app.callback()
def _main() -> None:
    """RLSGuard — static security scanner for Supabase projects."""
    # Presence of a callback keeps ``scan`` as an explicit subcommand
    # (otherwise Typer collapses the single command into the root).


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to the project to scan."),
    format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", help="Output format."
    ),
    fail_on: Threshold = typer.Option(
        Threshold.high, "--fail-on", help="Minimum severity that fails the scan."
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Attach Supabase doc citations to findings (and an AI explanation "
        "if ANTHROPIC_API_KEY is set).",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the report to a file instead of stdout (json/sarif formats).",
    ),
) -> None:
    """Scan a Supabase project for likely security misconfigurations."""
    # stderr console so machine output on stdout stays clean and pipeable.
    err = Console(stderr=True)

    try:
        result = run_scan(path, explain=explain)
    except InvalidProjectError as exc:
        err.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR)
    except Exception as exc:  # unexpected scanner failure
        err.print(f"[bold red]scanner error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR)

    if format is OutputFormat.json:
        rendered = render_json(result)
    elif format is OutputFormat.sarif:
        rendered = render_sarif(result)
    else:
        rendered = None

    if output:
        if rendered is None:
            err.print("[bold red]error:[/] --output requires --format json or sarif")
            raise typer.Exit(EXIT_ERROR)
        Path(output).write_text(rendered, encoding="utf-8")
        err.print(f"[dim]wrote {format.value} report to {output}[/]")
    elif rendered is not None:
        typer.echo(rendered)
    else:
        render_text(result, Console())

    threshold = SEVERITY_ORDER[fail_on.value]
    has_failing = any(f.severity_rank >= threshold for f in result.findings)
    raise typer.Exit(EXIT_FINDINGS if has_failing else EXIT_OK)


if __name__ == "__main__":
    app()
