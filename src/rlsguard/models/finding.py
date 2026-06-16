"""The Finding model — the unit of output for every rule."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]


class Citation(BaseModel):
    """A reference to a piece of source documentation backing an explanation."""

    title: str
    url: str
    snippet: str = ""

# Ordering used by --fail-on thresholds and report sorting (high number = worse).
SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Finding(BaseModel):
    """A single likely security issue detected by a rule.

    A Finding describes a *likely* risk, never a guaranteed vulnerability — the
    ``confidence`` field communicates how sure the rule is.
    """

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    file: str | None = None
    line: int | None = None
    evidence: str = ""
    explanation: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    # Populated by the optional RAG layer (`--explain`). When absent, `explanation`
    # above is the authoritative, deterministic fallback.
    citations: list[Citation] = Field(default_factory=list)
    generated_explanation: str | None = None

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]
