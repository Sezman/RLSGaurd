"""The Policy model — a reconstructed Postgres RLS policy."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Policy(BaseModel):
    """A row-level-security policy as reconstructed from migrations.

    ``operation`` is the normalized command the policy applies to: one of
    ``ALL``, ``SELECT``, ``INSERT``, ``UPDATE``, ``DELETE``.
    """

    name: str
    schema_name: str
    table: str
    operation: str = "ALL"
    roles: list[str] = Field(default_factory=list)
    using_expression: str | None = None
    check_expression: str | None = None

    # Provenance, so rules can attach precise locations to findings.
    file: str | None = None
    line: int | None = None
