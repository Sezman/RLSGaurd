"""The FunctionDef model — a reconstructed CREATE FUNCTION definition."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FunctionDef(BaseModel):
    """A database function, captured for SECURITY DEFINER analysis."""

    schema_name: str
    name: str
    security_definer: bool = False
    # True when the function `returns trigger` (invoked by triggers, not callable
    # directly through the API / RPC).
    returns_trigger: bool = False
    # The value of a `SET search_path = ...` clause, if one is configured.
    search_path: str | None = None
    body: str = ""

    # EXECUTE exposure derived from GRANT/REVOKE. `has_exec_grant_info` is True
    # once an explicit EXECUTE grant/revoke touched this function; until then the
    # PostgreSQL default (EXECUTE to PUBLIC) is assumed. `exec_api_roles` holds the
    # subset of {anon, authenticated} that can execute it.
    has_exec_grant_info: bool = False
    exec_api_roles: set[str] = Field(default_factory=set)

    file: str | None = None
    line: int | None = None

    @property
    def qualified_name(self) -> str:
        return f"{self.schema_name}.{self.name}"
