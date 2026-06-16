"""The TableState model — a table reconstructed from migration history."""

from __future__ import annotations

from pydantic import BaseModel, Field

from rlsguard.models.policy import Policy


class TableState(BaseModel):
    """The expected final state of a table after all migrations are applied."""

    schema_name: str
    name: str
    columns: list[str] = Field(default_factory=list)
    # Columns that are foreign keys to auth.users (raises ownership confidence).
    auth_users_columns: list[str] = Field(default_factory=list)
    rls_enabled: bool = False
    policies: list[Policy] = Field(default_factory=list)

    # API-role exposure derived from GRANT/REVOKE statements. `has_grant_info` is
    # True only once an explicit grant/revoke (table- or schema-wide) touched this
    # table; until then exposure is unknown and Supabase's permissive defaults are
    # assumed. `api_roles` holds the subset of {anon, authenticated} with access.
    has_grant_info: bool = False
    api_roles: set[str] = Field(default_factory=set)

    # Where the table was first created (for finding locations).
    file: str | None = None
    line: int | None = None

    @property
    def qualified_name(self) -> str:
        return f"{self.schema_name}.{self.name}"
