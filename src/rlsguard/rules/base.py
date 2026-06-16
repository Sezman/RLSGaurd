"""The rule contract.

A rule is any callable that takes the reconstructed :class:`SchemaState` and
returns a list of :class:`Finding`. Keeping the contract this small means a new
rule is just a new function added to a rule module's ``RULES`` list — the engine
never changes.
"""

from __future__ import annotations

from typing import Callable

from rlsguard.models.finding import Finding
from rlsguard.scanner.sql_analyzer import SchemaState

Rule = Callable[[SchemaState], list[Finding]]

# Schemas that Supabase exposes through its auto-generated API. A table here
# with RLS off is reachable by anonymous/authenticated clients.
API_EXPOSED_SCHEMAS = {"public"}
