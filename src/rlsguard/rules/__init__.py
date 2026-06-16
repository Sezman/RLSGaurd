"""Detection rules. Each rule consumes the schema state and emits Findings."""

from rlsguard.rules.functions import RULES as FUNCTION_RULES
from rlsguard.rules.policies import RULES as POLICY_RULES
from rlsguard.rules.rls import RULES as RLS_RULES
from rlsguard.rules.storage import RULES as STORAGE_RULES

# The active rule set. Append new rule callables here as they come online.
ALL_RULES = [*RLS_RULES, *POLICY_RULES, *STORAGE_RULES, *FUNCTION_RULES]

__all__ = ["ALL_RULES"]
