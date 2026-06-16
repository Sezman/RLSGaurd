"""Regression: --explain must not change findings, only enrich them.

The RAG layer may add citations and an optional generated explanation, but it
must never alter the set of findings or their severity/confidence.
"""

from pathlib import Path

import pytest

from rlsguard.engine import run_scan

FIXTURES = Path(__file__).parent.parent / "fixtures"

_FIXTURE_DIRS = [
    "table-without-rls",
    "unrestricted-select-policy",
    "update-missing-with-check",
    "ownership-not-protected",
    "unsafe-storage-policy",
    "unsafe-security-definer",
    "frontend-service-role-key",
]


def _identity(findings):
    # The decision-bearing fields that --explain must never change.
    return sorted(
        (f.rule_id, f.file, f.line, f.severity, f.confidence) for f in findings
    )


@pytest.mark.parametrize("fixture", _FIXTURE_DIRS)
def test_explain_preserves_finding_decisions(fixture):
    path = FIXTURES / fixture
    plain = run_scan(path, explain=False).findings
    explained = run_scan(path, explain=True).findings

    assert len(plain) == len(explained)
    assert _identity(plain) == _identity(explained)


def test_explain_only_adds_enrichment():
    path = FIXTURES / "table-without-rls"
    explained = run_scan(path, explain=True).findings
    assert explained
    # Enrichment is additive: citations attached, decisions untouched.
    assert all(f.citations for f in explained)
