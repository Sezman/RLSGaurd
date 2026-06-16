"""Tests for SARIF output (GitHub code scanning integration)."""

import json
from pathlib import Path

from rlsguard.engine import run_scan
from rlsguard.scanner.reporter import render_sarif

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_sarif_is_valid_and_maps_levels():
    result = run_scan(FIXTURES / "frontend-service-role-key")
    doc = json.loads(render_sarif(result))

    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "RLSGuard"

    # The critical secret finding maps to SARIF level "error".
    res = next(r for r in run["results"] if r["ruleId"] == "SUPA-KEY-001")
    assert res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/supabaseClient.ts"
    assert loc["region"]["startLine"] >= 1

    # Every result references a rule defined in the driver.
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= rule_ids


def test_sarif_level_mapping_for_low_severity():
    # A low-severity finding maps to SARIF "note".
    result = run_scan(FIXTURES / "update-missing-with-check")
    doc = json.loads(render_sarif(result))
    res = next(
        r for r in doc["runs"][0]["results"] if r["ruleId"] == "SUPA-RLS-004"
    )
    assert res["level"] == "note"
    assert res["properties"]["severity"] == "low"
