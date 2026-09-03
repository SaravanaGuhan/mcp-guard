"""Report format and CLI exit-code tests."""

from __future__ import annotations

import json
import os

import pytest

from conftest import REPO, fixture_path, run_scan_on

SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "schemas", "sarif-2.1.0.json")


def _cli(argv):
    from mcp_guard.cli import main
    return main(argv)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_json_report_carries_stages_and_full_evidence(tmp_path):
    out = tmp_path / "r.json"
    rc = _cli([fixture_path("vulnerable-server"), "--no-deps",
               "--format", "json", "-o", str(out)])
    assert rc == 1  # high-severity findings present
    doc = json.loads(out.read_text(encoding="utf-8"))

    assert doc["schema_version"]
    assert doc["tool_version"]
    assert {s["stage"] for s in doc["stages"]} == {
        "acquire", "detect", "static", "dependencies", "dynamic"}
    for s in doc["stages"]:
        assert isinstance(s["ran"], bool)
        if not s["ran"]:
            assert s["reason"], f"stage {s['stage']} skipped with no reason"

    assert doc["findings"]
    for f in doc["findings"]:
        assert f["evidence"]
        assert f["evidence"]["kind"] in ("static", "dynamic", "dependency")
        assert f["cvss_vector"].startswith("CVSS:4.0/")
        assert f["severity"] in ("none", "low", "medium", "high", "critical")


def test_json_findings_are_sorted_by_score_descending(tmp_path):
    out = tmp_path / "r.json"
    _cli([fixture_path("vulnerable-server"), "--no-deps",
          "--format", "json", "-o", str(out)])
    scores = [f["cvss_score"] for f in json.loads(out.read_text())["findings"]]
    assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not os.path.exists(SCHEMA), reason="SARIF schema not vendored")
def test_sarif_validates_against_the_oasis_schema(tmp_path):
    import jsonschema

    out = tmp_path / "r.sarif"
    _cli([fixture_path("vulnerable-server"), "--no-deps",
          "--format", "sarif", "-o", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    schema = json.loads(open(SCHEMA, encoding="utf-8").read())
    jsonschema.Draft7Validator(schema).validate(doc)

    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "MCP Guard"
    assert run["results"]
    for res in run["results"]:
        assert res["ruleId"]
        assert res["locations"]


@pytest.mark.skipif(not os.path.exists(SCHEMA), reason="SARIF schema not vendored")
def test_sarif_is_valid_even_with_no_findings(tmp_path):
    import jsonschema

    out = tmp_path / "clean.sarif"
    _cli([fixture_path("clean-server"), "--no-deps",
          "--format", "sarif", "-o", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    jsonschema.Draft7Validator(
        json.loads(open(SCHEMA, encoding="utf-8").read())).validate(doc)
    assert doc["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------


def test_console_leads_with_stages_and_redacts_secrets():
    from mcp_guard.report import console

    r = run_scan_on("vulnerable-server")
    text = console.render(r)

    assert text.index("STAGES") < text.index("FINDINGS")
    assert "DID NOT RUN" in text  # dynamic was not permitted
    # The full secret must not reach the console.
    assert "MCPGUARD_FAKE_SECRET_4f3a9c1e8b7d2a6f5c0e9b4a7d1f3e8c" not in text
    assert "MCPG-SECRET-HARDCODED" in text


def test_console_says_which_stages_ran_when_there_are_no_findings():
    from mcp_guard.report import console

    r = run_scan_on("clean-server")
    text = console.render(r)
    assert "No findings" in text
    assert "STAGES" in text


def test_json_report_keeps_the_full_secret_for_machine_use(tmp_path):
    """Documented behaviour: console redacts, JSON does not."""
    out = tmp_path / "r.json"
    _cli([fixture_path("vulnerable-server"), "--no-deps",
          "--format", "json", "-o", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    secrets = [f for f in doc["findings"]
               if f["rule_id"] == "MCPG-SECRET-HARDCODED"]
    assert secrets
    assert "MCPGUARD_FAKE_SECRET_" in secrets[0]["evidence"]["matched_source"]


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_exit_zero_when_clean(tmp_path):
    assert _cli([fixture_path("clean-server"), "--no-deps",
                 "--format", "json", "-o", str(tmp_path / "a.json")]) == 0


def test_exit_one_when_findings_at_or_above_threshold(tmp_path):
    assert _cli([fixture_path("vulnerable-server"), "--no-deps",
                 "--format", "json", "-o", str(tmp_path / "b.json")]) == 1


def test_fail_on_none_never_fails(tmp_path):
    assert _cli([fixture_path("vulnerable-server"), "--no-deps", "--fail-on",
                 "none", "--format", "json", "-o", str(tmp_path / "c.json")]) == 0


def test_fail_on_threshold_is_respected(tmp_path):
    # docker-server's worst finding is medium (5.1), so a high threshold passes.
    assert _cli([fixture_path("docker-server"), "--no-deps", "--fail-on", "high",
                 "--format", "json", "-o", str(tmp_path / "d.json")]) == 0
    assert _cli([fixture_path("docker-server"), "--no-deps", "--fail-on", "low",
                 "--format", "json", "-o", str(tmp_path / "e.json")]) == 1


def test_exit_three_when_target_cannot_be_acquired():
    assert _cli(["/definitely/not/a/real/path/xyzzy", "--no-deps"]) == 3


def test_exit_two_on_evidence_violation(tmp_path, monkeypatch):
    """The CLI must refuse to emit a report rather than print an unbacked one."""
    from mcp_guard.report import verify

    def boom(result, root):
        raise verify.EvidenceViolation("synthetic violation for test")

    monkeypatch.setattr("mcp_guard.cli.verify_result", boom)
    assert _cli([fixture_path("clean-server"), "--no-deps"]) == 2
