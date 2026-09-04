"""Golden-set regression test.

This is the correctness freeze for the efficiency work. It asserts that the
findings each fixture produces are exactly what they were before any
optimization. Ids, timestamps, durations, canary uuids and absolute paths are
excluded, so a green run means the *detections* are unchanged, not that the
run was byte-identical.

If an optimization changes this file's expectations, that change must be
justified finding by finding in the commit that regenerates it.
"""

from __future__ import annotations

import json
import os

import pytest

from conftest import REPO, needs_network, needs_node

import golden as golden_tool

GOLDEN = os.path.join(REPO, "tests", "golden")

OFFLINE_FIXTURES = [f for f in golden_tool.ALL
                    if f not in golden_tool.NETWORK_FIXTURES]


def load_golden(name: str) -> dict:
    path = os.path.join(GOLDEN, f"{name}.json")
    assert os.path.exists(path), (
        f"missing golden file for {name}; run `make golden`")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _diff(expected: list, actual: list) -> str:
    exp = {json.dumps(r, sort_keys=True) for r in expected}
    act = {json.dumps(r, sort_keys=True) for r in actual}
    lines = []
    for gone in sorted(exp - act):
        lines.append(f"  LOST:  {gone}")
    for new in sorted(act - exp):
        lines.append(f"  NEW:   {new}")
    return "\n".join(lines) or "  (ordering only)"


@needs_node
@pytest.mark.parametrize("fixture", OFFLINE_FIXTURES)
def test_findings_match_golden(fixture):
    expected = load_golden(fixture)
    actual = golden_tool.scan_fixture(fixture)

    assert actual["finding_count"] == expected["finding_count"], (
        f"{fixture}: finding count changed "
        f"{expected['finding_count']} -> {actual['finding_count']}\n"
        + _diff(expected["findings"], actual["findings"]))

    assert actual["findings"] == expected["findings"], (
        f"{fixture}: findings changed\n"
        + _diff(expected["findings"], actual["findings"]))


@needs_node
@pytest.mark.parametrize("fixture", OFFLINE_FIXTURES)
def test_stage_outcomes_match_golden(fixture):
    """Whether a stage ran, and why not, is part of the contract."""
    expected = load_golden(fixture)
    actual = golden_tool.scan_fixture(fixture)

    for stage, exp in expected["stages"].items():
        got = actual["stages"].get(stage)
        assert got is not None, f"{fixture}: stage {stage} disappeared"
        assert got["ran"] == exp["ran"], (
            f"{fixture}/{stage}: ran {exp['ran']} -> {got['ran']} "
            f"(reason: {got['reason']})")


@needs_node
@pytest.mark.parametrize("fixture", OFFLINE_FIXTURES)
def test_detection_metadata_matches_golden(fixture):
    expected = load_golden(fixture)
    actual = golden_tool.scan_fixture(fixture)
    assert actual["server_type"] == expected["server_type"]
    assert actual["is_mcp_server"] == expected["is_mcp_server"]


@needs_network
def test_dependency_findings_match_golden():
    expected = load_golden("vuln-deps")
    actual = golden_tool.scan_fixture("vuln-deps")

    exp_ids = {r["advisory_id"] for r in expected["findings"]
               if r["evidence_kind"] == "dependency"}
    act_ids = {r["advisory_id"] for r in actual["findings"]
               if r["evidence_kind"] == "dependency"}

    # Advisory databases grow, so new ids are tolerated; losing one is not.
    lost = exp_ids - act_ids
    assert not lost, f"advisories no longer reported: {sorted(lost)}"
