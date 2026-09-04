"""AIVSS scoring tests, OWASP AIVSS v0.8.

The point of these is not that the arithmetic is right, though it is checked
against worked examples from the spec. It is that an unobserved factor can
never become a number without something saying where the number came from.
"""

from __future__ import annotations

import pytest

from conftest import needs_node, run_scan_fresh, run_scan_on, stage
from mcp_guard.rules import all_rules
from mcp_guard.scoring import agentic
from mcp_guard.scoring.aivss import (
    DEFAULT_MITIGATION_KEY,
    DEFAULT_THM_KEY,
    FACTOR_KEYS,
    MITIGATION_FACTOR,
    NOT_APPLICABLE,
    OBSERVED,
    OPERATOR,
    SPEC_VERSION,
    THREAT_MULTIPLIER,
    UNOBSERVED,
    FactorObservation,
    InvalidFactorVector,
    band,
    parse_vector,
    score,
    score_from_vector,
    to_vector,
    unobserved,
)


def all_known(value=0.0, source="test"):
    return {k: FactorObservation(key=k, status=OBSERVED, value=value,
                                 source=source) for k in FACTOR_KEYS}


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------


def test_implements_v0_8():
    assert SPEC_VERSION == "0.8"


def test_ten_factors_in_spec_order():
    """Section 2.2 requires this exact order for the calculation vector."""
    assert FACTOR_KEYS == (
        "autonomy", "tools", "language", "context", "non_determinism",
        "opacity", "persistence", "identity", "multi_agent", "self_mod")


def test_spec_tables_are_the_spec_values():
    # Section 3.3.2 Table 4a, and 3.4.1 Table 4b.
    assert THREAT_MULTIPLIER == {"attacked": 1.00, "poc": 0.97, "unreported": 0.50}
    assert MITIGATION_FACTOR == {"none": 1.00, "partial": 0.83, "strong": 0.67}
    assert DEFAULT_THM_KEY == "poc"            # spec default 0.97
    assert DEFAULT_MITIGATION_KEY == "none"    # spec default 1.00


def test_severity_bands_are_the_spec_bands():
    # Section 3.5.2.
    assert band(9.0) == "critical"
    assert band(8.9) == "high"
    assert band(7.0) == "high"
    assert band(6.9) == "medium"
    assert band(4.0) == "medium"
    assert band(3.9) == "low"
    assert band(0.0) == "none"


# ---------------------------------------------------------------------------
# The formula
# ---------------------------------------------------------------------------


def test_formula_matches_a_hand_computation():
    """AARS = (10 - CVSS) * (Factor_Sum / 10) * ThM, then * Mitigation.

    CVSS 9.4, Factor_Sum 1.0, ThM 0.97, Mitigation 1.0:
      AARS = 0.6 * 0.1 * 0.97 = 0.0582
      raw  = 9.4 + 0.0582     = 9.4582  -> 9.5
    """
    obs = {k: FactorObservation(key=k, status=NOT_APPLICABLE, value=0.0,
                                source="n/a") for k in FACTOR_KEYS}
    obs["tools"] = FactorObservation(key="tools", status=OBSERVED, value=1.0,
                                     source="tools/list")
    s = score(9.4, obs)
    assert s.complete is True
    assert s.factor_sum_low == 1.0
    assert s.aars_low == pytest.approx(0.0582, abs=1e-4)
    assert s.low == 9.5


def test_all_factors_full_reaches_ten():
    s = score(5.0, all_known(1.0))
    # AARS = 5 * 1.0 * 0.97 = 4.85 -> 5.0 + 4.85 = 9.85 -> 9.9
    assert s.factor_sum_low == 10.0
    assert s.low == 9.9


def test_no_factors_leaves_cvss_untouched():
    s = score(7.3, all_known(0.0))
    assert s.low == 7.3


def test_mitigation_and_threat_multipliers_apply():
    strong = score(8.0, all_known(1.0), mitigation_key="strong")
    weak = score(8.0, all_known(1.0), mitigation_key="none")
    assert strong.low < weak.low

    unreported = score(8.0, all_known(1.0), thm_key="unreported")
    attacked = score(8.0, all_known(1.0), thm_key="attacked")
    assert unreported.low < attacked.low


def test_rounding_is_half_up():
    """Section 3.5.1: 8.65 becomes 8.7."""
    from mcp_guard.scoring.aivss import _round_half_up
    assert _round_half_up(8.64) == 8.6
    assert _round_half_up(8.65) == 8.7


# ---------------------------------------------------------------------------
# The observability rule
# ---------------------------------------------------------------------------


def test_an_unobserved_factor_never_becomes_a_number():
    obs = all_known(1.0)
    obs["autonomy"] = unobserved("autonomy", "deployment property")
    s = score(5.0, obs)

    assert s.complete is False
    assert s.score is None, "a partial result must not present a single score"
    assert "autonomy" in s.unobserved_factors
    assert s.low < s.high, "an unknown factor must widen the bound"
    # The unknown contributes 0.0 at the low end and 1.0 at the high end.
    assert s.factor_sum_low == 9.0
    assert s.factor_sum_high == 10.0


def test_unobserved_factor_cannot_carry_a_value():
    with pytest.raises(InvalidFactorVector):
        FactorObservation(key="autonomy", status=UNOBSERVED, value=0.5,
                          source="x")


def test_a_known_factor_must_say_where_it_came_from():
    with pytest.raises(InvalidFactorVector):
        FactorObservation(key="tools", status=OBSERVED, value=1.0, source="")


def test_values_outside_the_rubric_are_rejected():
    for bad in (0.3, 0.75, 1.5, -1.0):
        with pytest.raises(InvalidFactorVector):
            FactorObservation(key="tools", status=OBSERVED, value=bad,
                              source="test")


def test_complete_result_collapses_to_one_score():
    s = score(6.0, all_known(0.5))
    assert s.complete is True
    assert s.low == s.high
    assert s.score == s.low


# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------


def test_score_recomputes_from_its_own_vector():
    obs = all_known(0.5)
    obs["tools"] = FactorObservation(key="tools", status=OBSERVED, value=1.0,
                                     source="tools/list")
    original = score(7.7, obs)
    again = score_from_vector(7.7, original.vector)
    assert again.low == original.low
    assert again.high == original.high
    assert again.vector == original.vector


def test_every_rule_scores_reproducibly_from_its_factor_vector():
    """The CVSS discipline, applied to AIVSS: a score nobody can recompute
    from its vector is not evidence."""
    for rule in all_rules():
        obs = agentic.build_observations(rule.agentic_factors)
        computed = score(rule.score, obs)
        again = score_from_vector(rule.score, computed.vector)
        assert again.low == computed.low, rule.id
        assert again.high == computed.high, rule.id


def test_unobserved_factors_serialise_as_X():
    obs = all_known(1.0)
    obs["persistence"] = unobserved("persistence", "deployment property")
    v = to_vector(obs)
    assert v.startswith("AIVSS:0.8/")
    assert "/PE:X" in v
    assert parse_vector(v)["persistence"] is None


def test_malformed_vectors_raise_rather_than_scoring():
    for bad in ("", "AIVSS:0.5/AU:1.0", "AIVSS:0.8/AU:1.0",
                "AIVSS:0.8/ZZ:1.0", "nonsense"):
        with pytest.raises(InvalidFactorVector):
            parse_vector(bad)


def test_out_of_range_cvss_raises():
    with pytest.raises(InvalidFactorVector):
        score(11.0, all_known(0.0))


def test_unknown_multiplier_keys_raise():
    with pytest.raises(InvalidFactorVector):
        score(5.0, all_known(0.0), thm_key="made-up")
    with pytest.raises(InvalidFactorVector):
        score(5.0, all_known(0.0), mitigation_key="made-up")


# ---------------------------------------------------------------------------
# What the scanner can and cannot observe
# ---------------------------------------------------------------------------


def test_only_tools_is_scanner_observable():
    assert agentic.SCANNER_OBSERVABLE == ("tools",)


def test_tools_scored_from_tools_list():
    none = agentic.observe_tools({"tools_discovered": 0}, shell_proven=False)
    some = agentic.observe_tools({"tools_discovered": 3}, shell_proven=False)
    shell = agentic.observe_tools({"tools_discovered": 3}, shell_proven=True)
    assert none.value == 0.0
    assert some.value == 0.5
    assert shell.value == 1.0
    assert "canary" in shell.source


def test_tools_unobservable_without_the_dynamic_stage():
    assert agentic.observe_tools(None, shell_proven=False) is None
    obs = agentic.build_observations(("tools",), dynamic_artifacts=None)
    assert obs["tools"].status == UNOBSERVED
    assert obs["tools"].value is None


def test_factors_a_rule_is_not_affected_by_are_scored_not_assumed():
    obs = agentic.build_observations(("tools",))
    assert obs["multi_agent"].status == NOT_APPLICABLE
    assert obs["multi_agent"].value == 0.0
    assert "not applicable" in obs["multi_agent"].source
    # A factor the rule IS affected by, but which was not seen, stays unknown.
    assert obs["tools"].status == UNOBSERVED


def test_operator_supplied_factors_are_labelled_as_such():
    obs = agentic.build_observations(
        ("autonomy", "tools"), operator_factors={"autonomy": 1.0})
    assert obs["autonomy"].status == OPERATOR
    assert obs["autonomy"].value == 1.0
    assert "operator" in obs["autonomy"].source
    s = score(5.0, obs)
    assert "autonomy" not in s.unobserved_factors


def test_operator_factor_parsing_rejects_nonsense():
    assert agentic.parse_operator_factors("autonomy=1.0,persistence=0.5") == {
        "autonomy": 1.0, "persistence": 0.5}
    for bad in ("autonomy", "autonomy=0.3", "nope=1.0", "autonomy=high"):
        with pytest.raises(InvalidFactorVector):
            agentic.parse_operator_factors(bad)


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_scan_without_dynamic_reports_factors_unobserved():
    """No dynamic stage means tools/list was never read, so even the one
    observable factor is unknown and no confident score is emitted."""
    r = run_scan_on("vulnerable-server")
    assert stage(r, "dynamic").ran is False
    assert r.findings
    for f in r.findings:
        assert f.aivss is not None
        assert f.aivss.complete is False
        assert f.aivss.score is None
        assert f.aivss.unobserved_factors


@needs_node
def test_scan_with_dynamic_observes_the_tool_surface():
    r = run_scan_fresh("vulnerable-server", allow_execute=True,
                       skip_install=True)
    assert stage(r, "dynamic").ran is True
    cmd = next(f for f in r.findings if f.rule_id == "MCPG-DYN-CMDEXEC")
    tools = next(o for o in cmd.aivss.observations if o.key == "tools")
    assert tools.status == OBSERVED
    assert tools.value == 1.0
    assert "canary" in tools.source
    # Still partial: autonomy and language remain deployment properties.
    assert cmd.aivss.complete is False
    assert "partial AIVSS" in cmd.aivss.summary()


@needs_node
def test_operator_factors_narrow_the_bound():
    wide = run_scan_fresh("vulnerable-server", allow_execute=True,
                          skip_install=True, static_enabled=False)
    narrow = run_scan_fresh(
        "vulnerable-server", allow_execute=True, skip_install=True,
        static_enabled=False,
        aivss_factors={"autonomy": 1.0, "language": 1.0})

    w = next(f for f in wide.findings if f.rule_id == "MCPG-DYN-CMDEXEC").aivss
    n = next(f for f in narrow.findings if f.rule_id == "MCPG-DYN-CMDEXEC").aivss
    assert w.complete is False
    assert n.complete is True, n.unobserved_factors
    assert n.low == n.high
    assert w.low <= n.low <= w.high


def test_cvss_remains_the_primary_score():
    """Severity must still derive from CVSS so nothing downstream shifts."""
    r = run_scan_on("vulnerable-server")
    for f in r.findings:
        from mcp_guard.models import Severity
        assert f.severity is Severity.from_score(f.cvss_score)


def test_json_report_always_carries_aivss(tmp_path):
    import json

    from conftest import fixture_path
    from mcp_guard.cli import main

    out = tmp_path / "r.json"
    main([fixture_path("vulnerable-server"), "--no-deps", "--offline",
          "--quiet", "--format", "json", "-o", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["findings"]
    for f in doc["findings"]:
        a = f["aivss"]
        assert a is not None
        assert a["spec"] == "OWASP AIVSS v0.8"
        assert a["vector"].startswith("AIVSS:0.8/")
        assert a["partial"] is True
        assert a["score"] is None
        assert a["unobserved_factors"]
        assert len(a["factors"]) == 10
