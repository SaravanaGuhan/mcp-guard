"""Invariants.

These are the tests that stop the audited failure modes from coming back. They
check the shape of the codebase, not just its behaviour.
"""

from __future__ import annotations

import ast
import os
import tempfile

import pytest

from conftest import REPO, needs_node, run_scan_on

PKG = os.path.join(REPO, "mcp_guard")

BANNED_PHRASES = (
    "for realistic results",
    "for more interesting results",
    "simulates dynamic findings",
)


def _py_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "node_modules", "__pycache__",
                                    ".venv", "venv", "fixtures")]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


# ---------------------------------------------------------------------------
# 1. Evidence is mandatory and non-empty
# ---------------------------------------------------------------------------


def test_finding_cannot_be_constructed_without_evidence():
    from mcp_guard.models import Finding

    with pytest.raises(TypeError):
        Finding(  # type: ignore[call-arg]
            rule_id="X", title="t", description="d", cwe="CWE-1",
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/"
                        "SC:N/SI:N/SA:N",
            cvss_score=1.0,
        )


def test_finding_rejects_none_and_wrong_type_evidence():
    from mcp_guard.models import Finding

    base = dict(
        rule_id="X", title="t", description="d", cwe="CWE-1",
        cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/"
                    "SC:N/SI:N/SA:N",
        cvss_score=1.0,
    )
    with pytest.raises(TypeError):
        Finding(evidence=None, **base)
    with pytest.raises(TypeError):
        Finding(evidence={"file": "x"}, **base)
    with pytest.raises(TypeError):
        Finding(evidence="looks like evidence", **base)


def test_evidence_types_reject_empty_raw_data():
    from mcp_guard.models import (DependencyEvidence, DynamicEvidence,
                                  StaticEvidence)

    with pytest.raises(ValueError):
        StaticEvidence(file="a.py", line=1, column=1, matched_source="",
                       rule_id="R")
    with pytest.raises(ValueError):
        DynamicEvidence(request_json="{}", response_raw="", response_parsed=None,
                        oracle_id="o", why_this_proves_it="w")
    with pytest.raises(ValueError):
        DependencyEvidence(package="p", installed_version="1", advisory_id="",
                           affected_range="r", lockfile="l", lockfile_line=1)


@needs_node
@pytest.mark.parametrize("fixture", [
    "clean-server", "vulnerable-server", "not-a-server", "instant-exit",
    "always-error-live", "docker-server", "python-server", "ts-server",
])
def test_no_finding_in_any_fixture_has_empty_evidence(fixture):
    r = run_scan_on(fixture, allow_execute=True, skip_install=True)
    for f in r.findings:
        ev = f.evidence
        assert ev is not None
        if ev.kind == "static":
            assert ev.matched_source.strip(), f"{f.rule_id} empty matched_source"
            assert ev.line >= 1
        elif ev.kind == "dynamic":
            assert ev.response_raw.strip(), f"{f.rule_id} empty response_raw"
            assert ev.request_json.strip()
        elif ev.kind == "dependency":
            assert ev.advisory_id.strip()


@needs_node
def test_every_dynamic_finding_carries_bytes_from_the_server():
    r = run_scan_on("vulnerable-server", allow_execute=True, skip_install=True,
                    static_enabled=False)
    dynamic = [f for f in r.findings if f.evidence.kind == "dynamic"]
    assert dynamic, "expected at least one dynamic finding to check"
    for f in dynamic:
        assert len(f.evidence.response_raw.strip()) > 0


def test_report_writer_refuses_a_finding_whose_file_does_not_exist():
    from mcp_guard.models import Finding, ScanResult, StaticEvidence
    from mcp_guard.report.verify import EvidenceViolation, verify_result

    r = ScanResult(target="t", tool_version="test")
    r.findings.append(Finding(
        rule_id="X", title="t", description="d", cwe="CWE-1",
        cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/"
                    "SC:N/SI:N/SA:N",
        cvss_score=1.0,
        evidence=StaticEvidence(file="does/not/exist.py", line=1, column=1,
                                matched_source="x = 1", rule_id="X"),
    ))
    with tempfile.TemporaryDirectory() as td:
        with pytest.raises(EvidenceViolation):
            verify_result(r, td)


# ---------------------------------------------------------------------------
# 2. Scores come from vectors
# ---------------------------------------------------------------------------


def test_every_rule_score_equals_the_score_of_its_own_vector():
    from mcp_guard.rules import all_rules
    from mcp_guard.scoring.cvss import score_for

    rules = all_rules()
    assert rules, "rule registry is empty"
    for rule in rules:
        vector, score = score_for(rule.vector)
        assert score == rule.score, f"{rule.id}: {score} != {rule.score}"
        assert vector == rule.clean_vector


def test_severity_is_derived_from_score():
    from mcp_guard.models import Severity

    assert Severity.from_score(0.0) is Severity.NONE
    assert Severity.from_score(3.9) is Severity.LOW
    assert Severity.from_score(4.0) is Severity.MEDIUM
    assert Severity.from_score(6.9) is Severity.MEDIUM
    assert Severity.from_score(7.0) is Severity.HIGH
    assert Severity.from_score(8.9) is Severity.HIGH
    assert Severity.from_score(9.0) is Severity.CRITICAL


def test_finding_severity_has_no_setter():
    from mcp_guard.models import Finding, StaticEvidence

    f = Finding(
        rule_id="X", title="t", description="d", cwe="CWE-1",
        cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/"
                    "SC:H/SI:H/SA:H",
        cvss_score=9.4,
        evidence=StaticEvidence(file="a.py", line=1, column=1,
                                matched_source="x", rule_id="X"),
    )
    assert f.severity.value == "critical"
    with pytest.raises(AttributeError):
        f.severity = "low"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 3. Nothing is found where there is nothing
# ---------------------------------------------------------------------------


def test_empty_directory_yields_zero_findings():
    from mcp_guard.scan import run_scan

    with tempfile.TemporaryDirectory() as td:
        result, acquired = run_scan(td, deps_enabled=False)
        if acquired:
            acquired.cleanup()
        assert result.findings == []
        assert result.server_info is not None
        assert result.server_info.is_mcp_server is False


# ---------------------------------------------------------------------------
# 4. The fabrication constructs cannot come back
# ---------------------------------------------------------------------------


def test_banned_phrases_are_absent_from_the_source_tree():
    offenders = []
    for path in _py_files(REPO):
        if os.path.join("tests", "test_invariants.py") in path:
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read().lower()
        for phrase in BANNED_PHRASES:
            if phrase in text:
                offenders.append(f"{path}: {phrase!r}")
    assert not offenders, offenders


def test_no_class_defines_the_same_method_twice():
    """mcp_scanner.py defined UniversalStaticAnalyzer.analyze_server twice, so
    the second silently shadowed the first and 1,663 lines became unreachable."""
    offenders = []
    for path in _py_files(REPO):
        with open(path, encoding="utf-8", errors="replace") as fh:
            try:
                tree = ast.parse(fh.read(), filename=path)
            except SyntaxError:
                continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            seen = {}
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    decorators = {
                        getattr(d, "attr", getattr(d, "id", ""))
                        for d in item.decorator_list
                    }
                    # @property/@x.setter legitimately repeat a name
                    if decorators & {"setter", "getter", "deleter", "overload"}:
                        continue
                    if item.name in seen:
                        offenders.append(
                            f"{path}: {node.name}.{item.name} redefined at "
                            f"line {item.lineno} (first at {seen[item.name]})")
                    seen[item.name] = item.lineno
    assert not offenders, offenders


def test_no_module_defines_the_same_top_level_function_twice():
    offenders = []
    for path in _py_files(REPO):
        with open(path, encoding="utf-8", errors="replace") as fh:
            try:
                tree = ast.parse(fh.read(), filename=path)
            except SyntaxError:
                continue
        seen = {}
        for item in tree.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name in seen:
                    offenders.append(
                        f"{path}: {item.name} redefined at line {item.lineno}")
                seen[item.name] = item.lineno
    assert not offenders, offenders


def test_every_oracle_reads_its_response_argument():
    """An oracle that ignores the server's answer is the fabrication bug."""
    path = os.path.join(PKG, "dynamic", "oracles.py")
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)

    checked = 0
    offenders = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if not node.name.startswith("oracle_"):
            continue
        checked += 1
        names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        if "response" not in names:
            offenders.append(node.name)
    assert checked >= 5, f"only found {checked} oracles; did they move?"
    assert not offenders, f"oracles ignoring their response: {offenders}"


def test_default_mode_never_spawns_a_target_process():
    """Static and dependency analysis must execute nothing."""
    import subprocess

    from mcp_guard.scan import run_scan
    from conftest import fixture_path

    spawned = []
    real_popen, real_run = subprocess.Popen, subprocess.run

    def rec(argv):
        text = " ".join(map(str, argv)) if isinstance(argv, (list, tuple)) else str(argv)
        if any(tok in text for tok in ("npm", "npx", "node", "go build", "pip",
                                       "yarn", "pnpm")):
            spawned.append(text)

    class P(real_popen):  # type: ignore[misc,valid-type]
        def __init__(self, args, *a, **k):
            rec(args)
            super().__init__(args, *a, **k)

    def r(args, *a, **k):
        rec(args)
        return real_run(args, *a, **k)

    subprocess.Popen, subprocess.run = P, r
    try:
        result, acquired = run_scan(fixture_path("vulnerable-server"),
                                    deps_enabled=False)
        if acquired:
            acquired.cleanup()
    finally:
        subprocess.Popen, subprocess.run = real_popen, real_run

    assert spawned == [], f"default mode executed target code: {spawned}"
    assert result.status("dynamic").ran is False
    assert "allow-execute" in (result.status("dynamic").reason or "")
