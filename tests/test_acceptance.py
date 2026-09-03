"""Fixture acceptance tests.

Each assertion here is the contract from the rewrite plan. No test special-cases
a fixture path or name in production code; if one of these needs a hack in
mcp_guard/ to pass, the detection logic is wrong.
"""

from __future__ import annotations

import pytest

from conftest import needs_network, needs_node, rule_ids, run_scan_on, stage


# ---------------------------------------------------------------------------
# clean-server: nothing to find, and both stages actually ran
# ---------------------------------------------------------------------------


def test_clean_server_static_is_silent():
    r = run_scan_on("clean-server")
    assert stage(r, "static").ran is True
    assert r.findings == [], [f.rule_id for f in r.findings]


@needs_node
def test_clean_server_dynamic_runs_and_finds_nothing():
    r = run_scan_on("clean-server", allow_execute=True, skip_install=True)
    st = stage(r, "dynamic")
    assert st.ran is True, st.reason
    assert st.artifacts.get("tools_discovered") == 1
    assert r.findings == [], [f.rule_id for f in r.findings]


# ---------------------------------------------------------------------------
# not-a-server: detection says so, nothing is reported
# ---------------------------------------------------------------------------


def test_not_a_server_detects_no_mcp_server():
    r = run_scan_on("not-a-server")
    assert r.server_info is not None
    assert r.server_info.is_mcp_server is False
    assert r.server_info.server_type == "unknown"
    assert r.findings == []


@needs_node
def test_not_a_server_dynamic_does_not_run():
    r = run_scan_on("not-a-server", allow_execute=True, skip_install=True)
    st = stage(r, "dynamic")
    assert st.ran is False
    assert "launch command" in (st.reason or "")
    assert r.findings == []


# ---------------------------------------------------------------------------
# instant-exit: ran=False, with the exit code and stderr
# ---------------------------------------------------------------------------


@needs_node
def test_instant_exit_reports_not_run_with_reason():
    r = run_scan_on("instant-exit", allow_execute=True, skip_install=True)
    st = stage(r, "dynamic")
    assert st.ran is False
    assert st.reason and "exited" in st.reason
    assert st.artifacts.get("exit_code") == 1
    assert "stderr_tail" in st.artifacts
    assert r.findings == []


# ---------------------------------------------------------------------------
# always-error-live: handshake fails cleanly, zero findings
# ---------------------------------------------------------------------------


@needs_node
def test_always_error_live_handshake_fails_cleanly():
    r = run_scan_on("always-error-live", allow_execute=True, skip_install=True)
    st = stage(r, "dynamic")
    assert st.ran is False
    assert "handshake failed" in (st.reason or "")
    assert r.findings == []


@needs_node
def test_server_that_handshakes_but_refuses_everything_yields_nothing():
    """The plan's Phase 8 line for always-error-live expects a SUCCESSFUL
    handshake with all oracles negative; its Phase 3 line expects a failed
    handshake. Those are different servers, so both are covered:
    always-error-live errors even on initialize (test above), and clean-server
    handshakes and then answers -32601 to everything undeclared (here)."""
    r = run_scan_on("clean-server", allow_execute=True, skip_install=True)
    st = stage(r, "dynamic")
    assert st.ran is True
    assert r.findings == []


# ---------------------------------------------------------------------------
# vulnerable-server: exactly the three planted vulnerabilities
# ---------------------------------------------------------------------------

PLANTED_STATIC = {
    "MCPG-JS-SHELL-TAINT": "exec",            # 1: child_process.exec
    "MCPG-JS-PATH-TAINT": "readFileSync",     # 2: fs.readFileSync
    "MCPG-SECRET-HARDCODED": "MCPGUARD_FAKE_SECRET_",  # 3: hardcoded credential
}


def test_vulnerable_server_static_finds_exactly_the_three_planted():
    r = run_scan_on("vulnerable-server")
    assert stage(r, "static").ran is True
    assert len(r.findings) == 3, [f.rule_id for f in r.findings]
    assert rule_ids(r) == set(PLANTED_STATIC)

    for f in r.findings:
        token = PLANTED_STATIC[f.rule_id]
        src = f.evidence.matched_source
        assert src, f"{f.rule_id} has empty matched_source"
        assert token in src, f"{f.rule_id}: {token!r} not in {src[:120]!r}"
        assert f.evidence.file.endswith("index.js")
        assert f.evidence.line > 0


@needs_node
def test_vulnerable_server_dynamic_proves_exec_and_traversal():
    r = run_scan_on("vulnerable-server", allow_execute=True, skip_install=True,
                    static_enabled=False)
    st = stage(r, "dynamic")
    assert st.ran is True, st.reason
    assert rule_ids(r) == {"MCPG-DYN-CMDEXEC", "MCPG-DYN-PATHTRAVERSAL"}, \
        [f.rule_id for f in r.findings]

    for f in r.findings:
        assert f.evidence.kind == "dynamic"
        assert f.evidence.response_raw.strip(), "dynamic finding without bytes"

    cmd = next(f for f in r.findings if f.rule_id == "MCPG-DYN-CMDEXEC")
    # The proof: the collapsed marker is in the RESPONSE but not in the REQUEST.
    marker = cmd.evidence.why_this_proves_it.split("'")[1]
    assert marker in cmd.evidence.response_raw
    assert marker not in cmd.evidence.request_json

    trav = next(f for f in r.findings if f.rule_id == "MCPG-DYN-PATHTRAVERSAL")
    assert "MCPGUARD-CANARY-" in trav.evidence.response_raw


@needs_node
def test_vulnerable_server_full_scan_is_three_planted_vulns():
    """Static and dynamic together still describe exactly three real bugs."""
    r = run_scan_on("vulnerable-server", allow_execute=True, skip_install=True)
    ids = rule_ids(r)
    assert "MCPG-SECRET-HARDCODED" in ids
    assert {"MCPG-JS-SHELL-TAINT", "MCPG-DYN-CMDEXEC"} & ids
    assert {"MCPG-JS-PATH-TAINT", "MCPG-DYN-PATHTRAVERSAL"} & ids
    assert "MCPG-DYN-CRASH" not in ids
    assert "MCPG-DYN-NO-DISPATCH" not in ids


# ---------------------------------------------------------------------------
# docker-server
# ---------------------------------------------------------------------------


def test_docker_server_finds_root_and_chmod777():
    r = run_scan_on("docker-server")
    ids = rule_ids(r)
    assert "MCPG-DOCKER-ROOT" in ids
    assert "MCPG-DOCKER-CHMOD777" in ids
    for f in r.findings:
        assert f.evidence.file.lower().endswith("dockerfile")
        assert f.evidence.matched_source.strip()


# ---------------------------------------------------------------------------
# python-server and ts-server
# ---------------------------------------------------------------------------


def test_python_server_taint_reaches_shell_and_path_sinks():
    r = run_scan_on("python-server")
    ids = rule_ids(r)
    assert "MCPG-PY-SHELL-TAINT" in ids
    assert "MCPG-PY-PATH-TAINT" in ids
    srcs = " ".join(f.evidence.matched_source for f in r.findings)
    assert "shell=True" in srcs
    # The safe call must not be reported.
    assert 'subprocess.run(["git", "status"]' not in srcs
    assert "git" not in srcs or "shell=True" in srcs


def test_ts_server_flags_prompt_injection_not_safe_execfile():
    r = run_scan_on("ts-server")
    ids = rule_ids(r)
    assert "MCPG-MCP-PROMPT-INJECTION-SURFACE" in ids
    # execFile with a literal binary and an argument vector is safe.
    assert "MCPG-JS-SHELL-TAINT" not in ids


# ---------------------------------------------------------------------------
# vuln-deps
# ---------------------------------------------------------------------------


@needs_network
def test_vuln_deps_reports_real_osv_advisories():
    import re

    r = run_scan_on("vuln-deps", deps_enabled=True, static_enabled=False)
    st = stage(r, "dependencies")
    assert st.ran is True, st.reason
    assert len(r.findings) >= 3, len(r.findings)

    packages = {f.evidence.package for f in r.findings}
    for expected in ("lodash", "minimist", "axios"):
        assert expected in packages, f"no advisory for {expected}: {packages}"

    for f in r.findings:
        ev = f.evidence
        assert ev.advisory_id, "empty advisory id"
        assert re.match(r"^(GHSA|CVE|OSV|PYSEC|GO|MAL)-[\w.-]+$", ev.advisory_id), \
            f"malformed advisory id {ev.advisory_id!r}"
        assert ev.installed_version
        assert ev.affected_range
        assert ev.lockfile
