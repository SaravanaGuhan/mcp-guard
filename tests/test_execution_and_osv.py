"""Tests for execution control and the OSV client.

These paths matter: execution.py is the only module allowed to run target code,
and osv.py is the only one that talks to the network.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest


# ---------------------------------------------------------------------------
# execution: timeouts and process trees
# ---------------------------------------------------------------------------


def test_run_returns_stdout_and_exit_code(tmp_path):
    from mcp_guard.execution import run

    r = run([sys.executable, "-c", "print('hi')"], str(tmp_path), timeout=30)
    assert r.ok
    assert "hi" in r.stdout
    assert r.returncode == 0
    assert r.timed_out is False


def test_run_reports_a_nonzero_exit(tmp_path):
    from mcp_guard.execution import run

    r = run([sys.executable, "-c", "import sys; sys.exit(3)"], str(tmp_path),
            timeout=30)
    assert not r.ok
    assert r.returncode == 3


def test_run_times_out_and_kills_the_process(tmp_path):
    from mcp_guard.execution import run

    t0 = time.time()
    r = run([sys.executable, "-c", "import time; time.sleep(60)"],
            str(tmp_path), timeout=3)
    elapsed = time.time() - t0
    assert r.timed_out is True
    assert not r.ok
    assert elapsed < 30, f"timeout did not fire promptly ({elapsed:.1f}s)"


def test_timeout_kills_the_whole_process_tree(tmp_path):
    """A shell that spawned a child must not leave the child running.

    The grandchild writes a marker after GRANDCHILD_DELAY seconds. The parent
    is killed at 3s, then we wait past that delay: if the tree kill worked the
    marker never appears.
    """
    from mcp_guard.execution import run

    GRANDCHILD_DELAY = 8
    marker = tmp_path / "grandchild_ran.txt"
    child = tmp_path / "child.py"
    child.write_text(
        "import time, sys\n"
        f"time.sleep({GRANDCHILD_DELAY})\n"
        "open(sys.argv[1], 'w').write('x')\n",
        encoding="utf-8")
    parent = tmp_path / "parent.py"
    parent.write_text(
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, r'{child}', r'{marker}'])\n"
        "time.sleep(60)\n",
        encoding="utf-8")

    t0 = time.time()
    r = run([sys.executable, str(parent)], str(tmp_path), timeout=3)
    assert r.timed_out is True
    # Wait until well past the point the grandchild would have written.
    time.sleep(GRANDCHILD_DELAY + 3 - (time.time() - t0))
    assert not marker.exists(), (
        "grandchild survived the tree kill and wrote its marker")


def test_stderr_tail_limits_lines(tmp_path):
    from mcp_guard.execution import RunResult

    r = RunResult(["x"], 1, "", "\n".join(str(i) for i in range(100)))
    assert r.stderr_tail(5).splitlines() == ["95", "96", "97", "98", "99"]


def test_install_env_disables_npm_scripts():
    from mcp_guard.execution import install_env

    assert install_env("nodejs")["npm_config_ignore_scripts"] == "true"
    assert install_env("go")["CGO_ENABLED"] == "0"
    assert install_env("python") == {}


# ---------------------------------------------------------------------------
# execution: docker sandbox
# ---------------------------------------------------------------------------


def test_docker_argv_applies_every_documented_limit(tmp_path):
    from mcp_guard.execution import docker_argv

    argv = docker_argv("node:20-alpine", str(tmp_path), ["node", "x.js"],
                       network=False)
    joined = " ".join(argv)
    assert "--network none" in joined
    assert "--memory 512m" in joined
    assert "--pids-limit 256" in joined
    assert "--user 1000:1000" in joined
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--read-only" in joined
    assert ":/src:ro" in joined, "target must be mounted read-only"


def test_docker_argv_can_keep_the_network_for_install(tmp_path):
    from mcp_guard.execution import docker_argv

    argv = docker_argv("node:20-alpine", str(tmp_path), ["npm", "ci"],
                       network=True)
    assert "--network" not in " ".join(argv)


def test_require_docker_refuses_to_downgrade(monkeypatch):
    from mcp_guard import execution

    monkeypatch.setattr(execution, "docker_available", lambda: False)
    with pytest.raises(execution.SandboxUnavailable) as exc:
        execution.require_docker("nodejs")
    assert "Refusing to downgrade" in str(exc.value)


def test_require_docker_rejects_an_unknown_server_type(monkeypatch):
    from mcp_guard import execution

    monkeypatch.setattr(execution, "docker_available", lambda: True)
    with pytest.raises(execution.SandboxUnavailable):
        execution.require_docker("brainfuck")


# ---------------------------------------------------------------------------
# osv: retry, caching, parsing
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def test_osv_retries_on_5xx_then_succeeds(monkeypatch):
    from mcp_guard.deps import osv

    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append(1)
        if len(calls) < 3:
            return _Resp(503)
        return _Resp(200, {"results": [{"vulns": []}]})

    monkeypatch.setattr(osv.requests, "post", fake_post)
    monkeypatch.setattr(osv.time, "sleep", lambda s: None)
    out = osv._post({"queries": []})
    assert out == {"results": [{"vulns": []}]}
    assert len(calls) == 3


def test_osv_raises_after_exhausting_retries(monkeypatch):
    from mcp_guard.deps import osv

    monkeypatch.setattr(osv.requests, "post",
                        lambda *a, **k: _Resp(503))
    monkeypatch.setattr(osv.time, "sleep", lambda s: None)
    with pytest.raises(osv.OSVError):
        osv._post({"queries": []})


def test_osv_raises_immediately_on_4xx(monkeypatch):
    from mcp_guard.deps import osv

    monkeypatch.setattr(osv.requests, "post",
                        lambda *a, **k: _Resp(400, text="bad"))
    with pytest.raises(osv.OSVError):
        osv._post({"queries": []})


def test_osv_query_uses_the_cache_and_issues_no_request(monkeypatch, tmp_path):
    from mcp_guard.deps import osv

    monkeypatch.setenv("MCPGUARD_CACHE", str(tmp_path))
    purl = "pkg:npm/example@1.0.0"
    osv.cache_put("purl:" + purl, [{
        "id": "GHSA-test", "summary": "s", "affected_range": "r",
        "severity": "HIGH", "cvss_vector": None, "aliases": [], "url": "u"}])

    def boom(*a, **k):
        raise AssertionError("network was contacted despite a cache hit")

    monkeypatch.setattr(osv, "_post", boom)
    out = osv.query([purl])
    assert out[purl][0].id == "GHSA-test"


def test_osv_severity_prefers_a_cvss_entry():
    from mcp_guard.deps import osv

    qual, vec = osv._severity({"severity": [], "database_specific": {}})
    assert qual is None and vec is None

    qual, vec = osv._severity({
        "severity": [{"type": "CVSS_V4",
                      "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                               "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
        "database_specific": {"severity": "critical"}})
    assert qual == "CRITICAL"
    assert vec.startswith("CVSS:4.0/")


def test_osv_scoring_uses_a_published_v4_vector():
    from mcp_guard.deps import _score_for_advisory
    from mcp_guard.deps.osv import Advisory
    from mcp_guard.rules import get as get_rule

    rule = get_rule("MCPG-DEP-KNOWN-VULN")
    adv = Advisory(
        id="GHSA-x", summary="s", affected_range="r", severity="CRITICAL",
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/"
                    "SC:H/SI:H/SA:H",
        aliases=[], url="u")
    vector, score, note = _score_for_advisory(adv, rule)
    assert vector.startswith("CVSS:4.0/")
    assert score > rule.score
    assert "OSV published" in note


def test_osv_does_not_transcode_a_v3_vector():
    from mcp_guard.deps import _score_for_advisory
    from mcp_guard.deps.osv import Advisory
    from mcp_guard.rules import get as get_rule

    rule = get_rule("MCPG-DEP-KNOWN-VULN")
    adv = Advisory(id="GHSA-y", summary="s", affected_range="r",
                   severity="HIGH",
                   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                   aliases=[], url="u")
    vector, score, note = _score_for_advisory(adv, rule)
    assert vector == rule.clean_vector, "a 3.x vector must not be transcoded"
    assert score == rule.score
    assert "not CVSS 4.0" in note


# ---------------------------------------------------------------------------
# acquire
# ---------------------------------------------------------------------------


def test_acquire_rejects_a_missing_local_path():
    from mcp_guard.acquire import AcquireError, acquire

    with pytest.raises(AcquireError):
        acquire("https://not-github.example.com/x/y")


def test_acquire_records_the_local_commit(tmp_path):
    from mcp_guard.acquire import acquire

    subprocess.run(["git", "init", "-q", str(tmp_path)], capture_output=True)
    (tmp_path / "f.txt").write_text("x", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"],
                   capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.email=a@b",
                    "-c", "user.name=a", "commit", "-qm", "x"],
                   capture_output=True)

    got = acquire(str(tmp_path))
    assert got.root == os.path.abspath(str(tmp_path))
    assert got.commit and len(got.commit) == 40
    got.cleanup()
