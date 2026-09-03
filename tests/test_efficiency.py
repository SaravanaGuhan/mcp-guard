"""Tests for the machinery added by the efficiency phases.

Phases B-E added roughly 700 statements. These cover them directly rather than
relying on the fixture scans to reach them incidentally.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from conftest import REPO, fixture_path, needs_node, run_scan_fresh, run_scan_on


# ---------------------------------------------------------------------------
# Phase B: entrypoint derivation
# ---------------------------------------------------------------------------


def _pkg(tmp_path, data, **files):
    (tmp_path / "package.json").write_text(json.dumps(data), encoding="utf-8")
    for name, body in files.items():
        p = tmp_path / name.replace("__", "/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return str(tmp_path)


def test_bin_string_and_map_both_yield_candidates(tmp_path):
    from mcp_guard.detect import detect

    root = _pkg(tmp_path, {"name": "x", "bin": "cli.js",
                           "dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}},
                **{"cli.js": "//"})
    cands = detect(root).launch_candidates
    assert any(c.source == "package.json bin" for c in cands)

    (tmp_path / "b").mkdir()
    root2 = _pkg(tmp_path / "b", {"name": "y", "bin": {"a": "a.js", "b": "b.js"},
                                  "dependencies": {"mcp-server": "1"}},
                 **{"a.js": "//", "b.js": "//"})
    sources = [c.source for c in detect(root2).launch_candidates]
    assert "package.json bin[a]" in sources
    assert "package.json bin[b]" in sources


def test_missing_entry_with_build_script_is_a_build_candidate(tmp_path):
    from mcp_guard.detect import detect

    root = _pkg(tmp_path, {"name": "x", "main": "dist/index.js",
                           "scripts": {"build": "tsc"},
                           "dependencies": {"mcp-server": "1"}})
    cands = detect(root).launch_candidates
    assert cands and cands[0].requires_build is True


def test_missing_entry_without_build_script_is_not_a_candidate(tmp_path):
    from mcp_guard.detect import detect

    root = _pkg(tmp_path, {"name": "x", "main": "dist/index.js",
                           "dependencies": {"mcp-server": "1"}})
    info = detect(root)
    assert info.launch_candidates == []
    assert any("does not exist" in n for n in info.detection_notes)


def test_scripts_start_is_a_candidate(tmp_path):
    from mcp_guard.detect import detect

    root = _pkg(tmp_path, {"name": "x", "scripts": {"start": "node server.js"},
                           "dependencies": {"mcp-server": "1"}})
    assert [c.argv for c in detect(root).launch_candidates] == [["npm", "start"]]


def test_mcp_manifest_supplies_a_candidate(tmp_path):
    from mcp_guard.detect import detect

    root = _pkg(tmp_path, {"name": "x", "dependencies": {"mcp-server": "1"}})
    (tmp_path / "mcp.json").write_text(json.dumps(
        {"mcpServers": {"me": {"command": "node", "args": ["srv.js"]}}}),
        encoding="utf-8")
    cands = detect(root).launch_candidates
    assert cands and cands[0].argv == ["node", "srv.js"]


def test_workspace_members_declaring_mcp_become_candidates(tmp_path):
    from mcp_guard.detect import detect

    root = _pkg(tmp_path, {"name": "root", "workspaces": ["packages/*"]})
    member = tmp_path / "packages" / "srv"
    member.mkdir(parents=True)
    (member / "package.json").write_text(json.dumps(
        {"name": "srv", "main": "index.js",
         "dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}),
        encoding="utf-8")
    (member / "index.js").write_text("//", encoding="utf-8")

    info = detect(root)
    assert info.is_mcp_server is True
    assert any(c.source.startswith("workspace packages/srv")
               for c in info.launch_candidates)


def test_workspace_members_without_mcp_are_ignored(tmp_path):
    from mcp_guard.detect import detect

    root = _pkg(tmp_path, {"name": "root", "workspaces": ["packages/*"]})
    member = tmp_path / "packages" / "plain"
    member.mkdir(parents=True)
    (member / "package.json").write_text(
        json.dumps({"name": "plain", "main": "i.js"}), encoding="utf-8")
    (member / "i.js").write_text("//", encoding="utf-8")
    assert detect(root).launch_candidates == []


def test_candidate_chain_is_reported_in_stage_artifacts():
    r = run_scan_on("clean-server", allow_execute=True, skip_install=True)
    st = r.status("dynamic")
    assert st.ran
    tried = st.artifacts.get("candidates_tried")
    assert tried and tried[0]["ok"] is True
    assert tried[0]["source"]


def test_entrypoint_override_takes_precedence():
    r = run_scan_fresh("clean-server", allow_execute=True, skip_install=True,
                       static_enabled=False, entrypoint="node index.js")
    st = r.status("dynamic")
    assert st.ran is True, st.reason
    assert st.artifacts.get("launch_source") == "--entrypoint override"


def test_docker_target_says_static_only():
    r = run_scan_on("docker-server", allow_execute=True)
    st = r.status("dynamic")
    assert st.ran is False
    assert "statically only" in (st.reason or "")


# ---------------------------------------------------------------------------
# Phase B: build tool resolution
# ---------------------------------------------------------------------------


def test_resolve_bin_prefers_target_node_modules(tmp_path):
    from mcp_guard.execution import resolve_bin

    binroot = tmp_path / "node_modules" / ".bin"
    binroot.mkdir(parents=True)
    name = "faketool" + (".cmd" if os.name == "nt" else "")
    (binroot / name).write_text("", encoding="utf-8")

    hit = resolve_bin(str(tmp_path), "faketool")
    assert hit is not None
    argv, provenance = hit
    assert "node_modules" in provenance
    assert argv[0].endswith(name)


def test_rewrite_script_leaves_npm_verbs_alone(tmp_path):
    from mcp_guard.execution import rewrite_script_command

    assert rewrite_script_command(str(tmp_path), "npm run other") is None
    assert rewrite_script_command(str(tmp_path), "node build.js") is None
    assert rewrite_script_command(str(tmp_path), "") is None


def test_install_command_always_ignores_scripts(tmp_path):
    from mcp_guard.execution import install_command

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    argv = install_command("nodejs", str(tmp_path))
    assert "--ignore-scripts" in argv
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    argv = install_command("nodejs", str(tmp_path))
    assert argv[:2] == ["npm", "ci"] and "--ignore-scripts" in argv


# ---------------------------------------------------------------------------
# Phase C: inventory, skipping, cache
# ---------------------------------------------------------------------------


def test_inventory_walks_once_and_skips_vendored(tmp_path):
    from mcp_guard.static import build_inventory

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.js").write_text("var a=1", encoding="utf-8")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "a.js").write_text("var a=1", encoding="utf-8")
    nm = tmp_path / "node_modules" / "x"
    nm.mkdir(parents=True)
    (nm / "b.js").write_text("var b=1", encoding="utf-8")
    (tmp_path / "src" / "c.min.js").write_text("var c=1", encoding="utf-8")

    inv = build_inventory(str(tmp_path))
    rels = {r for _, r in inv.files}
    assert "src/a.js" in rels
    assert "dist/a.js" not in rels, "build output must be skipped when src exists"
    assert not any("node_modules" in r for r in rels)
    assert inv.skipped_generated >= 1


def test_build_output_analysed_when_no_source_dir(tmp_path):
    from mcp_guard.static import build_inventory

    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "a.js").write_text("var a=1", encoding="utf-8")
    rels = {r for _, r in build_inventory(str(tmp_path)).files}
    assert "dist/a.js" in rels


def test_oversized_files_are_recorded_not_silently_dropped(tmp_path, monkeypatch):
    import mcp_guard.static as st

    monkeypatch.setattr(st, "MAX_FILE_BYTES", 10)
    (tmp_path / "big.js").write_text("x" * 5000, encoding="utf-8")
    inv = st.build_inventory(str(tmp_path))
    assert inv.files == []
    assert inv.skipped_too_large and inv.skipped_too_large[0][0] == "big.js"


def test_each_file_is_parsed_exactly_once(monkeypatch):
    """The acceptance criterion for Phase C."""
    import mcp_guard.static as st

    counts: dict = {}
    orig = st.analyze_one

    def wrapped(path, rel):
        counts[rel] = counts.get(rel, 0) + 1
        return orig(path, rel)

    monkeypatch.setattr(st, "analyze_one", wrapped)
    from mcp_guard.detect import detect

    st.run_static(detect(fixture_path("vulnerable-server")), use_cache=False,
                  parallel=False)
    assert counts, "nothing was analysed"
    assert max(counts.values()) == 1, counts


def test_static_cache_round_trip(tmp_path, monkeypatch):
    import mcp_guard.static as st
    from mcp_guard.detect import detect

    monkeypatch.setenv("MCPGUARD_STATIC_CACHE", str(tmp_path))
    info = detect(fixture_path("vulnerable-server"))

    art1: dict = {}
    first = st.run_static(info, use_cache=True, parallel=False, artifacts=art1)
    art2: dict = {}
    second = st.run_static(info, use_cache=True, parallel=False, artifacts=art2)

    assert [f.rule_id for f in first] == [f.rule_id for f in second]
    assert art1["cache_misses"] > 0
    assert art2["cache_hits"] > 0
    assert art2["cache_misses"] == 0


def test_changing_the_ruleset_invalidates_the_cache():
    from mcp_guard.static import _cache_key

    a = _cache_key(b"same content")
    b = _cache_key(b"other content")
    assert a != b
    assert len(a) == 64


def test_skipped_directories_are_reported():
    r = run_scan_on("vulnerable-server")
    art = r.status("static").artifacts
    assert "skipped_directories" in art
    assert "node_modules" in art["skipped_directories"]
    assert art["files_analysed"] >= 1


# ---------------------------------------------------------------------------
# Phase D: timeouts and transport correlation
# ---------------------------------------------------------------------------


def test_probe_timeout_scales_with_rtt():
    from mcp_guard.dynamic import probe_timeout
    from mcp_guard.dynamic.probes import PROBE_CMD_INJECTION, PROBE_CRASH

    # A fast server gets the 250ms floor, not the probe's 8s ceiling.
    assert probe_timeout(PROBE_CMD_INJECTION, rtt_ms=1.0) == 0.25
    # A slow server gets 20x RTT.
    assert probe_timeout(PROBE_CMD_INJECTION, rtt_ms=100.0) == pytest.approx(2.0)
    # The probe's own timeout stays the ceiling.
    assert probe_timeout(PROBE_CRASH, rtt_ms=10_000.0) == PROBE_CRASH.timeout
    # No measurement -> unchanged behaviour.
    assert probe_timeout(PROBE_CRASH, rtt_ms=0.0) == PROBE_CRASH.timeout


def test_handshake_rtt_is_recorded():
    r = run_scan_on("clean-server", allow_execute=True, skip_install=True)
    st = r.status("dynamic")
    assert st.ran
    assert isinstance(st.artifacts.get("handshake_rtt_ms"), (int, float))


@needs_node
def test_transport_correlates_concurrent_requests():
    """Pipelining is only safe if answers cannot be stolen between requests."""
    import sys

    from mcp_guard.dynamic.transport import StdioClient, spawn

    script = (
        "import sys, json\n"
        "for line in sys.stdin:\n"
        "    m = json.loads(line)\n"
        "    sys.stdout.write(json.dumps("
        "{'jsonrpc':'2.0','id':m['id'],'result':{'echo':m['id']}}) + '\\n')\n"
        "    sys.stdout.flush()\n"
    )

    async def go():
        proc = await spawn([sys.executable, "-u", "-c", script], os.getcwd())
        client = StdioClient(proc)
        client.start_stderr_pump()
        exchanges = await asyncio.gather(*[
            client.request("m", {}, timeout=10.0) for _ in range(12)])
        await client.close()
        proc.kill()
        return exchanges

    if os.name == "nt":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    results = asyncio.run(go())

    assert len(results) == 12
    for ex in results:
        assert ex.answered, ex.transport_error or "timed out"
        # Each answer must carry the id of ITS OWN request.
        sent_id = json.loads(ex.request_json)["id"]
        assert ex.response_parsed["id"] == sent_id
        assert ex.response_parsed["result"]["echo"] == sent_id


# ---------------------------------------------------------------------------
# Phase E: dependency grouping
# ---------------------------------------------------------------------------


def _adv(id_, aliases=(), vector=None):
    from mcp_guard.deps.osv import Advisory

    return Advisory(id=id_, summary="s", affected_range="r", severity="HIGH",
                    cvss_vector=vector, aliases=list(aliases), url="u")


def test_alias_dedupe_collapses_mutual_ghsa_pairs():
    from mcp_guard.deps import _dedupe_aliases

    advisories = [
        _adv("GHSA-aaaa", ["CVE-1"]),
        _adv("GHSA-bbbb", ["CVE-2", "GHSA-cccc"]),
        _adv("GHSA-cccc", ["CVE-2", "GHSA-bbbb"]),
        _adv("GHSA-dddd", ["CVE-3"]),
    ]
    out = _dedupe_aliases(advisories)
    ids = {a.id for a in out}
    assert len(out) == 3, ids
    assert "GHSA-aaaa" in ids and "GHSA-dddd" in ids
    # exactly one of the mutual pair survives
    assert len({"GHSA-bbbb", "GHSA-cccc"} & ids) == 1


def test_alias_dedupe_collapses_ghsa_and_its_cve():
    from mcp_guard.deps import _dedupe_aliases

    out = _dedupe_aliases([_adv("GHSA-xxxx", ["CVE-9"]), _adv("CVE-9", [])])
    assert len(out) == 1


def test_alias_dedupe_keeps_unrelated_advisories():
    from mcp_guard.deps import _dedupe_aliases

    out = _dedupe_aliases([_adv("GHSA-1", []), _adv("GHSA-2", []),
                           _adv("GHSA-3", [])])
    assert len(out) == 3


def test_dependency_direct_and_dev_are_read_from_the_manifest(tmp_path):
    from mcp_guard.deps.lockfiles import collect

    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"prod": "1.0.0"},
        "devDependencies": {"devpkg": "2.0.0"},
    }), encoding="utf-8")
    pinned, _ = collect(str(tmp_path))
    by = {p.name: p for p in pinned}
    assert by["prod"].direct and not by["prod"].dev
    assert by["devpkg"].direct and by["devpkg"].dev


def test_console_filter_narrows_and_counts_suppressed():
    from mcp_guard.deps import filter_findings
    from mcp_guard.models import DependencyEvidence, Finding
    from mcp_guard.rules import get as get_rule

    rule = get_rule("MCPG-DEP-KNOWN-VULN")

    def mk(title, score):
        return Finding(
            rule_id=rule.id, title=title, description="d", cwe=rule.cwe,
            cvss_vector=rule.clean_vector, cvss_score=score,
            evidence=DependencyEvidence(
                package="p", installed_version="1", advisory_id="GHSA-1",
                affected_range="r", lockfile="package.json", lockfile_line=1))

    findings = [
        mk("a 1: 1 (direct, production)", 8.0),
        mk("b 1: 1 (transitive, production)", 8.0),
        mk("c 1: 1 (direct, dev)", 8.0),
        mk("d 1: 1 (direct, production)", 2.0),
    ]
    shown, suppressed = filter_findings(
        findings, include_transitive=False, include_dev=False,
        min_severity="medium")
    assert [f.title for f in shown] == ["a 1: 1 (direct, production)"]
    assert suppressed == 3

    shown, suppressed = filter_findings(
        findings, include_transitive=True, include_dev=True, min_severity="low")
    assert len(shown) == 4 and suppressed == 0
