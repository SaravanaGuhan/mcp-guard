"""Profiling harness. `make profile`.

Emits a markdown report to stdout. Every optimization phase cites numbers
against docs/profile-baseline.md, which is this script's committed output.

Instrumentation is done by wrapping functions at runtime from here, so the
production code carries no profiling hooks.
"""

from __future__ import annotations

import io
import os
import time
from collections import Counter, defaultdict

# Repo root is one level up from scripts/, so this runs from any cwd.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(REPO, "tests", "fixtures")
REAL = os.environ.get("MCPGUARD_REAL_REPOS",
                      r"C:\Users\Work\AppData\Local\Temp\audit\real")

FIXTURE_NAMES = ["clean-server", "vulnerable-server", "not-a-server",
                 "instant-exit", "always-error-live", "docker-server",
                 "python-server", "ts-server", "vuln-deps"]

REAL_NAMES = ["servers", "github-mcp-server", "mcp-server-cloudflare",
              "mcp-server-airbnb", "postgres-mcp", "playwright-mcp",
              "python-sdk", "typescript-sdk", "Figma-Context-MCP",
              "tavily-mcp", "firecrawl-mcp-server", "context7"]


# ---------------------------------------------------------------------------
# counters
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.reset()

    def reset(self):
        self.files_walked = 0
        self.files_parsed = 0
        self.parses_per_file = Counter()
        self.parse_ms = 0.0
        self.file_ms = defaultdict(float)
        self.bytes_read = 0
        self.osv_requests = 0
        self.osv_cache_hits = 0
        self.osv_network_ms = 0.0
        self.osv_advisories = 0
        self.packages_resolved = 0
        self.probe_ms = defaultdict(float)
        self.probe_count = Counter()
        self.timeout_waste_ms = 0.0
        self.probes_skipped = 0
        self.install_ms = 0.0
        self.build_ms = 0.0
        self.launch_ms = 0.0
        self.handshake_ms = 0.0
        self.handshake_ok = False
        self.handshake_reason = None


S = Stats()


def peak_rss_mb() -> float:
    """Peak resident set of this process, in MB.

    psutil where available (it handles the Windows PROCESS_MEMORY_COUNTERS
    struct correctly, which a hand-rolled ctypes version did not -- the call
    returned 0.0 on this machine). Falls back to resource on POSIX.
    """
    try:
        import psutil
        info = psutil.Process().memory_info()
        return getattr(info, "peak_wset", info.rss) / 1e6
    except Exception:
        pass
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# instrumentation
# ---------------------------------------------------------------------------


def instrument():
    import mcp_guard.deps.osv as osv
    import mcp_guard.detect as detect
    import mcp_guard.dynamic as dyn
    import mcp_guard.dynamic.harness as harness
    import mcp_guard.static.ast_javascript as astjs
    import mcp_guard.static.ast_python as astpy
    import mcp_guard.static.dockerfile as dockerfile
    import mcp_guard.static.mcp_rules as mcp_rules
    import mcp_guard.static.secrets as secrets

    orig_iter = detect.iter_source_files

    def iter_wrap(root, exts):
        out = orig_iter(root, exts)
        S.files_walked += len(out)
        return out

    detect.iter_source_files = iter_wrap
    # static/__init__ imported the name directly
    import mcp_guard.static as static_pkg
    static_pkg.iter_source_files = iter_wrap

    def wrap_analyzer(mod, label):
        orig = mod.analyze_file

        def w(path, rel):
            t0 = time.perf_counter()
            try:
                return orig(path, rel)
            finally:
                dt = (time.perf_counter() - t0) * 1000
                S.parse_ms += dt
                S.file_ms[rel] += dt
                S.files_parsed += 1
                S.parses_per_file[rel] += 1
                try:
                    S.bytes_read += os.path.getsize(path)
                except OSError:
                    pass

        mod.analyze_file = w

    for mod, label in ((astpy, "py"), (astjs, "js"), (secrets, "secrets"),
                       (dockerfile, "docker")):
        wrap_analyzer(mod, label)

    for name in ("analyze_js", "analyze_py"):
        orig = getattr(mcp_rules, name)

        def mk(orig):
            def w(path, rel):
                t0 = time.perf_counter()
                try:
                    return orig(path, rel)
                finally:
                    dt = (time.perf_counter() - t0) * 1000
                    S.parse_ms += dt
                    S.file_ms[rel] += dt
                    S.files_parsed += 1
                    S.parses_per_file[rel] += 1
            return w

        setattr(mcp_rules, name, mk(orig))

    # --- OSV ---
    orig_post = osv._post

    def post_wrap(payload):
        S.osv_requests += 1
        t0 = time.perf_counter()
        try:
            return orig_post(payload)
        finally:
            S.osv_network_ms += (time.perf_counter() - t0) * 1000

    osv._post = post_wrap

    orig_get = osv.cache_get

    def cache_wrap(key):
        v = orig_get(key)
        if v is not None and key.startswith("purl:"):
            S.osv_cache_hits += 1
        return v

    osv.cache_get = cache_wrap

    # --- dynamic ---
    orig_prepare = harness.prepare

    def prepare_wrap(info, **kw):
        t0 = time.perf_counter()
        try:
            return orig_prepare(info, **kw)
        finally:
            S.install_ms += (time.perf_counter() - t0) * 1000

    harness.prepare = prepare_wrap
    dyn.prepare = prepare_wrap

    orig_launch = harness.launch_and_handshake

    async def launch_wrap(info, **kw):
        t0 = time.perf_counter()
        r = await orig_launch(info, **kw)
        S.launch_ms += (time.perf_counter() - t0) * 1000
        S.handshake_ok = r.ran
        S.handshake_reason = r.reason
        return r

    harness.launch_and_handshake = launch_wrap
    dyn.launch_and_handshake = launch_wrap

    orig_send = dyn._send

    async def send_wrap(client, probe, req, timeout):
        t0 = time.perf_counter()
        ex = await orig_send(client, probe, req, timeout)
        dt = (time.perf_counter() - t0) * 1000
        S.probe_ms[probe.id] += dt
        S.probe_count[probe.id] += 1
        if not ex.response_raw:
            S.timeout_waste_ms += dt
        return ex

    dyn._send = send_wrap


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------


def profile_target(path: str, label: str, allow_execute: bool,
                   deps: bool) -> dict:
    from mcp_guard.scan import run_scan

    S.reset()
    t0 = time.perf_counter()
    try:
        result, acquired = run_scan(path, allow_execute=allow_execute,
                                    skip_install=True, deps_enabled=deps,
                                    timeout=60)
        if acquired:
            acquired.cleanup()
    except Exception as exc:  # noqa: BLE001
        return {"label": label, "error": f"{type(exc).__name__}: {exc}"}
    total = (time.perf_counter() - t0) * 1000

    stages = {st.stage: st for st in result.statuses}
    dyn_st = stages.get("dynamic")

    return {
        "label": label,
        "total_ms": total,
        "stage_ms": {k: v.duration_s * 1000 for k, v in stages.items()},
        "stage_ran": {k: v.ran for k, v in stages.items()},
        "dynamic_reason": dyn_st.reason if dyn_st else None,
        "handshake_ok": bool(dyn_st and dyn_st.ran),
        "findings": len(result.findings),
        "server_type": result.server_info.server_type if result.server_info else "?",
        "files_walked": S.files_walked,
        "files_parsed": S.files_parsed,
        "unique_files": len(S.parses_per_file),
        "max_parses": max(S.parses_per_file.values()) if S.parses_per_file else 0,
        "parse_ms": S.parse_ms,
        "bytes_read": S.bytes_read,
        "slowest": sorted(S.file_ms.items(), key=lambda kv: -kv[1])[:10],
        "osv_requests": S.osv_requests,
        "osv_cache_hits": S.osv_cache_hits,
        "osv_network_ms": S.osv_network_ms,
        "probe_ms": dict(S.probe_ms),
        "probe_count": dict(S.probe_count),
        "timeout_waste_ms": S.timeout_waste_ms,
        "install_ms": S.install_ms,
        "launch_ms": S.launch_ms,
        "rss_mb": peak_rss_mb(),
    }


def fmt(v, nd=1):
    return f"{v:,.{nd}f}" if isinstance(v, (int, float)) else str(v)


def main() -> int:
    instrument()
    rows = []

    for name in FIXTURE_NAMES:
        p = os.path.join(FIXTURES, name)
        rows.append(profile_target(p, f"fixture/{name}", True,
                                   name == "vuln-deps"))

    real_rows = []
    for name in REAL_NAMES:
        p = os.path.join(REAL, name)
        if not os.path.isdir(p):
            continue
        real_rows.append(profile_target(p, f"real/{name}", True, False))

    out = io.StringIO()
    w = out.write

    w("# MCP Guard profile baseline\n\n")
    w(f"Generated by `make profile` on {time.strftime('%Y-%m-%d')}. "
      "Python 3.11.9, Windows, Node v24.13.0.\n\n")
    w("All times in milliseconds. `--skip-install` is used throughout, so "
      "install cost is excluded except where noted.\n\n")

    # --- stage table ---
    w("## Wall time per stage\n\n")
    w("| target | type | total | acquire | detect | static | deps | dynamic | "
      "findings | RSS MB |\n")
    w("|---|---|--:|--:|--:|--:|--:|--:|--:|--:|\n")
    for r in rows + real_rows:
        if "error" in r:
            w(f"| {r['label']} | - | ERROR: {r['error'][:40]} | | | | | | | |\n")
            continue
        s = r["stage_ms"]
        w(f"| `{r['label']}` | {r['server_type']} | {fmt(r['total_ms'])} | "
          f"{fmt(s.get('acquire', 0))} | {fmt(s.get('detect', 0))} | "
          f"{fmt(s.get('static', 0))} | {fmt(s.get('dependencies', 0))} | "
          f"{fmt(s.get('dynamic', 0))} | {r['findings']} | "
          f"{fmt(r['rss_mb'], 0)} |\n")

    # --- static table ---
    w("\n## Static analysis\n\n")
    w("| target | files walked | unique files parsed | parse calls | "
      "max parses/file | parse ms | MB read |\n")
    w("|---|--:|--:|--:|--:|--:|--:|\n")
    for r in rows + real_rows:
        if "error" in r:
            continue
        w(f"| `{r['label']}` | {r['files_walked']} | {r['unique_files']} | "
          f"{r['files_parsed']} | {r['max_parses']} | {fmt(r['parse_ms'])} | "
          f"{fmt(r['bytes_read'] / 1e6, 2)} |\n")

    w("\n`files walked` counts every path returned by a tree walk, and the "
      "walk runs four times (PY_EXT, JS_EXT, TEXT_EXT, Dockerfile). "
      "`max parses/file` above 1 means a file is parsed more than once.\n")

    # --- slowest files ---
    w("\n### 10 slowest files (largest real repo)\n\n")
    biggest = max((r for r in real_rows if "error" not in r),
                  key=lambda r: r["parse_ms"], default=None)
    if biggest:
        w(f"`{biggest['label']}` -- {fmt(biggest['parse_ms'])} ms total\n\n")
        w("| file | ms |\n|---|--:|\n")
        for f, ms in biggest["slowest"]:
            w(f"| `{f[:70]}` | {fmt(ms)} |\n")

    # --- dynamic ---
    w("\n## Dynamic analysis\n\n")
    w("| target | handshake | launch ms | dynamic ms | timeout waste ms | "
      "probe sends | reason if not run |\n")
    w("|---|:--:|--:|--:|--:|--:|---|\n")
    for r in rows + real_rows:
        if "error" in r:
            continue
        sends = sum(r["probe_count"].values())
        reason = (r["dynamic_reason"] or "")[:70]
        w(f"| `{r['label']}` | {'OK' if r['handshake_ok'] else 'no'} | "
          f"{fmt(r['launch_ms'])} | {fmt(r['stage_ms'].get('dynamic', 0))} | "
          f"{fmt(r['timeout_waste_ms'])} | {sends} | {reason} |\n")

    w("\n### Per-probe wall time (fixtures that launched)\n\n")
    w("| target | probe | sends | ms |\n|---|---|--:|--:|\n")
    for r in rows + real_rows:
        if "error" in r or not r["handshake_ok"]:
            continue
        for pid, ms in sorted(r["probe_ms"].items(), key=lambda kv: -kv[1]):
            w(f"| `{r['label']}` | {pid} | {r['probe_count'][pid]} | "
              f"{fmt(ms)} |\n")

    # --- deps ---
    w("\n## Dependencies\n\n")
    w("| target | OSV requests | cache hits | network ms | deps ms |\n")
    w("|---|--:|--:|--:|--:|\n")
    for r in rows + real_rows:
        if "error" in r or not r["stage_ran"].get("dependencies"):
            continue
        w(f"| `{r['label']}` | {r['osv_requests']} | {r['osv_cache_hits']} | "
          f"{fmt(r['osv_network_ms'])} | "
          f"{fmt(r['stage_ms'].get('dependencies', 0))} |\n")

    # --- launch success ---
    w("\n## Launch success rate (headline metric for Phase B)\n\n")
    launchable = [r for r in rows + real_rows if "error" not in r]
    ok = [r for r in launchable if r["handshake_ok"]]
    w(f"**{len(ok)} / {len(launchable)} targets reached an MCP handshake.**\n\n")
    w("| target | handshake | reason |\n|---|:--:|---|\n")
    for r in launchable:
        w(f"| `{r['label']}` | {'YES' if r['handshake_ok'] else 'no'} | "
          f"{(r['dynamic_reason'] or '-')[:95]} |\n")

    text = out.getvalue()
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
