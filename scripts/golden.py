"""Generate the golden finding set.

The golden set is the correctness freeze for the efficiency work: it records
what each fixture produces, stripped of everything that legitimately varies
between runs (ids, timestamps, durations, canary uuids, absolute paths).

Regenerate with `make golden`. Any regeneration must be justified finding by
finding in the commit that does it.
"""

from __future__ import annotations

import json
import os
import re
import sys

# Repo root is one level up from scripts/.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from mcp_guard.scan import run_scan  # noqa: E402

FIXTURES = os.path.join(REPO, "tests", "fixtures")
GOLDEN = os.path.join(REPO, "tests", "golden")

# Fixtures that need the network (OSV) are recorded separately so an offline
# run can still verify the rest.
NETWORK_FIXTURES = {"vuln-deps"}

ALL = ["clean-server", "vulnerable-server", "not-a-server", "instant-exit",
       "always-error-live", "docker-server", "python-server", "ts-server",
       "vuln-deps"]

_UUID = re.compile(r"[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                   r"[0-9a-f]{4}-[0-9a-f]{12}")
_TMPPATH = re.compile(r"[A-Za-z]:[\\/][^\s\"']*|/tmp/[^\s\"']*|/var/folders/[^\s\"']*")


def normalise(text: str) -> str:
    """Strip canary uuids and absolute paths so the record is stable."""
    text = _UUID.sub("<uuid>", text)
    text = _TMPPATH.sub("<path>", text)
    return text


def finding_record(f) -> dict:
    ev = f.evidence
    rec = {
        "rule_id": f.rule_id,
        "cvss_vector": f.cvss_vector,
        "cvss_score": f.cvss_score,
        "severity": f.severity.value,
        "evidence_kind": ev.kind,
    }
    if ev.kind == "static":
        rec["file"] = ev.file.replace("\\", "/")
        rec["line"] = ev.line
    elif ev.kind == "dynamic":
        rec["oracle_id"] = ev.oracle_id
    elif ev.kind == "dependency":
        rec["package"] = ev.package
        rec["advisory_id"] = ev.advisory_id
        rec["installed_version"] = ev.installed_version
    return rec


_FIXTURE_CACHE: dict = {}


def scan_fixture(name: str) -> dict:
    """Memoised: the golden suite asserts on the same scan three times."""
    if name not in _FIXTURE_CACHE:
        _FIXTURE_CACHE[name] = _scan_fixture_uncached(name)
    return _FIXTURE_CACHE[name]


def _scan_fixture_uncached(name: str) -> dict:
    path = os.path.join(FIXTURES, name)
    deps = name in NETWORK_FIXTURES
    result, acquired = run_scan(
        path,
        allow_execute=True,
        skip_install=True,
        deps_enabled=deps,
        static_enabled=True,
        use_cache=False,
    )
    if acquired:
        acquired.cleanup()

    records = sorted(
        (finding_record(f) for f in result.findings),
        key=lambda r: (r["rule_id"], r.get("file", ""), r.get("line", 0),
                       r.get("oracle_id", ""), r.get("advisory_id", "")),
    )
    stages = {}
    for st in result.statuses:
        stages[st.stage] = {
            "ran": st.ran,
            # The reason string is part of the contract -- it is what a user
            # reads when a stage produces nothing -- but it carries paths.
            "reason": normalise(st.reason) if st.reason else None,
        }
    return {
        "fixture": name,
        "server_type": result.server_info.server_type if result.server_info else None,
        "is_mcp_server": (result.server_info.is_mcp_server
                          if result.server_info else None),
        "stages": stages,
        "finding_count": len(records),
        "findings": records,
    }


def main(names=None) -> int:
    os.makedirs(GOLDEN, exist_ok=True)
    for name in (names or ALL):
        data = scan_fixture(name)
        out = os.path.join(GOLDEN, f"{name}.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"{name:<20} {data['finding_count']:>3} findings -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or None))
