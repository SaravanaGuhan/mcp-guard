"""Unit tests for lockfile parsing and OSV range selection.

These run offline. They cover the parsing logic that the fixture acceptance
test exercises only for npm.
"""

from __future__ import annotations

import json

from mcp_guard.deps import lockfiles, osv


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


def test_package_lock_v3_is_parsed(tmp_path):
    data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/@scope/pkg": {"version": "2.1.0"},
        },
    }
    p = write(tmp_path, "package-lock.json", json.dumps(data, indent=1))
    out = lockfiles.parse_package_lock(p, "package-lock.json")
    got = {(x.name, x.version) for x in out}
    assert ("lodash", "4.17.15") in got
    assert ("@scope/pkg", "2.1.0") in got
    for x in out:
        assert x.ecosystem == lockfiles.ECOSYSTEM_NPM
        assert x.line >= 1


def test_package_lock_v1_nested_dependencies(tmp_path):
    data = {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0",
                  "dependencies": {"b": {"version": "2.0.0"}}},
        },
    }
    p = write(tmp_path, "package-lock.json", json.dumps(data, indent=1))
    got = {(x.name, x.version)
           for x in lockfiles.parse_package_lock(p, "package-lock.json")}
    assert ("a", "1.0.0") in got and ("b", "2.0.0") in got


def test_yarn_lock_is_parsed(tmp_path):
    text = (
        '# yarn lockfile v1\n\n'
        'lodash@^4.17.0:\n'
        '  version "4.17.15"\n'
        '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz"\n\n'
        '"@scope/pkg@^2.0.0":\n'
        '  version "2.1.0"\n'
    )
    p = write(tmp_path, "yarn.lock", text)
    got = {(x.name, x.version) for x in lockfiles.parse_yarn_lock(p, "yarn.lock")}
    assert ("lodash", "4.17.15") in got
    assert ("@scope/pkg", "2.1.0") in got


def test_package_json_uses_exact_pins_and_ignores_ranges(tmp_path):
    data = {"dependencies": {"pinned": "1.2.3", "ranged": "^1.2.3",
                             "tilde": "~1.0.0", "star": "*"}}
    p = write(tmp_path, "package.json", json.dumps(data, indent=1))
    got = {x.name for x in lockfiles.parse_package_json_pins(p, "package.json")}
    assert got == {"pinned"}, got


# ---------------------------------------------------------------------------
# Python / Go
# ---------------------------------------------------------------------------


def test_requirements_only_takes_double_equals(tmp_path):
    text = ("flask==2.0.1\n"
            "requests>=2.0  # a range, not a pin\n"
            "# comment\n"
            "-e .\n"
            "django[argon2]==4.2.1\n")
    p = write(tmp_path, "requirements.txt", text)
    got = {(x.name, x.version)
           for x in lockfiles.parse_requirements(p, "requirements.txt")}
    assert ("flask", "2.0.1") in got
    assert ("django", "4.2.1") in got
    assert not any(n == "requests" for n, _ in got)


def test_poetry_lock_is_parsed(tmp_path):
    text = ('[[package]]\nname = "flask"\nversion = "2.0.1"\n\n'
            '[[package]]\nname = "jinja2"\nversion = "3.1.2"\n')
    p = write(tmp_path, "poetry.lock", text)
    got = {(x.name, x.version)
           for x in lockfiles.parse_poetry_lock(p, "poetry.lock")}
    assert got == {("flask", "2.0.1"), ("jinja2", "3.1.2")}


def test_go_sum_dedupes_and_strips_go_mod_suffix(tmp_path):
    text = ("github.com/pkg/errors v0.9.1 h1:abc=\n"
            "github.com/pkg/errors v0.9.1/go.mod h1:def=\n")
    p = write(tmp_path, "go.sum", text)
    out = lockfiles.parse_go_sum(p, "go.sum")
    assert len(out) == 1
    assert out[0].name == "github.com/pkg/errors"
    assert out[0].version == "0.9.1"


def test_purl_shapes():
    npm = lockfiles.Pinned("lodash", "4.17.15", lockfiles.ECOSYSTEM_NPM, "l", 1)
    py = lockfiles.Pinned("Flask_Login", "0.6", lockfiles.ECOSYSTEM_PYPI, "l", 1)
    go = lockfiles.Pinned("github.com/x/y", "1.0.0", lockfiles.ECOSYSTEM_GO, "l", 1)
    assert npm.purl == "pkg:npm/lodash@4.17.15"
    assert py.purl == "pkg:pypi/flask-login@0.6"
    assert go.purl == "pkg:golang/github.com/x/y@1.0.0"


def test_collect_prefers_lockfile_over_package_json(tmp_path):
    write(tmp_path, "package.json",
          json.dumps({"dependencies": {"lodash": "4.17.15"}}))
    write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/lodash": {"version": "4.17.20"}},
    }))
    pinned, used = lockfiles.collect(str(tmp_path))
    versions = {p.version for p in pinned if p.name == "lodash"}
    assert versions == {"4.17.20"}
    assert "package-lock.json" in used
    assert not any("package.json (" in u for u in used)


# ---------------------------------------------------------------------------
# OSV range selection -- the evidence-accuracy bug found in Phase 5
# ---------------------------------------------------------------------------


VULN = {
    "affected": [{
        "package": {"name": "axios"},
        "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "0.21.1"},
            {"introduced": "1.0.0"}, {"fixed": "1.16.0"},
        ]}],
    }]
}


def test_affected_range_picks_the_range_containing_the_installed_version():
    assert osv._affected_range(VULN, "axios", "0.21.0") == ">=0 <0.21.1"
    assert osv._affected_range(VULN, "axios", "1.5.0") == ">=1.0.0 <1.16.0"


def test_affected_range_never_reports_a_range_excluding_the_version():
    got = osv._affected_range(VULN, "axios", "0.21.0")
    assert ">=1.0.0" not in got


def test_affected_range_falls_back_and_says_so_when_nothing_matches():
    got = osv._affected_range(VULN, "axios", "99.0.0")
    assert "published ranges" in got


def test_in_range_boundaries():
    assert osv._in_range("0.21.0", "0", "0.21.1") is True
    assert osv._in_range("0.21.1", "0", "0.21.1") is False   # fixed is exclusive
    assert osv._in_range("1.0.0", "1.0.0", "2.0.0") is True  # introduced inclusive
    assert osv._in_range("0.9.0", "1.0.0", "2.0.0") is False


def test_version_parts_compare_numerically_not_lexically():
    assert osv._vparts("4.17.9") < osv._vparts("4.17.15")
    assert osv._vparts("1.10.0") > osv._vparts("1.9.0")


def test_severity_is_read_as_published_not_recomputed():
    vuln = {
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "critical"},
    }
    qual, vec = osv._severity(vuln)
    assert qual == "CRITICAL"
    assert vec.startswith("CVSS:3.1/")


def test_cache_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("MCPGUARD_CACHE", str(tmp_path))
    osv.cache_put("purl:test", [{"a": 1}])
    assert osv.cache_get("purl:test") == [{"a": 1}]
    assert osv.cache_get("purl:missing") is None
