"""Shared fixtures.

Every test asserts. The suite this replaces had five test functions, zero
assert statements, and one test that was failing silently while pytest
reported "5 passed".
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
REPO = os.path.dirname(HERE)

# mcp_guard is NOT put on sys.path here. With a src layout the tests import
# whatever is installed, so a broken package cannot be masked by the working
# tree sitting next to the tests. Install with `pip install -e ".[dev]"`.
#
# scripts/ is a different matter: it holds dev tooling that the suite drives
# (the golden set generator), and it is deliberately not part of the shipped
# package, so it needs an explicit path entry.
sys.path.insert(0, os.path.join(REPO, "scripts"))


def fixture_path(name: str) -> str:
    p = os.path.join(FIXTURES, name)
    assert os.path.isdir(p), f"missing fixture {name!r} at {p}"
    return p


def have_node() -> bool:
    return shutil.which("node") is not None


def have_network() -> bool:
    if os.environ.get("MCPGUARD_NO_NETWORK"):
        return False
    try:
        import requests
        requests.get("https://api.osv.dev/v1/vulns/GHSA-vh95-rmgr-6w4m", timeout=8)
        return True
    except Exception:
        return False


needs_node = pytest.mark.skipif(
    not have_node(), reason="node is not installed; dynamic tests need it")

needs_network = pytest.mark.skipif(
    not have_network(), reason="OSV API unreachable; dependency tests need it")


@pytest.fixture(scope="session")
def repo_root() -> str:
    return REPO


# Session-scoped scan cache.
#
# The suite asserts on the same handful of fixtures from many angles, and the
# baseline re-ran a full scan -- including launching a Node process -- for every
# one. Scans are pure with respect to their arguments, so the result is memoised
# on (fixture, arguments). Tests that need a genuinely fresh scan (cache
# behaviour, determinism) call run_scan_fresh().
_SCAN_CACHE: dict = {}


def _key(name: str, kwargs: dict):
    return (name, tuple(sorted(kwargs.items())))


def run_scan_fresh(name: str, **kwargs):
    """Always perform a real scan. Use when the test is about scanning itself."""
    from mcp_guard.scan import run_scan

    kwargs.setdefault("deps_enabled", False)
    # The static result cache would otherwise short-circuit the analyzers, so
    # the suite would assert on cached JSON instead of exercising the rules.
    kwargs.setdefault("use_cache", False)
    result, acquired = run_scan(fixture_path(name), **kwargs)
    if acquired is not None:
        acquired.cleanup()
    return result


def run_scan_on(name: str, **kwargs):
    """Scan a fixture and return the ScanResult, memoised for the session."""
    kwargs.setdefault("deps_enabled", False)
    kwargs.setdefault("use_cache", False)
    k = _key(name, kwargs)
    if k not in _SCAN_CACHE:
        _SCAN_CACHE[k] = run_scan_fresh(name, **kwargs)
    return _SCAN_CACHE[k]


def rule_ids(result) -> set:
    return {f.rule_id for f in result.findings}


def stage(result, name):
    st = result.status(name)
    assert st is not None, f"no status recorded for stage {name!r}"
    return st
