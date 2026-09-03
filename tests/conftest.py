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

sys.path.insert(0, REPO)


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


def run_scan_on(name: str, **kwargs):
    """Scan a fixture and return the ScanResult."""
    from mcp_guard.scan import run_scan

    kwargs.setdefault("deps_enabled", False)
    result, acquired = run_scan(fixture_path(name), **kwargs)
    if acquired is not None:
        acquired.cleanup()
    return result


def rule_ids(result) -> set:
    return {f.rule_id for f in result.findings}


def stage(result, name):
    st = result.status(name)
    assert st is not None, f"no status recorded for stage {name!r}"
    return st
