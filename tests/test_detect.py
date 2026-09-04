"""Detection tests.

Detection decides what every later stage does, so its branches are worth
covering directly rather than only through whole-repo scans.
"""

from __future__ import annotations

import json
import os

import pytest

from mcp_guard.detect import _skip_dirs_for, detect, iter_source_files

# ---------------------------------------------------------------------------
# type detection
# ---------------------------------------------------------------------------


def test_empty_directory_is_unknown(tmp_path):
    info = detect(str(tmp_path))
    assert info.server_type == "unknown"
    assert info.is_mcp_server is False
    assert info.launch_candidates == []
    assert any("does not look like" in n for n in info.detection_notes)


def test_go_module_is_detected(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module github.com/x/y\n\nrequire (\n\tgithub.com/a/b v1.2.3\n)\n"
        "// mcp-server\n", encoding="utf-8")
    info = detect(str(tmp_path))
    assert info.server_type == "go"
    assert info.name == "github.com/x/y"
    assert info.dependencies.get("github.com/a/b") == "1.2.3"
    assert info.is_mcp_server is True


def test_go_sum_is_recorded_as_a_lockfile(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    (tmp_path / "go.sum").write_text("", encoding="utf-8")
    assert "go.sum" in detect(str(tmp_path)).lockfiles


def test_dockerfile_only_is_docker(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM node:20\n", encoding="utf-8")
    info = detect(str(tmp_path))
    assert info.server_type == "docker"
    assert info.launch_candidates == []
    assert any("statically" in n for n in info.detection_notes)


def test_requirements_only_is_python(tmp_path):
    (tmp_path / "requirements.txt").write_text("mcp==1.2.0\n", encoding="utf-8")
    info = detect(str(tmp_path))
    assert info.server_type == "python"
    assert info.dependencies.get("mcp") == "1.2.0"
    assert "requirements.txt" in info.lockfiles
    assert info.is_mcp_server is True


def test_pyproject_scripts_become_a_candidate(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "srv"\nversion = "1"\n'
        'dependencies = ["mcp>=1.0"]\n\n'
        '[project.scripts]\nsrv = "srv.cli:main"\n', encoding="utf-8")
    info = detect(str(tmp_path))
    assert info.server_type == "python"
    assert info.launch_candidates
    c = info.launch_candidates[0]
    assert c.source.startswith("pyproject [project.scripts]")
    assert c.argv == ["python", "-m", "srv.cli"]


def test_python_package_with_dunder_main_is_a_candidate(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my-srv"\nversion = "1"\n', encoding="utf-8")
    pkg = tmp_path / "my_srv"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__main__.py").write_text("print(1)", encoding="utf-8")
    info = detect(str(tmp_path))
    assert any(c.argv == ["python", "-m", "my_srv"]
               for c in info.launch_candidates)


def test_python_with_nothing_declared_says_so(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n",
                                               encoding="utf-8")
    info = detect(str(tmp_path))
    assert info.launch_candidates == []
    assert any("declares how to start it" in n for n in info.detection_notes)


def test_go_is_checked_before_package_json(tmp_path):
    """A Go repo with a package.json for tooling is still a Go target."""
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name":"tooling"}',
                                           encoding="utf-8")
    assert detect(str(tmp_path)).server_type == "go"


# ---------------------------------------------------------------------------
# manifests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("filename", ["mcp.json", ".mcp.json"])
def test_manifest_variants_are_read(tmp_path, filename):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"mcp-server": "1"}}),
        encoding="utf-8")
    (tmp_path / filename).write_text(
        json.dumps({"command": "node", "args": ["a.js"]}), encoding="utf-8")
    cands = detect(str(tmp_path)).launch_candidates
    assert any(c.argv == ["node", "a.js"] for c in cands)


def test_nested_mcp_config_is_read(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"mcp-server": "1"}}),
        encoding="utf-8")
    d = tmp_path / ".mcp"
    d.mkdir()
    (d / "config.json").write_text(
        json.dumps({"servers": {"s": {"command": "python",
                                      "args": ["-m", "s"]}}}),
        encoding="utf-8")
    cands = detect(str(tmp_path)).launch_candidates
    assert any(c.argv == ["python", "-m", "s"] for c in cands)


def test_malformed_manifest_is_ignored(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"mcp-server": "1"}}),
        encoding="utf-8")
    (tmp_path / "mcp.json").write_text("{not json", encoding="utf-8")
    detect(str(tmp_path))  # must not raise


def test_duplicate_candidates_are_collapsed(tmp_path):
    """bin and main naming the same file is one candidate, not two."""
    (tmp_path / "index.js").write_text("//", encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps(
        {"name": "x", "bin": "index.js", "main": "index.js",
         "dependencies": {"mcp-server": "1"}}), encoding="utf-8")
    cands = detect(str(tmp_path)).launch_candidates
    assert len(cands) == 1
    assert cands[0].source == "package.json bin"


def test_exports_map_supplies_a_candidate(tmp_path):
    (tmp_path / "out.js").write_text("//", encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps(
        {"name": "x", "exports": {".": {"import": "out.js"}},
         "dependencies": {"mcp-server": "1"}}), encoding="utf-8")
    cands = detect(str(tmp_path)).launch_candidates
    assert any(c.argv == ["node", "out.js"] for c in cands)


# ---------------------------------------------------------------------------
# walking
# ---------------------------------------------------------------------------


def test_skip_dirs_include_build_output_only_with_sources(tmp_path):
    (tmp_path / "src").mkdir()
    assert "dist" in _skip_dirs_for(str(tmp_path))

    other = tmp_path / "other"
    other.mkdir()
    assert "dist" not in _skip_dirs_for(str(other))


def test_iter_source_files_filters_by_extension(tmp_path):
    (tmp_path / "a.py").write_text("x=1", encoding="utf-8")
    (tmp_path / "b.txt").write_text("x", encoding="utf-8")
    got = iter_source_files(str(tmp_path), (".py",))
    assert len(got) == 1 and got[0].endswith("a.py")


def test_iter_source_files_prunes_vendored_directories(tmp_path):
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "x.py").write_text("x=1", encoding="utf-8")
    (tmp_path / "keep.py").write_text("x=1", encoding="utf-8")
    got = iter_source_files(str(tmp_path), (".py",))
    assert [os.path.basename(g) for g in got] == ["keep.py"]
