"""Server-type detection and entrypoint derivation.

Entrypoints come from the target's own metadata and nothing else. The original
scanner carried a global list of guessed filenames plus a hardcoded third-party
npm package; both are gone. If a target does not say how to start itself, we
report that we could not derive a launch command rather than guessing, because
a guessed launch that fails is what produced fabricated "dynamic" findings in
the first place.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .models import ServerInfo

MCP_HINTS = (
    "@modelcontextprotocol/sdk",
    "modelcontextprotocol",
    "mcp.server",
    "mcp-server",
    "fastmcp",
    "mcp[cli]",
)

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist-info",
    ".mypy_cache", ".pytest_cache", ".tox", ".idea", ".vscode",
}


def iter_source_files(root: str, exts: Tuple[str, ...]) -> List[str]:
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(exts):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _exists(root: str, *names: str) -> Optional[str]:
    for n in names:
        p = os.path.join(root, n)
        if os.path.exists(p):
            return p
    return None


# ---------------------------------------------------------------------------
# Node.js
# ---------------------------------------------------------------------------


def _detect_nodejs(root: str, pkg_path: str) -> ServerInfo:
    pkg = _read_json(pkg_path) or {}
    deps: Dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps.update(pkg.get(key) or {})

    info = ServerInfo(
        root=root,
        server_type="nodejs",
        name=pkg.get("name"),
        version=pkg.get("version"),
        manifest_files=["package.json"],
        dependencies=deps,
        install_argv=None,
        transport="stdio",
    )

    scripts = pkg.get("scripts") or {}

    # Entrypoint, in the order the plan specifies: bin -> main -> scripts.start.
    entry: Optional[str] = None
    bin_field = pkg.get("bin")
    if isinstance(bin_field, str):
        entry = bin_field
    elif isinstance(bin_field, dict) and bin_field:
        entry = next(iter(bin_field.values()))
    if entry is None and isinstance(pkg.get("main"), str):
        entry = pkg["main"]

    if entry:
        info.entrypoint = entry
        abs_entry = os.path.join(root, entry)
        if os.path.exists(abs_entry):
            info.launch_argv = ["node", entry]
        elif "build" in scripts:
            # main is declared but not built yet
            info.build_argv = ["npm", "run", "build"]
            info.launch_argv = ["node", entry]
            info.detection_notes.append(
                f"entrypoint {entry!r} absent; build script present"
            )
        else:
            info.detection_notes.append(
                f"declared entrypoint {entry!r} does not exist and no build script"
            )
            info.launch_argv = None
    elif "start" in scripts:
        info.entrypoint = f"npm:start ({scripts['start']})"
        info.launch_argv = ["npm", "start"]
    else:
        info.detection_notes.append(
            "package.json declares no bin, main or start script"
        )

    for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        if os.path.exists(os.path.join(root, lf)):
            info.lockfiles.append(lf)

    blob = json.dumps(pkg).lower()
    info.is_mcp_server = any(h in blob for h in MCP_HINTS)
    return info


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _detect_python(root: str) -> ServerInfo:
    info = ServerInfo(root=root, server_type="python", transport="stdio")
    deps: Dict[str, str] = {}
    blob = ""

    pyproject = _exists(root, "pyproject.toml")
    if pyproject:
        info.manifest_files.append("pyproject.toml")
        try:
            try:
                import tomllib  # py311+
            except ModuleNotFoundError:  # pragma: no cover
                import tomli as tomllib  # type: ignore
            with open(pyproject, "rb") as fh:
                data = tomllib.load(fh)
            project = data.get("project") or {}
            info.name = project.get("name")
            info.version = project.get("version")
            for spec in project.get("dependencies") or []:
                m = re.match(r"^\s*([A-Za-z0-9._\-\[\]]+)\s*(.*)$", spec)
                if m:
                    deps[m.group(1)] = m.group(2).strip() or "*"
            scripts = project.get("scripts") or {}
            if scripts:
                target = next(iter(scripts.values()))
                module = target.split(":")[0]
                info.entrypoint = f"{next(iter(scripts))} -> {target}"
                info.launch_argv = ["python", "-m", module]
            blob = json.dumps(data, default=str).lower()
        except Exception as exc:  # noqa: BLE001
            info.detection_notes.append(f"pyproject.toml unparsed: {exc}")

    req = _exists(root, "requirements.txt")
    if req:
        info.manifest_files.append("requirements.txt")
        info.lockfiles.append("requirements.txt")
        try:
            with open(req, encoding="utf-8") as fh:
                text = fh.read()
            blob += text.lower()
            for line in text.splitlines():
                line = line.split("#")[0].strip()
                m = re.match(r"^([A-Za-z0-9._\-\[\]]+)\s*(==|>=|~=)?\s*([^\s;]*)", line)
                if m and m.group(1):
                    deps[m.group(1)] = m.group(3) or "*"
        except Exception:
            pass

    if os.path.exists(os.path.join(root, "poetry.lock")):
        info.lockfiles.append("poetry.lock")

    if info.launch_argv is None:
        # module entry: a package dir with __main__.py, or server.py/main.py that
        # the project itself names. No global guess list.
        for cand in ("__main__.py",):
            hit = _exists(root, cand)
            if hit:
                info.entrypoint = cand
                info.launch_argv = ["python", cand]
                break
        else:
            if info.name:
                pkgdir = os.path.join(root, info.name.replace("-", "_"))
                if os.path.isdir(pkgdir) and os.path.exists(
                    os.path.join(pkgdir, "__main__.py")
                ):
                    mod = info.name.replace("-", "_")
                    info.entrypoint = f"{mod}/__main__.py"
                    info.launch_argv = ["python", "-m", mod]

    if info.launch_argv is None:
        info.detection_notes.append(
            "no [project.scripts] entry and no importable __main__ module"
        )

    info.dependencies = deps
    info.is_mcp_server = any(h in blob for h in MCP_HINTS)
    return info


# ---------------------------------------------------------------------------
# Go / Docker / generic
# ---------------------------------------------------------------------------


def _detect_go(root: str) -> ServerInfo:
    info = ServerInfo(root=root, server_type="go", transport="stdio",
                      manifest_files=["go.mod"])
    if os.path.exists(os.path.join(root, "go.sum")):
        info.lockfiles.append("go.sum")
    try:
        with open(os.path.join(root, "go.mod"), encoding="utf-8") as fh:
            text = fh.read()
        m = re.search(r"^module\s+(\S+)", text, re.M)
        if m:
            info.name = m.group(1)
        info.is_mcp_server = any(h in text.lower() for h in MCP_HINTS)
        for dm in re.finditer(r"^\s*([\w./\-]+)\s+v(\S+)", text, re.M):
            info.dependencies[dm.group(1)] = dm.group(2)
    except Exception as exc:  # noqa: BLE001
        info.detection_notes.append(f"go.mod unparsed: {exc}")
    info.build_argv = ["go", "build", "-o", "mcpguard-target", "."]
    info.launch_argv = [os.path.join(".", "mcpguard-target")]
    return info


def _detect_docker(root: str, dockerfile: str) -> ServerInfo:
    info = ServerInfo(root=root, server_type="docker",
                      manifest_files=[os.path.basename(dockerfile)])
    info.detection_notes.append(
        "docker targets are analysed statically; MCP Guard does not build or run "
        "target images"
    )
    return info


def detect(root: str) -> ServerInfo:
    """Classify the target. Order is most-specific first."""
    pkg = _exists(root, "package.json")
    if os.path.exists(os.path.join(root, "go.mod")):
        return _detect_go(root)
    if pkg:
        return _detect_nodejs(root, pkg)
    if _exists(root, "pyproject.toml", "setup.py", "requirements.txt"):
        return _detect_python(root)
    df = _exists(root, "Dockerfile", "dockerfile")
    if df:
        return _detect_docker(root, df)

    info = ServerInfo(root=root, server_type="unknown")
    info.detection_notes.append(
        "no package.json, pyproject.toml, requirements.txt, go.mod or Dockerfile "
        "found; target does not look like an MCP server"
    )
    return info
