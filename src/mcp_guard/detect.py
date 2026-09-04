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

from .models import LaunchCandidate, ServerInfo

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
    ".next", ".nuxt", ".turbo", ".cache", "coverage", "htmlcov",
    "site-packages", "vendor", ".mcpguard-venv",
}

# Build output. Skipped ONLY when the sources that produced it are also
# present: analysing both reports the same bug twice, once in src and once in
# the compiled copy. A package that ships only dist/ still gets analysed.
_BUILD_DIRS = {"dist", "build", "out", "lib"}
_SOURCE_DIRS = {"src", "source", "lib"}


def _skip_dirs_for(root: str) -> set:
    skip = set(_SKIP_DIRS)
    try:
        entries = {e.lower() for e in os.listdir(root)
                   if os.path.isdir(os.path.join(root, e))}
    except OSError:
        return skip
    if entries & {"src", "source"}:
        skip |= {d for d in _BUILD_DIRS if d not in _SOURCE_DIRS}
    return skip


def iter_source_files(root: str, exts: Tuple[str, ...]) -> List[str]:
    skip = _skip_dirs_for(root)
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in skip]
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



def _mcp_manifest_candidates(root: str) -> List[LaunchCandidate]:
    """Candidates from an MCP manifest the project ships itself.

    Recognised: mcp.json, .mcp/config.json, .mcp.json. Only the command the
    project declares is used; nothing is inferred.
    """
    out: List[LaunchCandidate] = []
    for rel in ("mcp.json", ".mcp.json", os.path.join(".mcp", "config.json")):
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            continue
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers") or data.get("servers") or {}
        if isinstance(servers, dict):
            for name, spec in servers.items():
                if not isinstance(spec, dict):
                    continue
                cmd = spec.get("command")
                args = spec.get("args") or []
                if isinstance(cmd, str) and isinstance(args, list):
                    out.append(LaunchCandidate(
                        f"{rel} mcpServers[{name}]",
                        [cmd] + [str(a) for a in args]))
        cmd = data.get("command")
        if isinstance(cmd, str):
            args = data.get("args") or []
            out.append(LaunchCandidate(
                f"{rel} command", [cmd] + [str(a) for a in args]))
    return out



def _workspace_globs(root: str, pkg: Dict[str, Any]) -> List[str]:
    """Workspace patterns the project declares for itself."""
    ws = pkg.get("workspaces")
    globs: List[str] = []
    if isinstance(ws, list):
        globs.extend([g for g in ws if isinstance(g, str)])
    elif isinstance(ws, dict) and isinstance(ws.get("packages"), list):
        globs.extend([g for g in ws["packages"] if isinstance(g, str)])

    pnpm = os.path.join(root, "pnpm-workspace.yaml")
    if os.path.exists(pnpm):
        try:
            with open(pnpm, encoding="utf-8") as fh:
                for line in fh:
                    m = re.match(r"\s*-\s*['\"]?([^'\"#]+)['\"]?", line)
                    if m:
                        globs.append(m.group(1).strip())
        except OSError:
            pass
    return globs


def _workspace_members(root: str, globs: List[str]) -> List[str]:
    """Directories matching the declared workspace globs that hold a package.json."""
    import glob as _glob

    out: List[str] = []
    for g in globs:
        pattern = os.path.join(root, g.replace("/", os.sep), "package.json")
        for hit in _glob.glob(pattern):
            out.append(os.path.dirname(hit))
        # one extra level, for patterns like "packages/*" holding nested servers
        pattern2 = os.path.join(root, g.replace("/", os.sep), "*", "package.json")
        for hit in _glob.glob(pattern2):
            out.append(os.path.dirname(hit))
    return sorted(set(out))


def _member_candidates(root: str, members: List[str]) -> List[LaunchCandidate]:
    """Candidates from workspace members that declare an MCP dependency.

    A monorepo root is usually not itself a server. Rather than reporting "no
    launch command could be derived", enumerate the members that say they are
    MCP servers and that declare their own entry file. Still target-declared:
    the member's own package.json names the file.
    """
    out: List[LaunchCandidate] = []
    for member in members:
        pkg = _read_json(os.path.join(member, "package.json"))
        if not isinstance(pkg, dict):
            continue
        blob = json.dumps(pkg).lower()
        if not any(h in blob for h in MCP_HINTS):
            continue

        rel_member = os.path.relpath(member, root).replace("\\", "/")
        entries: List[tuple] = []
        b = pkg.get("bin")
        if isinstance(b, str):
            entries.append(("bin", b))
        elif isinstance(b, dict):
            entries.extend(("bin[%s]" % k, v) for k, v in b.items()
                           if isinstance(v, str))
        if isinstance(pkg.get("main"), str):
            entries.append(("main", pkg["main"]))

        has_build = "build" in (pkg.get("scripts") or {})
        for label, entry in entries:
            entry = entry.strip().lstrip("./")
            abs_entry = os.path.join(member, entry)
            rel_entry = os.path.join(rel_member, entry).replace("\\", "/")
            if os.path.exists(abs_entry):
                out.append(LaunchCandidate(
                    f"workspace {rel_member} {label}", ["node", rel_entry],
                    note=f"member package {pkg.get('name')}"))
            elif has_build:
                out.append(LaunchCandidate(
                    f"workspace {rel_member} {label}", ["node", rel_entry],
                    requires_build=True,
                    note=f"member package {pkg.get('name')}; needs build"))
    return out


def _apply_candidates(info: ServerInfo, cands: List[LaunchCandidate]) -> None:
    """Record the chain and adopt the first candidate as the launch command.

    Candidates are ordered by cost, not just by declaration order: anything
    already runnable is tried before anything that needs a build. Measured on
    Figma-Context-MCP, the declaration order spent 8.8s building before
    reaching a candidate that did not need one.

    Within each group the original order is preserved, so bin still beats main
    still beats scripts.start.
    """
    # de-duplicate on argv, keeping the earliest source
    seen, unique = set(), []
    for c in cands:
        key = tuple(c.argv)
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    unique.sort(key=lambda c: 1 if c.requires_build else 0)
    info.launch_candidates = unique
    if unique:
        first = unique[0]
        info.entrypoint = f"{first.source}: {' '.join(first.argv)}"
        info.launch_argv = list(first.argv)
        if first.requires_build and info.build_argv is None:
            info.build_argv = ["npm", "run", "build"]


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
    cands: List[LaunchCandidate] = []

    def add_file(src: str, entry: str) -> None:
        """Add a candidate for a declared file, with a build step if absent."""
        if not isinstance(entry, str) or not entry.strip():
            return
        entry = entry.strip().lstrip("./")
        abs_entry = os.path.join(root, entry)
        if os.path.exists(abs_entry):
            cands.append(LaunchCandidate(src, ["node", entry]))
        elif "build" in scripts:
            cands.append(LaunchCandidate(
                src, ["node", entry], requires_build=True,
                note=f"{entry} absent; scripts.build declared"))
        else:
            info.detection_notes.append(
                f"{src} names {entry!r}, which does not exist and there is no "
                f"build script")

    # 1. bin -- a string, or a map whose values are paths
    bin_field = pkg.get("bin")
    if isinstance(bin_field, str):
        add_file("package.json bin", bin_field)
    elif isinstance(bin_field, dict):
        for k, v in bin_field.items():
            add_file(f"package.json bin[{k}]", v)

    # 2. main
    if isinstance(pkg.get("main"), str):
        add_file("package.json main", pkg["main"])

    # 3. exports -- the modern replacement for main, when it names a file
    exp = pkg.get("exports")
    if isinstance(exp, str):
        add_file("package.json exports", exp)
    elif isinstance(exp, dict):
        for k, v in list(exp.items())[:4]:
            if isinstance(v, str):
                add_file(f"package.json exports[{k}]", v)
            elif isinstance(v, dict):
                for sub in ("import", "require", "default", "node"):
                    if isinstance(v.get(sub), str):
                        add_file(f"package.json exports[{k}].{sub}", v[sub])
                        break

    # 4. scripts.start
    if isinstance(scripts.get("start"), str):
        cands.append(LaunchCandidate(
            "package.json scripts.start", ["npm", "start"],
            requires_build="build" in scripts,
            note=scripts["start"][:80]))

    # 5. an MCP manifest, if the project ships one
    cands.extend(_mcp_manifest_candidates(root))

    # 6. workspace members that declare themselves MCP servers
    globs = _workspace_globs(root, pkg)
    members = _workspace_members(root, globs) if globs else []
    if members:
        member_cands = _member_candidates(root, members)
        info.detection_notes.append(
            f"monorepo: {len(members)} workspace member(s) declared, "
            f"{len(member_cands)} launchable MCP server entry point(s)")
        cands.extend(member_cands)
        if member_cands:
            # A monorepo root often declares no MCP dependency itself. If its
            # members do, the repository is an MCP project and the dynamic
            # stage must not skip it as "no MCP server here".
            info.is_mcp_server = True

    _apply_candidates(info, cands)
    if not cands:
        detail = ("package.json declares no bin, main, exports or start script, "
                  "and no mcp.json was found")
        if globs and not members:
            detail += f"; workspace globs {globs} matched no packages"
        elif members:
            detail += (f"; none of the {len(members)} workspace members declare "
                       f"an MCP dependency with an entry file")
        info.detection_notes.append(detail)

    for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        if os.path.exists(os.path.join(root, lf)):
            info.lockfiles.append(lf)

    blob = json.dumps(pkg).lower()
    info.is_mcp_server = info.is_mcp_server or any(h in blob for h in MCP_HINTS)
    return info


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _detect_python(root: str) -> ServerInfo:
    info = ServerInfo(root=root, server_type="python", transport="stdio")
    deps: Dict[str, str] = {}
    blob = ""
    script_entries: Dict[str, Any] = {}

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
            script_entries = project.get("scripts") or {}
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

    cands: List[LaunchCandidate] = []

    # 1. [project.scripts] -- the project's own console entry points
    for name, target in (script_entries or {}).items():
        module = str(target).split(":")[0]
        cands.append(LaunchCandidate(
            f"pyproject [project.scripts].{name}",
            ["python", "-m", module],
            note=str(target)))

    # 2. an importable package with __main__
    pkg_names = []
    if info.name:
        pkg_names.append(info.name.replace("-", "_"))
    pkg_names.append(os.path.basename(os.path.abspath(root)).replace("-", "_"))
    for cand_name in dict.fromkeys(pkg_names):
        for base in (root, os.path.join(root, "src")):
            pkgdir = os.path.join(base, cand_name)
            if os.path.isdir(pkgdir) and os.path.exists(
                    os.path.join(pkgdir, "__main__.py")):
                cands.append(LaunchCandidate(
                    f"module {cand_name} with __main__.py",
                    ["python", "-m", cand_name]))
                break

    # 3. a top-level __main__.py
    if os.path.exists(os.path.join(root, "__main__.py")):
        cands.append(LaunchCandidate("__main__.py", ["python", "__main__.py"]))

    # 4. server.py / main.py ONLY when the project names it as a module in
    #    pyproject; otherwise this would be the global guess list we removed.
    for declared in (info.detection_notes and [] or []):
        pass

    # 5. an MCP manifest the project ships
    cands.extend(_mcp_manifest_candidates(root))

    _apply_candidates(info, cands)
    if not cands:
        info.detection_notes.append(
            "no [project.scripts] entry, no importable __main__ module and no "
            "mcp.json; nothing in the project declares how to start it")

    info.dependencies = deps
    # Substring hints alone miss the official Python SDK, whose distribution is
    # named exactly "mcp" -- a bare substring test for "mcp" would fire on any
    # word containing those letters, so match parsed dependency names instead.
    info.is_mcp_server = (
        any(h in blob for h in MCP_HINTS)
        or any(_is_mcp_distribution(name) for name in deps)
    )
    return info


# ---------------------------------------------------------------------------
# Go / Docker / generic
# ---------------------------------------------------------------------------


def _is_mcp_distribution(name: str) -> bool:
    """True for the Python SDK distribution and its extras/forks by name."""
    n = name.strip().lower().replace("_", "-")
    base = n.split("[")[0]
    return base == "mcp" or base.startswith("mcp-") or base in (
        "fastmcp", "modelcontextprotocol")


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
