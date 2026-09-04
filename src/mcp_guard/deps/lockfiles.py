"""Lockfile parsing.

Deliberately does not shell out to npm audit / pip-audit / safety / gosec /
govulncheck. Those require the target's toolchain to be installed, they are slow,
and in the audited version three of them were unreachable dead code anyway.
Parsing the lockfile directly needs nothing but the file.

Supported: package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock,
requirements.txt (pinned), go.sum, and package.json when it pins exact versions.

Every package records the file and line where its version is pinned, so the
finding can point at the line a reader has to edit.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

ECOSYSTEM_NPM = "npm"
ECOSYSTEM_PYPI = "PyPI"
ECOSYSTEM_GO = "Go"

EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+([.\-+][A-Za-z0-9.\-]+)?$")


@dataclass(frozen=True)
class Pinned:
    name: str
    version: str
    ecosystem: str
    lockfile: str      # repo-relative
    line: int
    direct: bool = True   # named by the project itself, not pulled in
    dev: bool = False     # devDependency / test extra

    @property
    def purl(self) -> str:
        if self.ecosystem == ECOSYSTEM_NPM:
            return f"pkg:npm/{self.name}@{self.version}"
        if self.ecosystem == ECOSYSTEM_PYPI:
            return f"pkg:pypi/{self.name.lower().replace('_', '-')}@{self.version}"
        return f"pkg:golang/{self.name}@{self.version}"

    def key(self) -> Tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


def _line_of(text_lines: List[str], *needles: str) -> int:
    """First line containing every needle, 1-based; 1 if not found."""
    for i, line in enumerate(text_lines, 1):
        if all(n in line for n in needles):
            return i
    return 1


def _read(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


def parse_package_lock(path: str, rel: str) -> List[Pinned]:
    text = _read(path)
    if text is None:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    lines = text.splitlines()
    out: List[Pinned] = []

    def add(name: str, version: str) -> None:
        if not name or not version or not EXACT_VERSION.match(version):
            return
        out.append(Pinned(name, version, ECOSYSTEM_NPM, rel,
                          _line_of(lines, f'"{name}"')))

    # lockfileVersion 2/3
    for pkg_path, meta in (data.get("packages") or {}).items():
        if not pkg_path or not isinstance(meta, dict):
            continue
        name = meta.get("name") or pkg_path.split("node_modules/")[-1]
        add(name, meta.get("version", ""))

    # lockfileVersion 1
    def walk_v1(deps: dict) -> None:
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                add(name, meta.get("version", ""))
                walk_v1(meta.get("dependencies") or {})

    walk_v1(data.get("dependencies") or {})
    return out


def parse_yarn_lock(path: str, rel: str) -> List[Pinned]:
    text = _read(path)
    if text is None:
        return []
    lines = text.splitlines()
    out: List[Pinned] = []
    current: Optional[str] = None
    current_line = 1
    for i, line in enumerate(lines, 1):
        if line and not line.startswith((" ", "\t", "#")):
            head = line.strip().rstrip(":")
            first = head.split(",")[0].strip().strip('"')
            if first.startswith("@"):
                name = "@" + first[1:].split("@")[0]
            else:
                name = first.split("@")[0]
            current, current_line = name or None, i
        elif current and line.strip().startswith("version"):
            m = re.search(r'version\s+"?([^"\s]+)"?', line)
            if m and EXACT_VERSION.match(m.group(1)):
                out.append(Pinned(current, m.group(1), ECOSYSTEM_NPM, rel,
                                  current_line))
            current = None
    return out


def parse_pnpm_lock(path: str, rel: str) -> List[Pinned]:
    text = _read(path)
    if text is None:
        return []
    lines = text.splitlines()
    out: List[Pinned] = []
    # entries look like: /lodash@4.17.15: or /@scope/pkg@1.2.3:
    for i, line in enumerate(lines, 1):
        m = re.match(r"^\s{2}/?(?P<name>@?[^@\s/][^@\s]*(?:/[^@\s]+)?)@"
                     r"(?P<ver>\d[^\s:(]*)[:(]", line)
        if m and EXACT_VERSION.match(m.group("ver")):
            out.append(Pinned(m.group("name"), m.group("ver"), ECOSYSTEM_NPM,
                              rel, i))
    return out


def parse_package_json_pins(path: str, rel: str) -> List[Pinned]:
    """Exact pins in package.json when there is no lockfile.

    Only versions with no range operator are used: `"lodash": "4.17.15"` is a
    resolved version, `"^4.17.15"` is not, and guessing what a caret resolves to
    would be inventing data.
    """
    text = _read(path)
    if text is None:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    lines = text.splitlines()
    out: List[Pinned] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str) and EXACT_VERSION.match(spec.strip()):
                out.append(Pinned(name, spec.strip(), ECOSYSTEM_NPM, rel,
                                  _line_of(lines, f'"{name}"')))
    return out


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def parse_requirements(path: str, rel: str) -> List[Pinned]:
    text = _read(path)
    if text is None:
        return []
    out: List[Pinned] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^(?P<name>[A-Za-z0-9._\-]+)\s*(\[[^\]]*\])?\s*==\s*"
                     r"(?P<ver>[A-Za-z0-9._\-+!]+)", line)
        if m:
            out.append(Pinned(m.group("name"), m.group("ver"), ECOSYSTEM_PYPI,
                              rel, i))
    return out


def parse_poetry_lock(path: str, rel: str) -> List[Pinned]:
    text = _read(path)
    if text is None:
        return []
    out: List[Pinned] = []
    name: Optional[str] = None
    name_line = 1
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line == "[[package]]":
            name, name_line = None, i
        elif line.startswith("name ="):
            name = line.split("=", 1)[1].strip().strip('"')
            name_line = i
        elif line.startswith("version =") and name:
            ver = line.split("=", 1)[1].strip().strip('"')
            out.append(Pinned(name, ver, ECOSYSTEM_PYPI, rel, name_line))
            name = None
    return out


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def parse_go_sum(path: str, rel: str) -> List[Pinned]:
    text = _read(path)
    if text is None:
        return []
    out: List[Pinned] = []
    seen = set()
    for i, raw in enumerate(text.splitlines(), 1):
        parts = raw.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        version = version.removesuffix("/go.mod")
        if not version.startswith("v"):
            continue
        key = (module, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Pinned(module, version.lstrip("v"), ECOSYSTEM_GO, rel, i))
    return out


# ---------------------------------------------------------------------------


_PARSERS = [
    ("package-lock.json", parse_package_lock),
    ("yarn.lock", parse_yarn_lock),
    ("pnpm-lock.yaml", parse_pnpm_lock),
    ("poetry.lock", parse_poetry_lock),
    ("requirements.txt", parse_requirements),
    ("go.sum", parse_go_sum),
]


def _manifest_sets(root: str) -> Tuple[set, set]:
    """(direct package names, dev package names) as the project declares them.

    Read from package.json rather than inferred from lockfile nesting, because
    npm v3+ hoists everything to a flat node_modules and depth stops meaning
    anything.
    """
    direct, dev = set(), set()
    pj = os.path.join(root, "package.json")
    if os.path.exists(pj):
        data = _read_json_safe(pj)
        if isinstance(data, dict):
            for k in ("dependencies", "optionalDependencies",
                      "peerDependencies"):
                direct.update((data.get(k) or {}).keys())
            dev.update((data.get("devDependencies") or {}).keys())
            direct.update(dev)
    return direct, dev


def _read_json_safe(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def collect(root: str) -> Tuple[List[Pinned], List[str]]:
    """Return (pinned packages, names of lockfiles actually parsed)."""
    found: List[Pinned] = []
    used: List[str] = []
    have_npm_lock = False

    for fname, parser in _PARSERS:
        path = os.path.join(root, fname)
        if os.path.exists(path):
            pkgs = parser(path, fname)
            if pkgs:
                found.extend(pkgs)
                used.append(fname)
                if fname in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                    have_npm_lock = True

    if not have_npm_lock:
        pj = os.path.join(root, "package.json")
        if os.path.exists(pj):
            pkgs = parse_package_json_pins(pj, "package.json")
            if pkgs:
                found.extend(pkgs)
                used.append("package.json (exact pins only)")

    direct_names, dev_names = _manifest_sets(root)

    # de-duplicate on (ecosystem, name, version), keeping the first location
    seen = set()
    unique: List[Pinned] = []
    for p in found:
        if p.key() in seen:
            continue
        seen.add(p.key())
        if p.ecosystem == ECOSYSTEM_NPM and direct_names:
            p = Pinned(p.name, p.version, p.ecosystem, p.lockfile, p.line,
                       direct=p.name in direct_names, dev=p.name in dev_names)
        unique.append(p)
    return unique, used
