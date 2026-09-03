"""Static analysis driver.

Reads files. Executes nothing. Every finding carries the literal source text at
the position it reports.

Phase C shape, measured against docs/profile-baseline.md:

  * ONE tree walk builds the file inventory, which is then classified and
    dispatched. The baseline walked the tree four times (PY_EXT, JS_EXT,
    TEXT_EXT, Dockerfile).
  * ONE parse per file. The parsed tree is handed to every rule that needs it.
    The baseline parsed each file three times, because ast_python /
    ast_javascript, mcp_rules and secrets each opened and parsed independently
    (python-sdk: 899 unique files, 2,575 parse calls).
  * Vendored and generated content is skipped, and what was skipped is reported
    in stage artifacts rather than silently dropped.
  * Results are cached by (file sha256, rule set version), so rescanning an
    unchanged tree reuses them.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..detect import _skip_dirs_for
from ..models import Finding, ServerInfo, StaticEvidence
from ..rules import all_rules
from . import ast_javascript, ast_python, dockerfile, mcp_rules, secrets

PY_EXT = (".py",)
JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
TEXT_EXT = (".go", ".json", ".yaml", ".yml", ".toml", ".env", ".sh", ".cfg",
            ".ini")
ALL_EXT = PY_EXT + JS_EXT + TEXT_EXT

# Files that are generated, minified or vendored: analysing them reports bugs
# nobody can fix in a form nobody can read.
SKIP_SUFFIXES = (".min.js", ".min.mjs", ".min.cjs", ".map", ".d.ts",
                 ".bundle.js", ".chunk.js", "-lock.json", ".lock")

MAX_FILE_BYTES = 2 * 1024 * 1024      # 2 MB

# Process-pool parallelism is OFF by default because it was measured slower on
# every repository tried. See _should_parallelise for the numbers.
PARALLEL_THRESHOLD = None


def _ruleset_version() -> str:
    """Cache key component: changing a rule must invalidate cached results."""
    h = hashlib.sha256()
    for r in all_rules():
        h.update(f"{r.id}|{r.vector}|{r.cwe}|{r.method}".encode("utf-8"))
    return h.hexdigest()[:16]


RULESET_VERSION = _ruleset_version()


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


@dataclass
class Inventory:
    files: List[Tuple[str, str]] = field(default_factory=list)  # (abs, rel)
    dockerfiles: List[Tuple[str, str]] = field(default_factory=list)
    skipped_dirs: List[str] = field(default_factory=list)
    skipped_generated: int = 0
    skipped_too_large: List[Tuple[str, int]] = field(default_factory=list)
    total_seen: int = 0


def build_inventory(root: str) -> Inventory:
    """One walk. Classify as we go."""
    inv = Inventory()
    skip = _skip_dirs_for(root)
    inv.skipped_dirs = sorted(skip)

    for dirpath, dirnames, filenames in os.walk(root):
        pruned = [d for d in dirnames if d.lower() in skip]
        dirnames[:] = [d for d in dirnames if d.lower() not in skip]
        for _ in pruned:
            pass
        for fn in filenames:
            inv.total_seen += 1
            low = fn.lower()
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root).replace("\\", "/")

            if low == "dockerfile" or low.endswith(".dockerfile"):
                inv.dockerfiles.append((path, rel))
                continue
            if not low.endswith(ALL_EXT):
                continue
            if low.endswith(SKIP_SUFFIXES):
                inv.skipped_generated += 1
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                inv.skipped_too_large.append((rel, size))
                continue
            inv.files.append((path, rel))

    inv.files.sort()
    inv.dockerfiles.sort()
    return inv


# ---------------------------------------------------------------------------
# Per-file analysis -- exactly one parse
# ---------------------------------------------------------------------------


def analyze_one(path: str, rel: str) -> List[Finding]:
    """Analyse a single file with exactly one parse.

    Returns findings from every rule that applies to this file type.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return []

    text = raw.decode("utf-8", errors="replace")
    low = rel.lower()
    out: List[Finding] = []

    if low.endswith(PY_EXT):
        import ast as _ast
        try:
            tree = _ast.parse(text, filename=rel)
        except (SyntaxError, ValueError):
            tree = None
        if tree is not None:
            out.extend(ast_python.analyze_tree(tree, text, rel))
        out.extend(mcp_rules.analyze_py_text(text, rel))

    elif low.endswith(JS_EXT):
        tree = ast_javascript.parse(raw)
        if tree is not None:
            out.extend(ast_javascript.analyze_tree(tree, raw, rel))
            out.extend(mcp_rules.analyze_js_tree(tree, raw, rel))

    out.extend(secrets.analyze_text(text, rel))
    return out


# ---------------------------------------------------------------------------
# Result cache
# ---------------------------------------------------------------------------


def cache_dir() -> str:
    base = os.environ.get("MCPGUARD_STATIC_CACHE") or os.path.join(
        os.path.expanduser("~"), ".cache", "mcp-guard", "static")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        base = os.path.join(tempfile.gettempdir(), "mcp-guard-static")
        os.makedirs(base, exist_ok=True)
    return base


def _cache_key(raw: bytes) -> str:
    h = hashlib.sha256()
    h.update(RULESET_VERSION.encode("utf-8"))
    h.update(b"\0")
    h.update(raw)
    return h.hexdigest()


def _serialise(findings: List[Finding]) -> List[dict]:
    return [f.as_dict() for f in findings]


def _deserialise(rows: List[dict], rel: str) -> Optional[List[Finding]]:
    from ..rules import get as get_rule

    out: List[Finding] = []
    for row in rows:
        ev = row.get("evidence") or {}
        if ev.get("kind") != "static":
            return None
        try:
            rule = get_rule(row["rule_id"])
            out.append(Finding(
                rule_id=row["rule_id"], title=row["title"],
                description=row["description"], cwe=row["cwe"],
                cvss_vector=row["cvss_vector"], cvss_score=row["cvss_score"],
                remediation=row.get("remediation", rule.remediation),
                references=row.get("references", []),
                evidence=StaticEvidence(
                    file=rel, line=ev["line"], column=ev["column"],
                    matched_source=ev["matched_source"], rule_id=ev["rule_id"]),
            ))
        except Exception:  # noqa: BLE001 - a bad cache entry is just a miss
            return None
    return out


def analyze_one_cached(path: str, rel: str, stats: Dict[str, int]) -> List[Finding]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return []

    key = _cache_key(raw)
    cpath = os.path.join(cache_dir(), key[:2], key[2:] + ".json")
    try:
        with open(cpath, encoding="utf-8") as fh:
            rows = json.load(fh)
        hit = _deserialise(rows, rel)
        if hit is not None:
            stats["cache_hits"] = stats.get("cache_hits", 0) + 1
            return hit
    except Exception:  # noqa: BLE001
        pass

    findings = analyze_one(path, rel)
    stats["cache_misses"] = stats.get("cache_misses", 0) + 1
    try:
        os.makedirs(os.path.dirname(cpath), exist_ok=True)
        with open(cpath, "w", encoding="utf-8") as fh:
            json.dump(_serialise(findings), fh)
    except OSError:
        pass
    return findings


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def _should_parallelise(n_files: int) -> bool:
    """Whether to use a process pool. Currently: never.

    TRIED AND REVERTED. A ProcessPoolExecutor over the file inventory was
    measured slower than serial on every repository tested, cold cache,
    milliseconds:

        repo                   files   serial   pool
        typescript-sdk           986     4878   6289
        python-sdk               899     3337   5031
        mcp-server-cloudflare    291      744   1275
        github-mcp-server        270      983   1693

    Windows has no fork, so each worker pays a fresh interpreter start plus a
    tree_sitter import, and every Finding has to be pickled back. Parsing a
    single file is a few milliseconds; the per-file work is far too small to
    amortise that. The pool is left reachable via ``parallel=True`` for anyone
    who wants to re-measure on a forking platform, but nothing enables it.
    """
    return False if PARALLEL_THRESHOLD is None else n_files >= PARALLEL_THRESHOLD


def _worker(args):
    path, rel = args
    try:
        return rel, [f.as_dict() for f in analyze_one(path, rel)]
    except Exception:  # noqa: BLE001
        return rel, []


def run_static(info: ServerInfo, *, use_cache: bool = True,
               parallel: Optional[bool] = None,
               artifacts: Optional[Dict] = None) -> List[Finding]:
    root = info.root
    art = artifacts if artifacts is not None else {}
    stats: Dict[str, int] = {}

    inv = build_inventory(root)
    findings: List[Finding] = []

    use_pool = _should_parallelise(len(inv.files)) if parallel is None else parallel

    if use_pool and len(inv.files) > 1:
        try:
            from concurrent.futures import ProcessPoolExecutor
            workers = min(os.cpu_count() or 2, 8)
            with ProcessPoolExecutor(max_workers=workers) as pool:
                for rel, rows in pool.map(_worker, inv.files, chunksize=8):
                    got = _deserialise(rows, rel)
                    if got:
                        findings.extend(got)
            art["parallel"] = f"process pool, {workers} workers"
        except Exception as exc:  # noqa: BLE001 - fall back rather than fail
            art["parallel"] = f"pool unavailable ({type(exc).__name__}); serial"
            use_pool = False
    if not use_pool:
        art["parallel"] = art.get("parallel", "serial")
        for path, rel in inv.files:
            if use_cache:
                findings.extend(analyze_one_cached(path, rel, stats))
            else:
                findings.extend(analyze_one(path, rel))

    for path, rel in inv.dockerfiles:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                findings.extend(dockerfile.analyze_text(fh.read(), rel))
        except OSError:
            continue

    art.update({
        "files_analysed": len(inv.files),
        "dockerfiles": len(inv.dockerfiles),
        "files_seen": inv.total_seen,
        "skipped_directories": inv.skipped_dirs,
        "skipped_generated_or_minified": inv.skipped_generated,
        "cache_hits": stats.get("cache_hits", 0),
        "cache_misses": stats.get("cache_misses", 0),
    })
    if inv.skipped_too_large:
        art["skipped_too_large"] = [
            {"file": f, "bytes": b} for f, b in inv.skipped_too_large[:20]
        ]
    return findings
