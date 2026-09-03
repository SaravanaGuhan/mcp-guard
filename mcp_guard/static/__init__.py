"""Static analysis.

Reads files. Executes nothing. Every finding carries the literal source text at
the position it reports.
"""

from __future__ import annotations

import os
from typing import List

from ..detect import iter_source_files
from ..models import Finding, ServerInfo
from . import ast_javascript, ast_python, dockerfile, mcp_rules, secrets

PY_EXT = (".py",)
JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
TEXT_EXT = PY_EXT + JS_EXT + (
    ".go", ".json", ".yaml", ".yml", ".toml", ".env", ".sh", ".cfg", ".ini",
)


def run_static(info: ServerInfo) -> List[Finding]:
    root = info.root
    findings: List[Finding] = []

    def rel(p: str) -> str:
        return os.path.relpath(p, root).replace("\\", "/")

    for path in iter_source_files(root, PY_EXT):
        findings.extend(ast_python.analyze_file(path, rel(path)))
        findings.extend(mcp_rules.analyze_py(path, rel(path)))

    for path in iter_source_files(root, JS_EXT):
        findings.extend(ast_javascript.analyze_file(path, rel(path)))
        findings.extend(mcp_rules.analyze_js(path, rel(path)))

    for path in iter_source_files(root, TEXT_EXT):
        findings.extend(secrets.analyze_file(path, rel(path)))

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git")]
        for fn in filenames:
            if fn.lower() == "dockerfile" or fn.lower().endswith(".dockerfile"):
                p = os.path.join(dirpath, fn)
                findings.extend(dockerfile.analyze_file(p, rel(p)))

    return findings
