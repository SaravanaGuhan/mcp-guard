"""Python static analysis via the stdlib ``ast`` module.

Taint model, stated plainly because the README must not overstate it:

  * **Intraprocedural only.** Taint is tracked from a function's own parameters
    (and from ``params[...]`` / ``arguments[...]`` subscripts inside it) through
    local assignments to a sink in the same function. Nothing crosses a call
    boundary. A value laundered through a helper function is not detected.
  * Sources: any parameter of a function, plus subscripts of names called
    ``params``, ``arguments``, ``args``, ``request``, ``req``, ``body``.
  * Sinks: subprocess.*, os.system/popen/exec*, eval/exec/compile, and
    open()/Path() for the path rules.

Every finding slices its ``matched_source`` out of the same buffer that was
parsed, so the evidence is the literal text at the reported position.
"""

from __future__ import annotations

import ast
from typing import List, Optional, Set, Tuple

from ..models import Finding, StaticEvidence
from ..rules import get as get_rule

TAINT_CONTAINERS = {"params", "arguments", "args", "request", "req", "body", "kwargs"}

SHELL_SINKS = {
    ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "Popen"),
    ("subprocess", "check_output"), ("subprocess", "check_call"),
    ("subprocess", "getoutput"), ("subprocess", "getstatusoutput"),
    ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
    ("os", "execl"), ("os", "spawnl"), ("os", "spawnv"),
}
SHELL_BUILTINS = {"eval", "exec", "compile"}

PATH_SINKS = {("os", "remove"), ("os", "unlink"), ("os", "rename"),
              ("shutil", "copy"), ("shutil", "move"), ("shutil", "rmtree"),
              ("pathlib", "Path")}
PATH_BUILTINS = {"open"}


def _src_slice(lines: List[str], node: ast.AST) -> str:
    lo = getattr(node, "lineno", 1) - 1
    hi = getattr(node, "end_lineno", lo + 1)
    chunk = "\n".join(lines[lo:hi]).strip()
    return chunk[:400] or (lines[lo].strip() if lo < len(lines) else "")


def _dotted(node: ast.AST) -> Optional[Tuple[str, str]]:
    """(module, attr) for a call like ``subprocess.run``."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return None


class _FunctionTaint(ast.NodeVisitor):
    """Tracks tainted local names inside one function."""

    def __init__(self, fn: ast.AST):
        self.tainted: Set[str] = set()
        args = getattr(fn, "args", None)
        if args is not None:
            for a in list(args.args) + list(args.kwonlyargs) + list(args.posonlyargs):
                if a.arg not in ("self", "cls"):
                    self.tainted.add(a.arg)
            if args.vararg:
                self.tainted.add(args.vararg.arg)
            if args.kwarg:
                self.tainted.add(args.kwarg.arg)

    def expr_is_tainted(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return True
            if isinstance(sub, ast.Subscript):
                base = sub.value
                if isinstance(base, ast.Name) and base.id in TAINT_CONTAINERS:
                    return True
                if isinstance(base, ast.Attribute) and base.attr in TAINT_CONTAINERS:
                    return True
            if isinstance(sub, ast.Attribute) and sub.attr in TAINT_CONTAINERS:
                return True
        return False

    def propagate(self, fn: ast.AST) -> None:
        """Two passes so `a = param; b = a` reaches b."""
        for _ in range(3):
            grew = False
            for node in ast.walk(fn):
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    value = node.value
                    if value is None:
                        continue
                    if not self.expr_is_tainted(value):
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for t in targets:
                        for sub in ast.walk(t):
                            if isinstance(sub, ast.Name) and sub.id not in self.tainted:
                                self.tainted.add(sub.id)
                                grew = True
            if not grew:
                break


def _shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) \
                and kw.value.value is True:
            return True
    return False


def analyze_file(path: str, rel: str) -> List[Finding]:
    """Convenience wrapper: read, parse, analyse. Used by tests."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError:
        return []
    try:
        tree = ast.parse(source, filename=rel)
    except SyntaxError:
        return []
    return analyze_tree(tree, source, rel)


def analyze_tree(tree, source: str, rel: str) -> List[Finding]:
    """Analyse an already-parsed module.

    The tree is parsed once per file by the static driver and shared with every
    rule that needs it. Previously ast_python and mcp_rules each parsed the same
    file independently.
    """
    lines = source.splitlines()
    findings: List[Finding] = []

    functions = [n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for fn in functions:
        taint = _FunctionTaint(fn)
        taint.propagate(fn)

        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue

            dotted = _dotted(node.func)
            name = node.func.id if isinstance(node.func, ast.Name) else None

            is_shell = (dotted in SHELL_SINKS) or (name in SHELL_BUILTINS)
            is_path = (dotted in PATH_SINKS) or (name in PATH_BUILTINS)

            if not (is_shell or is_path):
                continue

            first = node.args[0] if node.args else None
            if first is None or not taint.expr_is_tainted(first):
                continue

            # subprocess with an argument *list* and shell=False is the safe form.
            if is_shell and dotted and dotted[0] == "subprocess":
                if isinstance(first, (ast.List, ast.Tuple)) and not _shell_true(node):
                    continue

            rule = get_rule("MCPG-PY-SHELL-TAINT" if is_shell else "MCPG-PY-PATH-TAINT")
            sink = ".".join(dotted) if dotted else (name or "?")
            findings.append(Finding(
                rule_id=rule.id,
                title=f"{rule.title}: {sink}()",
                description=(
                    f"Value derived from a parameter of {fn.name}() reaches "
                    f"{sink}() without validation."
                ),
                cwe=rule.cwe,
                cvss_vector=rule.clean_vector,
                cvss_score=rule.score,
                remediation=rule.remediation,
                evidence=StaticEvidence(
                    file=rel,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    matched_source=_src_slice(lines, node),
                    rule_id=rule.id,
                ),
            ))
    return findings
