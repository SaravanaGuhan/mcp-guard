"""JavaScript/TypeScript static analysis via tree-sitter.

No regex. The file is parsed to a concrete syntax tree and sinks are located by
node type, so `exec(` inside a comment or a string is not a match -- which is
exactly the false positive the previous regex engine produced.

Detected:
  * child_process exec/execSync/spawn/spawnSync/execFile with a NON-LITERAL
    first argument (a string literal command is not user-controlled).
  * fs.* read/write/append/unlink with a non-literal path argument.
  * vm.runInNewContext / vm.runInThisContext / eval / new Function.

Where the non-literal argument traces back to a parameter of the enclosing
function, the parameter name is reported. That trace is intraprocedural.
"""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

from ..models import Finding, StaticEvidence
from ..rules import get as get_rule

try:
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language, Node, Parser
    _LANG = Language(_tsjs.language())
    AVAILABLE = True
except Exception:  # pragma: no cover - dependency missing
    AVAILABLE = False
    _LANG = None
    Node = object  # type: ignore

EXEC_FNS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
FS_FNS = {
    "readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile",
    "appendFileSync", "unlink", "unlinkSync", "createReadStream",
    "createWriteStream", "open", "openSync", "rm", "rmSync", "readdir",
    "readdirSync", "stat", "statSync", "copyFile", "copyFileSync",
}
VM_FNS = {"runInNewContext", "runInThisContext", "runInContext", "compileFunction"}

LITERAL_TYPES = {"string", "template_string", "number", "true", "false", "null"}


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _callee_parts(call, src: bytes) -> Tuple[Optional[str], Optional[str]]:
    """(object, property) for `a.b()`, or (None, name) for `b()`."""
    fn = call.child_by_field_name("function")
    if fn is None:
        return None, None
    if fn.type == "identifier":
        return None, _text(fn, src)
    if fn.type == "member_expression":
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        return (_text(obj, src) if obj else None,
                _text(prop, src) if prop else None)
    return None, None


def _first_arg(call):
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    for c in args.children:
        if c.is_named:
            return c
    return None


def _is_literal(node) -> bool:
    if node is None:
        return False
    if node.type in LITERAL_TYPES:
        return True
    if node.type == "template_string":
        # A template with no substitutions is still a literal.
        return not any(c.type == "template_substitution" for c in node.children)
    return False


def _enclosing_params(node, src: bytes) -> Set[str]:
    """Parameter names of the nearest enclosing function."""
    cur = node.parent
    while cur is not None:
        if cur.type in ("function_declaration", "function_expression",
                        "arrow_function", "method_definition",
                        "generator_function_declaration"):
            params = cur.child_by_field_name("parameters") or \
                cur.child_by_field_name("parameter")
            out: Set[str] = set()
            if params is not None:
                for n in _walk(params):
                    if n.type == "identifier":
                        out.add(_text(n, src))
            return out
        cur = cur.parent
    return set()


def _traces_to_param(arg, src: bytes) -> Optional[str]:
    params = _enclosing_params(arg, src)
    if not params:
        return None
    for n in _walk(arg):
        if n.type == "identifier" and _text(n, src) in params:
            return _text(n, src)
    return None


def parse(src: bytes):
    """Parse once. The driver shares the tree with every JS rule."""
    if not AVAILABLE:
        return None
    return Parser(_LANG).parse(src)


def analyze_file(path: str, rel: str) -> List[Finding]:
    """Convenience wrapper: read, parse, analyse. Used by tests."""
    if not AVAILABLE:
        return []
    try:
        with open(path, "rb") as fh:
            src = fh.read()
    except OSError:
        return []
    tree = parse(src)
    if tree is None:
        return []
    return analyze_tree(tree, src, rel)


def analyze_tree(tree, src: bytes, rel: str) -> List[Finding]:
    if not AVAILABLE or tree is None:
        return []
    text_lines = src.decode("utf-8", errors="replace").splitlines()
    findings: List[Finding] = []
    seen: Set[Tuple[str, int]] = set()

    def add(rule_id: str, node, detail: str) -> None:
        line = node.start_point[0] + 1
        key = (rule_id, line)
        if key in seen:
            return
        seen.add(key)
        rule = get_rule(rule_id)
        snippet = _text(node, src).strip()[:400]
        if not snippet:
            snippet = text_lines[line - 1].strip() if line - 1 < len(text_lines) else ""
        if not snippet:
            return
        findings.append(Finding(
            rule_id=rule.id,
            title=rule.title,
            description=detail,
            cwe=rule.cwe,
            cvss_vector=rule.clean_vector,
            cvss_score=rule.score,
            remediation=rule.remediation,
            evidence=StaticEvidence(
                file=rel, line=line, column=node.start_point[1] + 1,
                matched_source=snippet, rule_id=rule.id,
            ),
        ))

    for node in _walk(tree.root_node):
        if node.type == "new_expression":
            ctor = node.child_by_field_name("constructor")
            if ctor is not None and _text(ctor, src) == "Function":
                add("MCPG-JS-VM-EVAL", node,
                    "new Function() compiles code at runtime.")
            continue

        if node.type != "call_expression":
            continue

        obj, prop = _callee_parts(node, src)
        arg = _first_arg(node)

        if prop in EXEC_FNS and not _is_literal(arg) and arg is not None:
            param = _traces_to_param(arg, src)
            via = f" It derives from parameter {param!r}." if param else ""
            add("MCPG-JS-SHELL-TAINT", node,
                f"{(obj + '.') if obj else ''}{prop}() is called with the "
                f"non-literal command expression `{_text(arg, src)[:80]}`.{via}")
            continue

        if prop in FS_FNS and not _is_literal(arg) and arg is not None:
            param = _traces_to_param(arg, src)
            via = f" It derives from parameter {param!r}." if param else ""
            add("MCPG-JS-PATH-TAINT", node,
                f"{(obj + '.') if obj else ''}{prop}() is called with the "
                f"non-literal path expression `{_text(arg, src)[:80]}`.{via}")
            continue

        if prop in VM_FNS or (obj is None and prop == "eval"):
            if arg is not None and not _is_literal(arg):
                add("MCPG-JS-VM-EVAL", node,
                    f"{(obj + '.') if obj else ''}{prop}() evaluates a "
                    f"non-literal expression at runtime.")

    return findings
