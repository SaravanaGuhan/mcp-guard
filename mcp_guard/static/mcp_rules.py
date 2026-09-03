"""MCP-specific static rules.

These are the checks that are actually particular to MCP, as opposed to generic
appsec rules with "MCP" in the title. They operate on tool *declarations* found
in source: the object literals passed to tools/list responses or to an SDK's
registerTool/setRequestHandler.

Implemented:

  * MCPG-MCP-SCHEMA-UNDECLARED-ARGS -- a handler reads argument keys that the
    tool's own inputSchema never declares.
  * MCPG-MCP-PROMPT-INJECTION-SURFACE -- a tool description contains
    model-directed imperative text. Descriptions are fed to the model verbatim,
    so this is an injection surface into the agent's instruction channel.
  * MCPG-MCP-URI-CONCAT -- a resource URI/path is built by concatenation with no
    resolve-and-verify step.

Scope limit, stated because the README must not overstate it: declarations are
matched syntactically within a single file. A schema assembled at runtime, or
imported from another module, is not analysed.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Set, Tuple

from ..models import Finding, StaticEvidence
from ..rules import get as get_rule

try:
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language, Parser
    _LANG = Language(_tsjs.language())
    AVAILABLE = True
except Exception:  # pragma: no cover
    AVAILABLE = False
    _LANG = None

# Imperative, model-directed phrasing that does not belong in a description.
INSTRUCTION_RE = re.compile(
    r"\b("
    r"ignore (?:all |any )?(?:previous|prior|above)|"
    r"disregard (?:all |any )?(?:previous|prior|above)|"
    r"you (?:must|should|will|are required to)|"
    r"always (?:call|use|invoke|run|respond|reply)|"
    r"never (?:tell|reveal|mention|disclose|refuse)|"
    r"do not (?:tell|reveal|mention|ask|confirm)|"
    r"before (?:using|calling) any other tool|"
    r"system prompt|"
    r"</?(?:system|assistant|user)>"
    r")\b",
    re.I,
)

CONCAT_URI_RE = re.compile(
    r"(?:uri|path|filepath|filename|target)\s*=\s*[^;\n]*[\"'`][^\"'`\n]*[\"'`]\s*\+"
    r"|\+\s*(?:req|request|params|arguments|args)\b",
    re.I,
)
SAFE_RESOLVE_RE = re.compile(
    r"(path\.resolve|realpath|os\.path\.abspath|startsWith|is_relative_to|"
    r"commonpath|relative_to)", re.I)


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _obj_pairs(obj, src: bytes) -> Dict[str, object]:
    """Shallow key -> node map for a JS object literal."""
    out: Dict[str, object] = {}
    for child in obj.children:
        if child.type != "pair":
            continue
        k = child.child_by_field_name("key")
        v = child.child_by_field_name("value")
        if k is None or v is None:
            continue
        key = _text(k, src).strip("\"'`")
        out[key] = v
    return out


def _string_value(node, src: bytes) -> Optional[str]:
    if node is None:
        return None
    if node.type in ("string", "template_string"):
        return _text(node, src).strip("\"'`")
    return None


def _schema_property_names(schema_node, src: bytes) -> Set[str]:
    pairs = _obj_pairs(schema_node, src)
    props = pairs.get("properties")
    if props is None:
        return set()
    return set(_obj_pairs(props, src).keys())


def _enclosing_source(node, src: bytes, span: int = 4000) -> str:
    """Text following a declaration, used to look for argument reads."""
    end = min(len(src), node.end_byte + span)
    return src[node.start_byte:end].decode("utf-8", errors="replace")


def analyze_js(path: str, rel: str) -> List[Finding]:
    """Convenience wrapper: read, parse, analyse. Used by tests."""
    if not AVAILABLE:
        return []
    try:
        with open(path, "rb") as fh:
            src = fh.read()
    except OSError:
        return []
    return analyze_js_tree(Parser(_LANG).parse(src), src, rel)


def analyze_js_tree(tree, src: bytes, rel: str) -> List[Finding]:
    if not AVAILABLE or tree is None:
        return []
    findings: List[Finding] = []
    seen: Set[Tuple[str, int]] = set()

    def add(rule_id: str, line: int, col: int, snippet: str, detail: str) -> None:
        key = (rule_id, line)
        if key in seen or not snippet.strip():
            return
        seen.add(key)
        rule = get_rule(rule_id)
        findings.append(Finding(
            rule_id=rule.id, title=rule.title, description=detail,
            cwe=rule.cwe, cvss_vector=rule.clean_vector, cvss_score=rule.score,
            remediation=rule.remediation,
            evidence=StaticEvidence(file=rel, line=line, column=col,
                                    matched_source=snippet.strip()[:400],
                                    rule_id=rule.id),
        ))

    for node in _walk(tree.root_node):
        if node.type != "object":
            continue
        pairs = _obj_pairs(node, src)
        if "name" not in pairs:
            continue
        has_schema = "inputSchema" in pairs
        desc = _string_value(pairs.get("description"), src)
        if not has_schema and desc is None:
            continue

        tool_name = _string_value(pairs.get("name"), src) or "?"
        line = node.start_point[0] + 1
        col = node.start_point[1] + 1
        snippet = _text(node, src)

        # -- prompt injection surface --
        if desc:
            m = INSTRUCTION_RE.search(desc)
            if m:
                add("MCPG-MCP-PROMPT-INJECTION-SURFACE", line, col, snippet,
                    f"Tool {tool_name!r} has a description containing the "
                    f"model-directed phrase {m.group(0)!r}. Descriptions are "
                    f"passed to the model verbatim, so this text is an "
                    f"instruction-channel injection surface.")

        # -- undeclared argument reads --
        if has_schema:
            declared = _schema_property_names(pairs["inputSchema"], src)
            body = _enclosing_source(node, src)
            read_keys: Set[str] = set()
            for m in re.finditer(
                r"arguments\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*[\"'`]([^\"'`]+)[\"'`]\s*\])",
                body,
            ):
                read_keys.add(m.group(1) or m.group(2))
            undeclared = {k for k in read_keys if k and k not in declared}
            if undeclared and declared:
                add("MCPG-MCP-SCHEMA-UNDECLARED-ARGS", line, col, snippet,
                    f"Tool {tool_name!r} declares properties {sorted(declared)} "
                    f"but its handler reads {sorted(undeclared)}, which the "
                    f"schema does not declare and a validator would not check.")

    # -- URI concatenation --
    text = src.decode("utf-8", errors="replace")
    for i, line_text in enumerate(text.splitlines(), 1):
        if CONCAT_URI_RE.search(line_text) and not SAFE_RESOLVE_RE.search(line_text):
            add("MCPG-MCP-URI-CONCAT", i, 1, line_text,
                "A resource path/URI is assembled by concatenation with no "
                "resolve-and-verify step, so '..' segments are not neutralised.")

    return findings


def analyze_py(path: str, rel: str) -> List[Finding]:
    """Convenience wrapper: read then analyse. Used by tests."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return analyze_py_text(text, rel)


def analyze_py_text(text: str, rel: str) -> List[Finding]:
    """Python MCP servers: description and URI-concat checks only.

    Tool schemas in the Python SDK are usually derived from type hints rather
    than written as literals, so the undeclared-argument check does not apply
    and is deliberately not attempted here.
    """
    findings: List[Finding] = []
    seen: Set[Tuple[str, int]] = set()

    def add(rule_id: str, line: int, snippet: str, detail: str) -> None:
        key = (rule_id, line)
        if key in seen or not snippet.strip():
            return
        seen.add(key)
        rule = get_rule(rule_id)
        findings.append(Finding(
            rule_id=rule.id, title=rule.title, description=detail,
            cwe=rule.cwe, cvss_vector=rule.clean_vector, cvss_score=rule.score,
            remediation=rule.remediation,
            evidence=StaticEvidence(file=rel, line=line, column=1,
                                    matched_source=snippet.strip()[:400],
                                    rule_id=rule.id),
        ))

    for i, line_text in enumerate(text.splitlines(), 1):
        if "description" in line_text.lower():
            m = INSTRUCTION_RE.search(line_text)
            if m:
                add("MCPG-MCP-PROMPT-INJECTION-SURFACE", i, line_text,
                    f"A tool description contains the model-directed phrase "
                    f"{m.group(0)!r}.")
        if CONCAT_URI_RE.search(line_text) and not SAFE_RESOLVE_RE.search(line_text):
            add("MCPG-MCP-URI-CONCAT", i, line_text,
                "A resource path/URI is assembled by concatenation with no "
                "resolve-and-verify step.")
    return findings
