"""Probes.

A probe pairs a request builder with an oracle. Probes are capability-gated:
one that targets ``resources/read`` does not run against a server that never
declared a resources capability. Probing something a server does not implement
is "not applicable", not a finding.

Deleted deliberately, per the rewrite plan:

  * "Authorization Bypass" -- an MCP stdio server has no authentication layer,
    so there is nothing to bypass and the finding was meaningless by
    construction.
  * "Information Disclosure" via resource enumeration -- listing the resources a
    server advertises is the protocol working as designed.

Both existed only to inflate finding counts.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .oracles import (
    ProbeContext,
    oracle_canary_file_read,
    oracle_command_execution,
    oracle_crash,
    oracle_jsonrpc_violation,
    oracle_random_method_control,
    oracle_schema_unenforced,
    oracle_undeclared_method,
)
from .transport import Exchange


@dataclass
class Probe:
    id: str
    description: str
    required_capability: Optional[str]
    rule_id: str
    cwe: str
    build_requests: Callable[[Any, ProbeContext], List[Dict[str, Any]]]
    oracle: Callable[[Dict[str, Any], Exchange, ProbeContext], Optional[str]]
    raw: bool = False       # send request["__raw__"] verbatim instead of JSON-encoding
    watch_exit: bool = False  # oracle needs before/after liveness
    timeout: float = 8.0    # a well-behaved server answers fast or not at all


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_PATHY = ("path", "file", "filename", "filepath", "uri", "url", "src",
          "source", "dir", "directory", "location", "target")


def _string_props(schema: Dict[str, Any]) -> List[str]:
    props = (schema or {}).get("properties") or {}
    out = []
    for name, spec in props.items():
        if isinstance(spec, dict) and spec.get("type") in (None, "string"):
            out.append(name)
    return out


def _pathish_props(schema: Dict[str, Any]) -> List[str]:
    return [p for p in _string_props(schema) if any(k in p.lower() for k in _PATHY)]


def _tools_with_string_args(state) -> List[Dict[str, Any]]:
    out = []
    for t in state.tools:
        schema = t.get("inputSchema") or {}
        if _string_props(schema):
            out.append(t)
    return out


# ---------------------------------------------------------------------------
# 1. Command injection (canary)
# ---------------------------------------------------------------------------


def _build_cmd_injection(state, ctx: ProbeContext) -> List[Dict[str, Any]]:
    reqs = []
    for tool in _tools_with_string_args(state):
        schema = tool.get("inputSchema") or {}
        for prop in _string_props(schema):
            for payload, _marker in ctx.exec_canaries:
                args = {p: "x" for p in (schema.get("required") or []) if p != prop}
                args[prop] = payload
                reqs.append({
                    "method": "tools/call",
                    "params": {"name": tool.get("name"), "arguments": args},
                    "__label__": f"tools/call {tool.get('name')}.{prop}",
                })
    return reqs


PROBE_CMD_INJECTION = Probe(
    id="cmd-injection-canary",
    description=(
        "Send a shell-collapsing echo canary through every string tool argument. "
        "Positive only if the collapsed marker -- which was never transmitted -- "
        "appears in the response."
    ),
    required_capability="tools",
    rule_id="MCPG-DYN-CMDEXEC",
    cwe="CWE-78",
    build_requests=_build_cmd_injection,
    oracle=oracle_command_execution,
)


# ---------------------------------------------------------------------------
# 2. Path traversal via resources/read (canary file)
# ---------------------------------------------------------------------------


def _build_resource_traversal(state, ctx: ProbeContext) -> List[Dict[str, Any]]:
    import os

    name = os.path.basename(ctx.canary_path)
    rel = "../" * 8 + name
    candidates = [
        f"file://{ctx.canary_path}",
        ctx.canary_path,
        f"file://{rel}",
        rel,
    ]
    return [
        {
            "method": "resources/read",
            "params": {"uri": uri},
            "__label__": f"resources/read {uri}",
        }
        for uri in candidates
    ]


PROBE_RESOURCE_TRAVERSAL = Probe(
    id="resource-traversal-canary",
    description=(
        "Ask resources/read for a canary file written outside the target root, "
        "by absolute and relative-traversal URI. Positive only if the canary "
        "contents come back."
    ),
    required_capability="resources",
    rule_id="MCPG-DYN-PATHTRAVERSAL",
    cwe="CWE-22",
    build_requests=_build_resource_traversal,
    oracle=oracle_canary_file_read,
)


# ---------------------------------------------------------------------------
# 3. Path injection through tool arguments (canary file)
# ---------------------------------------------------------------------------


def _build_tool_path_injection(state, ctx: ProbeContext) -> List[Dict[str, Any]]:
    reqs = []
    for tool in state.tools:
        schema = tool.get("inputSchema") or {}
        for prop in _pathish_props(schema):
            args = {p: "x" for p in (schema.get("required") or []) if p != prop}
            args[prop] = ctx.canary_path
            reqs.append({
                "method": "tools/call",
                "params": {"name": tool.get("name"), "arguments": args},
                "__label__": f"tools/call {tool.get('name')}.{prop} (canary path)",
            })
    return reqs


PROBE_TOOL_PATH_INJECTION = Probe(
    id="tool-path-canary",
    description=(
        "Pass an absolute canary path through any tool parameter named like a "
        "path. Positive only if the canary contents come back."
    ),
    required_capability="tools",
    rule_id="MCPG-DYN-PATHTRAVERSAL",
    cwe="CWE-22",
    build_requests=_build_tool_path_injection,
    oracle=oracle_canary_file_read,
)


# ---------------------------------------------------------------------------
# 4. Method dispatch control + undeclared method exposure
# ---------------------------------------------------------------------------


def _build_random_control(state, ctx: ProbeContext) -> List[Dict[str, Any]]:
    return [{
        "method": f"mcpguard/control/{uuid.uuid4().hex}",
        "params": {},
        "__label__": "random-method control",
    }]


PROBE_DISPATCH_CONTROL = Probe(
    id="random-method-control",
    description=(
        "Send a method name that cannot exist. A correct server answers -32601. "
        "If it answers successfully, dispatch is absent and every method probe "
        "below is void."
    ),
    required_capability=None,
    rule_id="MCPG-DYN-NO-DISPATCH",
    cwe="CWE-1286",
    build_requests=_build_random_control,
    oracle=oracle_random_method_control,
)


def _build_undeclared_methods(state, ctx: ProbeContext) -> List[Dict[str, Any]]:
    candidates = [
        "debug/dump_memory", "debug/state", "debug/eval",
        "admin/shutdown", "admin/users", "admin/exec",
        "system/exec", "internal/config",
    ]
    return [
        {"method": m, "params": {}, "__label__": f"undeclared {m}"}
        for m in candidates
        if m not in ctx.declared_methods
    ]


PROBE_UNDECLARED_METHODS = Probe(
    id="undeclared-method-exposure",
    description=(
        "Probe debug/* and admin/* namespaces. A finding requires a non -32601 "
        "answer AND a passing dispatch control."
    ),
    required_capability=None,
    rule_id="MCPG-DYN-UNDECLARED-METHOD",
    cwe="CWE-749",
    build_requests=_build_undeclared_methods,
    oracle=oracle_undeclared_method,
)


# ---------------------------------------------------------------------------
# 5. Protocol robustness
# ---------------------------------------------------------------------------


def _build_malformed(state, ctx: ProbeContext) -> List[Dict[str, Any]]:
    big = "A" * 200_000
    return [
        {"__raw__": '{"jsonrpc":"2.0","id":901,"method":"ping"',   # truncated JSON
         "__label__": "truncated JSON frame"},
        {"__raw__": '{"id":902,"method":"ping"}',                  # no jsonrpc field
         "__label__": "missing jsonrpc field"},
        {"__raw__": 'not json at all',
         "__label__": "non-JSON line"},
        {"__raw__": json.dumps({"jsonrpc": "2.0", "id": 903, "method": "ping",
                                "params": {"blob": big}}),
         "__label__": "oversized params (200KB)"},
        {"__raw__": json.dumps({"jsonrpc": "2.0", "id": 904, "method": "ping"}) + "\n"
                    + json.dumps({"jsonrpc": "2.0", "id": 904, "method": "ping"}),
         "__label__": "duplicate request ids"},
    ]


PROBE_CRASH = Probe(
    id="malformed-frame-crash",
    description=(
        "Send malformed frames. Positive only if the process exits. Slowness is "
        "not a finding."
    ),
    required_capability=None,
    rule_id="MCPG-DYN-CRASH",
    cwe="CWE-248",
    build_requests=_build_malformed,
    oracle=oracle_crash,
    raw=True,
    watch_exit=True,
    timeout=2.0,
)

PROBE_JSONRPC = Probe(
    id="jsonrpc-conformance",
    description="Check that replies to malformed frames are valid JSON-RPC 2.0.",
    required_capability=None,
    rule_id="MCPG-DYN-JSONRPC-VIOLATION",
    cwe="CWE-20",
    build_requests=_build_malformed,
    oracle=oracle_jsonrpc_violation,
    raw=True,
    timeout=2.0,
)


# ---------------------------------------------------------------------------
# 6. Schema enforcement
# ---------------------------------------------------------------------------


def _build_schema_violation(state, ctx: ProbeContext) -> List[Dict[str, Any]]:
    reqs = []
    for tool in state.tools:
        schema = tool.get("inputSchema") or {}
        props = (schema.get("properties") or {})
        required = schema.get("required") or []
        name = tool.get("name")

        if required:
            reqs.append({
                "method": "tools/call",
                "params": {"name": name, "arguments": {}},
                "__label__": f"tools/call {name} with required args omitted",
                "__violation__": f"a call omitting required argument(s) {required}",
                "__tool__": name,
            })
        for prop, spec in props.items():
            if isinstance(spec, dict) and spec.get("type") == "string":
                args = {p: "x" for p in required if p != prop}
                args[prop] = 12345  # wrong type
                reqs.append({
                    "method": "tools/call",
                    "params": {"name": name, "arguments": args},
                    "__label__": f"tools/call {name}.{prop} with integer for string",
                    "__violation__": f"an integer passed for string property {prop!r}",
                    "__tool__": name,
                })
                break
    return reqs


PROBE_SCHEMA = Probe(
    id="schema-enforcement",
    description=(
        "Call declared tools with arguments their own inputSchema forbids. "
        "Positive only on a success result."
    ),
    required_capability="tools",
    rule_id="MCPG-DYN-SCHEMA-UNENFORCED",
    cwe="CWE-20",
    build_requests=_build_schema_violation,
    oracle=oracle_schema_unenforced,
)


# Order matters: the dispatch control runs before the method probes it gates.
ALL_PROBES: List[Probe] = [
    PROBE_DISPATCH_CONTROL,
    PROBE_CMD_INJECTION,
    PROBE_RESOURCE_TRAVERSAL,
    PROBE_TOOL_PATH_INJECTION,
    PROBE_UNDECLARED_METHODS,
    PROBE_SCHEMA,
    PROBE_JSONRPC,
    PROBE_CRASH,
]


def make_context(canary_path: str, canary_content: str, declared: set) -> ProbeContext:
    """Build canaries that collapse under a shell but not under an echo.

    Two payloads, because the collapsing character differs by shell:

      POSIX sh : ``echo MCPGUARD""_<id>``  -> quotes removed  -> MCPGUARD_<id>
      cmd.exe  : ``echo MCPGUARD^_<id>``   -> caret is escape -> MCPGUARD_<id>

    Node's child_process.exec uses /bin/sh on POSIX and cmd.exe on Windows, so a
    single-shell canary silently fails to detect a real injection on the other
    platform. Both payloads collapse to the same marker; neither contains it.
    """
    a, b = uuid.uuid4().hex, uuid.uuid4().hex
    return ProbeContext(
        exec_canaries=[
            (f'echo MCPGUARD""_{a}', f"MCPGUARD_{a}"),   # POSIX sh
            (f"echo MCPGUARD^_{b}", f"MCPGUARD_{b}"),    # cmd.exe
        ],
        canary_path=canary_path,
        canary_content=canary_content,
        declared_methods=declared,
    )
