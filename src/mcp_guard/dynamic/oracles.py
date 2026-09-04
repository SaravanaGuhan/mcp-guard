"""Oracles.

An oracle decides whether one exchange proves a vulnerability. It returns
``None`` for "no finding", or a human-readable string saying what in the
response constitutes proof.

Every oracle here reads its ``response`` argument. ``tests/test_invariants.py``
walks this module's AST and fails on any oracle whose body does not reference
``response`` -- an oracle that ignores the server's answer is the fabrication
bug this rewrite exists to prevent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .transport import Exchange

JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_PARSE_ERROR = -32700


@dataclass
class ProbeContext:
    """Canaries and state an oracle may consult."""

    # Each entry is (payload_we_send, marker_a_shell_must_output). The marker
    # never appears in the payload, so only shell interpretation can produce it.
    exec_canaries: List[tuple] = field(default_factory=list)
    canary_path: str = ""          # absolute path to a file outside the target
    canary_content: str = ""       # unique contents of that file
    declared_methods: set = field(default_factory=set)
    dispatch_ok: bool = True       # random-method control returned -32601
    process_alive_before: bool = True
    process_alive_after: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)


def _text(response: Exchange) -> str:
    return response.response_raw or ""


# ---------------------------------------------------------------------------
# Canary oracles -- a positive is proof, not inference
# ---------------------------------------------------------------------------


def oracle_command_execution(
    request: Dict[str, Any], response: Exchange, ctx: ProbeContext
) -> Optional[str]:
    """Positive only if the shell-collapsed marker appears in the response.

    The payload we send is ``echo MCPGUARD""_<uuid>``. A shell removes the empty
    quotes and prints ``MCPGUARD_<uuid>``. That collapsed form never appears in
    the bytes we sent, so a server that merely echoes our argument back cannot
    produce it -- only actual shell interpretation can.
    """
    body = _text(response)
    if not body:
        return None
    sent = request.get("__request_json__", "")
    for payload, marker in ctx.exec_canaries:
        if marker and marker in body and marker not in sent:
            return (
                f"response contains {marker!r}, which is the shell-collapsed form of "
                f"the payload {payload!r}. The collapsed form was never transmitted "
                f"(it does not appear in the request bytes), so the argument was "
                f"interpreted by a shell rather than echoed back."
            )
    return None


def oracle_canary_file_read(
    request: Dict[str, Any], response: Exchange, ctx: ProbeContext
) -> Optional[str]:
    """Positive only if the contents of a file outside the target root came back."""
    body = _text(response)
    if not body or not ctx.canary_content:
        return None
    if ctx.canary_content in body:
        return (
            f"response contains the contents of {ctx.canary_path}, a file written "
            f"outside the target root. The server read a path that escaped its own "
            f"directory."
        )
    return None


# ---------------------------------------------------------------------------
# Protocol oracles
# ---------------------------------------------------------------------------


def oracle_random_method_control(
    request: Dict[str, Any], response: Exchange, ctx: ProbeContext
) -> Optional[str]:
    """Control probe. Positive means the server answers ANYTHING.

    If a method name that cannot exist is answered successfully, the server has
    no method-existence check, every other method probe is uninterpretable, and
    we say so instead of reporting a pile of meaningless findings.
    """
    if response.timed_out or not response.answered:
        return None
    if response.result() is not None:
        return (
            f"server returned a success result for the method "
            f"{request.get('method')!r}, which it never declared and which does not "
            f"exist. No method-existence check is implemented, so method-based "
            f"probes cannot be interpreted."
        )
    return None


def oracle_undeclared_method(
    request: Dict[str, Any], response: Exchange, ctx: ProbeContext
) -> Optional[str]:
    """Positive if an undeclared method is answered as anything but -32601."""
    if not ctx.dispatch_ok:
        return None  # control failed; this probe is void
    if response.timed_out or not response.answered:
        return None
    code = response.error_code()
    if code == JSONRPC_METHOD_NOT_FOUND:
        return None
    method = request.get("method")
    if response.result() is not None:
        return (
            f"server returned a success result for undeclared method {method!r}; "
            f"the random-method control correctly returned -32601, so dispatch "
            f"works and this method is genuinely reachable."
        )
    if code is not None:
        return (
            f"server answered undeclared method {method!r} with error code {code} "
            f"rather than -32601 (method not found), indicating the method is "
            f"recognised."
        )
    return None


def oracle_crash(
    request: Dict[str, Any], response: Exchange, ctx: ProbeContext
) -> Optional[str]:
    """Positive only on process death. Slowness is explicitly not a finding."""
    _ = response  # the exchange is recorded as evidence even when the proof is the exit
    if ctx.process_alive_before and not ctx.process_alive_after:
        return (
            f"server process exited while handling {request.get('__label__', 'a frame')}; "
            f"a malformed request must not terminate the server."
        )
    return None


def oracle_jsonrpc_violation(
    request: Dict[str, Any], response: Exchange, ctx: ProbeContext
) -> Optional[str]:
    """Positive if a reply is not a valid JSON-RPC 2.0 response object."""
    if response.timed_out or not response.response_raw:
        return None
    parsed = response.response_parsed
    if parsed is None:
        return (
            "server wrote non-JSON bytes to stdout in reply to a JSON-RPC request: "
            f"{response.response_raw.strip()[:120]!r}"
        )
    has_result = "result" in parsed
    has_error = "error" in parsed
    if has_result and has_error:
        return "response carries both result and error, which JSON-RPC 2.0 forbids."
    if not has_result and not has_error:
        return "response carries neither result nor error, which JSON-RPC 2.0 requires."
    if parsed.get("jsonrpc") != "2.0":
        return (
            f"response omits or misdeclares the jsonrpc version "
            f"(got {parsed.get('jsonrpc')!r})."
        )
    return None


def oracle_schema_unenforced(
    request: Dict[str, Any], response: Exchange, ctx: ProbeContext
) -> Optional[str]:
    """Positive only if arguments the tool's own schema forbids are accepted."""
    if response.timed_out or not response.answered:
        return None
    result = response.result()
    if result is None:
        return None
    if isinstance(result, dict) and result.get("isError") is True:
        return None  # tool reported an error through the MCP result envelope
    violation = ctx.extra.get("schema_violation", "arguments violating its inputSchema")
    return (
        f"tool {ctx.extra.get('tool_name')!r} returned a success result for "
        f"{violation}; the declared inputSchema is not enforced."
    )
