"""Dynamic analysis.

Contract with the rest of the tool:

  * If the server cannot be launched or the handshake fails, this returns
    ``(<empty list>, {"ran": False, "reason": ...})`` plus the target's exit
    code and the last 20 lines of its stderr. It never substitutes static
    output, and nothing it returns is ever labelled anything but dynamic.
  * Every Finding it returns carries DynamicEvidence whose ``response_raw`` is
    the exact text the transport read from the server.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Tuple

from ..models import DynamicEvidence, Finding, ServerInfo
from ..rules import get as get_rule
from .harness import launch_and_handshake, prepare, shutdown
from .oracles import JSONRPC_METHOD_NOT_FOUND, ProbeContext
from .probes import ALL_PROBES, Probe, make_context
from .transport import Exchange, StdioClient


def _write_canary() -> tuple[str, str]:
    """A file outside the target root whose contents cannot be guessed."""
    content = f"MCPGUARD-CANARY-{uuid.uuid4().hex}-DO-NOT-SERVE"
    fd, path = tempfile.mkstemp(prefix="mcpguard_canary_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path, content


def _finding(rule_id: str, ex: Exchange, oracle_id: str, why: str,
             title_suffix: str = "") -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule.id,
        title=rule.title + (f" -- {title_suffix}" if title_suffix else ""),
        description=rule.rationale,
        cwe=rule.cwe,
        cvss_vector=rule.clean_vector,
        cvss_score=rule.score,
        remediation=rule.remediation,
        references=list(rule.references),
        evidence=DynamicEvidence(
            request_json=ex.request_json,
            response_raw=ex.response_raw,
            response_parsed=ex.response_parsed,
            oracle_id=oracle_id,
            why_this_proves_it=why,
        ),
    )


async def _send(client: StdioClient, probe: Probe, req: Dict[str, Any],
                timeout: float) -> Exchange:
    if probe.raw:
        return await client.send_raw(req["__raw__"], req, timeout=timeout)
    obj = {"jsonrpc": "2.0", "id": client.next_id(), "method": req["method"]}
    if "params" in req:
        obj["params"] = req["params"]
    return await client.send_object(obj, timeout=timeout, expect_id=obj["id"])



async def _confirm_alive(client: StdioClient) -> bool:
    """Round-trip a ping. Any answer -- including -32601 -- proves the process
    is still serving. Used to gate crash attribution."""
    if not client.alive:
        return False
    ex = await client.request("ping", {}, timeout=2.0)
    if ex.answered or ex.response_raw:
        return True
    await asyncio.sleep(0.2)
    return client.alive


async def _run_probes(client: StdioClient, state, ctx: ProbeContext,
                      timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    seen: set = set()

    for probe in ALL_PROBES:
        if probe.required_capability and not state.declares(probe.required_capability):
            continue
        if probe.id == "undeclared-method-exposure" and not ctx.dispatch_ok:
            continue

        try:
            requests = probe.build_requests(state, ctx)
        except Exception:  # noqa: BLE001 - a bad builder must not kill the stage
            continue

        for req in requests:
            if probe.watch_exit:
                # Attribute a crash only to the frame that actually caused it.
                # A process that died during an earlier probe may not have been
                # reaped yet, so confirm liveness with a real round trip first.
                if not await _confirm_alive(client):
                    break
            elif not client.alive:
                break
            ctx.process_alive_before = client.alive
            ctx.extra["tool_name"] = req.get("__tool__")
            ctx.extra["schema_violation"] = req.get("__violation__")

            ex = await _send(client, probe, req, min(timeout, probe.timeout))
            # give a crashing process a moment to actually die
            if probe.watch_exit:
                await asyncio.sleep(0.3)
            ctx.process_alive_after = client.alive

            probe_req = dict(req)
            probe_req["__request_json__"] = ex.request_json

            try:
                why = probe.oracle(probe_req, ex, ctx)
            except Exception:  # noqa: BLE001
                why = None

            if probe.id == "random-method-control":
                # This probe's job is to set the gate.
                if why:
                    ctx.dispatch_ok = False
                    if ex.response_raw:
                        findings.append(_finding(
                            probe.rule_id, ex, probe.id, why))
                else:
                    ctx.dispatch_ok = (
                        ex.error_code() == JSONRPC_METHOD_NOT_FOUND
                        or not ex.answered
                    )
                continue

            if not why:
                continue

            # A finding needs bytes. oracle_crash proves itself by process exit,
            # so it is allowed to use the last thing the server said instead.
            raw = ex.response_raw
            if not raw and probe.id == "malformed-frame-crash":
                raw = (
                    f"<no response; process exited with code "
                    f"{client.proc.returncode}> stderr tail:\n"
                    + client.stderr_tail(20)
                )
                ex = Exchange(request_obj=ex.request_obj,
                              request_json=ex.request_json,
                              response_raw=raw,
                              response_parsed=None)
            if not ex.response_raw:
                continue

            # One finding per rule per probe: four traversal URIs proving the
            # same escape are one vulnerability, not four.
            key = (probe.rule_id, probe.id)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_finding(
                probe.rule_id, ex, probe.id, why,
                title_suffix=str(req.get("__label__") or "")))

            if probe.id == "malformed-frame-crash" and not client.alive:
                break

    return findings


async def _run_async(info: ServerInfo, sandbox: str, timeout: int,
                     skip_install: bool) -> Tuple[List[Finding], Dict[str, Any]]:
    fail = prepare(info, sandbox=sandbox, timeout=timeout,
                   skip_install=skip_install)
    if fail:
        return [], {"ran": False, "reason": fail}

    h = await launch_and_handshake(info, sandbox=sandbox, timeout=timeout)
    if not h.ran:
        meta: Dict[str, Any] = {"ran": False, "reason": h.reason}
        meta.update(h.artifacts)
        return [], meta

    assert h.client is not None and h.state is not None
    canary_path, canary_content = _write_canary()
    ctx = make_context(canary_path, canary_content, h.state.declared_methods())

    try:
        findings = await _run_probes(h.client, h.state, ctx, float(min(timeout, 10)))
        meta = {"ran": True, "probes_run": len(ALL_PROBES)}
        meta.update(h.artifacts)
        meta["stderr_tail"] = h.client.stderr_tail(20)
        return findings, meta
    finally:
        await shutdown(h.client)
        try:
            os.unlink(canary_path)
        except OSError:
            pass


def run_dynamic(info: ServerInfo, *, sandbox: str = "none", timeout: int = 120,
                skip_install: bool = False) -> Tuple[List[Finding], Dict[str, Any]]:
    if os.name == "nt":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except AttributeError:  # pragma: no cover
            pass
    try:
        return asyncio.run(_run_async(info, sandbox, timeout, skip_install))
    except Exception as exc:  # noqa: BLE001
        return [], {"ran": False,
                    "reason": f"dynamic analysis error: {type(exc).__name__}: {exc}"}
