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
import time
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



def probe_timeout(probe, rtt_ms: float) -> float:
    """Per-probe deadline derived from the observed handshake round trip.

    A server that answers initialize in 4ms does not need an 8s budget for the
    next request. The baseline spent 8 of clean-server's 10s waiting out fixed
    timeouts on probes that expect no answer at all (jsonrpc-conformance
    4,024ms over 5 sends, malformed-frame-crash 4,015ms over 5).

    20x the handshake RTT with a 250ms floor absorbs ordinary jitter and a
    cold first call; the probe's own declared timeout stays the ceiling, so a
    slow server is never given less than before.
    """
    if rtt_ms <= 0:
        return probe.timeout
    derived = max(0.25, (rtt_ms * 20) / 1000.0)
    return min(probe.timeout, derived)


async def _confirm_alive(client: StdioClient, timeout: float = 2.0) -> bool:
    """Round-trip a ping. Any answer -- including -32601 -- proves the process
    is still serving. Used once on transition, not before every probe."""
    if not client.alive:
        return False
    ex = await client.request("ping", {}, timeout=timeout)
    if ex.answered or ex.response_raw:
        return True
    await asyncio.sleep(0.15)
    return client.alive


DEFAULT_PROBE_BUDGET = 30.0


async def _run_probes(client: StdioClient, state, ctx: ProbeContext,
                      base_timeout: float, rtt_ms: float,
                      window: int = 4,
                      budget_s: float = DEFAULT_PROBE_BUDGET,
                      report: Optional[Dict[str, Any]] = None) -> List[Finding]:
    """Run the probe set, pipelining what is safe to pipeline.

    JSON-RPC permits several in-flight requests with distinct ids, and the
    transport correlates by id, so capability-gated probes are sent
    concurrently with a bounded window. Probes with watch_exit=True stay
    strictly serial: a crash has to be attributable to one frame, and
    overlapping sends would make that ambiguous.
    """
    findings: List[Finding] = []
    seen: set = set()
    dead = False

    # A real server's tools do real work: an Airbnb search tool makes an HTTP
    # request, and a probe against it waits out the full ceiling. Measured,
    # probing mcp-server-airbnb spent 35.5s of a 46s dynamic stage inside
    # tools/call. The budget bounds that, and what it skipped is reported --
    # an unrun probe is stated, never assumed negative.
    started = time.monotonic()
    skipped: List[str] = []

    def out_of_budget() -> bool:
        return (time.monotonic() - started) > budget_s

    def record(probe, req, ex, why):
        key = (probe.rule_id, probe.id)
        if key in seen or not why:
            return
        raw = ex.response_raw
        if not raw:
            return
        seen.add(key)
        findings.append(_finding(
            probe.rule_id, ex, probe.id, why,
            title_suffix=str(req.get("__label__") or "")))

    for probe in ALL_PROBES:
        if dead:
            break
        if probe.required_capability and not state.declares(probe.required_capability):
            continue
        if probe.id == "undeclared-method-exposure" and not ctx.dispatch_ok:
            continue
        if out_of_budget():
            skipped.append(probe.id)
            continue

        try:
            requests = probe.build_requests(state, ctx)
        except Exception:  # noqa: BLE001 - a bad builder must not kill the stage
            continue
        if not requests:
            continue

        timeout = min(base_timeout, probe_timeout(probe, rtt_ms))

        # ---- serial path: crash probes need clean attribution ----
        if probe.watch_exit:
            for req in requests:
                if out_of_budget():
                    skipped.append(f"{probe.id} (budget)")
                    break
                if not await _confirm_alive(client, timeout=max(0.5, timeout)):
                    dead = True
                    break
                ctx.process_alive_before = True
                ex = await _send(client, probe, req, timeout)
                await asyncio.sleep(0.25)
                ctx.process_alive_after = client.alive

                probe_req = dict(req, __request_json__=ex.request_json)
                try:
                    why = probe.oracle(probe_req, ex, ctx)
                except Exception:  # noqa: BLE001
                    why = None
                if why and not ex.response_raw:
                    ex = Exchange(
                        request_obj=ex.request_obj,
                        request_json=ex.request_json,
                        response_raw=(
                            "<no response; process exited with code "
                            + str(client.proc.returncode) + "> stderr tail:\n"
                            + client.stderr_tail(20)),
                        response_parsed=None)
                record(probe, req, ex, why)
                if not client.alive:
                    dead = True
                    break
            continue

        # ---- pipelined path ----
        if not client.alive:
            dead = True
            break

        results = []
        for i in range(0, len(requests), window):
            if out_of_budget():
                skipped.append(f"{probe.id} ({len(requests) - i} requests)")
                break
            chunk = requests[i:i + window]
            sent = [_send(client, probe, r, timeout) for r in chunk]
            try:
                exchanges = await asyncio.gather(*sent, return_exceptions=True)
            except Exception:  # noqa: BLE001
                break
            for req, ex in zip(chunk, exchanges):
                if isinstance(ex, BaseException):
                    continue
                results.append((req, ex))
            if not client.alive:
                dead = True
                break

        for req, ex in results:
            ctx.extra["tool_name"] = req.get("__tool__")
            ctx.extra["schema_violation"] = req.get("__violation__")
            probe_req = dict(req, __request_json__=ex.request_json)
            try:
                why = probe.oracle(probe_req, ex, ctx)
            except Exception:  # noqa: BLE001
                why = None

            if probe.id == "random-method-control":
                if why:
                    ctx.dispatch_ok = False
                    record(probe, req, ex, why)
                else:
                    ctx.dispatch_ok = (
                        ex.error_code() == JSONRPC_METHOD_NOT_FOUND
                        or not ex.answered)
                continue

            record(probe, req, ex, why)

    if report is not None and skipped:
        report["probes_skipped_budget"] = sorted(set(skipped))
        report["probe_budget_s"] = budget_s
    return findings


async def _run_async(info: ServerInfo, sandbox: str, timeout: int,
                     skip_install: bool, probe_budget: float,
                     handshake_timeout: float
                     ) -> Tuple[List[Finding], Dict[str, Any]]:
    art: Dict[str, Any] = {}
    fail = prepare(info, sandbox=sandbox, timeout=timeout,
                   skip_install=skip_install, artifacts=art)
    if fail:
        return [], dict(art, ran=False, reason=fail)

    h = await launch_and_handshake(info, sandbox=sandbox, timeout=timeout,
                                   artifacts=art,
                                   handshake_timeout=handshake_timeout)
    if not h.ran:
        meta: Dict[str, Any] = {"ran": False, "reason": h.reason}
        meta.update(h.artifacts)
        return [], meta

    assert h.client is not None and h.state is not None
    canary_path, canary_content = _write_canary()
    ctx = make_context(canary_path, canary_content, h.state.declared_methods())

    try:
        rtt = getattr(h.state, "handshake_rtt_ms", 0.0)
        probe_report: Dict[str, Any] = {}
        findings = await _run_probes(h.client, h.state, ctx,
                                     float(min(timeout, 10)), rtt,
                                     budget_s=probe_budget,
                                     report=probe_report)
        meta = {"ran": True, "probes_run": len(ALL_PROBES),
                "handshake_rtt_ms": round(rtt, 1)}
        meta.update(probe_report)
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
                skip_install: bool = False,
                probe_budget: float = DEFAULT_PROBE_BUDGET,
                handshake_timeout: float = 10.0
                ) -> Tuple[List[Finding], Dict[str, Any]]:
    if os.name == "nt":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except AttributeError:  # pragma: no cover
            pass
    try:
        return asyncio.run(_run_async(info, sandbox, timeout, skip_install,
                                      probe_budget, handshake_timeout))
    except Exception as exc:  # noqa: BLE001
        return [], {"ran": False,
                    "reason": f"dynamic analysis error: {type(exc).__name__}: {exc}"}
