"""Dynamic harness: install, build, launch, handshake, capability discovery.

If the handshake does not succeed, the dynamic stage ends with ``ran=False``
and a reason, and emits **zero** findings. It never falls through to static
output. That fallthrough is precisely what produced the fabricated findings in
the audited version.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..execution import (
    RunResult,
    SandboxUnavailable,
    docker_argv,
    install_command,
    install_env,
    kill_tree,
    require_docker,
    run as run_sync,
    warn_executing,
)
from ..models import ServerInfo
from .transport import Exchange, StdioClient, spawn

PROTOCOL_VERSION = "2024-11-05"


@dataclass
class ServerState:
    """Everything the handshake told us. Probes may use only this."""

    capabilities: Dict[str, Any] = field(default_factory=dict)
    server_name: Optional[str] = None
    server_version: Optional[str] = None
    tools: List[Dict[str, Any]] = field(default_factory=list)
    resources: List[Dict[str, Any]] = field(default_factory=list)
    init_exchange: Optional[Exchange] = None

    def declares(self, capability: str) -> bool:
        """True only if the server actually advertised this capability."""
        if capability == "tools":
            return "tools" in self.capabilities
        if capability == "resources":
            return "resources" in self.capabilities
        if capability == "prompts":
            return "prompts" in self.capabilities
        return False

    def declared_methods(self) -> set:
        m = {"initialize", "ping"}
        if self.declares("tools"):
            m |= {"tools/list", "tools/call"}
        if self.declares("resources"):
            m |= {"resources/list", "resources/read", "resources/templates/list"}
        if self.declares("prompts"):
            m |= {"prompts/list", "prompts/get"}
        return m

    def tool_names(self) -> List[str]:
        return [t.get("name") for t in self.tools if isinstance(t.get("name"), str)]


@dataclass
class HarnessResult:
    ran: bool
    reason: Optional[str] = None
    client: Optional[StdioClient] = None
    state: Optional[ServerState] = None
    artifacts: Dict[str, Any] = field(default_factory=dict)


def _resolve_argv(argv: List[str], root: str) -> List[str]:
    """Resolve npm/node/go to absolute paths where the platform needs it."""
    if not argv:
        return argv
    exe = argv[0]
    if os.name == "nt" and exe in ("npm", "npx", "yarn", "pnpm"):
        found = shutil.which(exe) or shutil.which(exe + ".cmd")
        if found:
            return [found] + argv[1:]
    if exe == "python":
        return [sys.executable] + argv[1:]
    found = shutil.which(exe)
    if found:
        return [found] + argv[1:]
    return argv


def prepare(info: ServerInfo, *, sandbox: str, timeout: int,
            skip_install: bool = False) -> Optional[str]:
    """Install and build. Return a failure reason, or None on success."""
    root = info.root

    have_modules = os.path.isdir(os.path.join(root, "node_modules"))
    inst = None if (skip_install or have_modules) else install_command(
        info.server_type, root)
    if inst:
        r = run_sync(_resolve_argv(inst, root), root, timeout=timeout,
                     env=install_env(info.server_type), sandbox=sandbox)
        if not r.ok:
            detail = r.stderr_tail(5) or r.stdout[-300:]
            if r.timed_out:
                return f"dependency install timed out after {timeout}s"
            # A failed install is not necessarily fatal (deps may be vendored);
            # record it and continue to the launch attempt.
            info.detection_notes.append(
                f"install returned {r.returncode}: {detail[:200]}"
            )

    if info.build_argv:
        r = run_sync(_resolve_argv(info.build_argv, root), root, timeout=timeout,
                     env=install_env(info.server_type), sandbox=sandbox)
        if not r.ok:
            return (
                f"build failed ({' '.join(info.build_argv)} -> rc={r.returncode}): "
                f"{r.stderr_tail(5)[:300]}"
            )
    return None


async def launch_and_handshake(
    info: ServerInfo, *, sandbox: str, timeout: int
) -> HarnessResult:
    root = info.root
    argv = list(info.launch_argv or [])
    if not argv:
        return HarnessResult(False, "no launch command derived from target metadata")

    if sandbox == "docker":
        image = require_docker(info.server_type)  # raises if unavailable
        argv = docker_argv(image, root, argv, network=False)
    else:
        argv = _resolve_argv(argv, root)

    warn_executing(argv, root, sandbox)

    try:
        proc = await spawn(argv, root)
    except FileNotFoundError as exc:
        return HarnessResult(False, f"could not launch server: {exc}")
    except Exception as exc:  # noqa: BLE001
        return HarnessResult(False, f"could not launch server: {type(exc).__name__}: {exc}")

    client = StdioClient(proc)
    client.start_stderr_pump()

    # Give the process a moment; catch immediate exits explicitly.
    await asyncio.sleep(0.4)
    if proc.returncode is not None:
        tail = client.stderr_tail(20)
        await client.close()
        return HarnessResult(
            False,
            f"server exited immediately with code {proc.returncode} before any "
            f"request was sent",
            artifacts={
                "exit_code": proc.returncode,
                "stderr_tail": tail,
                "launch_argv": " ".join(argv),
            },
        )

    state = ServerState()

    init = await client.request(
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-guard", "version": "2.0.0"},
        },
        timeout=min(15.0, float(timeout)),
    )
    state.init_exchange = init

    if init.timed_out:
        tail = client.stderr_tail(20)
        rc = proc.returncode
        await shutdown(client)
        return HarnessResult(
            False,
            "handshake failed: server did not answer initialize within the deadline",
            artifacts={"exit_code": rc, "stderr_tail": tail,
                       "launch_argv": " ".join(argv)},
        )
    if init.transport_error:
        tail = client.stderr_tail(20)
        rc = proc.returncode
        await shutdown(client)
        return HarnessResult(
            False, f"handshake failed: {init.transport_error}",
            artifacts={"exit_code": rc, "stderr_tail": tail,
                       "launch_argv": " ".join(argv)},
        )
    if init.result() is None:
        err = init.error()
        tail = client.stderr_tail(20)
        await shutdown(client)
        return HarnessResult(
            False,
            "handshake failed: server answered initialize with "
            + (f"error {err}" if err else "no result"),
            artifacts={"stderr_tail": tail, "init_response": init.response_raw.strip(),
                       "launch_argv": " ".join(argv)},
        )

    res = init.result() or {}
    state.capabilities = res.get("capabilities") or {}
    si = res.get("serverInfo") or {}
    state.server_name = si.get("name")
    state.server_version = si.get("version")

    await client.notify("notifications/initialized")

    if state.declares("tools"):
        ex = await client.request("tools/list", {}, timeout=8.0)
        r = ex.result()
        if isinstance(r, dict) and isinstance(r.get("tools"), list):
            state.tools = [t for t in r["tools"] if isinstance(t, dict)]

    if state.declares("resources"):
        ex = await client.request("resources/list", {}, timeout=8.0)
        r = ex.result()
        if isinstance(r, dict) and isinstance(r.get("resources"), list):
            state.resources = [x for x in r["resources"] if isinstance(x, dict)]

    return HarnessResult(
        True,
        None,
        client=client,
        state=state,
        artifacts={
            "launch_argv": " ".join(argv),
            "server_name": state.server_name,
            "capabilities": sorted(state.capabilities.keys()),
            "tools_discovered": len(state.tools),
            "resources_discovered": len(state.resources),
        },
    )


async def shutdown(client: Optional[StdioClient]) -> None:
    if client is None:
        return
    await client.close()
    proc = client.proc
    if proc.returncode is None:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            try:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass
