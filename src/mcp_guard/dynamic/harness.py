"""Dynamic harness: install, build, launch, handshake, capability discovery.

If the handshake does not succeed, the dynamic stage ends with ``ran=False``
and a reason, and emits **zero** findings. It never falls through to static
output. That fallthrough is precisely what produced the fabricated findings in
the audited version.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..execution import (
    docker_argv,
    install_command,
    install_env,
    require_docker,
    rewrite_script_command,
    warn_executing,
)
from ..execution import (
    run as run_sync,
)
from ..models import LaunchCandidate
from .transport import Exchange, StdioClient, spawn

PROTOCOL_VERSION = "2024-11-05"

# How long to wait for a server to answer initialize. Servers that work answer
# in milliseconds (measured RTTs on the corpus are 0.4-1.7ms); one that is
# still silent after this is almost always missing configuration it never
# announced. Figma-Context-MCP starts, stays silent because it wants an API
# key, and burned the full deadline on every scan.
DEFAULT_HANDSHAKE_TIMEOUT = 10.0


@dataclass
class ServerState:
    """Everything the handshake told us. Probes may use only this."""

    capabilities: Dict[str, Any] = field(default_factory=dict)
    server_name: Optional[str] = None
    server_version: Optional[str] = None
    tools: List[Dict[str, Any]] = field(default_factory=list)
    resources: List[Dict[str, Any]] = field(default_factory=list)
    init_exchange: Optional[Exchange] = None
    handshake_rtt_ms: float = 0.0

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


VENV_DIRNAME = ".mcpguard-venv"


def _venv_dir_for(root: str) -> str:
    """Where to build the ephemeral venv.

    Deliberately OUTSIDE the target tree. Creating it inside the target made
    static analysis scan pip's vendored sources and produced 265 spurious
    findings on a 2-finding fixture -- caught by the golden test. Keeping it
    out of the tree also means MCP Guard never writes into the target.
    """
    import hashlib
    import tempfile

    key = hashlib.sha256(os.path.abspath(root).encode("utf-8")).hexdigest()[:16]
    base = os.path.join(tempfile.gettempdir(), "mcpguard-venvs")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, key)


def _venv_python(venv_dir: str) -> str:
    if os.name == "nt":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")


def _failing_package(stderr: str, stdout: str):
    """Pull the package name out of a pip failure so the reason is actionable."""
    blob = (stderr or "") + "\n" + (stdout or "")
    patterns = [
        r"Could not find a version that satisfies the requirement ([A-Za-z0-9._\-\[\]]+)",
        r"No matching distribution found for ([A-Za-z0-9._\-\[\]]+)",
        r"Could not build wheels for ([A-Za-z0-9._\-, ]+)",
        r"Failed to build ([A-Za-z0-9._\- ]+)",
        r"error: subprocess-exited-with-error[\s\S]{0,200}?for ([A-Za-z0-9._\-]+)",
    ]
    for pat in patterns:
        m = re.search(pat, blob, re.I)
        if m:
            return m.group(1).strip()
    return None


def _python_prepare(info, *, timeout, sandbox, artifacts):
    """Create an ephemeral venv and install the target's dependencies into it.

    Python targets previously failed with a bare "exited immediately with code
    1" because their dependencies were simply absent. A venv per target keeps
    the host interpreter clean and lets the failure reason name the package
    that could not be installed.
    """
    root = info.root
    venv_dir = _venv_dir_for(root)
    py = _venv_python(venv_dir)

    if not os.path.exists(py):
        r = run_sync([sys.executable, "-m", "venv", venv_dir], root,
                     timeout=max(timeout, 180), sandbox=sandbox, announce=False)
        if not r.ok or not os.path.exists(py):
            return "could not create virtualenv: " + r.stderr_tail(3)[:200]
    artifacts["venv"] = venv_dir
    info.launch_python = py

    if os.path.exists(os.path.join(root, "requirements.txt")):
        target_args = ["-r", "requirements.txt"]
        artifacts["python_install_source"] = "requirements.txt"
    elif os.path.exists(os.path.join(root, "pyproject.toml")):
        target_args = ["."]
        artifacts["python_install_source"] = "pyproject.toml"
    else:
        artifacts["python_install_source"] = "none"
        return None

    base = [py, "-m", "pip", "install", "--disable-pip-version-check", "-q"]
    # Wheels only first: that avoids executing arbitrary setup.py build backends.
    r = run_sync(base + ["--only-binary", ":all:"] + target_args, root,
                 timeout=max(timeout, 300), sandbox=sandbox)
    artifacts["python_install_mode"] = "wheels-only"
    if not r.ok:
        pkg = _failing_package(r.stderr, r.stdout)
        artifacts["python_install_wheels_only_failed"] = pkg or "unknown"
        # Retry allowing source builds. docs/SECURITY.md documents this gap.
        r2 = run_sync(base + target_args, root, timeout=max(timeout, 300),
                      sandbox=sandbox)
        artifacts["python_install_mode"] = "source-builds-allowed"
        if not r2.ok:
            pkg2 = _failing_package(r2.stderr, r2.stdout) or pkg
            detail = (r2.stderr_tail(3) or r2.stdout[-200:]).strip()
            if pkg2:
                return ("dependency install failed for package " + repr(pkg2) +
                        " (pip rc=" + str(r2.returncode) + "): " + detail[:180])
            return ("dependency install failed (pip rc=" + str(r2.returncode) +
                    "): " + detail[:200])
    return None


TOOLCHAIN = {"nodejs": "node", "go": "go", "python": None}


def _toolchain_missing(info, art):
    """A clear reason beats a FileNotFoundError from deep in the stack."""
    need = TOOLCHAIN.get(info.server_type)
    if need and shutil.which(need) is None:
        art["toolchain"] = need + " not found on PATH"
        return (info.server_type + " target requires the " + repr(need) +
                " toolchain, which is not installed on this machine")
    return None


def prepare(info, *, sandbox, timeout, skip_install=False, artifacts=None):
    """Install dependencies. Return a failure reason, or None on success.

    Building moved out of here and became per-candidate: only some candidates
    need a build, and a build failure should not sink candidates that do not
    depend on it.
    """
    art = artifacts if artifacts is not None else {}
    root = info.root

    missing = _toolchain_missing(info, art)
    if missing:
        return missing

    if skip_install:
        art["install"] = "skipped (--skip-install)"
        if info.server_type == "python":
            venv_py = _venv_python(_venv_dir_for(root))
            if os.path.exists(venv_py):
                info.launch_python = venv_py
        return None

    if info.server_type == "python":
        return _python_prepare(info, timeout=timeout, sandbox=sandbox,
                               artifacts=art)

    if info.server_type == "nodejs" and os.path.isdir(
            os.path.join(root, "node_modules")):
        art["install"] = "skipped (node_modules already present)"
        return None

    inst = install_command(info.server_type, root)
    if not inst:
        art["install"] = "no install step for this target type"
        return None

    r = run_sync(_resolve_argv(inst, root), root, timeout=max(timeout, 300),
                 env=install_env(info.server_type), sandbox=sandbox)
    art["install"] = " ".join(inst)
    if not r.ok:
        detail = (r.stderr_tail(3) or r.stdout[-200:]).strip()
        if r.timed_out:
            return "dependency install timed out"
        # Not fatal: dependencies may be vendored. Record and continue.
        art["install_warning"] = "rc=" + str(r.returncode) + ": " + detail[:180]
    return None


def _build_for(info, candidate, *, timeout, sandbox, artifacts):
    """Run the target's build.

    `npm run build` is preferred when a build script exists, because npm puts
    the target's own node_modules/.bin on PATH and handles shell operators --
    a script like `rm -rf dist && tsup src/index.ts` cannot be reduced to a
    single argv. Rewriting it against .bin ourselves broke exactly that case.

    We fall back to resolving the tool from node_modules/.bin, then the npx
    cache, only when npm is unavailable. Whichever was used is recorded in
    stage artifacts, so a report always says which toolchain actually ran; a
    global toolchain is never used silently.
    """
    root = info.root
    pkg = {}
    pj = os.path.join(root, "package.json")
    if os.path.exists(pj):
        try:
            with open(pj, encoding="utf-8") as fh:
                pkg = json.load(fh)
        except Exception:
            pkg = {}
    scripts = pkg.get("scripts") or {}
    script = scripts.get("build")

    if isinstance(script, str) and script.strip():
        npm = shutil.which("npm") or (shutil.which("npm.cmd")
                                      if os.name == "nt" else None)
        if npm:
            argv = [npm, "run", "build"]
            provenance = "npm run build (npm puts node_modules/.bin on PATH)"
        else:
            rewritten = rewrite_script_command(root, script)
            if not rewritten:
                return ("npm is not available and the build tool " +
                        repr(script.split()[0]) + " is not in the target's "
                        "node_modules/.bin or the npx cache")
            argv, provenance = rewritten
    elif info.build_argv:
        argv = _resolve_argv(list(info.build_argv), root)
        provenance = " ".join(info.build_argv)
    else:
        # Nothing declares a build. Say so rather than running `npm run build`
        # against a package that has no such script.
        artifacts["build"] = "no build script declared"
        return ("candidate needs a build but package.json declares no build "
                "script")

    r = run_sync(argv, root, timeout=max(timeout, 300),
                 env=install_env(info.server_type), sandbox=sandbox)
    artifacts["build_tool"] = provenance
    artifacts["build_rc"] = r.returncode
    if not r.ok:
        detail = (r.stderr_tail(4) or r.stdout[-300:]).strip()
        tool = script.split()[0] if isinstance(script, str) and script else "build"
        low = detail.lower()
        if "is not recognized" in low or "command not found" in low:
            missing = tool
            for tok in (script or "").split():
                if tok.lower() in low.replace("'", ""):
                    missing = tok
                    break
            return ("build tool " + repr(missing) + " is not installed; it is "
                    "not in the target's node_modules/.bin and not on PATH")
        return ("build failed (" + provenance + " -> rc=" + str(r.returncode) +
                "): " + detail[:220])
    return None


async def _try_one(info, candidate, *, sandbox, timeout, artifacts,
                   handshake_timeout=DEFAULT_HANDSHAKE_TIMEOUT):
    """Launch one candidate and handshake. Returns HarnessResult."""
    root = info.root
    argv = list(candidate.argv)

    if candidate.requires_build:
        fail = _build_for(info, candidate, timeout=timeout, sandbox=sandbox,
                          artifacts=artifacts)
        if fail:
            return HarnessResult(False, fail, artifacts=dict(artifacts))
        abs_entry = os.path.join(root, argv[-1]) if len(argv) > 1 else None
        if abs_entry and not os.path.exists(abs_entry):
            return HarnessResult(
                False,
                "build succeeded but " + argv[-1] + " still does not exist",
                artifacts=dict(artifacts))

    # A venv interpreter, when prepare() made one, replaces bare "python".
    if argv and argv[0] == "python" and info.launch_python:
        argv[0] = info.launch_python

    if sandbox == "docker":
        image = require_docker(info.server_type)
        argv = docker_argv(image, root, argv, network=False)
    else:
        argv = _resolve_argv(argv, root)

    warn_executing(argv, root, sandbox)

    try:
        proc = await spawn(argv, root)
    except FileNotFoundError as exc:
        return HarnessResult(False, "could not launch: " + str(exc),
                             artifacts=dict(artifacts))
    except Exception as exc:
        return HarnessResult(
            False, "could not launch: " + type(exc).__name__ + ": " + str(exc),
            artifacts=dict(artifacts))

    client = StdioClient(proc)
    client.start_stderr_pump()

    await asyncio.sleep(0.35)
    if proc.returncode is not None:
        tail = client.stderr_tail(20)
        await client.close()
        return HarnessResult(
            False,
            "server exited immediately with code " + str(proc.returncode) +
            " before any request was sent",
            artifacts=dict(artifacts, exit_code=proc.returncode,
                           stderr_tail=tail, launch_argv=" ".join(argv)),
        )

    state = ServerState()
    t0 = time.perf_counter()
    init = await client.request(
        "initialize",
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
         "clientInfo": {"name": "mcp-guard", "version": "2.0.0"}},
        timeout=min(float(handshake_timeout), float(timeout)),
    )
    rtt_ms = (time.perf_counter() - t0) * 1000
    state.init_exchange = init
    state.handshake_rtt_ms = rtt_ms

    def fail(reason, **extra):
        return HarnessResult(False, reason,
                             artifacts=dict(artifacts, launch_argv=" ".join(argv),
                                            **extra))

    if init.timed_out:
        tail = client.stderr_tail(20)
        rc = proc.returncode
        await shutdown(client)
        return fail(
            f"handshake failed: no answer to initialize within "
            f"{min(float(handshake_timeout), float(timeout)):.0f}s. The process "
            f"is running but silent, which usually means it needs "
            f"configuration it did not announce (an API key, a database URL). "
            f"Raise --handshake-timeout if the server is simply slow to boot.",
            exit_code=rc, stderr_tail=tail)
    if init.transport_error:
        tail = client.stderr_tail(20)
        rc = proc.returncode
        await shutdown(client)
        return fail("handshake failed: " + init.transport_error,
                    exit_code=rc, stderr_tail=tail)
    if init.result() is None:
        err = init.error()
        tail = client.stderr_tail(20)
        await shutdown(client)
        return fail("handshake failed: server answered initialize with " +
                    ("error " + str(err) if err else "no result"),
                    stderr_tail=tail, init_response=init.response_raw.strip())

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
        True, None, client=client, state=state,
        artifacts=dict(
            artifacts,
            launch_argv=" ".join(argv),
            launch_source=candidate.source,
            handshake_rtt_ms=round(rtt_ms, 1),
            server_name=state.server_name,
            capabilities=sorted(state.capabilities.keys()),
            tools_discovered=len(state.tools),
            resources_discovered=len(state.resources),
        ),
    )


async def launch_and_handshake(info, *, sandbox, timeout, artifacts=None,
                               handshake_timeout=DEFAULT_HANDSHAKE_TIMEOUT):
    """Try every derived candidate in order until one handshakes.

    The audited version had a single guessed command and gave up. Candidates
    come from the target's own metadata, and each attempt is logged, so a
    failure report names what was tried and why each one lost.
    """
    art = dict(artifacts or {})
    candidates = list(info.launch_candidates)
    if not candidates and info.launch_argv:
        candidates = [LaunchCandidate("derived", list(info.launch_argv))]

    if not candidates:
        return HarnessResult(
            False, "no launch command could be derived from target metadata",
            artifacts=art)

    attempts = []
    art["candidates_tried"] = attempts
    last_artifacts = {}
    for cand in candidates[:6]:
        result = await _try_one(info, cand, sandbox=sandbox, timeout=timeout,
                                artifacts=art,
                                handshake_timeout=handshake_timeout)
        attempts.append({
            "source": cand.source,
            "argv": " ".join(cand.argv),
            "ok": result.ran,
            "reason": result.reason,
        })
        if result.ran:
            result.artifacts["candidates_tried"] = attempts
            return result
        last_artifacts = result.artifacts or {}

    # Carry the last attempt's diagnostics up: exit_code and stderr_tail are
    # what a user needs when nothing launched, and they live on the attempt.
    merged = dict(art)
    for k, v in last_artifacts.items():
        if k != "candidates_tried":
            merged.setdefault(k, v)
    merged["candidates_tried"] = attempts

    last = attempts[-1]["reason"] if attempts else "no candidate ran"
    if len(attempts) == 1:
        reason = str(last)
    else:
        reason = ("all " + str(len(attempts)) + " derived launch candidate(s) "
                  "failed; last: " + str(last))
    return HarnessResult(False, reason, artifacts=merged)


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
