"""Controlled execution of target code.

Everything in this module runs code MCP Guard did not write. It is the only
place in the codebase permitted to do so, and it is reachable only when the
caller passed --allow-execute.

Guarantees:

  * npm dependency installation always passes --ignore-scripts, so a target's
    preinstall/install/postinstall hooks never run. The previous version ran a
    bare `npm install`, which executes those hooks as the invoking user.
  * Every subprocess has a hard timeout.
  * On timeout the whole process *tree* is killed, not just the direct child.
    A shell that spawned a server that spawned a worker leaves nothing behind.
  * A one-line warning naming the exact argv goes to stderr before anything runs.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

DEFAULT_TIMEOUT = 120


class SandboxUnavailable(RuntimeError):
    """Raised when --sandbox docker was requested but docker cannot be used.

    Never downgraded silently: asking for isolation and getting none is worse
    than being told no.
    """


@dataclass
class RunResult:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def stderr_tail(self, n: int = 20) -> str:
        return "\n".join(self.stderr.splitlines()[-n:])


def warn_executing(argv: Sequence[str], cwd: str, sandbox: str) -> None:
    where = "docker" if sandbox == "docker" else "this machine"
    print(
        f"mcp-guard: WARNING executing target code on {where}: "
        f"{' '.join(argv)}  (cwd={cwd})",
        file=sys.stderr,
    )


def kill_tree(proc: subprocess.Popen) -> None:
    """Kill a process and everything it spawned."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=15,
            )
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=10)
    except Exception:
        pass


def popen_kwargs() -> Dict[str, object]:
    """Platform flags that make a child its own killable group."""
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def run(
    argv: Sequence[str],
    cwd: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    env: Optional[Dict[str, str]] = None,
    sandbox: str = "none",
    announce: bool = True,
) -> RunResult:
    """Run a command to completion with a hard timeout and tree kill."""
    argv = list(argv)
    if announce:
        warn_executing(argv, cwd, sandbox)

    full_env = dict(os.environ)
    if env:
        full_env.update(env)

    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=full_env,
        **popen_kwargs(),  # type: ignore[arg-type]
    )
    try:
        out, err = proc.communicate(timeout=timeout)
        return RunResult(argv, proc.returncode, out or "", err or "")
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = "", ""
        return RunResult(argv, -9, out or "", err or "", timed_out=True)


# ---------------------------------------------------------------------------
# Dependency installation -- scripts disabled, always
# ---------------------------------------------------------------------------


def install_command(server_type: str, root: str) -> Optional[List[str]]:
    """The install argv for a target, or None if no install step is needed."""
    if server_type == "nodejs":
        has_lock = os.path.exists(os.path.join(root, "package-lock.json"))
        base = ["npm", "ci"] if has_lock else ["npm", "install"]
        # --ignore-scripts is non-negotiable: it is what stops a hostile target
        # from running arbitrary code during installation.
        return base + ["--ignore-scripts", "--no-audit", "--no-fund"]
    if server_type == "go":
        return ["go", "mod", "download"]
    if server_type == "python":
        req = os.path.join(root, "requirements.txt")
        if os.path.exists(req):
            # --no-build-isolation avoids invoking arbitrary build backends where
            # a wheel is available; setup.py execution cannot be fully avoided
            # for sdist-only packages, which is documented in docs/SECURITY.md.
            return [sys.executable, "-m", "pip", "install", "--only-binary", ":all:",
                    "-r", "requirements.txt"]
    return None


def install_env(server_type: str) -> Dict[str, str]:
    if server_type == "go":
        return {"GOFLAGS": "-mod=mod", "CGO_ENABLED": "0"}
    if server_type == "nodejs":
        return {"npm_config_ignore_scripts": "true", "NPM_CONFIG_FUND": "false"}
    return {}


# ---------------------------------------------------------------------------
# Docker sandbox
# ---------------------------------------------------------------------------

DOCKER_IMAGE = {
    "nodejs": "node:20-alpine",
    "python": "python:3.11-alpine",
    "go": "golang:1.22-alpine",
}


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=20)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def require_docker(server_type: str) -> str:
    """Return the image for this target, or raise. Never downgrades to none."""
    if not docker_available():
        raise SandboxUnavailable(
            "--sandbox docker was requested but docker is not available "
            "(binary missing or daemon unreachable). Refusing to downgrade to "
            "--sandbox none, which would execute target code directly on this "
            "machine."
        )
    image = DOCKER_IMAGE.get(server_type)
    if image is None:
        raise SandboxUnavailable(
            f"no sandbox image defined for server type {server_type!r}"
        )
    return image


def docker_argv(
    image: str,
    root: str,
    inner_argv: Sequence[str],
    *,
    network: bool,
    workdir: str = "/work",
) -> List[str]:
    """Build the docker run argv.

    The target is mounted read-only; the writable area is a tmpfs that vanishes
    with the container. --network none is used for the launch step so a target
    cannot exfiltrate during fuzzing.
    """
    argv = [
        "docker", "run", "--rm", "-i",
        "--user", "1000:1000",
        "--memory", "512m",
        "--pids-limit", "256",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", f"{workdir}:rw,exec,size=256m",
        "-v", f"{os.path.abspath(root)}:/src:ro",
        "-w", workdir,
    ]
    if not network:
        argv += ["--network", "none"]
    argv += [image, "sh", "-c",
             "cp -a /src/. " + workdir + " 2>/dev/null; " + " ".join(inner_argv)]
    return argv
