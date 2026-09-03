"""Scan orchestration.

Each stage records a ScanStatus whether it ran or not. A stage that cannot run
contributes zero findings and says why. No stage ever substitutes another
stage's output, and no finding is relabelled across stages.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__
from .acquire import AcquireError, Acquired, acquire
from .detect import detect
from .models import Finding, ScanResult, ScanStatus


class Stage:
    """Times a stage and guarantees a status is recorded even on exception."""

    def __init__(self, result: ScanResult, name: str):
        self.result = result
        self.name = name
        self.t0 = 0.0
        self.ran = False
        self.reason: Optional[str] = None
        self.artifacts: dict = {}

    def __enter__(self) -> "Stage":
        self.t0 = time.time()
        return self

    def skip(self, reason: str) -> None:
        self.ran = False
        self.reason = reason

    def done(self, **artifacts) -> None:
        self.ran = True
        self.artifacts.update(artifacts)

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None:
            self.ran = False
            self.reason = f"{exc_type.__name__}: {exc}"
        self.result.set_status(ScanStatus(
            stage=self.name,
            ran=self.ran,
            reason=self.reason,
            duration_s=time.time() - self.t0,
            artifacts=self.artifacts,
        ))
        return exc_type is not None and issubclass(exc_type, Exception)


def run_scan(
    target: str,
    *,
    allow_execute: bool = False,
    sandbox: str = "none",
    static_enabled: bool = True,
    deps_enabled: bool = True,
    offline: bool = False,
    timeout: int = 120,
    skip_install: bool = False,
    entrypoint: Optional[str] = None,
) -> tuple[ScanResult, Optional[Acquired]]:
    result = ScanResult(
        target=target,
        tool_version=__version__,
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    acquired: Optional[Acquired] = None

    # ---------------- acquire ----------------
    with Stage(result, "acquire") as st:
        acquired = acquire(target)
        result.target_commit = acquired.commit
        st.done(root=acquired.root)
    if acquired is None:
        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result, None

    root = acquired.root

    # ---------------- detect ----------------
    with Stage(result, "detect") as st:
        info = detect(root)
        result.server_info = info
        st.done(
            server_type=info.server_type,
            is_mcp_server=info.is_mcp_server,
            entrypoint=info.entrypoint,
            notes=info.detection_notes,
        )

    info = result.server_info

    if entrypoint and info is not None:
        from .models import LaunchCandidate
        argv = entrypoint.split() if " " in entrypoint else None
        if argv is None:
            argv = (["python", entrypoint] if entrypoint.endswith(".py")
                    else ["node", entrypoint])
        override = LaunchCandidate("--entrypoint override", argv)
        info.launch_candidates = [override] + list(info.launch_candidates)
        info.launch_argv = list(argv)
        info.entrypoint = f"--entrypoint: {entrypoint}"

    # ---------------- static ----------------
    with Stage(result, "static") as st:
        if not static_enabled:
            st.skip("disabled by --no-static")
        elif info is None:
            st.skip("detection did not complete")
        else:
            from .static import run_static
            found: List[Finding] = run_static(info)
            result.findings.extend(found)
            st.done(findings=len(found))

    # ---------------- dependencies ----------------
    with Stage(result, "dependencies") as st:
        if not deps_enabled:
            st.skip("disabled by --no-deps")
        elif info is None:
            st.skip("detection did not complete")
        elif offline:
            st.skip("offline mode: OSV lookup skipped")
        else:
            from .deps import run_dependencies
            found = run_dependencies(info)
            result.findings.extend(found)
            st.done(findings=len(found))

    # ---------------- dynamic ----------------
    with Stage(result, "dynamic") as st:
        if not allow_execute:
            st.skip("requires --allow-execute")
        elif info is None:
            st.skip("detection did not complete")
        elif info.server_type == "docker":
            st.skip(
                "Docker targets are analysed statically only: MCP Guard reads "
                "the Dockerfile and does not build or run target images. See "
                "the limits section of the README."
            )
        elif not info.is_mcp_server and not entrypoint:
            st.skip(
                "detect found no MCP server here (nothing declares an MCP "
                "dependency), so dynamic analysis is not applicable; pass "
                "--entrypoint to override"
            )
        elif not info.launch_argv:
            note = "; ".join(info.detection_notes) or "no launch command"
            st.skip(
                f"no launch command could be derived from target metadata "
                f"({note})"
            )
            st.artifacts["candidates_considered"] = [
                c.as_dict() for c in info.launch_candidates
            ]
        else:
            from .dynamic import run_dynamic
            found, meta = run_dynamic(info, sandbox=sandbox, timeout=timeout,
                                      skip_install=skip_install)
            if meta.get("ran"):
                result.findings.extend(found)
                st.done(**{k: v for k, v in meta.items() if k != "ran"})
            else:
                st.skip(meta.get("reason", "dynamic analysis did not run"))
                st.artifacts.update(
                    {k: v for k, v in meta.items() if k not in ("ran", "reason")}
                )

    result.finished_at = datetime.now(timezone.utc).isoformat()
    return result, acquired
