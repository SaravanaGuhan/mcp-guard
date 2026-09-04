"""Core types for MCP Guard.

THE ONE RULE: no Finding may exist without the evidence that produced it.

This is enforced structurally, not by convention:

  * ``Finding.evidence`` is a required field with no default. Omitting it is a
    ``TypeError`` from the generated ``__init__``; passing ``None`` or a
    non-Evidence object raises in ``__post_init__``.
  * Every Evidence subclass is frozen and carries *raw observed data* -- the
    literal bytes read from a server, or the literal source text sliced out of
    a file -- never a prose description of that data.
  * ``DynamicEvidence.response_raw`` is set only by the transport layer.
    Detection rules receive it; they never construct it.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

SCHEMA_VERSION = "2.0.0"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class Evidence:
    """Marker base. Only the three concrete subclasses below are permitted."""

    kind: str = "abstract"

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)  # type: ignore[arg-type]
        d["kind"] = self.kind
        return d


@dataclass(frozen=True)
class StaticEvidence(Evidence):
    """Evidence sliced out of a file on disk.

    ``matched_source`` is the literal text at ``file``:``line``:``column``. It
    is not a summary and not a reconstruction -- callers slice it from the same
    buffer they parsed.
    """

    file: str
    line: int
    column: int
    matched_source: str
    rule_id: str

    kind: str = field(default="static", init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.file:
            raise ValueError("StaticEvidence.file must be a non-empty path")
        if self.line < 1:
            raise ValueError(f"StaticEvidence.line must be 1-based, got {self.line}")
        if not self.matched_source:
            raise ValueError(
                "StaticEvidence.matched_source must be the literal matched text, "
                "not empty -- a finding with no source slice is not evidence"
            )
        if not self.rule_id:
            raise ValueError("StaticEvidence.rule_id must be set")


@dataclass(frozen=True)
class DynamicEvidence(Evidence):
    """Evidence observed on the wire.

    ``response_raw`` is the exact byte string read from the target's stdout,
    before any parsing. The transport layer is the only writer. A rule that
    wants to claim a server did something must point at the bytes in which the
    server did it.
    """

    request_json: str
    response_raw: str
    response_parsed: Optional[Dict[str, Any]]
    oracle_id: str
    why_this_proves_it: str

    kind: str = field(default="dynamic", init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.request_json:
            raise ValueError("DynamicEvidence.request_json must be the bytes sent")
        if not self.response_raw:
            raise ValueError(
                "DynamicEvidence.response_raw must be the exact bytes read from the "
                "server -- an empty response cannot prove a finding"
            )
        if not self.oracle_id:
            raise ValueError("DynamicEvidence.oracle_id must be set")
        if not self.why_this_proves_it:
            raise ValueError(
                "DynamicEvidence.why_this_proves_it must state what in the response "
                "constitutes proof"
            )


@dataclass(frozen=True)
class DependencyEvidence(Evidence):
    """Evidence from an advisory database keyed to a pinned version."""

    package: str
    installed_version: str
    advisory_id: str
    affected_range: str
    lockfile: str
    lockfile_line: int

    kind: str = field(default="dependency", init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.package:
            raise ValueError("DependencyEvidence.package must be set")
        if not self.installed_version:
            raise ValueError("DependencyEvidence.installed_version must be set")
        if not self.advisory_id:
            raise ValueError(
                "DependencyEvidence.advisory_id must be a real advisory id "
                "(e.g. GHSA-... / CVE-...)"
            )
        if not self.lockfile:
            raise ValueError("DependencyEvidence.lockfile must be set")


AnyEvidence = Union[StaticEvidence, DynamicEvidence, DependencyEvidence]
_EVIDENCE_TYPES = (StaticEvidence, DynamicEvidence, DependencyEvidence)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Standard CVSS qualitative bands. This is the ONLY way severity is set."""
        if score == 0.0:
            return cls.NONE
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL

    @property
    def rank(self) -> int:
        return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single reported issue.

    ``evidence`` has no default. There is deliberately no way to construct a
    Finding without it.
    """

    rule_id: str
    title: str
    description: str
    cwe: str
    cvss_vector: str
    cvss_score: float
    evidence: AnyEvidence
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # OWASP AIVSS v0.8, computed by scoring/aivss.py. Additional to CVSS, never
    # a replacement: Finding.severity still derives from cvss_score, so nothing
    # downstream shifts. None when AIVSS was not computed.
    aivss: Optional[Any] = None

    def __post_init__(self) -> None:
        if self.evidence is None:
            raise TypeError(
                f"Finding({self.rule_id!r}) constructed without evidence. "
                "Every finding must carry the raw observation that produced it."
            )
        if not isinstance(self.evidence, _EVIDENCE_TYPES):
            raise TypeError(
                f"Finding({self.rule_id!r}).evidence must be StaticEvidence, "
                f"DynamicEvidence or DependencyEvidence, got "
                f"{type(self.evidence).__name__}"
            )
        if not self.rule_id:
            raise ValueError("Finding.rule_id must be set")
        if not self.cvss_vector:
            raise ValueError(
                f"Finding({self.rule_id!r}) has no CVSS vector. Scores are computed "
                "from vectors; a score without its vector is not reproducible."
            )

    @property
    def severity(self) -> Severity:
        # Derived, never stored. There is no code path that sets severity
        # independently of the score.
        return Severity.from_score(self.cvss_score)

    @property
    def source(self) -> str:
        return self.evidence.kind

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "cwe": self.cwe,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity": self.severity.value,
            "remediation": self.remediation,
            "references": list(self.references),
            "evidence": self.evidence.as_dict(),
            "aivss": self.aivss.as_dict() if self.aivss is not None else None,
        }


# ---------------------------------------------------------------------------
# Scan status / result
# ---------------------------------------------------------------------------

STAGES = ("acquire", "detect", "static", "dependencies", "dynamic")


@dataclass
class ScanStatus:
    """Per-stage outcome. Reported before any findings, always."""

    stage: str
    ran: bool
    reason: Optional[str] = None
    duration_s: float = 0.0
    artifacts: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.stage not in STAGES:
            raise ValueError(f"unknown stage {self.stage!r}; expected one of {STAGES}")
        if not self.ran and not self.reason:
            raise ValueError(
                f"stage {self.stage!r} did not run but gave no reason. A stage that "
                "is skipped must say why -- silence reads as 'clean'."
            )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "ran": self.ran,
            "reason": self.reason,
            "duration_s": round(self.duration_s, 3),
            "artifacts": self.artifacts,
        }


@dataclass(frozen=True)
class LaunchCandidate:
    """One way the target itself says it can be started.

    ``source`` names the declaration it came from (package.json bin, pyproject
    [project.scripts], mcp.json, ...) so a launch failure is debuggable from the
    report without reading the scanner's source.
    """

    source: str
    argv: List[str]
    requires_build: bool = False
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "argv": list(self.argv),
                "requires_build": self.requires_build, "note": self.note}


@dataclass
class ServerInfo:
    """What detection concluded about the target. No guessing beyond this."""

    root: str
    server_type: str = "unknown"          # python | nodejs | go | docker | unknown
    is_mcp_server: bool = False
    name: Optional[str] = None
    version: Optional[str] = None
    entrypoint: Optional[str] = None      # derived from target metadata only
    launch_argv: Optional[List[str]] = None
    launch_candidates: List["LaunchCandidate"] = field(default_factory=list)
    launch_python: Optional[str] = None   # venv interpreter, set by prepare()
    build_argv: Optional[List[str]] = None
    install_argv: Optional[List[str]] = None
    transport: str = "stdio"
    manifest_files: List[str] = field(default_factory=list)
    lockfiles: List[str] = field(default_factory=list)
    dependencies: Dict[str, str] = field(default_factory=dict)
    detection_notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["launch_candidates"] = [c.as_dict() for c in self.launch_candidates]
        return d


@dataclass
class ScanResult:
    target: str
    tool_version: str
    schema_version: str = SCHEMA_VERSION
    target_commit: Optional[str] = None
    server_info: Optional[ServerInfo] = None
    statuses: List[ScanStatus] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    def status(self, stage: str) -> Optional[ScanStatus]:
        for s in self.statuses:
            if s.stage == stage:
                return s
        return None

    def set_status(self, status: ScanStatus) -> None:
        self.statuses = [s for s in self.statuses if s.stage != status.stage]
        self.statuses.append(status)
        self.statuses.sort(key=lambda s: STAGES.index(s.stage))

    def sorted_findings(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-f.cvss_score, f.rule_id, f.evidence.kind),
        )

    def counts_by_severity(self) -> Dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def counts_by_source(self) -> Dict[str, int]:
        out = {"static": 0, "dynamic": 0, "dependency": 0}
        for f in self.findings:
            out[f.evidence.kind] += 1
        return out

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "target": self.target,
            "target_commit": self.target_commit,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "server_info": self.server_info.as_dict() if self.server_info else None,
            "stages": [s.as_dict() for s in self.statuses],
            "summary": {
                "total": len(self.findings),
                "by_severity": self.counts_by_severity(),
                "by_source": self.counts_by_source(),
            },
            "findings": [f.as_dict() for f in self.sorted_findings()],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, sort_keys=False)
