"""Evidence verification.

This is the runtime backstop for THE ONE RULE. Types alone guarantee a Finding
*has* evidence; this check guarantees the evidence *refers to something real* --
a file that exists under the scanned target, or bytes actually read from a
server. It runs before any report is emitted, in every format.

A violation is not a warning. It aborts the scan, because a scanner that emits
an unbacked finding is exactly the failure mode this rewrite exists to remove.
"""

from __future__ import annotations

import os
from typing import List

from ..models import (
    DependencyEvidence,
    DynamicEvidence,
    Finding,
    ScanResult,
    StaticEvidence,
)


class EvidenceViolation(AssertionError):
    """Raised when a finding's evidence does not refer to observable data."""


def verify_finding(finding: Finding, target_root: str) -> None:
    ev = finding.evidence

    if isinstance(ev, StaticEvidence):
        path = ev.file if os.path.isabs(ev.file) else os.path.join(target_root, ev.file)
        if not os.path.exists(path):
            raise EvidenceViolation(
                f"{finding.rule_id}: StaticEvidence points at {ev.file!r}, which does "
                f"not exist under the target root {target_root!r}"
            )
        if not ev.matched_source.strip():
            raise EvidenceViolation(
                f"{finding.rule_id}: StaticEvidence.matched_source is blank"
            )

    elif isinstance(ev, DynamicEvidence):
        if not ev.response_raw.strip():
            raise EvidenceViolation(
                f"{finding.rule_id}: DynamicEvidence.response_raw is empty; nothing "
                "was observed from the server"
            )

    elif isinstance(ev, DependencyEvidence):
        path = (
            ev.lockfile
            if os.path.isabs(ev.lockfile)
            else os.path.join(target_root, ev.lockfile)
        )
        if not os.path.exists(path):
            raise EvidenceViolation(
                f"{finding.rule_id}: DependencyEvidence names lockfile {ev.lockfile!r}, "
                f"which does not exist under {target_root!r}"
            )
        if not ev.advisory_id.strip():
            raise EvidenceViolation(
                f"{finding.rule_id}: DependencyEvidence.advisory_id is blank"
            )

    else:  # pragma: no cover - constructor already rejects this
        raise EvidenceViolation(
            f"{finding.rule_id}: unknown evidence type {type(ev).__name__}"
        )


def verify_result(result: ScanResult, target_root: str) -> None:
    problems: List[str] = []
    for f in result.findings:
        try:
            verify_finding(f, target_root)
        except EvidenceViolation as exc:
            problems.append(str(exc))
    if problems:
        raise EvidenceViolation(
            "evidence verification failed for "
            f"{len(problems)} finding(s):\n  - " + "\n  - ".join(problems)
        )
