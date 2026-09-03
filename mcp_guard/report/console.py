"""Console report.

Leads with what ran and what did not. A stage that did not run is stated as
such, with its reason -- never silently omitted, and never backfilled with
output from a different stage.
"""

from __future__ import annotations

import textwrap
from typing import List

from ..models import (
    DependencyEvidence,
    DynamicEvidence,
    Finding,
    ScanResult,
    StaticEvidence,
)

BAR = "=" * 78
SUB = "-" * 78


def _redact(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 12:
        return s[:2] + "*" * max(0, len(s) - 2)
    return f"{s[:6]}...{s[-4:]} ({len(s)} chars)"


def _evidence_block(f: Finding) -> List[str]:
    ev = f.evidence
    out: List[str] = []
    if isinstance(ev, StaticEvidence):
        out.append(f"      where: {ev.file}:{ev.line}:{ev.column}")
        src = ev.matched_source
        if f.rule_id == "MCPG-SECRET-HARDCODED":
            src = _redact(src)
        for line in src.splitlines()[:4]:
            out.append(f"      src  | {line.strip()[:100]}")
    elif isinstance(ev, DynamicEvidence):
        out.append(f"      oracle: {ev.oracle_id}")
        out.append(f"      sent  > {ev.request_json[:160]}")
        out.append(f"      recv  < {ev.response_raw.strip()[:160]}")
        out.append(f"      proof : {ev.why_this_proves_it}")
    elif isinstance(ev, DependencyEvidence):
        out.append(
            f"      {ev.package} {ev.installed_version} -- {ev.advisory_id}"
        )
        out.append(f"      affected: {ev.affected_range}")
        out.append(f"      pinned at {ev.lockfile}:{ev.lockfile_line}")
    return out


def render(result: ScanResult) -> str:
    L: List[str] = []
    L.append(BAR)
    L.append("MCP GUARD SECURITY REPORT")
    L.append(BAR)
    L.append(f"Target        : {result.target}")
    if result.target_commit:
        L.append(f"Commit        : {result.target_commit}")
    si = result.server_info
    if si:
        L.append(f"Server type   : {si.server_type}"
                 + (f"  ({si.name})" if si.name else ""))
        L.append(f"MCP server    : {'yes' if si.is_mcp_server else 'not detected'}")
        if si.entrypoint:
            L.append(f"Entrypoint    : {si.entrypoint}")
    L.append(f"Tool version  : {result.tool_version}")
    L.append("")

    # --- stages first, always ---
    L.append(SUB)
    L.append("STAGES")
    L.append(SUB)
    for st in result.statuses:
        mark = "ran" if st.ran else "DID NOT RUN"
        L.append(f"  {st.stage:<13} {mark:<12} {st.duration_s:6.2f}s")
        if st.reason:
            for line in textwrap.wrap(st.reason, 68):
                L.append(f"       reason: {line}" if line == textwrap.wrap(st.reason, 68)[0]
                         else f"               {line}")
        for k, v in (st.artifacts or {}).items():
            if k == "stderr_tail" and v:
                L.append("       target stderr (last lines):")
                for line in str(v).splitlines()[-20:]:
                    L.append(f"         | {line[:100]}")
            else:
                L.append(f"       {k}: {v}")
    L.append("")

    # --- findings ---
    counts = result.counts_by_severity()
    by_src = result.counts_by_source()
    L.append(SUB)
    L.append("FINDINGS")
    L.append(SUB)
    L.append(
        f"  total {len(result.findings)}   "
        f"critical {counts['critical']}  high {counts['high']}  "
        f"medium {counts['medium']}  low {counts['low']}"
    )
    L.append(
        f"  by source: static {by_src['static']}  "
        f"dynamic {by_src['dynamic']}  dependency {by_src['dependency']}"
    )
    L.append("")

    if not result.findings:
        L.append("  No findings. Note which stages ran above before reading this")
        L.append("  as 'clean'.")
    else:
        for i, f in enumerate(result.sorted_findings(), 1):
            L.append(
                f"  [{i}] {f.severity.value.upper():<8} {f.cvss_score:4.1f}  "
                f"{f.rule_id}"
            )
            L.append(f"      {f.title}")
            L.append(f"      cwe: {f.cwe}   vector: {f.cvss_vector}")
            L.extend(_evidence_block(f))
            if f.remediation:
                for line in textwrap.wrap(f.remediation, 66):
                    L.append(f"      fix: {line}" if line == textwrap.wrap(f.remediation, 66)[0]
                             else f"           {line}")
            L.append("")

    L.append(BAR)
    return "\n".join(L)
