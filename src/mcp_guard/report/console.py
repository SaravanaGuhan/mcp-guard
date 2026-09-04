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

# How many extra locations to list before pointing at the JSON report.
MAX_LOCATIONS = 8


def _location(f: Finding) -> str:
    ev = f.evidence
    if isinstance(ev, StaticEvidence):
        return f"{ev.file}:{ev.line}"
    if isinstance(ev, DependencyEvidence):
        return f"{ev.package} {ev.installed_version}"
    if isinstance(ev, DynamicEvidence):
        return ev.oracle_id
    return "?"


def _location_key(f: Finding):
    ev = f.evidence
    if isinstance(ev, StaticEvidence):
        return (ev.file, ev.line)
    return (_location(f), 0)


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


def render(result: ScanResult, shown=None, suppressed: int = 0) -> str:
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
    shown_n = len(result.findings) if shown is None else len(shown)
    L.append(
        f"  total {len(result.findings)}"
        + (f" (showing {shown_n})" if shown_n != len(result.findings) else "")
        + f"   critical {counts['critical']}  high {counts['high']}  "
        f"medium {counts['medium']}  low {counts['low']}"
    )
    L.append(
        f"  by source: static {by_src['static']}  "
        f"dynamic {by_src['dynamic']}  dependency {by_src['dependency']}"
    )
    L.append("")

    findings = result.findings if shown is None else shown

    if not findings:
        L.append("  No findings. Note which stages ran above before reading this")
        L.append("  as 'clean'.")
    else:
        # Group repeated hits of the same rule. Twelve instances of one rule
        # across a repo is one problem with twelve locations, not twelve
        # entries to scroll past.
        groups: dict = {}
        for f in findings:
            groups.setdefault(f.rule_id, []).append(f)
        ordered_groups = sorted(
            groups.values(), key=lambda g: (-max(x.cvss_score for x in g),
                                            g[0].rule_id))

        for i, group in enumerate(ordered_groups, 1):
            head = max(group, key=lambda f: f.cvss_score)
            n = len(group)
            L.append(
                f"  [{i}] {head.severity.value.upper():<8} {head.cvss_score:4.1f}  "
                f"{head.rule_id}" + (f"   ({n} occurrences)" if n > 1 else "")
            )
            L.append(f"      {head.title}")
            L.append(f"      cwe: {head.cwe}   vector: {head.cvss_vector}")
            L.extend(_evidence_block(head))

            if n > 1:
                L.append("      also at:")
                for other in sorted(group, key=_location_key)[:MAX_LOCATIONS]:
                    if other is head:
                        continue
                    L.append(f"        - {_location(other)}")
                if n - 1 > MAX_LOCATIONS:
                    L.append(f"        ... and {n - 1 - MAX_LOCATIONS} more "
                             f"(all locations are in the JSON report)")

            if head.remediation:
                wrapped = textwrap.wrap(head.remediation, 66)
                for line in wrapped:
                    L.append(f"      fix: {line}" if line == wrapped[0]
                             else f"           {line}")
            L.append("")

    if suppressed:
        L.append(f"  {suppressed} further dependency finding(s) not shown "
                 f"(transitive, dev, or below --min-severity).")
        L.append("  Show them with --include-transitive --include-dev "
                 "--min-severity low.")
        L.append("  The JSON report always contains every finding.")
        L.append("")

    L.append(BAR)
    return "\n".join(L)
