"""One-screen verdict.

`--format summary` answers "is this thing safe to run, and did the scan
actually look?" in under a screen. It never omits a stage: a report with no
findings means nothing until you know which stages ran.
"""

from __future__ import annotations

from collections import Counter
from typing import List

from ..models import ScanResult

BAR = "=" * 70


def render(result: ScanResult) -> str:
    L: List[str] = []
    si = result.server_info
    counts = result.counts_by_severity()
    ran = [s for s in result.statuses if s.ran]
    skipped = [s for s in result.statuses if not s.ran]

    worst = max((f.cvss_score for f in result.findings), default=0.0)
    if not ran:
        verdict = "NOT ANALYSED"
    elif counts["critical"]:
        verdict = "CRITICAL FINDINGS"
    elif counts["high"]:
        verdict = "HIGH FINDINGS"
    elif result.findings:
        verdict = "FINDINGS"
    else:
        verdict = "NO FINDINGS"

    L.append(BAR)
    L.append(f"MCP GUARD: {verdict}")
    L.append(BAR)
    L.append(f"target   {result.target}")
    if si:
        L.append(f"type     {si.server_type}"
                 + (f" ({si.name})" if si.name else "")
                 + ("  [MCP server]" if si.is_mcp_server else "  [not an MCP server]"))
    L.append(f"stages   ran: {', '.join(s.stage for s in ran) or 'none'}")
    if skipped:
        L.append(f"         skipped: {', '.join(s.stage for s in skipped)}")
        for s in skipped:
            L.append(f"           {s.stage}: {(s.reason or '')[:58]}")
    L.append("")
    L.append(f"findings {len(result.findings)}"
             f"   critical {counts['critical']}"
             f"  high {counts['high']}"
             f"  medium {counts['medium']}"
             f"  low {counts['low']}")
    if result.findings:
        L.append(f"worst    {worst:.1f}")
        by_rule = Counter(f.rule_id for f in result.findings)
        L.append("")
        L.append("top rules")
        for rule_id, n in by_rule.most_common(6):
            L.append(f"  {n:>3}x  {rule_id}")
    L.append(BAR)
    return "\n".join(L)
