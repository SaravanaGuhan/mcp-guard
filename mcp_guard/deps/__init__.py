"""Dependency analysis.

Lockfile parsing plus OSV lookup. Executes nothing from the target.

Phase E reshapes the OUTPUT, not just the speed. The baseline emitted one
finding per advisory: 34 findings from 4 packages, 25 of them for axios. That
is a dump, not a report. Now:

  * Advisories that alias each other (a GHSA and its CVE) collapse into one.
  * One finding per (package, version), carrying every advisory id in evidence,
    with the highest advisory score driving the finding's score.
  * Direct/transitive and dev/production are recorded, so a console report can
    lead with what the project actually chose to depend on.

Severity still comes from OSV as published. Where OSV supplies a CVSS 4.0
vector we score that vector so the number and the vector always agree; where it
does not, the generic MCPG-DEP-KNOWN-VULN vector is used and the report says so.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from ..models import DependencyEvidence, Finding, ServerInfo, Severity
from ..rules import get as get_rule
from ..scoring.cvss import InvalidVector, score_for
from . import lockfiles, osv


def _dedupe_aliases(advisories: List[osv.Advisory]) -> List[osv.Advisory]:
    """Collapse advisories that describe the same vulnerability.

    OSV genuinely returns duplicates. lodash 4.17.15 comes back with six
    entries that are four vulnerabilities: GHSA-35jh-r3h4-6jhm and
    GHSA-r5fr-rjxr-66jc list each other as aliases and share CVE-2021-23337,
    and GHSA-f23m-r3pf-42rh / GHSA-xxjr-mmjv-4gpg likewise share
    CVE-2025-13465.

    Grouping is by connected component over the alias graph, with the
    lexicographically smallest id chosen as canonical. A first attempt did a
    pairwise keep/drop, which dropped BOTH sides of a mutual alias pair and
    silently lost four lodash advisories -- caught by asserting that no id
    present before grouping is absent after.
    """
    by_id = {a.id: a for a in advisories}
    parent: Dict[str, str] = {a.id: a.id for a in advisories}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            lo, hi = sorted((rx, ry))
            parent[hi] = lo

    for a in advisories:
        for alias in a.aliases:
            if alias in by_id:
                union(a.id, alias)

    canonical: Dict[str, osv.Advisory] = {}
    for a in advisories:
        root = find(a.id)
        # Prefer the entry with a CVSS vector, then the smallest id.
        cur = canonical.get(root)
        if cur is None or (a.cvss_vector and not cur.cvss_vector) or (
                bool(a.cvss_vector) == bool(cur.cvss_vector) and a.id < cur.id):
            canonical[root] = a
    return sorted(canonical.values(), key=lambda a: a.id)


def _score_for_advisory(adv: osv.Advisory, rule) -> Tuple[str, float, str]:
    if adv.cvss_vector and adv.cvss_vector.startswith("CVSS:4.0/"):
        try:
            v, sc = score_for(adv.cvss_vector)
            return v, sc, " (score from the vector OSV published)"
        except InvalidVector:
            pass
    if adv.cvss_vector:
        # A 3.x vector is NOT transcoded: a transcoded vector is not the one the
        # advisory asserts. Use the generic vector and name what happened.
        return (rule.clean_vector, rule.score,
                f" (OSV published {adv.cvss_vector.split('/')[0]}, not CVSS 4.0)")
    return rule.clean_vector, rule.score, ""


def run_dependencies(info: ServerInfo, *,
                     artifacts: Optional[Dict[str, Any]] = None) -> List[Finding]:
    art = artifacts if artifacts is not None else {}
    pinned, used = lockfiles.collect(info.root)
    if not pinned:
        raise RuntimeError(
            "no lockfile or exact version pins found (looked for "
            "package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, "
            "requirements.txt, go.sum, and exact pins in package.json)")

    by_purl = {p.purl: p for p in pinned}
    before = osv.cache_stats()
    results = osv.query(list(by_purl.keys()))
    after = osv.cache_stats()

    rule = get_rule("MCPG-DEP-KNOWN-VULN")
    findings: List[Finding] = []
    total_advisories = 0

    for purl, advisories in results.items():
        pkg = by_purl.get(purl)
        if pkg is None or not advisories:
            continue
        total_advisories += len(advisories)
        raw_advisories = list(advisories)
        advisories = _dedupe_aliases(advisories)
        if not advisories:
            continue

        scored = [(a, *_score_for_advisory(a, rule)) for a in advisories]
        # highest score drives the finding
        worst = max(scored, key=lambda t: t[2])
        adv, vector, score, note = worst

        # Every id OSV returned is preserved, not just the canonical ones:
        # grouping must not lose data.
        all_ids = sorted({a.id for a in raw_advisories})
        ids = sorted({a.id for a in advisories})
        others = [i for i in ids if i != adv.id]
        origin = ("direct" if pkg.direct else "transitive")
        env = "dev" if pkg.dev else "production"

        summary = adv.summary
        if others:
            summary += (f" (+{len(others)} further "
                        f"{'advisory' if len(others) == 1 else 'advisories'}: "
                        f"{', '.join(others[:6])}"
                        f"{' ...' if len(others) > 6 else ''})")

        sev = f"{adv.severity} per OSV. " if adv.severity else ""
        findings.append(Finding(
            rule_id=rule.id,
            title=(f"{pkg.name} {pkg.version}: {len(ids)} distinct "
                   f"vulnerabilit{'y' if len(ids) == 1 else 'ies'}"
                   + (f" across {len(all_ids)} advisory records"
                      if len(all_ids) != len(ids) else "")
                   + f" ({origin}, {env})"),
            description=f"{sev}{summary}{note}",
            cwe=rule.cwe,
            cvss_vector=vector,
            cvss_score=score,
            remediation=(f"Upgrade {pkg.name} to a version outside "
                         f"{adv.affected_range}."),
            references=[a.url for a in advisories][:8],
            evidence=DependencyEvidence(
                package=pkg.name,
                installed_version=pkg.version,
                # Every id is preserved here: grouping must not lose data.
                advisory_id=", ".join(all_ids),
                affected_range=adv.affected_range,
                lockfile=pkg.lockfile.split(" (")[0],
                lockfile_line=pkg.line,
            ),
        ))

    art.update({
        "lockfiles": used,
        "packages_resolved": len(pinned),
        "direct_packages": sum(1 for p in pinned if p.direct),
        "advisories_returned": total_advisories,
        "findings_after_grouping": len(findings),
        "osv_cache_hits": after["hits"] - before["hits"],
        "osv_cache_misses": after["misses"] - before["misses"],
    })
    return findings


def filter_findings(findings: List[Finding], *, include_transitive: bool,
                    include_dev: bool, min_severity: Optional[str]) -> Tuple[
                        List[Finding], int]:
    """Console-side narrowing. The JSON report always carries everything.

    The severity floor applies to every finding, not only dependency ones: a
    console report is for reading, and low-severity noise buries the two lines
    that matter. Transitive/dev filtering is dependency-specific because only
    dependency findings have that dimension.
    """
    floor = Severity(min_severity).rank if min_severity else -1
    keep: List[Finding] = []
    for f in findings:
        if f.severity.rank < floor:
            continue
        if f.evidence.kind == "dependency":
            title = f.title
            if not include_transitive and "(transitive" in title:
                continue
            if not include_dev and ", dev)" in title:
                continue
        keep.append(f)
    return keep, len(findings) - len(keep)
