"""Dependency analysis.

Lockfile parsing plus OSV lookup. Executes nothing from the target.

Severity comes from OSV as published. Where OSV supplies a CVSS vector we score
that vector with our own library so the number and the vector always agree;
where it does not, the generic MCPG-DEP-KNOWN-VULN vector is used and the
report says so.
"""

from __future__ import annotations

import os
from typing import List

from ..models import DependencyEvidence, Finding, ServerInfo
from ..rules import get as get_rule
from ..scoring.cvss import InvalidVector, score_for
from . import lockfiles, osv


def run_dependencies(info: ServerInfo) -> List[Finding]:
    pinned, used = lockfiles.collect(info.root)
    if not pinned:
        raise RuntimeError(
            "no lockfile or exact version pins found "
            "(looked for package-lock.json, yarn.lock, pnpm-lock.yaml, "
            "poetry.lock, requirements.txt, go.sum, and exact pins in "
            "package.json)"
        )

    by_purl = {p.purl: p for p in pinned}
    results = osv.query(list(by_purl.keys()))

    rule = get_rule("MCPG-DEP-KNOWN-VULN")
    findings: List[Finding] = []

    for purl, advisories in results.items():
        pkg = by_purl.get(purl)
        if pkg is None:
            continue
        for adv in advisories:
            vector, score = rule.clean_vector, rule.score
            note = ""
            if adv.cvss_vector and adv.cvss_vector.startswith("CVSS:4.0/"):
                try:
                    vector, score = score_for(adv.cvss_vector)
                    note = " (score from the vector OSV published)"
                except InvalidVector:
                    pass
            elif adv.cvss_vector:
                # OSV published a v3.x vector. We do not transcode it into a v4
                # vector, because a transcoded vector is not the one the
                # advisory asserts. The generic vector is used and named.
                note = (f" (OSV published {adv.cvss_vector.split('/')[0]}, not "
                        f"CVSS 4.0; generic vector used)")

            sev = f"{adv.severity} per OSV. " if adv.severity else ""
            findings.append(Finding(
                rule_id=rule.id,
                title=f"{pkg.name} {pkg.version}: {adv.id}",
                description=f"{sev}{adv.summary}{note}",
                cwe=rule.cwe,
                cvss_vector=vector,
                cvss_score=score,
                remediation=(
                    f"Upgrade {pkg.name} to a version outside {adv.affected_range}."
                ),
                references=[adv.url] + [
                    f"https://osv.dev/vulnerability/{a}" for a in adv.aliases[:3]
                ],
                evidence=DependencyEvidence(
                    package=pkg.name,
                    installed_version=pkg.version,
                    advisory_id=adv.id,
                    affected_range=adv.affected_range,
                    lockfile=pkg.lockfile.split(" (")[0],
                    lockfile_line=pkg.line,
                ),
            ))
    return findings
