"""SARIF 2.1.0 output.

Implemented against the OASIS 2.1.0 schema. Findings whose evidence is not
file-anchored (dynamic, dependency) are emitted with a logicalLocation instead
of a physical one, which SARIF permits, rather than being given a fake file
position.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..models import DependencyEvidence, DynamicEvidence, ScanResult, StaticEvidence
from ..rules import all_rules

SARIF_VERSION = "2.1.0"
SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "none": "none",
}


def _rules_block() -> List[Dict[str, Any]]:
    out = []
    for r in all_rules():
        out.append({
            "id": r.id,
            "name": r.id.replace("-", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.rationale},
            "help": {"text": r.remediation or r.title},
            "properties": {
                "cwe": r.cwe,
                "cvssV4_vector": r.clean_vector,
                "cvssV4_score": r.score,
                "detectionMethod": r.method,
                "tags": ["security", r.cwe, r.method],
            },
        })
    return out


def render(result: ScanResult) -> str:
    results: List[Dict[str, Any]] = []

    for f in result.sorted_findings():
        ev = f.evidence
        entry: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity.value],
            "message": {"text": f"{f.title}. {f.description}".strip()},
            "properties": {
                "cvssV4_vector": f.cvss_vector,
                "cvssV4_score": f.cvss_score,
                "cwe": f.cwe,
                "evidenceKind": ev.kind,
            },
        }

        if isinstance(ev, StaticEvidence):
            entry["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": ev.file.replace("\\", "/")},
                    "region": {
                        "startLine": ev.line,
                        "startColumn": max(1, ev.column),
                        "snippet": {"text": ev.matched_source},
                    },
                }
            }]
        elif isinstance(ev, DynamicEvidence):
            entry["locations"] = [{
                "logicalLocations": [{
                    "name": ev.oracle_id,
                    "kind": "function",
                    "fullyQualifiedName": f"dynamic/{ev.oracle_id}",
                }]
            }]
            entry["properties"]["request"] = ev.request_json
            entry["properties"]["response"] = ev.response_raw
            entry["properties"]["proof"] = ev.why_this_proves_it
        elif isinstance(ev, DependencyEvidence):
            entry["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": ev.lockfile.replace("\\", "/")},
                    "region": {"startLine": max(1, ev.lockfile_line)},
                }
            }]
            entry["properties"].update({
                "package": ev.package,
                "installedVersion": ev.installed_version,
                "advisoryId": ev.advisory_id,
                "affectedRange": ev.affected_range,
            })

        results.append(entry)

    doc = {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MCP Guard",
                    "version": result.tool_version,
                    "informationUri": "https://github.com/SaravanaGuhan/mcp-guard",
                    "rules": _rules_block(),
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "stages": [s.as_dict() for s in result.statuses],
                },
            }],
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
