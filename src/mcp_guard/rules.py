"""Rule registry.

Every detection rule -- static, dynamic or dependency -- is declared here with a
hand-authored CVSS v4.0 base vector and a one-line justification per metric.
The score is computed from the vector at import time by ``scoring.cvss``; no
rule carries a hand-written number.

Metric key (CVSS 4.0 base): AV attack vector, AC complexity, AT requirements,
PR privileges, UI user interaction, VC/VI/VA vulnerable-system C/I/A,
SC/SI/SA subsequent-system C/I/A.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .scoring.cvss import score_for


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    cwe: str
    vector: str
    rationale: str
    method: str          # "ast" | "canary-probe" | "protocol-probe" | "osv" | "regex+entropy"
    remediation: str
    references: List[str] = field(default_factory=list)

    # Which AIVSS v0.8 risk amplification factors amplify THIS finding class.
    # Section 3.3.1 says to review the ten factors "for each vulnerability", so
    # they are scored per finding. Factors absent from this tuple score 0.0 as
    # "not applicable to this finding class", which is a scored value rather
    # than an assumption about the deployment. A hardcoded credential and a
    # command injection through a tool do not amplify the same way.
    agentic_factors: tuple = ()

    @property
    def score(self) -> float:
        return score_for(self.vector)[1]

    @property
    def clean_vector(self) -> str:
        return score_for(self.vector)[0]


_RULES: Dict[str, Rule] = {}


def register(rule: Rule) -> Rule:
    if rule.id in _RULES:
        raise ValueError(f"duplicate rule id {rule.id!r}")
    score_for(rule.vector)  # fail at import on a malformed vector
    _RULES[rule.id] = rule
    return rule


def get(rule_id: str) -> Rule:
    try:
        return _RULES[rule_id]
    except KeyError:
        raise KeyError(f"unknown rule id {rule_id!r}") from None


def all_rules() -> List[Rule]:
    return sorted(_RULES.values(), key=lambda r: r.id)


# ---------------------------------------------------------------------------
# Dynamic rules (canary / protocol probes)
# ---------------------------------------------------------------------------

register(Rule(
    id="MCPG-DYN-CMDEXEC",
    title="Tool argument reaches a shell (proven by canary execution)",
    cwe="CWE-78",
    # AV:L  stdio server: the attacker is whoever speaks to the transport, locally.
    # AC:L  no special conditions; the argument is passed through as-is.
    # AT:N  no prerequisite state.
    # PR:N  MCP stdio declares no privilege model; any client can call the tool.
    # UI:N  no human interaction required.
    # VC/VI/VA:H  arbitrary command execution as the server user.
    # SC/SI/SA:H  the host beyond the server process is equally exposed.
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    rationale="Canary uuid echoed back proves the shell actually ran the argument.",
    method="canary-probe",
    remediation=(
        "Do not pass tool arguments to a shell. Use execFile/spawn with an argument "
        "vector, validate against an allowlist, and reject shell metacharacters."
    ),
    agentic_factors=("tools", "language", "autonomy"),
))

register(Rule(
    id="MCPG-DYN-PATHTRAVERSAL",
    title="Resource/tool path escapes the server root (proven by canary file)",
    cwe="CWE-22",
    # VC:H  arbitrary file read off the host.
    # VI:N/VA:N  read-only in what the probe proves.
    # SC:H  files outside the server's own tree are disclosed.
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
    rationale="Contents of a canary file written outside the target root came back.",
    method="canary-probe",
    remediation=(
        "Resolve the path and verify it is contained by an allowed root "
        "(os.path.realpath + prefix check / path.resolve + startsWith) before reading."
    ),
    agentic_factors=("tools", "autonomy", "persistence"),
))

register(Rule(
    id="MCPG-DYN-UNDECLARED-METHOD",
    title="Server answers a method it never declared",
    cwe="CWE-749",
    # VC:L  exposure depends on the method; the probe proves reachability only.
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    rationale=(
        "Server returned a non -32601 answer for an undeclared method while the "
        "random-method control correctly returned -32601."
    ),
    method="protocol-probe",
    remediation="Reject unknown methods with JSON-RPC error -32601.",
    agentic_factors=("tools", "autonomy"),
))

register(Rule(
    id="MCPG-DYN-NO-DISPATCH",
    title="Server does not implement JSON-RPC method dispatch",
    cwe="CWE-1286",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    rationale=(
        "A random, never-declared method name was answered successfully, so no "
        "method-existence check exists and every other probe is uninterpretable."
    ),
    method="protocol-probe",
    remediation="Return -32601 for methods the server does not implement.",
    agentic_factors=("tools",),
))

register(Rule(
    id="MCPG-DYN-CRASH",
    title="Malformed request crashes the server",
    cwe="CWE-248",
    # VA:H  process exit is a full availability loss for that session.
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
    rationale="Process exited while handling a malformed frame.",
    method="protocol-probe",
    remediation="Catch parse/validation errors and reply with -32700 / -32600.",
    agentic_factors=(),
))

register(Rule(
    id="MCPG-DYN-JSONRPC-VIOLATION",
    title="Response violates JSON-RPC 2.0",
    cwe="CWE-20",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    rationale="Response carried neither result nor error, or echoed a bad id.",
    method="protocol-probe",
    remediation="Always answer with exactly one of result/error and the request id.",
    agentic_factors=(),
))

register(Rule(
    id="MCPG-DYN-SCHEMA-UNENFORCED",
    title="Tool accepts arguments that violate its own inputSchema",
    cwe="CWE-20",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N",
    rationale="Server returned a success result for arguments its schema forbids.",
    method="protocol-probe",
    remediation="Validate arguments against the declared inputSchema before dispatch.",
    agentic_factors=("tools", "language"),
))


# ---------------------------------------------------------------------------
# Static rules (AST)
# ---------------------------------------------------------------------------

register(Rule(
    id="MCPG-PY-SHELL-TAINT",
    title="Request-derived value reaches a shell/eval sink (Python)",
    cwe="CWE-78",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    rationale="Intraprocedural taint from a handler parameter to subprocess/eval/exec.",
    method="ast",
    remediation="Pass an argument vector, never shell=True with request data.",
    agentic_factors=("tools", "language", "autonomy"),
))

register(Rule(
    id="MCPG-PY-PATH-TAINT",
    title="Request-derived value reaches a filesystem sink (Python)",
    cwe="CWE-22",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N",
    rationale="Intraprocedural taint from a handler parameter to open()/pathlib.",
    method="ast",
    remediation="Resolve and containment-check the path before opening it.",
    agentic_factors=("tools", "autonomy", "persistence"),
))

register(Rule(
    id="MCPG-JS-SHELL-TAINT",
    title="Non-literal argument to child_process exec/spawn (JS/TS)",
    cwe="CWE-78",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    rationale="exec/execSync/spawn called with a non-literal command expression.",
    method="ast",
    remediation="Use execFile/spawn with a fixed binary and an argument array.",
    agentic_factors=("tools", "language", "autonomy"),
))

register(Rule(
    id="MCPG-JS-PATH-TAINT",
    title="Non-literal path to a filesystem call (JS/TS)",
    cwe="CWE-22",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N",
    rationale="fs.* called with a non-literal path expression.",
    method="ast",
    remediation="path.resolve() then verify the result is inside an allowed root.",
    agentic_factors=("tools", "autonomy", "persistence"),
))

register(Rule(
    id="MCPG-JS-VM-EVAL",
    title="Dynamic code evaluation (JS/TS)",
    cwe="CWE-95",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    rationale="vm.runInNewContext / eval / new Function on a non-literal.",
    method="ast",
    remediation="Remove dynamic evaluation; parse data as data.",
    agentic_factors=("tools", "language", "autonomy", "self_mod"),
))

register(Rule(
    id="MCPG-SECRET-HARDCODED",
    title="Hardcoded credential",
    cwe="CWE-798",
    # PR:N/UI:N but VC:H -- a live key is a direct confidentiality loss.
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    rationale="Structural match (known prefix or secret-ish assignment) AND high entropy.",
    method="regex+entropy",
    remediation="Move the secret to an environment variable and rotate it.",
    agentic_factors=("identity", "persistence"),
))

register(Rule(
    id="MCPG-DOCKER-ROOT",
    title="Container runs as root",
    cwe="CWE-250",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L",
    rationale="No USER directive, or an explicit USER root/0.",
    method="ast",
    remediation="Add a non-root USER before CMD/ENTRYPOINT.",
    agentic_factors=("autonomy",),
))

register(Rule(
    id="MCPG-DOCKER-CHMOD777",
    title="World-writable permissions set in image",
    cwe="CWE-732",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    rationale="chmod 777 / a+rwx in a RUN layer.",
    method="ast",
    remediation="Grant the narrowest permissions the process needs.",
    agentic_factors=("autonomy",),
))

register(Rule(
    id="MCPG-DOCKER-CURL-PIPE-SH",
    title="Remote script piped to a shell during build",
    cwe="CWE-494",
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    rationale="curl/wget piped into sh/bash in a RUN layer.",
    method="ast",
    remediation="Download, verify a checksum or signature, then execute.",
    agentic_factors=("tools", "autonomy"),
))

register(Rule(
    id="MCPG-DOCKER-ADD-REMOTE",
    title="ADD from a remote URL",
    cwe="CWE-494",
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
    rationale="ADD with an http(s) source performs an unverified fetch.",
    method="ast",
    remediation="Use COPY for local files; fetch remotes explicitly with verification.",
    agentic_factors=("tools", "autonomy"),
))

register(Rule(
    id="MCPG-DOCKER-LATEST-TAG",
    title="Base image pinned to a floating tag",
    cwe="CWE-1104",
    vector="CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    rationale="FROM ...:latest or an untagged base is not reproducible.",
    method="ast",
    remediation="Pin the base image by digest or an immutable tag.",
    agentic_factors=(),
))

register(Rule(
    id="MCPG-DOCKER-ENV-SECRET",
    title="Secret baked into ENV/ARG",
    cwe="CWE-798",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    rationale="Secret-ish key assigned a literal value in an image layer.",
    method="ast",
    remediation="Inject secrets at runtime; image layers are readable by anyone.",
    agentic_factors=("identity", "persistence"),
))


# ---------------------------------------------------------------------------
# MCP-specific static rules (the project's actual novelty)
# ---------------------------------------------------------------------------

register(Rule(
    id="MCPG-MCP-SCHEMA-UNDECLARED-ARGS",
    title="Tool reads argument keys its inputSchema does not declare",
    cwe="CWE-1286",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    rationale="Handler body indexes arguments not present in the declared schema.",
    method="ast",
    remediation="Declare every accepted key in inputSchema and validate against it.",
    agentic_factors=("tools", "language"),
))

register(Rule(
    id="MCPG-MCP-PROMPT-INJECTION-SURFACE",
    title="Tool description carries model-directed instructions",
    cwe="CWE-77",
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:L/SI:L/SA:N",
    rationale=(
        "Tool descriptions are fed to the model verbatim; imperative text there is "
        "an injection surface into the agent's instruction channel."
    ),
    method="ast",
    remediation="Describe what the tool does; never instruct the model in a description.",
    agentic_factors=("language", "autonomy", "context", "multi_agent"),
))

register(Rule(
    id="MCPG-MCP-URI-CONCAT",
    title="Resource URI handler concatenates instead of resolving",
    cwe="CWE-22",
    vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N",
    rationale="URI/path built by string concatenation with no containment check.",
    method="ast",
    remediation="Resolve to an absolute path and verify containment before use.",
    agentic_factors=("tools", "autonomy", "persistence"),
))


# ---------------------------------------------------------------------------
# Dependency rule
# ---------------------------------------------------------------------------

register(Rule(
    id="MCPG-DEP-KNOWN-VULN",
    title="Dependency has a published advisory",
    cwe="CWE-1395",
    # Placeholder vector: dependency findings carry the OSV-published severity
    # where OSV provides one. See report writers -- this vector is only used when
    # the advisory has no CVSS of its own.
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    rationale="Pinned version falls inside a published affected range.",
    method="osv",
    remediation="Upgrade to a version outside the affected range.",
    references=["https://osv.dev/"],
    agentic_factors=("tools", "autonomy"),
))
