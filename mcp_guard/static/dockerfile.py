"""Dockerfile analysis.

The audited version had this logic at mcp_scanner.py:1567 but it was
unreachable, so a Dockerfile with ``USER root`` and ``chmod 777`` produced
nothing. It is reachable now and covered by tests.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ..models import Finding, StaticEvidence
from ..rules import get as get_rule
from .secrets import DENY_VALUE, SECRETISH, shannon_entropy

CURL_PIPE = re.compile(
    r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k|d)?sh\b", re.I)
CHMOD_777 = re.compile(r"chmod\s+(-[A-Za-z]+\s+)*(777|a\+rwx|o\+w)\b", re.I)
ADD_REMOTE = re.compile(r"^\s*ADD\s+(--\S+\s+)*(https?://\S+)", re.I)
FROM_RE = re.compile(r"^\s*FROM\s+(--\S+\s+)*(?P<image>\S+)", re.I)
USER_RE = re.compile(r"^\s*USER\s+(?P<user>\S+)", re.I)
ENVARG_RE = re.compile(
    r"^\s*(ENV|ARG)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*(?P<val>\S+)", re.I)


def _logical_lines(text: str) -> List[Tuple[int, str]]:
    """Join backslash continuations, keeping the starting line number."""
    out: List[Tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        stripped = raw.rstrip()
        if not buf:
            start = i
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        if buf.strip():
            out.append((start, buf))
        buf = ""
    if buf.strip():
        out.append((start, buf))
    return out


def analyze_file(path: str, rel: str) -> List[Finding]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []

    findings: List[Finding] = []
    last_user: Optional[str] = None
    saw_stage = False

    def add(rule_id: str, line: int, snippet: str, detail: str) -> None:
        rule = get_rule(rule_id)
        findings.append(Finding(
            rule_id=rule.id, title=rule.title, description=detail,
            cwe=rule.cwe, cvss_vector=rule.clean_vector, cvss_score=rule.score,
            remediation=rule.remediation,
            evidence=StaticEvidence(file=rel, line=line, column=1,
                                    matched_source=snippet.strip()[:300],
                                    rule_id=rule.id),
        ))

    lines = _logical_lines(text)
    for lineno, line in lines:
        if line.lstrip().startswith("#"):
            continue

        m = FROM_RE.match(line)
        if m:
            saw_stage = True
            last_user = None
            image = m.group("image")
            if "@sha256:" not in image and (
                image.endswith(":latest") or ":" not in image.split("/")[-1]
            ):
                add("MCPG-DOCKER-LATEST-TAG", lineno, line,
                    f"Base image {image!r} is not pinned to an immutable tag or "
                    f"digest, so rebuilds are not reproducible.")

        m = USER_RE.match(line)
        if m:
            last_user = m.group("user")
            if last_user.lower() in ("root", "0"):
                add("MCPG-DOCKER-ROOT", lineno, line,
                    f"USER is explicitly set to {last_user!r}.")

        if CHMOD_777.search(line):
            add("MCPG-DOCKER-CHMOD777", lineno, line,
                "A build layer grants world-writable permissions.")

        if CURL_PIPE.search(line):
            add("MCPG-DOCKER-CURL-PIPE-SH", lineno, line,
                "A remote script is downloaded and piped straight into a shell "
                "with no integrity check.")

        m = ADD_REMOTE.match(line)
        if m:
            add("MCPG-DOCKER-ADD-REMOTE", lineno, line,
                f"ADD fetches {m.group(2)} without verification; use COPY plus an "
                f"explicit, checksummed download.")

        m = ENVARG_RE.match(line)
        if m:
            name, val = m.group("name"), m.group("val").strip('"\'')
            if SECRETISH.search(name) and not DENY_VALUE.match(val) \
                    and len(val) >= 12 and shannon_entropy(val) >= 3.2:
                add("MCPG-DOCKER-ENV-SECRET", lineno, line,
                    f"{m.group(1).upper()} {name} embeds a high-entropy literal; "
                    f"image layers are readable by anyone who can pull the image.")

    # No USER directive at all in the final stage -> runs as root.
    if saw_stage and last_user is None:
        last_from = max((ln for ln, l in lines if FROM_RE.match(l)), default=1)
        snippet = next((l for ln, l in lines if ln == last_from), "FROM ...")
        add("MCPG-DOCKER-ROOT", last_from, snippet,
            "No USER directive after the final FROM, so the container runs as "
            "root by default.")

    return findings
