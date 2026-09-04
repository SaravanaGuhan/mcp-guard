"""Hardcoded secret detection.

A candidate must satisfy **both** conditions, which is what keeps this from
being the noise generator the old entropy-only rule was:

  1. Structural: either a known provider prefix (sk_live_, ghp_, AKIA...) or an
     assignment to an identifier matching secret/key/token/password/credential.
  2. Entropy: Shannon entropy over the value at or above a threshold, so
     ``API_KEY = "changeme"`` and ``token = os.environ["X"]`` do not match.

Test fixtures, examples and Markdown are excluded by path.

The console report redacts the match; the full value appears only in the JSON
report, which is documented in the README.
"""

from __future__ import annotations

import math
import os
import re
from typing import Iterable, List, Optional, Tuple

from ..models import Finding, StaticEvidence
from ..rules import get as get_rule

MIN_ENTROPY = 3.2
MIN_LEN = 12

# Provider prefixes are strong enough on their own to be structural evidence.
PREFIX_PATTERNS = [
    (r"sk_live_[A-Za-z0-9]{16,}", "Stripe live secret key"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI-style secret key"),
    (r"gh[pousr]_[A-Za-z0-9]{16,}", "GitHub token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack token"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "private key"),
]

# name = "value"  in Python / JS / TS / Go / JSON / YAML
ASSIGN_RE = re.compile(
    r"""(?P<name>[A-Za-z_][A-Za-z0-9_\-]{2,40})\s*[:=]\s*
        (?P<q>["'`])(?P<val>[^"'`\n]{%d,200})(?P=q)""" % MIN_LEN,
    re.VERBOSE,
)
SECRETISH = re.compile(
    r"(secret|passwd|password|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|client[_\-]?secret|auth|credential|bearer)",
    re.I,
)

# Values that are obviously not secrets even when they look random.
DENY_VALUE = re.compile(
    r"^(?:https?://|\$\{|\{\{|<%|process\.env|os\.environ|None|null|undefined|"
    r"true|false|xxx+|change[_\-]?me|your[_\-]|placeholder|example|redacted|"
    r"\*+|\.{3,})",
    re.I,
)

EXCLUDE_PARTS = (
    os.sep + "test" + os.sep, os.sep + "tests" + os.sep,
    os.sep + "__tests__" + os.sep, os.sep + "spec" + os.sep,
    os.sep + "example" + os.sep, os.sep + "examples" + os.sep,
    os.sep + "fixtures" + os.sep, os.sep + "node_modules" + os.sep,
    os.sep + "docs" + os.sep,
)
EXCLUDE_EXT = (".md", ".rst", ".txt", ".lock", ".map", ".min.js", ".svg")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_excluded(rel: str) -> bool:
    low = rel.lower()
    norm = os.sep + low.replace("/", os.sep)
    if any(part in norm for part in EXCLUDE_PARTS):
        return True
    return low.endswith(EXCLUDE_EXT)


def _finding(rel: str, line: int, col: int, matched: str, why: str) -> Finding:
    rule = get_rule("MCPG-SECRET-HARDCODED")
    return Finding(
        rule_id=rule.id,
        title=f"{rule.title} ({why})",
        description=(
            f"{why}. The value is embedded in source and is present in every "
            f"copy of this repository and its history."
        ),
        cwe=rule.cwe,
        cvss_vector=rule.clean_vector,
        cvss_score=rule.score,
        remediation=rule.remediation,
        evidence=StaticEvidence(
            file=rel, line=line, column=col, matched_source=matched,
            rule_id=rule.id,
        ),
    )


def analyze_file(path: str, rel: str) -> List[Finding]:
    """Convenience wrapper: read then analyse. Used by tests."""
    if is_excluded(rel):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return analyze_text(text, rel)


def analyze_text(text: str, rel: str) -> List[Finding]:
    if is_excluded(rel):
        return []
    out: List[Finding] = []
    seen: set = set()

    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue

        for pat, label in PREFIX_PATTERNS:
            for m in re.finditer(pat, line):
                val = m.group(0)
                if (lineno, val) in seen:
                    continue
                seen.add((lineno, val))
                out.append(_finding(rel, lineno, m.start() + 1, line.strip()[:300],
                                    label))

        for m in ASSIGN_RE.finditer(line):
            name, val = m.group("name"), m.group("val")
            if not SECRETISH.search(name):
                continue
            if DENY_VALUE.match(val):
                continue
            ent = shannon_entropy(val)
            if ent < MIN_ENTROPY:
                continue
            if (lineno, val) in seen:
                continue
            seen.add((lineno, val))
            out.append(_finding(
                rel, lineno, m.start() + 1, line.strip()[:300],
                f"assignment to {name!r} with entropy {ent:.2f} >= {MIN_ENTROPY}",
            ))

    return out
