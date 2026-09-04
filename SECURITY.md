# Security policy

This is the vulnerability disclosure policy for MCP Guard itself. For what the
tool executes on your machine when it scans a target, see
[docs/execution-model.md](docs/execution-model.md).

## Supported versions

| Version | Supported |
|---|---|
| 2.0.x | Yes |
| < 2.0 | No, and should not be used. See below. |

## Reporting a vulnerability

Report privately, not in a public issue.

- Open a [security advisory](https://github.com/SaravanaGuhan/mcp-guard/security/advisories/new)
  on this repository, or
- email saravanaguhan123@gmail.com with `mcp-guard` in the subject.

Please include the version or commit, the scan command, and enough detail to
reproduce. If the report involves a scanned target, say whether that target is
public.

Expected response: an acknowledgement within 7 days, and an assessment with a
fix or a decision within 30 days. If a fix ships, the advisory is published with
credit unless you ask otherwise.

Findings in a repository you scanned with MCP Guard belong to that project's
maintainers, not here.

## Versions before 2.0.0

Versions before 2.0.0 emitted fabricated findings: a substantial part of the
reported output was not derived from any observation of the target, and the
same five findings appeared against a deliberately safe server, a server that
exited immediately, and a repository containing no code at all. Do not use
those versions and do not cite results produced by them.

The audit is [docs/audit-2026-09.md](docs/audit-2026-09.md); the retraction and
what replaced it are in [CHANGELOG.md](CHANGELOG.md).
