# Changelog

## 2.0.0 — evidence-backed rewrite

### ⚠️ Do not use or cite any version before 2.0.0

**Versions before this release emitted fabricated findings.** They were not
merely inaccurate — a substantial part of the reported output was not derived
from any observation of the target.

An audit at commit `7900ec9` ([docs/AUDIT.md](docs/AUDIT.md)) established, with
reproducible experiments:

- Five findings ("Command Injection", "Path Traversal", "Authorization Bypass",
  "Information Disclosure", "Debug Endpoint Exposure") were emitted from
  hardcoded literal tables appended unconditionally, carrying invented
  `response` values that no server ever produced. The code comment read
  *"Always add some universal MCP vulnerabilities for realistic results."*
- Those same five findings were reproduced against a deliberately safe MCP
  server, a server whose first statement was `process.exit(1)`, a server that
  answered `-32601` to every request, and a repository whose only code was
  `console.log("x")`.
- In the one case where the target actually started, the genuine engine logged
  `Live fuzzing completed: 0 findings` and the tool reported 5 anyway.
- Every "evidence" guard (`_check_code_patterns`) returned `True` on all paths:
  *"Default to True for more interesting results."*
- `UniversalStaticAnalyzer.analyze_server` was defined twice, so the second
  definition shadowed the first and 1,663 lines / 65 methods — the whole static
  engine, npm audit, bandit, gosec, entropy secret detection and Dockerfile
  checks — were unreachable. This is why every report showed `static: 0`.
- "CVSS v4.0" was a 12-entry CWE→float lookup with a constant vector string.
  "AIVSS", advertised as the first open-source implementation, was
  `cvss * 0.7` plus 2.0 if the server's *name* contained "ai", "mcp", "llm" or
  "model".
- The test suite contained zero `assert` statements, so all five tests "passed"
  while one was in fact failing. Coverage was 14%.
- The tool ran `npm install` on untrusted repositories as the invoking user,
  executing lifecycle scripts, and executed `npx -y @openbnb/mcp-server-airbnb`
  — a package unrelated to the target — on every Node.js scan, while
  documentation claimed "Sandboxed Execution".

**If you published results from an earlier version, they should be retracted.**
Findings attributed to third-party projects by earlier releases were not
supported by any observation of those projects, and the README's sample output
named a real project against fabricated results.

### Added

- Evidence is structural. `Finding.evidence` is required with no default;
  `StaticEvidence` / `DynamicEvidence` / `DependencyEvidence` are frozen and
  reject empty raw data at construction. A report writer verifies that every
  finding's evidence names a file that exists or carries non-empty response
  bytes, and aborts the scan otherwise.
- Per-stage `ScanStatus` (acquire, detect, static, dependencies, dynamic).
  A stage that did not run must give a reason; both reports print stages before
  findings.
- Dynamic engine rebuilt on probes and canary oracles. Command injection is
  proven by a shell-collapsing marker that never appears in the request;
  path traversal by the contents of a canary file written outside the target
  root. Probes are capability-gated, and a random-method control voids the
  method probes if the server answers anything.
- Static analysis by AST: stdlib `ast` for Python, tree-sitter for JS/TS.
- MCP-specific rules: undeclared argument reads, prompt-injection surface in
  tool descriptions, unresolved URI concatenation.
- Dependency scanning by direct lockfile parsing plus the OSV API, with a disk
  cache. No shelling out to npm audit / pip-audit / safety / gosec.
- SARIF 2.1.0 output, validated against the OASIS schema in CI.
- CI exit codes: 0 clean, 1 findings at/above `--fail-on`, 2 scan error,
  3 unanalysable.
- `--allow-execute` gate, `--sandbox docker`, process-tree kill on timeout,
  and [docs/SECURITY.md](docs/SECURITY.md).
- 65 tests, all asserting, at 80% coverage with a 70% gate. Invariant tests
  fail if the banned phrases reappear, if any class defines a method twice, or
  if an oracle stops reading its `response` argument.

### Removed

- `mcp_scanner.py` (5,314 lines) and `simple_vulnerability_scoring.py`, deleted
  rather than repaired.
- The "Authorization Bypass" and "Information Disclosure" probes. An MCP stdio
  server has no authentication layer, so the first was meaningless by
  construction; the second reported the protocol working as designed.
- AIVSS, in name and implementation. Not reimplemented under the same name.
- The hardcoded `@openbnb/mcp-server-airbnb` startup path and all
  airbnb-specific payloads.
- README "Sample Output" and "Supported MCP Servers" sections, which attributed
  fabricated vulnerability counts to five named third-party projects.
- Claims never implemented: JUnit XML, batch/multi-repo scanning, remediation
  prioritization, "Sandboxed Execution", "Resource Limits".
- `asyncio-compat` from requirements, a package that does not exist on PyPI and
  which made `pip install -r requirements.txt` fail outright.

### Changed

- Entrypoints are derived from the target's own metadata (`bin` → `main` →
  `scripts.start`, pyproject `[project.scripts]`, the built Go binary). The
  global list of guessed filenames is gone.
- Severity is derived from the CVSS score and stored nowhere.
