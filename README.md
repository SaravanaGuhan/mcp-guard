# MCP Guard

Security scanner for Model Context Protocol servers.

Every finding it reports carries the raw observation that produced it: the
literal source text at a file position, the exact bytes a server sent back, or
an advisory id and the lockfile line where a version is pinned. A finding
cannot be constructed without that evidence — it is a required field with no
default, and the report writer refuses to emit a report whose evidence does not
refer to something real.

> **Versions before 2.0.0 fabricated findings and should not be used or cited.**
> See [CHANGELOG.md](CHANGELOG.md) and [docs/AUDIT.md](docs/AUDIT.md).

---

## Install

```bash
git clone https://github.com/SaravanaGuhan/mcp-guard.git
cd mcp-guard
pip install -r requirements.txt
pip install tree-sitter tree-sitter-javascript     # JavaScript/TypeScript AST
```

Python 3.10+. Node is only needed to run dynamic analysis against Node targets.

## Use

```bash
# Static + dependency analysis. Executes nothing from the target.
python -m mcp_guard.cli <repo-url-or-path>

# Add dynamic analysis. This RUNS the target's code.
python -m mcp_guard.cli <target> --allow-execute

# Same, isolated in a container.
python -m mcp_guard.cli <target> --allow-execute --sandbox docker

# CI
python -m mcp_guard.cli <target> --format sarif -o results.sarif --fail-on high
```

| Flag | Effect |
|---|---|
| `--allow-execute` | Permit dynamic analysis. Without it the dynamic stage reports `ran=False`. |
| `--sandbox none\|docker` | Isolation for dynamic analysis. `docker` errors out if docker is unavailable rather than downgrading. |
| `--entrypoint 'node dist/x.js'` | Launch this instead of the derived command. The derived candidate chain is still reported. |
| `--skip-install` | Assume dependencies are present. Also automatic when `node_modules` exists. |
| `--probe-budget N` | Seconds of dynamic probing before the rest are skipped (default 30). Skipped probes are **named** in the report. |
| `--handshake-timeout N` | Seconds to wait for `initialize` (default 10). Raise it for a server that is genuinely slow to boot. |
| `--timeout N` | Per-subprocess timeout, default 120s. |
| `--no-static`, `--no-deps`, `--offline` | Skip a stage; the report says it was skipped and why. |
| `--no-cache` | Bypass the static result cache. |
| `--quiet` | Suppress per-stage progress on stderr. |
| `--format console\|json\|sarif\|summary` | Output format. |
| `--min-severity`, `--include-transitive`, `--include-dev` | Console density. **JSON is never filtered.** |
| `--fail-on none\|low\|medium\|high\|critical` | Exit-code threshold, default `high`. |

**Exit codes:** `0` clean · `1` findings at or above `--fail-on` · `2` scan error
(including an evidence violation) · `3` target could not be analysed.

---

## What it detects

| Rule | Method | CWE | CVSS | What it means |
|---|---|---|---|---|
| `MCPG-DYN-CMDEXEC` | canary probe | CWE-78 | 9.4 | A tool argument reached a shell. Proven, not inferred. |
| `MCPG-DYN-PATHTRAVERSAL` | canary probe | CWE-22 | 8.2 | A path escaped the server root and returned a canary file's contents. |
| `MCPG-DYN-UNDECLARED-METHOD` | protocol probe | CWE-749 | 5.1 | The server answers a method it never declared. |
| `MCPG-DYN-NO-DISPATCH` | protocol probe | CWE-1286 | 5.1 | The server answers anything, so method probes are uninterpretable. |
| `MCPG-DYN-CRASH` | protocol probe | CWE-248 | 6.9 | A malformed frame killed the process. |
| `MCPG-DYN-JSONRPC-VIOLATION` | protocol probe | CWE-20 | 5.1 | A reply is not valid JSON-RPC 2.0. |
| `MCPG-DYN-SCHEMA-UNENFORCED` | protocol probe | CWE-20 | 5.1 | A tool accepted arguments its own `inputSchema` forbids. |
| `MCPG-PY-SHELL-TAINT` | AST | CWE-78 | 9.4 | Request-derived value reaches `subprocess`/`eval`/`exec` (Python). |
| `MCPG-PY-PATH-TAINT` | AST | CWE-22 | 7.0 | Request-derived value reaches `open()`/`pathlib` (Python). |
| `MCPG-JS-SHELL-TAINT` | AST | CWE-78 | 9.4 | Non-literal argument to `child_process` exec/spawn. |
| `MCPG-JS-PATH-TAINT` | AST | CWE-22 | 7.0 | Non-literal path to an `fs.*` call. |
| `MCPG-JS-VM-EVAL` | AST | CWE-95 | 9.4 | `vm.runInNewContext` / `eval` / `new Function`. |
| `MCPG-MCP-PROMPT-INJECTION-SURFACE` | AST | CWE-77 | 7.1 | A tool description carries model-directed instructions. |
| `MCPG-MCP-SCHEMA-UNDECLARED-ARGS` | AST | CWE-1286 | 5.1 | A handler reads argument keys its schema never declares. |
| `MCPG-MCP-URI-CONCAT` | AST | CWE-22 | 6.9 | A resource URI is concatenated rather than resolved and verified. |
| `MCPG-SECRET-HARDCODED` | structure + entropy | CWE-798 | 8.8 | A hardcoded credential. |
| `MCPG-DOCKER-ROOT` | AST | CWE-250 | 5.1 | Container runs as root. |
| `MCPG-DOCKER-CHMOD777` | AST | CWE-732 | 4.8 | World-writable permissions in an image layer. |
| `MCPG-DOCKER-CURL-PIPE-SH` | AST | CWE-494 | 9.3 | Remote script piped into a shell during build. |
| `MCPG-DOCKER-ADD-REMOTE` | AST | CWE-494 | 8.8 | `ADD` from a remote URL. |
| `MCPG-DOCKER-LATEST-TAG` | AST | CWE-1104 | 6.3 | Base image on a floating tag. |
| `MCPG-DOCKER-ENV-SECRET` | AST | CWE-798 | 6.8 | Secret baked into `ENV`/`ARG`. |
| `MCPG-DEP-KNOWN-VULN` | OSV lookup | CWE-1395 | published | A pinned dependency has an advisory. |

Scores are computed from a hand-authored CVSS v4.0 vector attached to each rule;
severity is derived from the score. No rule carries a hand-written number, and a
test recomputes every score from its vector.

### How the canary probes prove things

The command-injection probe sends `echo MCPGUARD""_<id>` (POSIX) and
`echo MCPGUARD^_<id>` (cmd.exe). A shell collapses the quoting and prints
`MCPGUARD_<id>` — a string that never appears in the bytes we sent. A server
that merely echoes the argument back cannot produce it. The path-traversal probe
writes a file with unguessable contents *outside* the target root and only
reports a finding if those contents come back.

---

## Performance

Measured on a 9-fixture corpus and 12 real MCP server repositories cloned from
GitHub. `docs/profile-baseline.md` and `docs/profile-after.md` are the committed
before/after, regenerated by `make profile`.

| | before | after |
|---|--:|--:|
| Targets reaching an MCP handshake | 2/21 | **8/21** |
| Static, `mcp-server-cloudflare` (291 files) | 14,311 ms | **744 ms** |
| Static, `python-sdk` (899 files) | 10,464 ms | **3,337 ms** |
| Static parses per file | 3 | **1** |
| Dynamic, `clean-server` | 10,033 ms | **2,247 ms** |
| Dynamic, `mcp-server-airbnb` | 45,952 ms | **12,228 ms** |
| End-to-end, `Figma-Context-MCP` (551 deps), cold | 66,065 ms | **17,814 ms** |
| End-to-end, same repo, warm caches | — | **1,141 ms** |
| Dependency findings, `vuln-deps` | 34 entries | **4** (every advisory id kept) |

Two caches make a rescan cheap: static results are keyed by
`(file sha256, rule set version)` in `~/.cache/mcp-guard/static`, and OSV
responses by package URL in `~/.cache/mcp-guard/osv`. A first scan is ~25%
slower for the write; a rescan is ~87% faster. `--no-cache` opts out.

Where a scan is slow, it is usually the target rather than the scanner: a tool
that makes a network call takes as long as that call. `--probe-budget` bounds
it, and names what it skipped.

Process-pool parallelism for static analysis was tried and **reverted** — it was
slower than serial on every repository tested. The measurement is in
`_should_parallelise`.

## What it does **not** detect

Stated explicitly, because the previous version's docs did the opposite.

- **Taint tracking is intraprocedural.** A value laundered through a helper
  function is not followed. Both the Python and JS analyzers track from a
  function's own parameters to a sink in the same function, and no further.
- **No authentication testing for stdio.** An MCP stdio server has no auth
  layer, so there is nothing to bypass. The old "Authorization Bypass" finding
  was meaningless by construction and was deleted rather than repaired. If you
  want auth checks, they belong on HTTP transports with a declared auth scheme,
  which is not implemented.
- **Go support is untested.** The code paths exist (`go mod download`,
  `go build`, launching the built binary), but no Go fixture is in the corpus
  and Go was not installed in the environment where this was developed. Treat it
  as unverified.
- **Docker targets are analysed statically only.** MCP Guard reads the
  Dockerfile; it does not build or run target images.
- **MCP schema rules are single-file and syntactic.** A tool schema assembled at
  runtime, or imported from another module, is not analysed.
- **Dependency findings are only as good as your lockfile.** Versions must be
  fully resolved. `"^4.17.15"` is a range, and MCP Guard will not guess what it
  resolves to.
- **No JUnit XML, no batch/multi-repo scanning, no remediation ranking beyond
  sorting by score.** These were claimed by earlier versions and were never
  implemented; the claims are deleted rather than stubbed.
- **A server that needs configuration cannot be probed.** If it wants an API key
  or a database URL and does not say so, it starts and stays silent, and the
  dynamic stage reports a handshake timeout. That is a documented outcome, not a
  clean bill of health. 13 of the 21 profiled targets do not launch, and the
  report always says which and why.
- **Probing can be truncated.** With `--probe-budget` exhausted, remaining
  probes are skipped and listed by name. A skipped probe is not a negative
  result.
- **Only the first launch candidate that handshakes is probed.** A monorepo
  exposing several MCP servers is scanned through one of them; the others appear
  in the candidate chain but are not fuzzed.

---

## Measured accuracy

On the 9-fixture corpus in `tests/fixtures/`, regenerated by `make bench`:

```
fixture               n  TP  FP  FN  categories
------------------------------------------------------------------------
clean-server          0   0   0   0  -
not-a-server          0   0   0   0  -
instant-exit          0   0   0   0  -
always-error-live     0   0   0   0  -
vulnerable-server     5   3   0   0  cmd-injection,hardcoded-secret,path-traversal
python-server         2   2   0   0  cmd-injection,path-traversal
ts-server             1   1   0   0  prompt-injection
docker-server         2   2   0   0  container-root,world-writable
------------------------------------------------------------------------
precision = 8/8 = 100.0%   recall = 8/8 = 100.0%
```

**Read this with the caveat it deserves.** A nine-repository corpus is not a
benchmark. The fixtures were written alongside the rules by the same author, so
these numbers measure "the rules do what they were built to do and produce
nothing on inert inputs" — a regression guard, not evidence of real-world
accuracy. Nobody should cite 100% as this tool's precision. Two of the four
negative fixtures are also degenerate by design (an empty repo, a process that
exits immediately).

`vulnerable-server` shows `n=5` for 3 categories because the exec injection and
the path traversal are each found twice, once statically and once dynamically.
Duplicates across stages are not counted as false positives.

---

## Sample output

Generated by an actual run — `make sample` regenerates
[docs/sample-output.txt](docs/sample-output.txt) so it cannot drift.

```
------------------------------------------------------------------------------
STAGES
------------------------------------------------------------------------------
  acquire       ran            0.02s
  detect        ran            0.00s
       server_type: nodejs
  static        ran            0.05s
       findings: 3
  dependencies  DID NOT RUN    0.00s
       reason: offline mode: OSV lookup skipped
  dynamic       ran            0.84s
       capabilities: ['resources', 'tools']

------------------------------------------------------------------------------
FINDINGS
------------------------------------------------------------------------------
  total 5   critical 2  high 3  medium 0  low 0

  [1] CRITICAL  9.4  MCPG-DYN-CMDEXEC
      Tool argument reaches a shell (proven by canary execution)
      oracle: cmd-injection-canary
      sent  > {"method": "tools/call", "params": {"name": "run",
               "arguments": {"cmd": "echo MCPGUARD^_5758296d..."}}}
      recv  < {"result":{"content":[{"type":"text",
               "text":"MCPGUARD_5758296d...\r\n"}]}}
      proof : the collapsed marker is in the response and not in the request,
              so the argument was interpreted by a shell, not echoed.
```

Note the stage block comes first. A report with no findings means nothing until
you know which stages ran.

---

## Safety

**Dynamic analysis runs the target's code.** It requires `--allow-execute`, and
`--sandbox docker` is strongly recommended for anything you do not trust.

Read [docs/SECURITY.md](docs/SECURITY.md) for exactly what executes in which
mode. In short: static and dependency analysis execute nothing; npm installs
always pass `--ignore-scripts`; every subprocess has a timeout and its whole
process tree is killed on expiry; and `--sandbox docker` uses `--network none`,
a read-only mount, a non-root user, `--memory 512m` and `--pids-limit 256`.

Secrets are redacted in console output and appear in full only in the JSON
report, so treat JSON reports as sensitive.

---

## Development

```bash
make test     # pytest, with a 70% coverage gate
make cov      # coverage HTML
make sample   # regenerate docs/sample-output.txt
make bench    # regenerate the accuracy table
```

Tests skip rather than silently pass when a prerequisite is missing: dynamic
tests need `node`, dependency tests need network access to OSV.

## License

MIT. See [LICENSE](LICENSE).
