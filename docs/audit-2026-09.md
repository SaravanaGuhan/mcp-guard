# MCP Guard — Security Audit

**Target:** `github.com/SaravanaGuhan/mcp-guard` @ `7900ec9c1f6c952fb5316e443ba830523d0fbf5e`
**Method:** static reading + controlled fixture experiments
**Date:** 2026-09-03

**Environment:** Python 3.11.9 · Node v24.13.0 · npm 11.6.2 · git 2.52.0.windows.1 · **Go: not installed**

`requirements.txt` line 4 pins `asyncio-compat>=0.1.2`, which does not exist on PyPI; installation was performed from a temp copy with that line removed. **No file in the repo was modified.** All instrumentation lives in `/tmp/audit/` and wraps the scanner's methods at runtime from an external driver.

---

## 1. VERDICT

**The dynamic analysis engine is fabricating findings, and the static analysis engine is dead code.**

Roughly one-sixth of what MCP Guard advertises is real. Of the ~18 headline capabilities checked, **3 are implemented, 6 are stubs or unreachable, and 9 do not exist in the codebase at all.** The core claim — that the tool detects vulnerabilities in MCP servers — is false as stated: five findings ("Command Injection", "Path Traversal", "Authorization Bypass", "Information Disclosure", "Debug Endpoint Exposure") are emitted from hardcoded literal tables appended unconditionally, with **invented `response` values that no server ever produced**. These same five findings were reproduced byte-identically against (a) a deliberately safe MCP server, (b) a server whose first statement is `process.exit(1)`, (c) a server that returns `-32601 Method not found` to every request, and (d) a repository whose only code is `console.log("x")`. In the one experiment where the target server actually started and was fuzzed for real, the genuine engine logged **"Live fuzzing completed: 0 findings"** and the tool still reported 5. Separately, **5 of the 6 findings from the README's own showcase scan of the production Airbnb MCP server are identical to those produced against an inert stub.** The `UniversalStaticAnalyzer` class defines `analyze_server` twice; the second definition (line 2662) silently shadows the first (line 992), rendering **1,663 lines / 65 methods** — the entire static engine, npm audit, bandit, gosec, entropy-based secret detection and Dockerfile checks — permanently unreachable. "CVSS v4.0" is a 12-entry CWE→float lookup with a constant vector string; "AIVSS" is `cvss * 0.7`, plus 2.0 if the server's *name* contains the substring "ai", "mcp", "llm" or "model". The test suite passes because its five test functions contain **zero `assert` statements**; one of them is in fact failing right now. What genuinely works is repository download, server-type detection, process launching, a 5-pattern regex scanner, and one response-gated JSON-RPC analyzer that is rarely reached.

---

## 2. CLAIM MAP (Phase 1)

| # | Advertised capability | Verdict | Evidence |
|---|---|---|---|
| 1 | **CVSS v4.0 scoring** | **STUB** | `simple_vulnerability_scoring.py:57` is a 12-entry dict lookup `cvss_score = self.cwe_scores.get(cwe_id, 5.0)`; the "vector" at `:103` is a constant f-string with no interpolation |
| 2 | **AIVSS scoring** | **STUB** | `simple_vulnerability_scoring.py:83` `aivss_score = cvss_score * 0.7`, then `:86-88` `+2.0` if the server *name* contains `mcp/ai/llm/model`. A second, unrelated impl at `mcp_scanner.py:5042` is a ternary on severity |
| 3 | **Static analysis** | **STUB (unreachable)** | `UniversalStaticAnalyzer.analyze_server` at `mcp_scanner.py:992` is shadowed by a second def at `:2662`. Runtime: `co_firstlineno == 2662`. Lines 992–2654 (65 methods) are dead |
| 4 | **Dynamic testing** | **PARTIAL / FABRICATED** | Real response-gated code exists (`:4888`, `:4938`) but a fabrication layer at `:2979` runs unconditionally via `:2721` regardless of whether a server started |
| 5 | **Intelligent fuzzing** | **PARTIAL** | `_generate_real_fuzzing_payloads` (`:3838`) and `_perform_live_fuzzing` (`:2742`) are real, but reached only when the server starts; results are then swamped by the fabrication layer |
| 6 | **Dependency CVE scanning** | **STUB (unreachable)** | `_run_npm_audit` (`:1423`), `_check_python_security_advisories` (`:2586`), `_run_go_vuln_check` (`:2619`) are called only from `:1120/:1409/:1411/:1413`, all inside the dead region. Subprocess trace on a repo pinning `lodash@4.17.15`, `minimist@0.0.8`, `axios@0.21.0` shows **no audit tool invoked and 0 dependency findings** |
| 7 | **Protocol validation** | **IMPLEMENTED (weak)** | `_test_mcp_protocol_vulnerabilities` (`:4938`) genuinely gates on `if response and "result" in response`. Reached only if the server starts |
| 8 | **Python support** | **PARTIAL** | Detection real (`_analyze_python_server`); static path dead; bandit unreachable |
| 9 | **Node.js support** | **PARTIAL** | Detection real; startup list hardcodes an unrelated third-party package (defect #4) |
| 10 | **Go support** | **UNVERIFIED** | Go is not installed in this environment, so no Go scan could be executed. Code paths exist (`:4621`, `:4665`); `_run_gosec` (`:1510`) and `_run_go_vuln_check` (`:2619`) are unreachable by the same shadowing defect |
| 11 | **Docker support** | **ABSENT (analysis)** | Detection only (`:554`). `_analyze_docker_static` is called from `:1007` (dead region); `_get_startup_commands` has branches for python/nodejs/go and **no docker branch**. A Dockerfile fixture with `USER root` + `chmod 777` produced 0 real findings |
| 12 | **SARIF output** | **ABSENT** | `grep -rniE "sarif" --include=*.py .` → 0 matches |
| 13 | **JUnit XML output** | **ABSENT** | `grep -rniE "junit" --include=*.py .` → 0 matches |
| 14 | **JSON output** | **IMPLEMENTED** | `mcp_scanner.py:5164-5167` writes the report |
| 15 | **CI/CD security gates** | **ABSENT** | `grep -rniE "security.gate|gate" --include=*.py .` → 0 matches; `main()` always returns exit code 0 |
| 16 | **Batch / multi-repo** | **ABSENT** | `grep -rniE "batch.scan|multi.repo" --include=*.py .` → 0 matches; `main()` accepts exactly one `sys.argv[1]` |
| 17 | **Remediation prioritization** | **ABSENT** | Single hit repo-wide, a comment at `:5267` `# Show only top 10 vulnerabilities (prioritize by severity)` |
| 18 | **"Sandboxed Execution"** (`PROJECT_SUMMARY.md:89`) | **ABSENT — FALSE** | `grep -niE "sandbox|--ignore-scripts|seccomp|chroot|nsjail"` → only an unrelated string at `:1567` |

---

## 3. CONTROL EXPERIMENT (Phase 2)

Fixtures in `/tmp/audit/fixtures/`, each a git repo declaring `@modelcontextprotocol/sdk`. Scanned via `/tmp/audit/run_fixture.py`, which monkeypatches only `download_repository` to hand the scanner a local copy.

| | **A: clean-server** | **B: vulnerable-server** | **C: not-a-server** | **D: instant-exit** | **E: always-error** | **E2: always-error-live** |
|---|---|---|---|---|---|---|
| Contents | safe MCP server, 1 fixed-string tool | 3 real planted vulns | README + LICENSE only | `process.exit(1)` line 1 | replies `-32601` to all | same, but actually starts |
| **Total findings** | **5** | **7** | **3** | **5** | **5** | **5** |
| critical / high / medium | 1 / 2 / 2 | 2 / 3 / 2 | 0 / 1 / 2 | 1 / 2 / 2 | 1 / 2 / 2 | 1 / 2 / 2 |
| static / dynamic | 0 / 5 | 0 / 7 | 0 / 3 | 0 / 5 | 0 / 5 | 0 / 5 |
| every `cvss_score` | 5.5 (×5) | 5.5 (×7) | 5.5 (×3) | 5.5 (×5) | 5.5 (×5) | 5.5 (×5) |
| every `aivss_score` | 5.8 (×5) | 5.8 (×7) | 5.8 (×3) | 5.8 (×5) | 5.8 (×5) | **3.8** (×5) |
| **Server actually started?** | **NO** — `Failed to start server: [WinError 2]` | **NO** | **NO** — `[WinError 87]` | **NO** | **NO** | **YES** — `Server started successfully` |
| Real engine's own result | n/a | n/a | n/a | n/a | n/a | **`Live fuzzing completed: 0 findings`** |

Identical finding sets (titles) for A, D, E, E2:
`Command Injection Vulnerability` · `Path Traversal Vulnerability` · `Authorization Bypass` · `Information Disclosure` · `Debug Endpoint Exposure`

### Q1 — Does the clean server produce findings?

**Yes: 5.** All five listed above. The clean server imports no `child_process`, no `fs`, has no `eval`, no admin tool and no debug method, and returns `-32601` for everything except `initialize` / `tools/list` / `tools/call ping`. **Its finding set is identical to the vulnerable server's fabricated subset.** The dynamic engine is fabricating.

### Q2 — Does the empty repo produce findings?

**Yes: 3** — `Authorization Bypass` (high), `Information Disclosure` (medium), `Debug Endpoint Exposure` (medium). The repo contains only `README.md` and `LICENSE`. There is no code, no `package.json`, and no server. It is detected as type `generic`, so only the *universal* fabrication block fires; the two Node-specific fabrications are skipped.

### Q3 — Did it find the 3 real planted vulnerabilities in B?

| Planted vulnerability | Detected? | Basis |
|---|---|---|
| (1) `exec(m.params.arguments.cmd)` — arg straight to `child_process.exec` | **CAUGHT** | regex `(exec\|eval\|system\|shell)\s*\(` at `:2802`, verified to match `exec(` |
| (2) `fs.readFileSync(p)` on unsanitized `resources/read` path | **MISSED** | the only path-traversal regex is `open\s*\([^)]*input[^)]*\)` (`:2808`) — Python-specific, verified **0 matches** against the JS source |
| (3) hardcoded `API_KEY = "sk_live_51H8x…"` | **CAUGHT** | regex `(password\|secret\|key\|token)\s*=\s*["'][^"']{8,}["']` at `:2820`, verified to match |

The `Path Traversal Vulnerability` that B *does* report is **not** a detection of vuln (2): the identical finding is emitted for the clean server, which performs no filesystem access at all. It carries zero information.

### Q4 — Confusion matrix (fixtures A + B + C — 15 findings, 3 real vulnerabilities)

|  | Real vuln present | No real vuln |
|---|---|---|
| **Reported** | **TP = 2** (exec injection; hardcoded key — both in B) | **FP = 13** (A: 5, B: 5, C: 3) |
| **Not reported** | **FN = 1** (`fs.readFileSync` path traversal) | TN — not enumerable |

**Precision = 2/15 = 13.3 %** · **Recall = 2/3 = 66.7 %**

Both true positives come from the 5-pattern regex scanner. **Zero true positives originate from dynamic analysis.**

### Cross-check against the project's own showcase target

The README advertises a scan of the production Airbnb MCP server. That scan produced 6 findings. **5 of those 6 are identical in title to the 5 produced against the inert clean stub.** The only target-dependent finding is the regex hit `command_injection: Code execution vulnerability detected`.

---

## 4. FABRICATION EVIDENCE

### 4.1 — Three findings appended unconditionally, with invented server responses

`mcp_scanner.py:2979-3010`, `_analyze_universal_mcp_patterns`:

```python
def _analyze_universal_mcp_patterns(self, server_info: MCPServerInfo) -> List[Dict]:
    """Analyze universal MCP protocol security patterns"""
    vulnerabilities = []

    # Always add some universal MCP vulnerabilities for realistic results
    vulnerabilities.extend([
        {
            "server": server_info.name,
            "payload": {"method": "tools/call", "params": {"name": "admin_tool", ...}},
            "response": {"error": "Unauthorized access attempt"},
            "vulnerabilities": ["Missing authorization checks", "Privileged tool access without authentication"],
            "severity": "high",
            ...
```

There is no condition, no target input, and no server. The comment states the intent: *"Always add some universal MCP vulnerabilities for realistic results."* The `response` field — later surfaced to the user as evidence — is a hand-written literal. This block alone accounts for the 3 findings on the empty repository.

### 4.2 — The fabrication layer runs whether or not the server started

`mcp_scanner.py:2712-2722`:

```python
if process:
    logger.info("✅ Server started successfully - performing live fuzzing")
    vulnerabilities = await self._perform_live_fuzzing(process, server_info)
    logger.info(f"🎯 Live fuzzing completed: {len(vulnerabilities)} findings")
else:
    logger.info("⚠️ Server startup had some issues - performing comprehensive static analysis")
    vulnerabilities = await self._perform_enhanced_static_dynamic_analysis(server_info)

# Add server-specific security pattern analysis
additional_vulns = await self._analyze_server_security_patterns(server_info)
vulnerabilities.extend(additional_vulns)
```

The `extend` at line 2721 sits outside the `if/else`. Fixture **E2** proves the consequence empirically: the log reads `Server started successfully` followed by `Live fuzzing completed: 0 findings`, and the tool still reported 5.

### 4.3 — Every "evidence" guard returns True unconditionally

`mcp_scanner.py:3044-3064`, `_check_code_patterns` — the function behind `_check_for_child_process`, `_check_for_fs_operations`, `_check_for_subprocess_calls`, `_check_for_eval_usage`, `_check_for_os_exec`, `_check_for_file_io`:

```python
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.go')):
                    ...
                                if any(pattern.lower() in content for pattern in patterns):
                                    return True
        except:
            pass

    # Default to True for more interesting results
    return True
```

The walk can only ever return `True` or fall through to `return True`. **There is no code path that returns `False`.** This is why the clean server — which contains no `child_process` and no `fs` — is reported with Command Injection and Path Traversal (`:2922-2941`).

### 4.4 — Node/Python/Go "detections" are literal tables

`mcp_scanner.py:2915-2944` (`_analyze_nodejs_security_patterns`), gated only by 4.3:

```python
    if has_child_process:
        vulnerabilities.append({
            "payload": {"method": "tools/call", "params": {"name": "shell_exec", "arguments": {"command": "ls -la && cat /etc/passwd"}}},
            "response": {"stdout": "Command executed with potential injection"},
            "vulnerabilities": ["Node.js child_process command injection", "Shell command execution without sanitization"],
            "severity": "critical",
```

The `response` value `"Command executed with potential injection"` is a literal. It appears verbatim in the report the user reads as proof that a payload was executed. Equivalent tables exist at `:2871` (Python) and `:2946` (Go), including a Go entry whose fabricated payload is `rm -rf / --no-preserve-root`.

### 4.5 — "Dynamic" findings are relabelled static regex hits

`mcp_scanner.py:2769` — the function is named `_perform_enhanced_static_dynamic_analysis` and its own docstring says *"Perform enhanced static analysis that **simulates dynamic findings**"*. At `:2838-2841` each regex match is packaged with `"payload": {"method": "static_analysis", ...}` and `"response": {"analysis": "Runtime vulnerability detected through static analysis"}`, then reported to the user as *"Security vulnerability detected during runtime analysis"* (`:4288`). No runtime occurred.

### 4.6 — Determinism

Two consecutive scans of fixture A produced finding sets that are **identical after removing `id` and `timestamp`** (`IDENTICAL: True`). Combined with identity across A/D/E/E2, the findings are constants.

---

## 5. RANKED DEFECT LIST

| # | Severity | Tag | Defect |
|---|---|---|---|
| 1 | Critical | **FABRICATED** | `_analyze_universal_mcp_patterns` (`:2979`) unconditionally emits 3 findings with invented `response` evidence — comment: *"Always add some universal MCP vulnerabilities for realistic results."* Fires on a repo containing no code |
| 2 | Critical | **FABRICATED** | `_check_code_patterns` (`:3064`) returns `True` on every path — *"Default to True for more interesting results"* — so the Node/Python/Go finding tables (`:2871`/`:2915`/`:2946`) always fire. The clean server is reported with Command Injection |
| 3 | Critical | **BROKEN** | `UniversalStaticAnalyzer.analyze_server` defined twice (`:992`, `:2662`); the second shadows the first. **1,663 lines / 65 methods dead**, including npm audit, bandit, gosec, pip-audit, govulncheck, entropy secret detection, Dockerfile checks. Runtime-confirmed `co_firstlineno == 2662`. Also explains `static: 0` in every report |
| 4 | High | **BROKEN** | `_start_npx_server` (`:3539`) tries `["npx","-y","@openbnb/mcp-server-airbnb"]` **first, for every Node.js target**. `npx -y` downloads and executes an unrelated third-party package from the npm registry; if it succeeds, the scanner fuzzes *that* server and attributes the results to the user's target |
| 5 | High | **FABRICATED** | Fabrication layer appended outside the `if process:` branch (`:2721`). Proven: real engine logged `0 findings`, tool reported 5 |
| 6 | High | **BROKEN** | `_convert_to_vulnerability` (`:4234`) calls the scorer with hardcoded `cwe_id='CWE-20'`, then **reassigns** `cwe_id` from severity at `:4254-4258`. Score and CWE are computed from different inputs and never reconciled — every finding receives CVSS 5.5 regardless of type or severity |
| 7 | High | **MISSING** | No dependency scanning ever executes. Verified by subprocess trace: on a repo pinning `lodash@4.17.15` / `minimist@0.0.8` / `axios@0.21.0`, **no audit tool ran and 0 CVEs were reported** |
| 8 | High | **BROKEN** | Test suite contains **zero `assert` statements**; its 5 functions `return True/False`, which pytest ignores. `test_static_analysis` is *currently failing* (`Scan completed with error: Failed to download repository`; its target `punkpeye/mcp-server-git` 404s) yet the suite reports `5 passed`. Real coverage of `mcp_scanner.py`: **14 %** (2164/2505 statements uncovered) |
| 9 | High | **MISSING** | No sandbox of any kind, while `PROJECT_SUMMARY.md:89` claims *"Sandboxed Execution: Isolated dynamic analysis"* and `:91` claims *"Resource Limits: CPU, memory, and time constraints"* |
| 10 | Medium | **FABRICATED** | "CVSS v4.0" is a 12-entry CWE→float dict (`simple_vulnerability_scoring.py:39-52`); the vector string (`:103`) is a constant f-string with no interpolation and always asserts `VC:H/VI:H/VA:H` regardless of the finding |
| 11 | Medium | **FABRICATED** | "AIVSS — first open-source implementation" is `cvss * 0.7` plus 2.0 if the *server name* contains `ai`/`mcp`/`llm`/`model` (`:83-88`). Empirically: identical findings scored **5.8** for `clean-mcp-server` and **3.8** for `always-error-live` — the score changed because of the **name**, not the vulnerability. A second, unrelated impl at `mcp_scanner.py:5042` is a ternary on severity |
| 12 | Medium | **MISSING** | SARIF, JUnit XML, CI/CD security gates, batch/multi-repo scanning: **0 grep matches repo-wide**. `main()` always exits 0, so it cannot gate a pipeline |
| 13 | Medium | **MISSING** | Docker analysis absent: `_get_startup_commands` has no docker branch; `_analyze_docker_static` is dead. A Dockerfile fixture with `USER root` + `chmod 777` yielded 0 real findings, though `_check_dockerfile_security:1567` contains an (unreachable) `Container Running as Root` check |
| 14 | Medium | **BROKEN** | The startup candidate list never tries `package.json`'s `main` or a plain `node index.js`, so ordinary MCP servers fail to start and silently fall through to the fabrication path. The failure is logged at INFO as *"Server startup had some issues"* and never surfaced in the report |
| 15 | Low | **BROKEN** | `requirements.txt:4` pins `asyncio-compat>=0.1.2`, which does not exist on PyPI. `pip install -r requirements.txt` fails outright; nothing in the codebase imports it |
| 16 | Low | **COSMETIC** | `PROJECT_SUMMARY.md` claims "2,500+ lines" (actual 5,453), "Test Coverage: Extensive" (14 %), "Low False Positive Rate" (measured precision 13.3 %), and lists `CHANGELOG.md`, `examples/`, `docs/INSTALLATION.md`, `docs/USAGE.md`, `docs/EXAMPLES.md` — none of which exist |
| 17 | Low | **COSMETIC** | Four stub methods `return []  # Implemented in universal patterns` (`:2557`, `:2570`, `:2574`, `:2578`) |

---

## 6. SAFETY REVIEW (Phase 7)

The scanner downloads an arbitrary repository and executes its contents with **no sandbox, no container, no user separation, and no `--ignore-scripts`**. Confirmed execution sites:

| file:line | Action |
|---|---|
| `mcp_scanner.py:4630` | `subprocess.run(server_info.install_command, cwd=local_path)` → `npm install` (`:702`) or `go mod download` (`:647`) |
| `mcp_scanner.py:4621` | `subprocess.run(['go','mod','tidy'], cwd=local_path)` |
| `mcp_scanner.py:4647`, `:4665-4675` | `go build ./...` on target-controlled source |
| `mcp_scanner.py:4706` | `subprocess.Popen(...)` launching the built target binary |
| `mcp_scanner.py:3130` | `subprocess.Popen` — HTTP server startup |
| `mcp_scanner.py:3284` | `subprocess.Popen` — Airbnb startup handler |
| `mcp_scanner.py:3467` | `subprocess.Popen` — generic stdio server startup |
| `mcp_scanner.py:3549` | `subprocess.Popen(cmd)` over the npx candidate list, including `npx -y @openbnb/mcp-server-airbnb` |

Observed subprocess trace for a single scan of one Node.js fixture:

```
Popen: ['npx', '-y', '@openbnb/mcp-server-airbnb']
Popen: ['npm', 'start']
Popen: ['node', 'dist/index.js']
Popen: ['node', 'build/index.js']
Popen: ['npx', 'ts-node', 'src/index.ts']
run:   ['npm', 'install']
Popen: ['npm', 'install']
```

**Stated plainly: running MCP Guard against an untrusted repository is equivalent to cloning that repository and running `npm install` (or `go build`) and its entrypoint as your own user, with your own filesystem, environment variables and network access.** `npm install` executes the target's `preinstall` / `install` / `postinstall` lifecycle scripts; nothing here restricts them. The tool additionally reaches out to the public npm registry and executes `@openbnb/mcp-server-airbnb` — a package unrelated to the target — on every Node.js scan.

`PROJECT_SUMMARY.md:89`'s "Sandboxed Execution" claim is false, and is the most dangerous documentation error in the project: it tells a security engineer the opposite of the truth about a tool whose entire purpose is to be pointed at untrusted code.

---

## 7. WHAT GENUINELY WORKS

Stated precisely, without inflation:

1. **Repository download** — `_download_github_zip` (`:458`) fetches a GitHub repo as a ZIP over HTTPS and tries `main`/`master`/`develop`. It works, and it correctly errors on a nonexistent repo.
2. **Server-type detection** — `detect_mcp_server_type` (`:537`) correctly distinguished nodejs / generic / docker across all fixtures, and on the real Airbnb repo correctly extracted the name, entry points, all 8 dependencies, package manager, transport type and runtime command. This is the most solid component in the project.
3. **Process launching and real MCP protocol I/O** — when the entrypoint matches its candidate list, the scanner genuinely starts the server, writes JSON-RPC to stdin and reads stdout (`:3729`, `:3758`, `:4798`). Fixture E2 confirms: `Server started successfully - performing live fuzzing`.
4. **One genuine response-gated analyzer** — `UniversalDynamicAnalyzer._analyze_real_response` (`:4888`) inspects the actual response and flags only on observed content. It correctly returned **0 findings** for a compliant server that answered `-32601` to everything. This is real detection logic; it is simply drowned out by the fabrication layer appended after it.
5. **Protocol capability test** — `_test_mcp_protocol_vulnerabilities` (`:4938`) is properly gated on `if response and "result" in response`.
6. **A 5-pattern regex scanner** — `_analyze_runtime_vulnerabilities` (`:2795`) genuinely reads target source and matched 2 of 3 planted vulnerabilities in fixture B while producing no such hits on the clean fixture. It is input-sensitive and is the **only** source of true positives in this audit. It is, however, mislabelled as dynamic analysis, and its path-traversal pattern is Python-only.
7. **JSON report output** — `main()` (`:5164`) writes a well-formed, complete JSON report.

Everything else measured in this audit is unreachable, fabricated, or absent.

---

*Artifacts: `/tmp/audit/` — `run_fixture.py`, `trace_static.py`, `trace_exec.py`, `fixtures/`, `report_*.json`, `log_*.txt`. The repository was not modified; `git status --porcelain` is clean at `7900ec9`.*
