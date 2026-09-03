# Security model

MCP Guard analyses repositories you may not trust. This document states exactly
what it executes, in which mode. If something here is not true of the code,
that is a bug — please report it.

## Short version

| Mode | Command | Does it execute target code? |
|---|---|---|
| Default | `mcp-guard <target>` | **No.** |
| Dynamic | `mcp-guard <target> --allow-execute` | **Yes**, directly on your machine. |
| Dynamic, isolated | `mcp-guard <target> --allow-execute --sandbox docker` | Yes, inside a container. |

Static analysis and dependency analysis **never** execute anything from the
target. They read files and query an HTTP API. Running MCP Guard with no flags
cannot spawn a target process — there is no code path from the default
invocation to `subprocess`.

## What dynamic mode runs

`--allow-execute` is required. Without it, the dynamic stage reports
`ran=False, reason="requires --allow-execute"` and contributes zero findings.

With it, MCP Guard will:

1. **Install dependencies.**
   - Node.js: `npm ci --ignore-scripts --no-audit --no-fund`, falling back to
     `npm install --ignore-scripts ...` when there is no lockfile.
     `--ignore-scripts` is not optional and is not configurable. It is what
     prevents a target's `preinstall` / `install` / `postinstall` hooks from
     running. Versions of this tool before 2.0.0 ran a bare `npm install` and
     therefore executed those hooks as the invoking user.
   - Go: `go mod download` with `GOFLAGS=-mod=mod`, `CGO_ENABLED=0`. No
     `go generate` step is ever run.
   - Python: `pip install --only-binary :all: -r requirements.txt`.
     See the limitation note below.
2. **Build, if the target declares a build step** (`npm run build`,
   `go build`). This executes the target's own build scripts.
3. **Launch the server** using a command derived from the target's own
   metadata (`package.json` `bin` → `main` → `scripts.start`; pyproject
   `[project.scripts]`; the built Go binary). MCP Guard never launches a
   package that is not the target, and never guesses filenames.
4. **Speak JSON-RPC to it** over stdio and evaluate the responses.

A one-line warning naming the exact argv is printed to stderr before anything
target-controlled runs.

## Limits that apply in every execution mode

- Hard timeout per subprocess, default 120s (`--timeout`).
- On timeout the entire process **tree** is killed (`taskkill /F /T` on Windows,
  `killpg` on POSIX), so orphaned grandchildren are not left running.
- Children are started in their own process group / session so that kill works.

## `--sandbox docker`

When docker is available, dynamic mode runs install, build and launch inside a
container with:

- `--network none` for the launch step
- the target mounted **read-only** at `/src`, with a `tmpfs` working copy
- `--memory 512m`, `--pids-limit 256`
- `--user 1000:1000` (non-root), `--cap-drop ALL`,
  `--security-opt no-new-privileges`
- `--read-only` root filesystem

If docker is not installed or the daemon is unreachable, MCP Guard **errors
out**. It does not fall back to `--sandbox none`. Asking for isolation and
silently not getting it is worse than being told no.

## Known limitations — stated, not hidden

- **`--sandbox none` is not a sandbox.** It is the default for dynamic mode and
  it runs target code as your user, with your filesystem and network. Use
  `--sandbox docker` for untrusted targets.
- **Python sdist installs can still execute `setup.py`.** `--only-binary :all:`
  avoids this for packages that publish wheels, but a dependency that ships
  only an sdist cannot be installed without running its build. If that matters
  to you, use `--sandbox docker`.
- **Build scripts are target code.** `npm run build` and `go build` execute
  whatever the target defines. `--ignore-scripts` covers npm *lifecycle* hooks,
  not an explicit build you asked for.
- **Docker mode isolates the target from your host, not from itself.** A target
  that is happy to destroy its own container is unaffected by any of this.

## Reporting

Security issues in MCP Guard itself: open an issue on the repository.
