"""Command line interface.

Exit codes (contract for CI):
  0  clean -- scan completed, no finding at or above --fail-on
  1  findings at or above --fail-on
  2  scan error (crash, evidence violation, bad usage)
  3  target could not be analysed (acquire/detect failed, or nothing to scan)
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .models import Severity
from .report import console as console_report
from .report import json as json_report
from .report import sarif as sarif_report
from .report import summary as summary_report
from .report.verify import EvidenceViolation, verify_result

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_UNANALYSABLE = 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-guard",
        description=(
            "Security scanner for Model Context Protocol servers. "
            "Static and dependency analysis execute nothing. Dynamic analysis "
            "runs the target and requires --allow-execute."
        ),
    )
    p.add_argument("target", help="GitHub URL or local path")
    p.add_argument("--version", action="version", version=f"mcp-guard {__version__}")

    ex = p.add_argument_group("execution")
    ex.add_argument(
        "--allow-execute", action="store_true",
        help="permit dynamic analysis, which installs and RUNS the target's code",
    )
    ex.add_argument(
        "--sandbox", choices=("none", "docker"), default="none",
        help="isolation for dynamic analysis (default: none)",
    )
    ex.add_argument(
        "--skip-install", action="store_true",
        help="assume the target's dependencies are already present; skip the "
             "install step (it is also skipped automatically when node_modules "
             "already exists)",
    )
    ex.add_argument(
        "--entrypoint",
        help="launch this instead of the derived command, e.g. "
             "'node dist/server.js'. Use when derivation misses a server; "
             "the derived candidate chain is printed in stage artifacts.",
    )
    ex.add_argument(
        "--timeout", type=int, default=120,
        help="per-subprocess timeout in seconds (default: 120)",
    )

    sc = p.add_argument_group("stages")
    sc.add_argument("--no-static", action="store_true", help="skip static analysis")
    sc.add_argument("--no-deps", action="store_true", help="skip dependency analysis")
    sc.add_argument(
        "--quiet", action="store_true",
        help="suppress per-stage progress on stderr",
    )
    sc.add_argument(
        "--no-cache", action="store_true",
        help="do not read or write the static result cache (caching costs "
             "~25%% on a cold scan and saves ~87%% on a rescan)",
    )
    sc.add_argument(
        "--offline", action="store_true",
        help="do not contact the OSV API; dependency stage reports as not run",
    )

    out = p.add_argument_group("output")
    out.add_argument(
        "--format", choices=("console", "json", "sarif", "summary"),
        default="console",
    )
    out.add_argument("-o", "--output", help="write the report to this path")
    out.add_argument(
        "--include-transitive", action="store_true",
        help="show dependency findings for transitive packages too "
             "(the JSON report always contains them)",
    )
    out.add_argument(
        "--include-dev", action="store_true",
        help="show dependency findings for devDependencies too",
    )
    out.add_argument(
        "--min-severity",
        choices=("low", "medium", "high", "critical"), default="medium",
        help="minimum severity for dependency findings in the CONSOLE "
             "report (default: medium); JSON is never filtered",
    )
    out.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="exit 1 if any finding is at or above this severity (default: high)",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    from .scan import run_scan

    acquired = None
    try:
        result, acquired = run_scan(
            args.target,
            allow_execute=args.allow_execute,
            sandbox=args.sandbox,
            static_enabled=not args.no_static,
            deps_enabled=not args.no_deps,
            offline=args.offline,
            timeout=args.timeout,
            skip_install=args.skip_install,
            use_cache=not args.no_cache,
            entrypoint=args.entrypoint,
            progress=not args.quiet,
        )

        acq = result.status("acquire")
        if acq is None or not acq.ran:
            reason = acq.reason if acq else "acquire stage did not record a status"
            print(f"mcp-guard: target could not be acquired: {reason}",
                  file=sys.stderr)
            return EXIT_UNANALYSABLE

        # THE ONE RULE, enforced before anything is emitted.
        root = acquired.root if acquired else args.target
        verify_result(result, root)

        if args.format == "json":
            text = json_report.render(result)
        elif args.format == "sarif":
            text = sarif_report.render(result)
        elif args.format == "summary":
            text = summary_report.render(result)
        else:
            from .deps import filter_findings
            shown, suppressed = filter_findings(
                result.findings,
                include_transitive=args.include_transitive,
                include_dev=args.include_dev,
                min_severity=args.min_severity)
            text = console_report.render(result, shown=shown,
                                         suppressed=suppressed)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            print(f"report written to {args.output}", file=sys.stderr)
        else:
            print(text)

        if args.fail_on == "none":
            return EXIT_CLEAN
        threshold = Severity(args.fail_on).rank
        if any(f.severity.rank >= threshold for f in result.findings):
            return EXIT_FINDINGS
        return EXIT_CLEAN

    except EvidenceViolation as exc:
        print(f"mcp-guard: EVIDENCE VIOLATION -- refusing to emit a report.\n{exc}",
              file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("mcp-guard: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        print(f"mcp-guard: scan error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        if acquired is not None:
            acquired.cleanup()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
