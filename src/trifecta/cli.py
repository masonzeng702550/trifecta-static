"""``trifecta`` command-line entry point.

    trifecta scan <path> [options]

Exit codes: 0 = clean (or below --fail-on), 1 = findings at/above threshold,
2 = usage / IO error. The non-zero finding code is what wires it into a CI
gate.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .baseline import write_baseline
from .report import to_json, to_sarif, to_table
from .report.finding import severity_at_least
from .scan import run_scan

_FRAMEWORKS = ["auto", "langchain", "llamaindex", "mcp", "openai", "anthropic", "crewai", "autogen"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trifecta",
        description="Static detection of the lethal trifecta in AI agent codebases.",
    )
    p.add_argument("--version", action="version", version=f"trifecta-static {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a path for lethal-trifecta findings.")
    scan.add_argument("path", help="File or directory to scan.")
    scan.add_argument(
        "--framework",
        action="append",
        choices=_FRAMEWORKS,
        help="Limit to one or more frameworks (repeatable). Default: auto.",
    )
    scan.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    scan.add_argument(
        "--depth",
        choices=["shallow", "deep"],
        default="shallow",
        help="shallow = co-location only; deep = add taint/reachability.",
    )
    scan.add_argument("--llm-classify", action="store_true", help="Enable optional LLM-assisted classification.")
    scan.add_argument("--egress-allowlist", metavar="FILE", help="File of trusted egress hosts, one per line.")
    scan.add_argument("--baseline", metavar="FILE", help="Suppress findings recorded in this baseline file.")
    scan.add_argument("--write-baseline", metavar="FILE", help="Write current findings as a baseline and exit 0.")
    scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="Exit non-zero when a finding at or above this severity remains. Default: high.",
    )
    scan.add_argument("-o", "--output", metavar="FILE", help="Write report to FILE instead of stdout.")
    scan.add_argument("--no-color", action="store_true", help="Disable ANSI colour in table output.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    return 2


def _cmd_scan(args) -> int:
    if not os.path.exists(args.path):
        print(f"trifecta: path not found: {args.path}", file=sys.stderr)
        return 2

    frameworks = _resolve_frameworks(args.framework)
    allowlist = _load_allowlist(args.egress_allowlist)

    try:
        result = run_scan(
            args.path,
            frameworks=frameworks,
            depth=args.depth,
            use_llm=args.llm_classify,
            egress_allowlist=allowlist,
            baseline_path=args.baseline,
        )
    except OSError as exc:
        print(f"trifecta: {exc}", file=sys.stderr)
        return 2

    if args.write_baseline:
        write_baseline(args.write_baseline, result.findings)
        print(f"trifecta: wrote baseline with {len(result.findings)} finding(s) to {args.write_baseline}", file=sys.stderr)
        return 0

    report = _render(args.format, result, color=not args.no_color)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)

    return _exit_code(result.findings, args.fail_on)


def _resolve_frameworks(selected):
    if not selected or "auto" in selected:
        return None
    return set(selected)


def _load_allowlist(path):
    if not path:
        return set()
    hosts = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.add(line)
    return hosts


def _render(fmt, result, *, color):
    if fmt == "json":
        return to_json(result.findings, frameworks=result.frameworks, depth=result.depth)
    if fmt == "sarif":
        return to_sarif(result.findings)
    return to_table(result.findings, frameworks=result.frameworks, depth=result.depth, color=color)


def _exit_code(findings, fail_on) -> int:
    for f in findings:
        if severity_at_least(f.severity, fail_on):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
