"""SkillGuard command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .parser import find_manifest, parse_skill
from .report import (
    render_json,
    render_markdown,
    render_sarif,
    render_summary_line,
    render_terminal,
)
from .rules import RULES
from .scanner import ScanResult, scan

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

VERDICT_RANK = {"pass": 0, "review": 1, "block": 2}


def _discover(root: Path) -> list[Path]:
    """Find every skill package under a directory."""
    if (root / "SKILL.md").is_file():
        return [root]
    packages: list[Path] = []
    for manifest in sorted(root.rglob("SKILL.md")):
        if any(part in {".git", "node_modules", "__pycache__"} for part in manifest.parts):
            continue
        packages.append(manifest.parent)
    return packages


def _scan_path(path: Path, min_severity: str) -> ScanResult:
    return scan(parse_skill(path), min_severity=min_severity)


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"skillguard: path not found: {target}", file=sys.stderr)
        return EXIT_ERROR

    if target.is_file():
        packages = [target]
    else:
        packages = _discover(target)
        if not packages:
            print(f"skillguard: no SKILL.md found under {target}", file=sys.stderr)
            return EXIT_ERROR

    color = not args.no_color and sys.stdout.isatty()
    results: list[ScanResult] = []

    for package in packages:
        try:
            results.append(_scan_path(package, args.min_severity))
        except FileNotFoundError as exc:
            print(f"skillguard: {exc}", file=sys.stderr)
            return EXIT_ERROR

    if args.format == "json":
        payload = results[0].to_dict() if len(results) == 1 else [r.to_dict() for r in results]
        import json

        print(json.dumps(payload, indent=2) if len(results) > 1 else render_json(results[0]))
    elif args.format == "sarif":
        print(render_sarif(results if len(results) > 1 else results[0]))
    elif args.format == "markdown":
        print("\n".join(render_markdown(r) for r in results))
    else:
        if len(results) > 1:
            print(f"\n  Scanned {len(results)} skill packages\n")
            for result in sorted(results, key=lambda r: -VERDICT_RANK[r.verdict]):
                print(render_summary_line(result, color))
            print()
            for result in results:
                if result.verdict != "pass" or args.verbose:
                    print(render_terminal(result, color, show_why=not args.quiet_why))
        else:
            print(render_terminal(results[0], color, show_why=not args.quiet_why))

    worst = max(VERDICT_RANK[r.verdict] for r in results)
    threshold = VERDICT_RANK[args.fail_on]
    return EXIT_FINDINGS if worst >= threshold else EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    if args.format == "json":
        import json

        print(
            json.dumps(
                [
                    {
                        "id": r.id,
                        "name": r.name,
                        "severity": r.severity,
                        "category": r.category,
                        "why": r.why,
                    }
                    for r in RULES
                ],
                indent=2,
            )
        )
        return EXIT_OK

    grouped: dict[str, list] = {}
    for rule in RULES:
        grouped.setdefault(rule.category, []).append(rule)

    print(f"\n  {len(RULES)} rules\n")
    for category in sorted(grouped):
        print(f"  {category}")
        for rule in grouped[category]:
            print(f"    {rule.id}  {rule.severity.ljust(8)}  {rule.name}")
        print()
    return EXIT_OK


def cmd_info(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    manifest = target if target.is_file() else find_manifest(target)
    if manifest is None:
        print(f"skillguard: no SKILL.md found under {target}", file=sys.stderr)
        return EXIT_ERROR

    skill = parse_skill(manifest)
    print(f"\n  name         {skill.name}")
    print(f"  manifest     {skill.manifest_path}")
    print(f"  description  {skill.description or '(none)'}")
    print(f"  allowed      {', '.join(skill.declared_tools) or '(not declared)'}")
    print(f"  files        {len(skill.files)}")
    for skill_file in skill.files[:25]:
        marker = " " if skill_file.is_text else "·"
        print(f"    {marker} {skill_file.relpath}  ({skill_file.size} bytes)")
    if len(skill.files) > 25:
        print(f"    … {len(skill.files) - 25} more")
    print()
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve

    return serve(host=args.host, port=args.port, open_browser=not args.no_browser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillguard",
        description="Static safety scanner for agent skill packages (SKILL.md).",
    )
    parser.add_argument("--version", action="version", version=f"skillguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="scan a skill package or a directory of packages")
    scan_parser.add_argument("path", help="path to a skill directory, SKILL.md, or a parent folder")
    scan_parser.add_argument(
        "--format", choices=["terminal", "json", "sarif", "markdown"], default="terminal"
    )
    scan_parser.add_argument(
        "--min-severity", choices=["info", "low", "medium", "high", "critical"], default="low"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["pass", "review", "block"],
        default="block",
        help="exit non-zero at this verdict or worse (default: block)",
    )
    scan_parser.add_argument("--no-color", action="store_true")
    scan_parser.add_argument("--quiet-why", action="store_true", help="hide the explanation lines")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="show passing skills too")
    scan_parser.set_defaults(func=cmd_scan)

    rules_parser = sub.add_parser("rules", help="list the detection rules")
    rules_parser.add_argument("--format", choices=["terminal", "json"], default="terminal")
    rules_parser.set_defaults(func=cmd_rules)

    info_parser = sub.add_parser("info", help="show a skill's manifest and file list")
    info_parser.add_argument("path")
    info_parser.set_defaults(func=cmd_info)

    serve_parser = sub.add_parser("serve", help="open a local web UI for scanning skills")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    serve_parser.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
