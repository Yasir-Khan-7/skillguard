"""Render scan results for humans and for CI."""

from __future__ import annotations

import json

from .scanner import ScanResult

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[96m",
    "low": "\033[94m",
    "info": "\033[90m",
}
VERDICT_COLOR = {"pass": "\033[92m", "review": "\033[93m", "block": "\033[91m"}
VERDICT_LABEL = {"pass": "PASS", "review": "NEEDS REVIEW", "block": "BLOCK"}


def _loc(finding) -> str:
    """file:line for static findings; sandbox findings have no line."""
    return f"{finding.file}:{finding.line}" if finding.line else finding.file


def _c(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def render_terminal(result: ScanResult, color: bool = True, show_why: bool = True) -> str:
    lines: list[str] = []
    verdict = result.verdict

    lines.append("")
    lines.append(_c(f"  {result.skill_name}", BOLD, color))
    if result.description:
        desc = result.description if len(result.description) <= 96 else result.description[:95] + "…"
        lines.append(_c(f"  {desc}", DIM, color))
    lines.append("")

    bar_filled = round(result.score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    verdict_text = _c(f"[ {VERDICT_LABEL[verdict]} ]", VERDICT_COLOR[verdict] + BOLD, color)
    lines.append(f"  Trust score  {bar}  {result.score}/100   {verdict_text}")

    counts = result.counts()
    summary_parts = [
        f"{counts[level]} {level}"
        for level in ("critical", "high", "medium", "low")
        if counts.get(level)
    ]
    summary = ", ".join(summary_parts) if summary_parts else "no findings"
    lines.append(f"  {result.file_count} files scanned · {summary}")

    if result.capabilities:
        lines.append(f"  Capabilities: {', '.join(result.capabilities)}")
    if result.undeclared_capabilities:
        lines.append(
            _c(
                f"  Undeclared: {', '.join(result.undeclared_capabilities)} "
                f"(not covered by allowed-tools)",
                COLORS["high"],
                color,
            )
        )
    if result.network_hosts:
        shown = ", ".join(result.network_hosts[:6])
        extra = "" if len(result.network_hosts) <= 6 else f" (+{len(result.network_hosts) - 6} more)"
        lines.append(f"  Network: {shown}{extra}")

    for error in result.parse_errors:
        lines.append(_c(f"  ! {error}", COLORS["medium"], color))

    if result.sandbox is not None:
        lines.extend(_render_sandbox(result.sandbox, color))

    if result.findings:
        lines.append("")
        current_severity = None
        for finding in result.findings:
            if finding.severity != current_severity:
                current_severity = finding.severity
                lines.append(
                    _c(f"  {finding.severity.upper()}", COLORS[finding.severity] + BOLD, color)
                )
            marker = _c("●", COLORS[finding.severity], color)
            lines.append(f"    {marker} {finding.rule_id}  {finding.rule_name}")
            lines.append(_c(f"        {_loc(finding)}", DIM, color))
            lines.append(f"        {finding.excerpt}")
            if show_why:
                lines.append(_c(f"        → {finding.why}", DIM, color))
        lines.append("")
    else:
        lines.append("")
        lines.append(_c("  No rule matches.", COLORS["low"], color))
        lines.append("")

    return "\n".join(lines)


def _render_sandbox(sb: dict, color: bool) -> list[str]:
    lines = [""]
    if sb.get("error"):
        lines.append(_c(f"  Sandbox: unavailable ({sb['error']})", COLORS["medium"], color))
        return lines
    runs = sb.get("runs") or []
    lines.append(_c(f"  Sandbox: {len(runs)} script{'s' if len(runs) != 1 else ''} executed "
                    f"({sb.get('image')})", BOLD, color))
    for run in runs:
        status = "timed out" if run["timed_out"] else f"exit {run['exit_code']}"
        lines.append(f"    {run['command']}  ·  {status} in {run['duration_s']}s")
        if run["canary_reads"]:
            lines.append(_c(f"      decoys read: {', '.join(run['canary_reads'])}",
                            COLORS["critical"], color))
        if run["connections"]:
            lines.append(_c(f"      connections: {', '.join(run['connections'])}",
                            COLORS["high"], color))
        procs = [p for p in run["processes"][1:]][:8]
        if procs:
            lines.append(_c(f"      spawned: {' | '.join(p[:60] for p in procs)}", DIM, color))
        outside = [p for p in run["files_written"] if "/skill/" not in p]
        if outside:
            lines.append(f"      wrote: {', '.join(outside[:6])}")
        if run.get("trace_error"):
            lines.append(_c(f"      ! {run['trace_error']}", COLORS["medium"], color))
    for item in sb.get("skipped") or []:
        lines.append(_c(f"    skipped: {item}", DIM, color))
    return lines


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_markdown(result: ScanResult) -> str:
    counts = result.counts()
    lines = [
        f"# SkillGuard report: {result.skill_name}",
        "",
        f"**Verdict:** {VERDICT_LABEL[result.verdict]} · **Score:** {result.score}/100",
        "",
        f"- Files scanned: {result.file_count}",
        (
            f"- Findings: {counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low"
        ),
    ]
    if result.capabilities:
        lines.append(f"- Capabilities: {', '.join(result.capabilities)}")
    if result.undeclared_capabilities:
        lines.append(f"- Undeclared capabilities: {', '.join(result.undeclared_capabilities)}")
    if result.network_hosts:
        lines.append(f"- Network hosts: {', '.join(result.network_hosts)}")
    lines.append("")

    if result.findings:
        lines += ["| Severity | Rule | Location | Detail |", "| --- | --- | --- | --- |"]
        for finding in result.findings:
            excerpt = finding.excerpt.replace("|", "\\|")
            lines.append(
                f"| {finding.severity} | {finding.rule_id} {finding.rule_name} | "
                f"`{_loc(finding)}` | `{excerpt}` |"
            )
    else:
        lines.append("No rule matches.")
    lines.append("")
    return "\n".join(lines)


def _sarif_uri(res: ScanResult, finding, results: list[ScanResult]) -> str:
    """Prefix the path with the skill root when several skills share one report."""
    if len(results) == 1:
        return finding.file
    return f"{res.root.rstrip('/').split('/')[-1]}/{finding.file}"


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}


def render_sarif(result: ScanResult | list[ScanResult]) -> str:
    results = result if isinstance(result, list) else [result]
    rule_ids = {}
    for res in results:
        for finding in res.findings:
            rule_ids[finding.rule_id] = finding

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillGuard",
                        "informationUri": "https://github.com/Yasir-Khan-7/skillguard",
                        "rules": [
                            {
                                "id": rid,
                                "name": f.rule_name,
                                "shortDescription": {"text": f.rule_name},
                                "fullDescription": {"text": f.why},
                                "properties": {"category": f.category, "severity": f.severity},
                            }
                            for rid, f in sorted(rule_ids.items())
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": SARIF_LEVEL.get(f.severity, "note"),
                        "message": {"text": f"{f.rule_name}: {f.why}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": _sarif_uri(res, f, results)},
                                    **({"region": {"startLine": f.line}} if f.line else {}),
                                }
                            }
                        ],
                    }
                    for res in results
                    for f in res.findings
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_summary_line(result: ScanResult, color: bool = True) -> str:
    verdict = result.verdict
    label = _c(VERDICT_LABEL[verdict].ljust(12), VERDICT_COLOR[verdict], color)
    return f"  {label} {str(result.score).rjust(3)}/100  {result.skill_name}"
