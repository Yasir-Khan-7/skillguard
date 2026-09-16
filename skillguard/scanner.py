"""Scan a parsed skill package and produce findings, capabilities and a score."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .parser import Skill
from .rules import RULES, SEVERITY_ORDER, SEVERITY_WEIGHT, Rule

# Files whose contents are examples, not instructions the agent will run.
DOC_HINTS = ("readme", "changelog", "contributing", "license", "security.md")

URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)")
ALLOWED_DOC_DOMAINS = {"github.com", "raw.githubusercontent.com", "docs.python.org", "pypi.org"}


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    category: str
    file: str
    line: int
    excerpt: str
    why: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    skill_name: str
    root: str
    description: str
    findings: list[Finding] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    declared_tools: list[str] = field(default_factory=list)
    undeclared_capabilities: list[str] = field(default_factory=list)
    network_hosts: list[str] = field(default_factory=list)
    file_count: int = 0
    parse_errors: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        """100 is clean. Every finding subtracts weight by severity."""
        penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in self.findings)
        penalty += 8 * len(self.undeclared_capabilities)
        return max(0, 100 - penalty)

    @property
    def verdict(self) -> str:
        if any(f.severity == "critical" for f in self.findings):
            return "block"
        score = self.score
        if score >= 85:
            return "pass"
        if score >= 55:
            return "review"
        return "block"

    def counts(self) -> dict[str, int]:
        out = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "skill": self.skill_name,
            "root": self.root,
            "description": self.description,
            "score": self.score,
            "verdict": self.verdict,
            "counts": self.counts(),
            "capabilities": self.capabilities,
            "declared_tools": self.declared_tools,
            "undeclared_capabilities": self.undeclared_capabilities,
            "network_hosts": self.network_hosts,
            "file_count": self.file_count,
            "parse_errors": self.parse_errors,
            "findings": [f.to_dict() for f in self.findings],
        }


CAPABILITY_PATTERNS: dict[str, str] = {
    "shell": r"\b(bash|sh|zsh|subprocess|child_process|os\.system|Popen|execSync)\b",
    "network": r"\b(curl|wget|requests\.|httpx|fetch\(|axios|urllib|nc\s|socket\.)\b",
    "filesystem-write": r"\b(open\([^)]*['\"][wa]|fs\.write|>>?\s*[\w./~-]+|rm\s|mv\s|cp\s|mkdir\s)",
    "filesystem-read": r"\b(cat\s|open\([^)]*['\"]r|fs\.read|Path\([^)]*\)\.read)",
    "package-install": r"\b(pip3?\s+install|npm\s+i(nstall)?|yarn\s+add|apt(-get)?\s+install|brew\s+install)\b",
    "browser": r"\b(playwright|puppeteer|selenium|webdriver|chromedriver)\b",
    "database": r"\b(psycopg|sqlite3|mysql|mongodb|redis\.|DROP TABLE|DELETE FROM)\b",
    "credentials": r"\b(os\.environ|process\.env|\.env\b|api[_-]?key|token)\b",
}

# Rough map from declared tool names to the capability they imply.
TOOL_CAPABILITY = {
    "bash": {"shell"},
    "shell": {"shell"},
    "execute": {"shell"},
    "read": {"filesystem-read"},
    "write": {"filesystem-write"},
    "edit": {"filesystem-write"},
    "webfetch": {"network"},
    "web_search": {"network"},
    "websearch": {"network"},
    "fetch": {"network"},
    "browser": {"browser", "network"},
    "playwright": {"browser", "network"},
}


def _is_doc(relpath: str) -> bool:
    lowered = relpath.lower()
    return any(hint in lowered for hint in DOC_HINTS)


def _excerpt(line: str, limit: int = 160) -> str:
    stripped = line.strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[: limit - 1] + "…"


def _scan_text(
    relpath: str,
    text: str,
    rules: tuple[Rule, ...],
    severity_floor: int,
) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for rule in rules:
        if SEVERITY_ORDER.get(rule.severity, 0) < severity_floor:
            continue
        # Documentation gets a pass on hygiene-level noise only.
        if _is_doc(relpath) and rule.severity in {"low", "info"}:
            continue
        regex = rule.compiled()
        for index, line in enumerate(lines, start=1):
            if regex.search(line):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        file=relpath,
                        line=index,
                        excerpt=_excerpt(line),
                        why=rule.why,
                    )
                )
        # Multi-line constructs (hidden comments, long blobs) need a whole-text pass.
        if rule.id in {"SG503", "SG303"}:
            for match in regex.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                already = any(f.rule_id == rule.id and f.line == line_no and f.file == relpath
                              for f in findings)
                if not already:
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            file=relpath,
                            line=line_no,
                            excerpt=_excerpt(match.group(0)),
                            why=rule.why,
                        )
                    )
    return findings


def infer_capabilities(skill: Skill) -> list[str]:
    found: set[str] = set()
    for skill_file in skill.text_files():
        if _is_doc(skill_file.relpath):
            continue
        for capability, pattern in CAPABILITY_PATTERNS.items():
            if re.search(pattern, skill_file.text or "", re.IGNORECASE):
                found.add(capability)
    return sorted(found)


def collect_hosts(skill: Skill) -> list[str]:
    hosts: set[str] = set()
    for skill_file in skill.text_files():
        for match in URL_RE.finditer(skill_file.text or ""):
            host = match.group(1).lower()
            if _is_doc(skill_file.relpath) and host in ALLOWED_DOC_DOMAINS:
                continue
            hosts.add(host)
    return sorted(hosts)


def _undeclared(capabilities: list[str], declared_tools: list[str]) -> list[str]:
    if not declared_tools:
        return []
    covered: set[str] = set()
    for tool in declared_tools:
        key = tool.split("(")[0].strip().lower()
        covered |= TOOL_CAPABILITY.get(key, set())
    risky = {"shell", "network", "browser", "package-install", "filesystem-write"}
    return sorted(risky & set(capabilities) - covered)


def scan(skill: Skill, min_severity: str = "low") -> ScanResult:
    """Run every rule over every text file in the package."""
    floor = SEVERITY_ORDER.get(min_severity, 1)

    findings: list[Finding] = []
    for skill_file in skill.text_files():
        findings.extend(_scan_text(skill_file.relpath, skill_file.text or "", RULES, floor))

    findings.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line)
    )

    capabilities = infer_capabilities(skill)
    declared = skill.declared_tools

    return ScanResult(
        skill_name=skill.name,
        root=str(skill.root),
        description=skill.description,
        findings=findings,
        capabilities=capabilities,
        declared_tools=declared,
        undeclared_capabilities=_undeclared(capabilities, declared),
        network_hosts=collect_hosts(skill),
        file_count=len(skill.files),
        parse_errors=skill.parse_errors,
    )
