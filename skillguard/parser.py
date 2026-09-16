"""Parse a skill package: SKILL.md frontmatter, body, and bundled files."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

TEXT_SUFFIXES = {
    ".md", ".txt", ".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
    ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".rb", ".pl", ".ps1",
    ".env", ".sql", ".rs", ".go", ".php", ".java", ".lua",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}

MAX_FILE_BYTES = 2_000_000


@dataclass
class SkillFile:
    """One file inside the skill package."""

    path: Path
    relpath: str
    text: str | None
    size: int

    @property
    def is_text(self) -> bool:
        return self.text is not None


@dataclass
class Skill:
    """A parsed skill package."""

    root: Path
    manifest_path: Path
    frontmatter: dict = field(default_factory=dict)
    body: str = ""
    files: list[SkillFile] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return str(self.frontmatter.get("name") or self.root.name)

    @property
    def description(self) -> str:
        return str(self.frontmatter.get("description") or "")

    @property
    def declared_tools(self) -> list[str]:
        raw = self.frontmatter.get("allowed-tools") or self.frontmatter.get("allowed_tools") or []
        if isinstance(raw, str):
            return [part.strip() for part in raw.split(",") if part.strip()]
        if isinstance(raw, list):
            return [str(item).strip() for item in raw]
        return []

    def text_files(self) -> list[SkillFile]:
        return [f for f in self.files if f.is_text]


def _split_frontmatter(raw: str) -> tuple[str, str]:
    """Return (frontmatter_text, body). Empty frontmatter if absent."""
    if not raw.startswith("---"):
        return "", raw
    lines = raw.splitlines()
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            return "\n".join(lines[1:index]), "\n".join(lines[index + 1:])
    return "", raw


def _read_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile", "Makefile"}:
        return None
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def find_manifest(root: Path) -> Path | None:
    """Locate SKILL.md at the package root, or one level down."""
    direct = root / "SKILL.md"
    if direct.is_file():
        return direct
    for child in sorted(root.iterdir()) if root.is_dir() else []:
        candidate = child / "SKILL.md"
        if child.is_dir() and candidate.is_file():
            return candidate
    return None


def parse_skill(path: str | os.PathLike) -> Skill:
    """Parse a skill directory (or a direct path to a SKILL.md file)."""
    target = Path(path).resolve()

    if target.is_file():
        manifest = target
        root = target.parent
    else:
        found = find_manifest(target)
        if found is None:
            raise FileNotFoundError(f"No SKILL.md found in {target}")
        manifest = found
        root = manifest.parent

    raw = manifest.read_text(encoding="utf-8", errors="replace")
    fm_text, body = _split_frontmatter(raw)

    frontmatter: dict = {}
    errors: list[str] = []
    if fm_text.strip():
        if yaml is None:
            errors.append("PyYAML is not installed; frontmatter was not parsed")
        else:
            try:
                loaded = yaml.safe_load(fm_text)
                if isinstance(loaded, dict):
                    frontmatter = loaded
                else:
                    errors.append("Frontmatter is not a YAML mapping")
            except Exception as exc:  # noqa: BLE001 - surfaced to the user
                errors.append(f"Frontmatter YAML error: {exc}")

    files: list[SkillFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in sorted(filenames):
            full = Path(dirpath) / filename
            try:
                size = full.stat().st_size
            except OSError:
                continue
            files.append(
                SkillFile(
                    path=full,
                    relpath=str(full.relative_to(root)),
                    text=_read_text(full),
                    size=size,
                )
            )

    return Skill(
        root=root,
        manifest_path=manifest,
        frontmatter=frontmatter,
        body=body,
        files=files,
        parse_errors=errors,
    )
