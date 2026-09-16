"""SkillGuard: static safety scanning for agent skill packages."""

__version__ = "0.1.0"

from .parser import Skill, parse_skill
from .scanner import Finding, ScanResult, scan

__all__ = ["Finding", "ScanResult", "Skill", "__version__", "parse_skill", "scan"]
