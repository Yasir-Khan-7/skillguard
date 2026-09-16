"""Detection rules for skill packages.

Each rule is a regular expression with a severity, a category and a plain
explanation of why it matters. Rules are deliberately data, not code, so that
new ones can be added without touching the scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHT = {"critical": 45, "high": 25, "medium": 10, "low": 4, "info": 0}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    category: str
    pattern: str
    why: str
    flags: int = re.IGNORECASE

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern, self.flags)


RULES: tuple[Rule, ...] = (
    # --- credential access -------------------------------------------------
    Rule(
        id="SG101",
        name="Reads SSH private keys",
        severity="critical",
        category="credentials",
        pattern=r"~/\.ssh/id_[a-z0-9_]+|\.ssh/id_rsa|ssh/authorized_keys",
        why="Private keys give an attacker persistent access to every host you can reach.",
    ),
    Rule(
        id="SG102",
        name="Reads cloud or provider credentials",
        severity="critical",
        category="credentials",
        pattern=r"~/\.aws/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|"
                r"~/\.netrc|\.npmrc\b|\.pypirc\b",
        why="These files hold long-lived tokens for cloud accounts and package registries.",
    ),
    Rule(
        id="SG103",
        name="Harvests environment variables wholesale",
        severity="high",
        category="credentials",
        pattern=r"\bprintenv\b|\benv\s*\|\s*(curl|nc|base64)|os\.environ\b\s*\)|json\.dumps\(\s*dict\(\s*os\.environ",
        why="Dumping the whole environment usually means exfiltrating API keys, not reading one setting.",
    ),
    Rule(
        id="SG104",
        name="Touches wallet or keychain material",
        severity="critical",
        category="credentials",
        pattern=r"wallet\.dat|keychain\s+dump|security\s+find-generic-password|"
                r"metamask|\.electrum|Local Storage/leveldb",
        why="Crypto wallets and OS keychains are a common target of malicious skills.",
    ),

    # --- exfiltration ------------------------------------------------------
    Rule(
        id="SG201",
        name="Pipes local data to a remote host",
        severity="critical",
        category="exfiltration",
        pattern=r"(cat|tar|zip|base64|cp)\s+[^\n|]{0,120}\|\s*(curl|wget|nc|ncat|socat)\b",
        why="Reading a file and piping it straight to the network is the classic exfiltration shape.",
    ),
    Rule(
        id="SG202",
        name="POSTs a file body to an external URL",
        severity="high",
        category="exfiltration",
        pattern=r"curl[^\n]{0,160}(-d\s*@|--data-binary\s*@|-F\s*['\"]?file=@)",
        why="Uploads a local file to a server the user never chose.",
    ),
    Rule(
        id="SG203",
        name="Hardcoded raw IP endpoint",
        severity="high",
        category="exfiltration",
        pattern=r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?",
        why="Legitimate skills call named services; raw IPs are typical of drop servers.",
    ),
    Rule(
        id="SG204",
        name="Reverse shell",
        severity="critical",
        category="exfiltration",
        pattern=r"bash\s+-i\s*>&\s*/dev/tcp/|nc\s+(-[a-z]*e|.*-e\s*/bin/(ba)?sh)|"
                r"socket\.socket\([^\n]{0,80}\)[^\n]{0,80}subprocess\.call",
        why="Opens an interactive shell back to an attacker-controlled host.",
    ),
    Rule(
        id="SG205",
        name="Webhook or paste-site upload",
        severity="medium",
        category="exfiltration",
        pattern=r"(hooks\.slack\.com|discord(app)?\.com/api/webhooks|pastebin\.com/api|"
                r"webhook\.site|requestbin|ngrok\.io|trycloudflare\.com)",
        why="Common collection points for stolen data. Fine if the skill is about that service.",
    ),

    # --- remote code execution --------------------------------------------
    Rule(
        id="SG301",
        name="Downloads and executes a remote script",
        severity="critical",
        category="rce",
        pattern=r"(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|d)?sh\b|"
                r"(curl|wget)[^\n|]{0,200}\|\s*(python3?|node|ruby|perl)\b",
        why="Whatever that URL serves today runs with your privileges, unreviewed.",
    ),
    Rule(
        id="SG302",
        name="Evaluates dynamically built code",
        severity="high",
        category="rce",
        pattern=r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|child_process\.exec\s*\(|"
                r"subprocess\.(run|call|Popen)\([^\n]{0,120}shell\s*=\s*True",
        why="Dynamic execution hides the real behaviour from review and from this scanner.",
    ),
    Rule(
        id="SG303",
        name="Obfuscated payload",
        severity="high",
        category="rce",
        pattern=r"base64\s+(-d|--decode)\b[^\n]{0,60}\|\s*(ba)?sh|"
                r"atob\s*\(|codecs\.decode\([^\n]{0,60}rot_?13|"
                r"[A-Za-z0-9+/]{220,}={0,2}",
        why="Long encoded blobs in a skill file are almost never benign.",
    ),

    # --- destructive / persistence ----------------------------------------
    Rule(
        id="SG401",
        name="Destructive filesystem command",
        severity="critical",
        category="destructive",
        pattern=r"rm\s+-[a-z]*r[a-z]*f\s+(/\s|/\*|/$|~/?\s|~/?$|\$HOME\b|\*/|\s\*\s)|mkfs\.|dd\s+if=/dev/(zero|urandom)\s+of=/dev/",
        why="Can wipe the user's machine with no confirmation step.",
    ),
    Rule(
        id="SG402",
        name="Installs persistence",
        severity="high",
        category="persistence",
        pattern=r"crontab\s+-|launchctl\s+load|systemctl\s+enable|"
                r"(>>|tee)\s*[^\n]{0,60}(\.bashrc|\.zshrc|\.profile|authorized_keys)",
        why="Keeps running after the skill finishes, outside the agent's lifecycle.",
    ),
    Rule(
        id="SG403",
        name="Escalates privileges",
        severity="medium",
        category="destructive",
        pattern=r"\bsudo\s+(-S|--stdin)\b|\bchmod\s+(777|\+s)\b|osascript[^\n]{0,80}administrator privileges",
        why="A skill should not need root, and should never supply a password non-interactively.",
    ),

    # --- prompt-layer attacks ---------------------------------------------
    Rule(
        id="SG501",
        name="Instruction-override text",
        severity="high",
        category="prompt-injection",
        pattern=r"ignore (all |any )?(previous|prior|above) (instructions|rules|prompts)|"
                r"disregard (your|the) (system prompt|guidelines|instructions)|"
                r"you are now in (developer|god|unrestricted) mode",
        why="Targets the agent's own reasoning rather than the operating system.",
    ),
    Rule(
        id="SG502",
        name="Tells the agent to hide its actions",
        severity="critical",
        category="prompt-injection",
        pattern=r"(do not|don'?t|never)\s+(tell|inform|mention|show|reveal|disclose)\s+"
                r"(the\s+)?(user|human|operator)|without (telling|informing|asking) the user|"
                r"silently (send|upload|forward|delete)",
        why="Concealment from the operator has no legitimate use in a skill.",
    ),
    Rule(
        id="SG503",
        name="Hidden text in the manifest",
        severity="high",
        category="prompt-injection",
        pattern=r"<!--[\s\S]{120,}?-->|[\u200b\u200c\u200d\u2060\ufeff]{3,}|"
                r"color\s*:\s*#f{3,6}\b",
        why="Text invisible to a human reviewer but still read by the model.",
    ),

    # --- hygiene -----------------------------------------------------------
    Rule(
        id="SG601",
        name="Committed secret",
        severity="high",
        category="hygiene",
        pattern=r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|"
                r"xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
        why="A live credential in the package leaks the author's account, and often the user's too.",
    ),
    Rule(
        id="SG602",
        name="Unpinned install from the internet",
        severity="low",
        category="hygiene",
        pattern=r"(pip3?\s+install|npm\s+i(nstall)?|cargo\s+install|go\s+install)\s+[^\n]{0,120}"
                r"(--pre|@latest|\bgit\+https?://)",
        why="Floating dependencies mean the reviewed version is not the installed version.",
    ),
)


def rules_by_category() -> dict[str, list[Rule]]:
    grouped: dict[str, list[Rule]] = {}
    for rule in RULES:
        grouped.setdefault(rule.category, []).append(rule)
    return grouped
