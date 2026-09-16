"""Dynamic analysis: run a skill's scripts in a throwaway Docker container.

The container has no network, no capabilities, a pid and memory cap, and a
fake home directory seeded with decoy credentials. Every script is traced
with strace so we see what it *tried* to do: which files it opened, what it
executed, and where it attempted to connect.

Everything here shells out to the ``docker`` CLI; no Python dependencies.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .parser import Skill
from .scanner import Finding

IMAGE = "skillguard-sandbox:0.2"
HOME = "/home/agent"
WORK = f"{HOME}/skill"
OUT = "/out"

DOCKERFILE = """\
FROM debian:bookworm-slim
RUN apt-get update -qq \\
 && apt-get install -y -qq --no-install-recommends \\
      strace bash python3 curl wget ca-certificates coreutils procps git cron sudo >/dev/null \\
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 -s /bin/bash agent
USER agent
WORKDIR /home/agent
"""

# Decoy secrets. The content is deliberately fake but shaped like the real
# thing, so a script that greps for "AKIA" or "PRIVATE KEY" still bites.
DECOYS: dict[str, str] = {
    ".ssh/id_rsa": (
        "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n"
        "SKILLGUARD-DECOY-0000000000000000000000000000000000000000\n"
        "-----END OPENSSH " + "PRIVATE KEY-----\n"
    ),
    ".ssh/id_ed25519": "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nSKILLGUARD-DECOY\n-----END OPENSSH " + "PRIVATE KEY-----\n",
    ".aws/credentials": (
        "[default]\naws_access_key_id = " + "AKIA" + "SKILLGUARDDECOY1\n"
        "aws_secret_access_key = skillguard/decoy/secret/not/real/0000000000\n"
    ),
    ".npmrc": "//registry.npmjs.org/:_authToken=npm_SKILLGUARDDECOY000000000000000000000\n",
    ".netrc": "machine github.com login decoy password skillguard-decoy-token\n",
    ".env": "OPENAI_API_KEY=" + "sk-" + "SKILLGUARDDECOY000000000000000000000000\nDATABASE_URL=postgres://decoy:decoy@localhost/decoy\n",
    ".config/gcloud/credentials.db": "SKILLGUARD-DECOY\n",
    ".kube/config": "apiVersion: v1\nusers:\n- name: decoy\n  user:\n    token: skillguard-decoy\n",
    ".gitconfig": "[user]\n\tname = Decoy User\n\temail = decoy@example.com\n",
}

# Files a well-behaved script might legitimately read; not canaries.
BENIGN_HOME_FILES = {".bashrc", ".profile", ".bash_logout", ".gitconfig"}

INTERPRETERS = {
    ".sh": ["bash"],
    ".bash": ["bash"],
    ".zsh": ["bash"],  # zsh is not installed; bash is close enough to observe intent
    ".py": ["python3"],
}

SHELL_BINARIES = {"bash", "sh", "dash", "zsh"}
NETWORK_BINARIES = {"curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "git"}
PRIVILEGE_BINARIES = {"sudo", "su", "doas", "chmod", "chown", "crontab", "systemctl", "launchctl"}

# Matches completed calls, "call(args) = ret", and interleaved ones, "call(args <unfinished ...>".
_TRACE_RE = re.compile(r"^(\d+)\s+(\w+)\((.*?)(?:\)\s*=\s*(-?\d+|\?).*|\s*<unfinished \.\.\.>)$")
_DIRFD_RE = re.compile(r"^\s*(?:\d+|AT_FDCWD)<([^>]*)>")  # strace -y decorates fds as 4</home/agent/.ssh>
_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_INET_RE = re.compile(r'sin6?_addr=inet6?_addr\("([^"]+)"\)')
_PORT_RE = re.compile(r"sin6?_port=htons\((\d+)\)")


class SandboxUnavailable(RuntimeError):
    """Docker is missing, not running, or the image could not be built."""


@dataclass
class ScriptRun:
    command: str
    exit_code: int | None
    duration_s: float
    timed_out: bool
    canary_reads: list[str] = field(default_factory=list)
    home_reads: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    connections: list[str] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    trace_error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SandboxResult:
    image: str
    runs: list[ScriptRun] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def canary_reads(self) -> list[str]:
        return sorted({c for r in self.runs for c in r.canary_reads})

    @property
    def connections(self) -> list[str]:
        return sorted({c for r in self.runs for c in r.connections})

    def to_dict(self) -> dict:
        return {
            "image": self.image,
            "runs": [r.to_dict() for r in self.runs],
            "skipped": self.skipped,
            "error": self.error,
            "canary_reads": self.canary_reads,
            "connections": self.connections,
        }

    def to_findings(self) -> list[Finding]:
        """Turn observed behaviour into findings that merge with static ones."""
        findings: list[Finding] = []

        def add(rule_id: str, name: str, severity: str, category: str, file: str,
                excerpt: str, why: str) -> None:
            findings.append(Finding(rule_id, name, severity, category, file, 0, excerpt, why))

        for run in self.runs:
            script = run.command
            for path in run.canary_reads:
                add("SG701", "Read a decoy credential at runtime", "critical", "credentials",
                    script, f"opened {path}",
                    "The script has no reason to touch this file. This is observed behaviour, "
                    "not a pattern match.")
            for conn in run.connections:
                add("SG702", "Attempted a network connection", "high", "exfiltration",
                    script, f"connect {conn}",
                    "The sandbox has no network; the script tried anyway. Check the destination.")
            for proc in run.processes:
                name = proc.split()[0].rsplit("/", 1)[-1] if proc else ""
                if name in PRIVILEGE_BINARIES:
                    add("SG703", "Ran a privilege or persistence tool", "high", "persistence",
                        script, proc[:160],
                        "Skills should not need root, cron, or service managers.")
            outside = [p for p in run.files_written if not p.startswith(WORK + "/")]
            for path in outside:
                add("SG704", "Wrote outside the skill directory", "medium", "destructive",
                    script, f"wrote {path}",
                    "Writes to the home directory or system paths persist after the skill ends.")
            if run.timed_out:
                add("SG705", "Script did not finish within the timeout", "low", "hygiene",
                    script, f"killed after {run.duration_s:.0f}s",
                    "Hanging scripts often wait on a network that is not there, or on user input.")
        return findings


# --------------------------------------------------------------------------
# docker plumbing

def docker_available() -> tuple[bool, str]:
    exe = shutil.which("docker")
    if not exe:
        return False, "docker CLI not found on PATH"
    try:
        proc = subprocess.run([exe, "info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker not responding: {exc}"
    if proc.returncode != 0:
        return False, "docker daemon is not running (start Docker Desktop and retry)"
    return True, proc.stdout.strip()


def image_exists(image: str = IMAGE) -> bool:
    proc = subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False)
    return proc.returncode == 0


def build_image(image: str = IMAGE, quiet: bool = True) -> None:
    with tempfile.TemporaryDirectory(prefix="skillguard-build-") as tmp:
        (Path(tmp) / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
        cmd = ["docker", "build", "-t", image, tmp]
        if quiet:
            cmd.insert(2, "-q")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)
        if proc.returncode != 0:
            raise SandboxUnavailable(f"docker build failed:\n{proc.stderr[-2000:]}")


def ensure_image(image: str = IMAGE) -> None:
    ok, why = docker_available()
    if not ok:
        raise SandboxUnavailable(why)
    if not image_exists(image):
        build_image(image)


# --------------------------------------------------------------------------
# what to run

def discover_scripts(skill: Skill) -> tuple[list[tuple[str, list[str]]], list[str]]:
    """Return ([(relpath, argv-prefix)], skipped) for every runnable script."""
    runnable: list[tuple[str, list[str]]] = []
    skipped: list[str] = []
    for f in skill.files:
        rel = f.relpath
        suffix = Path(rel).suffix.lower()
        if suffix in INTERPRETERS:
            runnable.append((rel, INTERPRETERS[suffix]))
        elif f.is_text and (f.text or "").startswith("#!"):
            shebang = (f.text or "").splitlines()[0]
            if "python" in shebang:
                runnable.append((rel, ["python3"]))
            elif any(s in shebang for s in ("bash", "/sh", "zsh")):
                runnable.append((rel, ["bash"]))
            else:
                skipped.append(f"{rel} (unsupported interpreter: {shebang})")
        elif suffix in {".js", ".ts", ".rb", ".pl", ".ps1"}:
            skipped.append(f"{rel} (no interpreter for {suffix} in the sandbox yet)")
    return runnable, skipped


# --------------------------------------------------------------------------
# trace parsing

def _unescape(s: str) -> str:
    try:
        return s.encode("utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return s


def parse_trace(text: str, home: str = HOME, work: str = WORK) -> dict:
    """Extract canary reads, processes and connection attempts from strace output."""
    canaries: list[str] = []
    home_reads: list[str] = []
    processes: list[str] = []
    connections: list[str] = []
    decoy_paths = {f"{home}/{rel}" for rel in DECOYS}

    for line in text.splitlines():
        m = _TRACE_RE.match(line)
        if not m:
            continue
        _pid, call, args, _ret = m.groups()
        if call in {"openat", "open", "stat", "lstat", "readlink", "access", "statx", "newfstatat"}:
            strings = _STR_RE.findall(args)
            if not strings:
                continue
            path = _unescape(strings[0])
            if not path.startswith("/"):
                # relative to a directory fd: openat(4</home/agent/.ssh>, "id_rsa", ...)
                dirfd = _DIRFD_RE.match(args)
                if dirfd and dirfd.group(1).startswith("/"):
                    path = dirfd.group(1).rstrip("/") + "/" + path
                elif path != ".":
                    path = work + "/" + path  # AT_FDCWD: cwd is the skill dir
            path = _normalize(path)
            if _is_decoy(path, decoy_paths, home):
                canaries.append(path)
            elif path.startswith(home + "/") and not path.startswith(work + "/"):
                first = path[len(home) + 1:].split("/")[0]
                if first not in BENIGN_HOME_FILES and first != "skill":
                    home_reads.append(path)
        elif call == "execve":
            strings = _STR_RE.findall(args)
            if strings:
                argv = [_unescape(s) for s in strings[1:]] or [_unescape(strings[0])]
                processes.append(" ".join(argv)[:200])
        elif call == "connect":
            if "AF_UNIX" in args:
                continue
            addr = _INET_RE.search(args)
            port = _PORT_RE.search(args)
            if addr:
                connections.append(f"{addr.group(1)}:{port.group(1) if port else '?'}")
    return {
        "canary_reads": sorted(set(canaries)),
        "home_reads": sorted(set(home_reads)),
        "processes": _dedupe(processes),
        "connections": sorted(set(connections)),
    }


def _normalize(path: str) -> str:
    parts: list[str] = []
    for part in path.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def _is_decoy(path: str, decoy_paths: set[str], home: str) -> bool:
    """A decoy file, or a directory that exists only to hold decoys (~/.ssh, ~/.aws)."""
    if path in decoy_paths or any(path.startswith(d + "/") for d in decoy_paths):
        return True
    if not path.startswith(home + "/") or path == home + "/.config":
        return False
    return any(d.startswith(path + "/") for d in decoy_paths)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# --------------------------------------------------------------------------
# running

def _snapshot(root: Path) -> dict[str, str]:
    snap: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                snap[str(path)] = hashlib.sha1(path.read_bytes()).hexdigest()
            except OSError:
                continue
    return snap


def seed_home(home_dir: Path, skill_root: Path) -> None:
    for rel, content in DECOYS.items():
        target = home_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    for rel in (".ssh",):
        (home_dir / rel).chmod(0o700)
    shutil.copytree(skill_root, home_dir / "skill", symlinks=False,
                    ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__", ".venv"))


def run_skill(skill: Skill, timeout: int = 30, image: str = IMAGE,
              only: list[str] | None = None, keep_trace: Path | None = None) -> SandboxResult:
    """Execute each script of the skill in the sandbox and collect observations."""
    result = SandboxResult(image=image)
    try:
        ensure_image(image)
    except SandboxUnavailable as exc:
        result.error = str(exc)
        return result

    scripts, skipped = discover_scripts(skill)
    result.skipped = skipped
    if only:
        scripts = [s for s in scripts if s[0] in only]
    if not scripts:
        result.skipped.append("no runnable scripts found (only .sh/.py or shebang files are run)")
        return result

    for rel, interp in scripts:
        result.runs.append(_run_one(skill, rel, interp, timeout, image, keep_trace))
    return result


def _run_one(skill: Skill, rel: str, interp: list[str], timeout: int, image: str,
             keep_trace: Path | None = None) -> ScriptRun:
    with tempfile.TemporaryDirectory(prefix="skillguard-sbx-") as tmp:
        tmp_path = Path(tmp)
        home_dir = tmp_path / "home"
        out_dir = tmp_path / "out"
        home_dir.mkdir()
        out_dir.mkdir()
        # Docker Desktop on macOS maps the host user to uid 1000 inside the mount
        # only via file sharing; make everything world-writable so `agent` can work.
        seed_home(home_dir, skill.root)
        for p in [home_dir, *home_dir.rglob("*")]:
            try:
                p.chmod(0o777 if p.is_dir() else 0o666)
            except OSError:
                pass
        out_dir.chmod(0o777)
        before = _snapshot(home_dir)

        inner = (
            f"cd {WORK} && timeout -s KILL {timeout} "
            f"strace -f -qq -y -s 256 -e trace=openat,open,execve,connect,stat,lstat,statx,newfstatat "
            f"-o {OUT}/trace.log -- {' '.join(interp)} {_shq(rel)} "
            f">{OUT}/stdout.log 2>{OUT}/stderr.log; echo $? >{OUT}/exit"
        )
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256",
            "--memory", "512m",
            "--cpus", "1",
            "--user", "1000:1000",
            "-e", f"HOME={HOME}", "-e", "PATH=/usr/local/bin:/usr/bin:/bin",
            "-e", "SKILLGUARD_SANDBOX=1",
            "-v", f"{home_dir}:{HOME}",
            "-v", f"{out_dir}:{OUT}",
            "-w", WORK,
            image, "bash", "-c", inner,
        ]


        start = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60, check=False)
            docker_err = proc.stderr.strip()
        except subprocess.TimeoutExpired:
            docker_err = "docker run itself timed out"
        duration = time.monotonic() - start

        exit_text = (out_dir / "exit").read_text().strip() if (out_dir / "exit").exists() else ""
        exit_code = int(exit_text) if exit_text.lstrip("-").isdigit() else None
        timed_out = exit_code == 137
        trace = (out_dir / "trace.log").read_text(errors="replace") if (out_dir / "trace.log").exists() else ""
        if keep_trace is not None:
            keep_trace.mkdir(parents=True, exist_ok=True)
            (keep_trace / (rel.replace("/", "__") + ".strace")).write_text(trace, encoding="utf-8")
        parsed = parse_trace(trace)

        after = _snapshot(home_dir)
        written = sorted(
            _container_path(p, home_dir) for p, h in after.items() if before.get(p) != h
        )

        return ScriptRun(
            command=f"{' '.join(interp)} {rel}",
            exit_code=exit_code,
            duration_s=round(duration, 2),
            timed_out=timed_out,
            canary_reads=parsed["canary_reads"],
            home_reads=parsed["home_reads"],
            processes=parsed["processes"],
            connections=parsed["connections"],
            files_written=written,
            stdout=_tail(out_dir / "stdout.log"),
            stderr=_tail(out_dir / "stderr.log"),
            trace_error="" if trace else (docker_err or "no trace produced"),
        )


def _container_path(host_path: str, home_dir: Path) -> str:
    return HOME + host_path[len(str(home_dir)):]


def _tail(path: Path, limit: int = 1500) -> str:
    if not path.exists():
        return ""
    text = path.read_text(errors="replace")
    return text if len(text) <= limit else "…" + text[-limit:]


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def summarize(result: SandboxResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
