"""A tiny local web UI for trying SkillGuard in the browser.

Standard library only. Binds to loopback by default; it is a developer tool,
not a public service.
"""

from __future__ import annotations

import json
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path, PurePosixPath

from . import __version__
from .parser import parse_skill
from .rules import RULES
from .scanner import scan

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
MAX_BODY = 5_000_000


def _load_examples() -> list[dict]:
    """Return the bundled example skills as {name, files:{relpath:text}}."""
    out: list[dict] = []
    if not EXAMPLES_DIR.is_dir():
        return out
    for pkg in sorted(EXAMPLES_DIR.iterdir()):
        if not (pkg / "SKILL.md").is_file():
            continue
        files: dict[str, str] = {}
        for path in sorted(pkg.rglob("*")):
            if path.is_file():
                try:
                    files[str(path.relative_to(pkg))] = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
        out.append({"name": pkg.name, "files": files})
    return out


def _safe_relpath(relpath: str) -> str:
    """Reject absolute paths and traversal so pasted files stay in the temp dir."""
    pure = PurePosixPath(relpath.replace("\\", "/"))
    if pure.is_absolute() or any(part in {"..", ""} for part in pure.parts):
        raise ValueError(f"unsafe file name: {relpath!r}")
    return str(pure)


def _run_sandbox(skill, result, timeout: int) -> None:
    from .sandbox import run_skill

    sandbox = run_skill(skill, timeout=timeout)
    result.merge_dynamic(sandbox.to_findings(), sandbox.to_dict())


def scan_files(files: dict[str, str], min_severity: str = "low",
               sandbox: bool = False, timeout: int = 30) -> dict:
    """Write pasted files to a throwaway directory and scan (optionally run) them."""
    if "SKILL.md" not in files:
        raise ValueError("a file named SKILL.md is required")
    with tempfile.TemporaryDirectory(prefix="skillguard-") as tmp:
        root = Path(tmp)
        for relpath, text in files.items():
            target = root / _safe_relpath(relpath)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        skill = parse_skill(root)
        result = scan(skill, min_severity=min_severity)
        if sandbox:
            _run_sandbox(skill, result, timeout)
        payload = result.to_dict()
        payload["root"] = "(pasted)"
        return payload


def scan_path(path: str, min_severity: str = "low",
              sandbox: bool = False, timeout: int = 30) -> dict:
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"path not found: {target}")
    skill = parse_skill(target)
    result = scan(skill, min_severity=min_severity)
    if sandbox:
        _run_sandbox(skill, result, timeout)
    return result.to_dict()


class Handler(BaseHTTPRequestHandler):
    server_version = f"SkillGuard/{__version__}"

    def log_message(self, fmt: str, *args) -> None:  # quieter than the default
        print(f"  {self.address_string()} {fmt % args}")

    # -- helpers ----------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        data = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(data, dict):
            raise TypeError("expected a JSON object")
        return data

    # -- routes -----------------------------------------------------------
    def do_GET(self) -> None:
        route = self.path.split("?", 1)[0]
        if route in {"/", "/index.html"}:
            html = resources.files("skillguard").joinpath("ui.html").read_text(encoding="utf-8")
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif route == "/api/examples":
            self._json(200, _load_examples())
        elif route == "/api/rules":
            self._json(
                200,
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
            )
        elif route == "/api/version":
            from .sandbox import docker_available

            ok, detail = docker_available()
            self._json(200, {"version": __version__, "docker": ok, "docker_detail": detail})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        route = self.path.split("?", 1)[0]
        if route not in {"/api/scan", "/api/run"}:
            self._json(404, {"error": "not found"})
            return
        use_sandbox = route == "/api/run"
        try:
            data = self._read_json()
            min_severity = str(data.get("min_severity") or "low")
            timeout = max(1, min(int(data.get("timeout") or 30), 300))
            if data.get("path"):
                payload = scan_path(str(data["path"]), min_severity, use_sandbox, timeout)
            else:
                files = data.get("files") or {}
                if not isinstance(files, dict):
                    raise ValueError("files must be an object of {path: text}")
                payload = scan_files({str(k): str(v) for k, v in files.items()},
                                     min_severity, use_sandbox, timeout)
            self._json(200, payload)
        except (ValueError, TypeError, FileNotFoundError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - shown to the developer in the UI
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> int:
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print(f"\n  SkillGuard {__version__} UI at {url}\n  Press Ctrl+C to stop.\n")
    if open_browser:
        import webbrowser

        webbrowser.open(url)  # best-effort; returns False rather than raising when no browser
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
    finally:
        server.server_close()
    return 0
