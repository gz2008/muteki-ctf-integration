#!/usr/bin/env python3
"""CTF Studio - a local-first graphical entry point for the pinned CTF toolchain.

The server is deliberately standard-library only.  It binds to loopback, injects a
per-process token into the page, and exposes a small JSON API:

  - local mode: deterministic lanes (inventory, strings, corpus, web, coordinator)
  - codex mode: several `codex exec` workers racing in isolated subdirectories
  - muteki mode: dispatch to a running Project Muteki service and mirror its SSE

No challenge data is sent anywhere by the local mode.  The codex and muteki modes
are explicit user choices and use the already-configured local CLI/service.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html.parser
import json
import mimetypes
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable


STUDIO_DIR = Path(os.environ.get("CTF_STUDIO_HOME", Path(__file__).resolve().parent)).resolve()
ROOT = Path(os.environ.get("CTF_STUDIO_ROOT", STUDIO_DIR.parent)).resolve()
WEB_DIR = Path(os.environ.get("CTF_STUDIO_WEB", STUDIO_DIR / "web")).resolve()
DEFAULT_RUNS = Path(os.environ.get("CTF_STUDIO_RUNS", STUDIO_DIR / "runs"))
EXPERIENCE_FILE = Path(os.environ.get("CTF_STUDIO_EXPERIENCE", STUDIO_DIR / "experience.jsonl"))
PYTHON = sys.executable
WSL_EXE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wsl.exe"
DISTRO = os.environ.get("CTF_KALI_DISTRO", "ctf-kali")
KALI_USER = os.environ.get("CTF_KALI_USER", "ctf")
STUDIO_VERSION = "1.0.0"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
DEFAULT_FLAG = "flag{...}"
MAX_UPLOAD = 512 * 1024 * 1024
MAX_EVENTS = 2500
MAX_BODY_JSON = 4 * 1024 * 1024


def now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts or now()))


def run_cmd(
    args: list[str],
    *,
    cwd: Path | str | None = None,
    timeout: float | None = 60,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    merged = os.environ.copy()
    merged.setdefault("PYTHONIOENCODING", "utf-8")
    merged.setdefault("NO_COLOR", "1")
    if env:
        merged.update(env)
    try:
        proc = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=merged,
            creationflags=CREATE_NO_WINDOW,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return 124, out, (err + f"\n[timeout after {timeout}s]").strip()
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except Exception as exc:  # pragma: no cover - defensive boundary
        return 1, "", f"{type(exc).__name__}: {exc}"


def wsl_path(path: Path | str) -> str:
    full = Path(path).resolve()
    drive = full.drive[:1].lower()
    if drive:
        return "/mnt/" + drive + str(full)[2:].replace("\\", "/")
    return str(full).replace("\\", "/")


def safe_name(name: str, fallback: str = "file") -> str:
    name = Path(str(name or "")).name
    name = re.sub(r"[\x00-\x1f<>:\"|?*]+", "_", name).strip(" .")
    return name or fallback


def within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


def http_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: float = 3,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    data = None
    hdrs = {"Accept": "application/json", "User-Agent": f"CTF-Studio/{STUDIO_VERSION}"}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(4 * 1024 * 1024)
            return resp.status, json.loads(raw.decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read(65536)
        try:
            parsed = json.loads(raw.decode("utf-8", "replace") or "{}")
        except Exception:
            parsed = {"detail": raw.decode("utf-8", "replace")[:1000]}
        return exc.code, parsed
    except Exception as exc:
        return 0, {"error": f"{type(exc).__name__}: {exc}"}


def http_upload(
    url: str,
    files: list[Path],
    *,
    timeout: float = 120,
) -> tuple[int, Any]:
    boundary = "----ctfstudio" + uuid.uuid4().hex
    chunks: list[bytes] = []
    for path in files:
        name = path.name.replace('"', "_")
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="files"; filename="{name}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode("utf-8")
        )
        chunks.append(path.read_bytes())
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    data = b"".join(chunks)
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(data)),
            "User-Agent": f"CTF-Studio/{STUDIO_VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(4 * 1024 * 1024)
            return resp.status, json.loads(raw.decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {"detail": exc.read(65536).decode("utf-8", "replace")}
    except Exception as exc:
        return 0, {"error": f"{type(exc).__name__}: {exc}"}


def http_status(url: str, *, timeout: float = 2) -> int:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"CTF-Studio/{STUDIO_VERSION}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Toolchain adapters


def run_triage(path: Path, timeout: float = 90) -> tuple[int, Any]:
    code, out, err = run_cmd(
        [PYTHON, str(ROOT / "scripts" / "ctf-triage.py"), "--json", str(path)],
        timeout=timeout,
    )
    if code != 0:
        return code, {"error": (err or out).strip()[:2000]}
    try:
        return 0, json.loads(out)
    except Exception:
        return 1, {"error": "triage produced non-JSON output", "raw": out[:2000]}


def run_index(query: str, n: int = 6, timeout: float = 90) -> tuple[int, str, str]:
    return run_cmd(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "bin" / "ctf-index.ps1"),
            "query",
            query,
            "-n",
            str(max(1, min(n, 20))),
        ],
        timeout=timeout,
    )


def run_corpus(category: str, pattern: str, timeout: float = 60) -> tuple[int, str, str]:
    return run_cmd(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "bin" / "ctf-corpus.ps1"),
            "-c",
            category,
            pattern,
        ],
        timeout=timeout,
    )


def resolve_codex() -> str:
    env = os.environ.get("CTF_CODEX_CLI")
    if env and Path(env).exists():
        return env
    exe = shutil.which("codex.exe")
    if exe:
        return exe
    local = Path(os.environ.get("LOCALAPPDATA", "")) / "OpenAI" / "Codex" / "bin"
    if local.is_dir():
        found = sorted(local.glob("*/codex.exe"), key=lambda p: p.stat().st_mtime)
        if found:
            return str(found[-1])
    cmd = shutil.which("codex") or shutil.which("codex.cmd")
    return cmd or ""


def parse_index_output(text: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*\d+\.\s+\[([0-9.]+)\]\s+\[([^\]]+)\]\s+(.+?)(?:\s+\(\+\d+\))?\s*$", line)
        if not m:
            continue
        snippet = lines[i + 1].strip() if i + 1 < len(lines) else ""
        items.append(
            {
                "score": float(m.group(1)),
                "source": m.group(2),
                "path": m.group(3).strip(),
                "snippet": snippet[:500],
            }
        )
    return items


def parse_corpus_output(text: str, limit: int = 40) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    pattern = re.compile(r"^\[([^\]]+)\]\s+(.+?):(\d+):(.*)$")
    for line in text.splitlines():
        m = pattern.match(line)
        if not m:
            continue
        items.append(
            {
                "source": m.group(1),
                "path": m.group(2),
                "line": int(m.group(3)),
                "text": m.group(4)[:500],
            }
        )
        if len(items) >= limit:
            break
    return items


# ---------------------------------------------------------------------------
# Flag contracts and category inference


CATEGORY_WORDS: dict[str, tuple[str, ...]] = {
    "web": (
        "http", "https", "url", "sqli", "sql", "xss", "csrf", "ssrf", "jwt", "cookie",
        "upload", "webshell", "php", "flask", "django", "graphql", "lfi", "rfi", "rce",
        "login", "admin", "session", "web",
    ),
    "pwn": (
        "pwn", "elf", "libc", "heap", "stack", "overflow", "canary", "rop", "shellcode",
        "pwntools", "nc ", "netcat", "binary", "malloc", "tcache", "format string",
    ),
    "crypto": (
        "crypto", "rsa", "aes", "des", "cipher", "encrypt", "decrypt", "modulus",
        "prime", "ecc", "elliptic", "hash", "xor", "nonce", "padding", "signature",
    ),
    "rev": (
        "reverse", "rev", "crackme", "keygen", "serial", "apk", "dex", "jar", "pyc",
        "wasm", "ghidra", "ida", "disassembly", "license", "vm",
    ),
    "forensics": (
        "forensic", "pcap", "packet", "memory", "memdump", "disk", "image", "stego",
        "exif", "zip", "rar", "wav", "audio", "usb", "registry", "volatility", "carve",
    ),
    "osint": ("osint", "geolocation", "social", "username", "email", "whois", "dns"),
    "blockchain": ("blockchain", "ethereum", "solidity", "smart contract", "web3", "bitcoin"),
    "mobile": ("android", "ios", "apk", "mobile", "frida", "jadx"),
}

EXT_CATEGORY: dict[str, str] = {
    ".pcap": "forensics", ".pcapng": "forensics", ".raw": "forensics", ".img": "forensics",
    ".vmdk": "forensics", ".mem": "forensics", ".e01": "forensics", ".zip": "forensics",
    ".rar": "forensics", ".7z": "forensics", ".png": "forensics", ".jpg": "forensics",
    ".jpeg": "forensics", ".gif": "forensics", ".wav": "forensics", ".mp3": "forensics",
    ".elf": "pwn", ".so": "pwn", ".exe": "rev", ".dll": "rev", ".apk": "mobile",
    ".pyc": "rev", ".jar": "rev", ".wasm": "rev",
}


def infer_category(text: str, files: Iterable[str], explicit: str = "") -> tuple[str, list[str]]:
    explicit = (explicit or "").strip().lower()
    if explicit and explicit not in {"auto", "unknown"}:
        return explicit, [f"用户指定类别：{explicit}"]
    lowered = (text or "").lower()
    scores: dict[str, int] = {}
    hits: dict[str, list[str]] = {}
    for category, words in CATEGORY_WORDS.items():
        for word in words:
            if word in lowered:
                scores[category] = scores.get(category, 0) + (3 if len(word) > 4 else 1)
                hits.setdefault(category, []).append(word)
    for name in files:
        ext = Path(name).suffix.lower()
        if ext in EXT_CATEGORY:
            cat = EXT_CATEGORY[ext]
            scores[cat] = scores.get(cat, 0) + 2
            hits.setdefault(cat, []).append(ext)
    if not scores:
        return "misc", ["没有明显类别关键词，按 misc 起步"]
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    best = ranked[0][0]
    why = [f"关键词：{', '.join(hits.get(best, [])[:8])}"]
    if len(ranked) > 1:
        why.append(f"次选：{ranked[1][0]}({ranked[1][1]})")
    return best, why


PLACEHOLDER_FLAGS = {"flag{...}", "flag{test}", "flag{example}", "flag{your_flag}", "flag{redacted}"}
GENERIC_FLAG = re.compile(
    r"(?i)\b(?:flag|ctf|key|picoctf|htb|ductf|irisctf|corctf|sekai|uiuctf|n1ctf|hgame|moectf|nssctf)"
    r"\{[^}\r\n]{1,240}\}"
)


def flag_contract(spec: str) -> dict[str, Any]:
    spec = (spec or DEFAULT_FLAG).strip()
    if spec.lower() == "token":
        return {"kind": "token", "spec": spec, "regex": r"[A-Za-z0-9_\-]{16,160}"}
    if "..." in spec:
        prefix, suffix = spec.split("...", 1)
        return {
            "kind": "template",
            "spec": spec,
            "prefix": prefix,
            "suffix": suffix,
            "regex": re.escape(prefix) + r"[^}\s\r\n]{1,240}" + re.escape(suffix),
        }
    if re.fullmatch(r"[A-Za-z0-9_\-]+\{[^}]*\}", spec):
        return {"kind": "template", "spec": spec, "regex": re.escape(spec)}
    return {"kind": "literal", "spec": spec, "regex": re.escape(spec)}


def flag_matches(value: str, spec: str) -> bool:
    contract = flag_contract(spec)
    try:
        return re.search(contract["regex"], value or "") is not None
    except re.error:
        return False


def extract_flags(text: str, spec: str, *, include_generic: bool = True) -> list[str]:
    found: list[str] = []
    contract = flag_contract(spec)
    patterns = [contract["regex"]]
    if include_generic and contract["kind"] != "token":
        patterns.append(GENERIC_FLAG.pattern)
    for pattern in patterns:
        try:
            for match in re.finditer(pattern, text or "", re.IGNORECASE):
                value = match.group(0).strip().strip(".,;:'\"`")
                if not value or value.lower() in PLACEHOLDER_FLAGS:
                    continue
                if "..." in value:
                    continue
                if value not in found:
                    found.append(value)
        except re.error:
            continue
    return found


# ---------------------------------------------------------------------------
# URL probe


class PageParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.forms: list[dict[str, Any]] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.comments: list[str] = []
        self.meta: list[dict[str, str]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._form = {
                "action": data.get("action", ""),
                "method": (data.get("method") or "get").upper(),
                "inputs": [],
            }
            self.forms.append(self._form)
        elif tag in {"input", "textarea", "select", "button"} and self._form is not None:
            self._form["inputs"].append(
                {
                    "tag": tag,
                    "type": data.get("type", ""),
                    "name": data.get("name", ""),
                    "id": data.get("id", ""),
                }
            )
        elif tag == "a" and data.get("href"):
            self.links.append(data["href"])
        elif tag == "script" and data.get("src"):
            self.scripts.append(data["src"])
        elif tag == "meta":
            self.meta.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data

    def handle_comment(self, data: str) -> None:
        if data.strip() and len(self.comments) < 20:
            self.comments.append(data.strip()[:500])


def probe_url(url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return {"ok": False, "error": "only http/https URLs are supported"}
    host = (parsed.hostname or "").lower()
    if host in {"169.254.169.254", "metadata.google.internal"}:
        return {"ok": False, "error": "metadata endpoints are blocked"}
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"CTF-Studio/{STUDIO_VERSION} (authorized CTF probe)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            status = resp.status
            final_url = resp.geturl()
            headers = dict(resp.headers.items())
            raw = resp.read(2 * 1024 * 1024)
            content_type = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        status = exc.code
        final_url = url
        headers = dict(exc.headers.items()) if exc.headers else {}
        raw = exc.read(512 * 1024)
        content_type = headers.get("Content-Type", "")
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "url": url}
    text = raw.decode("utf-8", "replace")
    parser = PageParser()
    if "html" in content_type.lower() or text.lstrip().startswith("<"):
        try:
            parser.feed(text[:1024 * 1024])
        except Exception:
            pass
    interesting_headers = {}
    for key in ("Server", "X-Powered-By", "Content-Type", "Location", "WWW-Authenticate", "Set-Cookie"):
        if key.lower() in {k.lower() for k in headers}:
            actual = next(k for k in headers if k.lower() == key.lower())
            value = headers[actual]
            if key == "Set-Cookie":
                value = "; ".join(
                    part.strip().split("=", 1)[0]
                    for part in value.split(",")
                    if "=" in part
                )
            interesting_headers[key] = value[:1000]
    return {
        "ok": True,
        "url": url,
        "final_url": final_url,
        "status": status,
        "content_type": content_type,
        "bytes": len(raw),
        "headers": interesting_headers,
        "title": parser.title.strip()[:300],
        "forms": parser.forms[:12],
        "links": list(dict.fromkeys(parser.links))[:40],
        "scripts": list(dict.fromkeys(parser.scripts))[:20],
        "comments": parser.comments,
        "meta": parser.meta[:20],
        "preview": text[:1200],
    }


# ---------------------------------------------------------------------------
# Run model


class Run:
    def __init__(self, run_id: str, payload: dict[str, Any], runs_dir: Path) -> None:
        self.id = run_id
        self.runs_dir = runs_dir
        self.dir = runs_dir / run_id
        self.files_dir = self.dir / "files"
        self.workers_dir = self.dir / "workers"
        self.logs_dir = self.dir / "logs"
        for path in (self.files_dir, self.workers_dir, self.logs_dir):
            path.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.save_lock = threading.Lock()
        self.procs: list[subprocess.Popen[Any]] = []
        self.cancelled = False
        self.seq = 0
        self.fact_seq = 0
        self.flag_seq = 0
        contract = flag_contract(str(payload.get("flag_format") or DEFAULT_FLAG))
        self.data: dict[str, Any] = {
            "id": run_id,
            "title": str(payload.get("title") or "").strip(),
            "description": str(payload.get("description") or "").strip(),
            "url": str(payload.get("url") or "").strip(),
            "category": str(payload.get("category") or "auto").strip().lower(),
            "flag_format": str(payload.get("flag_format") or DEFAULT_FLAG).strip(),
            "flag_contract": contract,
            "mode": str(payload.get("mode") or "local").strip().lower(),
            "workers": max(1, min(int(payload.get("workers") or 2), 8)),
            "race_seconds": max(30, min(int(payload.get("race_seconds") or 300), 3600)),
            "total_seconds": max(0, min(int(payload.get("total_seconds") or 0), 14400)),
            "cost_budget_usd": max(0.0, float(payload.get("cost_budget_usd") or 0)),
            "allow_input": bool(payload.get("allow_input")),
            "web_tools": bool(payload.get("web_tools", True)),
            "offline": bool(payload.get("offline", False)),
            "container": bool(payload.get("container")),
            "multi_flag": bool(payload.get("multi_flag")),
            "status": "created",
            "created_at": iso(),
            "started_at": None,
            "finished_at": None,
            "elapsed": 0,
            "solved": False,
            "winner": "",
            "error": "",
            "attachments": [],
            "lanes": {},
            "facts": [],
            "flags": [],
            "actions": [],
            "events": [],
            "usage": {},
            "muteki_run_id": "",
            "brief": "",
        }
        self.save()

    @property
    def run_json(self) -> Path:
        return self.dir / "run.json"

    def snapshot(self, after: int = 0) -> dict[str, Any]:
        with self.lock:
            data = json.loads(json.dumps(self.data, ensure_ascii=False))
            if after:
                data["events"] = [e for e in data["events"] if e["seq"] > after]
            return data

    def save(self) -> None:
        with self.lock:
            payload = json.loads(json.dumps(self.data, ensure_ascii=False))
        with self.save_lock:
            tmp = self.run_json.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, self.run_json)

    def event(
        self,
        lane: str,
        kind: str,
        text: str,
        *,
        level: str = "info",
        payload: dict[str, Any] | None = None,
        persist: bool = True,
    ) -> None:
        if not text:
            return
        with self.lock:
            self.seq += 1
            event = {
                "seq": self.seq,
                "ts": now(),
                "lane": lane,
                "kind": kind,
                "level": level,
                "text": text[:20000],
            }
            if payload:
                event["payload"] = payload
            self.data["events"].append(event)
            if len(self.data["events"]) > MAX_EVENTS:
                del self.data["events"][: len(self.data["events"]) - MAX_EVENTS]
            lane_state = self.data["lanes"].setdefault(
                lane,
                {
                    "id": lane,
                    "name": lane,
                    "role": "",
                    "status": "running",
                    "started": now(),
                    "ended": None,
                    "last": "",
                    "events": 0,
                    "usage": {},
                },
            )
            lane_state["events"] = int(lane_state.get("events") or 0) + 1
            lane_state["last"] = text[:500]
        if persist:
            try:
                with (self.logs_dir / "events.jsonl").open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            except Exception:
                pass

    def lane(self, lane_id: str, name: str, role: str = "", status: str = "queued") -> None:
        with self.lock:
            self.data["lanes"][lane_id] = {
                "id": lane_id,
                "name": name,
                "role": role,
                "status": status,
                "started": now() if status == "running" else None,
                "ended": None,
                "last": "",
                "events": 0,
                "usage": {},
            }

    def lane_status(self, lane_id: str, status: str, *, note: str = "") -> None:
        with self.lock:
            lane_state = self.data["lanes"].setdefault(
                lane_id, {"id": lane_id, "name": lane_id, "role": "", "events": 0, "usage": {}}
            )
            lane_state["status"] = status
            if status == "running" and not lane_state.get("started"):
                lane_state["started"] = now()
            if status in {"done", "failed", "timeout", "cancelled", "skipped"}:
                lane_state["ended"] = now()
            if note:
                lane_state["last"] = note[:500]
        if note:
            self.event(lane_id, "status", note)

    def fact(
        self,
        lane: str,
        kind: str,
        text: str,
        *,
        source: str = "",
        verified: bool = True,
        detail: str = "",
    ) -> None:
        text = (text or "").strip()
        if not text:
            return
        with self.lock:
            for item in self.data["facts"]:
                if item["kind"] == kind and item["text"] == text:
                    return
            self.fact_seq += 1
            fact = {
                "id": self.fact_seq,
                "lane": lane,
                "kind": kind,
                "text": text[:3000],
                "source": source[:500],
                "verified": bool(verified),
                "detail": detail[:3000],
                "ts": now(),
            }
            self.data["facts"].append(fact)
            if len(self.data["facts"]) > 500:
                del self.data["facts"][: len(self.data["facts"]) - 500]
        self.event(lane, "fact", text, payload={"fact_id": fact["id"], "source": source})

    def flag(
        self,
        lane: str,
        value: str,
        *,
        status: str = "candidate",
        source: str = "",
        evidence: str = "",
    ) -> None:
        value = (value or "").strip()
        if not value:
            return
        with self.lock:
            for item in self.data["flags"]:
                if item["value"] == value:
                    if status == "verified" and item["status"] != "verified":
                        item["status"] = "verified"
                        item["source"] = source or item["source"]
                        item["evidence"] = evidence or item["evidence"]
                    return
            self.flag_seq += 1
            entry = {
                "id": self.flag_seq,
                "value": value,
                "lane": lane,
                "status": status,
                "source": source[:500],
                "evidence": evidence[:2000],
                "ts": now(),
            }
            self.data["flags"].append(entry)
        self.event(
            lane,
            "flag",
            f"{value} [{status}]",
            level="success" if status == "verified" else "warn",
            payload={"flag": value, "status": status, "source": source},
        )

    def action(
        self,
        title: str,
        command: str,
        why: str = "",
        lane: str = "coordinator",
        shell: str = "wsl",
    ) -> None:
        command = (command or "").strip()
        if not command:
            return
        with self.lock:
            if any(a["command"] == command for a in self.data["actions"]):
                return
            self.data["actions"].append(
                {
                    "title": title[:200],
                    "command": command,
                    "why": why[:500],
                    "lane": lane,
                    "shell": shell if shell in {"wsl", "windows"} else "wsl",
                }
            )

    def register_proc(self, proc: subprocess.Popen[Any]) -> None:
        with self.lock:
            self.procs.append(proc)

    def cancel(self) -> None:
        self.cancelled = True
        with self.lock:
            self.data["cancelled"] = True
        with self.lock:
            procs = list(self.procs)
        for proc in procs:
            kill_tree(proc)


def kill_tree(proc: subprocess.Popen[Any]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW,
                timeout=15,
            )
        else:
            proc.terminate()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Studio service


class Studio:
    def __init__(self, runs_dir: Path, token: str) -> None:
        self.runs_dir = runs_dir
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.token = token
        self.runs: dict[str, Run] = {}
        self.lock = threading.RLock()
        self.status_cache: tuple[float, dict[str, Any]] | None = None
        self.start_lock = threading.Lock()
        self.muteki_proc: subprocess.Popen[Any] | None = None
        self._load_runs()

    def _load_runs(self) -> None:
        for path in sorted(self.runs_dir.glob("*/run.json"), reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                run = Run.__new__(Run)
                run.id = data["id"]
                run.runs_dir = self.runs_dir
                run.dir = self.runs_dir / run.id
                run.files_dir = run.dir / "files"
                run.workers_dir = run.dir / "workers"
                run.logs_dir = run.dir / "logs"
                run.lock = threading.RLock()
                run.save_lock = threading.Lock()
                run.procs = []
                run.cancelled = bool(data.get("cancelled"))
                run.seq = max((e.get("seq", 0) for e in data.get("events", [])), default=0)
                run.fact_seq = max((f.get("id", 0) for f in data.get("facts", [])), default=0)
                run.flag_seq = max((f.get("id", 0) for f in data.get("flags", [])), default=0)
                run.data = data
                if run.data.get("status") in {"running", "queued"}:
                    run.data["status"] = "interrupted"
                    run.data["error"] = "服务重启，运行已中断；可重新派发。"
                self.runs[run.id] = run
            except Exception:
                continue

    def new_run(self, payload: dict[str, Any]) -> Run:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        run_id = f"{stamp}-{secrets.token_hex(3)}"
        run = Run(run_id, payload, self.runs_dir)
        with self.lock:
            self.runs[run_id] = run
        return run

    def get(self, run_id: str) -> Run | None:
        with self.lock:
            return self.runs.get(run_id)

    def list_runs(self) -> list[dict[str, Any]]:
        with self.lock:
            runs = list(self.runs.values())
        items = []
        for run in runs:
            data = run.data
            items.append(
                {
                    "id": data["id"],
                    "title": data.get("title") or data.get("description", "")[:80] or data["id"],
                    "mode": data.get("mode"),
                    "status": data.get("status"),
                    "created_at": data.get("created_at"),
                    "elapsed": data.get("elapsed"),
                    "category": data.get("category"),
                    "solved": data.get("solved"),
                    "flags": len(data.get("flags", [])),
                    "facts": len(data.get("facts", [])),
                }
            )
        return sorted(items, key=lambda x: x["created_at"] or "", reverse=True)

    def status(self, force: bool = False) -> dict[str, Any]:
        with self.lock:
            if not force and self.status_cache and now() - self.status_cache[0] < 20:
                return self.status_cache[1]
        result = self._collect_status()
        with self.lock:
            self.status_cache = (now(), result)
        return result

    def _collect_status(self) -> dict[str, Any]:
        corpus = {}
        for name in ("knowledges", "pocs", "wordlists", "nuclei-templates"):
            path = ROOT / "muteki-tool-root" / name
            corpus[name] = bool(path.is_dir() and any(path.iterdir()))
        codex = resolve_codex()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            wsl_future = pool.submit(
                run_cmd,
                [str(WSL_EXE), "-d", DISTRO, "-u", KALI_USER, "--", "bash", "-c",
                 "test -x /opt/ctf/venvs/core/bin/python && echo WSL_OK"],
                timeout=12,
            )
            muteki_future = pool.submit(
                http_json, "http://127.0.0.1:8000/api/health", timeout=2
            )
            ui_future = pool.submit(
                http_status, "http://127.0.0.1:3001/ctf", timeout=2
            )
            try:
                wsl_code, wsl_out, _wsl_err = wsl_future.result(timeout=15)
            except Exception:
                wsl_code, wsl_out = 1, ""
            try:
                muteki_health_code, muteki_health = muteki_future.result(timeout=5)
            except Exception:
                muteki_health_code, muteki_health = 0, {"error": "health check failed"}
            try:
                ui_code, _ui = ui_future.result(timeout=5)
            except Exception:
                ui_code = 0
        wsl_ok = wsl_code == 0 and "WSL_OK" in wsl_out
        muteki_online = muteki_health_code == 200 and isinstance(muteki_health, dict)
        return {
            "version": STUDIO_VERSION,
            "root": str(ROOT),
            "runs_dir": str(self.runs_dir),
            "corpus": corpus,
            "corpus_ready": all(corpus.values()),
            "tools": {
                "triage": (ROOT / "bin" / "ctf-triage.cmd").is_file(),
                "index": (ROOT / "bin" / "ctf-index.cmd").is_file(),
                "corpus": (ROOT / "bin" / "ctf-corpus.cmd").is_file(),
                "linux": (ROOT / "bin" / "ctf-linux.cmd").is_file(),
                "net": (ROOT / "bin" / "ctf-net.cmd").is_file(),
                "repair": (ROOT / "bin" / "ctf-repair.cmd").is_file(),
            },
            "wsl": {"ok": wsl_ok, "distro": DISTRO, "user": KALI_USER},
            "python": {"version": sys.version.split()[0], "path": PYTHON},
            "codex": {"ok": bool(codex), "path": codex},
            "muteki": {
                "online": muteki_online,
                "api": "http://127.0.0.1:8000",
                "ui": "http://127.0.0.1:3001/ctf",
                "ui_online": ui_code in {200, 301, 302, 307, 308},
                "health": muteki_health if muteki_online else {},
                "error": "" if muteki_online else muteki_health.get("error", ""),
            },
            "runs": len(self.runs),
            "checked_at": iso(),
        }

    def dispatch(self, run: Run) -> None:
        with run.lock:
            if run.data["status"] not in {"created", "interrupted", "failed"}:
                raise ValueError("run is not dispatchable")
            run.data["status"] = "running"
            run.data["started_at"] = iso()
            run.data["error"] = ""
            run.cancelled = False
        run.save()
        thread = threading.Thread(target=self._dispatch_thread, args=(run,), daemon=True)
        thread.start()

    def _dispatch_thread(self, run: Run) -> None:
        mode = run.data["mode"]
        try:
            if mode == "local":
                self._dispatch_local(run)
            elif mode == "codex":
                self._dispatch_codex(run)
            elif mode == "muteki":
                self._dispatch_muteki(run)
            else:
                raise ValueError(f"unknown mode: {mode}")
        except Exception as exc:
            with run.lock:
                run.data["status"] = "failed"
                run.data["error"] = f"{type(exc).__name__}: {exc}"
                run.data["finished_at"] = iso()
            run.event("coordinator", "error", run.data["error"], level="error")
        finally:
            with run.lock:
                if run.data["status"] == "running":
                    run.data["status"] = "cancelled" if run.cancelled else "done"
                if run.data["started_at"]:
                    try:
                        started = time.mktime(time.strptime(run.data["started_at"], "%Y-%m-%dT%H:%M:%S"))
                        run.data["elapsed"] = round(now() - started, 1)
                    except Exception:
                        pass
                run.data["finished_at"] = run.data.get("finished_at") or iso()
            run.save()
            self._record_experience(run)

    # ---- local deterministic swarm ----------------------------------------

    def _dispatch_local(self, run: Run) -> None:
        run.event("coordinator", "status", "本地快解启动：分诊、字符串、语料、Web 情报并行。")
        run.lane("coordinator", "协调器", "合并事实并给出下一手", "running")
        run.lane("inventory", "附件分诊", "类型/熵/嵌入对象/建议命令")
        run.lane("strings", "字符串扫描", "flag 候选与高价值线索")
        run.lane("knowledge", "离线语料", "BM25 排序检索")
        run.lane("binary", "二进制计划", "保护/架构/策略排序")
        run.lane("web", "Web 情报", "一次授权 GET，记录结构")
        run.lane("brief", "解题简报", "汇总下一手")

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            futures = {
                pool.submit(self._lane_inventory, run): "inventory",
                pool.submit(self._lane_strings, run): "strings",
                pool.submit(self._lane_knowledge, run): "knowledge",
            }
            if self._binary_candidates(run):
                futures[pool.submit(self._lane_binary, run)] = "binary"
            else:
                run.lane_status("binary", "skipped", note="没有 ELF/PE 类附件")
            if run.data.get("url"):
                futures[pool.submit(self._lane_web, run)] = "web"
            else:
                run.lane_status("web", "skipped", note="没有提供 URL")
            for future in concurrent.futures.as_completed(futures):
                lane = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    run.lane_status(lane, "failed", note=f"{type(exc).__name__}: {exc}")

        self._coordinator(run)

    def _attachments(self, run: Run) -> list[Path]:
        return [p for p in run.files_dir.iterdir() if p.is_file()]

    def _binary_candidates(self, run: Run) -> list[Path]:
        candidates = []
        binary_exts = {".elf", ".so", ".exe", ".dll", ".apk", ".pyc", ".wasm", ".bin", ".out", ".ko"}
        for path in self._attachments(run):
            try:
                head = path.read_bytes()[:4]
            except Exception:
                continue
            if path.suffix.lower() in binary_exts or head in (b"\x7fELF", b"MZ") or head[:4] == b"\x00asm":
                candidates.append(path)
        return candidates

    def _lane_inventory(self, run: Run) -> None:
        files = self._attachments(run)
        run.lane_status("inventory", "running")
        if not files:
            run.lane_status("inventory", "skipped", note="没有附件，仅根据题面推断")
            return
        run.event("inventory", "tool", f"ctf-triage --json {run.files_dir}（{len(files)} 个文件）")
        code, data = run_triage(run.files_dir, timeout=120)
        if code != 0 or not isinstance(data, list):
            run.event("inventory", "error", f"triage 失败：{data}", level="error")
            run.lane_status("inventory", "failed")
            return
        for item in data[:60]:
            name = Path(str(item.get("file", ""))).name
            kind = item.get("kind", "unknown")
            size = item.get("size", 0)
            entropy = item.get("entropy", 0)
            run.fact("inventory", "file", f"{name}: {kind}, {size} bytes, entropy {entropy}", source=str(item.get("file", "")))
            for embedded in item.get("embedded", [])[:8]:
                run.fact("inventory", "embedded", f"{name}: {embedded}", source=name)
            for interesting in item.get("interesting", [])[:10]:
                run.fact("inventory", "string", f"{name}: {interesting}", source=name)
                for value in extract_flags(str(interesting), run.data["flag_format"]):
                    run.flag("inventory", value, status="candidate", source=f"{name} / ctf-triage", evidence=str(interesting))
            for suggestion in item.get("suggestions", [])[:6]:
                cmd, shell = self._concretize_suggestion(str(suggestion), name, run)
                if cmd:
                    run.action("分诊建议", cmd, f"来自 {name} 的 {kind}", lane="inventory", shell=shell)
        run.lane_status("inventory", "done", note=f"已分诊 {len(data)} 个文件")

    def _concretize_suggestion(self, suggestion: str, name: str, run: Run) -> tuple[str, str]:
        text = suggestion.strip()
        if not text:
            return "", "wsl"
        text = text.replace("<file>", name)
        if any(token in text for token in ("<category>", "<technique>", "<what the challenge asks for>")):
            return "", "wsl"
        if text.startswith("base64 -d / CyberChef"):
            return "", "wsl"
        if text.startswith("ctf-"):
            return text, "windows"
        if text.startswith(("checksec ", "strings ", "r2 ", "objdump ", "readelf ", "file ")):
            return text, "wsl"
        if text.startswith("rg "):
            return text, "wsl"
        if text.startswith("zsteg") or text.startswith("stegseek"):
            return f"ctf-linux.cmd {run.files_dir} \"{text}\"", "windows"
        if text.startswith("binwalk"):
            return f"ctf-linux.cmd {run.files_dir} \"{text}\"", "windows"
        if text.startswith("7z") or text.startswith("unzip"):
            return f"ctf-linux.cmd {run.files_dir} \"{text}\"", "windows"
        return text, "wsl"

    def _lane_strings(self, run: Run) -> None:
        files = self._attachments(run)
        run.lane_status("strings", "running")
        if not files:
            run.lane_status("strings", "skipped", note="没有附件")
            return
        pattern = re.compile(
            rb"(?i)(?:flag|ctf|key|htb|picoctf|ductf|irisctf|corctf|sekai|uiuctf|n1ctf|hgame|moectf|nssctf)\{[^}\r\n]{1,240}\}"
        )
        hits = 0
        for path in files[:80]:
            try:
                if path.stat().st_size > 64 * 1024 * 1024:
                    run.event("strings", "status", f"跳过 {path.name}（>64MB）")
                    continue
                blob = path.read_bytes()
            except Exception as exc:
                run.event("strings", "error", f"读取 {path.name} 失败：{exc}", level="error")
                continue
            for match in pattern.finditer(blob):
                value = match.group(0).decode("utf-8", "replace")
                if value.lower() in PLACEHOLDER_FLAGS or "..." in value:
                    continue
                run.flag("strings", value, status="candidate", source=f"{path.name} 原始字节", evidence=f"offset 0x{match.start():x}")
                hits += 1
            text = blob.decode("utf-8", "replace")
            for line in text.splitlines():
                if any(word in line.lower() for word in ("password", "secret", "token", "api_key", "http://", "https://")):
                    run.fact("strings", "string", f"{path.name}: {line.strip()[:300]}", source=path.name)
                    if len(run.data["facts"]) > 120:
                        break
        run.lane_status("strings", "done", note=f"{hits} 个 flag 候选")

    def _knowledge_query(self, run: Run) -> str:
        text = (run.data.get("title", "") + " " + run.data.get("description", "")).strip()
        text = re.sub(r"https?://\S+", " ", text)
        text = re.sub(r"\s+", " ", text)
        if len(text) > 220:
            text = text[:220]
        if not text:
            text = {
                "web": "web exploitation sql injection",
                "pwn": "pwn heap tcache",
                "crypto": "RSA Coppersmith attack",
                "rev": "reverse engineering crackme",
                "forensics": "pcap forensics carving",
                "misc": "CTF misc encoding",
            }.get(run.data.get("category", "misc"), "CTF solve")
        return text

    def _lane_knowledge(self, run: Run) -> None:
        run.lane_status("knowledge", "running")
        query = self._knowledge_query(run)
        run.event("knowledge", "tool", f"ctf-index query {query!r} -n 6")
        code, out, err = run_index(query, 6, timeout=120)
        if code != 0:
            run.event("knowledge", "error", f"ctf-index 失败：{(err or out)[:1200]}", level="error")
            run.lane_status("knowledge", "failed")
            return
        items = parse_index_output(out)
        for item in items:
            run.fact(
                "knowledge",
                "corpus",
                f"[{item['source']}] {item['path']}",
                source=f"BM25 {item['score']}",
                detail=item.get("snippet", ""),
            )
            run.action(
                "打开语料命中",
                f"notepad \"{ROOT / 'muteki-tool-root' / item['path']}\"",
                item.get("snippet", ""),
                lane="knowledge",
                shell="windows",
            )
        if not items:
            run.event("knowledge", "status", "BM25 没有返回结果")
        run.lane_status("knowledge", "done", note=f"{len(items)} 条语料命中")

    def _lane_binary(self, run: Run) -> None:
        candidates = self._binary_candidates(run)
        run.lane_status("binary", "running")
        if not candidates:
            run.lane_status("binary", "skipped", note="没有 ELF/PE 类附件")
            return
        for path in candidates[:8]:
            name = path.name
            command = (
                f"file {name}; "
                f"checksec --file {name} 2>&1; "
                f"readelf -h {name} 2>&1 | head -30; "
                f"readelf -l {name} 2>&1 | grep -E 'GNU_STACK|GNU_RELRO|LOAD' | head -12; "
                f"strings -n 6 {name} 2>/dev/null | head -60"
            )
            run.event("binary", "tool", f"$ {command}")
            code, out, err = run_cmd(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(ROOT / "bin" / "ctf-linux.ps1"),
                    str(run.files_dir),
                    command,
                ],
                timeout=180,
            )
            merged = (out or "") + (("\n" + err) if err.strip() else "")
            if code != 0 and not merged.strip():
                run.event("binary", "error", f"{name}: ctf-linux 失败，exit {code}", level="warn")
                continue
            first = next((line.strip() for line in merged.splitlines() if line.strip()), "")
            if first:
                run.fact("binary", "binary", f"{name}: {first}", source=str(path))
            protections = []
            for line in merged.splitlines():
                line = line.strip()
                if re.match(r"(?i)(RELRO|Stack|NX|PIE|Canary|RPATH|RUNPATH|FORTIFY)\s*:", line):
                    protections.append(line)
            for line in protections[:10]:
                run.fact("binary", "protection", f"{name}: {line}", source=str(path))
            prot = merged.lower()
            strategies: list[tuple[int, str, str]] = []
            if "nx disabled" in prot or "nx:         nx disabled" in prot:
                strategies.append((95, "shellcode / ret2shellcode", "NX 关闭，优先检查可执行栈或 RWX 段"))
            if "no canary" in prot and "pie enabled" not in prot:
                strategies.append((90, "ret2win / ret2libc", "无 Canary 且非 PIE，先找 win 或可控返回地址"))
            if "no canary" in prot and "pie enabled" in prot:
                strategies.append((82, "PIE leak + ret2libc", "PIE 开启，先找泄漏再算基址"))
            if "canary" in prot and "no canary" not in prot:
                strategies.append((60, "先泄漏 Canary", "有 Canary，先找格式化字符串/越界读泄漏"))
            if "full relro" in prot:
                strategies.append((45, "绕开 GOT 覆盖", "Full RELRO，改走栈/堆/FSOP 等路线"))
            elif "partial relro" in prot:
                strategies.append((52, "GOT 覆盖可行", "Partial RELRO，GOT 仍可写"))
            strategies.sort(reverse=True)
            if strategies:
                run.fact(
                    "binary",
                    "strategy",
                    f"{name} 策略排序：" + " > ".join(f"{name_} ({score})" for score, name_, _why in strategies[:4]),
                    source="checksec + ELF header",
                    verified=False,
                )
                run.action("首选策略", f"checksec --file {name}", strategies[0][2], lane="binary", shell="wsl")
            for value in extract_flags(merged, run.data["flag_format"]):
                if flag_matches(value, run.data["flag_format"]):
                    run.flag("binary", value, status="verified", source=f"{name} strings/file output", evidence=merged[-1200:])
                    self._mark_solved(run, "binary", value)
            is_elf = "ELF" in merged
            is_pe = "PE32" in merged or "MS-DOS" in merged or "PE32+" in merged
            if is_elf:
                run.action("二进制保护", f"checksec --file {name}", "先确认 NX/PIE/Canary/RELRO，再决定利用路线", lane="binary", shell="wsl")
                run.action("反汇编入口", f"objdump -d -M intel {name} | head -160", "看 main / win / 校验函数的结构", lane="binary", shell="wsl")
                run.action("函数列表", f"r2 -A -q -c \"afl\" {name}", "反汇编前先列出函数，找 main/check/win", lane="binary", shell="wsl")
                run.action("ROP gadgets", f"ropper --file {name} --search \"pop rdi; ret\"", "只有需要 ROP 时再跑；先确认栈/寄存器控制", lane="binary", shell="wsl")
                run.action("字符串线索", f"strings -n 6 {name} | head -120", "快速找 win 函数、提示语、格式串", lane="binary", shell="wsl")
            elif is_pe:
                run.action("PE 保护", f"rabin2 -I {name}", "查看 PE 架构、入口与保护", lane="binary", shell="wsl")
                run.action("PE 字符串", f"strings -n 6 {name} | head -120", "找提示语、URL 与内嵌资源", lane="binary", shell="wsl")
        run.lane_status("binary", "done", note=f"{len(candidates)} 个二进制候选")

    def _lane_web(self, run: Run) -> None:
        url = run.data.get("url", "")
        if not url:
            run.lane_status("web", "skipped", note="没有 URL")
            return
        run.lane_status("web", "running")
        run.event("web", "tool", f"一次授权 GET：{url}")
        result = probe_url(url)
        if not result.get("ok"):
            run.event("web", "error", f"探测失败：{result.get('error')}", level="error")
            run.lane_status("web", "failed")
            return
        run.fact("web", "http", f"HTTP {result['status']} {result.get('content_type','')} ({result['bytes']} bytes)", source=result["final_url"])
        if result.get("title"):
            run.fact("web", "title", f"标题：{result['title']}", source=result["final_url"])
        for key, value in result.get("headers", {}).items():
            run.fact("web", "header", f"{key}: {value}", source=result["final_url"])
        for form in result.get("forms", [])[:8]:
            inputs = ", ".join(
                f"{i.get('tag')}:{i.get('name') or i.get('id') or i.get('type')}"
                for i in form.get("inputs", [])[:12]
            )
            run.fact("web", "form", f"{form['method']} {form['action'] or '(self)'} [{inputs}]", source=result["final_url"])
        for comment in result.get("comments", [])[:8]:
            run.fact("web", "comment", comment, source=result["final_url"])
        for link in result.get("links", [])[:20]:
            run.fact("web", "link", link, source=result["final_url"], verified=False)
        for value in extract_flags(result.get("preview", ""), run.data["flag_format"]):
            run.flag("web", value, status="candidate", source=result["final_url"], evidence="HTTP 响应预览")
        run.action("抓取页面原文", f"ctf-linux.cmd {run.files_dir} \"curl -i -sS {url}\"", "确认状态码、响应头与表单", lane="web", shell="windows")
        run.lane_status("web", "done", note=f"HTTP {result['status']}")

    def _coordinator(self, run: Run) -> None:
        run.lane_status("coordinator", "running", note="合并事实")
        category, reasons = infer_category(
            run.data.get("description", ""),
            [p.name for p in self._attachments(run)],
            run.data.get("category", "auto"),
        )
        with run.lock:
            run.data["category"] = category
        run.fact("coordinator", "category", f"推断类别：{category}", source="; ".join(reasons))
        self._replay_experience(run)

        generic = {
            "web": "sql injection bypass",
            "pwn": "heap tcache exploitation",
            "crypto": "RSA common modulus",
            "rev": "crackme anti-debug",
            "forensics": "pcap tcp reassembly",
            "misc": "CTF encoding steganography",
        }
        query = generic.get(category, "CTF")
        code, out, _err = run_corpus(category if category in CATEGORY_WORDS else "misc", query, timeout=45)
        for item in parse_corpus_output(out, 12):
            run.fact(
                "coordinator",
                "corpus",
                f"[{item['source']}] {item['path']}:{item['line']}",
                source=query,
                detail=item["text"],
            )

        # A small, category-aware opening sequence.  Every command is explicit
        # and can be copied into the console; none is executed automatically.
        attachments = self._attachments(run)
        if attachments:
            first = attachments[0]
            run.action("重新分诊", f"ctf-linux.cmd {run.files_dir} \"ctf-triage {'--recursive' if len(attachments) > 1 else ''} .\"", "在 Kali 中得到一致的分诊结果", lane="coordinator", shell="windows")
            if first.suffix.lower() in {".pcap", ".pcapng"}:
                run.action("重组抓包", f"ctf-linux.cmd {run.files_dir} \"ctf-net {first.name} --out carved\"", "按 TCP 序列号重组并只保留通过格式校验的 carve", lane="coordinator", shell="windows")
            if first.suffix.lower() in {".zip", ".rar", ".7z"}:
                run.action("查看归档", f"ctf-linux.cmd {run.files_dir} \"7z l {first.name}\"", "先列目录，避免直接解压覆盖", lane="coordinator", shell="windows")
            if first.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp"}:
                run.action("图片隐写", f"ctf-linux.cmd {run.files_dir} \"zsteg -a {first.name}\"", "检查 LSB / 附加数据", lane="coordinator", shell="windows")
        if run.data.get("url"):
            run.action("目录探测", f"ctf-linux.cmd {run.files_dir} \"ffuf -u {run.data['url'].rstrip('/')}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc all -fs 0\"", "只在题目授权范围内使用；先看响应差异", lane="coordinator", shell="windows")
        if category == "crypto":
            run.action("检索 RSA 套路", "ctf-index \"RSA small e Coppersmith\" -n 6", "把题面特征映射到已知攻击", lane="coordinator", shell="windows")
        if category == "pwn":
            run.action("检查保护", f"ctf-linux.cmd {run.files_dir} \"checksec --file ./chall\"", "先确认 NX/PIE/Canary/RELRO", lane="coordinator", shell="windows")
        run.action("继续检索", f"ctf-index \"{query}\" -n 8", "本地 BM25，不联网", lane="coordinator", shell="windows")

        run.lane_status("brief", "running")
        brief = self._write_brief(run, category, reasons)
        with run.lock:
            run.data["brief"] = brief
        run.lane_status("brief", "done", note="brief.md 已写入运行目录")
        run.lane_status("coordinator", "done", note=f"类别 {category}，{len(run.data['actions'])} 个下一手")

    def _record_experience(self, run: Run) -> None:
        """Persist reusable technique, never the flag or challenge bytes."""
        try:
            data = run.data
            record = {
                "ts": iso(),
                "run_id": run.id,
                "category": data.get("category") or "misc",
                "title": (data.get("title") or "")[:200],
                "description": (data.get("description") or "")[:600],
                "solved": bool(data.get("solved")),
                "actions": [
                    {
                        "title": a.get("title", ""),
                        "command": a.get("command", ""),
                        "shell": a.get("shell", "wsl"),
                        "why": a.get("why", ""),
                    }
                    for a in (data.get("actions") or [])[:20]
                ],
                "facts": [f.get("text", "") for f in (data.get("facts") or [])[:20]],
            }
            with self.lock:
                with EXPERIENCE_FILE.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _replay_experience(self, run: Run) -> None:
        """Bring back commands from similar past runs as explicitly unverified hints."""
        if not EXPERIENCE_FILE.is_file():
            return
        try:
            lines = EXPERIENCE_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-300:]
        except Exception:
            return
        category = run.data.get("category") or "auto"
        text = (run.data.get("title", "") + " " + run.data.get("description", "")).lower()
        words = {w for w in re.findall(r"[a-z0-9_]{4,}", text)}
        ranked = []
        for line in lines:
            try:
                record = json.loads(line)
            except Exception:
                continue
            score = 0
            if record.get("category") == category:
                score += 3
            record_text = (str(record.get("title", "")) + " " + str(record.get("description", ""))).lower()
            score += min(4, len(words & set(re.findall(r"[a-z0-9_]{4,}", record_text))))
            if record.get("solved"):
                score += 2
            if score >= 4:
                ranked.append((score, record))
        ranked.sort(key=lambda item: item[0], reverse=True)
        selected = ranked[:3]
        if not selected:
            return
        run.fact("coordinator", "experience", f"命中 {len(selected)} 条历史经验（只复用命令，不复制 flag）", source="studio/experience.jsonl", verified=False)
        for score, record in selected:
            run.fact(
                "coordinator",
                "experience",
                f"历史：{record.get('title') or record.get('run_id')}（{record.get('category')}，score {score}）",
                source=record.get("run_id", ""),
                verified=False,
            )
            for action in (record.get("actions") or [])[:3]:
                if action.get("command"):
                    run.action(
                        "历史经验 · " + str(action.get("title", "命令")),
                        str(action["command"]),
                        str(action.get("why", "")) + "（来自历史运行，需复核）",
                        lane="coordinator",
                        shell=action.get("shell", "wsl"),
                    )

    def _write_brief(self, run: Run, category: str, reasons: list[str]) -> str:
        lines = [
            f"# {run.data.get('title') or 'CTF run ' + run.id}",
            "",
            f"- Run: `{run.id}`",
            f"- Mode: `{run.data['mode']}`",
            f"- Category: `{category}`",
            f"- Flag format: `{run.data['flag_format']}`",
            f"- Created: {run.data['created_at']}",
            "",
            "## Challenge",
            "",
            run.data.get("description", "") or "(no description)",
            "",
            "## Facts",
            "",
        ]
        for fact in run.data["facts"][:80]:
            lines.append(f"- [{fact['lane']}] {fact['text']}")
        lines += ["", "## Flags", ""]
        if run.data["flags"]:
            for flag in run.data["flags"]:
                lines.append(f"- `{flag['value']}` ({flag['status']}) — {flag['source']}")
        else:
            lines.append("- none")
        lines += ["", "## Next actions", ""]
        for action in run.data["actions"][:40]:
            lines.append(f"- **{action['title']}** (`{action.get('shell', 'wsl')}`) — {action['why']}")
            lines.append(f"  ```text\n  {action['command']}\n  ```")
        lines += ["", "## Classification evidence", ""]
        lines += [f"- {reason}" for reason in reasons]
        text = "\n".join(lines).rstrip() + "\n"
        (run.dir / "brief.md").write_text(text, encoding="utf-8")
        return text

    # ---- codex workers ----------------------------------------------------

    def _copy_attachments(self, run: Run, dest: Path) -> list[Path]:
        dest.mkdir(parents=True, exist_ok=True)
        copied = []
        for src in self._attachments(run):
            target = dest / src.name
            try:
                if target.exists():
                    target.unlink()
                os.link(src, target)
            except Exception:
                shutil.copy2(src, target)
            copied.append(target)
        return copied

    def _dispatch_codex(self, run: Run) -> None:
        codex = resolve_codex()
        if not codex:
            run.event("coordinator", "error", "找不到 codex CLI；请先登录 Codex 或切换到本地快解。", level="error")
            run.lane_status("coordinator", "failed")
            return
        category, reasons = infer_category(
            run.data.get("description", ""),
            [p.name for p in self._attachments(run)],
            run.data.get("category", "auto"),
        )
        with run.lock:
            run.data["category"] = category
        run.lane("coordinator", "协调器", "共享事实与竞速裁决", "running")
        run.fact("coordinator", "category", f"推断类别：{category}", source="; ".join(reasons))
        run.event("coordinator", "status", f"Codex 蜂群启动：{run.data['workers']} 个 Worker，类别 {category}。")

        # Deterministic support lanes run alongside the model workers.  They give
        # the operator immediate facts even if every model worker is slow.
        support: dict[concurrent.futures.Future[Any], str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            support[pool.submit(self._lane_inventory, run)] = "inventory"
            support[pool.submit(self._lane_strings, run)] = "strings"
            if self._binary_candidates(run):
                support[pool.submit(self._lane_binary, run)] = "binary"
            else:
                run.lane_status("binary", "skipped", note="没有 ELF/PE 类附件")
            if run.data.get("url"):
                support[pool.submit(self._lane_web, run)] = "web"
            else:
                run.lane_status("web", "skipped", note="没有提供 URL")

            workers = []
            roles = [
                ("侦察", "先跑 ctf-triage，按最具体的异常深入；优先验证一个可复现的小假设。"),
                ("知识", "先用 ctf-index / ctf-corpus 找同型题与手法，再把命中的步骤落到当前文件上。"),
                ("执行", "优先把静态线索变成可执行验证：解包、解码、运行 ELF、重放协议；每一步留下证据。"),
                ("反证", "检查其他 Worker 可能忽略的隐藏层：附加数据、异常编码、时间线、容器/归档边界。"),
                ("工具", "用 Kali 工具链做深挖：binwalk、tshark、volatility、ghidra、z3、pwntools；只报告真实输出。"),
                ("横向", "从题面与附件之外找结构：路由、表单、源码泄漏、备份、元数据；不要越出题目目录。"),
                ("收尾", "把已有事实串成最短验证链，优先产出可提交的 flag 与一段可复现证据。"),
                ("复核", "独立重做最可疑的一步，确认 flag 不是 decoy，并检查格式合同。"),
            ]
            for i in range(run.data["workers"]):
                lane_id = f"w{i + 1}"
                role_name, role_hint = roles[i % len(roles)]
                worker_dir = run.workers_dir / lane_id
                files = self._copy_attachments(run, worker_dir / "files")
                playbook_src = ROOT / "skills" / "muteki-ctf-local-playbook"
                if playbook_src.is_dir():
                    shutil.copytree(
                        playbook_src,
                        worker_dir / "skill",
                        dirs_exist_ok=True,
                    )
                prompt = self._worker_prompt(run, lane_id, role_name, role_hint, worker_dir, files)
                (worker_dir / "prompt.md").write_text(prompt, encoding="utf-8")
                run.lane(lane_id, f"Worker {i + 1} · {role_name}", role_hint, "queued")
                thread = threading.Thread(
                    target=self._codex_worker,
                    args=(run, codex, lane_id, worker_dir, prompt),
                    daemon=True,
                )
                thread.start()
                workers.append(thread)
            for thread in workers:
                thread.join(timeout=max(30, run.data["race_seconds"] + 90))
            if any(thread.is_alive() for thread in workers):
                run.event("coordinator", "error", "Worker 未在时限内退出，已终止。", level="warn")
                run.cancel()
            for future, lane in support.items():
                try:
                    future.result(timeout=5)
                except Exception as exc:
                    run.lane_status(lane, "failed", note=f"{type(exc).__name__}: {exc}")
        if run.data.get("solved"):
            run.event("coordinator", "status", f"已锁定 flag，来源 {run.data.get('winner')}。", level="success")
        else:
            run.event("coordinator", "status", "本轮没有确认 flag；保留事实与下一手。")
        self._coordinator(run)

    def _worker_prompt(
        self,
        run: Run,
        lane_id: str,
        role_name: str,
        role_hint: str,
        worker_dir: Path,
        files: list[Path],
    ) -> str:
        tool = ROOT / "bin"
        attachments = "\n".join(f"- {p}" for p in files) or "- (none)"
        return f"""You are {lane_id}, one worker in an authorized, local CTF race.

Role: {role_name}
Strategy: {role_hint}

Challenge title: {run.data.get('title') or '(untitled)'}
Category hint: {run.data.get('category')} (inferred; verify it)
Flag format: {run.data.get('flag_format')}
Target URL: {run.data.get('url') or '(none)'}

Challenge description:
{run.data.get('description') or '(no description)'}

Attachments staged in your workspace:
{attachments}

Rules:
1. Work only inside this worker directory and the files staged in ./files. Do not read
   benchmark manifests, expected-flag files, other workers' directories, or the host's
   CTF-suite benchmark tree. The challenge is the artifact and the description above.
2. Use the pinned tools instead of installing anything:
   - `{tool / 'ctf-triage.cmd'}` — run this first on every artifact.
   - `{tool / 'ctf-index.cmd'}` — BM25 search over offline corpora.
   - `{tool / 'ctf-corpus.cmd'}` — ripgrep over offline corpora.
   - `{tool / 'ctf-net.cmd'}` — pcap/TCP reassembly and validated carving.
   - `{tool / 'ctf-repair.cmd'}` — single-byte repair.
   - `{tool / 'ctf-linux.cmd'}` — run a command in ctf-kali (pwntools, gdb, z3, etc.).
3. Read `./skill/SKILL.md` after mechanical triage, then open only the single best
   matching reference under `./skill/references/`. If this client also supports Agent
   Skills and a specialized CTF skill is installed, use it when useful. Treat all
   skill guidance as a hypothesis and local tool output as the evidence.
4. A flag is real only when it appears in actual tool output or a verified decoded result.
   Never invent, guess, or reconstruct a flag from its format. If a candidate is only a
   string in the artifact, say it is a candidate.
5. When solved, write the exact flag on one line to `flag.txt` in {worker_dir} and append
   the command/output evidence to `notes.md`. Then finish with:
   STATUS: SOLVED
   FLAG: <value>
   EVIDENCE: <one line>
6. If not solved, write `STATUS: UNSOLVED`, the strongest facts in `notes.md`, and the
   next two concrete commands. Do not stop early just because the first idea failed.

Be concise, execute commands, and keep the evidence trail reproducible.
"""

    def _codex_worker(
        self,
        run: Run,
        codex: str,
        lane_id: str,
        worker_dir: Path,
        prompt: str,
    ) -> None:
        run.lane_status(lane_id, "running", note="codex exec 已启动")
        last_file = worker_dir / "last.md"
        args = [
            codex,
            "exec",
            "--skip-git-repo-check",
            "-C",
            str(worker_dir),
            "-s",
            "workspace-write",
            "--color",
            "never",
            "--json",
            "-o",
            str(last_file),
            prompt,
        ]
        log_path = run.logs_dir / f"{lane_id}.log"
        proc: subprocess.Popen[Any] | None = None
        started = now()
        saw_verified = False
        timed_out = {"value": False}
        try:
            with log_path.open("w", encoding="utf-8") as log:
                proc = subprocess.Popen(
                    args,
                    cwd=str(worker_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    creationflags=CREATE_NO_WINDOW,
                )
                run.register_proc(proc)

                def read_stderr() -> None:
                    assert proc is not None and proc.stderr is not None
                    for line in proc.stderr:
                        line = line.rstrip()
                        if not line:
                            continue
                        log.write("[stderr] " + line + "\n")
                        log.flush()
                        if any(x in line for x in ("ERROR", "error:", "failed", "Error")):
                            run.event(lane_id, "error", line[:1200], level="warn")

                err_thread = threading.Thread(target=read_stderr, daemon=True)
                err_thread.start()
                deadline = started + run.data["race_seconds"]
                def watchdog() -> None:
                    while proc is not None and proc.poll() is None and now() < deadline:
                        time.sleep(1)
                    if proc is not None and proc.poll() is None:
                        timed_out["value"] = True
                        run.event(lane_id, "status", f"达到竞速上限 {run.data['race_seconds']}s，停止。", level="warn")
                        kill_tree(proc)

                threading.Thread(target=watchdog, daemon=True).start()
                assert proc.stdout is not None
                for line in proc.stdout:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    log.write(line + "\n")
                    log.flush()
                    if run.cancelled:
                        break
                    if self._consume_codex_line(run, lane_id, line):
                        saw_verified = True
                        if run.data.get("solved"):
                            kill_tree(proc)
                            break
                    if now() > deadline:
                        timed_out["value"] = True
                        run.event(lane_id, "status", f"达到竞速上限 {run.data['race_seconds']}s，停止。", level="warn")
                        kill_tree(proc)
                        break
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    kill_tree(proc)
                    proc.wait(timeout=10)
                err_thread.join(timeout=3)
        except Exception as exc:
            run.event(lane_id, "error", f"Worker 启动失败：{type(exc).__name__}: {exc}", level="error")
            run.lane_status(lane_id, "failed")
            return

        flag_file = worker_dir / "flag.txt"
        if flag_file.is_file():
            try:
                value = flag_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()[0].strip()
            except Exception:
                value = ""
            if value and flag_matches(value, run.data["flag_format"]):
                status = "verified" if self._flag_seen_in_evidence(run, lane_id, value) else "claimed"
                run.flag(lane_id, value, status=status, source=f"{lane_id}/flag.txt", evidence="worker 写入的 flag.txt")
                if status == "verified":
                    self._mark_solved(run, lane_id, value)
        if last_file.is_file():
            try:
                last = last_file.read_text(encoding="utf-8", errors="replace").strip()
                if last:
                    run.event(lane_id, "result", last[-6000:])
                    for value in extract_flags(last, run.data["flag_format"]):
                        if flag_matches(value, run.data["flag_format"]):
                            status = "verified" if self._flag_seen_in_evidence(run, lane_id, value) else "claimed"
                            run.flag(lane_id, value, status=status, source=f"{lane_id}/last.md", evidence="worker 最终消息")
                            if status == "verified":
                                self._mark_solved(run, lane_id, value)
            except Exception:
                pass
        elapsed = round(now() - started, 1)
        with run.lock:
            lane = run.data["lanes"].get(lane_id)
            if lane is not None:
                lane["elapsed"] = elapsed
        if not run.cancelled:
            run.lane_status(lane_id, "timeout" if timed_out["value"] else "done", note=f"{elapsed}s")
        run.save()

    def _consume_codex_line(self, run: Run, lane_id: str, line: str) -> bool:
        try:
            event = json.loads(line)
        except Exception:
            if line.strip():
                run.event(lane_id, "log", line[:2000])
            return False
        typ = event.get("type", "")
        if typ == "item.completed":
            item = event.get("item") or {}
            itype = item.get("type", "")
            if itype == "agent_message":
                text = item.get("text", "")
                run.event(lane_id, "message", text[:12000])
                for value in extract_flags(text, run.data["flag_format"]):
                    if flag_matches(value, run.data["flag_format"]):
                        run.flag(lane_id, value, status="claimed", source=f"{lane_id} 最终消息", evidence=text[:1500])
            elif itype == "command_execution":
                cmd = str(item.get("command") or item.get("cmd") or "")
                output = str(item.get("aggregated_output") or item.get("output") or "")
                code = item.get("exit_code")
                run.event(lane_id, "tool", f"$ {cmd}\n{output[-6000:]}" if output else f"$ {cmd}", payload={"exit_code": code})
                for value in extract_flags(output, run.data["flag_format"]):
                    if flag_matches(value, run.data["flag_format"]):
                        run.flag(lane_id, value, status="verified", source=f"{lane_id} 工具输出", evidence=f"$ {cmd}\n{output[-1200:]}")
                        self._mark_solved(run, lane_id, value)
                        return True
            elif itype in {"file_change", "patch_apply", "mcp_tool_call"}:
                run.event(lane_id, "tool", json.dumps(item, ensure_ascii=False)[:2000])
        elif typ == "turn.completed":
            usage = event.get("usage") or {}
            with run.lock:
                lane = run.data["lanes"].get(lane_id)
                if lane is not None:
                    lane["usage"] = usage
                run.data["usage"][lane_id] = usage
            run.event(lane_id, "usage", f"tokens in={usage.get('input_tokens','?')} out={usage.get('output_tokens','?')}")
        elif typ == "error":
            run.event(lane_id, "error", json.dumps(event, ensure_ascii=False)[:2000], level="error")
        elif typ in {"turn.started", "thread.started"}:
            run.event(lane_id, "status", typ)
        return False

    def _flag_seen_in_evidence(self, run: Run, lane_id: str, value: str) -> bool:
        with run.lock:
            for event in reversed(run.data["events"]):
                if event.get("lane") != lane_id:
                    continue
                if event.get("kind") in {"tool", "result", "message"} and value in event.get("text", ""):
                    return True
        return False

    def _mark_solved(self, run: Run, lane_id: str, value: str) -> None:
        with run.lock:
            if run.data.get("solved"):
                return
            run.data["solved"] = True
            run.data["winner"] = lane_id
        run.event("coordinator", "status", f"首个可验证 flag 来自 {lane_id}，取消其余 Worker。", level="success")
        with run.lock:
            procs = list(run.procs)
        for proc in procs:
            if proc.pid:
                # The winning process may still be in its own pipe; killing all is
                # fine because the flag is already recorded from tool output.
                kill_tree(proc)

    # ---- muteki adapter ---------------------------------------------------

    def _dispatch_muteki(self, run: Run) -> None:
        status = self.status(force=True)
        if not status["muteki"]["online"]:
            raise RuntimeError(
                "Muteki 服务未运行（127.0.0.1:8000 无响应）。"
                "请先在 ctf-kali 中启动 ./run.sh web，或改用 Codex 蜂群。"
            )
        run.lane("coordinator", "Muteki 协调器", "外部多 Agent 服务", "running")
        run.event("coordinator", "status", "连接 Muteki API，创建 run。")
        code, created = http_json("http://127.0.0.1:8000/api/runs", method="POST", body={}, timeout=20)
        if code != 200 or not isinstance(created, dict) or not created.get("run_id"):
            raise RuntimeError(f"Muteki run.create 失败：HTTP {code} {created}")
        muteki_id = str(created["run_id"])
        with run.lock:
            run.data["muteki_run_id"] = muteki_id
        run.event("coordinator", "status", f"Muteki run: {muteki_id}")
        attachments = [p for p in self._attachments(run) if p.is_file()]
        uploaded: list[str] = []
        if attachments:
            up_code, up_data = http_upload(
                f"http://127.0.0.1:8000/api/runs/{urllib.parse.quote(muteki_id)}/uploads",
                attachments,
                timeout=300,
            )
            if up_code != 200:
                raise RuntimeError(f"Muteki uploads 失败：HTTP {up_code} {up_data}")
            for item in (up_data.get("saved") or up_data.get("files") or []):
                if isinstance(item, dict) and item.get("path"):
                    uploaded.append(str(item["path"]))
            run.event("coordinator", "status", f"已上传 {len(uploaded)} 个附件。")
        challenge: dict[str, Any] = {
            "description": run.data["description"],
            "attachments": uploaded,
            "flag_format": run.data["flag_format"],
        }
        if run.data.get("multi_flag"):
            challenge["multi_flag"] = True
        body = {
            "kind": "swarm",
            "prompt": run.data["description"] or run.data["title"],
            "offline": bool(run.data["offline"]),
            "allow_operator_input": bool(run.data["allow_input"]),
            "challenge": challenge,
            "worker_backend": "container" if run.data.get("container") else "local",
            "race_timeout": run.data["race_seconds"],
            "wall_clock_budget": run.data["total_seconds"],
            "max_total_workers": run.data["workers"],
            "cost_budget_usd": run.data["cost_budget_usd"],
        }
        start_code, start_data = http_json(
            f"http://127.0.0.1:8000/api/runs/{urllib.parse.quote(muteki_id)}/start",
            method="POST",
            body=body,
            timeout=60,
        )
        if start_code != 200:
            raise RuntimeError(f"Muteki run.start 失败：HTTP {start_code} {start_data}")
        run.event("coordinator", "status", "Muteki 已接受派发，开始镜像事件流。")
        self._mirror_muteki(run, muteki_id)

    def _mirror_muteki(self, run: Run, muteki_id: str) -> None:
        base = f"http://127.0.0.1:8000/api/runs/{urllib.parse.quote(muteki_id)}/events"
        after = 0
        deadline = now() + max(60, run.data["total_seconds"] or run.data["race_seconds"] + 120)
        seen_workers: set[str] = set()
        while now() < deadline and not run.cancelled:
            url = f"{base}?after={after}"
            req = urllib.request.Request(url, headers={"Accept": "text/event-stream", "User-Agent": f"CTF-Studio/{STUDIO_VERSION}"})
            try:
                with urllib.request.urlopen(req, timeout=35) as resp:
                    event_name = ""
                    data_lines: list[str] = []
                    for raw in resp:
                        if run.cancelled:
                            return
                        line = raw.decode("utf-8", "replace").rstrip("\r\n")
                        if not line:
                            if data_lines:
                                data = "\n".join(data_lines)
                                try:
                                    parsed = json.loads(data)
                                except Exception:
                                    parsed = {"raw": data}
                                seq = parsed.get("seq") if isinstance(parsed, dict) else None
                                if isinstance(seq, int):
                                    after = max(after, seq)
                                self._consume_muteki_event(run, event_name, parsed, seen_workers)
                            event_name = ""
                            data_lines = []
                            continue
                        if line.startswith(":"):
                            continue
                        if line.startswith("event:"):
                            event_name = line.split(":", 1)[1].strip()
                        elif line.startswith("data:"):
                            data_lines.append(line.split(":", 1)[1].lstrip())
                        elif line.startswith("id:") and line.split(":", 1)[1].strip().isdigit():
                            after = max(after, int(line.split(":", 1)[1].strip()))
                        if now() > deadline:
                            break
            except Exception as exc:
                run.event("coordinator", "status", f"事件流断开，重试：{type(exc).__name__}: {exc}", level="warn")
                time.sleep(2)
                continue
            if run.data.get("solved"):
                break
            # A finished run's SSE stays open by design; poll the run list to see
            # whether the lifecycle has closed, then stop mirroring.
            code, listing = http_json("http://127.0.0.1:8000/api/runs", timeout=5)
            if code == 200 and isinstance(listing, dict):
                for item in listing.get("runs", []) if isinstance(listing.get("runs"), list) else []:
                    if str(item.get("run_id")) == muteki_id and item.get("finished"):
                        return
            break
        run.event("coordinator", "status", "停止镜像 Muteki 事件流。")

    def _consume_muteki_event(
        self, run: Run, event_name: str, parsed: Any, seen_workers: set[str]
    ) -> None:
        if not isinstance(parsed, dict):
            return
        payload = parsed.get("payload") if isinstance(parsed.get("payload"), dict) else {}
        event_type = str(parsed.get("event_type") or parsed.get("type") or event_name or "muteki")
        text = ""
        for key in ("text", "message", "summary", "detail", "output"):
            if isinstance(payload.get(key), str) and payload[key].strip():
                text = payload[key].strip()
                break
        if not text:
            text = json.dumps(payload or parsed, ensure_ascii=False)[:1500]
        worker = ""
        for key in ("solver_id", "worker_id", "actor", "target"):
            if isinstance(payload.get(key), str) and payload[key]:
                worker = payload[key]
                break
        lane = worker or "coordinator"
        if worker and worker not in seen_workers:
            seen_workers.add(worker)
            run.lane(worker, f"Muteki · {worker}", "外部 Worker", "running")
        run.event(lane, "muteki", f"[{event_type}] {text}"[:12000], payload={"event_type": event_type})
        for value in extract_flags(text, run.data["flag_format"]):
            if flag_matches(value, run.data["flag_format"]):
                run.flag(lane, value, status="verified" if "flag" in event_type.lower() else "claimed", source=f"Muteki {event_type}", evidence=text[:1200])
                if "flag" in event_type.lower():
                    self._mark_solved(run, lane, value)
        if event_type in {"run.finished", "run.completed", "run.failed"}:
            run.event("coordinator", "status", f"Muteki 事件：{event_type}")

    # ---- muteki launch ----------------------------------------------------

    def start_muteki(self) -> dict[str, Any]:
        with self.start_lock:
            if self.muteki_proc is not None and self.muteki_proc.poll() is None:
                return {"started": True, "already": True, "pid": self.muteki_proc.pid}
            status = self.status(force=True)
            if status["muteki"]["online"]:
                return {"started": True, "already": True, "online": True}
            muteki_root = Path(os.environ.get("MUTEKI_ROOT", str(ROOT.parent / "muteki")))
            if not (muteki_root / "run.sh").is_file():
                return {
                    "started": False,
                    "error": f"找不到 Muteki 源码：{muteki_root}。设置 MUTEKI_ROOT 指向包含 run.sh 的目录。",
                }
            log_path = STUDIO_DIR / "muteki-start.log"
            script = (
                f"cd {wsl_path(muteki_root)} || exit 2; "
                f"MUTEKI_LOCAL_WORKER_ROOT={wsl_path(ROOT / 'muteki-tool-root')} "
                f"MUTEKI_CTF_BRIDGE_ROOT={wsl_path(ROOT)} "
                f"./run.sh web"
            )
            log = log_path.open("a", encoding="utf-8")
            log.write(f"\n=== {iso()} ===\n")
            log.flush()
            self.muteki_proc = subprocess.Popen(
                [str(WSL_EXE), "-d", DISTRO, "-u", KALI_USER, "--", "bash", "-lc", script],
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=CREATE_NO_WINDOW,
            )
            return {
                "started": True,
                "pid": self.muteki_proc.pid,
                "log": str(log_path),
                "note": "首次启动会安装 uv/依赖并构建前端，可能需要几分钟。轮询状态即可。",
            }


# ---------------------------------------------------------------------------
# HTTP server


class Handler(BaseHTTPRequestHandler):
    server_version = f"CTFStudio/{STUDIO_VERSION}"
    studio: Studio

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep the console readable; requests are also visible in the UI.
        if os.environ.get("CTF_STUDIO_VERBOSE"):
            super().log_message(fmt, *args)

    def _send(self, code: int, body: bytes, content_type: str = "application/json; charset=utf-8", headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code: int, payload: Any) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def _error(self, code: int, message: str) -> None:
        self._json(code, {"error": message})

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        return host in {"127.0.0.1", "localhost", "::1"}

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urllib.parse.urlparse(origin)
        host = (parsed.hostname or "").lower()
        return host in {"127.0.0.1", "localhost", "::1"}

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-Studio-Token") or ""
        if not supplied:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            supplied = (query.get("token") or [""])[0]
        return bool(supplied) and secrets.compare_digest(supplied, self.studio.token)

    def _require(self) -> bool:
        if not self._host_ok():
            self._error(403, "loopback host required")
            return False
        if not self._origin_ok():
            self._error(403, "origin not allowed")
            return False
        if not self._authorized():
            self._error(401, "missing or invalid studio token")
            return False
        return True

    def _body(self, limit: int = MAX_BODY_JSON) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        if length > limit:
            raise ValueError(f"body too large ({length} > {limit})")
        return self.rfile.read(length)

    def _route(self) -> tuple[str, list[str]]:
        path = urllib.parse.urlparse(self.path).path
        return path, [part for part in path.split("/") if part]

    def do_GET(self) -> None:
        try:
            path, parts = self._route()
            if path in {"/", "/index.html"}:
                self._serve_index()
                return
            if path.startswith("/static/"):
                self._serve_static(parts[-1] if parts else "")
                return
            if not self._require():
                return
            if path == "/api/status":
                self._json(200, self.studio.status(force=self._query_flag("force")))
                return
            if path == "/api/runs":
                self._json(200, {"runs": self.studio.list_runs()})
                return
            if len(parts) >= 3 and parts[0] == "api" and parts[1] == "runs":
                run = self.studio.get(parts[2])
                if not run:
                    self._error(404, "unknown run")
                    return
                if len(parts) == 3:
                    after = int(self._query_value("after") or 0)
                    self._json(200, run.snapshot(after=after))
                    return
                if len(parts) == 4 and parts[3] == "file":
                    rel = self._query_value("path") or ""
                    target = (run.dir / rel).resolve()
                    if not within(target, run.dir) or not target.is_file():
                        self._error(404, "file not found")
                        return
                    ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
                    self._send(200, target.read_bytes(), ctype)
                    return
            self._error(404, "not found")
        except Exception as exc:
            self._error(500, f"{type(exc).__name__}: {exc}")

    def do_POST(self) -> None:
        try:
            if not self._require():
                return
            path, parts = self._route()
            if path == "/api/client-info":
                payload = json.loads((self._body() or b"{}").decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("body must be a JSON object")
                keep = (
                    "innerWidth",
                    "innerHeight",
                    "outerWidth",
                    "outerHeight",
                    "devicePixelRatio",
                    "screen",
                    "avail",
                    "visualScale",
                    "userAgent",
                )
                info = {key: payload.get(key) for key in keep}
                info["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
                target = self.studio.runs_dir.parent / "client-info.json"
                target.write_text(
                    json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                self._json(200, {"ok": True})
                return
            if path == "/api/runs":
                payload = json.loads((self._body() or b"{}").decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("body must be a JSON object")
                run = self.studio.new_run(payload)
                self._json(200, {"run": run.snapshot()})
                return
            if path == "/api/search":
                payload = json.loads((self._body() or b"{}").decode("utf-8"))
                query = str(payload.get("query") or "").strip()
                if not query:
                    self._error(400, "query required")
                    return
                mode = str(payload.get("mode") or "index")
                n = max(1, min(int(payload.get("n") or 8), 30))
                if mode == "corpus":
                    category = str(payload.get("category") or "web")
                    code, out, err = run_corpus(category, query, timeout=90)
                    items = parse_corpus_output(out, n * 4)
                else:
                    code, out, err = run_index(query, n, timeout=120)
                    items = parse_index_output(out)
                self._json(200, {"ok": code == 0, "mode": mode, "raw": (out or err)[:20000], "items": items})
                return
            if path == "/api/muteki/start":
                self._json(200, self.studio.start_muteki())
                return
            if len(parts) >= 4 and parts[0] == "api" and parts[1] == "runs":
                run = self.studio.get(parts[2])
                if not run:
                    self._error(404, "unknown run")
                    return
                action = parts[3]
                if action == "dispatch":
                    payload = json.loads((self._body() or b"{}").decode("utf-8") or "{}")
                    if isinstance(payload, dict):
                        with run.lock:
                            for key in ("mode", "workers", "race_seconds", "total_seconds", "flag_format", "category", "allow_input", "web_tools", "offline", "container", "multi_flag"):
                                if key in payload and payload[key] is not None:
                                    run.data[key] = payload[key]
                            if "multi_flag" in payload:
                                run.data["multi_flag"] = bool(payload["multi_flag"])
                    self.studio.dispatch(run)
                    self._json(200, {"run": run.snapshot()})
                    return
                if action == "command":
                    payload = json.loads((self._body() or b"{}").decode("utf-8") or "{}")
                    command = str(payload.get("command") or "").strip()
                    shell = str(payload.get("shell") or "wsl").strip().lower()
                    if not command:
                        self._error(400, "command required")
                        return
                    if len(command) > 8000:
                        self._error(413, "command too long")
                        return
                    self._run_console(run, command, shell)
                    self._json(200, {"ok": True})
                    return
                if action == "cancel":
                    run.cancel()
                    run.lane_status("coordinator", "cancelled", note="用户停止")
                    self._json(200, {"ok": True})
                    return
                if action == "flag":
                    payload = json.loads((self._body() or b"{}").decode("utf-8") or "{}")
                    value = str(payload.get("value") or "").strip()
                    review = str(payload.get("review") or "confirm").strip().lower()
                    if review not in {"confirm", "reject"}:
                        self._error(422, "review must be confirm or reject")
                        return
                    if not flag_matches(value, run.data["flag_format"]):
                        self._error(422, "flag does not match the run contract")
                        return
                    with run.lock:
                        found = None
                        for item in run.data["flags"]:
                            if item["value"] == value:
                                found = item
                                break
                        if found is None:
                            found = {
                                "id": len(run.data["flags"]) + 1,
                                "value": value,
                                "lane": "operator",
                                "status": "candidate",
                                "source": "operator",
                                "evidence": "",
                                "ts": now(),
                            }
                            run.data["flags"].append(found)
                        found["status"] = "verified" if review == "confirm" else "rejected"
                        found["source"] = "operator confirmation" if review == "confirm" else "operator rejection"
                        found["evidence"] = "人工审核"
                    run.event(
                        "operator",
                        "flag",
                        f"{value} [{'verified' if review == 'confirm' else 'rejected'}]",
                        level="success" if review == "confirm" else "warn",
                        payload={"flag": value, "status": review},
                    )
                    if review == "confirm":
                        self.studio._mark_solved(run, "operator", value)
                    run.save()
                    self._json(200, {"ok": True})
                    return
            self._error(404, "not found")
        except ValueError as exc:
            self._error(400, str(exc))
        except Exception as exc:
            self._error(500, f"{type(exc).__name__}: {exc}")

    def do_PUT(self) -> None:
        try:
            if not self._require():
                return
            path, parts = self._route()
            if len(parts) >= 4 and parts[0] == "api" and parts[1] == "runs" and parts[3] == "files":
                run = self.studio.get(parts[2])
                if not run:
                    self._error(404, "unknown run")
                    return
                name = safe_name(self._query_value("name") or "file")
                target = run.files_dir / name
                if target.exists():
                    stem, suffix = target.stem, target.suffix
                    i = 1
                    while (run.files_dir / f"{stem}-{i}{suffix}").exists():
                        i += 1
                    target = run.files_dir / f"{stem}-{i}{suffix}"
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_UPLOAD:
                    self._error(413, "file too large")
                    return
                remaining = length
                with target.open("wb") as fh:
                    while remaining > 0:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        fh.write(chunk)
                        remaining -= len(chunk)
                with run.lock:
                    run.data["attachments"].append({"name": target.name, "size": target.stat().st_size})
                run.event("inventory", "status", f"收到附件 {target.name}（{target.stat().st_size} bytes）")
                run.save()
                self._json(200, {"name": target.name, "size": target.stat().st_size})
                return
            self._error(404, "not found")
        except Exception as exc:
            self._error(500, f"{type(exc).__name__}: {exc}")

    def do_DELETE(self) -> None:
        self._error(405, "not supported")

    def _query_value(self, key: str) -> str:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return (query.get(key) or [""])[0]

    def _query_flag(self, key: str) -> bool:
        return self._query_value(key).lower() in {"1", "true", "yes"}

    def _serve_index(self) -> None:
        index = WEB_DIR / "index.html"
        if not index.is_file():
            self._error(500, "studio UI is missing")
            return
        text = index.read_text(encoding="utf-8")
        text = text.replace("__TOKEN_VALUE__", self.studio.token)
        text = text.replace("__VERSION_VALUE__", STUDIO_VERSION)
        self._send(200, text.encode("utf-8"), "text/html; charset=utf-8")

    def _serve_static(self, name: str) -> None:
        target = (WEB_DIR / safe_name(name)).resolve()
        if not within(target, WEB_DIR) or not target.is_file():
            self._error(404, "not found")
            return
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send(200, target.read_bytes(), f"{ctype}; charset=utf-8" if ctype.startswith("text/") or ctype.endswith("javascript") else ctype)

    def _run_console(self, run: Run, command: str, shell: str = "wsl") -> None:
        shell = shell if shell in {"wsl", "windows"} else "wsl"
        run.lane("console", "控制台", "Kali / Windows 命令", "running")
        run.event("console", "tool", f"$ {command}", payload={"command": command, "shell": shell})

        def worker() -> None:
            if shell == "windows":
                code, out, err = run_cmd(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        command,
                    ],
                    cwd=run.files_dir,
                    timeout=1800,
                )
            else:
                code, out, err = run_cmd(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(ROOT / "bin" / "ctf-linux.ps1"),
                        str(run.files_dir),
                        command,
                    ],
                    timeout=1800,
                )
            merged = (out or "") + (("\n[stderr]\n" + err) if err.strip() else "")
            run.event("console", "output", merged[-50000:] or "(no output)", payload={"exit_code": code, "shell": shell})
            for value in extract_flags(merged, run.data["flag_format"]):
                if flag_matches(value, run.data["flag_format"]):
                    run.flag("console", value, status="verified", source=f"{shell} 控制台", evidence=f"$ {command}\n{merged[-1200:]}")
                    self.studio._mark_solved(run, "console", value)
            run.lane_status("console", "done" if code == 0 else "failed", note=f"exit {code}")
            run.save()

        threading.Thread(target=worker, daemon=True).start()


def build_server(host: str, port: int, runs_dir: Path, token: str) -> ThreadingHTTPServer:
    studio = Studio(runs_dir, token)
    handler = type("BoundHandler", (Handler,), {"studio": studio})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd


def main() -> int:
    parser = argparse.ArgumentParser(description="CTF Studio local GUI")
    parser.add_argument("--host", default=os.environ.get("CTF_STUDIO_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CTF_STUDIO_PORT", "8765")))
    parser.add_argument("--runs", default=os.environ.get("CTF_STUDIO_RUNS", str(DEFAULT_RUNS)))
    parser.add_argument("--token", default=os.environ.get("CTF_STUDIO_TOKEN", ""))
    parser.add_argument("--open", action="store_true", help="open the browser after start")
    parser.add_argument("--no-open", action="store_true", help="suppress browser launch")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"} and os.environ.get("CTF_STUDIO_ALLOW_REMOTE") != "1":
        print("refusing non-loopback host; set CTF_STUDIO_ALLOW_REMOTE=1 to override", file=sys.stderr)
        return 2
    token = args.token or secrets.token_urlsafe(24)
    httpd = build_server(args.host, args.port, Path(args.runs), token)
    url = f"http://{'127.0.0.1' if args.host in {'127.0.0.1', 'localhost', '::1'} else args.host}:{args.port}/"
    print(f"CTF Studio {STUDIO_VERSION}")
    print(f"  root:  {ROOT}")
    print(f"  url:   {url}")
    print(f"  token: {token}")
    print("  stop:  Ctrl+C")
    if args.open and not args.no_open and os.environ.get("CTF_STUDIO_NO_OPEN") != "1":
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
