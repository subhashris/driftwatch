r"""
app.py -- DriftWatch FastAPI backend.

Endpoints:
  POST /api/scan                     -- kick off scan.py -> sweep.py -> ownership.py
  GET  /api/status/{job_id}          -- poll progress for an in-flight scan
  GET  /api/results/{owner}/{repo}   -- merged JSON from the three pipeline stages
  GET  /                             -- serves radar.html

Run:
  $env:Path += ";$env:USERPROFILE\.local\bin"
  uvicorn app:app --reload --port 8080
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import httpx


# ── Paths ────────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

DEMO_DIR = PROJECT_ROOT / "demo_data"

CORAL_BIN_DIR = Path(os.environ["USERPROFILE"]) / ".local" / "bin" if "USERPROFILE" in os.environ else None


def get_config_value(name: str) -> tuple[Optional[str], Optional[str]]:
    value = os.environ.get(name)
    if value:
        return value, "process"

    for env_path in (PROJECT_ROOT / ".env.local", PROJECT_ROOT / ".env"):
        if not env_path.exists():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            if key.strip() != name:
                continue
            value = raw_value.strip().strip('"').strip("'")
            if value:
                return value, env_path.name

    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                value, _ = winreg.QueryValueEx(key, name)
            if value:
                return str(value), "windows-user-env"
        except OSError:
            pass

    return None, None


def subprocess_env() -> dict:
    """Return an env with coral.exe on PATH and project root on PYTHONPATH."""
    env = os.environ.copy()
    path_parts = [env.get("PATH", "")]
    if CORAL_BIN_DIR and CORAL_BIN_DIR.exists():
        path_parts.insert(0, str(CORAL_BIN_DIR))
    env["PATH"] = os.pathsep.join(p for p in path_parts if p)
    # ownership.py does `from sweep import upgrade_actionability`. We run with
    # cwd=OUTPUT_DIR so sweep.py isn't on the default path -- add project root.
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{PROJECT_ROOT}{os.pathsep}{existing_pp}" if existing_pp else str(PROJECT_ROOT)
    )
    return env


# ── Job tracking ─────────────────────────────────────────────────────────────

@dataclass
class Job:
    job_id: str
    owner: str
    repo: str
    status: str = "running"        # running | complete | error
    progress: int = 0              # 0-100
    message: str = "Queued..."
    error: Optional[str] = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def update(self, *, status: Optional[str] = None,
               progress: Optional[int] = None,
               message: Optional[str] = None,
               error: Optional[str] = None) -> None:
        with self.lock:
            if status is not None:
                self.status = status
            if progress is not None:
                self.progress = max(self.progress, progress)
            if message is not None:
                self.message = message
            if error is not None:
                self.error = error

    def snapshot(self) -> dict:
        with self.lock:
            d = {
                "job_id": self.job_id,
                "owner": self.owner,
                "repo": self.repo,
                "status": self.status,
                "progress": self.progress,
                "message": self.message,
            }
            if self.error:
                d["error"] = self.error
            return d


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


# ── Pipeline runner ──────────────────────────────────────────────────────────

PROGRESS_RE = re.compile(r"\[(\d+)/(\d+)\]")


def _stream_subprocess(cmd: list[str], cwd: Path, env: dict,
                       job: Job, stage_start: int, stage_end: int,
                       stage_label: str) -> int:
    """
    Run a subprocess, stream stdout, and translate '[i/N]' progress lines
    into job.progress between stage_start and stage_end.
    Returns the process return code.
    """
    job.update(progress=stage_start, message=stage_label)
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    assert proc.stdout is not None
    last_line = ""
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        last_line = line
        m = PROGRESS_RE.search(line)
        if m:
            i, n = int(m.group(1)), int(m.group(2))
            if n > 0:
                frac = i / n
                pct = int(stage_start + (stage_end - stage_start) * frac)
                job.update(progress=pct, message=f"{stage_label} ({i}/{n})")
        else:
            # Non-progress chatter -- keep showing the stage label, but if the
            # line looks informative (a header), surface it.
            short = line.strip()
            if short and not short.startswith(("=", "-", "─")) and len(short) < 120:
                job.update(message=f"{stage_label}: {short}")
    rc = proc.wait()
    if rc != 0:
        # surface the last line in the error
        raise RuntimeError(
            f"{stage_label} failed (exit {rc}). Last output: {last_line!r}"
        )
    job.update(progress=stage_end)
    return rc


def run_pipeline(job: Job) -> None:
    """Run scan -> sweep -> ownership in OUTPUT_DIR. Updates job state."""
    owner = job.owner
    repo = job.repo
    env = subprocess_env()

    scan_json = OUTPUT_DIR / f"scan_{owner}_{repo}.json"
    sweep_json = OUTPUT_DIR / f"sweep_{owner}_{repo}.json"
    ownership_json = OUTPUT_DIR / f"ownership_{owner}_{repo}.json"

    try:
        # Stage 1: scan.py  (0 → 60)
        _stream_subprocess(
            ["python", str(PROJECT_ROOT / "scan.py"), owner, repo],
            cwd=OUTPUT_DIR, env=env, job=job,
            stage_start=2, stage_end=60,
            stage_label="Charting the waters — SBOM × OSV",
        )
        if not scan_json.exists():
            raise RuntimeError(f"scan.py produced no {scan_json.name}")

        # Stage 2: sweep.py  (60 → 85)
        _stream_subprocess(
            ["python", str(PROJECT_ROOT / "sweep.py"), owner, repo,
             "--scan-json", str(scan_json)],
            cwd=OUTPUT_DIR, env=env, job=job,
            stage_start=60, stage_end=85,
            stage_label="Scanning for storm warnings — deps.dev",
        )

        # Stage 3: ownership.py  (85 → 99)
        _stream_subprocess(
            ["python", str(PROJECT_ROOT / "ownership.py"), owner, repo,
             "--scan-json", str(scan_json)],
            cwd=OUTPUT_DIR, env=env, job=job,
            stage_start=85, stage_end=99,
            stage_label="Building crew manifest — ownership map",
        )

        job.update(status="complete", progress=100, message="Scan complete.")
    except Exception as exc:
        job.update(status="error", message=f"Scan failed: {exc}", error=str(exc))


# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="DriftWatch", version="0.1.0")


class ScanRequest(BaseModel):
    owner: str
    repo: str


@app.get("/")
def index():
    radar = PROJECT_ROOT / "radar.html"
    if not radar.exists():
        return JSONResponse({"error": "radar.html not found"}, status_code=404)
    return FileResponse(str(radar), media_type="text/html")


@app.post("/api/scan")
def start_scan(req: ScanRequest):
    owner = req.owner.strip()
    repo = req.repo.strip()
    if not owner or not repo:
        raise HTTPException(status_code=400, detail="owner and repo are required")

    job_id = uuid.uuid4().hex
    job = Job(job_id=job_id, owner=owner, repo=repo,
              message=f"Starting scan of {owner}/{repo}...")
    with JOBS_LOCK:
        JOBS[job_id] = job

    thread = threading.Thread(target=run_pipeline, args=(job,), daemon=True)
    thread.start()

    return {"job_id": job_id, "status": "started"}


@app.get("/api/status/{job_id}")
def job_status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Unknown job_id: {job_id}")
    return job.snapshot()


def _read_json(path: Path):
    if not path.exists():
        return None
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Malformed JSON in {path.name}: {exc}",
        )


@app.get("/api/results/{owner}/{repo}")
def get_results(owner: str, repo: str, demo: bool = False):
    """
    Merge scan + sweep + ownership JSON. Looks in OUTPUT_DIR; if ?demo=true
    (or files missing and demo_data has them), falls back to DEMO_DIR.
    """
    def resolve(stem: str) -> Path:
        filename = f"{stem}_{owner}_{repo}.json"
        primary = OUTPUT_DIR / filename
        if demo:
            return DEMO_DIR / filename
        if primary.exists():
            return primary
        # graceful demo fallback when nothing scanned yet
        fallback = DEMO_DIR / filename
        return fallback

    scan_path = resolve("scan")
    sweep_path = resolve("sweep")
    ownership_path = resolve("ownership")

    scan_data = _read_json(scan_path)
    sweep_data = _read_json(sweep_path)
    ownership_data = _read_json(ownership_path)

    if scan_data is None and sweep_data is None and ownership_data is None:
        raise HTTPException(
            status_code=404,
            detail=f"No results found for {owner}/{repo}. Run a scan first.",
        )

    return {
        "owner": owner,
        "repo": repo,
        "sources": {
            "scan": str(scan_path) if scan_data is not None else None,
            "sweep": str(sweep_path) if sweep_data is not None else None,
            "ownership": str(ownership_path) if ownership_data is not None else None,
        },
        "scan": scan_data or [],
        "sweep": sweep_data or {},
        "ownership": ownership_data or [],
    }


@app.get("/api/health")
def health():
    _, groq_source = get_config_value("GROQ_API_KEY")
    return {
        "ok": True,
        "python": sys.version.split()[0],
        "project_root": str(PROJECT_ROOT),
        "output_dir": str(OUTPUT_DIR),
        "coral_on_path": bool(CORAL_BIN_DIR and CORAL_BIN_DIR.exists()),
        "groq_configured": bool(groq_source),
        "groq_source": groq_source,
    }

@app.post("/api/chat")
async def chat(req: dict):
    api_key, api_key_source = get_config_value("GROQ_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY was not found in the process env, .env.local, .env, or Windows user environment. Set it and restart uvicorn.",
        )

    try:
        system_prompt = req["system"]
        messages = req["messages"]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing chat field: {exc.args[0]}") from exc

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": get_config_value("GROQ_MODEL")[0] or "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        *messages,
                    ],
                    "max_tokens": 1000,
                },
            )
            r.raise_for_status()
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json()
        except ValueError:
            detail = exc.response.text
        raise HTTPException(status_code=exc.response.status_code, detail=detail) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach Groq: {exc}") from exc

    data = r.json()
    content = data.get("choices", [{}])[0].get("message", {}).get("content")
    return {"content": content, "provider": "groq", "api_key_source": api_key_source, "raw": data}
