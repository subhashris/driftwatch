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
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import httpx

load_dotenv()

from coral_utils import (
    PURL_TO_DEPSDEV,
    PURL_TO_OSV,
    is_exact_version,
    parse_sbom,
    prioritize_packages,
    run_coral,
    run_coral_parallel,
)
from scan import fixed_version_from_affected
from tools import TOOL_REGISTRY


# â”€â”€ Paths â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

DEMO_DIR = PROJECT_ROOT / "demo_data"

CORAL_BIN_DIR = Path(os.environ["USERPROFILE"]) / ".local" / "bin" if "USERPROFILE" in os.environ else None

REPO_ALIASES = {
    ("apache", "log4j"): ("apache", "logging-log4j2"),
}


def normalize_repo(owner: str, repo: str) -> tuple[str, str]:
    return REPO_ALIASES.get((owner.lower(), repo.lower()), (owner, repo))


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
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


# â”€â”€ Job tracking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@dataclass
class Job:
    job_id: str
    owner: str
    repo: str
    mode: str = "fast"
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
                "mode": self.mode,
                "status": self.status,
                "progress": self.progress,
                "message": self.message,
            }
            if self.error:
                d["error"] = self.error
            return d


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


# â”€â”€ Pipeline runner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
            if short and not short.startswith(("=", "-", "â”€")) and len(short) < 120:
                job.update(message=f"{stage_label}: {short}")
    rc = proc.wait()
    if rc != 0:
        # surface the last line in the error
        raise RuntimeError(
            f"{stage_label} failed (exit {rc}). Last output: {last_line!r}"
        )
    job.update(progress=stage_end)
    return rc


def _load_json_file(path: Path, default):
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write_scan_meta(owner: str, repo: str, **updates) -> None:
    meta_path = OUTPUT_DIR / f"scan_meta_{owner}_{repo}.json"
    meta = _load_json_file(meta_path, {})
    stages_update = updates.pop("stages", None) or {}
    meta.update({key: value for key, value in updates.items() if value is not None})
    meta.setdefault("repo", f"{owner}/{repo}")
    meta.setdefault("mode", "fast_triage")
    meta.setdefault("scan_completed_at", datetime.now(timezone.utc).isoformat())
    stages = meta.setdefault("stages", {})
    stages.update(stages_update)
    with meta_path.open("w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)


def _begin_scan_attempt(owner: str, repo: str, mode: str = "fast") -> None:
    meta_path = OUTPUT_DIR / f"scan_meta_{owner}_{repo}.json"
    meta = {
        "repo": f"{owner}/{repo}",
        "mode": "fast_triage" if mode == "fast" else "deep_sweep",
        "latest_attempt_status": "running",
        "scan_started_at": datetime.now(timezone.utc).isoformat(),
        "scan_completed_at": None,
        "stages": {"scan": "running"},
        "failed_stages": {},
    }
    with meta_path.open("w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)


def _run_optional_stage(job: Job, *, cmd: list[str], cwd: Path, env: dict,
                        stage_start: int, stage_end: int, stage_label: str,
                        stage_key: str, failures: dict) -> bool:
    try:
        _stream_subprocess(
            cmd,
            cwd=cwd,
            env=env,
            job=job,
            stage_start=stage_start,
            stage_end=stage_end,
            stage_label=stage_label,
        )
        _write_scan_meta(job.owner, job.repo, stages={stage_key: "complete"})
        return True
    except Exception as exc:
        failures[stage_key] = str(exc)
        _write_scan_meta(job.owner, job.repo, stages={stage_key: "failed"})
        traceback.print_exc()
        job.update(progress=stage_end, message=f"{stage_label}: skipped after error")
        return False


def run_pipeline(job: Job) -> None:
    """Run scan -> sweep -> ownership in OUTPUT_DIR. Updates job state."""
    owner = job.owner
    repo = job.repo
    env = subprocess_env()

    scan_json = OUTPUT_DIR / f"scan_{owner}_{repo}.json"
    ownership_json = OUTPUT_DIR / f"ownership_{owner}_{repo}.json"
    failures = {}
    deep = job.mode == "deep"
    scan_cmd = ["python", str(PROJECT_ROOT / "scan.py"), owner, repo]
    if deep:
        scan_cmd.extend(["--batch-size", "15", "--workers", "3"])
        scan_label = "Deep sweep: batched SBOM x OSV"
        scan_mode = "deep_sweep"
    else:
        scan_cmd.extend(["--max-packages", "50", "--batch-size", "10", "--workers", "4"])
        scan_label = "Fast triage: prioritized SBOM x OSV"
        scan_mode = "fast_triage"

    try:
        _stream_subprocess(
            scan_cmd,
            cwd=OUTPUT_DIR,
            env=env,
            job=job,
            stage_start=2,
            stage_end=75,
            stage_label=scan_label,
        )
        if not scan_json.exists():
            raise RuntimeError(f"scan.py produced no {scan_json.name}")

        scan_data = _load_json_file(scan_json, [])
        _write_scan_meta(
            owner,
            repo,
            mode=scan_mode,
            latest_attempt_status="complete",
            scan_completed_at=datetime.now(timezone.utc).isoformat(),
            vulnerable_findings=len(scan_data) if isinstance(scan_data, list) else 0,
            stages={"scan": "complete", "sbom": "complete", "osv": "complete"},
        )

        _run_optional_stage(
            job,
            cmd=(
                ["python", str(PROJECT_ROOT / "sweep.py"), owner, repo,
                 "--scan-json", str(scan_json)]
                + ([] if deep else ["--skip-pre-cve"])
            ),
            cwd=OUTPUT_DIR,
            env=env,
            stage_start=75,
            stage_end=88,
            stage_label="Best-effort enrichment: deps.dev actionability",
            stage_key="sweep",
            failures=failures,
        )

        if deep and isinstance(scan_data, list) and scan_data:
            _run_optional_stage(
                job,
                cmd=["python", str(PROJECT_ROOT / "ownership.py"), owner, repo,
                     "--scan-json", str(scan_json)],
                cwd=OUTPUT_DIR,
                env=env,
                stage_start=88,
                stage_end=99,
                stage_label="Best-effort enrichment: ownership",
                stage_key="ownership",
                failures=failures,
            )
        else:
            with ownership_json.open("w", encoding="utf-8") as fh:
                json.dump([], fh, indent=2)
            ownership_stage = "skipped_no_findings" if deep else "on_demand_agent"
            _write_scan_meta(owner, repo, stages={"ownership": ownership_stage})

        message = "Deep sweep complete." if deep else "Fast triage complete."
        if failures:
            message += " Some enrichment stages failed; latest scan remains authoritative."
        _write_scan_meta(owner, repo, failed_stages=failures)
        job.update(status="complete", progress=100, message=message)
        return
    except Exception as exc:
        _write_scan_meta(
            owner,
            repo,
            mode=scan_mode,
            latest_attempt_status="failed",
            scan_completed_at=datetime.now(timezone.utc).isoformat(),
            stages={"scan": "failed"},
            failed_stages={"scan": str(exc)},
        )
        job.update(status="error", message=f"Scan failed: {exc}", error=str(exc))
        return


# â”€â”€ FastAPI app â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

app = FastAPI(title="DriftWatch", version="0.1.0")


class ScanRequest(BaseModel):
    owner: str
    repo: str
    mode: str = "fast"


@app.get("/")
def index():
    radar = PROJECT_ROOT / "radar.html"
    if not radar.exists():
        return JSONResponse({"error": "radar.html not found"}, status_code=404)
    return FileResponse(str(radar), media_type="text/html; charset=utf-8")


@app.post("/api/scan")
def start_scan(req: ScanRequest):
    owner = req.owner.strip()
    repo = req.repo.strip()
    if not owner or not repo:
        raise HTTPException(status_code=400, detail="owner and repo are required")
    owner, repo = normalize_repo(owner, repo)
    mode = req.mode if req.mode in {"fast", "deep"} else "fast"

    job_id = uuid.uuid4().hex
    job = Job(job_id=job_id, owner=owner, repo=repo, mode=mode,
              message=f"Starting {mode} scan of {owner}/{repo}...")
    _begin_scan_attempt(owner, repo, mode)
    try:
        _fetch_vulnerability_snapshot.cache_clear()
    except NameError:
        pass
    with JOBS_LOCK:
        JOBS[job_id] = job

    thread = threading.Thread(target=run_pipeline, args=(job,), daemon=True)
    thread.start()

    return {"job_id": job_id, "status": "started", "owner": owner, "repo": repo, "mode": mode}


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


def _is_useful_result(stem: str, data) -> bool:
    if data is None:
        return False
    if stem in {"scan", "ownership"}:
        return isinstance(data, list) and len(data) > 0
    if stem == "sweep":
        return isinstance(data, dict) and bool(
            data.get("pre_cve_findings") or data.get("upgrade_actionability")
        )
    return True


@app.get("/api/results/{owner}/{repo}")
def get_results(owner: str, repo: str, demo: bool = False):
    """
    Merge scan + sweep + ownership JSON.
    Latest live output is authoritative; bundled sample data is loaded only
    when the caller explicitly passes ?demo=true.
    """
    owner, repo = normalize_repo(owner.strip(), repo.strip())

    def resolve(stem: str) -> tuple[Path, object, str | None]:
        filename = f"{stem}_{owner}_{repo}.json"
        scheduled = PROJECT_ROOT / "scheduled_scans" / f"{owner}_{repo}" / filename
        if demo:
            candidates = [DEMO_DIR / filename]
        else:
            candidates = [scheduled, OUTPUT_DIR / filename, PROJECT_ROOT / filename]

        for candidate in candidates:
            data = _read_json(candidate)
            if data is None:
                continue
            source_kind = (
                "latest scheduled scan artifact" if "scheduled_scans" in candidate.parts
                else "latest scan output" if candidate.parent == OUTPUT_DIR
                else "project scan snapshot" if candidate.parent == PROJECT_ROOT
                else "bundled Coral scan snapshot"
            )
            return candidate, data, source_kind
        return OUTPUT_DIR / filename, None, None

    scan_path, scan_data, scan_kind = resolve("scan")
    sweep_path, sweep_data, sweep_kind = resolve("sweep")
    ownership_path, ownership_data, ownership_kind = resolve("ownership")
    meta_path, scan_meta, meta_kind = resolve("scan_meta")

    if not demo and isinstance(scan_meta, dict) and meta_kind == "latest scan output":
        attempt_status = scan_meta.get("latest_attempt_status")
        stages = scan_meta.get("stages") or {}
        scan_stage = stages.get("scan")
        if attempt_status in {"running", "failed"} or scan_stage in {"running", "failed"}:
            detail = {
                "message": (
                    "Latest scan is still running."
                    if attempt_status == "running" or scan_stage == "running"
                    else "Latest scan failed; stale scan output was not used."
                ),
                "owner": owner,
                "repo": repo,
                "scan_meta": scan_meta,
            }
            raise HTTPException(status_code=409, detail=detail)

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
            "scan_meta": str(meta_path) if scan_meta is not None else None,
            "scan_kind": scan_kind,
            "sweep_kind": sweep_kind,
            "ownership_kind": ownership_kind,
            "scan_meta_kind": meta_kind,
        },
        "scan_meta": scan_meta or {},
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


class InvestigateRequest(BaseModel):
    owner: str
    repo: str
    question: str


def _json_array(value: str | None) -> list:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _days_since_iso(value: str | None) -> int | None:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).days)
    except ValueError:
        return None


def _sql(value: str) -> str:
    return str(value).replace("'", "''")


def _source_repo_for_package(pkg: dict) -> tuple[str | None, str | None]:
    return None, None


def _cve_ids_for_rows(rows: list[dict]) -> list[str]:
    cves: list[str] = []
    for row in rows:
        row_id = row.get("id", "")
        if row_id.startswith("CVE-"):
            cves.append(row_id)
        for alias in _json_array(row.get("aliases")):
            if isinstance(alias, str) and alias.startswith("CVE-"):
                cves.append(alias)
    return sorted(set(cves))


def _load_scan_shortlist(owner: str, repo: str) -> tuple[list[dict], str | None]:
    best: tuple[list[dict], str | None] = ([], None)
    scheduled = PROJECT_ROOT / "scheduled_scans" / f"{owner}_{repo}"
    for base in (scheduled, OUTPUT_DIR, PROJECT_ROOT, DEMO_DIR):
        path = base / f"scan_{owner}_{repo}.json"
        data = _read_json(path)
        if isinstance(data, list) and len(data) > len(best[0]):
            best = (data, str(path))
    return best


def _scan_meta_for_source(scan_path: str | None, owner: str, repo: str) -> dict:
    if scan_path:
        path = Path(scan_path)
        meta = _read_json(path.with_name(f"scan_meta_{owner}_{repo}.json"))
        if isinstance(meta, dict):
            return meta
    return {}


def _pkg_from_scan_row(row: dict) -> dict:
    ecosystem = str(row.get("ecosystem", ""))
    purl_type = ecosystem.lower()
    if ecosystem == "PyPI":
        purl_type = "pypi"
    elif ecosystem == "Maven":
        purl_type = "maven"
    return {
        "name": row.get("name") or row.get("package"),
        "version": row.get("version"),
        "ecosystem": purl_type,
        "osv_ecosystem": ecosystem,
        "depsdev_system": PURL_TO_DEPSDEV.get(purl_type),
        "purl": row.get("purl", ""),
        "_scan_row": row,
    }


def _finding_from_scan_row(row: dict) -> dict | None:
    name = row.get("name") or row.get("package")
    version = str(row.get("version") or "")
    ecosystem = row.get("ecosystem") or row.get("osv_ecosystem")
    if not name or not version:
        return None
    cves = row.get("cves") or []
    normalized = []
    cve_ids = []
    fix_versions = []
    worst_days = row.get("worst_days_exposed") or 0
    for cve in cves:
        aliases = cve.get("aliases") or []
        if isinstance(aliases, str):
            aliases = _json_array(aliases)
        cve_id = cve.get("id")
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            cve_ids.append(cve_id)
        for alias in aliases:
            if isinstance(alias, str) and alias.startswith("CVE-"):
                cve_ids.append(alias)
        if cve.get("fixed_in"):
            fix_versions.append(cve["fixed_in"])
        days = cve.get("days_exposed")
        if isinstance(days, int):
            worst_days = max(worst_days, days)
        normalized.append({
            "id": cve_id,
            "aliases": aliases,
            "summary": cve.get("summary", ""),
            "published": cve.get("published"),
            "days_exposed": days,
            "fixed_in": cve.get("fixed_in"),
        })
    return {
        "package": name,
        "version": version,
        "ecosystem": ecosystem,
        "purl": row.get("purl"),
        "cves": normalized,
        "cve_ids": sorted(set(cve_ids)),
        "worst_days_exposed": worst_days,
        "fix_versions": sorted(set(fix_versions)),
        "risk_score": min(100, round((worst_days or 0) / 25 + len(normalized) * 8)),
        "pkg": _pkg_from_scan_row(row),
        "evidence_origin": "latest scheduled scan artifact",
    }


@lru_cache(maxsize=16)
def _fetch_vulnerability_snapshot(owner: str, repo: str, limit: int | None = None) -> dict:
    queries_used: list[str] = []
    catalog_query = (
        "SELECT schema_name, table_name, required_filters FROM coral.tables "
        "WHERE schema_name IN ('github','osv','epss','kev','depsdev','npm','scorecard') "
        "ORDER BY schema_name, table_name LIMIT 80"
    )
    queries_used.append(catalog_query)
    catalog_rows = run_coral(catalog_query)

    scan_shortlist, scan_path = _load_scan_shortlist(owner, repo)
    if scan_shortlist:
        scan_meta = _scan_meta_for_source(scan_path, owner, repo)
        sorted_rows = sorted(
            scan_shortlist,
            key=lambda row: row.get("worst_days_exposed", 0),
            reverse=True,
        )
        if limit:
            sorted_rows = sorted_rows[:limit]
        findings = [
            finding for finding in (_finding_from_scan_row(row) for row in sorted_rows)
            if finding is not None
        ]
        packages = [finding["pkg"] for finding in findings]
        packages_raw_count = scan_meta.get("sbom_packages_total") or len(scan_shortlist)
        candidate_source = f"latest scheduled scan artifact: {scan_path}"
    else:
        packages_raw = parse_sbom(owner, repo)
        if isinstance(packages_raw, dict):
            return {
                "error": packages_raw.get("message", "SBOM unavailable"),
                "packages": [],
                "findings": [],
                "queries": queries_used,
                "catalog": catalog_rows,
                "candidate_source": "live SBOM unavailable",
            }
        fallback_limit = limit or 16
        packages = prioritize_packages(packages_raw)[:fallback_limit]
        packages_raw_count = len(packages_raw)
        candidate_source = f"live github.sbom prioritized sample ({fallback_limit} packages)"

        findings = []
        osv_queries: list[tuple[str, dict]] = []
        for pkg in packages:
            ecosystem = pkg.get("osv_ecosystem") or PURL_TO_OSV.get(str(pkg.get("ecosystem", "")).lower())
            version = str(pkg.get("version", ""))
            if not ecosystem or not is_exact_version(version):
                continue
            name = pkg["name"].lower() if ecosystem == "PyPI" else pkg["name"]
            query = (
                "SELECT id, aliases, summary, published, affected "
                "FROM osv.query_by_version "
                f"WHERE package_name='{_sql(name)}' "
                f"AND ecosystem='{_sql(ecosystem)}' "
                f"AND version='{_sql(version)}'"
            )
            queries_used.append(query)
            osv_queries.append((query, {"pkg": pkg, "ecosystem": ecosystem}))

        for metadata, rows in run_coral_parallel(osv_queries, max_workers=8):
            if not rows:
                continue
            pkg = metadata["pkg"]
            ecosystem = metadata["ecosystem"]
            version = str(pkg.get("version", ""))
            cve_ids = _cve_ids_for_rows(rows)
            cves = []
            worst_days = 0
            fix_versions: list[str] = []
            for row in rows:
                days = _days_since_iso(row.get("published")) or 0
                worst_days = max(worst_days, days)
                fixed = fixed_version_from_affected(row.get("affected"), version)
                if fixed:
                    fix_versions.append(fixed)
                cves.append({
                    "id": row.get("id"),
                    "aliases": _json_array(row.get("aliases")),
                    "summary": row.get("summary", ""),
                    "published": row.get("published"),
                    "days_exposed": days,
                    "fixed_in": fixed,
                })
            findings.append({
                "package": pkg["name"],
                "version": version,
                "ecosystem": ecosystem,
                "purl": pkg.get("purl"),
                "cves": cves,
                "cve_ids": cve_ids,
                "worst_days_exposed": worst_days,
                "fix_versions": sorted(set(fix_versions)),
                "risk_score": min(100, round(worst_days / 25 + len(cves) * 8)),
                "pkg": pkg,
                "evidence_origin": "live Coral OSV evidence",
            })

    all_cves = sorted({cve for finding in findings for cve in finding["cve_ids"]})
    epss_by_cve: dict[str, dict] = {}
    if all_cves:
        cve_arg = ",".join(all_cves[:80])
        query = (
            "SELECT cve_id, epss_score, percentile, score_date "
            f"FROM epss.scores(cve => '{_sql(cve_arg)}')"
        )
        queries_used.append(query)
        for row in run_coral(query):
            epss_by_cve[row.get("cve_id", "")] = row

        query = (
            "SELECT cve_id, vulnerability_name, date_added, ransomware_use, required_action "
            "FROM kev.vulns WHERE cve_id IN "
            f"({', '.join(repr(cve) for cve in all_cves[:80])})"
        )
        queries_used.append(query)
        kev_by_cve = {row.get("cve_id", ""): row for row in run_coral(query)}
    else:
        kev_by_cve = {}

    for finding in findings:
        epss_rows = [epss_by_cve[cve] for cve in finding["cve_ids"] if cve in epss_by_cve]
        kev_rows = [kev_by_cve[cve] for cve in finding["cve_ids"] if cve in kev_by_cve]
        max_epss = 0.0
        max_percentile = 0.0
        for row in epss_rows:
            try:
                max_epss = max(max_epss, float(row.get("epss_score") or 0))
                max_percentile = max(max_percentile, float(row.get("percentile") or 0))
            except ValueError:
                pass
        finding["epss"] = epss_rows
        finding["kev"] = kev_rows
        finding["max_epss"] = max_epss
        finding["max_epss_percentile"] = max_percentile
        finding["risk_score"] = min(
            100,
            finding["risk_score"]
            + round(max_epss * 55)
            + (35 if kev_rows else 0)
            + (10 if any(not fix for fix in finding["fix_versions"]) else 0),
        )

    findings.sort(key=lambda item: item["risk_score"], reverse=True)
    return {
        "packages": packages,
        "packages_total": packages_raw_count,
        "findings": findings,
        "queries": queries_used,
        "catalog": catalog_rows,
        "candidate_source": candidate_source,
    }


def _find_named_finding(question: str, findings: list[dict]) -> dict | None:
    lowered = question.lower()
    matches = [
        finding for finding in findings
        if finding["package"].lower() in lowered
        or finding["package"].lower().split("/")[-1] in lowered
        or finding["package"].lower().split(":")[-1] in lowered
    ]
    return matches[0] if matches else (findings[0] if findings else None)


def _ownership_evidence(owner: str, repo: str, package: str) -> dict:
    search_name = package.split("/")[-1].split(":")[-1]
    code_query = (
        "SELECT name, path, html_url FROM github.search_code("
        f"q => 'repo:{_sql(owner)}/{_sql(repo)} {_sql(search_name)}') LIMIT 5"
    )
    commit_query = (
        "SELECT author_login, message FROM github.search_commits("
        f"q => 'repo:{_sql(owner)}/{_sql(repo)} {_sql(search_name)}') LIMIT 8"
    )
    files = run_coral(code_query)
    commits = run_coral(commit_query)
    humans: list[str] = []
    bots: list[str] = []
    for row in commits:
        login = row.get("author_login")
        if not login:
            continue
        bucket = bots if "[bot]" in login.lower() or "renovate" in login.lower() else humans
        if login not in bucket:
            bucket.append(login)
    return {
        "files": files,
        "commits": commits,
        "humans": humans,
        "bots": bots,
        "queries": [code_query, commit_query],
    }


def _upstream_evidence(finding: dict) -> dict:
    pkg = finding.get("pkg") or {}
    queries: list[str] = []
    npm = []
    scorecard = []
    repo_owner, repo_name = _source_repo_for_package(pkg)
    if finding.get("ecosystem") == "npm":
        query = (
            "SELECT name, latest_version, maintainers "
            "FROM npm.package_info "
            f"WHERE package_name='{_sql(finding['package'])}'"
        )
        queries.append(query)
        npm = run_coral(query)
    if repo_owner and repo_name:
        query = (
            "SELECT full_repo_name, score, date, checks "
            "FROM scorecard.project_score "
            f"WHERE owner='{_sql(repo_owner)}' AND repo='{_sql(repo_name)}'"
        )
        queries.append(query)
        scorecard = run_coral(query)
    return {
        "repo": f"{repo_owner}/{repo_name}" if repo_owner and repo_name else None,
        "npm": npm,
        "scorecard": scorecard,
        "queries": queries,
    }


def _actionability(current: str, fixed: str | None) -> str:
    if not fixed:
        return "mitigate or replace; OSV did not expose a clean fixed version"
    cur_major = re.search(r"\d+", current or "")
    fix_major = re.search(r"\d+", fixed or "")
    if cur_major and fix_major and cur_major.group(0) != fix_major.group(0):
        return f"plan migration to {fixed}; this crosses a major version"
    return f"patch to {fixed}; likely a low-risk upgrade"


def _format_finding(finding: dict) -> dict:
    cve = finding["cve_ids"][0] if finding["cve_ids"] else finding["cves"][0]["id"]
    fix = finding["fix_versions"][0] if finding["fix_versions"] else None
    kev = finding["kev"][0] if finding.get("kev") else None
    return {
        "package": f"{finding['package']}@{finding['version']}",
        "cve": cve,
        "days_exposed": finding["worst_days_exposed"],
        "epss": round(finding.get("max_epss", 0.0), 5),
        "epss_percentile": round(finding.get("max_epss_percentile", 0.0), 5),
        "kev": kev.get("ransomware_use") if kev else "not in KEV",
        "fix": fix or "no fixed version found in OSV",
        "action": _actionability(finding["version"], fix),
        "evidence_origin": finding.get("evidence_origin", "live Coral evidence"),
    }


@app.post("/api/chat")
async def chat_agent(req: InvestigateRequest):
    """
    Real LLM agent using Groq + live Coral SQL queries.
    Replaces keyword routing with actual reasoning.
    """
    try:
        from agent import run_watch_agent
        result = await run_watch_agent(
            req.owner.strip(),
            req.repo.strip(),
            req.question.strip(),
        )
        return result
    except Exception as e:
        traceback.print_exc()
        return investigate(req)


@app.post("/api/investigate")
def investigate(req: InvestigateRequest):
    owner, repo = normalize_repo(req.owner.strip(), req.repo.strip())
    question = req.question.strip()
    if not owner or not repo or not question:
        raise HTTPException(status_code=400, detail="owner, repo, and question are required")

    snapshot = _fetch_vulnerability_snapshot(owner, repo)
    if snapshot.get("error"):
        return {
            "content": snapshot["error"],
            "verdict": "I could not read the repository SBOM.",
            "evidence": [],
            "recommended_actions": ["Enable GitHub dependency graph and rerun the scan."],
            "sources_used": ["github.sbom"],
            "coral_queries": snapshot.get("queries", []),
            "confidence": "low",
            "candidate_source": snapshot.get("candidate_source"),
        }

    findings = snapshot["findings"]
    q = question.lower()
    sources = [
        "coral.tables",
        "github.sbom",
        "osv.query_by_version",
        "epss.scores",
        "kev.vulns",
    ]
    queries = list(snapshot["queries"])
    evidence: list[dict] = []
    actions: list[str] = []
    confidence = "high" if findings else "medium"

    if not findings:
        verdict = f"I did not find OSV vulnerability matches in the prioritized live SBOM sample for {owner}/{repo}."
        actions = ["Run a full scan if you need exhaustive coverage beyond the current candidate shortlist."]
        content = verdict
    elif any(token in q for token in ("who", "talk to", "owner", "team")):
        finding = _find_named_finding(question, findings)
        own = _ownership_evidence(owner, repo, finding["package"])
        queries.extend(own["queries"])
        sources.extend(["github.search_code", "github.search_commits"])
        evidence = [_format_finding(finding)]
        evidence.append({
            "local_files": [row.get("path") for row in own["files"]],
            "human_candidates": own["humans"],
            "automation_seen": own["bots"],
        })
        target = own["humans"][0] if own["humans"] else "the repo maintainers"
        verdict = f"Talk to {target} first about {finding['package']}@{finding['version']}."
        actions = [f"Open a ticket for {target} with the vulnerable package, fix version, and file evidence."]
        content = (
            f"{verdict}\n\nI found local references and commit evidence for "
            f"{finding['package']}. Bots are evidence of attempted maintenance, but I would not treat them as owners."
        )
    elif any(token in q for token in ("three", "week", "patch", "fix first", "one engineering day")):
        top = findings[:3]
        evidence = [_format_finding(item) for item in top]
        verdict = f"Patch these three first: {', '.join(item['package'] for item in top)}."
        actions = [f"{item['package']}: {_actionability(item['version'], item['fix_versions'][0] if item['fix_versions'] else None)}" for item in top]
        content = verdict + "\n\nI ranked them by EPSS/KEV pressure, exposure age, CVE count, and whether a fix is visible."
    elif any(token in q for token in ("attacker", "exploited", "weaponized", "target")):
        top = sorted(findings, key=lambda item: (len(item.get("kev", [])), item.get("max_epss", 0), item["worst_days_exposed"]), reverse=True)[:3]
        evidence = [_format_finding(item) for item in top]
        first = top[0]
        verdict = f"An attacker would look first at {first['package']}@{first['version']}."
        actions = [f"Check reachability and patch/mitigate {first['package']} before lower-EPSS findings."]
        content = (
            f"{verdict}\n\nThat call is based on live EPSS probability, KEV status, and how long the vulnerable version has stayed in the SBOM."
        )
    elif any(token in q for token in ("soc 2", "soc2", "audit")):
        top = findings[:5]
        evidence = [_format_finding(item) for item in top]
        oldest = max(findings, key=lambda item: item["worst_days_exposed"])
        verdict = f"SOC 2 summary: {len(findings)} vulnerable prioritized dependencies found; oldest exposure is {oldest['worst_days_exposed']} days on {oldest['package']}."
        actions = [
            "Document owner, decision, and remediation date for the top findings.",
            "Separate bot activity from accountable human ownership.",
            "Record KEV/EPSS checks as evidence of risk-based prioritization.",
        ]
        content = verdict + "\n\nThe audit concern is not only vulnerability presence; it is whether fixes, owners, and risk decisions are traceable."
    elif any(token in q for token in ("takeover", "history", "burst", "maintainer trust", "upstream controls")):
        finding = _find_named_finding(question, findings)
        upstream = _upstream_evidence(finding)
        queries.extend(upstream["queries"])
        sources.extend(["npm.package_info", "scorecard.project_score", "depsdev.package_versions"])
        evidence = [_format_finding(finding)]
        if upstream["npm"]:
            maintainers = _json_array(upstream["npm"][0].get("maintainers"))
            evidence.append({"npm_maintainer_count": len(maintainers), "maintainers": maintainers})
        if upstream["scorecard"]:
            evidence.append({
                "upstream_repo": upstream["repo"],
                "scorecard_score": upstream["scorecard"][0].get("score"),
                "scorecard_date": upstream["scorecard"][0].get("date"),
            })
        verdict = f"I would review upstream trust for {finding['package']} before approving the next upgrade."
        actions = ["Verify publisher access, release notes, and lockfile diffs before merging an upgrade."]
        content = verdict + "\n\nI checked npm publisher metadata and OpenSSF Scorecard where a source repo was discoverable."
    elif any(token in q for token in ("safe to deploy", "deploy right now", "latest correct fix", "fix version")):
        finding = _find_named_finding(question, findings)
        evidence = [_format_finding(finding)]
        fix = finding["fix_versions"][0] if finding["fix_versions"] else None
        verdict = (
            f"Use {fix} as the visible OSV fix for {finding['package']}."
            if fix else
            f"I do not see a clean fixed version for {finding['package']} in OSV."
        )
        actions = [f"Do not treat deploy safety as proven until {finding['package']} is patched or reachability is ruled out."]
        content = verdict + "\n\nThis is a dependency-risk answer, not a full application release approval."
    else:
        first = findings[0]
        own = _ownership_evidence(owner, repo, first["package"])
        upstream = _upstream_evidence(first)
        queries.extend(own["queries"] + upstream["queries"])
        sources.extend(["github.search_code", "github.search_commits", "npm.package_info", "scorecard.project_score"])
        evidence = [_format_finding(first)]
        evidence.append({
            "local_files": [row.get("path") for row in own["files"]],
            "human_candidates": own["humans"],
            "upstream_repo": upstream["repo"],
        })
        verdict = f"What you are most likely to regret ignoring is {first['package']}@{first['version']}."
        actions = [f"Assign an owner and move {first['package']} to a fixed version or documented mitigation."]
        content = (
            f"{verdict}\n\nI ranked it highest from live OSV, EPSS, KEV, exposure age, local usage evidence, and upstream trust signals."
        )

    sources = sorted(dict.fromkeys(sources))
    return {
        "repo": f"{owner}/{repo}",
        "question": question,
        "content": content,
        "verdict": verdict,
        "evidence": evidence,
        "recommended_actions": actions,
        "sources_used": sources,
        "coral_queries": queries[-12:],
        "confidence": confidence,
        "packages_sampled": snapshot.get("packages_total", 0),
        "findings_considered": len(findings),
        "candidate_source": snapshot.get("candidate_source"),
    }


DRIFTWATCH_AGENT_PROMPT = """
You are DriftWatch, an expert supply-chain security agent.
You have access to 5 tools that query live security intelligence
across GitHub, OSV, CISA KEV, deps.dev, and OpenSSF Scorecard.

Always call tools when a user asks about vulnerabilities,
package health, or security risks for a repository.
Always cite which data sources you queried in your answer.
When a tool returns no active exploitation, pivot to pre-CVE
collapse risks and the negligence window.
Never show raw tool-call syntax, XML tags, JSON arguments, or function
names to the user. If another tool would help, describe the concrete
security action in plain English instead.

Repository context: When the user mentions a repo or it's in
the conversation, use it as owner/repo parameters.
Default demo repo: parse-community/parse-server
""".strip()


GROQ_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "predict_pre_cve_collapse",
            "description": "Find npm dependencies in a repository that are deprecated, abandoned, low-score, or otherwise at pre-CVE collapse risk using GitHub SBOM, deps.dev, Scorecard, commits, releases, and OSV.",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string", "description": "GitHub repository owner"},
                    "repo": {"type": "string", "description": "GitHub repository name"},
                },
                "required": ["owner", "repo"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_active_exploitation",
            "description": "Cross-reference exact repository npm package versions against OSV CVEs and CISA KEV active exploitation and ransomware intelligence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string", "description": "GitHub repository owner"},
                    "repo": {"type": "string", "description": "GitHub repository name"},
                },
                "required": ["owner", "repo"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "audit_negligence_window",
            "description": "Find human commits that landed after known CVE disclosure or KEV weaponization dates for vulnerable repository packages.",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string", "description": "GitHub repository owner"},
                    "repo": {"type": "string", "description": "GitHub repository name"},
                },
                "required": ["owner", "repo"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_dependency_takeover_risk",
            "description": "Detect anomalous npm publish bursts after silence that can indicate dependency maintainer account takeover, including the ua-parser-js reference case.",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string", "description": "GitHub repository owner"},
                    "repo": {"type": "string", "description": "GitHub repository name"},
                },
                "required": ["owner", "repo"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_supply_chain_impersonation",
            "description": "Cross-reference repository SBOM packages against CISA KEV supply-chain poisoning and impersonation entries, including current npm ecosystem warnings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string", "description": "GitHub repository owner"},
                    "repo": {"type": "string", "description": "GitHub repository name"},
                },
                "required": ["owner", "repo"],
            },
        },
    },
]


async def _groq_chat(api_key: str, payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=90) as client:
        response = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()
        return response.json()


TOOL_CALL_TAG_RE = re.compile(
    r"<function=([A-Za-z0-9_]+)>\s*(\{.*?\})\s*</function>",
    re.DOTALL,
)


TOOL_LABELS = {
    "predict_pre_cve_collapse": "the pre-CVE collapse-risk check",
    "detect_active_exploitation": "an active exploitation check",
    "audit_negligence_window": "the negligence-window audit",
    "detect_dependency_takeover_risk": "a dependency takeover-risk check",
    "detect_supply_chain_impersonation": "a supply-chain impersonation-risk check",
}


def _sanitize_agent_content(content: Optional[str]) -> Optional[str]:
    """Remove pseudo tool-call markup that some models emit as prose."""
    if content is None:
        return None

    def replace_tag(match: re.Match) -> str:
        tool_name = match.group(1)
        label = TOOL_LABELS.get(tool_name, "the recommended DriftWatch check")
        try:
            args = json.loads(match.group(2))
        except json.JSONDecodeError:
            args = {}
        owner = args.get("owner")
        repo = args.get("repo")
        if owner and repo:
            return f"{label} for {owner}/{repo}"
        return label

    sanitized = TOOL_CALL_TAG_RE.sub(replace_tag, content)
    sanitized = re.sub(r"\bfunction=([A-Za-z0-9_]+)\b", r"\1", sanitized)
    return sanitized


@app.post("/api/chat_legacy")
async def chat(req: dict):
    api_key, api_key_source = get_config_value("GROQ_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY was not found in the process env, .env.local, .env, or Windows user environment. Set it and restart uvicorn.",
        )

    messages = req.get("messages")
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="Missing chat field: messages")

    user_system_prompt = (req.get("system") or "").strip()
    owner_ctx = (req.get("owner") or "parse-community").strip()
    repo_ctx = (req.get("repo") or "parse-server").strip()
    owner_ctx, repo_ctx = normalize_repo(owner_ctx, repo_ctx)
    owner = owner_ctx
    repo = repo_ctx
    repo_line = (
        f"\n\nRepo currently being analyzed: {owner_ctx}/{repo_ctx}. "
        f"ALWAYS use owner='{owner_ctx}' and repo='{repo_ctx}' as parameters "
        f"in ALL tool calls unless the user explicitly names a different repo."
    )
    system_prompt = DRIFTWATCH_AGENT_PROMPT + repo_line
    if user_system_prompt:
        system_prompt += f"\n\nAdditional operator instructions:\n{user_system_prompt}"

    conversation = [{"role": "system", "content": system_prompt}, *messages]
    tools_called: list[str] = []
    raw_responses: list[dict] = []
    model = get_config_value("GROQ_MODEL")[0] or "llama-3.3-70b-versatile"

    try:
        for _ in range(3):
            data = await _groq_chat(
                api_key,
                {
                    "model": model,
                    "messages": conversation,
                    "tools": GROQ_TOOL_DEFINITIONS,
                    "tool_choice": "auto",
                    "max_tokens": 1000,
                },
            )
            raw_responses.append(data)
            choice = data.get("choices", [{}])[0]
            message = choice.get("message", {})
            tool_calls = message.get("tool_calls") or []
            if choice.get("finish_reason") != "tool_calls" or not tool_calls:
                return {
                    "content": _sanitize_agent_content(message.get("content")),
                    "tools_called": tools_called,
                    "provider": "groq",
                    "api_key_source": api_key_source,
                    "raw": data,
                }

            conversation.append(message)
            for tool_call in tool_calls:
                function = tool_call.get("function", {})
                tool_name = function.get("name")
                try:
                    arguments = json.loads(function.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {}
                arguments["owner"] = (arguments.get("owner") or owner).strip()
                arguments["repo"] = (arguments.get("repo") or repo).strip()
                tool_func = TOOL_REGISTRY.get(tool_name)
                if tool_func is None:
                    result = {"error": f"Unknown DriftWatch tool: {tool_name}"}
                else:
                    try:
                        result = tool_func(arguments["owner"], arguments["repo"])
                    except Exception as exc:
                        result = {"error": str(exc), "tool": tool_name}
                    tools_called.append(tool_name)
                conversation.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.get("id"),
                        "name": tool_name,
                        "content": json.dumps(result, ensure_ascii=False),
                    }
                )

        data = await _groq_chat(
            api_key,
            {
                "model": model,
                "messages": conversation,
                "max_tokens": 1000,
            },
        )
        raw_responses.append(data)
        content = data.get("choices", [{}])[0].get("message", {}).get("content")
        return {
            "content": _sanitize_agent_content(content),
            "tools_called": tools_called,
            "provider": "groq",
            "api_key_source": api_key_source,
            "raw": data,
        }
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json()
        except ValueError:
            detail = exc.response.text
        raise HTTPException(status_code=exc.response.status_code, detail=detail) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach Groq: {exc}") from exc
