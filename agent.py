"""
agent.py -- DriftWatch LLM agent using Groq + live Coral SQL queries.
"""

from __future__ import annotations

import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from groq import Groq

from coral_utils import run_coral

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
DEMO_DIR = PROJECT_ROOT / "demo_data"

_executor = ThreadPoolExecutor(max_workers=4)


async def _run_coral_async(sql: str) -> list[dict]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, run_coral, sql)


def _load_scan_context(owner: str, repo: str) -> list[dict]:
    candidates = [
        OUTPUT_DIR / f"scan_{owner}_{repo}.json",
        PROJECT_ROOT / f"scan_{owner}_{repo}.json",
        OUTPUT_DIR / "scan_jellyfin_jellyfin-web.json",
        DEMO_DIR / "scan_jellyfin_jellyfin-web.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, list) and data:
                    return data
            except (json.JSONDecodeError, OSError):
                continue
    return []


def _build_scan_summary(findings: list[dict]) -> str:
    lines = []
    for f in findings[:10]:
        name = f.get("name") or f.get("package", "unknown")
        version = f.get("version", "?")
        days = f.get("worst_days_exposed", 0)
        cves = f.get("cves") or []
        worst_cve = cves[0].get("id", "n/a") if cves else "n/a"
        fixed_in = cves[0].get("fixed_in", "?") if cves else "?"
        kev = "KEV!" if f.get("kev_hits") else ""
        lines.append(f"{name}@{version}: {days}d, {worst_cve}, fix={fixed_in} {kev}".strip())
    return "\n".join(lines)


def _build_system_prompt(owner: str, repo: str, scan_summary: str) -> str:
    return f"""You are DriftWatch, an expert supply-chain security analyst.
Repo: {owner}/{repo}

TOP VULNERABLE PACKAGES (sorted by urgency: KEV status > days exposed > CVE count):
{scan_summary if scan_summary else "(no scan data loaded — use coral_sql to query live)"}

CORAL SOURCES (use coral_sql tool to query live data):

github.sbom — get package list as JSON blob:
  SELECT sbom__packages FROM github.sbom WHERE owner='{owner}' AND repo='{repo}'
  (returns JSON blob; parse with json_get_array / unnest / json_get_str)

github.commits columns: owner, repo, sha, commit__message, commit__author__date, author__login, html_url
  Example: SELECT sha, commit__message, author__login, commit__author__date FROM github.commits WHERE owner='{owner}' AND repo='{repo}' LIMIT 10

github.search_commits columns: sha, html_url, message, author_login, repository_full_name, score
  Syntax: SELECT author_login, message, html_url FROM github.search_commits(q => 'repo:{owner}/{repo} keyword')

github.search_code columns: name, path, html_url
  Syntax: SELECT name, path, html_url FROM github.search_code(q => 'repo:{owner}/{repo} keyword')

osv.query_by_version columns: id, aliases, summary, published, affected
  Required filters: ecosystem, package_name, version (all must be constant strings)
  Example: SELECT id, summary, published, affected FROM osv.query_by_version WHERE ecosystem='npm' AND package_name='braces' AND version='2.3.2'

kev.vulns columns: cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, ransomware_use, notes
  Example: SELECT cve_id, vulnerability_name, date_added, required_action FROM kev.vulns WHERE cve_id='CVE-2021-3450'

epss.scores columns: cve_id, epss_score, percentile, score_date
  Syntax: SELECT cve_id, epss_score, percentile FROM epss.scores(cve => 'CVE-xxx,CVE-yyy')

depsdev.package_versions columns: name, version, system, is_deprecated, deprecated_reason, published_at, is_default
  Example: SELECT version, is_deprecated, deprecated_reason, published_at FROM depsdev.package_versions WHERE system='NPM' AND package_name='dompurify'

scorecard.project_score columns: full_repo_name, score, date, checks
  Required: owner, repo
  Example: SELECT full_repo_name, score, date, checks FROM scorecard.project_score WHERE owner='postcss' AND repo='postcss'

npm.package_info — package metadata (maintainers, downloads, etc.)
  Example: SELECT * FROM npm.package_info WHERE package_name='postcss'

RULES:
- Answer from scan context for simple questions about known findings — do not call coral_sql unnecessarily
- Call coral_sql for: ownership questions, pre-CVE signals, commit history, EPSS lookups for specific CVEs, anything needing live data not in the scan summary
- For cross-source questions JOIN multiple sources in one SQL query where Coral supports it
- Always cite which Coral sources you queried
- Be direct. End every response with one concrete action.
- Never hallucinate. If Coral returns empty rows, say so.
- If a query fails, try a simpler version before giving up.
- WHO SHOULD FIX (CRITICAL RULE): When asked who should fix a vulnerability, you MUST use github.search_commits with the table-function syntax. Do NOT use github.commits with LIKE — it will return nothing. The ONLY correct pattern is:
    SELECT author_login, message, html_url FROM github.search_commits(q => 'repo:{owner}/{repo} <package_keyword>')
  Search for contributors in {owner}/{repo} (the consumer repo), NOT upstream npm/pypi maintainers. Name a specific {owner}/{repo} contributor in your answer.

DANGER RANKING: The most dangerous vulnerability is NOT simply the oldest one. Rank by: KEV status first, then EPSS score, then days exposed, then CVE count. pdfjs-dist@3.11.174 with CVE-2024-4367 is likely the most dangerous — 754 days exposed, RCE via malicious PDF. Always check EPSS before answering danger questions.

CORAL SUBQUERY RULE: Coral does NOT support subqueries across different source schemas. Never write: WHERE cve_id IN (SELECT id FROM osv...). Instead make two separate coral_sql calls:
  Call 1: get CVE IDs from OSV (e.g. SELECT id FROM osv.query_by_version WHERE ecosystem='npm' AND package_name='pdfjs-dist' AND version='3.11.174')
  Call 2: use those CVE IDs explicitly in KEV query (e.g. SELECT cve_id, vulnerability_name, ransomware_use FROM kev.vulns WHERE cve_id IN ('CVE-2024-4367'))"""


CORAL_TOOL_DEF = {
    "type": "function",
    "function": {
        "name": "coral_sql",
        "description": (
            "Execute SQL against Coral security sources. "
            "Use for live data: CVE lookups, KEV status, EPSS scores, "
            "commit history, ownership, deprecation signals."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "SQL query to execute against Coral",
                }
            },
            "required": ["sql"],
        },
    },
}


async def run_watch_agent(owner: str, repo: str, question: str) -> dict:
    # Step 1 — Load scan context
    all_findings = _load_scan_context(owner, repo)
    def _urgency_score(finding: dict) -> float:
        return (
            (10 if finding.get("kev_hits") else 0)
            + min(finding.get("worst_days_exposed", 0) / 50, 10)
            + (len(finding.get("cves", [])) * 2)
        )

    scan_findings = sorted(all_findings, key=_urgency_score, reverse=True)[:10]
    scan_summary = _build_scan_summary(scan_findings)

    # Step 2 — Build system prompt
    system_prompt = _build_system_prompt(owner, repo, scan_summary)

    # Step 3 — Groq client
    api_key = os.environ.get("GROQ_API_KEY")
    client = Groq(api_key=api_key)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": question},
    ]

    coral_queries: list[str] = []
    sources_used: set[str] = set()
    max_iterations = 5
    final_message: Any = None

    try:
        for _ in range(max_iterations):
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                tools=[CORAL_TOOL_DEF],
                tool_choice="auto",
                max_tokens=2048,
                temperature=0.1,
            )

            message = response.choices[0].message
            final_message = message
            messages.append(message)

            if not message.tool_calls:
                break

            # Execute each tool call
            for tool_call in message.tool_calls:
                if tool_call.function.name != "coral_sql":
                    continue

                try:
                    sql = json.loads(tool_call.function.arguments)["sql"]
                except (json.JSONDecodeError, KeyError):
                    sql = tool_call.function.arguments

                coral_queries.append(sql)
                for schema in ("github", "osv", "kev", "epss", "depsdev", "scorecard", "npm"):
                    if schema in sql.lower():
                        sources_used.add(schema)

                try:
                    rows = await _run_coral_async(sql)
                    if rows:
                        payload = json.dumps({"rows": rows, "count": len(rows)})
                        # Truncate to avoid exceeding Groq token limits
                        if len(payload) > 3000:
                            payload = payload[:3000] + '... (truncated)'
                        result_payload = payload
                    else:
                        result_payload = json.dumps(
                            {"rows": [], "count": 0, "note": "No results returned"}
                        )
                except Exception as exc:
                    result_payload = json.dumps({"error": str(exc), "rows": []})

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result_payload,
                    }
                )

    except Exception as exc:
        err_str = str(exc)
        if "429" in err_str or "rate limit" in err_str.lower():
            return {
                "content": "Rate limit hit. Try again in 30 seconds.",
                "verdict": "Rate limited.",
                "coral_queries": [],
                "sources_used": [],
                "confidence": "low",
                "repo": f"{owner}/{repo}",
                "question": question,
            }
        return {
            "content": f"Agent error: {err_str}",
            "verdict": "Agent encountered an error.",
            "coral_queries": coral_queries,
            "sources_used": sorted(sources_used),
            "confidence": "low",
            "repo": f"{owner}/{repo}",
            "question": question,
        }

    # Step 5 — Return result
    final_content = (
        (final_message.content or "Analysis complete.") if final_message else "Analysis complete."
    )
    verdict = (final_content.split(".")[0] + ".") if final_content else ""
    confidence = "high" if coral_queries else ("medium" if scan_findings else "low")

    return {
        "content": final_content,
        "verdict": verdict,
        "coral_queries": coral_queries,
        "sources_used": sorted(sources_used),
        "confidence": confidence,
        "repo": f"{owner}/{repo}",
        "question": question,
        "packages_sampled": len(scan_findings),
        "findings_considered": len(scan_findings),
    }
