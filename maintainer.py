"""
maintainer.py  --  Maintainer Responsiveness analysis (lean version)

The idea (the HERO feature):
  When a vulnerable package gets a CVE, the real question a security engineer has is
  "will the maintainers actually fix this fast, or am I stuck?"
  We answer it with real data:

    latency = (date the FIXED release shipped) - (date the CVE was published)

  A small/negative latency  -> maintainers patch fast (often before disclosure). GOOD.
  A large latency           -> maintainers are slow. Don't wait -> mitigate now.

  "Lean" means: we measure responsiveness using the CVE(s) we already detected for a
  package, not its entire historical CVE list. It's an honest, smaller claim.

How the data connects (all verified in Coral):
  OSV gives    : CVE id, published date, and the fixed version (from `affected`).
  OSV refs give: the package's GitHub repo (a reference with type == "PACKAGE").
  GitHub gives : github.releases -> when a given version tag actually shipped.

This module is meant to be imported by scan.py, or run standalone for one package.
"""

import subprocess
import json
from datetime import datetime, timezone


def run_coral(query):
    """Run `coral sql --format json` and return parsed rows (list of dicts)."""
    result = subprocess.run(
        ["coral", "sql", "--format", "json", query],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Coral query failed:\n{result.stderr.strip()}")
    output = result.stdout.strip()
    if not output:
        return []
    return json.loads(output)


def parse_iso(iso_date):
    """Turn '2023-09-28T22:15:30Z' into a datetime. None if unparseable."""
    if not iso_date:
        return None
    try:
        return datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
    except ValueError:
        return None


def github_repo_from_references(references_raw):
    """
    Pull the package's GitHub repo (owner, repo) out of a CVE's `references`.

    `references_raw` is a JSON string like:
      [{"type":"PACKAGE","url":"https://github.com/postcss/postcss"}, ...]

    Strategy (most reliable first):
      1. a reference with type == "PACKAGE" pointing at github.com
      2. otherwise, any github.com URL we can find
    Returns (owner, repo) or None.
    """
    if not references_raw:
        return None
    try:
        refs = json.loads(references_raw)
    except (json.JSONDecodeError, TypeError):
        return None

    # Pass 1: prefer the canonical PACKAGE reference.
    candidates = [r for r in refs if r.get("type") == "PACKAGE"]
    # Pass 2: fall back to any other reference.
    candidates += [r for r in refs if r.get("type") != "PACKAGE"]

    for ref in candidates:
        owner_repo = _parse_github_owner_repo(ref.get("url", ""))
        if owner_repo:
            return owner_repo
    return None


def _parse_github_owner_repo(url):
    """
    From 'https://github.com/postcss/postcss/releases/tag/8.4.31'
    extract ('postcss', 'postcss'). Returns None if not a github repo URL.
    """
    marker = "github.com/"
    if marker not in url:
        return None
    tail = url.split(marker, 1)[1]          # 'postcss/postcss/releases/tag/8.4.31'
    parts = tail.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    owner = parts[0]
    repo = parts[1]
    # strip a trailing ".git" if present
    if repo.endswith(".git"):
        repo = repo[:-4]
    # ignore non-repo paths like github.com/advisories/...
    if owner in {"advisories", "github"}:
        # 'github/advisory-database' is the advisory repo, not the package repo
        if not (owner == "github" and repo == "advisory-database"):
            pass
        return None if owner == "advisories" else (owner, repo)
    return (owner, repo)


def release_date_for_version(owner, repo, version):
    """
    Find when a given version shipped, via github.releases.
    Tries the bare tag ('8.4.31') and the 'v'-prefixed tag ('v8.4.31').
    Returns an ISO date string or None.
    """
    for tag in (version, f"v{version}"):
        safe_tag = tag.replace("'", "''")
        rows = run_coral(
            "SELECT tag_name, published_at FROM github.releases "
            f"WHERE owner='{owner}' AND repo='{repo}' AND tag_name='{safe_tag}'"
        )
        if rows:
            return rows[0].get("published_at")
    return None


def classify(latency_days):
    """Turn a latency number into a human label."""
    if latency_days is None:
        return "unknown"
    if latency_days <= 7:
        return "fast"          # fixed within a week (or before disclosure)
    if latency_days <= 30:
        return "moderate"
    if latency_days <= 90:
        return "slow"
    return "very slow"


def responsiveness_for_cve(cve):
    """
    Compute responsiveness for ONE detected CVE.

    `cve` is a dict from our scan: {id, published, fixed_in, affected?, references?}
    We need its `references` (to find the repo) and `fixed_in` (the fix version).

    Returns a dict describing what we could (or couldn't) compute -- always honest.
    """
    cve_id = cve.get("id")
    published = cve.get("published")
    fixed_in = cve.get("fixed_in")

    # We need the CVE's references to locate the repo. If our scan didn't carry them,
    # fetch them now from osv.vulns.
    references_raw = cve.get("references")
    if not references_raw and cve_id:
        rows = run_coral(
            f"SELECT references FROM osv.vulns WHERE id='{cve_id}'"
        )
        if rows:
            references_raw = rows[0].get("references")

    repo = github_repo_from_references(references_raw)

    # Honest early-outs: say exactly why we can't compute, never guess.
    if not fixed_in:
        return {"cve": cve_id, "status": "no fix version listed"}
    if not repo:
        return {"cve": cve_id, "status": "no GitHub repo found in references"}

    owner, repo_name = repo
    fix_shipped = release_date_for_version(owner, repo_name, fixed_in)
    if not fix_shipped:
        return {
            "cve": cve_id,
            "status": f"fix {fixed_in} not found in {owner}/{repo_name} releases",
            "repo": f"{owner}/{repo_name}",
        }

    pub_dt = parse_iso(published)
    fix_dt = parse_iso(fix_shipped)
    if not pub_dt or not fix_dt:
        return {"cve": cve_id, "status": "could not parse dates"}

    latency = (fix_dt - pub_dt).days
    return {
        "cve": cve_id,
        "status": "ok",
        "repo": f"{owner}/{repo_name}",
        "fixed_in": fixed_in,
        "cve_published": published,
        "fix_shipped": fix_shipped,
        "latency_days": latency,
        "label": classify(latency),
    }


def analyze_package(finding):
    """
    Given one vulnerable-package finding from scan.py
    ({name, version, cves:[...]}), compute responsiveness across its CVEs.
    Returns a summary dict.
    """
    results = [responsiveness_for_cve(c) for c in finding.get("cves", [])]
    computed = [r for r in results if r.get("status") == "ok"]

    summary = {
        "name": finding.get("name"),
        "version": finding.get("version"),
        "per_cve": results,
    }
    if computed:
        latencies = [r["latency_days"] for r in computed]
        avg = sum(latencies) / len(latencies)
        summary["avg_latency_days"] = round(avg, 1)
        summary["overall_label"] = classify(avg)
    else:
        summary["avg_latency_days"] = None
        summary["overall_label"] = "insufficient release history"
    return summary


# ---- standalone test: read a scan_*.json and analyze it ----
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python maintainer.py scan_jellyfin_jellyfin-web.json")
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as f:
        findings = json.load(f)

    print(f"Analyzing maintainer responsiveness for {len(findings)} vulnerable package(s)...\n")
    for finding in findings:
        summary = analyze_package(finding)
        label = summary["overall_label"]
        avg = summary["avg_latency_days"]
        avg_str = f"{avg} days avg" if avg is not None else "n/a"
        print(f"{summary['name']}@{summary['version']}  ->  {label}  ({avg_str})")
        for r in summary["per_cve"]:
            if r.get("status") == "ok":
                print(f"    {r['cve']}: fix shipped {r['latency_days']} days "
                      f"after disclosure  [{r['label']}]  ({r['repo']})")
            else:
                print(f"    {r['cve']}: {r['status']}")
        print()
