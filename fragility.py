"""
fragility.py  --  Upstream Risk Radar: fragility scoring engine v2

Signals:
  1. Abandonment / Bus-Factor  (GitHub commits + contributors)
  2. Release Anomaly           (GitHub releases)
  3. Issue Stagnation          (GitHub issues)
  4. PR Stagnation             (GitHub pulls)
  5. Maintainer Responsiveness (passed in from maintainer.py)
  6. npm Ownership Risk        (npm registry: maintainer count + downloads)

Urgency Score = fragility x patch_lag_multiplier x blast_radius_multiplier
  patch_lag_multiplier : 1x (fresh) -> 3x (2000+ days exposed with fix)
  blast_radius         : number of your repos depending on this package
  KEV                  : standalone alert layer (not a multiplier)
"""

import subprocess
import json
import math
import urllib.request
from datetime import datetime, timezone


def run_coral(query):
    result = subprocess.run(
        ["coral", "sql", "--format", "json", query],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return []
    output = result.stdout.strip()
    if not output:
        return []
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return []


def days_ago(iso_date):
    if not iso_date:
        return None
    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


# ── Signal 1: Abandonment / Bus-Factor (GitHub) ─────────────────────────────

def score_abandonment(owner, repo):
    commits = run_coral(
        "SELECT commit__author__date FROM github.commits "
        f"WHERE owner='{owner}' AND repo='{repo}' "
        "ORDER BY commit__author__date DESC LIMIT 1"
    )
    last_commit_days = None
    if commits:
        last_commit_days = days_ago(commits[0].get("commit__author__date"))

    contributors = run_coral(
        "SELECT login, contributions FROM github.repo_contributors "
        f"WHERE owner='{owner}' AND repo='{repo}' "
        "ORDER BY contributions DESC LIMIT 20"
    )
    total_contribs = sum(c.get("contributions", 0) for c in contributors)
    top_contrib = contributors[0].get("contributions", 0) if contributors else 0
    contributor_count = len(contributors)
    bus_factor_pct = (top_contrib / total_contribs * 100) if total_contribs > 0 else 100

    if last_commit_days is None:       recency_score = 100
    elif last_commit_days <= 14:       recency_score = 0
    elif last_commit_days <= 30:       recency_score = 15
    elif last_commit_days <= 90:       recency_score = 40
    elif last_commit_days <= 180:      recency_score = 65
    elif last_commit_days <= 365:      recency_score = 85
    else:                              recency_score = 100

    bus_score   = 90 if bus_factor_pct >= 90 else 60 if bus_factor_pct >= 70 else 30 if bus_factor_pct >= 50 else 10
    count_score = 90 if contributor_count <= 1 else 60 if contributor_count <= 3 else 20 if contributor_count <= 10 else 0

    score = round(recency_score * 0.5 + bus_score * 0.3 + count_score * 0.2)
    return {
        "signal": "abandonment",
        "score": score,
        "last_commit_days": last_commit_days,
        "contributor_count": contributor_count,
        "top_contributor_pct": round(bus_factor_pct, 1),
        "top_contributor": contributors[0].get("login") if contributors else None,
        "explanation": (
            f"Last commit {last_commit_days}d ago, "
            f"{contributor_count} contributors, "
            f"top contributor owns {bus_factor_pct:.0f}% of commits"
        )
    }


# ── Signal 2: Release Anomaly (GitHub) ──────────────────────────────────────

def score_release_anomaly(owner, repo):
    releases = run_coral(
        "SELECT tag_name, published_at FROM github.releases "
        f"WHERE owner='{owner}' AND repo='{repo}' "
        "ORDER BY published_at DESC LIMIT 30"
    )
    if not releases:
        return {"signal": "release_anomaly", "score": 30,
                "explanation": "No releases found"}

    dates = []
    for r in releases:
        d = r.get("published_at")
        if d:
            try:
                dates.append(datetime.fromisoformat(d.replace("Z", "+00:00")))
            except ValueError:
                pass

    burst_detected, burst_detail = False, ""
    for i, d in enumerate(dates):
        window = [x for x in dates if abs((x - d).days) <= 3]
        if len(window) >= 4:
            burst_detected = True
            burst_detail = f"{len(window)} releases within 3 days of {d.date()}"
            break

    dormancy_burst = False
    if len(dates) >= 3:
        if abs((dates[1] - dates[2]).days) > 180 and abs((dates[0] - dates[1]).days) < 7:
            dormancy_burst = True

    score, reasons = 0, []
    if burst_detected:
        score += 70
        reasons.append(f"release burst: {burst_detail}")
    if dormancy_burst:
        score += 50
        reasons.append("dormant project suddenly active")
    if not burst_detected and not dormancy_burst:
        last_days = days_ago(releases[0].get("published_at")) if releases else None
        if last_days and last_days > 365:
            score += 30
            reasons.append(f"no release in {last_days} days")
        else:
            reasons.append("normal release pattern")

    return {
        "signal": "release_anomaly",
        "score": min(score, 100),
        "burst_detected": burst_detected,
        "dormancy_burst": dormancy_burst,
        "last_release_days": days_ago(releases[0].get("published_at")) if releases else None,
        "explanation": "; ".join(reasons) if reasons else "normal release pattern"
    }


# ── Signal 3: Issue Stagnation (GitHub) ─────────────────────────────────────

def score_issue_stagnation(owner, repo):
    issues = run_coral(
        "SELECT state, created_at, closed_at FROM github.issues "
        f"WHERE owner='{owner}' AND repo='{repo}' LIMIT 50"
    )
    if not issues:
        return {"signal": "issue_stagnation", "score": 0,
                "explanation": "No issues found"}

    open_issues = [i for i in issues if i.get("state") == "open"]
    open_count  = len(open_issues)
    open_ratio  = open_count / len(issues)
    oldest_days = max(
        (days_ago(i.get("created_at")) or 0 for i in open_issues), default=0)

    ratio_score = min(open_ratio * 100, 100)
    age_score   = (100 if oldest_days > 365 else 70 if oldest_days > 180
                   else 40 if oldest_days > 90 else 20 if oldest_days > 30 else 0)
    score = round(ratio_score * 0.4 + age_score * 0.6)

    return {
        "signal": "issue_stagnation",
        "score": score,
        "open_issues": open_count,
        "total_checked": len(issues),
        "oldest_open_days": oldest_days,
        "explanation": (
            f"{open_count}/{len(issues)} issues open, "
            f"oldest unresolved: {oldest_days} days"
        )
    }


# ── Signal 4: PR Stagnation (GitHub) ────────────────────────────────────────

def score_pr_stagnation(owner, repo):
    pulls = run_coral(
        "SELECT state, created_at, closed_at FROM github.pulls "
        f"WHERE owner='{owner}' AND repo='{repo}' LIMIT 30"
    )
    if not pulls:
        return {"signal": "pr_stagnation", "score": 0, "explanation": "No PRs found"}

    open_prs   = [p for p in pulls if p.get("state") == "open"]
    closed_prs = [p for p in pulls if p.get("state") == "closed"
                  and p.get("closed_at") and p.get("created_at")]
    open_count = len(open_prs)

    avg_close_days = None
    if closed_prs:
        times = []
        for pr in closed_prs:
            try:
                c = datetime.fromisoformat(pr["created_at"].replace("Z", "+00:00"))
                x = datetime.fromisoformat(pr["closed_at"].replace("Z", "+00:00"))
                times.append((x - c).days)
            except (ValueError, KeyError):
                pass
        if times:
            avg_close_days = sum(times) / len(times)

    open_score    = (80 if open_count >= 10 else 50 if open_count >= 5
                     else 25 if open_count >= 2 else 0)
    latency_score = (80 if avg_close_days and avg_close_days > 30
                     else 50 if avg_close_days and avg_close_days > 14
                     else 25 if avg_close_days and avg_close_days > 7 else 0)
    score = round(open_score * 0.4 + latency_score * 0.6)
    avg_str = f"{avg_close_days:.1f}d avg" if avg_close_days else "n/a"

    return {
        "signal": "pr_stagnation",
        "score": score,
        "open_prs": open_count,
        "avg_close_days": round(avg_close_days, 1) if avg_close_days else None,
        "explanation": f"{open_count} open PRs, {avg_str} close time"
    }


# ── Signal 6: npm Ownership Risk ────────────────────────────────────────────

def score_npm_ownership(package_name):
    """
    Pulls npm registry data for the package:
      - Maintainer count (bus-factor on npm, not just GitHub)
      - Weekly downloads (blast radius scale)
    Downloads come from api.npmjs.org directly (different base URL than registry).
    """
    # npm registry: maintainer info
    rows = run_coral(
        f"SELECT maintainers FROM npm.package_info "
        f"WHERE package_name='{package_name}'"
    )
    maintainer_count = None
    maintainers = []
    if rows:
        raw = rows[0].get("maintainers")
        if raw:
            try:
                maintainers = json.loads(raw)
                maintainer_count = len(maintainers)
            except (json.JSONDecodeError, TypeError):
                pass

    # npm downloads: via direct HTTP (api.npmjs.org has different base URL)
    weekly_downloads = None
    try:
        url = f"https://api.npmjs.org/downloads/point/last-week/{package_name}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            weekly_downloads = data.get("downloads")
    except Exception:
        pass

    # Score: low maintainer count + high downloads = high risk
    if maintainer_count is None:
        ownership_score = 20  # unknown
    elif maintainer_count == 1:
        ownership_score = 90
    elif maintainer_count <= 3:
        ownership_score = 55
    elif maintainer_count <= 7:
        ownership_score = 25
    else:
        ownership_score = 5

    # Download scale amplifier (informational, not added to score directly)
    if weekly_downloads and weekly_downloads > 10_000_000:
        scale = "massive (>10M/week)"
    elif weekly_downloads and weekly_downloads > 1_000_000:
        scale = "large (>1M/week)"
    elif weekly_downloads and weekly_downloads > 100_000:
        scale = "medium (>100K/week)"
    elif weekly_downloads:
        scale = f"small ({weekly_downloads:,}/week)"
    else:
        scale = "unknown"

    dl_str = f"{weekly_downloads:,}" if weekly_downloads else "unknown"
    return {
        "signal": "npm_ownership",
        "score": ownership_score,
        "maintainer_count": maintainer_count,
        "maintainer_names": [m.get("name") for m in maintainers],
        "weekly_downloads": weekly_downloads,
        "download_scale": scale,
        "explanation": (
            f"{maintainer_count or '?'} npm maintainer(s), "
            f"{dl_str} weekly downloads ({scale})"
        )
    }


# ── KEV check (standalone alert, not a multiplier) ──────────────────────────

def check_kev(cve_ids):
    if not cve_ids:
        return []
    try:
        with open("kev.json", encoding="utf-8") as f:
            kev_data = json.load(f)
        kev_cves = {v["cveID"]: v for v in kev_data.get("vulnerabilities", [])}
        return [kev_cves[c] for c in cve_ids if c in kev_cves]
    except FileNotFoundError:
        return []


# ── Patch-lag multiplier ─────────────────────────────────────────────────────

def patch_lag_multiplier(worst_days_exposed):
    """
    Scales urgency based on how long a fix has been available but ignored.
    1x = fresh CVE or no fix. 3x = 2000+ days exposed with fix available.
    This fires on every enterprise codebase with technical debt.
    """
    if not worst_days_exposed or worst_days_exposed <= 0:
        return 1.0
    if worst_days_exposed < 30:
        return 1.1
    if worst_days_exposed < 90:
        return 1.3
    if worst_days_exposed < 180:
        return 1.6
    if worst_days_exposed < 365:
        return 2.0
    if worst_days_exposed < 730:
        return 2.4
    return 3.0   # 2+ years = maximum


# ── Composite Fragility + Urgency Score ─────────────────────────────────────

def compute_fragility(owner, repo, package_name=None, cve_ids=None,
                      blast_radius=1, maintainer_responsiveness_label=None,
                      worst_days_exposed=None):
    """
    Compute the full fragility profile for one upstream project.

    owner, repo         : the upstream GitHub project
    package_name        : npm package name (for npm signal; defaults to repo)
    cve_ids             : list of CVE IDs (for KEV check)
    blast_radius        : how many of your repos depend on this package
    maintainer_responsiveness_label : 'fast'/'moderate'/'slow'/'very slow'/'unknown'
    worst_days_exposed  : worst patch lag in days (for urgency multiplier)
    """
    pkg = package_name or repo

    # Run all signals
    abandonment = score_abandonment(owner, repo)
    release     = score_release_anomaly(owner, repo)
    issues      = score_issue_stagnation(owner, repo)
    prs         = score_pr_stagnation(owner, repo)
    npm         = score_npm_ownership(pkg)

    resp_scores = {
        "fast": 0, "moderate": 25, "slow": 65,
        "very slow": 90, "unknown": 40,
        "insufficient release history": 40
    }
    resp_score = resp_scores.get(maintainer_responsiveness_label or "unknown", 40)

    # Weighted fragility (0-100)
    # npm ownership replaces 10% of the weight, responsiveness stays at 20%
    fragility = round(
        abandonment["score"] * 0.25 +
        release["score"]     * 0.20 +
        issues["score"]      * 0.15 +
        prs["score"]         * 0.10 +
        resp_score           * 0.20 +
        npm["score"]         * 0.10
    )

    # Multipliers
    lag_mult    = patch_lag_multiplier(worst_days_exposed)
    radius_mult = 1.0 + math.log(max(blast_radius, 1)) * 0.4

    # Final urgency (capped at 100)
    urgency = min(round(fragility * lag_mult * radius_mult), 100)

    # Verdict
    if urgency >= 80:   verdict = "CRITICAL — escalate now"
    elif urgency >= 60: verdict = "HIGH — plan remediation this week"
    elif urgency >= 40: verdict = "MEDIUM — monitor closely"
    elif urgency >= 20: verdict = "LOW — watch"
    else:               verdict = "HEALTHY"

    # KEV alert (standalone — shown as a flag, not baked into score)
    kev_hits = check_kev(cve_ids or [])

    # Pre-CVE flag: fragile but no known CVEs
    pre_cve = fragility >= 40 and not cve_ids

    return {
        "upstream_repo": f"{owner}/{repo}",
        "package_name": pkg,
        "fragility_score": fragility,
        "urgency_score": urgency,
        "verdict": verdict,
        "pre_cve_risk": pre_cve,
        "kev_hits": kev_hits,
        "kev_alert": len(kev_hits) > 0,
        "blast_radius_repos": blast_radius,
        "patch_lag_days": worst_days_exposed,
        "patch_lag_multiplier": lag_mult,
        "signals": {
            "abandonment":              abandonment,
            "release_anomaly":          release,
            "issue_stagnation":         issues,
            "pr_stagnation":            prs,
            "npm_ownership":            npm,
            "maintainer_responsiveness": {
                "label": maintainer_responsiveness_label or "unknown",
                "score": resp_score
            }
        }
    }


# ── Standalone test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    owner = sys.argv[1] if len(sys.argv) > 2 else "postcss"
    repo  = sys.argv[2] if len(sys.argv) > 2 else "postcss"

    print(f"Computing fragility for {owner}/{repo} ...\n")
    profile = compute_fragility(
        owner, repo,
        package_name=repo,
        cve_ids=["CVE-2023-44270"],
        blast_radius=3,
        maintainer_responsiveness_label="fast",
        worst_days_exposed=970
    )

    print(f"Fragility Score       : {profile['fragility_score']}/100")
    print(f"Urgency Score         : {profile['urgency_score']}/100")
    print(f"Verdict               : {profile['verdict']}")
    print(f"Pre-CVE Risk          : {profile['pre_cve_risk']}")
    print(f"KEV Alert             : {profile['kev_alert']} ({len(profile['kev_hits'])} hits)")
    print(f"Patch Lag Multiplier  : {profile['patch_lag_multiplier']}x")
    print(f"Blast Radius          : {profile['blast_radius_repos']} repo(s)")
    print()
    for name, sig in profile["signals"].items():
        if isinstance(sig, dict) and "score" in sig:
            print(f"  {name:30s} score={sig['score']:3d}  "
                  f"{sig.get('explanation', sig.get('label',''))}")
