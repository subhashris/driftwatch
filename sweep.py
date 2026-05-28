"""
sweep.py -- Pre-CVE Canary: Deprecated Version Sweep + Upgrade Actionability

Two features in one script, both using deps.dev:

FEATURE A: Deprecated Version Sweep
  Scans every dependency in your SBOM against deps.dev.
  Flags packages where ANY version was deprecated/yanked in the last N days
  with a security-related reason. These are packages where something went
  wrong BEFORE a CVE was filed. The dompurify 3.4.4 example is the proof:
  "Fixed a security issue introduced in 3.4.4" -- no CVE exists yet.
  This is your strongest pre-CVE signal.

FEATURE B: Upgrade Actionability Score
  For each vulnerable package, answers "how hard is it to actually fix this?"
  - SAFE: patch or minor version bump (e.g. 1.2.3 -> 1.2.9)
  - MODERATE: minor version bump across a larger gap
  - BREAKING: major version bump (e.g. 1.x -> 2.x, likely API changes)
  - NO_FIX: no fixed version listed in OSV
  Combined with "how many of your repos use this" = realistic remediation cost.
  Nobody computes this. Every security engineer needs it.

Usage:
  python sweep.py jellyfin jellyfin-web
  python sweep.py jellyfin jellyfin-web --days 60 --limit 200
"""

import subprocess
import json
import argparse
import time
import urllib.request
from datetime import datetime, timezone, timedelta


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


def get_packages(owner, repo, limit=None):
    """Fetch all packages from SBOM."""
    query = (
        "SELECT "
        "json_get_str(pkg,'name') AS name, "
        "json_get_str(pkg,'versionInfo') AS version, "
        "json_get_str(json_get(pkg,'externalRefs',0),'referenceLocator') AS purl "
        "FROM (SELECT unnest(json_get_array(sbom__packages)) AS pkg "
        f"FROM github.sbom WHERE owner='{owner}' AND repo='{repo}')"
    )
    if limit:
        query += f" LIMIT {limit}"
    return run_coral(query)


def ecosystem_from_purl(purl):
    """Map PURL type to deps.dev system name."""
    if not purl or not purl.startswith("pkg:"):
        return None
    purl_type = purl[4:].split("/", 1)[0].lower()
    mapping = {
        "npm": "NPM",
        "pypi": "PYPI",
        "maven": "MAVEN",
        "cargo": "CARGO",
        "golang": "GO",
    }
    return mapping.get(purl_type)


def get_depsdev_versions(system, package_name):
    """Get all versions from deps.dev for a package."""
    safe_name = package_name.replace("'", "''")
    return run_coral(
        "SELECT version, published_at, is_deprecated, deprecated_reason "
        "FROM depsdev.package_versions "
        f"WHERE system='{system}' AND package_name='{safe_name}'"
    )


# ── SECURITY-RELATED DEPRECATION KEYWORDS ───────────────────────────────────
# These keywords in a deprecation reason suggest a security issue
def scan_ecosystem_to_depsdev(system):
    """Map scan.py ecosystem names to deps.dev system names."""
    if not system:
        return None
    mapping = {
        "npm": "NPM",
        "pypi": "PYPI",
        "maven": "MAVEN",
        "cargo": "CARGO",
        "golang": "GO",
        "go": "GO",
    }
    return mapping.get(str(system).lower(), str(system).upper())


SECURITY_KEYWORDS = [
    "security", "vulnerability", "vuln", "cve", "exploit", "injection",
    "xss", "csrf", "rce", "attack", "malicious", "compromise", "breach",
    "unsafe", "dangerous", "critical", "fix", "patch", "issue introduced"
]

def is_security_related(reason):
    """Check if a deprecation reason is security-related."""
    if not reason:
        return False
    reason_lower = reason.lower()
    return any(kw in reason_lower for kw in SECURITY_KEYWORDS)


# ── SEMVER UTILITIES ─────────────────────────────────────────────────────────

def parse_semver(version_str):
    """Parse a version string into (major, minor, patch) tuple. Returns None if unparseable."""
    if not version_str:
        return None
    # Strip common prefixes
    v = version_str.lstrip("v=~^")
    # Take only the first version if it's a range
    v = v.split(" ")[0].split(",")[0].split(";")[0]
    parts = v.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2].split("-")[0].split("+")[0]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return None


def upgrade_actionability(current_version, fixed_version):
    """
    Classify how hard it is to upgrade from current to fixed version.
    Returns (label, explanation) tuple.
    """
    if not fixed_version:
        return ("NO_FIX", "No fix version available in OSV — mitigate or pin")

    current = parse_semver(current_version)
    fixed = parse_semver(fixed_version)

    if not current or not fixed:
        return ("UNKNOWN", f"Cannot parse versions: {current_version} -> {fixed_version}")

    curr_major, curr_minor, curr_patch = current
    fix_major, fix_minor, fix_patch = fixed

    if fix_major > curr_major:
        gap = fix_major - curr_major
        return (
            "BREAKING",
            f"Major version bump: {current_version} → {fixed_version} "
            f"({gap} major version{'s' if gap > 1 else ''} — likely breaking API changes, "
            f"requires migration planning)"
        )
    elif fix_minor > curr_minor:
        gap = fix_minor - curr_minor
        if gap > 5:
            return (
                "MODERATE",
                f"Large minor version gap: {current_version} → {fixed_version} "
                f"({gap} minor versions — review changelog before upgrading)"
            )
        return (
            "SAFE",
            f"Minor version bump: {current_version} → {fixed_version} "
            f"(low risk — upgrade recommended immediately)"
        )
    elif fix_patch > curr_patch:
        return (
            "SAFE",
            f"Patch version bump: {current_version} → {fixed_version} "
            f"(safe to upgrade — do it now)"
        )
    else:
        return (
            "UNKNOWN",
            f"Cannot determine direction: {current_version} → {fixed_version}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Pre-CVE deprecated version sweep + upgrade actionability")
    parser.add_argument("owner", help="GitHub owner")
    parser.add_argument("repo", help="GitHub repo")
    parser.add_argument("--days", type=int, default=90,
                        help="Flag deprecations within this many days (default 90)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit packages scanned (for testing)")
    parser.add_argument("--scan-json", type=str, default=None,
                        help="Path to existing scan_*.json for upgrade actionability")
    parser.add_argument("--delay", type=float, default=0.1)
    args = parser.parse_args()

    print(f"\n{'='*64}")
    print(f"UPSTREAM RISK RADAR — Pre-CVE Canary Sweep")
    print(f"Repo: {args.owner}/{args.repo}")
    print(f"Deprecation window: last {args.days} days")
    print(f"{'='*64}\n")

    # ── FETCH SBOM ───────────────────────────────────────────────────────────
    print("Fetching SBOM packages...")
    packages = get_packages(args.owner, args.repo, args.limit)
    print(f"Found {len(packages)} packages to scan.\n")

    # ── FEATURE A: DEPRECATED VERSION SWEEP ─────────────────────────────────
    print(f"{'─'*64}")
    print(f"FEATURE A: Pre-CVE Canary — Deprecated Version Sweep")
    print(f"Scanning for versions deprecated in the last {args.days} days...")
    print(f"{'─'*64}")

    pre_cve_findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)

    for i, pkg in enumerate(packages, 1):
        name = pkg.get("name")
        version = pkg.get("version")
        purl = pkg.get("purl")
        system = ecosystem_from_purl(purl)

        if not system or not name or not version:
            continue

        print(f"[{i}/{len(packages)}] {name}@{version} ...", end=" ", flush=True)

        versions = get_depsdev_versions(system, name)
        if not versions:
            print("no data")
            time.sleep(args.delay)
            continue

        # Check for recently deprecated versions
        recent_deprecations = []
        for v in versions:
            if not v.get("is_deprecated"):
                continue
            pub_date = v.get("published_at")
            if not pub_date:
                continue
            try:
                dt = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
                if dt >= cutoff:
                    recent_deprecations.append({
                        "version": v.get("version"),
                        "published_at": pub_date,
                        "days_ago": days_ago(pub_date),
                        "reason": v.get("deprecated_reason", ""),
                        "security_related": is_security_related(
                            v.get("deprecated_reason", ""))
                    })
            except ValueError:
                pass

        if recent_deprecations:
            security_hits = [d for d in recent_deprecations if d["security_related"]]
            if security_hits:
                print(f"⚠️  PRE-CVE SIGNAL — {len(security_hits)} security deprecation(s)")
            else:
                print(f"📦 {len(recent_deprecations)} deprecation(s) (non-security)")
            pre_cve_findings.append({
                "name": name,
                "installed_version": version,
                "system": system,
                "deprecations": recent_deprecations,
                "has_security_deprecation": len(security_hits) > 0,
                "security_deprecations": security_hits
            })
        else:
            print("clean")

        time.sleep(args.delay)

    # ── FEATURE B: UPGRADE ACTIONABILITY ────────────────────────────────────
    upgrade_findings = []
    if args.scan_json:
        print(f"\n{'─'*64}")
        print(f"FEATURE B: Upgrade Actionability Score")
        print(f"Reading from: {args.scan_json}")
        print(f"{'─'*64}")
        try:
            with open(args.scan_json, encoding="utf-8") as f:
                scan_data = json.load(f)

            version_cache = {}
            for finding in scan_data:
                name = finding.get("name")
                version = finding.get("version")
                system = scan_ecosystem_to_depsdev(finding.get("ecosystem"))
                versions = []
                if system:
                    cache_key = (system, name)
                    if cache_key not in version_cache:
                        version_cache[cache_key] = get_depsdev_versions(system, name)
                        time.sleep(args.delay)
                    versions = version_cache[cache_key]
                for cve in finding.get("cves", []):
                    fixed_in = cve.get("fixed_in")
                    label, explanation = upgrade_actionability(version, fixed_in)
                    days_exposed = cve.get("days_exposed", 0)
                    fix_row = next((v for v in versions if v.get("version") == fixed_in), {})
                    upgrade_findings.append({
                        "name": name,
                        "current_version": version,
                        "fixed_version": fixed_in,
                        "published_at": fix_row.get("published_at"),
                        "fix_published_at": fix_row.get("published_at"),
                        "cve_id": cve.get("id"),
                        "days_exposed": days_exposed,
                        "actionability": label,
                        "explanation": explanation
                    })
        except FileNotFoundError:
            print(f"  File not found: {args.scan_json}")

    # ── REPORT ───────────────────────────────────────────────────────────────
    print(f"\n{'='*64}")
    print(f"PRE-CVE CANARY REPORT: {args.owner}/{args.repo}")
    print(f"{'='*64}")

    security_findings = [f for f in pre_cve_findings if f["has_security_deprecation"]]
    other_findings = [f for f in pre_cve_findings if not f["has_security_deprecation"]]

    print(f"\n  Packages scanned        : {len(packages)}")
    print(f"  Security deprecations   : {len(security_findings)}  ← PRE-CVE SIGNALS")
    print(f"  Other deprecations      : {len(other_findings)}")

    if security_findings:
        print(f"\n{'─'*64}")
        print("⚠️  SECURITY DEPRECATIONS (PRE-CVE SIGNALS) — Act immediately")
        print(f"{'─'*64}")
        for f in security_findings:
            print(f"\n  📦 {f['name']}@{f['installed_version']} ({f['system']})")
            for d in f["security_deprecations"]:
                print(f"     Version {d['version']} deprecated {d['days_ago']} days ago")
                print(f"     Reason : \"{d['reason']}\"")
                print(f"     ⚡ No CVE filed yet — this is your early warning")

    if other_findings:
        print(f"\n{'─'*64}")
        print("📦 OTHER RECENT DEPRECATIONS (monitor)")
        print(f"{'─'*64}")
        for f in other_findings:
            print(f"\n  {f['name']}@{f['installed_version']}")
            for d in f["deprecations"]:
                reason = d['reason'] or "no reason given"
                print(f"     v{d['version']}: {reason[:80]}")

    if upgrade_findings:
        print(f"\n{'─'*64}")
        print("FEATURE B: UPGRADE ACTIONABILITY")
        print(f"{'─'*64}")

        # Group by actionability
        for label, emoji in [("SAFE", "✅"), ("MODERATE", "⚠️"),
                              ("BREAKING", "🔴"), ("NO_FIX", "⛔"), ("UNKNOWN", "❓")]:
            group = [u for u in upgrade_findings if u["actionability"] == label]
            if not group:
                continue
            print(f"\n  {emoji} {label} ({len(group)} finding{'s' if len(group)>1 else ''})")
            for u in sorted(group, key=lambda x: x.get("days_exposed", 0), reverse=True):
                print(f"     {u['name']} {u['current_version']} → {u.get('fixed_version','?')}")
                print(f"       {u['explanation']}")
                print(f"       Exposed: {u['days_exposed']} days | CVE: {u['cve_id']}")

    # Save results
    out = {
        "repo": f"{args.owner}/{args.repo}",
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "pre_cve_findings": pre_cve_findings,
        "upgrade_actionability": upgrade_findings
    }
    out_name = f"sweep_{args.owner}_{args.repo}.json"
    with open(out_name, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nSaved to {out_name}")


if __name__ == "__main__":
    main()
