"""
scan.py  --  Supply-chain vulnerability scanner with PATCH LAG (Option A)

New in this version (vs the basic scanner):
  * For every CVE we now also pull `published` (when the CVE went public).
  * We compute "days exposed" = today - published date.
  * We dig into OSV's `affected` data to find the FIXED version, so we can say
    "a fix has existed in version X this whole time."

Definition of patch lag we use (the honest one):
  days_exposed = today - CVE.published
  This is always available and unambiguous. We ALSO report the fix version
  when OSV lists one, but we never guess if it's missing.

Usage (from PowerShell):
    python scan.py jellyfin jellyfin-web --limit 150
    python scan.py jellyfin jellyfin-web              (scans everything)
"""

import subprocess
import json
import time
import argparse
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


def get_packages(owner, repo):
    """Fetch all packages from the repo's SBOM as {name, version, purl}."""
    query = (
        "SELECT "
        "json_get_str(pkg,'name') AS name, "
        "json_get_str(pkg,'versionInfo') AS version, "
        "json_get_str(json_get(pkg,'externalRefs',0),'referenceLocator') AS purl "
        "FROM (SELECT unnest(json_get_array(sbom__packages)) AS pkg "
        f"FROM github.sbom WHERE owner='{owner}' AND repo='{repo}')"
    )
    return run_coral(query)


PURL_TYPE_TO_OSV_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "golang": "Go",
    "maven": "Maven",
    "composer": "Packagist",
    "nuget": "NuGet",
}


def ecosystem_from_purl(purl):
    """Turn 'pkg:npm/lodash@1.0.0' into OSV ecosystem 'npm'. None if unknown."""
    if not purl or not purl.startswith("pkg:"):
        return None
    purl_type = purl[4:].split("/", 1)[0].lower()
    return PURL_TYPE_TO_OSV_ECOSYSTEM.get(purl_type)


def check_vulnerability(ecosystem, name, version):
    """
    Ask OSV about one package-version.
    Now also pulls `published` and `affected` (for the fix version).
    Returns a list of CVE dicts: {id, summary, published, affected}.
    """
    safe_name = name.replace("'", "''")
    safe_version = version.replace("'", "''")
    query = (
        "SELECT id, summary, published, affected "
        "FROM osv.query_by_version "
        f"WHERE ecosystem='{ecosystem}' "
        f"AND package_name='{safe_name}' "
        f"AND version='{safe_version}'"
    )
    return run_coral(query)


def days_since(iso_date):
    """
    Given an ISO date string like '2024-05-14T18:30:54Z', return whole days
    from then until now. Returns None if the date can't be parsed.
    """
    if not iso_date:
        return None
    try:
        # Python's fromisoformat doesn't like a trailing 'Z', so swap it for +00:00
        cleaned = iso_date.replace("Z", "+00:00")
        published = datetime.fromisoformat(cleaned)
        now = datetime.now(timezone.utc)
        return (now - published).days
    except ValueError:
        return None


def fixed_version_from_affected(affected_raw):
    """
    Dig the FIXED version out of OSV's `affected` data.

    `affected_raw` is a JSON *string* that looks like:
      [{"package":{...},"ranges":[{"type":"SEMVER","events":[
          {"introduced":"0"},{"fixed":"3.0.3"}]}], ...}]

    We walk through it defensively and return the first 'fixed' version we find,
    or None if no fix is listed (some CVEs genuinely have no fix yet).
    """
    if not affected_raw:
        return None
    try:
        affected = json.loads(affected_raw)
    except (json.JSONDecodeError, TypeError):
        return None

    for entry in affected:
        for rng in entry.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def main():
    parser = argparse.ArgumentParser(description="Scan a repo's SBOM for vulnerabilities + patch lag.")
    parser.add_argument("owner", help="GitHub owner, e.g. jellyfin")
    parser.add_argument("repo", help="GitHub repo, e.g. jellyfin-web")
    parser.add_argument("--limit", type=int, default=None,
                        help="Only scan the first N packages (useful for testing).")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="Seconds to wait between OSV calls (default 0.2).")
    args = parser.parse_args()

    print(f"Fetching SBOM for {args.owner}/{args.repo} ...")
    packages = get_packages(args.owner, args.repo)
    print(f"Found {len(packages)} packages.")

    if args.limit:
        packages = packages[:args.limit]
        print(f"Scanning only the first {len(packages)} (because --limit was set).")

    findings = []   # one entry per vulnerable package
    skipped = 0

    for i, pkg in enumerate(packages, start=1):
        name = pkg.get("name")
        version = pkg.get("version")
        ecosystem = ecosystem_from_purl(pkg.get("purl"))

        print(f"[{i}/{len(packages)}] {name}@{version} ...", end=" ")

        if not ecosystem or not name or not version:
            print("skipped")
            skipped += 1
            continue

        cves = check_vulnerability(ecosystem, name, version)
        if not cves:
            print("ok")
            time.sleep(args.delay)
            continue

        # Enrich each CVE with patch-lag info.
        enriched_cves = []
        worst_lag = 0   # track the longest exposure for this package
        for cve in cves:
            exposed = days_since(cve.get("published"))
            fixed_in = fixed_version_from_affected(cve.get("affected"))
            enriched_cves.append({
                "id": cve.get("id"),
                "summary": cve.get("summary"),
                "published": cve.get("published"),
                "days_exposed": exposed,
                "fixed_in": fixed_in,
            })
            if exposed and exposed > worst_lag:
                worst_lag = exposed

        print(f"VULNERABLE -- {len(cves)} CVE(s), worst exposure {worst_lag} days")
        findings.append({
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "worst_days_exposed": worst_lag,
            "cves": enriched_cves,
        })
        time.sleep(args.delay)

    # ----- report, sorted by worst exposure (most urgent first) -----
    findings.sort(key=lambda f: f["worst_days_exposed"], reverse=True)

    print("\n" + "=" * 64)
    print(f"PATCH LAG REPORT: {args.owner}/{args.repo}")
    print(f"  Packages scanned : {len(packages)}")
    print(f"  Skipped          : {skipped}")
    print(f"  Vulnerable       : {len(findings)}")
    print("=" * 64)

    for f in findings:
        print(f"\n  {f['name']}@{f['version']}  -- exposed up to {f['worst_days_exposed']} days")
        for cve in f["cves"]:
            fix = f"fix in {cve['fixed_in']}" if cve["fixed_in"] else "no fix listed"
            exposed = cve["days_exposed"] if cve["days_exposed"] is not None else "?"
            print(f"     - {cve['id']}: {exposed} days exposed, {fix}")
            print(f"         {cve['summary']}")

    out_name = f"scan_{args.owner}_{args.repo}.json"
    with open(out_name, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    print(f"\nSaved detailed results to {out_name}")


if __name__ == "__main__":
    main()