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

import argparse
import json
import re
import sys
from datetime import datetime, timezone

from coral_utils import (
    is_exact_version,
    package_priority_tier,
    parse_sbom,
    prioritize_packages,
    run_coral,
    run_coral_parallel,
)


def _sql(value):
    return str(value).replace("'", "''")


def days_since(iso_date):
    """
    Given an ISO date string like '2024-05-14T18:30:54Z', return whole days
    from then until now. Returns None if the date can't be parsed.
    """
    if not iso_date:
        return None
    try:
        cleaned = iso_date.replace("Z", "+00:00")
        published = datetime.fromisoformat(cleaned)
        now = datetime.now(timezone.utc)
        return (now - published).days
    except ValueError:
        return None


def _version_tuple(version):
    if not version:
        return None
    match = re.search(r"\d+(?:\.\d+){0,3}", str(version))
    if not match:
        return None
    parts = [int(part) for part in match.group(0).split(".")]
    return tuple(parts + [0] * (4 - len(parts)))


def fixed_version_from_affected(affected_raw, installed_version=None):
    """
    Dig the closest usable FIXED version out of OSV's `affected` data.

    Prefer a fix above the installed version in the same major line. If none
    exists, return the lowest available fixed version.
    """
    if not affected_raw:
        return None
    try:
        affected = json.loads(affected_raw)
    except (json.JSONDecodeError, TypeError):
        return None

    fixes = []
    for entry in affected:
        for rng in entry.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    parsed = _version_tuple(event["fixed"])
                    if parsed:
                        fixes.append((parsed, event["fixed"]))
    if not fixes:
        return None

    fixes.sort(key=lambda item: item[0])
    installed = _version_tuple(installed_version)
    if installed:
        same_major = [
            item for item in fixes
            if item[0][0] == installed[0] and item[0] > installed
        ]
        if same_major:
            return same_major[0][1]
    return fixes[0][1]


def _chunked(items, size):
    for index in range(0, len(items), size):
        yield items[index:index + size]


def _parse_aliases(raw):
    if not raw:
        return []
    try:
        aliases = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return aliases if isinstance(aliases, list) else []


def _cve_ids_for_cves(cves):
    ids = set()
    for cve in cves:
        cve_id = cve.get("id")
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            ids.add(cve_id)
        for alias in _parse_aliases(cve.get("aliases")):
            if isinstance(alias, str) and alias.startswith("CVE-"):
                ids.add(alias)
    return sorted(ids)


def _kev_by_cve(cve_ids):
    if not cve_ids:
        return {}
    quoted = ", ".join(f"'{_sql(cve)}'" for cve in sorted(set(cve_ids)))
    query = (
        "SELECT cve_id, vendor_project, product, vulnerability_name, "
        "date_added, ransomware_use, required_action "
        "FROM kev.vulns "
        f"WHERE cve_id IN ({quoted})"
    )
    rows = run_coral(query)
    return {row.get("cve_id"): row for row in rows if row.get("cve_id")}


def _osv_select_for_package(pkg):
    name = pkg.get("name")
    version = pkg.get("version")
    ecosystem = pkg.get("osv_ecosystem")
    query_name = name.lower() if ecosystem == "PyPI" else name
    return (
        f"SELECT '{_sql(ecosystem)}' AS scan_ecosystem, "
        f"'{_sql(name)}' AS scan_package_name, "
        f"'{_sql(version)}' AS scan_version, "
        "id, aliases, summary, published, affected "
        "FROM osv.query_by_version "
        f"WHERE ecosystem='{_sql(ecosystem)}' "
        f"AND package_name='{_sql(query_name)}' "
        f"AND version='{_sql(version)}'"
    )


def scan_all_vulnerabilities(packages, max_packages=None, *, batch_size=10, workers=4):
    scan_packages = prioritize_packages(packages)
    if max_packages:
        scan_packages = scan_packages[:max_packages]
    queryable_packages = []
    skipped = 0
    for pkg in scan_packages:
        name = pkg.get("name")
        version = pkg.get("version")
        ecosystem = pkg.get("osv_ecosystem")
        if not ecosystem or not name or not is_exact_version(version):
            skipped += 1
            continue
        queryable_packages.append(pkg)

    batches = []
    for index, batch in enumerate(_chunked(queryable_packages, max(1, batch_size)), 1):
        query = " UNION ALL ".join(_osv_select_for_package(pkg) for pkg in batch)
        batches.append((query, {"index": index, "packages": batch}))

    cves_by_package = {}
    total_batches = len(batches)
    for metadata, rows in run_coral_parallel(batches, max_workers=max(1, workers)):
        batch_packages = metadata.get("packages", [])
        print(
            f"[{metadata.get('index', '?')}/{total_batches}] "
            f"OSV batch scanned {len(batch_packages)} package(s), "
            f"{len(rows)} advisory row(s)"
        )
        for row in rows:
            key = (
                row.get("scan_ecosystem"),
                row.get("scan_package_name"),
                row.get("scan_version"),
            )
            cves_by_package.setdefault(key, []).append(row)

    all_cve_ids = []
    for cves in cves_by_package.values():
        all_cve_ids.extend(_cve_ids_for_cves(cves))
    kev = _kev_by_cve(all_cve_ids)
    findings = []
    for pkg in queryable_packages:
        name = pkg.get("name")
        version = pkg.get("version")
        ecosystem = pkg.get("osv_ecosystem")
        cves = cves_by_package.get((ecosystem, name, version), [])

        if not cves:
            print(f"{name}@{version} ... ok")
            continue

        enriched_cves = []
        worst_lag = 0
        for cve in cves:
            exposed = days_since(cve.get("published"))
            fixed_in = fixed_version_from_affected(cve.get("affected"), version)
            cve_ids = _cve_ids_for_cves([cve])
            kev_hits = [kev[cve_id] for cve_id in cve_ids if cve_id in kev]
            enriched_cves.append({
                "id": cve.get("id"),
                "aliases": _parse_aliases(cve.get("aliases")),
                "summary": cve.get("summary"),
                "published": cve.get("published"),
                "days_exposed": exposed,
                "fixed_in": fixed_in,
                "kev": kev_hits,
            })
            if exposed and exposed > worst_lag:
                worst_lag = exposed

        print(f"{name}@{version} ... VULNERABLE -- {len(cves)} CVE(s), worst exposure {worst_lag} days")
        findings.append({
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "priority_tier": pkg.get("_priority_tier"),
            "purl": pkg.get("purl"),
            "worst_days_exposed": worst_lag,
            "cves": enriched_cves,
            "kev_hits": [
                hit for cve in enriched_cves for hit in cve.get("kev", [])
            ],
        })

    return findings, skipped, len(queryable_packages)


def write_scan_meta(owner, repo, *, total_packages, prioritized_count, scan_count,
                    skipped, vulnerable, max_packages, batch_size, workers):
    meta = {
        "repo": f"{owner}/{repo}",
        "mode": "fast_triage" if max_packages else "deep_scan",
        "scan_completed_at": datetime.now(timezone.utc).isoformat(),
        "sbom_packages_total": total_packages,
        "prioritized_packages_total": prioritized_count,
        "packages_scanned": scan_count,
        "skipped_packages": skipped,
        "vulnerable_packages": vulnerable,
        "max_packages": max_packages,
        "batch_size": batch_size,
        "workers": workers,
        "scan_strategy": "batched_union_osv",
        "stages": {
            "sbom": "complete",
            "osv": "complete",
            "kev": "complete",
            "epss": "on_demand_agent",
            "ownership": "on_demand_agent",
            "pre_cve": "deep_sweep_only",
        },
    }
    out_name = f"scan_meta_{owner}_{repo}.json"
    with open(out_name, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print(f"Saved scan metadata to {out_name}")


def main():
    parser = argparse.ArgumentParser(description="Scan a repo's SBOM for vulnerabilities + patch lag.")
    parser.add_argument("owner", help="GitHub owner, e.g. jellyfin")
    parser.add_argument("repo", help="GitHub repo, e.g. jellyfin-web")
    parser.add_argument("--limit", type=int, default=None,
                        help="Only scan the first N packages (useful for testing).")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="Ignored; scans are parallel now.")
    parser.add_argument("--max-packages", type=int, default=None,
                        help="Scan only the first N prioritized packages.")
    parser.add_argument("--batch-size", type=int, default=10,
                        help="Packages per generated UNION ALL OSV query.")
    parser.add_argument("--workers", type=int, default=4,
                        help="Parallel Coral batch workers.")
    args = parser.parse_args()

    print(f"Fetching SBOM for {args.owner}/{args.repo} ...")
    packages = parse_sbom(args.owner, args.repo)
    if isinstance(packages, dict) and packages.get("error") == "SBOM_UNAVAILABLE":
        print(f"SBOM_UNAVAILABLE: {packages.get('message')}")
        sys.exit(1)
    print(f"Found {len(packages)} packages.")

    if args.limit:
        packages = packages[:args.limit]
        print(f"Scanning only the first {len(packages)} (because --limit was set).")

    prioritized = prioritize_packages(packages)
    candidate_count = min(len(prioritized), args.max_packages) if args.max_packages else len(prioritized)
    tier_1 = sum(1 for pkg in prioritized if pkg.get("_priority_tier") == 1)
    tier_2 = sum(1 for pkg in prioritized if pkg.get("_priority_tier") == 2)
    tier_3 = sum(1 for pkg in prioritized if pkg.get("_priority_tier") == 3)
    tier_0 = sum(1 for pkg in packages if package_priority_tier(pkg) == 0)
    print(
        f"Scanning up to {candidate_count} prioritized packages "
        f"({tier_1} tier-1, {tier_2} tier-2, {tier_3} tier-3, {tier_0} skipped)"
    )

    findings, skipped_missing, scan_count = scan_all_vulnerabilities(
        packages,
        args.max_packages,
        batch_size=args.batch_size,
        workers=args.workers,
    )
    skipped = tier_0 + skipped_missing

    findings.sort(key=lambda f: f["worst_days_exposed"], reverse=True)

    print("\n" + "=" * 64)
    print(f"PATCH LAG REPORT: {args.owner}/{args.repo}")
    print(f"  Packages scanned : {scan_count}")
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
    write_scan_meta(
        args.owner,
        args.repo,
        total_packages=len(packages),
        prioritized_count=len(prioritized),
        scan_count=scan_count,
        skipped=skipped,
        vulnerable=len(findings),
        max_packages=args.max_packages,
        batch_size=args.batch_size,
        workers=args.workers,
    )


if __name__ == "__main__":
    main()
