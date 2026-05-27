"""
ownership.py -- Dependency Ownership Map

Answers the security engineer's most operationally painful question:
"I found a vulnerable dependency. Who in my org do I talk to?"

Strategy:
  1. Find files that reference the package (code search)
  2. Find who committed mentioning the package name (commit search)
  3. Cross-reference with top repo contributors
  4. Output: ranked owner list + copy-paste ticket text

This is a cross-source join (github.search_code x github.search_commits
x github.repo_contributors) that no commercial tool does automatically.
"""

import subprocess
import json
import argparse
import time
from collections import defaultdict


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


def find_files_using_package(owner, repo, package_name):
    """Find files in the repo that reference this package."""
    # Use bare package name (strip scope for broader search)
    search_name = package_name.split("/")[-1] if "/" in package_name else package_name
    query = (
        f"SELECT name, path, html_url FROM github.search_code("
        f"q => 'repo:{owner}/{repo} {search_name}') LIMIT 8"
    )
    return run_coral(query)


def find_committers_for_package(owner, repo, package_name):
    """
    Find who has committed mentioning this package.
    More reliable than file-path search for config files.
    """
    search_name = package_name.split("/")[-1] if "/" in package_name else package_name
    # Search commits that mention this package name
    query = (
        f"SELECT author_login, message FROM github.search_commits("
        f"q => 'repo:{owner}/{repo} {search_name}') LIMIT 10"
    )
    results = run_coral(query)

    # Also try package.json specifically (always relevant for npm deps)
    query2 = (
        f"SELECT author_login, message FROM github.search_commits("
        f"q => 'repo:{owner}/{repo} path:package.json') LIMIT 5"
    )
    pkg_json_results = run_coral(query2)

    # Combine, dedup by login
    all_results = results + pkg_json_results
    seen = set()
    unique = []
    for r in all_results:
        login = r.get("author_login")
        if login and login not in seen:
            seen.add(login)
            unique.append(r)
    return unique


def get_top_contributors(owner, repo):
    """Get top contributors for cross-reference."""
    return run_coral(
        "SELECT login, contributions FROM github.repo_contributors "
        f"WHERE owner='{owner}' AND repo='{repo}' "
        "ORDER BY contributions DESC LIMIT 20"
    )


def build_ticket_text(package_name, current_version, worst_exposure,
                       actionability, fixed_version, owners, files):
    """Generate a paste-ready ticket description."""
    owner_str = ", ".join(owners) if owners else "owner unknown — check git log"
    file_str = ", ".join(files[:2]) if files else "see package.json"
    action_map = {
        "SAFE": f"Safe to upgrade: bump {package_name} from {current_version} to {fixed_version}. Low risk, do it this sprint.",
        "BREAKING": f"Major version upgrade required: {package_name} {current_version} → {fixed_version}. Plan migration — breaking API changes likely.",
        "MODERATE": f"Upgrade {package_name} from {current_version} to {fixed_version}. Review changelog before applying.",
        "NO_FIX": f"No fix available for {package_name} {current_version}. Consider alternatives or apply mitigations.",
        "UNKNOWN": f"Upgrade {package_name} from {current_version} to {fixed_version}.",
    }
    action = action_map.get(actionability, action_map["UNKNOWN"])
    return (
        f"[SECURITY] Vulnerable dependency: {package_name}@{current_version}\n"
        f"Exposed: {worst_exposure} days with fix available in {fixed_version or 'unknown'}\n"
        f"Action: {action}\n"
        f"Files: {file_str}\n"
        f"Recommended owner(s): {owner_str}"
    )


def main():
    parser = argparse.ArgumentParser(description="Dependency ownership map")
    parser.add_argument("owner", help="GitHub owner")
    parser.add_argument("repo", help="GitHub repo")
    parser.add_argument("--scan-json", required=True,
                        help="Path to scan_*.json with vulnerable packages")
    parser.add_argument("--delay", type=float, default=0.3)
    args = parser.parse_args()

    print(f"\n{'='*64}")
    print(f"UPSTREAM RISK RADAR — Dependency Ownership Map")
    print(f"Repo: {args.owner}/{args.repo}")
    print(f"{'='*64}\n")

    # Load scan results
    try:
        with open(args.scan_json, encoding="utf-8") as f:
            scan_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {args.scan_json} not found.")
        return

    # Deduplicate by package name, keep worst CVE info
    unique_packages = {}
    for finding in scan_data:
        name = finding.get("name")
        if not name or name in unique_packages:
            continue
        worst = max(
            finding.get("cves", []),
            key=lambda c: c.get("days_exposed", 0),
            default={}
        )
        unique_packages[name] = {
            "name": name,
            "version": finding.get("version"),
            "worst_days": worst.get("days_exposed", 0),
            "fixed_in": worst.get("fixed_in"),
            "cve_id": worst.get("id"),
        }

    print(f"Mapping ownership for {len(unique_packages)} vulnerable package(s)...\n")

    # Get contributors once
    print("Fetching repo contributors...")
    contributors = get_top_contributors(args.owner, args.repo)
    top_logins = {c["login"] for c in contributors[:10]}
    print(f"Found {len(contributors)} contributors.\n")

    results = []

    for pkg_info in sorted(unique_packages.values(),
                           key=lambda x: x["worst_days"], reverse=True):
        name = pkg_info["name"]
        version = pkg_info["version"]
        worst_days = pkg_info["worst_days"]
        fixed_in = pkg_info["fixed_in"]

        print(f"  {name}@{version} ({worst_days}d exposure)...", end=" ", flush=True)

        # Find files
        files = find_files_using_package(args.owner, args.repo, name)
        time.sleep(args.delay)

        # Find committers
        committers = find_committers_for_package(args.owner, args.repo, name)
        time.sleep(args.delay)

        # Rank owners: prefer top contributors
        owner_counts = defaultdict(int)
        for c in committers:
            login = c.get("author_login")
            if login:
                # Boost score if they're a top contributor
                owner_counts[login] += 2 if login in top_logins else 1

        ranked = sorted(owner_counts.items(), key=lambda x: x[1], reverse=True)
        top_owners = [login for login, _ in ranked[:3]]

        if top_owners:
            print(f"→ {', '.join('@' + o for o in top_owners)}")
        else:
            print("→ owner not found")

        file_paths = [f.get("path", "") for f in files[:3]]

        # Determine actionability (simplified — sweep.py has full version)
        from sweep import upgrade_actionability
        actionability, _ = upgrade_actionability(version, fixed_in)

        ticket = build_ticket_text(
            name, version, worst_days,
            actionability, fixed_in, top_owners, file_paths
        )

        results.append({
            "package": name,
            "version": version,
            "worst_days_exposed": worst_days,
            "fixed_in": fixed_in,
            "actionability": actionability,
            "files": file_paths,
            "owners": top_owners,
            "ticket_text": ticket,
        })

    # Report
    print(f"\n{'='*64}")
    print(f"OWNERSHIP MAP — {args.owner}/{args.repo}")
    print(f"{'='*64}\n")

    owned = [r for r in results if r["owners"]]
    unowned = [r for r in results if not r["owners"]]

    print(f"  Ownership identified: {len(owned)}/{len(results)} packages\n")

    for r in owned:
        print(f"  📦 {r['package']}@{r['version']}  ({r['worst_days_exposed']}d | {r['actionability']})")
        print(f"     Owner(s): {', '.join('@' + o for o in r['owners'])}")
        if r["files"]:
            print(f"     Files   : {', '.join(r['files'][:2])}")
        print(f"     Ticket  ↓")
        for line in r["ticket_text"].split("\n"):
            print(f"       {line}")
        print()

    if unowned:
        print(f"  No owner found:")
        for r in unowned:
            print(f"     {r['package']} — check git log manually")

    # Save
    out_name = f"ownership_{args.owner}_{args.repo}.json"
    with open(out_name, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nSaved to {out_name}")


if __name__ == "__main__":
    main()
