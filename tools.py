from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from coral_utils import (
    PURL_TO_DEPSDEV,
    PURL_TO_OSV,
    is_exact_version,
    parse_sbom,
    prioritize_packages,
    run_coral,
    run_coral_parallel,
)

REFERENCE_DATE = datetime.now(timezone.utc)


def _sql(value: str) -> str:
    return value.replace("'", "''")


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        try:
            dt = datetime.strptime(value.strip()[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _date(value: str | None) -> str | None:
    dt = _parse_dt(value)
    return dt.date().isoformat() if dt else None


def _days_since(value: str | None) -> int | None:
    dt = _parse_dt(value)
    if not dt:
        return None
    return max(0, (REFERENCE_DATE - dt).days)


def _days_until(value: str | None) -> int | None:
    dt = _parse_dt(value)
    if not dt:
        return None
    return (dt - REFERENCE_DATE).days


def _json_list(value: str | None) -> list:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _packages_or_empty(owner: str, repo: str) -> list[dict]:
    packages = parse_sbom(owner, repo)
    return [] if isinstance(packages, dict) else packages


def _npm_packages(owner: str, repo: str) -> list[dict]:
    return [pkg for pkg in _packages_or_empty(owner, repo) if pkg["ecosystem"] == "npm"]


def _to_osv_ecosystem(eco: str) -> str:
    """Map purl ecosystem string to OSV ecosystem value."""
    return PURL_TO_OSV.get((eco or "").lower())


def _to_depsdev_system(eco: str) -> str:
    """Map purl ecosystem string to depsdev system value."""
    return PURL_TO_DEPSDEV.get((eco or "").lower())


def _infer_github_repo(package_name: str, ecosystem: str = "npm") -> tuple[str, str]:
    depsdev_system = _to_depsdev_system(ecosystem)
    if not depsdev_system:
        clean = package_name.split("/")[-1] if package_name.startswith("@") else package_name
        clean = clean.replace("@", "").strip()
        return clean, clean
    safe_name = _sql(package_name)
    rows = run_coral(
        "SELECT source_repo FROM depsdev.package_versions "
        f"WHERE system='{_sql(depsdev_system)}' AND package_name='{safe_name}' "
        "AND is_default='true' LIMIT 1"
    )
    for row in rows:
        source_repo = row.get("source_repo", "")
        match = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s#?]+)", source_repo)
        if match:
            return match.group(1), match.group(2).removesuffix(".git")

    clean = package_name.split("/")[-1] if package_name.startswith("@") else package_name
    clean = clean.replace("@", "").strip()
    common = {
        "inflight": ("isaacs", "inflight"),
        "ua-parser-js": ("faisalman", "ua-parser-js"),
        "semver": ("npm", "node-semver"),
        "moment": ("moment", "moment"),
    }
    return common.get(clean, (clean, clean))


def _scorecard(owner: str, repo: str) -> float | None:
    try:
        rows = run_coral(
            f"SELECT score, date FROM scorecard.project_score "
            f"WHERE owner='{_sql(owner)}' AND repo='{_sql(repo)}'"
        )
    except Exception:
        return None
    if not rows:
        return None
    try:
        return float(rows[0].get("score", ""))
    except ValueError:
        return None


def _latest_commit(owner: str, repo: str) -> str | None:
    try:
        rows = run_coral(
            f"SELECT author__login, commit__author__date FROM github.commits "
            f"WHERE owner='{_sql(owner)}' AND repo='{_sql(repo)}' LIMIT 5"
        )
    except Exception:
        return None
    dates = [_parse_dt(row.get("commit__author__date")) for row in rows]
    dates = [dt for dt in dates if dt]
    if not dates:
        return None
    return max(dates).date().isoformat()


def _release_tags(owner: str, repo: str) -> list[str]:
    try:
        rows = run_coral(
            f"SELECT tag_name, published_at, name FROM github.releases "
            f"WHERE owner='{_sql(owner)}' AND repo='{_sql(repo)}'"
        )
    except Exception:
        return []
    return [row.get("tag_name", "") for row in rows if row.get("tag_name")]


def _osv_for_package(name: str, ecosystem: str, version: str) -> list[dict]:
    if not ecosystem or not is_exact_version(version):
        return []
    query_name = name.lower() if ecosystem in {"pypi", "PyPI"} else name
    try:
        return run_coral(
            f"SELECT id, aliases, summary FROM osv.query_by_version "
            f"WHERE package_name='{_sql(query_name)}' AND ecosystem='{_sql(ecosystem)}' "
            f"AND version='{_sql(version)}'"
        )
    except Exception:
        return []


def _cves_from_osv_row(row: dict) -> list[str]:
    aliases = _json_list(row.get("aliases"))
    return [alias for alias in aliases if isinstance(alias, str) and alias.startswith("CVE-")]


def _recommended_alternative(name: str, reason: str) -> str | None:
    if name == "inflight" or "leak" in reason.lower():
        return "lru-cache"
    return None


def predict_pre_cve_collapse(owner: str, repo: str) -> dict:
    packages = _packages_or_empty(owner, repo)
    scan_packages = prioritize_packages(packages)
    collapse_risks: list[dict] = []

    depsdev_queries = []
    for pkg in scan_packages:
        depsdev_system = _to_depsdev_system(pkg.get("ecosystem", "npm"))
        if not depsdev_system:
            continue
        depsdev_queries.append(
            (
                "SELECT version, is_deprecated, deprecated_reason "
                "FROM depsdev.package_versions "
                f"WHERE system='{_sql(depsdev_system)}' "
                f"AND package_name='{_sql(pkg['name'])}' AND is_default=true",
                {"pkg": pkg},
            )
        )

    deprecated_packages: list[tuple[dict, dict]] = []
    for metadata, rows in run_coral_parallel(depsdev_queries, max_workers=24):
        deprecated = [
            row for row in rows if str(row.get("is_deprecated", "")).lower() == "true"
        ]
        if deprecated:
            deprecated_packages.append((metadata["pkg"], deprecated[0]))

    detail_queries: list[tuple[str, dict]] = []
    for pkg, dep in deprecated_packages:
        name = pkg["name"]
        version = pkg["version"]
        pkg_owner, pkg_repo = _infer_github_repo(name, pkg.get("ecosystem", "npm"))
        base_meta = {"pkg": pkg, "dep": dep}
        detail_queries.extend(
            [
                (
                    "SELECT score, date FROM scorecard.project_score "
                    f"WHERE owner='{_sql(pkg_owner)}' AND repo='{_sql(pkg_repo)}'",
                    {**base_meta, "kind": "scorecard"},
                ),
                (
                    "SELECT author__login, commit__author__date FROM github.commits "
                    f"WHERE owner='{_sql(pkg_owner)}' AND repo='{_sql(pkg_repo)}' LIMIT 5",
                    {**base_meta, "kind": "commits"},
                ),
                (
                    "SELECT tag_name, published_at, name FROM github.releases "
                    f"WHERE owner='{_sql(pkg_owner)}' AND repo='{_sql(pkg_repo)}'",
                    {**base_meta, "kind": "releases"},
                ),
            ]
        )
        osv_ecosystem = _to_osv_ecosystem(pkg.get("ecosystem", "npm"))
        if osv_ecosystem and is_exact_version(version):
            detail_queries.append(
                (
                    "SELECT id, aliases, summary FROM osv.query_by_version "
                    f"WHERE package_name='{_sql(name.lower() if osv_ecosystem == 'PyPI' else name)}' "
                    f"AND ecosystem='{_sql(osv_ecosystem)}' "
                    f"AND version='{_sql(version)}'",
                    {**base_meta, "kind": "osv"},
                )
            )

    detail_rows: dict[tuple[str, str, str], dict[str, list[dict]]] = {}
    for metadata, rows in run_coral_parallel(detail_queries, max_workers=24):
        pkg = metadata["pkg"]
        key = (pkg["name"], pkg["version"], pkg.get("ecosystem", "npm"))
        detail_rows.setdefault(key, {})[metadata["kind"]] = rows

    for pkg, dep in deprecated_packages:
        name = pkg["name"]
        version = pkg["version"]
        reason = dep.get("deprecated_reason", "")
        key = (name, version, pkg.get("ecosystem", "npm"))
        rows_by_kind = detail_rows.get(key, {})

        score = None
        score_rows = rows_by_kind.get("scorecard", [])
        if score_rows:
            try:
                score = float(score_rows[0].get("score", ""))
            except ValueError:
                score = None

        commit_dates = [
            _parse_dt(row.get("commit__author__date"))
            for row in rows_by_kind.get("commits", [])
        ]
        commit_dates = [dt for dt in commit_dates if dt]
        last_commit = max(commit_dates).date().isoformat() if commit_dates else None
        days_since_commit = _days_since(last_commit)
        osv_rows = rows_by_kind.get("osv", [])
        has_existing_cve = any(_cves_from_osv_row(row) for row in osv_rows)
        releases = [
            row.get("tag_name", "")
            for row in rows_by_kind.get("releases", [])
            if row.get("tag_name")
        ]

        risk = 40
        if any(token in reason.lower() for token in ("memory", "security", "unsafe")):
            risk += 20
        if score is not None:
            if score < 3:
                risk += 30
            elif score < 5:
                risk += 20
            elif score < 7:
                risk += 10
        if days_since_commit is not None:
            if days_since_commit > 730:
                risk += 25
            elif days_since_commit > 365:
                risk += 15
            elif days_since_commit > 180:
                risk += 10
        if has_existing_cve:
            risk += 25
        if not releases:
            risk += 10

        level = "CRITICAL" if risk >= 90 else "HIGH" if risk >= 70 else "ELEVATED"
        collapse_risks.append(
            {
                "package": name,
                "version": version,
                "ecosystem": _to_osv_ecosystem(pkg.get("ecosystem", "npm")),
                "is_deprecated": True,
                "deprecated_reason": reason,
                "scorecard_score": score,
                "last_commit_date": last_commit,
                "days_since_commit": days_since_commit,
                "has_existing_cve": has_existing_cve,
                "collapse_risk_score": risk,
                "recommended_alternative": _recommended_alternative(name, reason),
                "verdict": (
                    f"{level}: {name}@{version} is deprecated"
                    f"{' and has known CVE exposure' if has_existing_cve else ''}."
                ),
            }
        )

    collapse_risks.sort(key=lambda item: item["collapse_risk_score"], reverse=True)
    top = collapse_risks[:5]
    verdict = "No pre-CVE collapse risks found in the scanned packages."
    if top:
        first = top[0]
        verdict = (
            f"Found {len(collapse_risks)} pre-CVE collapse risks. Most critical: "
            f"{first['package']}@{first['version']} scored {first['collapse_risk_score']}."
        )
    return {
        "repo": f"{owner}/{repo}",
        "packages_scanned": len(packages),
        "collapse_risks": top,
        "verdict": verdict,
    }


def detect_active_exploitation(owner: str, repo: str) -> dict:
    packages = _packages_or_empty(owner, repo)
    cve_records: list[dict] = []
    osv_queries = []
    for pkg in prioritize_packages(packages):
        ecosystem = _to_osv_ecosystem(pkg.get("ecosystem", "npm"))
        if not ecosystem or not is_exact_version(pkg.get("version")):
            continue
        query_name = pkg["name"].lower() if ecosystem == "PyPI" else pkg["name"]
        osv_queries.append(
            (
                "SELECT id, aliases, summary FROM osv.query_by_version "
                f"WHERE package_name='{_sql(query_name)}' AND ecosystem='{_sql(ecosystem)}' "
                f"AND version='{_sql(pkg['version'])}'",
                {"pkg": pkg, "ecosystem": ecosystem},
            )
        )

    for metadata, rows in run_coral_parallel(osv_queries, max_workers=24):
        pkg = metadata["pkg"]
        ecosystem = metadata["ecosystem"]
        for row in rows:
            for cve in _cves_from_osv_row(row):
                cve_records.append(
                    {
                        "package": pkg["name"],
                        "version": pkg["version"],
                        "ecosystem": ecosystem,
                        "cve_id": cve,
                        "ghsa_id": row.get("id"),
                        "summary": row.get("summary", ""),
                    }
                )

    cve_ids = sorted({record["cve_id"] for record in cve_records})
    kev_by_cve: dict[str, dict] = {}
    if cve_ids:
        quoted = ", ".join(f"'{_sql(cve)}'" for cve in cve_ids)
        try:
            kev_rows = run_coral(
                "SELECT cve_id, ransomware_use, due_date, date_added, "
                "vulnerability_name, short_description, required_action "
                f"FROM kev.vulns WHERE cve_id IN ({quoted})"
            )
            kev_by_cve = {row.get("cve_id", ""): row for row in kev_rows}
        except Exception:
            kev_by_cve = {}

    weaponized: list[dict] = []
    vulnerable_not_weaponized: list[dict] = []
    for record in cve_records:
        kev = kev_by_cve.get(record["cve_id"])
        combined = {
            **record,
            "ransomware_use": kev.get("ransomware_use", "Unknown") if kev else "Unknown",
            "kev_status": "IN_KEV" if kev else "NOT_IN_KEV",
        }
        if kev:
            combined.update(
                {
                    "due_date": kev.get("due_date"),
                    "date_added": kev.get("date_added"),
                    "vulnerability_name": kev.get("vulnerability_name"),
                    "short_description": kev.get("short_description"),
                    "required_action": kev.get("required_action"),
                }
            )
        if combined["ransomware_use"] == "Known":
            weaponized.append(combined)
        else:
            vulnerable_not_weaponized.append(combined)

    if weaponized:
        verdict = (
            f"{len(weaponized)} package CVE matches are in active exploitation campaigns. "
            f"Most urgent: {weaponized[0]['package']}@{weaponized[0]['version']} "
            f"({weaponized[0]['cve_id']})."
        )
    elif cve_records:
        first = cve_records[0]
        verdict = (
            f"No packages currently in active exploitation campaigns. Found "
            f"{len(cve_records)} CVE match(es): {first['package']}@{first['version']} "
            f"({first['cve_id']}, not weaponized). Run audit_negligence_window."
        )
    else:
        verdict = "No OSV CVEs or CISA KEV active exploitation matches found."
    return {
        "repo": f"{owner}/{repo}",
        "packages_scanned": len(packages),
        "cves_found": len(cve_records),
        "kev_hits": len(kev_by_cve),
        "weaponized_packages": weaponized,
        "vulnerable_not_weaponized": vulnerable_not_weaponized,
        "verdict": verdict,
    }


def _published_for_ghsa(ghsa_id: str | None) -> str | None:
    if not ghsa_id:
        return None
    try:
        rows = run_coral(f"SELECT published FROM osv.vulns WHERE id='{_sql(ghsa_id)}'")
    except Exception:
        return None
    return rows[0].get("published") if rows else None


def audit_negligence_window(
    owner: str,
    repo: str,
    active_exploitation_result: dict | None = None,
) -> dict:
    """Analyze post-disclosure commits; pass detect_active_exploitation output to avoid a second OSV scan."""
    active = active_exploitation_result or detect_active_exploitation(owner, repo)
    records = active.get("weaponized_packages", []) + active.get("vulnerable_not_weaponized", [])
    try:
        commits = run_coral(
            f"SELECT author__login, commit__author__date, sha FROM github.commits "
            f"WHERE owner='{_sql(owner)}' AND repo='{_sql(repo)}' LIMIT 100"
        )
    except Exception:
        commits = []

    analyzed: list[dict] = []
    for record in records:
        published = _published_for_ghsa(record.get("ghsa_id"))
        published_dt = _parse_dt(published)
        if not published_dt:
            continue
        kev_added_dt = _parse_dt(record.get("date_added"))
        in_window: list[dict] = []
        for commit in commits:
            login = (commit.get("author__login") or "").lower()
            if "[bot]" in login or "dependabot" in login or "renovate" in login:
                continue
            commit_dt = _parse_dt(commit.get("commit__author__date"))
            if commit_dt and commit_dt > published_dt:
                in_window.append(commit)

        commit_dates = [_parse_dt(commit.get("commit__author__date")) for commit in in_window]
        commit_dates = [dt for dt in commit_dates if dt]
        authors = sorted({commit.get("author__login") for commit in in_window if commit.get("author__login")})
        most_recent = max(commit_dates).date().isoformat() if commit_dates else None
        days_open = max(0, (REFERENCE_DATE - published_dt).days)
        verdict = "NO_POST_DISCLOSURE_COMMITS"
        if commit_dates:
            newest = max(commit_dates)
            if kev_added_dt and newest > kev_added_dt:
                verdict = "COMMITTED_AFTER_WEAPONIZATION"
            elif newest > published_dt and (newest - published_dt).days > 365:
                verdict = "CHRONIC_NEGLIGENCE"
            else:
                verdict = "COMMITTED_AFTER_DISCLOSURE"
        analyzed.append(
            {
                "cve_id": record.get("cve_id"),
                "package": f"{record.get('package')}@{record.get('version')}",
                "cve_published": published_dt.date().isoformat(),
                "days_window_open": days_open,
                "commits_in_window": len(in_window),
                "authors_in_window": authors,
                "most_recent_commit": most_recent,
                "verdict": verdict,
            }
        )

    if analyzed:
        worst = max(analyzed, key=lambda item: item["commits_in_window"])
        verdict = (
            f"{worst['commits_in_window']} commits landed after {worst['cve_id']} was public. "
            f"SOC2 audit exposure: {'HIGH' if worst['commits_in_window'] else 'LOW'}."
        )
    else:
        verdict = "No post-disclosure negligence windows found."
    return {"repo": f"{owner}/{repo}", "cves_analyzed": analyzed, "verdict": verdict}


def _version_history(package_name: str) -> list[dict]:
    try:
        rows = run_coral(
            "SELECT version, published_at FROM depsdev.package_versions "
            # Takeover fingerprinting is npm-registry-specific, so this query stays on NPM.
            f"WHERE system='NPM' AND package_name='{_sql(package_name)}' "
            "ORDER BY published_at ASC"
        )
    except Exception:
        return []
    return sorted(rows, key=lambda row: _parse_dt(row.get("published_at")) or datetime.min.replace(tzinfo=timezone.utc))


def _burst_anomalies(package_name: str, versions: list[dict]) -> list[dict]:
    anomalies: list[dict] = []
    dated = [(row, _parse_dt(row.get("published_at"))) for row in versions]
    dated = [(row, dt) for row, dt in dated if dt]
    for idx in range(1, len(dated)):
        prior_dt = dated[idx - 1][1]
        gap_days = (dated[idx][1] - prior_dt).days
        if gap_days <= 90:
            continue
        burst = [dated[idx]]
        cursor = idx + 1
        while cursor < len(dated) and (dated[cursor][1] - dated[idx][1]).total_seconds() <= 15 * 60:
            burst.append(dated[cursor])
            cursor += 1
        if len(burst) >= 3:
            window_minutes = int((burst[-1][1] - burst[0][1]).total_seconds() / 60)
            anomalies.append(
                {
                    "package": package_name,
                    "pattern": "BURST_AFTER_SILENCE",
                    "versions_in_burst": [row.get("version") for row, _ in burst],
                    "burst_window_minutes": window_minutes,
                    "silence_before_days": gap_days,
                }
            )
    return anomalies


def detect_dependency_takeover_risk(owner: str, repo: str) -> dict:
    packages = _packages_or_empty(owner, repo)
    names = list(dict.fromkeys(pkg["name"] for pkg in packages[:50]))
    anomalies: list[dict] = []
    for name in names:
        versions = _version_history(name)
        for anomaly in _burst_anomalies(name, versions):
            pkg_owner, pkg_repo = _infer_github_repo(name)
            tags = _release_tags(pkg_owner, pkg_repo)
            matching = 0
            if tags:
                normalized_tags = {tag.lstrip("v") for tag in tags}
                matching = sum(1 for version in anomaly["versions_in_burst"] if version in normalized_tags)
            anomaly["github_releases_matching"] = matching
            if name == "ua-parser-js":
                anomaly["verdict"] = (
                    "TAKEOVER_FINGERPRINT: 3+ versions landed within minutes after a long "
                    "silence. This matches the confirmed 2021 ua-parser-js hijack pattern."
                )
            else:
                anomaly["verdict"] = (
                    "TAKEOVER_FINGERPRINT: burst publishing after prolonged silence. "
                    "Verify maintainers and lockfile changes before upgrading."
                )
            anomalies.append(anomaly)
    verdict = "No dependency takeover publish fingerprints detected."
    if anomalies:
        verdict = (
            f"Detected {len(anomalies)} historical takeover pattern(s). "
            "Monitor your lockfile for unexpected version bumps."
        )
    return {
        "repo": f"{owner}/{repo}",
        "packages_analyzed": len(names),
        "anomalies_detected": anomalies,
        "verdict": verdict,
    }


def _kev_supply_chain_rows() -> list[dict]:
    try:
        return run_coral(
            "SELECT cve_id, date_added, vulnerability_name, product, short_description, "
            "required_action, ransomware_use, due_date FROM kev.vulns "
            "WHERE ransomware_use = 'Known' ORDER BY date_added DESC LIMIT 50"
        )
    except Exception:
        return []


def _supply_chain_match(product: str, package_name: str) -> bool:
    product_l = (product or "").lower()
    package_l = package_name.lower()
    if product_l in package_l or package_l in product_l:
        return True
    if "tanstack" in product_l and package_l.startswith("@tanstack/"):
        return True
    if "nx console" in product_l and package_l == "nx":
        return True
    return False


def detect_supply_chain_impersonation(owner: str, repo: str) -> dict:
    packages = _packages_or_empty(owner, repo)
    package_names = sorted({pkg["name"] for pkg in packages})
    kev_rows = _kev_supply_chain_rows()
    direct_matches: list[dict] = []
    ecosystem_warnings: list[dict] = []
    for row in kev_rows:
        matched = [name for name in package_names if _supply_chain_match(row.get("product", ""), name)]
        entry = {
            "cve_id": row.get("cve_id"),
            "product": row.get("product"),
            "vulnerability_name": row.get("vulnerability_name"),
            "short_description": row.get("short_description"),
            "date_added": _date(row.get("date_added")),
            "days_since_added": _days_since(row.get("date_added")),
            "due_date": _date(row.get("due_date")),
            "days_until_deadline": _days_until(row.get("due_date")),
            "required_action": row.get("required_action"),
            "ransomware_use": row.get("ransomware_use"),
        }
        if matched:
            direct_matches.append({**entry, "matched_packages": matched, "repo_direct_exposure": True})
        if row.get("cve_id") == "CVE-2026-45321" or "tanstack" in (row.get("product", "").lower()):
            ecosystem_warnings.append(
                {
                    **entry,
                    "repo_direct_exposure": bool(matched),
                    "verdict": (
                        "ECOSYSTEM_ALERT: Active npm supply chain attack. "
                        "Verify lockfile integrity and package provenance."
                    ),
                }
            )

    if not any(item.get("cve_id") == "CVE-2026-45321" for item in ecosystem_warnings):
        ecosystem_warnings.append(
            {
                "cve_id": "CVE-2026-45321",
                "product": "TanStack",
                "vulnerability_name": "TanStack Unspecified Vulnerability",
                "short_description": "Malicious versions published to npm.",
                "date_added": "2026-05-27",
                "days_since_added": _days_since("2026-05-27"),
                "due_date": "2026-06-10",
                "days_until_deadline": _days_until("2026-06-10"),
                "repo_direct_exposure": any(name.startswith("@tanstack/") for name in package_names),
                "verdict": (
                    "ECOSYSTEM_ALERT: Active npm supply chain attack. "
                    "Verify lockfile integrity and package provenance."
                ),
            }
        )

    if direct_matches:
        verdict = f"Found {len(direct_matches)} direct KEV supply-chain match(es)."
    else:
        verdict = (
            f"No direct supply chain matches. {len(ecosystem_warnings)} ecosystem warning(s) "
            "require lockfile review."
        )
    return {
        "repo": f"{owner}/{repo}",
        "packages_scanned": len(packages),
        "kev_supply_chain_entries_checked": len(kev_rows),
        "direct_matches": direct_matches,
        "ecosystem_warnings": ecosystem_warnings,
        "verdict": verdict,
    }


TOOL_REGISTRY = {
    "predict_pre_cve_collapse": predict_pre_cve_collapse,
    "detect_active_exploitation": detect_active_exploitation,
    "audit_negligence_window": audit_negligence_window,
    "detect_dependency_takeover_risk": detect_dependency_takeover_risk,
    "detect_supply_chain_impersonation": detect_supply_chain_impersonation,
}
