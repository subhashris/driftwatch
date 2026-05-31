from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import unquote


PURL_TO_OSV = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "cargo": "crates.io",
    "golang": "Go",
    "nuget": "NuGet",
}

PURL_TO_DEPSDEV = {
    "npm": "NPM",
    "pypi": "PYPI",
    "maven": "MAVEN",
    "cargo": "CARGO",
    "golang": "GO",
    "nuget": "NUGET",
}

_SBOM_CACHE: dict[tuple[str, str], list[dict] | dict] = {}

_TIER0_EXACT = {
    "eslint",
    "prettier",
    "webpack",
    "babel",
    "jest",
    "mocha",
    "chai",
    "sinon",
    "nyc",
    "rollup",
    "vite",
    "esbuild",
    "stylelint",
    "lint-staged",
}

_TIER1_KEYWORDS = {
    "crypto", "ssl", "tls", "jwt", "oauth", "saml", "bcrypt", "hash",
    "cipher", "sign", "token", "auth", "password", "secret", "keystore",
    "x509", "cert", "xml", "yaml", "yml", "json", "html", "markdown",
    "parse", "sax", "dom", "xslt", "csv", "toml", "http", "https",
    "request", "fetch", "axios", "urllib", "curl", "socket", "netty",
    "okhttp", "retrofit", "template", "jinja", "mustache", "handlebars",
    "thymeleaf", "freemarker", "velocity", "pebble", "serial", "marshal",
    "pickle", "avro", "protobuf", "msgpack", "cbor", "jackson", "gson",
    "kryo", "sql", "mysql", "postgres", "sqlite", "mongo", "redis",
    "elasticsearch", "jdbc", "hibernate", "orm", "datasource", "zip",
    "tar", "gzip", "compress", "archive", "zlib", "lz4", "snappy",
}

_MAVEN_HIGH_RISK = (
    "org.apache",
    "org.springframework",
    "com.fasterxml",
    "io.netty",
    "org.hibernate",
    "commons-",
    "log4j",
    "logback",
    "ch.qos",
)


def _coral_binary() -> str:
    coral_path = os.path.join(
        os.environ.get("USERPROFILE", ""), ".local", "bin", "coral.exe"
    )
    return coral_path if os.path.exists(coral_path) else "coral"


def _log_error(message: str) -> None:
    print(f"[coral] {message}", file=sys.stderr)


def parse_coral_table(output: str) -> list[dict]:
    lines = output.strip().splitlines()
    headers: list[str] = []
    rows: list[dict] = []
    for line in lines:
        if line.startswith("+"):
            continue
        if "|" not in line:
            continue
        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        if not headers:
            headers = cells
        elif len(cells) == len(headers):
            rows.append(dict(zip(headers, cells)))
    return rows


def run_coral(query: str) -> list[dict]:
    try:
        result = subprocess.run(
            [_coral_binary(), "sql", query],
            capture_output=True,
            text=True,
            timeout=25,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        _log_error("query timed out after 25s")
        return []
    except OSError as exc:
        _log_error(f"could not start coral: {exc}")
        return []

    if result.returncode != 0:
        _log_error(result.stderr.strip() or f"query failed with code {result.returncode}")
        return []
    return parse_coral_table(result.stdout)


def run_coral_parallel(
    queries: list[tuple[str, dict]], max_workers: int = 12
) -> list[tuple[dict, list[dict]]]:
    def _run(query: str, metadata: dict) -> tuple[dict, list[dict]]:
        try:
            return metadata, run_coral(query)
        except Exception as exc:
            _log_error(f"parallel query failed: {exc}")
            return metadata, []

    results: list[tuple[dict, list[dict]]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_run, query, metadata) for query, metadata in queries]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                _log_error(f"parallel worker failed: {exc}")
                results.append(({}, []))
    return results


def _sql(value: Any) -> str:
    return str(value).replace("'", "''")


def _purl_type(purl: str) -> str | None:
    match = re.match(r"pkg:([^/]+)/", purl or "")
    return match.group(1).lower() if match else None


def _name_version_from_purl(
    purl: str, fallback_name: str, fallback_version: str
) -> tuple[str, str]:
    body = (purl or "").split("?", 1)[0]
    if "@" not in body:
        return fallback_name, fallback_version
    name_part, version = body.rsplit("@", 1)
    version = unquote(version or fallback_version)
    purl_type = _purl_type(purl) or ""

    if purl_type == "maven":
        after_scheme = (
            name_part.split("pkg:maven/", 1)[-1]
            if "pkg:maven/" in name_part
            else name_part
        )
        parts = after_scheme.strip("/").split("/")
        if len(parts) >= 2:
            name = f"{unquote(parts[0])}:{unquote(parts[1])}"
        elif parts:
            name = unquote(parts[0])
        else:
            name = fallback_name
    else:
        name = name_part.split("/", 1)[1] if "/" in name_part else fallback_name
        name = unquote(name or fallback_name)
        if purl_type == "pypi":
            name = name.lower()

    return name, version


def _sbom_unavailable(owner: str, repo: str) -> dict:
    return {
        "error": "SBOM_UNAVAILABLE",
        "message": (
            "Enable GitHub dependency graph at "
            f"github.com/{owner}/{repo}/settings/security_analysis"
        ),
    }


def parse_sbom(owner: str, repo: str) -> list[dict] | dict:
    cache_key = (owner, repo)
    if cache_key in _SBOM_CACHE:
        return _SBOM_CACHE[cache_key]

    rows = run_coral(
        f"SELECT sbom FROM github.sbom WHERE owner='{_sql(owner)}' AND repo='{_sql(repo)}'"
    )
    if not rows:
        result = _sbom_unavailable(owner, repo)
        _SBOM_CACHE[cache_key] = result
        return result

    raw_values = [row.get("sbom", "") for row in rows if row.get("sbom")]
    candidates = raw_values + (["".join(raw_values)] if len(raw_values) > 1 else [])
    packages: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for raw in candidates:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(data, dict) or not data.get("packages"):
            continue

        for pkg in data.get("packages", []):
            refs = pkg.get("externalRefs") or []
            purl = ""
            for ref in refs:
                locator = ref.get("referenceLocator", "")
                if locator.startswith("pkg:"):
                    purl = locator
                    break
            ecosystem = _purl_type(purl)
            if not ecosystem or ecosystem not in PURL_TO_OSV:
                continue
            name, version = _name_version_from_purl(
                purl, str(pkg.get("name", "")), str(pkg.get("versionInfo", ""))
            )
            if not name or not version:
                continue
            key = (name, version, purl)
            if key in seen:
                continue
            seen.add(key)
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "purl": purl,
                    "osv_ecosystem": PURL_TO_OSV.get(ecosystem),
                    "depsdev_system": PURL_TO_DEPSDEV.get(ecosystem),
                }
            )
        if packages:
            break

    if not packages:
        result = _sbom_unavailable(owner, repo)
        _SBOM_CACHE[cache_key] = result
        return result

    _SBOM_CACHE[cache_key] = packages
    return packages


def _major_version(version: str | None) -> int | None:
    if not version:
        return None
    match = re.search(r"\d+", version)
    if not match:
        return None
    try:
        return int(match.group(0))
    except ValueError:
        return None


def is_exact_version(version: str | None) -> bool:
    if not version:
        return False
    raw = str(version).strip()
    if not raw:
        return False
    if any(token in raw for token in ("<", ">", "^", "~", "*", ",", "||", " ")):
        return False
    if raw[0] in "=([{":
        return False
    return bool(re.search(r"\d", raw))


def _is_tier0(name: str) -> bool:
    lowered = name.lower()
    bare = lowered.split("/")[-1] if lowered.startswith("@") else lowered
    if lowered.startswith("@types/") or lowered.startswith("@typescript-eslint/"):
        return True
    if (
        bare.endswith("-types")
        or "-type-" in bare
        or bare.endswith("-test")
        or bare.endswith("-mock")
        or bare.endswith("-stub")
        or bare.endswith("-dev")
        or bare.endswith("-docs")
        or bare.startswith("eslint")
        or bare.startswith("prettier")
        or bare.startswith("webpack")
        or bare.startswith("babel")
        or bare.startswith("jest")
        or bare.startswith("mocha")
        or bare.startswith("chai")
        or bare.startswith("sinon")
        or bare.startswith("nyc")
        or bare.startswith("ts-")
        or bare.startswith("rollup")
        or bare.startswith("vite")
        or bare.startswith("esbuild")
        or bare.startswith("stylelint")
        or bare.startswith("lint-staged")
    ):
        return True
    return bare in _TIER0_EXACT


def package_priority_tier(pkg: dict) -> int:
    name = str(pkg.get("name", ""))
    lowered = name.lower()
    if _is_tier0(name):
        return 0
    if any(keyword in lowered for keyword in _TIER1_KEYWORDS):
        return 1
    if (pkg.get("ecosystem") or "").lower() == "maven" and any(
        marker in lowered for marker in _MAVEN_HIGH_RISK
    ):
        return 1
    major = _major_version(pkg.get("version"))
    if major is not None and major <= 1:
        return 2
    return 3


def prioritize_packages(packages: list[dict]) -> list[dict]:
    tiers: dict[int, list[dict]] = {1: [], 2: [], 3: []}
    for pkg in packages:
        tier = package_priority_tier(pkg)
        if tier == 0:
            continue
        enriched = {**pkg, "_priority_tier": tier}
        tiers[tier].append(enriched)

    def sort_key(pkg: dict) -> tuple[int, str]:
        major = _major_version(pkg.get("version"))
        return (major if major is not None else 9999, str(pkg.get("name", "")))

    return (
        sorted(tiers[1], key=sort_key)
        + sorted(tiers[2], key=sort_key)
        + sorted(tiers[3], key=sort_key)
    )
