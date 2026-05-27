<div align="center">

```
██████╗ ██████╗ ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██║  ██║██████╔╝██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║  ██║██╔══██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██████╔╝██║  ██║██║██║        ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
```

**Predictive supply-chain intelligence — catch dependency drift before the CVE exists**

[![Built with Coral](https://img.shields.io/badge/Built%20with-Coral-0d6efd?style=flat-square)](https://withcoral.com)
[![Pirates of the Coral Bean](https://img.shields.io/badge/Hackathon-Pirates%20of%20the%20Coral%20Bean-f59e0b?style=flat-square)](https://withcoral.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

</div>

---

## The Problem

Every security tool tells you what's **already broken**.

Snyk finds your CVEs. Endor Labs checks reachability. Socket watches package behavior. But by the time a CVE exists, you're already behind. And even when you have a list of vulnerabilities, nobody tells you:

- **How long** you've been exposed (with a fix sitting there the whole time)
- **Whether upstream will actually fix it** — or if you're on your own
- **Who in your org** owns the code that uses this dependency
- **What's about to become dangerous** — before any CVE is filed

DriftWatch answers all four. It's not a scanner. It's a **triage intelligence layer** built on [Coral](https://withcoral.com) — one SQL interface joining six data sources into a single, ranked, actionable view of your supply chain risk.

---

## What Makes It Different

| Question | Snyk / Endor | Socket | DriftWatch |
|---|---|---|---|
| Is this vulnerable? | ✅ | ✅ | ✅ |
| Is the vulnerable code reachable? | ✅ | — | — |
| How long have we been exposed? | — | — | ✅ |
| Will upstream fix it fast? | — | — | ✅ |
| Who in my org owns this dep? | — | — | ✅ |
| What's breaking before a CVE exists? | — | Partial | ✅ |
| Paste-ready ticket for the dev team? | — | — | ✅ |

---

## Features

### ⧖ Patch Lag Tracker
Measures days elapsed since a CVE was published — with a fix available the entire time. `yargs-parser` in jellyfin-web: **2,090 days**. That's not a severity score. That's a neglect metric. It's the number that makes a CISO act.

### ⟳ Maintainer Responsiveness
For each vulnerable dependency, computes how fast the upstream maintainers historically shipped security fixes. Answers the question security engineers have no data on: *"If I wait for upstream to patch this, how long will I actually wait?"* Fast → wait. Slow → mitigate now. Nobody else computes this.

### ⚡ Pre-CVE Canary Sweep
Scans every dependency against [deps.dev](https://deps.dev) for versions deprecated with security-related reasons — **before any CVE is filed**. Real example from our demo: `dompurify` v3.4.4 was deprecated 10 days ago with *"Fixed a security issue introduced in 3.4.4."* No CVE exists. Every scanner is silent. DriftWatch fires.

### 📊 OpenSSF Scorecard Integration
Incorporates [OpenSSF Scorecard](https://securityscorecards.dev) — the industry standard maintained by Google and the Linux Foundation — cross-referenced against your actual SBOM. Your specific dependencies, scored by an external authority, enriched with your exposure data.

### ↑ Upgrade Actionability
Classifies every fix as **SAFE** (patch/minor bump — do it this sprint) or **BREAKING** (major version — plan a migration). Turns a vulnerability list into a work plan. `qs 6.13.0 → 6.14.1` is a one-liner. `postcss 7.0.36 → 8.4.31` is a project.

### 👤 Dependency Ownership Map
Cross-references vulnerable packages against GitHub code search and commit history to find **who in your org owns the code using each vulnerable dependency** — automatically. Produces paste-ready Jira tickets. The feature the market most clearly lacks.

---

## Data Sources

DriftWatch is powered by Coral's SQL-over-APIs runtime. One query plane, six sources, zero ETL:

| Source | Type | What It Provides |
|---|---|---|
| GitHub SBOM | Coral native | Your full dependency tree |
| OSV Vulnerability DB | Community spec | CVE detection + fix versions |
| CISA KEV | **Custom spec** | Active exploitation alerts |
| npm Registry | **Custom spec** | Publisher ownership + download scale |
| PyPI | **Custom spec** | Python package maintainer data |
| Maven Central | **Custom spec** | Java artifact version staleness |
| deps.dev | **Custom spec** | Universal version history (npm/PyPI/Maven/Go/Cargo) |
| OpenSSF Scorecard | **Custom spec** | Industry-standard project health scores |

Four original custom source specs contributed back to the Coral ecosystem.

---

## The Coral SQL Story

DriftWatch isn't just built *on* Coral — it demonstrates what Coral uniquely enables. These are real queries powering real features:

```sql
-- Explode 1,638 packages from a single SBOM
SELECT json_get_str(pkg,'name') AS name,
       json_get_str(pkg,'versionInfo') AS version,
       json_get_str(json_get(pkg,'externalRefs',0),'referenceLocator') AS purl
FROM (SELECT unnest(json_get_array(sbom__packages)) AS pkg
      FROM github.sbom WHERE owner='jellyfin' AND repo='jellyfin-web')

-- Check active exploitation against CISA's live feed
SELECT cve_id, vulnerability_name, date_added, ransomware_use
FROM kev.vulns WHERE cve_id = 'CVE-2021-44228'

-- Pre-CVE: find deprecated versions with security reasons
SELECT version, published_at, deprecated_reason
FROM depsdev.package_versions
WHERE system='NPM' AND package_name='dompurify' AND is_deprecated=true

-- Ownership: who committed to files using this dependency?
SELECT author_login, message
FROM github.search_commits(q => 'repo:jellyfin/jellyfin-web postcss')

-- Maintainer responsiveness: when did the fix actually ship?
SELECT tag_name, published_at FROM github.releases
WHERE owner='postcss' AND repo='postcss' AND tag_name='8.4.31'
```

The cross-source join — SBOM × OSV × GitHub maintainer data × deps.dev × OpenSSF Scorecard × ownership — is what makes this impossible to build without Coral.

---

## Quick Start

### Prerequisites
- [Coral CLI](https://withcoral.com) installed and configured with a GitHub PAT
- Python 3.10+
- Git

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/driftwatch.git
cd driftwatch
pip install -r requirements.txt
```

### Add Coral Sources

```bash
coral source add --file sources/kev.yaml
coral source add --file sources/npm.yaml
coral source add --file sources/pypi.yaml
coral source add --file sources/maven.yaml
coral source add --file sources/depsdev.yaml
coral source add --file sources/scorecard.yaml
```

### Run

```bash
uvicorn app:app --reload --port 8080
```

Open `http://localhost:8080`, type any GitHub `owner/repo`, click **Scan**.

### Windows (PowerShell)

```powershell
# Ensure Coral is on PATH for the session
$env:Path += ";$env:USERPROFILE\.local\bin"

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn app:app --reload --port 8080
```

---

## Demo

Scan `jellyfin/jellyfin-web` to see DriftWatch on a real production codebase:

- **2,090 days** — yargs-parser exposure with fix available since 2020
- **226M weekly downloads** — postcss maintained by 1 npm publisher
- **Pre-CVE signal** — dompurify v3.4.4 deprecated for a security issue with no CVE yet
- **12/12 packages** with identified human owners and paste-ready tickets

---

## Architecture

```
GitHub SBOM ──────┐
OSV Vuln DB ──────┤
CISA KEV ─────────┤  Coral SQL  ──►  Python Pipeline  ──►  FastAPI  ──►  radar.html
deps.dev ─────────┤  (scan.py, sweep.py,                    (app.py)      Captain's
npm Registry ─────┤   ownership.py,                                        Chart Room
OpenSSF ──────────┤   fragility.py,                                        UI
GitHub Search ────┘   maintainer.py)
```

---

## Built For

**Pirates of the Coral Bean** hackathon — May 25–31, 2026
Built with [Coral](https://withcoral.com) by Subha

---

## License

MIT — see [LICENSE](LICENSE)
