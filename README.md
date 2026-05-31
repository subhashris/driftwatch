# DriftWatch — Supply Chain Security Radar

> **Pirates of the Coral Bean Hackathon 2026**  
> Built by Subhashri Sakthivel

DriftWatch is a supply-chain security intelligence platform that answers the questions no scanner answers:
- *How long has this vulnerability been sitting here — and who was responsible for fixing it?*
- *Is this package dying before a CVE is even filed?*
- *Before I deploy, which packages are actively being exploited right now?*

Powered entirely by **Coral's cross-source SQL** — seven live data sources, zero ETL, zero glue code.

### Custom Coral Source Specs built for this project

| Source | What it connects to |
|---|---|
| `epss` | FIRST.org — live exploitation probability scores for any CVE |
| `kev` | CISA Known Exploited Vulnerabilities catalog |
| `depsdev` | deps.dev — package deprecation, version history, abandonment signals |
| `npm` | npm registry — maintainer metadata, publish history |
| `pypi` | PyPI registry — Python package metadata |
| `scorecard` | OpenSSF Scorecard — upstream project health scores |

These six custom source specs extend Coral's built-in GitHub and OSV sources, giving DriftWatch a complete seven-source security intelligence layer. Every signal in the product — EPSS scores, KEV status, deprecation warnings, maintainer health — flows through these specs as standard SQL queries.

---

## The Problem

Security teams today open five browser tabs to understand dependency risk:
- Snyk or Dependabot for CVEs
- GitHub for commit history
- deps.dev for package health
- FIRST.org for exploitation probability
- CISA KEV for active exploitation

DriftWatch replaces all of that with one SQL interface and one natural language agent.

---

## What DriftWatch Does

### Five Intelligence Signals

| Signal | What it answers | Coral sources |
|---|---|---|
| **Patch Lag** | How long has this CVE been exposed with a fix available? | `osv.query_by_version` + `kev.vulns` |
| **Pre-CVE Detection** | Which packages are deprecated for security reasons before any CVE exists? | `depsdev.package_versions` + `osv.query_by_version` |
| **Active Exploitation** | Which CVEs are being weaponised right now? | `kev.vulns` + `epss.scores` |
| **Crew Accountability** | Who in your org owns the negligence? | `github.search_commits` + `github.search_code` + `github.repo_contributors` |
| **Upstream Health** | Is the maintainer responsive? Is the package abandoned? | `depsdev.package_versions` + `scorecard.project_score` |

### URGENCY SCORE

Every finding is ranked by:
```
URGENCY = KEV active (×40) + EPSS percentile (×60) + patch lag (×10) + CVE count (×2)
```

### Ask the Watch Agent

A natural language security analyst powered by Groq (`llama3-70b-8192`) with live Coral tool calling. Ask any question about a scanned repo — the agent writes cross-source SQL, executes it live through Coral, and answers from real data.

Example questions:
- *"Is jellyfin/jellyfin-web safe to deploy right now?"*
- *"What is the full risk profile of pdfjs-dist?"*
- *"Who should I talk to about the pdfjs-dist vulnerability?"*
- *"Are there any pre-CVE warning signals I should know about?"*

---

## Coral Sources

DriftWatch uses **7 Coral sources** — 4 custom source specs built for this project:

| Source | Type | What it provides |
|---|---|---|
| `github.sbom` | Built-in | Repository SBOM (SPDX format), dependency graph |
| `github.search_commits` | Built-in | Commit history, author attribution |
| `github.search_code` | Built-in | Code search for package references |
| `osv.query_by_version` | Built-in | CVE/GHSA lookup by package + version |
| `epss.scores` | **Custom spec** | Live EPSS exploitation probability from FIRST.org |
| `kev.vulns` | **Custom spec** | CISA Known Exploited Vulnerabilities catalog |
| `depsdev.package_versions` | **Custom spec** | Package deprecation, version history from deps.dev |
| `npm.package_info` | **Custom spec** | npm maintainer metadata |
| `scorecard.project_score` | **Custom spec** | OpenSSF Scorecard upstream health |

### Signature Cross-Source Queries

**Active exploitation cross-reference:**
```sql
SELECT cve_id, vulnerability_name, date_added, ransomware_use
FROM kev.vulns
WHERE cve_id IN ('CVE-2024-4367', 'CVE-2020-7753')
```

**Live EPSS for all scan findings:**
```sql
SELECT cve_id, epss_score, percentile
FROM epss.scores(cve => 'CVE-2024-4367,CVE-2020-7753,CVE-2021-33623')
```

**Pre-CVE deprecation signal:**
```sql
SELECT name, version, is_deprecated, deprecated_reason
FROM depsdev.package_versions
WHERE system = 'NPM' AND package_name = 'glob'
```

**Negligence window — commits after CVE disclosure:**
```sql
SELECT author_login, commit__message, commit__author__date, html_url
FROM github.search_commits
WHERE q = 'repo:jellyfin/jellyfin-web pdfjs'
```

**Ownership mapping:**
```sql
SELECT author_login, message
FROM github.search_commits
WHERE q = 'repo:jellyfin/jellyfin-web path:package.json'
```

---

## Claude Code + Coral MCP Integration

DriftWatch registers `coral mcp-stdio` with Claude Code as an MCP server:

```bash
claude mcp add --scope user coral -- coral mcp-stdio
```

Claude Code can then answer security questions by writing Coral SQL autonomously:

```
> Find packages in jellyfin/jellyfin-web deprecated for security 
  with no CVE yet — pre-CVE signals

Claude writes → executes → returns:
glob@7.1.6: deprecated "widely publicized security vulnerabilities"
No CVE in OSV. 16-month-ahead warning. npm audit misses this entirely.
```

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  DriftWatch                      │
│                                                  │
│  radar.html (React-style SPA)                   │
│       ↓                                          │
│  FastAPI (app.py) — port 8080                   │
│       ↓                                          │
│  ┌──────────────┬──────────────────────┐         │
│  │  scan.py     │  agent.py            │         │
│  │  sweep.py    │  (Groq + tool calls) │         │
│  │  ownership.py│                      │         │
│  └──────┬───────┴──────────┬───────────┘         │
│         ↓                  ↓                     │
│    coral CLI          coral mcp-stdio            │
│    (subprocess)       (MCP server)               │
└─────────────────────────────────────────────────┘
         ↓                  ↓
    Coral Engine — 7 live data sources
    GitHub · OSV · KEV · EPSS · deps.dev · npm · Scorecard
```

---

## Pipeline

```
scan.py         → SBOM + OSV + KEV (batch parallel Coral queries)
enrich_epss.py  → Live EPSS + KEV enrichment via Coral
sweep.py        → Pre-CVE signals via depsdev + OSV cross-join
ownership.py    → GitHub commit × code search × contributors join
app.py          → FastAPI serving radar.html + /api/chat agent
agent.py        → Groq LLM with coral_sql tool calling
```

---

## Real Findings — jellyfin/jellyfin-web

| Package | Version | Days Exposed | EPSS | Finding |
|---|---|---|---|---|
| pdfjs-dist | 3.11.174 | 753 | **97th %ile** | RCE via malicious PDF. Mitigated in 34 days with one flag. Never upgraded. |
| trim | 0.0.1 | 1,845 | 88th %ile | ReDoS. 5 dependency levels deep. Invisible to Renovate. Zero commits ever. |
| trim-newlines | 2.0.0 | 1,817 | 82nd %ile | ReDoS. Abandoned package chain. |
| glob | 7.1.6 | — | — | **PRE-CVE signal** — deprecated for security, no CVE filed yet. |
| yargs-parser | 10.1.0 | 2,093 | 31st %ile | Prototype pollution. Fix available since September 2020. |

---

## Prerequisites

- Python 3.11+
- [Coral](https://withcoral.com) installed and configured
- GitHub personal access token configured in Coral
- Groq API key (free tier)

---

## Setup

```powershell
# Clone
git clone https://github.com/subhashris/driftwatch
cd driftwatch

# Install dependencies
pip install -r requirements.txt

# Configure Coral sources
coral source add github
coral source add osv
# Add custom sources (see /sources folder)

# Register with Claude Code (optional)
claude mcp add --scope user coral -- coral mcp-stdio

# Add Groq API key
echo "GROQ_API_KEY=your_key_here" > .env

# Start server
$env:Path += ";$env:USERPROFILE\.local\bin"
uvicorn app:app --reload --port 8080
```

Open `http://localhost:8080`

---

## Running a Scan

```powershell
# Full deep scan
python scan.py jellyfin jellyfin-web

# Fast triage (top 50 packages)
python scan.py jellyfin jellyfin-web --max-packages 50

# Enrich with live EPSS + KEV
python enrich_epss.py --scan output/scan_jellyfin_jellyfin-web.json

# Pre-CVE sweep
python sweep.py jellyfin jellyfin-web --scan-json output/scan_jellyfin_jellyfin-web.json

# Ownership mapping
python ownership.py jellyfin jellyfin-web --scan-json output/scan_jellyfin_jellyfin-web.json
```

---

## Project Structure

```
driftwatch/
├── app.py              # FastAPI backend + /api/chat endpoint
├── agent.py            # Groq LLM agent with Coral SQL tool calling
├── scan.py             # SBOM → OSV → KEV scan pipeline
├── sweep.py            # Pre-CVE signal detection
├── ownership.py        # Dependency ownership mapping
├── coral_utils.py      # Coral SQL utilities + SBOM parser
├── enrich_epss.py      # Live EPSS + KEV enrichment via Coral
├── mcp_server.py       # Custom MCP server (driftwatch tools)
├── radar.html          # Single-page dashboard UI
├── sources/            # Custom Coral source specs
│   ├── epss.toml
│   ├── kev.toml
│   ├── depsdev.toml
│   └── npm.toml
├── output/             # Scan results
└── .env                # API keys (not committed)
```

---

## Supported Ecosystems

- **npm** (Node.js)
- **PyPI** (Python)
- **Maven** (Java)
- **Cargo** (Rust)
- **Go**

Any GitHub repo with the dependency graph enabled works out of the box.

---

## Why Coral

Coral makes DriftWatch possible by providing:

1. **Cross-source SQL joins** — GitHub + OSV + KEV + EPSS in one query
2. **No ETL** — live data from 7 sources without a data warehouse
3. **Self-describing schema** — `SELECT * FROM coral.tables` gives Claude everything it needs to write correct SQL autonomously
4. **MCP integration** — Claude Code connects directly to `coral mcp-stdio` and writes security intelligence queries in natural language
5. **Custom source specs** — We extended Coral with EPSS, KEV, deps.dev, npm, and Scorecard in hours, not weeks

The negligence forensics query — finding that pdfjs-dist was mitigated with one line of code 34 days after CVE disclosure but never upgraded in 754 days — required joining `osv.query_by_version` (CVE date), `github.search_commits` (commit history filtered by date), and `epss.scores` (current exploitation probability). Without Coral that's three separate API integrations with pagination, rate limiting, and date parsing. With Coral it's one SQL query.

---

## Demo

Watch the full demo: https://youtu.be/MDMsCJjWAqk

---

## Hackathon

Built for **Pirates of the Coral Bean** hackathon (May 26–31, 2026)  
Category: Security & Compliance  
Built by: Subhashri Sakthivel
