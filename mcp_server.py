# claude mcp add --scope user driftwatch -- python mcp_server.py

from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from tools import (
    audit_negligence_window,
    detect_active_exploitation,
    detect_dependency_takeover_risk,
    detect_supply_chain_impersonation,
    predict_pre_cve_collapse,
)


server = Server("driftwatch")

TOOL_FUNCTIONS = {
    "predict_pre_cve_collapse": predict_pre_cve_collapse,
    "detect_active_exploitation": detect_active_exploitation,
    "audit_negligence_window": audit_negligence_window,
    "detect_dependency_takeover_risk": detect_dependency_takeover_risk,
    "detect_supply_chain_impersonation": detect_supply_chain_impersonation,
}

TOOL_DESCRIPTIONS = {
    "predict_pre_cve_collapse": "Find npm dependencies silently dying before any CVE exists using GitHub SBOM, deps.dev, Scorecard, commits, releases, and OSV.",
    "detect_active_exploitation": "Cross-reference exact repository npm package versions against OSV CVEs and CISA KEV active exploitation intelligence.",
    "audit_negligence_window": "Find non-bot commits that happened after a CVE was publicly disclosed or after CISA KEV weaponization.",
    "detect_dependency_takeover_risk": "Detect anomalous npm publish bursts after long silence, including the ua-parser-js takeover reference pattern.",
    "detect_supply_chain_impersonation": "Cross-reference SBOM packages against CISA KEV supply-chain poisoning entries and npm ecosystem warnings.",
}

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "owner": {
            "type": "string",
            "description": "GitHub repository owner, for example parse-community",
        },
        "repo": {
            "type": "string",
            "description": "GitHub repository name, for example parse-server",
        },
    },
    "required": ["owner", "repo"],
}


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name=name,
            description=TOOL_DESCRIPTIONS[name],
            inputSchema=INPUT_SCHEMA,
        )
        for name in TOOL_FUNCTIONS
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[types.TextContent]:
    args = arguments or {}
    owner = str(args.get("owner", "")).strip()
    repo = str(args.get("repo", "")).strip()
    if not owner or not repo:
        payload = {"error": "owner and repo are required string arguments"}
    elif name not in TOOL_FUNCTIONS:
        payload = {"error": f"Unknown tool: {name}"}
    else:
        try:
            payload = TOOL_FUNCTIONS[name](owner, repo)
        except Exception as exc:
            payload = {"error": str(exc), "tool": name, "repo": f"{owner}/{repo}"}
    return [
        types.TextContent(
            type="text",
            text=json.dumps(payload, indent=2, ensure_ascii=False),
        )
    ]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
