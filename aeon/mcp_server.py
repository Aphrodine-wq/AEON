"""AEON MCP Server — Inline formal verification for Claude Code conversations.

Exposes AEON scan/check as MCP tools so Claude can verify code mid-conversation
without shelling out to the CLI.

Tools:
  aeon_check_file    — Verify a single file (quick, returns findings)
  aeon_scan_dir      — Scan a directory (with profile + baseline support)
  aeon_check_snippet — Verify a code snippet (paste code, get findings)
  aeon_explain       — Plain-English explanation of a finding
  aeon_portfolio     — Scan all registered projects

Usage in Claude Code settings.json:
  {
    "mcpServers": {
      "aeon": {
        "command": "/Users/jameswalton/Desktop/WORK/Projects/IN House/AEON/.venv/bin/python3.12",
        "args": ["/Users/jameswalton/Desktop/WORK/Projects/IN House/AEON/aeon/mcp_server.py"]
      }
    }
  }
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

# Add parent to path so we can import aeon modules
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

from aeon.scanner import scan_directory
from aeon.config import load_config
from aeon.baseline import load_baseline, filter_new_findings


def _scan_result_to_summary(result) -> str:
    """Convert a ScanResult to a human-readable summary."""
    lines = []
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Files verified: {result.files_verified}")
    lines.append(f"Errors: {result.total_errors}")
    lines.append(f"Warnings: {result.total_warnings}")
    lines.append("")

    if result.total_errors == 0 and result.total_warnings == 0:
        lines.append("No issues found.")
        return "\n".join(lines)

    # Group by severity
    for fr in result.file_results:
        if fr.errors > 0 or fr.warnings > 0:
            lines.append(f"--- {fr.file} ({fr.errors} errors, {fr.warnings} warnings) ---")
            for finding in getattr(fr, 'findings', []):
                severity = getattr(finding, 'severity', 'warning').upper()
                message = getattr(finding, 'message', str(finding))
                line_num = getattr(finding, 'line', '?')
                lines.append(f"  [{severity}] line {line_num}: {message}")

    return "\n".join(lines)


def create_server():
    server = Server("aeon")

    @server.list_tools()
    async def list_tools():
        return [
            Tool(
                name="aeon_check_file",
                description="Verify a single file with AEON formal verification. Returns findings (taint flows, division-by-zero, injection risks, etc.)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to the file to verify"
                        },
                        "profile": {
                            "type": "string",
                            "description": "Analysis profile: quick, daily, security, construction, safety",
                            "default": "quick"
                        }
                    },
                    "required": ["file_path"]
                }
            ),
            Tool(
                name="aeon_scan_dir",
                description="Scan a directory with AEON. Uses project .aeonrc.yml if present. Supports baseline filtering (only new issues).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "directory": {
                            "type": "string",
                            "description": "Absolute path to directory to scan"
                        },
                        "profile": {
                            "type": "string",
                            "description": "Analysis profile (overrides .aeonrc.yml)",
                            "default": ""
                        },
                        "use_baseline": {
                            "type": "boolean",
                            "description": "If true, filter out known baseline issues",
                            "default": True
                        }
                    },
                    "required": ["directory"]
                }
            ),
            Tool(
                name="aeon_check_snippet",
                description="Verify a code snippet. Paste code directly and get formal verification findings.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The code to verify"
                        },
                        "language": {
                            "type": "string",
                            "description": "Language: python, typescript, javascript, rust, go, java, swift",
                            "default": "typescript"
                        },
                        "profile": {
                            "type": "string",
                            "description": "Analysis profile",
                            "default": "security"
                        }
                    },
                    "required": ["code"]
                }
            ),
            Tool(
                name="aeon_portfolio",
                description="Scan all registered projects from ~/.aeon-portfolio.yml. Returns summary of findings across all projects.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "project": {
                            "type": "string",
                            "description": "Scan only this project alias (e.g. 'mhp', 'ftw'). Omit to scan all.",
                            "default": ""
                        }
                    }
                }
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        try:
            if name == "aeon_check_file":
                return await _handle_check_file(arguments)
            elif name == "aeon_scan_dir":
                return await _handle_scan_dir(arguments)
            elif name == "aeon_check_snippet":
                return await _handle_check_snippet(arguments)
            elif name == "aeon_portfolio":
                return await _handle_portfolio(arguments)
            else:
                return [TextContent(type="text", text=f"Unknown tool: {name}")]
        except Exception as e:
            return [TextContent(type="text", text=f"AEON error: {e}\n{traceback.format_exc()}")]

    async def _handle_check_file(args):
        file_path = args["file_path"]
        profile = args.get("profile", "quick")

        if not os.path.isfile(file_path):
            return [TextContent(type="text", text=f"File not found: {file_path}")]

        # Scan the parent directory but only include this file
        parent = os.path.dirname(file_path)
        filename = os.path.basename(file_path)

        config = load_config(start_dir=parent)
        if profile:
            config.profile = profile

        result = scan_directory(parent, config=config)

        # Filter to just this file
        file_findings = [fr for fr in result.file_results if fr.file == filename]
        if not file_findings:
            return [TextContent(type="text", text=f"No findings for {filename}")]

        summary = _scan_result_to_summary(result)
        return [TextContent(type="text", text=summary)]

    async def _handle_scan_dir(args):
        directory = args["directory"]
        profile = args.get("profile", "")
        use_baseline = args.get("use_baseline", True)

        if not os.path.isdir(directory):
            return [TextContent(type="text", text=f"Directory not found: {directory}")]

        config = load_config(start_dir=directory)
        if profile:
            config.profile = profile

        result = scan_directory(directory, config=config)

        # Filter against baseline if requested
        if use_baseline:
            baseline_path = os.path.join(directory, ".aeon-baseline.json")
            if os.path.isfile(baseline_path):
                baseline = load_baseline(baseline_path)
                result = filter_new_findings(result, baseline)

        summary = _scan_result_to_summary(result)
        return [TextContent(type="text", text=summary)]

    async def _handle_check_snippet(args):
        code = args["code"]
        language = args.get("language", "typescript")
        profile = args.get("profile", "security")

        ext_map = {
            "python": ".py", "typescript": ".ts", "javascript": ".js",
            "rust": ".rs", "go": ".go", "java": ".java", "swift": ".swift",
        }
        ext = ext_map.get(language, ".ts")

        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, dir="/tmp") as f:
            f.write(code)
            tmp_path = f.name

        try:
            config = load_config()
            config.profile = profile
            result = scan_directory(os.path.dirname(tmp_path), config=config)
            summary = _scan_result_to_summary(result)
            return [TextContent(type="text", text=summary)]
        finally:
            os.unlink(tmp_path)

    async def _handle_portfolio(args):
        from aeon.portfolio import load_portfolio, scan_project

        portfolio = load_portfolio()
        if not portfolio or not portfolio.projects:
            return [TextContent(type="text", text="No portfolio found. Create ~/.aeon-portfolio.yml")]

        target = args.get("project", "")
        projects = portfolio.projects
        if target:
            projects = [p for p in projects if p.alias == target]
            if not projects:
                aliases = ", ".join(p.alias for p in portfolio.projects)
                return [TextContent(type="text", text=f"Project '{target}' not found. Available: {aliases}")]

        lines = ["AEON Portfolio Scan", "=" * 40, ""]
        for proj in projects:
            try:
                result = scan_project(proj)
                status = "CLEAN" if result.total_errors == 0 else f"{result.total_errors} ERRORS"
                lines.append(f"{proj.alias}: {result.files_scanned} files, {status}, {result.total_warnings} warnings")
            except Exception as e:
                lines.append(f"{proj.alias}: SCAN FAILED — {e}")

        return [TextContent(type="text", text="\n".join(lines))]

    return server


async def main():
    if not HAS_MCP:
        print("MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
        sys.exit(1)

    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
