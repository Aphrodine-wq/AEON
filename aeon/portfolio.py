"""AEON Portfolio Scanner — Multi-Project Verification.

Scans all projects defined in ~/.aeon-portfolio.yml with the right
profile for each.  One command, all projects, right settings.

Usage:
    aeon portfolio                    # Scan all projects
    aeon portfolio --project ftw      # Scan one project by alias
    aeon portfolio --summary          # Quick summary only
    aeon portfolio --json             # Machine-readable output

Example ~/.aeon-portfolio.yml:

    projects:
      ftw:
        path: ~/Desktop/FairTradeWorker/FairEstimator
        profile: security
        description: Two-sided marketplace

      fairestimator:
        path: ~/Desktop/WORK/Projects/IN House/FairEstimator
        profile: security
        description: Construction estimation SaaS

      constructionai:
        path: ~/Desktop/WORK/Projects/IN House/ConstructionAI
        profile: daily
        description: Fine-tuned construction LLM

      driftlands:
        path: ~/Desktop/WORK/Projects/IN House/Driftlands
        profile: safety
        description: Rust/Bevy survival game

      claude-eyes:
        path: ~/Desktop/WORK/Projects/IN House/Claude See ME
        profile: security
        description: Screen awareness MCP

      walt:
        path: ~/Desktop/WORK/Projects/IN House/ears
        profile: security
        description: Voice AI system
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any

from aeon.scanner import scan_directory, ScanResult
from aeon.config import load_config, AeonConfig, _parse_simple_yaml


# ---------------------------------------------------------------------------
# Portfolio Config
# ---------------------------------------------------------------------------

_PORTFOLIO_PATHS = [
    os.path.expanduser("~/.aeon-portfolio.yml"),
    os.path.expanduser("~/.aeon-portfolio.yaml"),
    os.path.expanduser("~/.aeon-portfolio.json"),
    os.path.expanduser("~/.config/aeon/portfolio.yml"),
]


@dataclass
class ProjectEntry:
    """A project in the portfolio."""
    alias: str
    path: str
    profile: str = "daily"
    description: str = ""


@dataclass
class PortfolioConfig:
    """Portfolio configuration."""
    projects: List[ProjectEntry] = field(default_factory=list)


@dataclass
class ProjectResult:
    """Results from scanning a single project."""
    alias: str
    path: str
    profile: str
    description: str
    scan: Optional[ScanResult] = None
    error: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class PortfolioResult:
    """Aggregated results from scanning all projects."""
    projects: List[ProjectResult] = field(default_factory=list)
    total_files: int = 0
    total_errors: int = 0
    total_warnings: int = 0
    total_functions: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        results = []
        for pr in self.projects:
            entry: Dict[str, Any] = {
                "alias": pr.alias,
                "path": pr.path,
                "profile": pr.profile,
                "description": pr.description,
                "duration_ms": pr.duration_ms,
            }
            if pr.error:
                entry["error"] = pr.error
            elif pr.scan:
                entry["files_scanned"] = pr.scan.files_scanned
                entry["errors"] = pr.scan.total_errors
                entry["warnings"] = pr.scan.total_warnings
                entry["functions"] = pr.scan.total_functions
                entry["languages"] = pr.scan.languages
            results.append(entry)

        return {
            "projects": results,
            "total_files": self.total_files,
            "total_errors": self.total_errors,
            "total_warnings": self.total_warnings,
            "total_functions": self.total_functions,
            "duration_ms": self.duration_ms,
        }


# ---------------------------------------------------------------------------
# Config Loading
# ---------------------------------------------------------------------------

def find_portfolio_config() -> Optional[str]:
    """Find the portfolio config file."""
    for path in _PORTFOLIO_PATHS:
        if os.path.isfile(path):
            return path
    return None


def load_portfolio(path: Optional[str] = None) -> PortfolioConfig:
    """Load portfolio configuration."""
    if path is None:
        path = find_portfolio_config()

    if path is None:
        return PortfolioConfig()

    try:
        with open(path, "r") as f:
            content = f.read()
    except (IOError, OSError):
        return PortfolioConfig()

    if path.endswith(".json"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return PortfolioConfig()
    else:
        data = _parse_simple_yaml(content)

    return _dict_to_portfolio(data)


def _dict_to_portfolio(data: Dict[str, Any]) -> PortfolioConfig:
    """Convert parsed dict to PortfolioConfig."""
    config = PortfolioConfig()

    projects = data.get("projects", {})
    if isinstance(projects, dict):
        for alias, info in projects.items():
            if isinstance(info, dict):
                path = str(info.get("path", ""))
                path = os.path.expanduser(path)
                config.projects.append(ProjectEntry(
                    alias=str(alias),
                    path=path,
                    profile=str(info.get("profile", "daily")),
                    description=str(info.get("description", "")),
                ))
    elif isinstance(projects, list):
        for item in projects:
            if isinstance(item, dict):
                path = str(item.get("path", ""))
                path = os.path.expanduser(path)
                config.projects.append(ProjectEntry(
                    alias=str(item.get("alias", item.get("name", ""))),
                    path=path,
                    profile=str(item.get("profile", "daily")),
                    description=str(item.get("description", "")),
                ))

    return config


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_portfolio(config: Optional[PortfolioConfig] = None,
                   project_filter: Optional[str] = None,
                   quality_filter: bool = False,
                   min_confidence: float = 0.3) -> PortfolioResult:
    """Scan all projects in the portfolio.

    Args:
        config: Portfolio config (loads from file if not provided)
        project_filter: Only scan this project alias (case-insensitive)
    """
    if config is None:
        config = load_portfolio()

    result = PortfolioResult()
    start = time.time()

    for entry in config.projects:
        # Filter if requested
        if project_filter and entry.alias.lower() != project_filter.lower():
            continue

        pr = ProjectResult(
            alias=entry.alias,
            path=entry.path,
            profile=entry.profile,
            description=entry.description,
        )

        if not os.path.isdir(entry.path):
            pr.error = f"Directory not found: {entry.path}"
            result.projects.append(pr)
            continue

        proj_start = time.time()

        try:
            # Load project-local config if available
            local_config = load_config(start_dir=entry.path)

            # Profile from portfolio overrides local if set
            deep = local_config.deep_verify
            profile = entry.profile or local_config.profile or "daily"

            # Resolve profile to deep_verify
            if profile == "safety":
                deep = True

            scan = scan_directory(
                entry.path,
                deep_verify=deep,
            )

            # Apply quality filtering if requested
            if quality_filter:
                from aeon.scanner import apply_quality_filter
                scan = apply_quality_filter(scan, min_confidence=min_confidence)

            pr.scan = scan
            pr.duration_ms = round((time.time() - proj_start) * 1000, 1)

            result.total_files += scan.files_scanned
            result.total_errors += scan.total_errors
            result.total_warnings += scan.total_warnings
            result.total_functions += scan.total_functions

        except Exception as e:
            pr.error = str(e)
            pr.duration_ms = round((time.time() - proj_start) * 1000, 1)

        result.projects.append(pr)

    result.duration_ms = round((time.time() - start) * 1000, 1)
    return result


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def format_portfolio_pretty(result: PortfolioResult) -> str:
    """Format portfolio results for terminal display."""
    lines: List[str] = []

    lines.append("")
    lines.append("  AEON Portfolio Scan")
    lines.append("  " + "=" * 58)
    lines.append("")

    for pr in result.projects:
        if pr.error:
            status = "!!"
            detail = pr.error
        elif pr.scan:
            if pr.scan.total_errors == 0:
                status = "OK"
            else:
                status = "!!"
            detail = (
                f"{pr.scan.files_scanned} files, "
                f"{pr.scan.total_errors} errors, "
                f"{pr.scan.total_warnings} warnings"
            )
            if pr.scan.languages:
                langs = ", ".join(sorted(pr.scan.languages.keys()))
                detail += f" [{langs}]"
        else:
            status = "??"
            detail = "No results"

        icon = "+" if status == "OK" else "x" if status == "!!" else "?"
        alias_padded = pr.alias.ljust(18)
        profile_padded = f"[{pr.profile}]".ljust(16)

        lines.append(f"  [{icon}] {alias_padded} {profile_padded} {detail}")

        if pr.description:
            lines.append(f"      {pr.description}")
        lines.append(f"      {pr.path} ({pr.duration_ms}ms)")
        lines.append("")

    lines.append("  " + "-" * 58)
    lines.append(
        f"  Total: {result.total_files} files, "
        f"{result.total_errors} errors, "
        f"{result.total_warnings} warnings, "
        f"{result.total_functions} functions"
    )
    lines.append(f"  Duration: {result.duration_ms}ms")
    lines.append("")

    if result.total_errors == 0:
        lines.append("  ALL PROJECTS VERIFIED")
    else:
        error_projects = [
            pr.alias for pr in result.projects
            if pr.scan and pr.scan.total_errors > 0
        ]
        lines.append(
            f"  {result.total_errors} error(s) in: "
            f"{', '.join(error_projects)}"
        )

    lines.append("")
    return "\n".join(lines)


def format_portfolio_summary(result: PortfolioResult) -> str:
    """One-line-per-project summary."""
    lines: List[str] = []
    for pr in result.projects:
        if pr.error:
            lines.append(f"  !! {pr.alias}: {pr.error}")
        elif pr.scan:
            icon = "+" if pr.scan.total_errors == 0 else "x"
            lines.append(
                f"  [{icon}] {pr.alias}: "
                f"{pr.scan.files_scanned}f "
                f"{pr.scan.total_errors}e "
                f"{pr.scan.total_warnings}w "
                f"({pr.duration_ms}ms)"
            )
    lines.append(f"  --- {result.total_errors} total errors across {len(result.projects)} projects")
    return "\n".join(lines)
