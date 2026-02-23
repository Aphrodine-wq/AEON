"""AEON Output Formatters — Human-friendly terminal output.

Provides multiple output modes:
    pretty   — colored, grouped by file, severity icons (default)
    summary  — one-line pass/fail per function
    annotate — source with inline comments showing issues
    markdown — for pasting into PRs / docs
    json     — machine-readable (existing behavior)
    sarif    — GitHub Code Scanning (existing behavior)
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Union


# ── ANSI color helpers ───────────────────────────────────────────────────

_NO_COLOR = os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if _NO_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(t: str) -> str:
    return _c("31", t)


def yellow(t: str) -> str:
    return _c("33", t)


def green(t: str) -> str:
    return _c("32", t)


def cyan(t: str) -> str:
    return _c("36", t)


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


def magenta(t: str) -> str:
    return _c("35", t)


# ── Severity icons ──────────────────────────────────────────────────────

ICON_ERROR = red("✖")
ICON_WARNING = yellow("▲")
ICON_OK = green("✔")
ICON_INFO = cyan("ℹ")
ICON_FIX = magenta("⚡")


# ── Pretty formatter (default) ──────────────────────────────────────────

def format_pretty(result: Dict[str, Any], filepath: Optional[str] = None) -> str:
    """Format a verification result with colors and icons."""
    lines: List[str] = []

    verified = result.get("verified", False)
    errors = result.get("errors", [])
    warnings = result.get("warnings", [])
    summary_text = result.get("summary", "")

    # Header
    if filepath:
        status_icon = ICON_OK if verified else ICON_ERROR
        lines.append(f"\n {status_icon}  {bold(filepath)}")
    else:
        status_icon = ICON_OK if verified else ICON_ERROR
        lines.append(f"\n {status_icon}  {bold(summary_text)}")

    # Errors
    for err in errors:
        loc = _format_location(err, filepath)
        msg = err.get("message", "Unknown error")
        lines.append(f"   {ICON_ERROR}  {loc}{red(msg)}")

        # Show suggestion if available
        suggestion = _extract_suggestion(err)
        if suggestion:
            lines.append(f"      {ICON_FIX}  {dim('Fix:')} {suggestion}")

        # Show function context if available
        func_sig = err.get("details", {}).get("function_signature", "")
        if func_sig:
            lines.append(f"      {dim('in')} {cyan(func_sig)}")

    # Warnings
    for warn in warnings:
        loc = _format_location(warn, filepath)
        msg = warn.get("message", "Warning")
        lines.append(f"   {ICON_WARNING}  {loc}{yellow(msg)}")

    # Footer summary
    err_count = len(errors)
    warn_count = len(warnings)
    if verified and err_count == 0:
        lines.append(f"\n   {green('No issues found.')}\n")
    else:
        parts = []
        if err_count:
            parts.append(red(f"{err_count} error{'s' if err_count != 1 else ''}"))
        if warn_count:
            parts.append(yellow(f"{warn_count} warning{'s' if warn_count != 1 else ''}"))
        lines.append(f"\n   {' · '.join(parts)}\n")

    return "\n".join(lines)


def format_pretty_scan(scan_result: Any) -> str:
    """Format a directory scan result with colors and icons."""
    lines: List[str] = []

    total_errors = getattr(scan_result, "total_errors", 0)
    total_warnings = getattr(scan_result, "total_warnings", 0)
    total_files = getattr(scan_result, "total_files", 0)
    verified_files = getattr(scan_result, "verified_files", 0)
    file_results = getattr(scan_result, "file_results", [])

    # Header
    lines.append(f"\n {bold('AEON Scan Results')}")
    lines.append(f" {dim('─' * 50)}")

    # Per-file results
    for fr in file_results:
        fpath = fr.get("file", "?")
        f_verified = fr.get("verified", False)
        f_errors = fr.get("errors", 0)
        f_warnings = fr.get("warnings", 0)

        icon = ICON_OK if f_verified else ICON_ERROR
        detail = ""
        if f_errors:
            detail += red(f" {f_errors} error{'s' if f_errors != 1 else ''}")
        if f_warnings:
            detail += yellow(f" {f_warnings} warning{'s' if f_warnings != 1 else ''}")

        lines.append(f"   {icon}  {fpath}{detail}")

    # Summary
    lines.append(f" {dim('─' * 50)}")
    lines.append(
        f"   {bold('Files:')} {verified_files}/{total_files} verified  ·  "
        f"{red(str(total_errors))} errors  ·  "
        f"{yellow(str(total_warnings))} warnings\n"
    )

    return "\n".join(lines)


# ── Summary formatter ───────────────────────────────────────────────────

def format_summary(result: Dict[str, Any], filepath: Optional[str] = None) -> str:
    """One-line pass/fail summary."""
    verified = result.get("verified", False)
    errors = result.get("errors", [])
    warnings = result.get("warnings", [])
    name = filepath or "<stdin>"

    err_count = len(errors)
    warn_count = len(warnings)

    if verified:
        return f"{ICON_OK}  {name}  —  {green('PASS')}"
    else:
        parts = []
        if err_count:
            parts.append(f"{err_count} error{'s' if err_count != 1 else ''}")
        if warn_count:
            parts.append(f"{warn_count} warning{'s' if warn_count != 1 else ''}")
        detail = ", ".join(parts)
        return f"{ICON_ERROR}  {name}  —  {red('FAIL')}  ({detail})"


# ── Annotated source formatter ──────────────────────────────────────────

def format_annotated(
    source: str, result: Dict[str, Any], filepath: Optional[str] = None
) -> str:
    """Print source code with inline annotations for each issue."""
    lines: List[str] = []
    source_lines = source.splitlines()

    # Build a map: line_number -> list of messages
    annotations: Dict[int, List[str]] = {}
    for err in result.get("errors", []):
        lineno = err.get("location", {}).get("line", 0)
        msg = err.get("message", "error")
        annotations.setdefault(lineno, []).append(f"{ICON_ERROR} {red(msg)}")
    for warn in result.get("warnings", []):
        lineno = warn.get("location", {}).get("line", 0)
        msg = warn.get("message", "warning")
        annotations.setdefault(lineno, []).append(f"{ICON_WARNING} {yellow(msg)}")

    if filepath:
        lines.append(f"\n{dim('──')} {bold(filepath)} {dim('──')}\n")

    for i, src_line in enumerate(source_lines, start=1):
        line_num = dim(f"{i:4d} │ ")
        lines.append(f"{line_num}{src_line}")
        if i in annotations:
            for ann in annotations[i]:
                lines.append(f"     {dim('│')}  {ann}")

    return "\n".join(lines)


# ── Markdown formatter ──────────────────────────────────────────────────

def format_markdown(result: Dict[str, Any], filepath: Optional[str] = None) -> str:
    """Format results as Markdown for PR comments / docs."""
    lines: List[str] = []

    verified = result.get("verified", False)
    errors = result.get("errors", [])
    warnings = result.get("warnings", [])

    status = "✅ PASS" if verified else "❌ FAIL"
    heading = f"## AEON Verification: {status}"
    if filepath:
        heading += f" — `{filepath}`"
    lines.append(heading)
    lines.append("")

    if errors:
        lines.append(f"### Errors ({len(errors)})")
        lines.append("")
        lines.append("| # | Location | Message |")
        lines.append("|---|----------|---------|")
        for i, err in enumerate(errors, 1):
            loc = _md_location(err, filepath)
            msg = err.get("message", "").replace("|", "\\|")
            lines.append(f"| {i} | {loc} | {msg} |")
        lines.append("")

    if warnings:
        lines.append(f"### Warnings ({len(warnings)})")
        lines.append("")
        lines.append("| # | Location | Message |")
        lines.append("|---|----------|---------|")
        for i, warn in enumerate(warnings, 1):
            loc = _md_location(warn, filepath)
            msg = warn.get("message", "").replace("|", "\\|")
            lines.append(f"| {i} | {loc} | {msg} |")
        lines.append("")

    if verified:
        lines.append("> No issues found. All verification engines passed.")
    else:
        lines.append(f"> **{len(errors)} error(s)** and **{len(warnings)} warning(s)** detected.")

    return "\n".join(lines)


def format_markdown_scan(scan_result: Any) -> str:
    """Format a directory scan as Markdown."""
    lines: List[str] = []

    total_errors = getattr(scan_result, "total_errors", 0)
    total_warnings = getattr(scan_result, "total_warnings", 0)
    total_files = getattr(scan_result, "total_files", 0)
    verified_files = getattr(scan_result, "verified_files", 0)
    file_results = getattr(scan_result, "file_results", [])

    status = "✅ PASS" if total_errors == 0 else "❌ FAIL"
    lines.append(f"## AEON Scan: {status}")
    lines.append("")
    lines.append(f"**{verified_files}/{total_files}** files verified  ·  "
                 f"**{total_errors}** errors  ·  **{total_warnings}** warnings")
    lines.append("")
    lines.append("| File | Status | Errors | Warnings |")
    lines.append("|------|--------|--------|----------|")
    for fr in file_results:
        fpath = fr.get("file", "?")
        fv = "✅" if fr.get("verified", False) else "❌"
        fe = fr.get("errors", 0)
        fw = fr.get("warnings", 0)
        lines.append(f"| `{fpath}` | {fv} | {fe} | {fw} |")

    return "\n".join(lines)


# ── Helpers ─────────────────────────────────────────────────────────────

def _format_location(err: Dict[str, Any], filepath: Optional[str] = None) -> str:
    loc = err.get("location", {})
    line = loc.get("line")
    col = loc.get("column")
    if line is not None:
        loc_str = f"L{line}"
        if col is not None:
            loc_str += f":{col}"
        return dim(f"{loc_str}  ")
    return ""


def _md_location(err: Dict[str, Any], filepath: Optional[str] = None) -> str:
    loc = err.get("location", {})
    line = loc.get("line")
    col = loc.get("column")
    if line is not None:
        loc_str = f"Line {line}"
        if col is not None:
            loc_str += f":{col}"
        return f"`{loc_str}`"
    return "—"


def _extract_suggestion(err: Dict[str, Any]) -> Optional[str]:
    """Try to extract a fix suggestion from an error's details."""
    details = err.get("details", {})
    for key in ("suggestion", "fix", "fix_suggestion", "recommended_fix"):
        if key in details:
            return str(details[key])
    return None


# ── Dispatcher ──────────────────────────────────────────────────────────

def format_result(
    result: Dict[str, Any],
    fmt: str = "pretty",
    filepath: Optional[str] = None,
    source: Optional[str] = None,
) -> str:
    """Dispatch to the appropriate formatter.

    Args:
        result: Verification result dict (verified, errors, warnings, summary).
        fmt: One of "pretty", "summary", "annotate", "markdown", "json".
        filepath: Optional file path for display context.
        source: Source code text (required for "annotate" mode).
    """
    if fmt == "pretty":
        return format_pretty(result, filepath)
    elif fmt == "summary":
        return format_summary(result, filepath)
    elif fmt == "annotate":
        return format_annotated(source or "", result, filepath)
    elif fmt == "markdown":
        return format_markdown(result, filepath)
    elif fmt == "json":
        return json.dumps(result, indent=2)
    else:
        return format_pretty(result, filepath)
