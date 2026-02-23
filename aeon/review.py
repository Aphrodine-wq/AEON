"""AEON Code Review — AI-powered code review for PRs and commits.

Orchestrates AEON's analysis engines into a coherent, human-readable
code review report. Designed to be the smartest reviewer on your team.

Usage:
    aeon review app.py                 # Full review of a file
    aeon review --diff HEAD~1          # Review the last commit
    aeon review src/ --format markdown # Markdown report for PR comment
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from aeon.explain import explain_all, format_explanations
from aeon.formatters import (
    format_pretty, format_markdown, ICON_ERROR, ICON_WARNING,
    ICON_OK, ICON_FIX, bold, dim, red, yellow, green, cyan, magenta,
)


@dataclass
class ReviewFinding:
    """A single finding in a code review."""
    severity: str  # "critical", "error", "warning", "suggestion"
    category: str  # "security", "correctness", "performance", "style"
    title: str
    description: str
    file: str
    line: Optional[int] = None
    suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "file": self.file,
        }
        if self.line is not None:
            d["line"] = self.line
        if self.suggestion:
            d["suggestion"] = self.suggestion
        return d


@dataclass
class ReviewReport:
    """Complete code review report."""
    files_reviewed: List[str] = field(default_factory=list)
    findings: List[ReviewFinding] = field(default_factory=list)
    summary: str = ""
    overall_grade: str = ""  # "A", "B", "C", "D", "F"
    stats: Dict[str, int] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in ("critical", "error"))

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")

    @property
    def suggestion_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "suggestion")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_reviewed": self.files_reviewed,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "overall_grade": self.overall_grade,
            "stats": self.stats,
        }


# ── Review Engine ───────────────────────────────────────────────────────

class ReviewEngine:
    """Orchestrates AEON analysis engines into a code review."""

    def __init__(self, deep_verify: bool = True):
        self.deep_verify = deep_verify

    def review_file(self, filepath: str) -> ReviewReport:
        """Review a single file."""
        if not os.path.isfile(filepath):
            report = ReviewReport()
            report.summary = f"File not found: {filepath}"
            return report

        with open(filepath, "r") as f:
            source = f.read()

        language = self._detect_language(filepath)
        result = self._verify(source, language, filepath)

        findings = self._result_to_findings(result, filepath)
        report = self._build_report([filepath], findings)
        return report

    def review_files(self, filepaths: List[str]) -> ReviewReport:
        """Review multiple files."""
        all_findings: List[ReviewFinding] = []

        for filepath in filepaths:
            if not os.path.isfile(filepath):
                continue
            with open(filepath, "r") as f:
                source = f.read()
            language = self._detect_language(filepath)
            result = self._verify(source, language, filepath)
            findings = self._result_to_findings(result, filepath)
            all_findings.extend(findings)

        return self._build_report(filepaths, all_findings)

    def review_directory(self, dirpath: str) -> ReviewReport:
        """Review all supported files in a directory."""
        from aeon.scanner import discover_files
        files = discover_files(dirpath)
        return self.review_files(files)

    def review_diff(self, diff_ref: str = "HEAD~1", cwd: str = ".") -> ReviewReport:
        """Review only the files changed in a git diff."""
        changed_files = self._get_changed_files(diff_ref, cwd)
        if not changed_files:
            report = ReviewReport()
            report.summary = "No changed files found."
            report.overall_grade = "A"
            return report

        abs_files = [os.path.join(cwd, f) for f in changed_files if os.path.isfile(os.path.join(cwd, f))]
        return self.review_files(abs_files)

    # ── Internal ────────────────────────────────────────────────────────

    def _verify(self, source: str, language: str, filepath: str) -> Dict[str, Any]:
        """Run AEON verification."""
        try:
            if language == "aeon":
                from aeon.parser import parse
                from aeon.pass1_prove import prove
                program = parse(source, filename=filepath)
                errors = prove(program, deep_verify=self.deep_verify)
                error_list = []
                warning_list = []
                for e in errors:
                    d = e.to_dict()
                    if e.kind.value in ("type_error", "ownership_error", "contract_error"):
                        error_list.append(d)
                    else:
                        warning_list.append(d)
                return {
                    "verified": len(error_list) == 0,
                    "errors": error_list,
                    "warnings": warning_list,
                }
            else:
                from aeon.language_adapter import verify
                result = verify(source, language, deep_verify=self.deep_verify)
                return result.to_dict()
        except Exception as e:
            return {"verified": False, "errors": [{"message": str(e)}], "warnings": []}

    def _result_to_findings(
        self, result: Dict[str, Any], filepath: str
    ) -> List[ReviewFinding]:
        """Convert verification results to review findings."""
        findings: List[ReviewFinding] = []

        explanations = explain_all(result)
        for exp in explanations:
            loc = exp.get("location", {})
            line = loc.get("line") if loc else None

            severity = self._map_severity(exp.get("severity", "warning"))
            category = self._categorize(exp)

            findings.append(ReviewFinding(
                severity=severity,
                category=category,
                title=exp.get("title", "Issue"),
                description=exp.get("why", exp.get("explanation", "")),
                file=filepath,
                line=line,
                suggestion=exp.get("fix"),
            ))

        return findings

    def _build_report(
        self, files: List[str], findings: List[ReviewFinding]
    ) -> ReviewReport:
        """Build a complete review report."""
        report = ReviewReport(
            files_reviewed=files,
            findings=findings,
        )

        # Calculate grade
        critical = report.critical_count
        errors = report.error_count
        warnings = report.warning_count
        total_issues = critical + errors + warnings

        if total_issues == 0:
            report.overall_grade = "A"
            report.summary = "Excellent — no issues found."
        elif critical > 0:
            report.overall_grade = "F"
            report.summary = f"Critical issues found: {critical} critical, {errors} errors, {warnings} warnings."
        elif errors > 2:
            report.overall_grade = "D"
            report.summary = f"Significant issues: {errors} errors, {warnings} warnings."
        elif errors > 0:
            report.overall_grade = "C"
            report.summary = f"Some issues: {errors} errors, {warnings} warnings."
        elif warnings > 3:
            report.overall_grade = "B"
            report.summary = f"Minor issues: {warnings} warnings."
        else:
            report.overall_grade = "A" if warnings == 0 else "B"
            report.summary = f"Good — {warnings} minor warning(s)." if warnings else "Clean."

        report.stats = {
            "files_reviewed": len(files),
            "critical": critical,
            "errors": errors,
            "warnings": warnings,
            "suggestions": report.suggestion_count,
        }

        return report

    def _map_severity(self, severity: str) -> str:
        """Map explain severity to review severity."""
        if severity == "error":
            return "error"
        return "warning"

    def _categorize(self, explanation: Dict[str, Any]) -> str:
        """Categorize a finding."""
        title = explanation.get("title", "").lower()
        if any(k in title for k in ["injection", "taint", "leak", "secret", "sensitive"]):
            return "security"
        if any(k in title for k in ["race", "deadlock", "concurrent"]):
            return "concurrency"
        if any(k in title for k in ["overflow", "termination", "complexity"]):
            return "performance"
        if any(k in title for k in ["unreachable", "dead code"]):
            return "style"
        return "correctness"

    def _detect_language(self, filepath: str) -> str:
        """Detect language from file extension."""
        ext = os.path.splitext(filepath)[1].lower()
        lang_map = {
            ".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript",
            ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust",
            ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".rb": "ruby",
            ".swift": "swift", ".kt": "kotlin", ".php": "php", ".scala": "scala",
            ".dart": "dart", ".aeon": "aeon",
        }
        return lang_map.get(ext, "python")

    def _get_changed_files(self, diff_ref: str, cwd: str) -> List[str]:
        """Get list of changed files from git diff."""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", diff_ref],
                capture_output=True, text=True, cwd=cwd,
            )
            if result.returncode != 0:
                return []
            return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        except (FileNotFoundError, subprocess.SubprocessError):
            return []


# ── Formatters ──────────────────────────────────────────────────────────

def format_review_pretty(report: ReviewReport) -> str:
    """Format a review report for terminal output."""
    lines: List[str] = []

    grade_colors = {"A": green, "B": green, "C": yellow, "D": red, "F": red}
    color_fn = grade_colors.get(report.overall_grade, dim)

    lines.append(f"\n {bold('AEON Code Review')}")
    lines.append(f" {dim('─' * 55)}")
    lines.append(f" Grade: {color_fn(bold(report.overall_grade))}  ·  {report.summary}")
    lines.append(f" Files reviewed: {len(report.files_reviewed)}")
    lines.append(f" {dim('─' * 55)}")

    if not report.findings:
        lines.append(f"\n {ICON_OK}  {green('No issues found. Ship it!')}\n")
        return "\n".join(lines)

    # Group by file
    by_file: Dict[str, List[ReviewFinding]] = {}
    for f in report.findings:
        by_file.setdefault(f.file, []).append(f)

    for filepath, findings in by_file.items():
        lines.append(f"\n {bold(filepath)}")
        for f in findings:
            icon = ICON_ERROR if f.severity in ("critical", "error") else ICON_WARNING
            loc = f"L{f.line}" if f.line else ""
            lines.append(f"   {icon}  {dim(loc + '  ') if loc else ''}{f.title}")
            lines.append(f"      {dim(f.description[:120])}")
            if f.suggestion:
                # Show first line of suggestion
                first_line = f.suggestion.split("\n")[0]
                lines.append(f"      {ICON_FIX}  {dim('Fix:')} {first_line}")

    lines.append(f"\n {dim('─' * 55)}")
    stats = report.stats
    lines.append(
        f" {red(str(stats.get('errors', 0)))} errors  ·  "
        f"{yellow(str(stats.get('warnings', 0)))} warnings  ·  "
        f"{cyan(str(stats.get('suggestions', 0)))} suggestions\n"
    )

    return "\n".join(lines)


def format_review_markdown(report: ReviewReport) -> str:
    """Format a review report as Markdown for PR comments."""
    lines: List[str] = []

    grade_emoji = {"A": "🟢", "B": "🟡", "C": "🟠", "D": "🔴", "F": "🔴"}
    emoji = grade_emoji.get(report.overall_grade, "⚪")

    lines.append(f"## {emoji} AEON Code Review: Grade {report.overall_grade}")
    lines.append("")
    lines.append(f"> {report.summary}")
    lines.append("")

    if not report.findings:
        lines.append("✅ No issues found. LGTM!")
        return "\n".join(lines)

    # Stats
    lines.append(f"**{report.stats.get('errors', 0)}** errors · "
                 f"**{report.stats.get('warnings', 0)}** warnings · "
                 f"**{report.stats.get('suggestions', 0)}** suggestions")
    lines.append("")

    # Findings table
    lines.append("### Findings")
    lines.append("")
    lines.append("| Severity | File | Line | Issue | Category |")
    lines.append("|----------|------|------|-------|----------|")

    for f in report.findings:
        sev_icon = "🔴" if f.severity in ("critical", "error") else "🟡"
        loc = str(f.line) if f.line else "—"
        title = f.title.replace("|", "\\|")
        lines.append(f"| {sev_icon} {f.severity} | `{os.path.basename(f.file)}` | {loc} | {title} | {f.category} |")

    lines.append("")

    # Details
    if any(f.suggestion for f in report.findings):
        lines.append("### Suggested Fixes")
        lines.append("")
        for i, f in enumerate(report.findings, 1):
            if f.suggestion:
                lines.append(f"**{i}. {f.title}** (`{os.path.basename(f.file)}:{f.line or '?'}`)")
                lines.append(f"```")
                lines.append(f.suggestion)
                lines.append(f"```")
                lines.append("")

    return "\n".join(lines)
