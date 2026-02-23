"""AEON Baseline — Diff Mode for Incremental Adoption.

Allows teams to adopt AEON on large codebases by establishing a baseline
of known issues and only reporting NEW issues in subsequent runs.

Usage:
    # Create a baseline
    aeon check src/ --deep-verify --baseline .aeon-baseline.json --create-baseline

    # Check only new issues
    aeon check src/ --deep-verify --baseline .aeon-baseline.json
"""

from __future__ import annotations

import json
import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any

from aeon.scanner import ScanResult


@dataclass
class BaselineEntry:
    """A single issue in the baseline."""
    fingerprint: str
    file: str
    rule_id: str
    message: str
    line: int = 0


@dataclass
class Baseline:
    """A baseline of known issues."""
    version: str = "1.0"
    created_at: str = ""
    entries: List[BaselineEntry] = field(default_factory=list)
    fingerprints: Set[str] = field(default_factory=set)

    def contains(self, fingerprint: str) -> bool:
        return fingerprint in self.fingerprints


def _compute_fingerprint(file: str, message: str, line: int = 0) -> str:
    """Compute a stable fingerprint for an issue.

    The fingerprint is based on file + message content (not line number)
    so that it survives minor code movements.
    """
    # Normalize the message for stable fingerprinting
    content = f"{file}:{message}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def create_baseline(scan_result: ScanResult) -> Baseline:
    """Create a baseline from scan results."""
    from datetime import datetime
    baseline = Baseline(
        created_at=datetime.utcnow().isoformat() + "Z",
    )

    for file_result in scan_result.file_results:
        filepath = file_result.get("file", "")

        for detail in file_result.get("error_details", []):
            message = detail.get("message", detail.get("precondition", str(detail)))
            loc = detail.get("location", {})
            line = loc.get("line", 0) if isinstance(loc, dict) else 0
            fp = _compute_fingerprint(filepath, message, line)

            baseline.entries.append(BaselineEntry(
                fingerprint=fp,
                file=filepath,
                rule_id=detail.get("kind", "unknown"),
                message=message,
                line=line,
            ))
            baseline.fingerprints.add(fp)

        for detail in file_result.get("warning_details", []):
            message = detail.get("message", detail.get("precondition", str(detail)))
            loc = detail.get("location", {})
            line = loc.get("line", 0) if isinstance(loc, dict) else 0
            fp = _compute_fingerprint(filepath, message, line)

            baseline.entries.append(BaselineEntry(
                fingerprint=fp,
                file=filepath,
                rule_id=detail.get("kind", "unknown"),
                message=message,
                line=line,
            ))
            baseline.fingerprints.add(fp)

    return baseline


def save_baseline(baseline: Baseline, path: str) -> None:
    """Save a baseline to a JSON file."""
    data = {
        "version": baseline.version,
        "created_at": baseline.created_at,
        "entries": [
            {
                "fingerprint": e.fingerprint,
                "file": e.file,
                "rule_id": e.rule_id,
                "message": e.message,
                "line": e.line,
            }
            for e in baseline.entries
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_baseline(path: str) -> Baseline:
    """Load a baseline from a JSON file."""
    with open(path, "r") as f:
        data = json.load(f)

    baseline = Baseline(
        version=data.get("version", "1.0"),
        created_at=data.get("created_at", ""),
    )
    for entry_data in data.get("entries", []):
        entry = BaselineEntry(
            fingerprint=entry_data["fingerprint"],
            file=entry_data["file"],
            rule_id=entry_data.get("rule_id", ""),
            message=entry_data.get("message", ""),
            line=entry_data.get("line", 0),
        )
        baseline.entries.append(entry)
        baseline.fingerprints.add(entry.fingerprint)

    return baseline


def filter_by_baseline(scan_result: ScanResult, baseline: Baseline) -> ScanResult:
    """Filter scan results to only show NEW issues not in the baseline.

    Returns a new ScanResult with only the new issues.
    """
    filtered = ScanResult(
        root=scan_result.root,
        files_scanned=scan_result.files_scanned,
        languages=dict(scan_result.languages),
        total_functions=scan_result.total_functions,
        total_classes=scan_result.total_classes,
        duration_ms=scan_result.duration_ms,
    )

    for file_result in scan_result.file_results:
        filepath = file_result.get("file", "")
        new_entry: Dict[str, Any] = {
            "file": filepath,
            "language": file_result.get("language", ""),
            "functions": file_result.get("functions", 0),
            "classes": file_result.get("classes", 0),
        }

        new_errors = []
        for detail in file_result.get("error_details", []):
            message = detail.get("message", detail.get("precondition", str(detail)))
            loc = detail.get("location", {})
            line = loc.get("line", 0) if isinstance(loc, dict) else 0
            fp = _compute_fingerprint(filepath, message, line)
            if not baseline.contains(fp):
                new_errors.append(detail)

        new_warnings = []
        for detail in file_result.get("warning_details", []):
            message = detail.get("message", detail.get("precondition", str(detail)))
            loc = detail.get("location", {})
            line = loc.get("line", 0) if isinstance(loc, dict) else 0
            fp = _compute_fingerprint(filepath, message, line)
            if not baseline.contains(fp):
                new_warnings.append(detail)

        new_entry["errors"] = len(new_errors)
        new_entry["warnings"] = len(new_warnings)
        new_entry["verified"] = len(new_errors) == 0
        if new_errors:
            new_entry["error_details"] = new_errors
        if new_warnings:
            new_entry["warning_details"] = new_warnings

        filtered.file_results.append(new_entry)

        if new_errors:
            filtered.files_with_errors += 1
            filtered.total_errors += len(new_errors)
        if new_warnings:
            filtered.files_with_warnings += 1
            filtered.total_warnings += len(new_warnings)
        if not new_errors:
            filtered.files_verified += 1

    # Summary
    baseline_count = len(baseline.entries)
    if filtered.total_errors == 0:
        filtered.summary = (
            f"\u2705 No NEW issues ({baseline_count} baseline issues suppressed)"
        )
    else:
        filtered.summary = (
            f"\u274c {filtered.total_errors} NEW error(s) found "
            f"({baseline_count} baseline issues suppressed)"
        )

    return filtered
