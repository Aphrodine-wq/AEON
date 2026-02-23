"""AEON SARIF Output — Static Analysis Results Interchange Format.

Produces SARIF 2.1.0 JSON output compatible with:
  - GitHub Code Scanning
  - Azure DevOps
  - VS Code SARIF Viewer
  - Any SARIF-compatible tool

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Usage:
    from aeon.sarif import to_sarif
    sarif_json = to_sarif(scan_result)
"""

from __future__ import annotations

import json
from typing import Optional, List, Dict, Any

from aeon.scanner import ScanResult


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

# Map AEON engine names to SARIF rule IDs
_RULE_MAP = {
    "division by zero": ("AEON001", "Division by Zero", "error"),
    "may not terminate": ("AEON002", "Non-Termination", "warning"),
    "information flow": ("AEON003", "Information Flow Violation", "error"),
    "contract": ("AEON004", "Contract Violation", "error"),
    "use-after-free": ("AEON005", "Use After Free", "error"),
    "double-free": ("AEON006", "Double Free", "error"),
    "memory leak": ("AEON007", "Memory Leak", "warning"),
    "taint": ("AEON008", "Injection Vulnerability", "error"),
    "sql injection": ("AEON008", "SQL Injection", "error"),
    "xss": ("AEON009", "Cross-Site Scripting", "error"),
    "command injection": ("AEON010", "Command Injection", "error"),
    "data race": ("AEON011", "Data Race", "error"),
    "deadlock": ("AEON012", "Deadlock", "error"),
    "atomicity": ("AEON013", "Atomicity Violation", "warning"),
    "cycle creation": ("AEON014", "Cycle in Acyclic Structure", "warning"),
    "assertion": ("AEON015", "Assertion Violation", "error"),
    "type_error": ("AEON100", "Type Error", "error"),
    "effect_error": ("AEON101", "Effect Error", "warning"),
}


def _classify_result(message: str) -> tuple:
    """Classify a result message into (rule_id, rule_name, level)."""
    msg_lower = message.lower()
    for keyword, (rule_id, rule_name, level) in _RULE_MAP.items():
        if keyword in msg_lower:
            return (rule_id, rule_name, level)
    return ("AEON999", "Verification Issue", "warning")


def to_sarif(scan_result: ScanResult, tool_version: str = "0.5.0") -> str:
    """Convert a ScanResult to SARIF 2.1.0 JSON string.

    Args:
        scan_result: Result from scan_directory()
        tool_version: AEON version string

    Returns:
        SARIF JSON string
    """
    results: List[Dict[str, Any]] = []
    rules_seen: Dict[str, Dict[str, Any]] = {}

    for file_result in scan_result.file_results:
        filepath = file_result.get("file", "")
        uri = filepath.replace("\\", "/")

        # Process errors
        for detail in file_result.get("error_details", []):
            message = detail.get("message", detail.get("precondition", str(detail)))
            rule_id, rule_name, level = _classify_result(message)

            # Extract location
            loc = detail.get("location", {})
            line = loc.get("line", 1) if isinstance(loc, dict) else 1
            col = loc.get("column", 1) if isinstance(loc, dict) else 1

            result_obj: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {
                            "startLine": max(1, line),
                            "startColumn": max(1, col),
                        }
                    }
                }],
            }

            # Add failing values as properties
            failing = detail.get("failing_values", {})
            if failing:
                result_obj["properties"] = failing

            results.append(result_obj)

            if rule_id not in rules_seen:
                rules_seen[rule_id] = {
                    "id": rule_id,
                    "name": rule_name,
                    "shortDescription": {"text": rule_name},
                    "defaultConfiguration": {"level": level},
                }

        # Process warnings
        for detail in file_result.get("warning_details", []):
            message = detail.get("message", detail.get("precondition", str(detail)))
            rule_id, rule_name, _ = _classify_result(message)

            loc = detail.get("location", {})
            line = loc.get("line", 1) if isinstance(loc, dict) else 1
            col = loc.get("column", 1) if isinstance(loc, dict) else 1

            result_obj = {
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {
                            "startLine": max(1, line),
                            "startColumn": max(1, col),
                        }
                    }
                }],
            }
            results.append(result_obj)

            if rule_id not in rules_seen:
                rules_seen[rule_id] = {
                    "id": rule_id,
                    "name": rule_name,
                    "shortDescription": {"text": rule_name},
                    "defaultConfiguration": {"level": "warning"},
                }

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AEON",
                    "version": tool_version,
                    "informationUri": "https://github.com/aeon-lang/aeon",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "filesScanned": scan_result.files_scanned,
                    "totalFunctions": scan_result.total_functions,
                    "totalClasses": scan_result.total_classes,
                    "durationMs": scan_result.duration_ms,
                }
            }],
        }],
    }

    return json.dumps(sarif, indent=2)


def to_sarif_from_verification(result, filepath: str = "input",
                                tool_version: str = "0.5.0") -> str:
    """Convert a single VerificationResult to SARIF JSON."""
    scan = ScanResult(
        root=".",
        files_scanned=1,
        file_results=[{
            "file": filepath,
            "language": getattr(result, 'source_language', 'unknown'),
            "verified": result.verified,
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "functions": result.functions_analyzed,
            "classes": result.classes_analyzed,
            "error_details": result.errors,
            "warning_details": result.warnings,
        }],
    )
    return to_sarif(scan, tool_version)
