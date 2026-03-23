"""AEON Directory Scanner — Recursive Project Verification.

Scans entire project directories, respects .gitignore, auto-detects
languages from file extensions, and produces aggregated results.

Usage:
    from aeon.scanner import scan_directory
    results = scan_directory("src/", deep_verify=True)
    print(results.summary)
"""

from __future__ import annotations

import os
import fnmatch
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set
from pathlib import Path

from aeon.language_adapter import (
    verify_file, detect_language, VerificationResult,
    _EXT_MAP,
)


# ---------------------------------------------------------------------------
# Gitignore Parser
# ---------------------------------------------------------------------------

def _parse_gitignore(root: str) -> List[str]:
    """Parse .gitignore patterns from a directory."""
    patterns: List[str] = []
    gitignore_path = os.path.join(root, ".gitignore")
    if os.path.isfile(gitignore_path):
        with open(gitignore_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    # Always ignore common directories
    patterns.extend([
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
        "*.pyc", "*.pyo", "*.class", "*.o", "*.so", "*.dylib",
    ])
    return patterns


def _is_ignored(path: str, patterns: List[str], root: str) -> bool:
    """Check if a path matches any gitignore pattern."""
    rel = os.path.relpath(path, root)
    basename = os.path.basename(path)
    for pattern in patterns:
        if fnmatch.fnmatch(basename, pattern):
            return True
        if fnmatch.fnmatch(rel, pattern):
            return True
        if fnmatch.fnmatch(rel, pattern.rstrip("/") + "/*"):
            return True
    return False


# ---------------------------------------------------------------------------
# Scan Result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Aggregated results from scanning a directory."""
    root: str = ""
    files_scanned: int = 0
    files_verified: int = 0
    files_with_errors: int = 0
    files_with_warnings: int = 0
    total_errors: int = 0
    total_warnings: int = 0
    total_functions: int = 0
    total_classes: int = 0
    languages: Dict[str, int] = field(default_factory=dict)
    file_results: List[Dict] = field(default_factory=list)
    summary: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_verified": self.files_verified,
            "files_with_errors": self.files_with_errors,
            "files_with_warnings": self.files_with_warnings,
            "total_errors": self.total_errors,
            "total_warnings": self.total_warnings,
            "total_functions": self.total_functions,
            "total_classes": self.total_classes,
            "languages": self.languages,
            "file_results": self.file_results,
            "summary": self.summary,
            "duration_ms": self.duration_ms,
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def discover_files(root: str, extensions: Optional[Set[str]] = None,
                   ignore_patterns: Optional[List[str]] = None) -> List[str]:
    """Discover source files in a directory tree.

    Args:
        root: Root directory to scan
        extensions: File extensions to include (default: all supported)
        ignore_patterns: Gitignore-style patterns to exclude
    """
    if extensions is None:
        extensions = set(_EXT_MAP.keys())

    if ignore_patterns is None:
        ignore_patterns = _parse_gitignore(root)

    files: List[str] = []
    root = os.path.abspath(root)

    for dirpath, dirnames, filenames in os.walk(root):
        # Filter out ignored directories (in-place to prevent os.walk descent)
        dirnames[:] = [
            d for d in dirnames
            if not _is_ignored(os.path.join(dirpath, d), ignore_patterns, root)
        ]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            ext = os.path.splitext(filename)[1]
            if ext in extensions and not _is_ignored(filepath, ignore_patterns, root):
                files.append(filepath)

    return sorted(files)


def scan_directory(root: str, deep_verify: bool = True,
                   analyses: Optional[List[str]] = None,
                   extensions: Optional[Set[str]] = None,
                   ignore_patterns: Optional[List[str]] = None,
                   prove_kwargs: Optional[Dict] = None) -> ScanResult:
    """Scan and verify all source files in a directory.

    Args:
        root: Root directory to scan
        deep_verify: Enable all analysis engines
        analyses: Specific analyses to run
        extensions: File extensions to include
        ignore_patterns: Patterns to exclude
    """
    import time
    start = time.time()

    result = ScanResult(root=os.path.abspath(root))
    files = discover_files(root, extensions, ignore_patterns)
    result.files_scanned = len(files)

    for filepath in files:
        try:
            lang = detect_language(filepath)
            result.languages[lang] = result.languages.get(lang, 0) + 1

            vr = verify_file(filepath, deep_verify=deep_verify, analyses=analyses, prove_kwargs=prove_kwargs)

            file_entry = {
                "file": os.path.relpath(filepath, root),
                "language": lang,
                "verified": vr.verified,
                "errors": len(vr.errors),
                "warnings": len(vr.warnings),
                "functions": vr.functions_analyzed,
                "classes": vr.classes_analyzed,
                "summary": vr.summary,
            }
            if vr.errors:
                file_entry["error_details"] = vr.errors
            if vr.warnings:
                file_entry["warning_details"] = vr.warnings

            result.file_results.append(file_entry)

            if vr.verified:
                result.files_verified += 1
            if vr.errors:
                result.files_with_errors += 1
                result.total_errors += len(vr.errors)
            if vr.warnings:
                result.files_with_warnings += 1
                result.total_warnings += len(vr.warnings)

            result.total_functions += vr.functions_analyzed
            result.total_classes += vr.classes_analyzed

        except Exception as e:
            result.file_results.append({
                "file": os.path.relpath(filepath, root),
                "error": str(e),
                "verified": False,
            })

    elapsed = (time.time() - start) * 1000
    result.duration_ms = round(elapsed, 1)

    # Build summary
    lang_list = ", ".join(f"{v} {k}" for k, v in sorted(result.languages.items()))
    if result.total_errors == 0:
        result.summary = (
            f"\u2705 ALL VERIFIED: {result.files_scanned} files, "
            f"{result.total_functions} functions, {result.total_classes} classes "
            f"({lang_list}) — {result.duration_ms}ms"
        )
    else:
        result.summary = (
            f"\u274c {result.total_errors} error(s) in {result.files_with_errors} of "
            f"{result.files_scanned} files ({lang_list}) — {result.duration_ms}ms"
        )

    return result


def apply_quality_filter(result: ScanResult,
                         min_confidence: float = 0.3,
                         top_n: int = 0) -> ScanResult:
    """Apply confidence scoring and smart filtering to scan results.

    Transforms raw findings into qualified, deduplicated, prioritized results.
    This is what makes the difference between 38K noise and 200 real findings.

    Args:
        result: Raw scan result
        min_confidence: Minimum confidence threshold (default: 0.3)
        top_n: Only keep top N findings across all files (0=all above threshold)
    """
    try:
        from aeon.engines.finding_quality import FindingQualityAnalyzer
    except ImportError:
        return result  # Finding quality module not available

    analyzer = FindingQualityAnalyzer(min_confidence=min_confidence)
    quality = analyzer.process_scan_results(result.file_results)

    # Replace file results with enriched versions
    filtered = ScanResult(
        root=result.root,
        files_scanned=result.files_scanned,
        files_verified=result.files_verified,
        total_functions=result.total_functions,
        total_classes=result.total_classes,
        languages=result.languages,
        duration_ms=result.duration_ms,
    )

    for enriched_fr in quality["file_results"]:
        filtered.file_results.append(enriched_fr)
        real_e = enriched_fr.get("real_errors", 0)
        real_w = enriched_fr.get("real_warnings", 0)
        if real_e > 0:
            filtered.files_with_errors += 1
            filtered.total_errors += real_e
        if real_w > 0:
            filtered.files_with_warnings += 1
            filtered.total_warnings += real_w

    # Build quality-aware summary
    raw_total = quality["total_raw"]
    real_total = quality["total_real"]
    suppressed = quality["total_suppressed"]
    noise_pct = round(quality["noise_ratio"] * 100)
    health = quality["health_score"]

    lang_list = ", ".join(f"{v} {k}" for k, v in sorted(filtered.languages.items()))
    if real_total == 0:
        filtered.summary = (
            f"VERIFIED: {filtered.files_scanned} files, "
            f"{filtered.total_functions} functions "
            f"({lang_list}) — {filtered.duration_ms}ms "
            f"[{suppressed} noise suppressed, health: {health}/100]"
        )
    else:
        filtered.summary = (
            f"{real_total} real finding(s) in {filtered.files_with_errors} file(s) "
            f"({lang_list}) — {filtered.duration_ms}ms "
            f"[{suppressed}/{raw_total} noise suppressed ({noise_pct}%), health: {health}/100]"
        )

    return filtered

    return result
