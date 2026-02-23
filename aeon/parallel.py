"""AEON Parallel Verification — Multi-process File Scanning.

Verifies multiple files in parallel using Python's multiprocessing
for faster analysis of large codebases.

Usage:
    from aeon.parallel import parallel_scan
    result = parallel_scan("src/", deep_verify=True, workers=4)
"""

from __future__ import annotations

import os
import time
from multiprocessing import Pool, cpu_count
from dataclasses import dataclass
from typing import Optional, List, Dict, Set, Tuple, Any

from aeon.scanner import ScanResult, discover_files
from aeon.language_adapter import verify_file, detect_language


# ---------------------------------------------------------------------------
# Worker function (must be top-level for pickling)
# ---------------------------------------------------------------------------

def _verify_single_file(args: Tuple[str, str, bool, Optional[List[str]]]) -> Dict[str, Any]:
    """Verify a single file (worker function for multiprocessing).

    Args:
        args: (filepath, root, deep_verify, analyses)

    Returns:
        Dict with file result data
    """
    filepath, root, deep_verify, analyses = args

    try:
        lang = detect_language(filepath)
        vr = verify_file(filepath, deep_verify=deep_verify, analyses=analyses)

        result = {
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
            result["error_details"] = vr.errors
        if vr.warnings:
            result["warning_details"] = vr.warnings

        return result

    except Exception as e:
        return {
            "file": os.path.relpath(filepath, root),
            "error": str(e),
            "verified": False,
            "errors": 0,
            "warnings": 0,
            "functions": 0,
            "classes": 0,
        }


# ---------------------------------------------------------------------------
# Parallel Scanner
# ---------------------------------------------------------------------------

def parallel_scan(root: str, deep_verify: bool = True,
                  analyses: Optional[List[str]] = None,
                  workers: int = 0,
                  extensions: Optional[Set[str]] = None,
                  ignore_patterns: Optional[List[str]] = None) -> ScanResult:
    """Scan and verify files in parallel using multiprocessing.

    Args:
        root: Root directory to scan
        deep_verify: Enable all analysis engines
        analyses: Specific analyses to run
        workers: Number of worker processes (0 = auto = cpu_count)
        extensions: File extensions to include
        ignore_patterns: Patterns to exclude

    Returns:
        ScanResult with aggregated results
    """
    start = time.time()
    root = os.path.abspath(root)

    # Discover files
    files = discover_files(root, extensions, ignore_patterns)

    if not files:
        return ScanResult(root=root, summary="No files found to scan")

    # Determine worker count
    if workers <= 0:
        workers = min(cpu_count(), len(files), 8)  # Cap at 8 workers
    workers = max(1, workers)

    # Build work items
    work_items = [(f, root, deep_verify, analyses) for f in files]

    # Execute in parallel
    if workers == 1 or len(files) <= 2:
        # Sequential for small sets (avoid multiprocessing overhead)
        file_results = [_verify_single_file(item) for item in work_items]
    else:
        with Pool(processes=workers) as pool:
            file_results = pool.map(_verify_single_file, work_items)

    # Aggregate results
    result = ScanResult(root=root, files_scanned=len(files))

    for fr in file_results:
        result.file_results.append(fr)
        lang = fr.get("language", "unknown")
        result.languages[lang] = result.languages.get(lang, 0) + 1

        if fr.get("verified", False):
            result.files_verified += 1
        if fr.get("errors", 0) > 0:
            result.files_with_errors += 1
            result.total_errors += fr["errors"]
        if fr.get("warnings", 0) > 0:
            result.files_with_warnings += 1
            result.total_warnings += fr["warnings"]
        result.total_functions += fr.get("functions", 0)
        result.total_classes += fr.get("classes", 0)

    elapsed = (time.time() - start) * 1000
    result.duration_ms = round(elapsed, 1)

    # Summary
    lang_list = ", ".join(f"{v} {k}" for k, v in sorted(result.languages.items()))
    worker_info = f"{workers} workers"
    if result.total_errors == 0:
        result.summary = (
            f"\u2705 ALL VERIFIED: {result.files_scanned} files, "
            f"{result.total_functions} functions ({lang_list}) — "
            f"{result.duration_ms}ms [{worker_info}]"
        )
    else:
        result.summary = (
            f"\u274c {result.total_errors} error(s) in {result.files_with_errors} of "
            f"{result.files_scanned} files ({lang_list}) — "
            f"{result.duration_ms}ms [{worker_info}]"
        )

    return result
