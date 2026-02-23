"""AEON GitHub Action — Verify Python files and produce a report.

Usage:
    python verify.py --path "**/*.py" --deep-verify true --fail-on-errors true --output report.json
"""

import argparse
import glob
import json
import os
import sys
import time

# Add parent directory to path so we can import aeon
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from aeon.python_adapter import verify_python


def find_python_files(pattern: str) -> list:
    """Find Python files matching a glob pattern."""
    if os.path.isfile(pattern):
        return [pattern]

    files = glob.glob(pattern, recursive=True)
    # Filter to .py files only, skip common non-source directories
    skip_dirs = {'venv', '.venv', 'node_modules', '__pycache__', '.git', '.tox', 'dist', 'build'}
    result = []
    for f in files:
        if not f.endswith('.py'):
            continue
        parts = f.split(os.sep)
        if any(d in skip_dirs for d in parts):
            continue
        result.append(f)

    return sorted(result)


def verify_file(filepath: str, deep_verify: bool) -> dict:
    """Verify a single Python file."""
    try:
        with open(filepath, 'r') as f:
            source = f.read()
    except Exception as e:
        return {
            "file": filepath,
            "verified": False,
            "errors": [{"message": f"Could not read file: {e}"}],
            "warnings": [],
            "functions_analyzed": 0,
            "skipped": False,
        }

    # Skip empty files and files with no functions
    if not source.strip():
        return {
            "file": filepath,
            "verified": True,
            "errors": [],
            "warnings": [],
            "functions_analyzed": 0,
            "skipped": True,
        }

    try:
        result = verify_python(source, deep_verify=deep_verify)
        return {
            "file": filepath,
            "verified": result.verified,
            "errors": result.errors,
            "warnings": result.warnings,
            "functions_analyzed": result.functions_analyzed,
            "classes_analyzed": result.classes_analyzed,
            "summary": result.summary,
            "skipped": False,
        }
    except Exception as e:
        return {
            "file": filepath,
            "verified": False,
            "errors": [{"message": f"Verification failed: {e}"}],
            "warnings": [],
            "functions_analyzed": 0,
            "skipped": False,
        }


def main():
    parser = argparse.ArgumentParser(description="AEON GitHub Action Verification")
    parser.add_argument("--path", default="**/*.py", help="Glob pattern for Python files")
    parser.add_argument("--deep-verify", default="true", help="Run all 10 engines")
    parser.add_argument("--fail-on-errors", default="true", help="Exit 1 if errors found")
    parser.add_argument("--output", default="aeon-report.json", help="Output report path")
    args = parser.parse_args()

    deep_verify = args.deep_verify.lower() == "true"
    fail_on_errors = args.fail_on_errors.lower() == "true"

    # Find files
    files = find_python_files(args.path)
    if not files:
        print("No Python files found matching pattern:", args.path)
        report = {"files": [], "total_errors": 0, "total_warnings": 0, "all_verified": True}
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        return

    print(f"AEON Verification — analyzing {len(files)} file(s)")
    print(f"  Deep verify: {deep_verify}")
    print(f"  Engines: {'10 (all)' if deep_verify else 'standard'}")
    print()

    # Verify each file
    results = []
    total_errors = 0
    total_warnings = 0
    total_functions = 0
    start_time = time.time()

    for filepath in files:
        result = verify_file(filepath, deep_verify)
        results.append(result)

        err_count = len(result.get("errors", []))
        warn_count = len(result.get("warnings", []))
        func_count = result.get("functions_analyzed", 0)
        total_errors += err_count
        total_warnings += warn_count
        total_functions += func_count

        if result.get("skipped"):
            print(f"  SKIP  {filepath} (empty)")
        elif result["verified"]:
            suffix = f" ({warn_count} warnings)" if warn_count else ""
            print(f"  \u2705  {filepath} — {func_count} functions verified{suffix}")
        else:
            print(f"  \u274c  {filepath} — {err_count} error(s)")
            for err in result.get("errors", []):
                msg = err.get("message", "unknown")
                print(f"       \u26a0 {msg}")

    elapsed = time.time() - start_time
    print()
    print(f"{'=' * 60}")
    print(f"  Files:     {len(files)}")
    print(f"  Functions: {total_functions}")
    print(f"  Errors:    {total_errors}")
    print(f"  Warnings:  {total_warnings}")
    print(f"  Time:      {elapsed:.2f}s")
    print(f"{'=' * 60}")

    all_verified = total_errors == 0

    if all_verified:
        print(f"\n\u2705 ALL FILES VERIFIED")
    else:
        print(f"\n\u274c {total_errors} ERROR(S) FOUND")

    # Write report
    report = {
        "files": results,
        "total_errors": total_errors,
        "total_warnings": total_warnings,
        "total_functions": total_functions,
        "all_verified": all_verified,
        "elapsed_seconds": round(elapsed, 2),
        "deep_verify": deep_verify,
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\nReport written to {args.output}")

    # Set GitHub Actions outputs
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, 'a') as f:
            f.write(f"verified={str(all_verified).lower()}\n")
            f.write(f"errors={total_errors}\n")
            f.write(f"warnings={total_warnings}\n")
            f.write(f"report={args.output}\n")

    # Exit code
    if fail_on_errors and not all_verified:
        sys.exit(1)


if __name__ == "__main__":
    main()
