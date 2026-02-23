"""AEON Auto-Fix — Automatically fix detected issues in source code.

Maps each error type to a concrete code transformation. Supports:
  - Division-by-zero guards
  - Null/None checks
  - Contract (Requires/Ensures) insertion
  - Taint sanitization stubs
  - Type annotation fixes
  - Lock guards for race conditions

Usage:
    aeon fix app.py                 # Fix all detected issues in-place
    aeon fix app.py --dry-run       # Show proposed fixes without applying
    aeon fix src/ --type security   # Fix only security issues in a directory
"""

from __future__ import annotations

import os
import re
import textwrap
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Fix:
    """A single proposed code fix."""
    line: int
    description: str
    original: str
    replacement: str
    category: str  # "security", "correctness", "safety", "style"
    confidence: float  # 0.0–1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line": self.line,
            "description": self.description,
            "original": self.original,
            "replacement": self.replacement,
            "category": self.category,
            "confidence": self.confidence,
        }


@dataclass
class FixResult:
    """Result of running the auto-fixer on a file."""
    filepath: str
    fixes_applied: List[Fix] = field(default_factory=list)
    fixes_skipped: List[Fix] = field(default_factory=list)
    original_source: str = ""
    fixed_source: str = ""
    error_count_before: int = 0
    error_count_after: int = 0

    @property
    def summary(self) -> str:
        applied = len(self.fixes_applied)
        skipped = len(self.fixes_skipped)
        if applied == 0 and skipped == 0:
            return f"✅ {self.filepath}: No issues to fix."
        parts = []
        if applied:
            parts.append(f"⚡ {applied} fix{'es' if applied != 1 else ''} applied")
        if skipped:
            parts.append(f"⏭ {skipped} skipped (low confidence)")
        return f"{self.filepath}: {', '.join(parts)}"


# ── Fix strategies ──────────────────────────────────────────────────────

class FixEngine:
    """Maps verification errors to code transformations."""

    def __init__(self, min_confidence: float = 0.5):
        self.min_confidence = min_confidence

    def generate_fixes(
        self, source: str, errors: List[Dict[str, Any]], language: str = "python"
    ) -> List[Fix]:
        """Generate a list of proposed fixes for the given errors."""
        fixes: List[Fix] = []
        source_lines = source.splitlines()

        for err in errors:
            msg = err.get("message", "").lower()
            details = err.get("details", {})
            loc = err.get("location", {})
            raw_line = loc.get("line", 0)

            # Safely convert line to int — skip non-numeric values
            try:
                line = int(raw_line)
            except (ValueError, TypeError):
                continue

            if line < 1 or line > len(source_lines):
                continue

            src_line = source_lines[line - 1]

            # Division by zero
            if any(p in msg for p in ["division by zero", "divide by zero"]):
                fix = self._fix_division_by_zero(src_line, line, details, language)
                if fix:
                    fixes.append(fix)

            # Null / None access
            elif any(p in msg for p in ["none", "null", "nonetype"]):
                fix = self._fix_null_check(src_line, line, details, language)
                if fix:
                    fixes.append(fix)

            # Taint / injection
            elif any(p in msg for p in ["taint", "injection", "sql injection", "xss"]):
                fix = self._fix_taint(src_line, line, details, language)
                if fix:
                    fixes.append(fix)

            # Information flow / secret leak
            elif any(p in msg for p in ["information flow", "secret", "noninterference"]):
                fix = self._fix_info_leak(src_line, line, details, language)
                if fix:
                    fixes.append(fix)

            # Contract: missing requires
            elif any(p in msg for p in ["contract violation", "precondition"]):
                fix = self._fix_add_contract(src_line, line, details, language, source_lines)
                if fix:
                    fixes.append(fix)

            # Race condition
            elif any(p in msg for p in ["race condition", "data race"]):
                fix = self._fix_race_condition(src_line, line, details, language)
                if fix:
                    fixes.append(fix)

        return fixes

    def apply_fixes(
        self, source: str, fixes: List[Fix], dry_run: bool = False
    ) -> Tuple[str, List[Fix], List[Fix]]:
        """Apply fixes to source code.

        Returns (fixed_source, applied, skipped).
        Fixes are applied bottom-up to preserve line numbers.
        """
        applied: List[Fix] = []
        skipped: List[Fix] = []

        # Filter by confidence
        for fix in fixes:
            if fix.confidence >= self.min_confidence:
                applied.append(fix)
            else:
                skipped.append(fix)

        if dry_run or not applied:
            return source, applied, skipped

        # Sort by line descending so edits don't shift line numbers
        applied.sort(key=lambda f: f.line, reverse=True)

        lines = source.splitlines(keepends=True)
        for fix in applied:
            idx = fix.line - 1
            if 0 <= idx < len(lines):
                # Replace the line content
                original_ending = ""
                if lines[idx].endswith("\n"):
                    original_ending = "\n"
                lines[idx] = fix.replacement
                if not lines[idx].endswith("\n") and original_ending:
                    lines[idx] += "\n"

        fixed_source = "".join(lines)
        return fixed_source, applied, skipped

    # ── Individual fix strategies ───────────────────────────────────────

    def _fix_division_by_zero(
        self, line: str, lineno: int, details: Dict, language: str
    ) -> Optional[Fix]:
        """Add a zero-check guard before division."""
        indent = _get_indent(line)

        # Try to find the divisor
        div_match = re.search(r'[/]\s*(\w+)', line)
        if not div_match:
            div_match = re.search(r'//\s*(\w+)', line)
        if not div_match:
            return None

        divisor = div_match.group(1)

        if language in ("python", "ruby"):
            guard = f"{indent}if {divisor} == 0:\n{indent}    raise ValueError(\"Division by zero: {divisor} must not be zero\")\n"
            replacement = guard + line
        elif language in ("javascript", "typescript"):
            guard = f"{indent}if ({divisor} === 0) {{ throw new Error(\"Division by zero\"); }}\n"
            replacement = guard + line
        elif language in ("java", "kotlin", "scala", "dart"):
            guard = f"{indent}if ({divisor} == 0) {{ throw new ArithmeticException(\"Division by zero\"); }}\n"
            replacement = guard + line
        elif language in ("go",):
            guard = f"{indent}if {divisor} == 0 {{ return 0, fmt.Errorf(\"division by zero\") }}\n"
            replacement = guard + line
        elif language in ("rust",):
            guard = f"{indent}if {divisor} == 0 {{ return Err(\"division by zero\".into()); }}\n"
            replacement = guard + line
        elif language in ("c", "cpp"):
            guard = f"{indent}if ({divisor} == 0) {{ return -1; /* division by zero guard */ }}\n"
            replacement = guard + line
        else:
            guard = f"{indent}# AEON: guard against division by zero on '{divisor}'\n"
            replacement = guard + line

        return Fix(
            line=lineno,
            description=f"Add zero-check guard for divisor '{divisor}'",
            original=line,
            replacement=replacement,
            category="correctness",
            confidence=0.85,
        )

    def _fix_null_check(
        self, line: str, lineno: int, details: Dict, language: str
    ) -> Optional[Fix]:
        """Add a null/None check."""
        indent = _get_indent(line)
        var = details.get("variable", "")
        if not var:
            # Try to extract from line
            match = re.search(r'(\w+)\s*\.', line)
            var = match.group(1) if match else "value"

        if language in ("python", "ruby"):
            guard = f"{indent}if {var} is None:\n{indent}    raise ValueError(\"{var} must not be None\")\n"
        elif language in ("javascript", "typescript"):
            guard = f"{indent}if ({var} == null) {{ throw new Error(\"{var} must not be null\"); }}\n"
        elif language in ("java", "kotlin"):
            guard = f"{indent}Objects.requireNonNull({var}, \"{var} must not be null\");\n"
        else:
            guard = f"{indent}/* AEON: null check for {var} */\n"

        return Fix(
            line=lineno,
            description=f"Add null check for '{var}'",
            original=line,
            replacement=guard + line,
            category="correctness",
            confidence=0.75,
        )

    def _fix_taint(
        self, line: str, lineno: int, details: Dict, language: str
    ) -> Optional[Fix]:
        """Add sanitization for tainted data."""
        indent = _get_indent(line)

        if language == "python":
            comment = f"{indent}# AEON: Sanitize user input before use — parameterize queries or escape output\n"
        elif language in ("javascript", "typescript"):
            comment = f"{indent}// AEON: Sanitize user input — use parameterized queries or escape output\n"
        elif language in ("java",):
            comment = f"{indent}// AEON: Sanitize user input — use PreparedStatement or escape output\n"
        else:
            comment = f"{indent}/* AEON: Sanitize user input before use */\n"

        return Fix(
            line=lineno,
            description="Flag tainted data flow — add sanitization",
            original=line,
            replacement=comment + line,
            category="security",
            confidence=0.65,
        )

    def _fix_info_leak(
        self, line: str, lineno: int, details: Dict, language: str
    ) -> Optional[Fix]:
        """Mask or redact sensitive data."""
        indent = _get_indent(line)

        if language == "python":
            comment = f"{indent}# AEON: Sensitive data detected — mask before output (e.g. '****' + val[-4:])\n"
        else:
            comment = f"{indent}// AEON: Sensitive data detected — mask before output\n"

        return Fix(
            line=lineno,
            description="Flag sensitive data leak — mask before output",
            original=line,
            replacement=comment + line,
            category="security",
            confidence=0.7,
        )

    def _fix_add_contract(
        self, line: str, lineno: int, details: Dict, language: str,
        source_lines: List[str]
    ) -> Optional[Fix]:
        """Add a Requires clause to a function."""
        precondition = details.get("precondition", "")
        if not precondition:
            return None

        # Find function definition above this line
        func_line_idx = None
        for i in range(lineno - 1, -1, -1):
            if i < len(source_lines) and re.match(r'\s*(def |async def |pure |task )', source_lines[i]):
                func_line_idx = i
                break

        if func_line_idx is None:
            return None

        indent = _get_indent(source_lines[func_line_idx]) + "    "

        if language == "python":
            # Add Requires in docstring
            docstring_line = f'{indent}"""\n{indent}Requires: {precondition}\n{indent}"""\n'
            target_line = func_line_idx + 2  # after def line + 1
        else:
            docstring_line = f'{indent}// Requires: {precondition}\n'
            target_line = func_line_idx + 2

        return Fix(
            line=target_line,
            description=f"Add contract: Requires: {precondition}",
            original="",
            replacement=docstring_line,
            category="correctness",
            confidence=0.8,
        )

    def _fix_race_condition(
        self, line: str, lineno: int, details: Dict, language: str
    ) -> Optional[Fix]:
        """Add lock acquisition around shared state access."""
        indent = _get_indent(line)

        if language == "python":
            replacement = (
                f"{indent}with _lock:  # AEON: protect shared state\n"
                f"{indent}    {line.strip()}\n"
            )
        elif language in ("java",):
            replacement = (
                f"{indent}synchronized (this) {{ // AEON: protect shared state\n"
                f"{indent}    {line.strip()}\n"
                f"{indent}}}\n"
            )
        elif language in ("javascript", "typescript"):
            replacement = (
                f"{indent}// AEON: This access needs synchronization (use mutex or async lock)\n"
                f"{line}"
            )
        else:
            replacement = (
                f"{indent}/* AEON: protect this shared-state access with a lock */\n"
                f"{line}"
            )

        return Fix(
            line=lineno,
            description="Add lock guard for shared state access",
            original=line,
            replacement=replacement,
            category="correctness",
            confidence=0.6,
        )


# ── High-level API ──────────────────────────────────────────────────────

def fix_file(
    filepath: str,
    dry_run: bool = False,
    fix_type: Optional[str] = None,
    min_confidence: float = 0.5,
    deep_verify: bool = True,
) -> FixResult:
    """Verify a file and apply auto-fixes.

    Args:
        filepath: Path to source file.
        dry_run: If True, show fixes without applying.
        fix_type: Filter fixes by category ("security", "correctness", etc.).
        min_confidence: Minimum confidence threshold for applying fixes.
        deep_verify: Whether to use deep verification.

    Returns:
        FixResult with details of applied/skipped fixes.
    """
    if not os.path.isfile(filepath):
        return FixResult(filepath=filepath)

    with open(filepath, "r") as f:
        source = f.read()

    # Detect language
    ext = os.path.splitext(filepath)[1].lower()
    lang_map = {
        ".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust",
        ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".rb": "ruby",
        ".swift": "swift", ".kt": "kotlin", ".php": "php", ".scala": "scala",
        ".dart": "dart", ".aeon": "aeon",
    }
    language = lang_map.get(ext, "python")

    # Run verification to get errors
    errors = _run_verification(source, language, filepath, deep_verify)

    result = FixResult(
        filepath=filepath,
        original_source=source,
        error_count_before=len(errors),
    )

    if not errors:
        result.fixed_source = source
        return result

    # Generate fixes
    engine = FixEngine(min_confidence=min_confidence)
    fixes = engine.generate_fixes(source, errors, language)

    # Filter by type if requested
    if fix_type:
        fixes = [f for f in fixes if f.category == fix_type]

    # Apply fixes
    fixed_source, applied, skipped = engine.apply_fixes(source, fixes, dry_run=dry_run)

    result.fixes_applied = applied
    result.fixes_skipped = skipped
    result.fixed_source = fixed_source

    if not dry_run and applied:
        with open(filepath, "w") as f:
            f.write(fixed_source)

    # Re-verify to count remaining errors
    if not dry_run and applied:
        remaining_errors = _run_verification(fixed_source, language, filepath, deep_verify)
        result.error_count_after = len(remaining_errors)
    else:
        result.error_count_after = result.error_count_before

    return result


def fix_directory(
    dirpath: str,
    dry_run: bool = False,
    fix_type: Optional[str] = None,
    min_confidence: float = 0.5,
    deep_verify: bool = True,
) -> List[FixResult]:
    """Fix all supported files in a directory."""
    from aeon.scanner import discover_files

    results = []
    files = discover_files(dirpath)

    for filepath in files:
        result = fix_file(
            filepath,
            dry_run=dry_run,
            fix_type=fix_type,
            min_confidence=min_confidence,
            deep_verify=deep_verify,
        )
        results.append(result)

    return results


def format_fix_result(result: FixResult, verbose: bool = False) -> str:
    """Format a FixResult for terminal output."""
    lines = [result.summary]

    if verbose and result.fixes_applied:
        for fix in result.fixes_applied:
            lines.append(f"  ⚡ L{fix.line}: {fix.description} [{fix.category}] ({fix.confidence:.0%})")

    if verbose and result.fixes_skipped:
        for fix in result.fixes_skipped:
            lines.append(f"  ⏭  L{fix.line}: {fix.description} (skipped, {fix.confidence:.0%} confidence)")

    if result.fixes_applied:
        lines.append(
            f"  📊 Errors: {result.error_count_before} → {result.error_count_after}"
        )

    return "\n".join(lines)


def format_fix_diff(result: FixResult) -> str:
    """Show a unified diff of changes."""
    import difflib
    if result.original_source == result.fixed_source:
        return "No changes."

    diff = difflib.unified_diff(
        result.original_source.splitlines(keepends=True),
        result.fixed_source.splitlines(keepends=True),
        fromfile=f"a/{result.filepath}",
        tofile=f"b/{result.filepath}",
        lineterm="",
    )
    return "".join(diff)


# ── Internal helpers ────────────────────────────────────────────────────

def _get_indent(line: str) -> str:
    """Extract leading whitespace from a line."""
    match = re.match(r'^(\s*)', line)
    return match.group(1) if match else ""


def _run_verification(
    source: str, language: str, filepath: str, deep_verify: bool
) -> List[Dict[str, Any]]:
    """Run AEON verification and return error dicts."""
    try:
        if language == "aeon":
            from aeon.parser import parse
            from aeon.pass1_prove import prove
            program = parse(source, filename=filepath)
            errors = prove(program, deep_verify=deep_verify)
            return [e.to_dict() for e in errors]
        else:
            from aeon.language_adapter import verify
            result = verify(source, language, deep_verify=deep_verify)
            return result.to_dict().get("errors", []) + result.to_dict().get("warnings", [])
    except Exception:
        return []
