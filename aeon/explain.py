"""AEON Explain — Plain-English bug explanations with concrete fix suggestions.

Translates formal verification results into developer-friendly language.
Every error type gets:
  1. A clear description of *what* went wrong
  2. *Why* it matters (real-world consequences)
  3. A concrete code fix suggestion

Usage:
    aeon check app.py --explain
    aeon explain app.py
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ── Explanation templates by error pattern ──────────────────────────────

_EXPLANATIONS: List[Dict[str, Any]] = [
    {
        "patterns": ["division by zero", "divide by zero", "ZeroDivisionError"],
        "title": "Possible Division by Zero",
        "why": (
            "If the divisor is ever zero at runtime, your program will crash "
            "with an unhandled exception. This is one of the most common "
            "production bugs."
        ),
        "fix_template": (
            "Add a guard before the division:\n"
            "    if {divisor} == 0:\n"
            "        return {default}  # or raise a descriptive error\n"
            "Or add a contract: Requires: {divisor} != 0"
        ),
        "severity": "error",
    },
    {
        "patterns": ["overflow", "integer overflow", "arithmetic overflow"],
        "title": "Potential Integer Overflow",
        "why": (
            "When arithmetic results exceed the type's range, the value "
            "wraps around silently (in C/Rust) or becomes arbitrarily large "
            "(in Python). This can cause incorrect calculations, security "
            "vulnerabilities, or crashes."
        ),
        "fix_template": (
            "Add bounds checking before the operation, or use a wider type.\n"
            "Example: Requires: {var} <= MAX_SAFE_VALUE"
        ),
        "severity": "error",
    },
    {
        "patterns": ["null", "none", "NoneType", "null pointer", "null reference"],
        "title": "Possible Null/None Access",
        "why": (
            "Accessing an attribute or calling a method on a None value will "
            "raise an AttributeError (Python) or NullPointerException (Java). "
            "This is the #1 cause of runtime crashes in most languages."
        ),
        "fix_template": (
            "Add a null check:\n"
            "    if {var} is not None:\n"
            "        # safe to use {var}\n"
            "Or use Optional type annotations with early returns."
        ),
        "severity": "error",
    },
    {
        "patterns": ["taint", "injection", "sql injection", "xss", "command injection"],
        "title": "Injection Vulnerability (Tainted Data)",
        "why": (
            "User-controlled input is flowing directly into a sensitive "
            "operation (SQL query, HTML output, shell command) without "
            "sanitization. An attacker can exploit this to steal data, "
            "execute arbitrary code, or take over your system."
        ),
        "fix_template": (
            "Sanitize or parameterize the input before use:\n"
            "  - SQL: Use parameterized queries (cursor.execute(sql, params))\n"
            "  - HTML: Use template escaping ({{ var | escape }})\n"
            "  - Shell: Use subprocess with a list, not a string"
        ),
        "severity": "error",
    },
    {
        "patterns": ["information flow", "noninterference", "secret", "security lattice"],
        "title": "Sensitive Data Leak",
        "why": (
            "Secret or confidential data (passwords, API keys, PII) is "
            "flowing to a public output (logs, API responses, UI). This "
            "violates data privacy regulations and can expose your users."
        ),
        "fix_template": (
            "Mask or redact the sensitive data before output:\n"
            "    masked = '****' + card_number[-4:]\n"
            "Or remove the sensitive field from the output entirely."
        ),
        "severity": "error",
    },
    {
        "patterns": ["race condition", "data race", "concurrent", "lock"],
        "title": "Potential Race Condition",
        "why": (
            "Multiple threads or processes can access the same data "
            "simultaneously without proper synchronization. This causes "
            "intermittent bugs that are extremely hard to reproduce and debug."
        ),
        "fix_template": (
            "Protect shared state with synchronization:\n"
            "    with lock:\n"
            "        shared_var = new_value\n"
            "Or use thread-safe data structures (queue.Queue, etc.)."
        ),
        "severity": "error",
    },
    {
        "patterns": ["deadlock", "lock order"],
        "title": "Potential Deadlock",
        "why": (
            "Two or more threads are waiting for each other to release locks, "
            "causing the program to hang indefinitely. In production, this "
            "means your service becomes unresponsive."
        ),
        "fix_template": (
            "Always acquire locks in the same order across all threads.\n"
            "Use a timeout: lock.acquire(timeout=5)\n"
            "Consider using asyncio or actor-based patterns instead."
        ),
        "severity": "error",
    },
    {
        "patterns": ["contract violation", "precondition", "requires", "ensures"],
        "title": "Contract Violation",
        "why": (
            "A function's precondition (Requires) or postcondition (Ensures) "
            "cannot be guaranteed. This means the function may receive invalid "
            "inputs or produce incorrect outputs under certain conditions."
        ),
        "fix_template": (
            "Either:\n"
            "  1. Add input validation at the call site to satisfy the Requires clause\n"
            "  2. Weaken the contract if the requirement is too strict\n"
            "  3. Fix the function body to satisfy the Ensures clause"
        ),
        "severity": "error",
    },
    {
        "patterns": ["termination", "non-terminating", "infinite loop", "infinite recursion"],
        "title": "Possible Non-Termination",
        "why": (
            "The function may loop or recurse forever under some inputs. "
            "In a server, this causes a hung request. In a UI, it freezes "
            "the application."
        ),
        "fix_template": (
            "Ensure the loop/recursion has a well-founded decreasing measure:\n"
            "  - Add a base case that is always reachable\n"
            "  - Verify the recursive argument gets strictly smaller\n"
            "  - Add a maximum iteration/depth bound as a safety net"
        ),
        "severity": "warning",
    },
    {
        "patterns": ["use after free", "dangling pointer", "double free", "memory leak"],
        "title": "Memory Safety Violation",
        "why": (
            "Accessing freed memory, freeing memory twice, or leaking "
            "allocations causes undefined behavior, crashes, or gradually "
            "increasing memory consumption."
        ),
        "fix_template": (
            "Follow ownership rules:\n"
            "  - Free memory exactly once\n"
            "  - Never access a pointer after its target is freed\n"
            "  - Use RAII / context managers to ensure cleanup"
        ),
        "severity": "error",
    },
    {
        "patterns": ["unreachable", "dead code"],
        "title": "Unreachable Code Detected",
        "why": (
            "Some code paths can never execute. This usually indicates a "
            "logic error — perhaps a condition is always true/false, or an "
            "early return prevents code from running."
        ),
        "fix_template": (
            "Review the branching logic:\n"
            "  - Check if conditions are correct\n"
            "  - Remove genuinely dead code to reduce maintenance burden\n"
            "  - If intentional, add a comment explaining why"
        ),
        "severity": "warning",
    },
    {
        "patterns": ["type error", "expected type", "type mismatch"],
        "title": "Type Mismatch",
        "why": (
            "A value of the wrong type is being used where a different type "
            "is expected. This will cause a TypeError at runtime or incorrect "
            "behavior if the language silently coerces types."
        ),
        "fix_template": (
            "Ensure the value matches the expected type:\n"
            "  - Add an explicit conversion: int(value), str(value)\n"
            "  - Fix the function signature or return type\n"
            "  - Add type annotations to catch this earlier"
        ),
        "severity": "error",
    },
    {
        "patterns": ["ownership", "borrow", "moved value"],
        "title": "Ownership Violation",
        "why": (
            "A value is being used after it has been moved or its borrow "
            "has expired. This prevents the compiler from guaranteeing "
            "memory safety."
        ),
        "fix_template": (
            "Options:\n"
            "  - Clone the value if you need it in multiple places\n"
            "  - Restructure code to avoid using the value after the move\n"
            "  - Use references/borrows instead of taking ownership"
        ),
        "severity": "error",
    },
]


def explain_error(error: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a plain-English explanation for a single error.

    Args:
        error: An error dict with at least 'message' and optionally
               'kind', 'location', 'details'.

    Returns:
        A dict with 'title', 'explanation', 'why', 'fix', 'severity'.
    """
    message = error.get("message", "").lower()
    details = error.get("details", {})

    # Try to match against known patterns
    for template in _EXPLANATIONS:
        for pattern in template["patterns"]:
            if pattern in message:
                fix = _interpolate_fix(template["fix_template"], error)
                return {
                    "title": template["title"],
                    "explanation": error.get("message", ""),
                    "why": template["why"],
                    "fix": fix,
                    "severity": template["severity"],
                }

    # Fallback: generic explanation
    return {
        "title": "Verification Issue",
        "explanation": error.get("message", "Unknown issue"),
        "why": "This issue was flagged by AEON's analysis engines and should be reviewed.",
        "fix": _suggest_generic_fix(error),
        "severity": "warning",
    }


def explain_all(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Explain all errors and warnings in a verification result."""
    explanations = []
    for err in result.get("errors", []):
        exp = explain_error(err)
        exp["location"] = err.get("location")
        exp["original"] = err
        explanations.append(exp)
    for warn in result.get("warnings", []):
        exp = explain_error(warn)
        exp["location"] = warn.get("location")
        exp["original"] = warn
        explanations.append(exp)
    return explanations


def format_explanations(explanations: List[Dict[str, Any]], filepath: Optional[str] = None) -> str:
    """Format explanations into a readable report."""
    if not explanations:
        return "✅ No issues to explain. Code looks good!\n"

    lines = []
    if filepath:
        lines.append(f"\n📋 AEON Explanation Report — {filepath}")
    else:
        lines.append("\n📋 AEON Explanation Report")
    lines.append("=" * 60)

    for i, exp in enumerate(explanations, 1):
        loc = exp.get("location", {})
        line_num = loc.get("line", "?") if loc else "?"

        severity_icon = "❌" if exp["severity"] == "error" else "⚠️"
        lines.append(f"\n{severity_icon}  Issue #{i}: {exp['title']}")
        lines.append(f"   Line: {line_num}")
        lines.append(f"   What: {exp['explanation']}")
        lines.append(f"   Why:  {exp['why']}")
        lines.append(f"   Fix:  {exp['fix']}")
        lines.append("")

    err_count = sum(1 for e in explanations if e["severity"] == "error")
    warn_count = sum(1 for e in explanations if e["severity"] != "error")
    lines.append(f"Total: {err_count} error(s), {warn_count} warning(s)")
    lines.append("")

    return "\n".join(lines)


# ── Internal helpers ────────────────────────────────────────────────────

def _interpolate_fix(template: str, error: Dict[str, Any]) -> str:
    """Fill in fix template with context from the error."""
    details = error.get("details", {})
    message = error.get("message", "")

    # Try to extract variable names from the error
    replacements = {
        "divisor": details.get("variable", _extract_var(message, "divisor")),
        "var": details.get("variable", _extract_var(message, "variable")),
        "default": "0",
    }

    try:
        return template.format(**replacements)
    except (KeyError, IndexError):
        return template


def _extract_var(message: str, fallback: str = "x") -> str:
    """Try to extract a variable name from an error message."""
    import re
    match = re.search(r"'(\w+)'", message)
    if match:
        return match.group(1)
    return fallback


def _suggest_generic_fix(error: Dict[str, Any]) -> str:
    """Generate a generic fix suggestion."""
    kind = error.get("kind", "")
    if kind == "type_error":
        return "Check type annotations and ensure values match expected types."
    elif kind == "contract_error":
        return "Review the function's Requires/Ensures clauses and ensure they hold."
    elif kind == "ownership_error":
        return "Review value ownership — avoid using values after they've been moved."
    elif kind == "effect_error":
        return "Declare the missing effect in the function's effects list."
    elif kind == "syntax_error":
        return "Fix the syntax error indicated by the compiler."
    elif kind == "name_error":
        return "Check that all variable and function names are defined before use."
    else:
        return "Review the flagged code and add appropriate guards or validation."
