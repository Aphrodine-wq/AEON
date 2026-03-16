"""AEON Ghost — Ghost-Assertion Shadowing.

AI-inferred intent contracts. AEON scans your code, guesses what contracts
you *intended* but didn't write, and flags deviations as "Intent Violations."

Catches bugs before they become formal errors.

Usage:
    aeon ghost <file>           # Analyze for ghost assertions
    aeon ghost <file> --json    # JSON output
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Tuple


@dataclass
class GhostAssertion:
    """An AI-inferred contract the developer probably intended."""
    function: str
    line: int
    assertion: str          # The inferred contract
    confidence: float       # 0.0-1.0
    matches_code: bool      # Does the code actually satisfy this?
    explanation: str = ""
    category: str = ""      # 'null_safety', 'bounds', 'return_value', 'state', 'resource'

    def to_dict(self) -> dict:
        return {
            "function": self.function,
            "line": self.line,
            "assertion": self.assertion,
            "confidence": self.confidence,
            "matches_code": self.matches_code,
            "explanation": self.explanation,
            "category": self.category,
        }


# ---------------------------------------------------------------------------
# Ghost inference rules
# ---------------------------------------------------------------------------

GHOST_RULES: List[Dict] = [
    # Parameter null checks
    {
        "name": "null_param_check",
        "category": "null_safety",
        "param_pattern": r'(\w+)\s*(?::\s*(?:Optional|str|list|dict|bytes))',
        "body_check": lambda name, body: f"if {name} is None" in body or f"if not {name}" in body,
        "ghost": lambda name: f"requires {name} is not None",
        "confidence": 0.85,
        "explanation": lambda name: f"Parameter '{name}' is used without null guard but has nullable type",
    },
    # Division operations
    {
        "name": "division_guard",
        "category": "bounds",
        "body_pattern": r'(\w+)\s*/\s*(\w+)',
        "body_check": lambda divisor, body: f"if {divisor}" in body or f"{divisor} != 0" in body or f"{divisor} == 0" in body,
        "ghost": lambda divisor: f"requires {divisor} != 0",
        "confidence": 0.95,
        "explanation": lambda divisor: f"Division by '{divisor}' without zero guard",
    },
    # Array index access
    {
        "name": "bounds_check",
        "category": "bounds",
        "body_pattern": r'(\w+)\[(\w+)\]',
        "body_check": lambda idx, body: f"if {idx}" in body or f"len(" in body or f"range(" in body,
        "ghost": lambda idx: f"requires 0 <= {idx} < len(collection)",
        "confidence": 0.80,
        "explanation": lambda idx: f"Index '{idx}' used without bounds verification",
    },
    # Return value guarantees
    {
        "name": "return_not_none",
        "category": "return_value",
        "return_pattern": r'->\s*(?!None|bool)(\w+)',
        "body_check": lambda body: "return None" not in body and "return" in body,
        "ghost": "ensures result is not None",
        "confidence": 0.70,
        "explanation": "Function has non-None return type but might return None on some paths",
    },
    # File handle closure
    {
        "name": "file_closure",
        "category": "resource",
        "body_pattern": r'open\s*\(',
        "body_check": lambda body: "with open" in body or ".close()" in body,
        "ghost": "ensures file handle is closed",
        "confidence": 0.90,
        "explanation": "File opened without context manager — may leak handle",
    },
    # Positive amount in financial operations
    {
        "name": "positive_amount",
        "category": "bounds",
        "param_pattern": r'(amount|price|cost|fee|balance|total)\s*:\s*(?:int|float|Decimal)',
        "body_check": lambda name, body: f"{name} > 0" in body or f"{name} >= 0" in body or f"{name} <= 0" in body,
        "ghost": lambda name: f"requires {name} >= 0",
        "confidence": 0.90,
        "explanation": lambda name: f"Financial value '{name}' should be non-negative",
    },
    # List non-empty check
    {
        "name": "nonempty_list",
        "category": "bounds",
        "body_pattern": r'(\w+)\[0\]|(\w+)\[-1\]|min\((\w+)\)|max\((\w+)\)',
        "body_check": lambda name, body: f"if {name}" in body or f"len({name})" in body or f"if not {name}" in body,
        "ghost": lambda name: f"requires len({name}) > 0",
        "confidence": 0.85,
        "explanation": lambda name: f"Accessing first/last element of '{name}' without empty check",
    },
]


EXT_TO_LANG: Dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "javascript",
    ".java": "java", ".go": "go", ".rs": "rust", ".swift": "swift",
}


class GhostAnalyzer:
    """Analyze code for ghost assertions — contracts the developer likely intended."""

    def analyze_file(self, filepath: str) -> List[GhostAssertion]:
        """Analyze a file for ghost assertions."""
        path = Path(filepath)
        lang = EXT_TO_LANG.get(path.suffix.lower(), "python")
        source = path.read_text(encoding="utf-8", errors="ignore")

        if lang == "python":
            return self._analyze_python(source, filepath)
        return self._analyze_generic(source, filepath, lang)

    def _analyze_python(self, source: str, filepath: str) -> List[GhostAssertion]:
        """Analyze Python source for ghost assertions."""
        ghosts: List[GhostAssertion] = []
        functions = self._extract_python_functions(source)

        for func_name, func_line, func_params, func_body, func_return in functions:
            # Check division without guard
            div_matches = re.finditer(r'[^/]\s*/\s*(\w+)', func_body)
            for dm in div_matches:
                divisor = dm.group(1)
                if divisor.isdigit():
                    continue
                has_guard = (
                    f"if {divisor}" in func_body
                    or f"{divisor} != 0" in func_body
                    or f"{divisor} == 0" in func_body
                    or f"if not {divisor}" in func_body
                )
                ghosts.append(GhostAssertion(
                    function=func_name, line=func_line,
                    assertion=f"requires {divisor} != 0",
                    confidence=0.95,
                    matches_code=has_guard,
                    explanation=f"Division by '{divisor}' {'is guarded' if has_guard else 'has no zero guard'}",
                    category="bounds",
                ))

            # Check array access without bounds
            idx_matches = re.finditer(r'(\w+)\[(\w+)\]', func_body)
            seen_collections = set()
            for im in idx_matches:
                collection, index = im.group(1), im.group(2)
                if collection in seen_collections or index.isdigit() or collection in ('self', 'cls'):
                    continue
                seen_collections.add(collection)
                has_guard = (
                    f"len({collection})" in func_body
                    or f"if {index}" in func_body
                    or f"range(" in func_body
                    or f"enumerate(" in func_body
                )
                if not has_guard:
                    ghosts.append(GhostAssertion(
                        function=func_name, line=func_line,
                        assertion=f"requires 0 <= {index} < len({collection})",
                        confidence=0.80,
                        matches_code=False,
                        explanation=f"Index '{index}' into '{collection}' without bounds check",
                        category="bounds",
                    ))

            # Check file open without context manager
            if re.search(r'(?<!with\s)open\s*\(', func_body):
                has_with = "with open" in func_body
                has_close = ".close()" in func_body
                if not has_with and not has_close:
                    ghosts.append(GhostAssertion(
                        function=func_name, line=func_line,
                        assertion="ensures file handle is closed",
                        confidence=0.90,
                        matches_code=False,
                        explanation="File opened without context manager or explicit close",
                        category="resource",
                    ))

            # Check nullable params used without guard
            for param in func_params:
                if 'Optional' in param.get('type', '') or param.get('default') == 'None':
                    name = param['name']
                    has_guard = (
                        f"if {name} is None" in func_body
                        or f"if {name} is not None" in func_body
                        or f"if not {name}" in func_body
                        or f"if {name}:" in func_body
                        or f"{name} or " in func_body
                    )
                    if not has_guard and name in func_body:
                        ghosts.append(GhostAssertion(
                            function=func_name, line=func_line,
                            assertion=f"requires {name} is not None",
                            confidence=0.85,
                            matches_code=False,
                            explanation=f"Optional parameter '{name}' used without null check",
                            category="null_safety",
                        ))

            # Check financial amounts
            for param in func_params:
                name = param['name']
                if re.match(r'amount|price|cost|fee|balance|total|quantity', name, re.I):
                    has_guard = f"{name} > 0" in func_body or f"{name} >= 0" in func_body or f"{name} <= 0" in func_body
                    ghosts.append(GhostAssertion(
                        function=func_name, line=func_line,
                        assertion=f"requires {name} >= 0",
                        confidence=0.90,
                        matches_code=has_guard,
                        explanation=f"Financial value '{name}' {'is validated' if has_guard else 'has no positivity check'}",
                        category="bounds",
                    ))

            # Return type vs None paths
            if func_return and func_return not in ('None', 'bool', 'Any'):
                paths_return_none = 'return None' in func_body or (
                    func_body.count('return') > 1 and
                    re.search(r'return\s*$', func_body, re.M)
                )
                if paths_return_none:
                    ghosts.append(GhostAssertion(
                        function=func_name, line=func_line,
                        assertion="ensures result is not None",
                        confidence=0.75,
                        matches_code=False,
                        explanation=f"Return type is {func_return} but function may return None",
                        category="return_value",
                    ))

        return ghosts

    def _analyze_generic(self, source: str, filepath: str, language: str) -> List[GhostAssertion]:
        """Basic ghost analysis for non-Python languages."""
        ghosts: List[GhostAssertion] = []
        lines = source.split("\n")

        for i, line in enumerate(lines, 1):
            # Division without guard
            div_m = re.search(r'(\w+)\s*/\s*(\w+)', line)
            if div_m and not div_m.group(2).isdigit():
                divisor = div_m.group(2)
                context = "\n".join(lines[max(0, i-5):i])
                has_guard = f"{divisor} != 0" in context or f"{divisor} == 0" in context
                ghosts.append(GhostAssertion(
                    function="<unknown>", line=i,
                    assertion=f"requires {divisor} != 0",
                    confidence=0.90, matches_code=has_guard,
                    category="bounds",
                ))

        return ghosts

    def _extract_python_functions(self, source: str) -> List[Tuple]:
        """Extract Python functions with metadata."""
        results = []
        lines = source.split("\n")
        func_starts: List[Tuple[str, int, str]] = []

        for i, line in enumerate(lines):
            m = re.match(r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*(\S+))?', line)
            if m:
                indent = len(m.group(1))
                func_starts.append((m.group(2), i + 1, m.group(3), m.group(4) or "", indent))

        for idx, (name, start, params_raw, return_type, indent) in enumerate(func_starts):
            # Find function end
            if idx + 1 < len(func_starts):
                end = func_starts[idx + 1][1] - 1
            else:
                end = len(lines)
            body = "\n".join(lines[start:end])

            # Parse params
            params: List[Dict[str, str]] = []
            for p in params_raw.split(","):
                p = p.strip()
                if not p or p in ('self', 'cls'):
                    continue
                name_m = re.match(r'(\w+)(?:\s*:\s*(.+?))?(?:\s*=\s*(.+))?$', p)
                if name_m:
                    params.append({
                        "name": name_m.group(1),
                        "type": name_m.group(2) or "",
                        "default": name_m.group(3) or "",
                    })

            results.append((name, start, params, body, return_type))

        return results
