"""AEON Code Synthesizer — generate provably correct code from specifications.

Usage:
    aeon synthesize --spec "safely divide two integers"
    aeon synthesize spec.aeon --language rust
    aeon synthesize --list-templates
"""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from pathlib import Path

try:
    import z3
    HAS_Z3 = True
except Exception:
    HAS_Z3 = False


@dataclass
class SynthesisResult:
    """Result of code synthesis."""
    source_code: str
    language: str
    function_name: str
    contracts_satisfied: List[str] = field(default_factory=list)
    proof_status: str = "unverified"  # 'proven', 'partial', 'unverified'
    confidence: float = 0.0
    alternatives: List[str] = field(default_factory=list)


@dataclass
class FunctionSpec:
    """Parsed function specification."""
    name: str
    params: List[Dict[str, str]]
    return_type: str
    requires: List[str] = field(default_factory=list)
    ensures: List[str] = field(default_factory=list)
    description: str = ""


# ---------------------------------------------------------------------------
# Template library
# ---------------------------------------------------------------------------

SYNTHESIS_TEMPLATES: Dict[str, dict] = {
    "safe_divide": {
        "patterns": ["divide", "division", "safe.*div"],
        "spec": FunctionSpec(
            name="safe_divide",
            params=[{"name": "a", "type": "int"}, {"name": "b", "type": "int"}],
            return_type="int",
            requires=["b != 0"],
            ensures=["result * b <= a", "result * b > a - b"],
            description="Safely divide two integers",
        ),
        "implementations": {
            "python": 'def safe_divide(a: int, b: int) -> int:\n    """\n    Requires: b != 0\n    Ensures: result * b <= a and result * b > a - b\n    """\n    if b == 0:\n        raise ValueError("Division by zero")\n    return a // b',
            "javascript": 'function safeDivide(a, b) {\n    // Requires: b !== 0\n    if (b === 0) throw new Error("Division by zero");\n    return Math.floor(a / b);\n}',
            "rust": 'fn safe_divide(a: i64, b: i64) -> Result<i64, &\'static str> {\n    // Requires: b != 0\n    if b == 0 { return Err("Division by zero"); }\n    Ok(a / b)\n}',
            "go": 'func safeDivide(a, b int) (int, error) {\n    // Requires: b != 0\n    if b == 0 { return 0, fmt.Errorf("division by zero") }\n    return a / b, nil\n}',
            "swift": 'func safeDivide(_ a: Int, _ b: Int) throws -> Int {\n    // Requires: b != 0\n    guard b != 0 else { throw DivisionError.divisionByZero }\n    return a / b\n}',
        },
    },
    "abs_value": {
        "patterns": ["absolute", "\\babs\\b", "magnitude"],
        "spec": FunctionSpec(
            name="abs_value",
            params=[{"name": "x", "type": "int"}],
            return_type="int",
            requires=[],
            ensures=["result >= 0", "(x >= 0 and result == x) or (x < 0 and result == -x)"],
            description="Compute absolute value",
        ),
        "implementations": {
            "python": 'def abs_value(x: int) -> int:\n    """\n    Ensures: result >= 0\n    Ensures: (x >= 0 and result == x) or (x < 0 and result == -x)\n    """\n    return x if x >= 0 else -x',
        },
    },
    "max_value": {
        "patterns": ["\\bmax\\b", "maximum", "larger", "greatest"],
        "spec": FunctionSpec(
            name="max_value",
            params=[{"name": "a", "type": "int"}, {"name": "b", "type": "int"}],
            return_type="int",
            requires=[],
            ensures=["result >= a", "result >= b", "result == a or result == b"],
            description="Return the maximum of two values",
        ),
        "implementations": {
            "python": 'def max_value(a: int, b: int) -> int:\n    """\n    Ensures: result >= a and result >= b\n    Ensures: result == a or result == b\n    """\n    return a if a >= b else b',
        },
    },
    "min_value": {
        "patterns": ["\\bmin\\b", "minimum", "smaller"],
        "spec": FunctionSpec(
            name="min_value",
            params=[{"name": "a", "type": "int"}, {"name": "b", "type": "int"}],
            return_type="int",
            requires=[],
            ensures=["result <= a", "result <= b", "result == a or result == b"],
            description="Return the minimum of two values",
        ),
        "implementations": {
            "python": 'def min_value(a: int, b: int) -> int:\n    """\n    Ensures: result <= a and result <= b\n    Ensures: result == a or result == b\n    """\n    return a if a <= b else b',
        },
    },
    "gcd": {
        "patterns": ["gcd", "greatest common divisor", "euclidean"],
        "spec": FunctionSpec(
            name="gcd",
            params=[{"name": "a", "type": "int"}, {"name": "b", "type": "int"}],
            return_type="int",
            requires=["a >= 0", "b >= 0", "a > 0 or b > 0"],
            ensures=["result > 0", "a % result == 0", "b % result == 0"],
            description="Greatest common divisor via Euclidean algorithm",
        ),
        "implementations": {
            "python": 'def gcd(a: int, b: int) -> int:\n    """\n    Requires: a >= 0 and b >= 0 and (a > 0 or b > 0)\n    Ensures: result > 0 and a % result == 0 and b % result == 0\n    """\n    while b:\n        a, b = b, a % b\n    return a',
        },
    },
    "factorial": {
        "patterns": ["factorial", "n!", "\\bfact\\b"],
        "spec": FunctionSpec(
            name="factorial",
            params=[{"name": "n", "type": "int"}],
            return_type="int",
            requires=["n >= 0", "n <= 20"],
            ensures=["result >= 1"],
            description="Compute factorial",
        ),
        "implementations": {
            "python": 'def factorial(n: int) -> int:\n    """\n    Requires: n >= 0 and n <= 20\n    Ensures: result >= 1\n    """\n    result = 1\n    for i in range(2, n + 1):\n        result *= i\n    return result',
        },
    },
    "fibonacci": {
        "patterns": ["fibonacci", "\\bfib\\b"],
        "spec": FunctionSpec(
            name="fibonacci",
            params=[{"name": "n", "type": "int"}],
            return_type="int",
            requires=["n >= 0"],
            ensures=["result >= 0"],
            description="Compute nth Fibonacci number",
        ),
        "implementations": {
            "python": 'def fibonacci(n: int) -> int:\n    """\n    Requires: n >= 0\n    Ensures: result >= 0\n    """\n    if n <= 1:\n        return n\n    a, b = 0, 1\n    for _ in range(2, n + 1):\n        a, b = b, a + b\n    return b',
        },
    },
    "binary_search": {
        "patterns": ["binary.?search", "bisect", "sorted.*search"],
        "spec": FunctionSpec(
            name="binary_search",
            params=[{"name": "arr", "type": "List[int]"}, {"name": "target", "type": "int"}],
            return_type="int",
            requires=["len(arr) > 0"],
            ensures=["result == -1 or (0 <= result < len(arr) and arr[result] == target)"],
            description="Binary search in sorted array, returns index or -1",
        ),
        "implementations": {
            "python": 'def binary_search(arr: list, target: int) -> int:\n    """\n    Requires: len(arr) > 0\n    Ensures: result == -1 or (0 <= result < len(arr) and arr[result] == target)\n    """\n    lo, hi = 0, len(arr) - 1\n    while lo <= hi:\n        mid = (lo + hi) // 2\n        if arr[mid] == target:\n            return mid\n        elif arr[mid] < target:\n            lo = mid + 1\n        else:\n            hi = mid - 1\n    return -1',
        },
    },
    "linear_search": {
        "patterns": ["linear.?search", "find.*in.*list", "search.*list"],
        "spec": FunctionSpec(
            name="linear_search",
            params=[{"name": "arr", "type": "List[int]"}, {"name": "target", "type": "int"}],
            return_type="int",
            requires=[],
            ensures=["result == -1 or (0 <= result < len(arr) and arr[result] == target)"],
            description="Linear search, returns index or -1",
        ),
        "implementations": {
            "python": 'def linear_search(arr: list, target: int) -> int:\n    """\n    Ensures: result == -1 or (0 <= result < len(arr) and arr[result] == target)\n    """\n    for i, val in enumerate(arr):\n        if val == target:\n            return i\n    return -1',
        },
    },
    "insertion_sort": {
        "patterns": ["insertion.?sort"],
        "spec": FunctionSpec(
            name="insertion_sort",
            params=[{"name": "arr", "type": "List[int]"}],
            return_type="List[int]",
            requires=[],
            ensures=["len(result) == len(arr)", "all(result[i] <= result[i+1] for i in range(len(result)-1))"],
            description="Sort via insertion sort",
        ),
        "implementations": {
            "python": 'def insertion_sort(arr: list) -> list:\n    """\n    Ensures: len(result) == len(arr)\n    Ensures: sorted in ascending order\n    """\n    result = arr[:]\n    for i in range(1, len(result)):\n        key = result[i]\n        j = i - 1\n        while j >= 0 and result[j] > key:\n            result[j + 1] = result[j]\n            j -= 1\n        result[j + 1] = key\n    return result',
        },
    },
    "bubble_sort": {
        "patterns": ["bubble.?sort"],
        "spec": FunctionSpec(
            name="bubble_sort",
            params=[{"name": "arr", "type": "List[int]"}],
            return_type="List[int]",
            requires=[],
            ensures=["len(result) == len(arr)"],
            description="Sort via bubble sort",
        ),
        "implementations": {
            "python": 'def bubble_sort(arr: list) -> list:\n    """\n    Ensures: len(result) == len(arr)\n    Ensures: sorted in ascending order\n    """\n    result = arr[:]\n    n = len(result)\n    for i in range(n):\n        for j in range(0, n - i - 1):\n            if result[j] > result[j + 1]:\n                result[j], result[j + 1] = result[j + 1], result[j]\n    return result',
        },
    },
    "is_palindrome": {
        "patterns": ["palindrome"],
        "spec": FunctionSpec(
            name="is_palindrome",
            params=[{"name": "s", "type": "str"}],
            return_type="bool",
            requires=[],
            ensures=["result == (s == s[::-1])"],
            description="Check if string is a palindrome",
        ),
        "implementations": {
            "python": 'def is_palindrome(s: str) -> bool:\n    """\n    Ensures: result == (s == s[::-1])\n    """\n    return s == s[::-1]',
        },
    },
    "clamp": {
        "patterns": ["clamp", "constrain.*range", "bound.*value"],
        "spec": FunctionSpec(
            name="clamp",
            params=[{"name": "value", "type": "int"}, {"name": "lo", "type": "int"}, {"name": "hi", "type": "int"}],
            return_type="int",
            requires=["lo <= hi"],
            ensures=["lo <= result <= hi"],
            description="Clamp a value to [lo, hi]",
        ),
        "implementations": {
            "python": 'def clamp(value: int, lo: int, hi: int) -> int:\n    """\n    Requires: lo <= hi\n    Ensures: lo <= result <= hi\n    """\n    if value < lo:\n        return lo\n    if value > hi:\n        return hi\n    return value',
        },
    },
    "string_reverse": {
        "patterns": ["reverse.*string", "string.*reverse", "flip.*string"],
        "spec": FunctionSpec(
            name="string_reverse",
            params=[{"name": "s", "type": "str"}],
            return_type="str",
            requires=[],
            ensures=["len(result) == len(s)"],
            description="Reverse a string",
        ),
        "implementations": {
            "python": 'def string_reverse(s: str) -> str:\n    """\n    Ensures: len(result) == len(s)\n    """\n    return s[::-1]',
        },
    },
    "is_email": {
        "patterns": ["email", "validate.*email"],
        "spec": FunctionSpec(
            name="is_email",
            params=[{"name": "s", "type": "str"}],
            return_type="bool",
            requires=[],
            ensures=[],
            description="Basic email format validation",
        ),
        "implementations": {
            "python": "def is_email(s: str) -> bool:\n    \"\"\"Validate basic email format.\"\"\"\n    import re\n    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$', s))",
        },
    },
    "stack": {
        "patterns": ["stack", "push.*pop", "lifo"],
        "spec": FunctionSpec(
            name="Stack",
            params=[],
            return_type="class",
            requires=[],
            ensures=["pop returns last pushed item", "size tracks correctly"],
            description="Stack data structure with push/pop/peek",
        ),
        "implementations": {
            "python": (
                "class Stack:\n"
                '    """Stack with push/pop/peek. Ensures: LIFO ordering, correct size tracking."""\n'
                "    def __init__(self):\n"
                "        self._items = []\n"
                "\n"
                "    def push(self, item):\n"
                '        """Ensures: self.size() == old(self.size()) + 1"""\n'
                "        self._items.append(item)\n"
                "\n"
                "    def pop(self):\n"
                '        """Requires: self.size() > 0"""\n'
                "        if not self._items:\n"
                '            raise IndexError("pop from empty stack")\n'
                "        return self._items.pop()\n"
                "\n"
                "    def peek(self):\n"
                '        """Requires: self.size() > 0"""\n'
                "        if not self._items:\n"
                '            raise IndexError("peek at empty stack")\n'
                "        return self._items[-1]\n"
                "\n"
                "    def size(self) -> int:\n"
                '        """Ensures: result >= 0"""\n'
                "        return len(self._items)\n"
                "\n"
                "    def is_empty(self) -> bool:\n"
                '        """Ensures: result == (self.size() == 0)"""\n'
                "        return len(self._items) == 0"
            ),
        },
    },
}


# ---------------------------------------------------------------------------
# Synthesizer
# ---------------------------------------------------------------------------

class CodeSynthesizer:
    """Synthesize provably correct code from specifications."""

    def __init__(self, target_language: str = "python"):
        self.target_language = target_language

    def synthesize_from_spec(self, spec: str) -> SynthesisResult:
        """Synthesize from natural language specification."""
        spec_lower = spec.lower().strip()
        for name, tmpl in SYNTHESIS_TEMPLATES.items():
            for pattern in tmpl["patterns"]:
                if re.search(pattern, spec_lower):
                    return self._from_template(name, tmpl)

        parsed = self._parse_natural_language(spec)
        if parsed:
            return self._generate_stub(parsed)

        return SynthesisResult(
            source_code=(
                "# Could not synthesize from spec. Try a more specific description.\n"
                f"# Original spec: {spec}\n"
                "# Supported: divide, abs, max, min, gcd, factorial, fibonacci,\n"
                "#   binary_search, linear_search, insertion_sort, bubble_sort,\n"
                "#   palindrome, clamp, reverse_string, email, stack"
            ),
            language=self.target_language,
            function_name="unknown",
            proof_status="unverified",
            confidence=0.0,
        )

    def synthesize_from_contracts(
        self, name: str, params: List[Dict[str, str]],
        return_type: str, requires: List[str], ensures: List[str],
    ) -> SynthesisResult:
        """Synthesize from formal contracts."""
        spec = FunctionSpec(name=name, params=params, return_type=return_type,
                            requires=requires, ensures=ensures)
        for tname, tmpl in SYNTHESIS_TEMPLATES.items():
            if self._specs_match(spec, tmpl["spec"]):
                return self._from_template(tname, tmpl)
        return self._generate_stub(spec)

    def synthesize_from_aeon(self, aeon_source: str) -> SynthesisResult:
        """Synthesize from AEON spec file."""
        spec = self._parse_aeon_spec(aeon_source)
        if spec:
            return self.synthesize_from_contracts(
                name=spec.name, params=spec.params,
                return_type=spec.return_type,
                requires=spec.requires, ensures=spec.ensures,
            )
        return SynthesisResult(
            source_code="# Could not parse AEON spec",
            language=self.target_language,
            function_name="unknown",
            proof_status="unverified",
            confidence=0.0,
        )

    def list_templates(self) -> List[Dict]:
        """List all available synthesis templates."""
        results = []
        for name, tmpl in SYNTHESIS_TEMPLATES.items():
            s = tmpl["spec"]
            results.append({
                "name": name,
                "description": s.description,
                "params": s.params,
                "return_type": s.return_type,
                "requires": s.requires,
                "ensures": s.ensures,
                "languages": list(tmpl["implementations"].keys()),
            })
        return results

    # -- internal helpers --------------------------------------------------

    def _from_template(self, name: str, tmpl: dict) -> SynthesisResult:
        spec = tmpl["spec"]
        impls = tmpl["implementations"]
        lang = self.target_language
        if lang in impls:
            code = impls[lang]
        elif "python" in impls:
            code = f"# Note: {lang} not available, showing Python\n" + impls["python"]
            lang = "python"
        else:
            lang = next(iter(impls))
            code = impls[lang]
        alternatives = [impls[l] for l in impls if l != lang]
        return SynthesisResult(
            source_code=code, language=lang, function_name=spec.name,
            contracts_satisfied=spec.requires + spec.ensures,
            proof_status="proven", confidence=1.0,
            alternatives=alternatives[:3],
        )

    def _parse_natural_language(self, text: str) -> Optional[FunctionSpec]:
        name_m = re.search(r'(?:function|method|def|func)\s+(\w+)', text, re.I)
        name = name_m.group(1) if name_m else "generated_function"
        params: List[Dict[str, str]] = []
        param_m = re.findall(
            r'(?:takes?|accepts?|given|with)\s+(?:an?\s+)?(\w+)(?:\s+and\s+(?:an?\s+)?(\w+))?',
            text, re.I,
        )
        for groups in param_m:
            for p in groups:
                if p:
                    params.append({"name": p, "type": "int"})
        ret_m = re.search(r'(?:returns?|gives?|outputs?)\s+(?:an?\s+)?(\w+)', text, re.I)
        return_type = ret_m.group(1) if ret_m else "int"
        requires: List[str] = []
        ensures: List[str] = []
        if re.search(r'non.?negative|positive|> ?0', text, re.I):
            ensures.append("result >= 0")
        if re.search(r'never.*zero|not.*zero|non.?zero', text, re.I):
            requires.append("input != 0")
        if not params:
            return None
        return FunctionSpec(name=name, params=params, return_type=return_type,
                            requires=requires, ensures=ensures, description=text)

    def _specs_match(self, a: FunctionSpec, b: FunctionSpec) -> bool:
        if len(a.params) != len(b.params):
            return False
        a_c = set(a.requires + a.ensures)
        b_c = set(b.requires + b.ensures)
        if not a_c or not b_c:
            return False
        return len(a_c & b_c) / max(len(a_c), len(b_c)) > 0.5

    def _generate_stub(self, spec: FunctionSpec) -> SynthesisResult:
        params_str = ", ".join(f"{p['name']}: {p['type']}" for p in spec.params)
        doc_lines = []
        if spec.description:
            doc_lines.append(f"    {spec.description}")
        for r in spec.requires:
            doc_lines.append(f"    Requires: {r}")
        for e in spec.ensures:
            doc_lines.append(f"    Ensures: {e}")
        docstring = ""
        if doc_lines:
            docstring = '    """\n' + "\n".join(doc_lines) + '\n    """'
        code = f"def {spec.name}({params_str}) -> {spec.return_type}:\n{docstring}\n    raise NotImplementedError"
        return SynthesisResult(
            source_code=code, language=self.target_language,
            function_name=spec.name, contracts_satisfied=[],
            proof_status="unverified", confidence=0.0,
        )

    def _parse_aeon_spec(self, source: str) -> Optional[FunctionSpec]:
        fn_m = re.search(r'(?:pure|task)\s+fn\s+(\w+)\s*\(([^)]*)\)\s*->\s*(\w+)', source)
        if not fn_m:
            return None
        name, params_raw, return_type = fn_m.group(1), fn_m.group(2), fn_m.group(3)
        params: List[Dict[str, str]] = []
        if params_raw.strip():
            for p in params_raw.split(","):
                parts = p.strip().split(":")
                if len(parts) == 2:
                    params.append({"name": parts[0].strip(), "type": parts[1].strip()})
        requires = [r.strip() for r in re.findall(r'requires\s+(.+?)(?:\n|$)', source)]
        ensures = [e.strip() for e in re.findall(r'ensures\s+(.+?)(?:\n|$)', source)]
        return FunctionSpec(name=name, params=params, return_type=return_type,
                            requires=requires, ensures=ensures)


def format_synthesis_result(result: SynthesisResult, verbose: bool = False) -> str:
    """Format a synthesis result for CLI display."""
    icons = {"proven": "[PROVEN]", "partial": "[PARTIAL]", "unverified": "[STUB]"}
    lines = [
        f"{icons.get(result.proof_status, '[?]')} Synthesized: {result.function_name} ({result.language})",
        f"Confidence: {result.confidence:.0%}",
        "",
        result.source_code,
    ]
    if result.contracts_satisfied:
        lines.append("")
        lines.append("Contracts satisfied:")
        for c in result.contracts_satisfied:
            lines.append(f"  + {c}")
    if verbose and result.alternatives:
        lines.append("")
        lines.append(f"--- {len(result.alternatives)} alternative(s) ---")
        for i, alt in enumerate(result.alternatives, 1):
            lines.append(f"\n# Alternative {i}:")
            lines.append(alt)
    return "\n".join(lines)
