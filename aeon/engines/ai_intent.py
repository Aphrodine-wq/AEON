"""AEON AI Intent Engine — LLM-Powered Logic Bug Detection.

Uses Claude to understand what code INTENDS to do, then flags where
the implementation diverges from that intent. Catches bugs that
pattern matching and formal verification cannot:

  - Business logic errors (calculation does wrong thing)
  - Missing edge cases (what happens when all inputs are zero?)
  - Security logic flaws (auth check exists but is bypassable)
  - State machine violations (estimate can be signed twice)
  - Semantic mismatches (function name says X but does Y)

Requires ANTHROPIC_API_KEY environment variable.
"""

from __future__ import annotations

import os
import json
import re
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from pathlib import Path

from aeon.errors import AeonError, ErrorKind, SourceLocation


@dataclass
class IntentFinding:
    """An AI-detected intent violation."""
    function: str
    line: int
    category: str       # logic | edge_case | security | state | semantic
    severity: str       # error | warning | info
    intent: str         # What the code appears to intend
    violation: str      # How the implementation diverges
    suggestion: str     # How to fix it
    confidence: float   # 0.0-1.0

    def to_aeon_error(self, filepath: str) -> AeonError:
        return AeonError(
            kind=ErrorKind.CONTRACT_ERROR,
            message=f"Intent: {self.violation}",
            location=SourceLocation(file=filepath, line=self.line, column=1),
            details={
                "precondition": self.violation,
                "failing_values": {
                    "category": f"intent-{self.category}",
                    "severity": self.severity,
                    "rule": f"ai-{self.category}",
                    "intent": self.intent,
                    "confidence": self.confidence,
                },
                "function_signature": self.function,
            },
            fix_suggestion=self.suggestion,
        )


# ── Claude API Integration ────────────────────────────────────────────────────

def _get_api_key() -> Optional[str]:
    return os.environ.get("ANTHROPIC_API_KEY")


def _call_claude(prompt: str, system: str = "", max_tokens: int = 4096) -> Optional[str]:
    """Call Claude API. Returns response text or None on failure."""
    api_key = _get_api_key()
    if not api_key:
        return None

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
    except ImportError:
        # Try raw HTTP if anthropic SDK not installed
        try:
            import urllib.request
            import urllib.error

            headers = {
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }
            body = json.dumps({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            }).encode()

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=body, headers=headers, method="POST",
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
                return data["content"][0]["text"]
        except Exception:
            return None
    except Exception:
        return None


# ── Function Extraction ───────────────────────────────────────────────────────

@dataclass
class ExtractedFunction:
    name: str
    line: int
    source: str
    params: str
    is_async: bool
    is_api_handler: bool
    file_context: str  # Surrounding imports/types for context


def extract_functions(source: str, filepath: str) -> List[ExtractedFunction]:
    """Extract functions from TypeScript/JavaScript source."""
    functions: List[ExtractedFunction] = []
    lines = source.split("\n")

    # Get file-level context (imports, types, interfaces — first 50 lines usually)
    context_lines = []
    for line in lines[:80]:
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("export type") or \
           stripped.startswith("export interface") or stripped.startswith("interface ") or \
           stripped.startswith("type ") or stripped.startswith("const ") and "=" not in stripped:
            context_lines.append(line)
    file_context = "\n".join(context_lines)

    # Find function boundaries
    func_pattern = re.compile(
        r'^(\s*)(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)|'  # function decl
        r'^(\s*)(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*(?::\s*\w+)?\s*=>|'  # arrow
        r'^(\s*)(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?function',  # const function
        re.MULTILINE
    )

    for match in func_pattern.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        indent = match.group(1) or match.group(4) or match.group(6) or ""
        name = match.group(2) or match.group(5) or match.group(7) or "anonymous"
        params = match.group(3) or ""

        # Find end of function (track brace depth)
        start_pos = match.start()
        brace_start = source.find("{", start_pos)
        if brace_start == -1:
            continue

        depth = 0
        pos = brace_start
        while pos < len(source):
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
                if depth == 0:
                    break
            pos += 1

        func_source = source[start_pos:pos + 1]

        # Skip tiny functions (getters, one-liners)
        if func_source.count("\n") < 3:
            continue

        is_async = "async" in source[start_pos:brace_start]
        is_api = bool(re.match(r'\s*export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)\b', func_source))

        functions.append(ExtractedFunction(
            name=name,
            line=line_num,
            source=func_source,
            params=params,
            is_async=is_async,
            is_api_handler=is_api,
            file_context=file_context,
        ))

    return functions


# ── Analysis Prompts ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are AEON's AI intent analysis engine. You analyze source code functions to find logic bugs that pattern matching and unit tests cannot catch.

Your job is to:
1. Understand what the function INTENDS to do (from name, params, comments, context)
2. Find where the IMPLEMENTATION diverges from that intent
3. Flag missing edge cases that would cause wrong behavior in production

Focus on:
- Business logic errors (wrong calculation, wrong condition)
- Missing edge cases (what if input is 0, negative, null, empty array?)
- Security logic flaws (auth bypass, IDOR, missing validation)
- State violations (double-processing, race conditions)
- Semantic mismatches (function name/docs say X but code does Y)

DO NOT flag:
- Style issues, naming conventions, or formatting
- Performance optimizations
- Missing comments or documentation
- Things that are clearly intentional patterns

Output ONLY valid JSON — an array of finding objects. If no issues found, return [].
Each finding:
{
  "function": "functionName",
  "line_offset": 5,
  "category": "logic|edge_case|security|state|semantic",
  "severity": "error|warning|info",
  "intent": "What the code appears to intend",
  "violation": "How implementation diverges from intent",
  "suggestion": "Specific fix",
  "confidence": 0.85
}"""

def _build_analysis_prompt(func: ExtractedFunction, filepath: str) -> str:
    return f"""Analyze this function for intent violations. File: {filepath}

Context (imports/types):
```
{func.file_context}
```

Function to analyze:
```typescript
{func.source}
```

Find logic bugs, missing edge cases, and security issues. Return JSON array of findings. Be precise about line_offset (relative to function start). Only report HIGH confidence findings."""


# ── Engine ────────────────────────────────────────────────────────────────────

class AIIntentEngine:
    """Analyze code using Claude to detect intent violations."""

    def __init__(self, max_functions: int = 20, skip_small: int = 5):
        self.max_functions = max_functions
        self.skip_small_lines = skip_small
        self.api_available = _get_api_key() is not None

    def analyze_file(self, filepath: str) -> List[AeonError]:
        """Analyze a file for intent violations using AI."""
        if not self.api_available:
            return []

        source = Path(filepath).read_text(encoding="utf-8", errors="ignore")
        functions = extract_functions(source, filepath)

        if not functions:
            return []

        # Prioritize: API handlers first, then largest functions
        functions.sort(key=lambda f: (not f.is_api_handler, -f.source.count("\n")))
        functions = functions[:self.max_functions]

        errors: List[AeonError] = []

        for func in functions:
            # Skip small functions
            if func.source.count("\n") < self.skip_small_lines:
                continue

            findings = self._analyze_function(func, filepath)
            errors.extend(findings)

        return errors

    def _analyze_function(self, func: ExtractedFunction, filepath: str) -> List[AeonError]:
        """Analyze a single function with Claude."""
        prompt = _build_analysis_prompt(func, filepath)
        response = _call_claude(prompt, system=SYSTEM_PROMPT, max_tokens=2048)

        if not response:
            return []

        return self._parse_response(response, func, filepath)

    def _parse_response(self, response: str, func: ExtractedFunction, filepath: str) -> List[AeonError]:
        """Parse Claude's JSON response into AeonErrors."""
        errors: List[AeonError] = []

        try:
            # Extract JSON from response (handle markdown code blocks)
            json_text = response.strip()
            if json_text.startswith("```"):
                json_text = re.sub(r'^```\w*\n?', '', json_text)
                json_text = re.sub(r'\n?```\s*$', '', json_text)

            findings = json.loads(json_text)
            if not isinstance(findings, list):
                return []

            for f in findings:
                if not isinstance(f, dict):
                    continue

                confidence = float(f.get("confidence", 0.5))
                if confidence < 0.7:
                    continue

                line = func.line + int(f.get("line_offset", 0))
                finding = IntentFinding(
                    function=f.get("function", func.name),
                    line=line,
                    category=f.get("category", "logic"),
                    severity=f.get("severity", "warning"),
                    intent=f.get("intent", ""),
                    violation=f.get("violation", "Unknown"),
                    suggestion=f.get("suggestion", ""),
                    confidence=confidence,
                )
                errors.append(finding.to_aeon_error(filepath))

        except (json.JSONDecodeError, ValueError, KeyError):
            pass

        return errors

    def analyze_source(self, source: str, filepath: str = "<unknown>") -> List[AeonError]:
        """Analyze source text directly (for pipeline integration)."""
        if not self.api_available:
            return []

        functions = extract_functions(source, filepath)
        if not functions:
            return []

        functions.sort(key=lambda f: (not f.is_api_handler, -f.source.count("\n")))
        functions = functions[:self.max_functions]

        errors: List[AeonError] = []
        for func in functions:
            if func.source.count("\n") < self.skip_small_lines:
                continue
            findings = self._analyze_function(func, filepath)
            errors.extend(findings)

        return errors


# ── Module Entry Point ────────────────────────────────────────────────────────

def check_intent(source: str, filepath: str = "<unknown>") -> List[AeonError]:
    """Run AI intent analysis on source code."""
    engine = AIIntentEngine()
    return engine.analyze_source(source, filepath)


def is_available() -> bool:
    """Check if AI intent analysis is available (API key configured)."""
    return _get_api_key() is not None
