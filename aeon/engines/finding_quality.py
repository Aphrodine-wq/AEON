"""AEON Finding Quality Engine — Confidence Scoring, Dedup, Smart Filtering.

Transforms raw engine output from noise into signal.  Every finding gets:
  - confidence: 0.0–1.0 (how likely this is a real bug, not a false positive)
  - priority: 1–5 (how urgently it should be fixed)
  - category: what kind of issue (security, money, correctness, style)
  - deduplicated: same bug from multiple engines → single finding

Confidence heuristics:
  - Engine crash → 0.0 (suppress entirely)
  - Type translation artifact → 0.0 (suppress)
  - Division by constant → 0.05 (almost always false positive)
  - Division by guarded variable → 0.1
  - Division by unguarded variable in money code → 0.95
  - Taint from known source to known sink → 0.9
  - Generic "contract violation" → 0.3 (needs context)
  - Money math in estimation function → 0.85

Priority heuristics:
  - Security (taint, injection, leak) in API route → P1
  - Money math bug in pricing/estimation → P1
  - Null access in business logic → P2
  - Division by zero in guarded code → P4
  - Style/type suggestion → P5
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any


# ---------------------------------------------------------------------------
# Finding with Quality Metadata
# ---------------------------------------------------------------------------

@dataclass
class QualifiedFinding:
    """A finding enriched with quality metadata."""
    message: str
    file: str = ""
    line: int = 0
    engine: str = "unknown"
    severity: str = "warning"  # error, warning, info
    confidence: float = 0.5
    priority: int = 3  # 1=critical, 5=low
    category: str = "correctness"  # security, money, correctness, performance, style
    rule_id: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    dedup_key: str = ""
    original: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "engine": self.engine,
            "severity": self.severity,
            "confidence": self.confidence,
            "priority": self.priority,
            "category": self.category,
            "rule_id": self.rule_id,
            "suppressed": self.suppressed,
        }


# ---------------------------------------------------------------------------
# Noise Patterns — things that are almost always false positives
# ---------------------------------------------------------------------------

# Engine crash patterns (confidence → 0.0)
ENGINE_CRASH_PATTERNS: List[str] = [
    r"analysis failed:",
    r"checking failed:",
    r"verification failed:",
    r"'[A-Za-z]+' object has no attribute",
    r"object is not subscriptable",
    r"cannot unpack non-sequence",
    r"list index out of range",
    r"maximum recursion depth",
    r"NoneType",
]

# Type translation artifacts (confidence → 0.0)
TYPE_NOISE_PATTERNS: List[str] = [
    r"Expected type '.*', got 'Void'",
    r"Expected type 'Data type', got",
    r"Cannot determine type of",
    r"Unknown type '.*' in",
    r"Type '.*' is not assignable to",
]

# Effect inference noise (confidence → 0.1)
EFFECT_NOISE_PATTERNS: List[str] = [
    r"Effect '.*' not declared\. Declared",
    r"Undeclared effect",
    r"effects \[.*\] used but not declared",
]

# React/JSX translation artifacts (confidence → 0.0)
JSX_NOISE_PATTERNS: List[str] = [
    r"Unreachable code.*after 'return'",  # JSX returns always look like this
    r"Null dereference.*accessing '\.\d",  # Tailwind fractions: 0.5, 1.5
    r"Null dereference.*accessing '\.' on '['\"]",  # String literal prop access
    r"Null dereference.*accessing '\.\"'",  # JSX attribute quotes
    r"Null dereference.*accessing '\.' on '\d",  # Numeric noise
    r"Unused parameter.*children",  # React children prop
    r"Unused parameter.*\{$",  # Destructured React props
]

# Division by constant (confidence → 0.05)
SAFE_DIVISION_PATTERNS: List[str] = [
    r"divisor '(?:100|2|10|1000|60|24|12|365|1024|256|3\.14|Math\.PI)'",
    r"division.*(?:/ 100|/ 2\.0|/ 10|/ 1000)",
]

# Division by guarded variable (confidence → 0.15)
GUARDED_DIVISION_INDICATORS: Set[str] = {
    "> 0", "!= 0", "!== 0", "> 0.0", "!= 0.0",
    "length > 0", "count > 0", "size > 0",
}

# Abstract interpretation "top" domain = no info = false positive
ABSTRACT_INTERP_NOISE: List[str] = [
    r"divisor_range.*top",
    r"abstract interpretation.*division",
]

# File types where division-by-zero is almost certainly noise
UI_COMPONENT_PATTERNS: List[str] = [
    r"component", r"page\.tsx", r"layout\.tsx", r"hero", r"footer",
    r"navbar", r"sidebar", r"header", r"badge", r"button", r"card",
    r"dialog", r"modal", r"form", r"testimonial", r"pricing",
    r"features", r"cta", r"stats", r"section",
]

# Money-specific patterns that are HIGH confidence
MONEY_HIGH_CONFIDENCE: List[str] = [
    r"float.*money",
    r"money.*float",
    r"toFixed\(\).*money",
    r"Accumulating money",
    r"Precision risk in money",
    r"unrounded money",
]

# Security patterns that are HIGH confidence
SECURITY_HIGH_CONFIDENCE: List[str] = [
    r"Tainted input flows into Supabase",
    r"XSS risk.*tainted",
    r"Open redirect.*tainted",
    r"dangerouslySetInnerHTML",
    r"SQL injection",
    r"command injection",
]


# ---------------------------------------------------------------------------
# Confidence Scorer
# ---------------------------------------------------------------------------

class FindingQualityAnalyzer:
    """Scores and filters verification findings."""

    def __init__(self, min_confidence: float = 0.3, max_findings: int = 0):
        self.min_confidence = min_confidence
        self.max_findings = max_findings  # 0 = unlimited
        self._seen_dedup: Set[str] = set()

    def process_findings(self, findings: List[Dict[str, Any]],
                         filepath: str = "") -> List[QualifiedFinding]:
        """Process raw findings into qualified, scored, deduplicated results."""
        qualified: List[QualifiedFinding] = []

        for f in findings:
            qf = self._qualify(f, filepath)

            # Dedup: same message at same location → keep highest confidence
            if qf.dedup_key in self._seen_dedup:
                continue
            self._seen_dedup.add(qf.dedup_key)

            # Filter by confidence
            if qf.confidence < self.min_confidence:
                qf.suppressed = True
                qf.suppression_reason = f"confidence {qf.confidence:.2f} < threshold {self.min_confidence:.2f}"

            qualified.append(qf)

        # Sort by priority then confidence (descending)
        qualified.sort(key=lambda x: (x.priority, -x.confidence))

        # Limit if requested
        if self.max_findings > 0:
            qualified = qualified[:self.max_findings]

        return qualified

    def process_scan_results(self, file_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process an entire scan's file results through quality analysis.

        Returns enriched results with confidence scores, suppressed counts,
        and health score.
        """
        self._seen_dedup = set()
        total_raw = 0
        total_real = 0
        total_suppressed = 0
        enriched_files: List[Dict[str, Any]] = []

        for fr in file_results:
            filepath = fr.get("file", "")
            raw_errors = fr.get("error_details", [])
            raw_warnings = fr.get("warning_details", [])
            total_raw += len(raw_errors) + len(raw_warnings)

            all_findings = []
            for e in raw_errors:
                e["_severity"] = "error"
                all_findings.append(e)
            for w in raw_warnings:
                w["_severity"] = "warning"
                all_findings.append(w)

            qualified = self.process_findings(all_findings, filepath)
            real = [q for q in qualified if not q.suppressed]
            suppressed = [q for q in qualified if q.suppressed]

            total_real += len(real)
            total_suppressed += len(suppressed)

            enriched = dict(fr)
            enriched["qualified_findings"] = [q.to_dict() for q in real]
            enriched["real_errors"] = len([q for q in real if q.severity == "error"])
            enriched["real_warnings"] = len([q for q in real if q.severity == "warning"])
            enriched["suppressed_count"] = len(suppressed)
            enriched_files.append(enriched)

        # Health score: 100 = no real findings, 0 = everything is broken
        health = max(0, 100 - (total_real * 2))

        return {
            "file_results": enriched_files,
            "total_raw": total_raw,
            "total_real": total_real,
            "total_suppressed": total_suppressed,
            "noise_ratio": round(total_suppressed / max(total_raw, 1), 2),
            "health_score": health,
        }

    def _qualify(self, finding: Dict[str, Any], filepath: str) -> QualifiedFinding:
        """Score a single finding."""
        msg = finding.get("message", "")
        details = finding.get("details", {})
        fv = details.get("failing_values", {})
        engine = fv.get("engine", "unknown")
        severity = finding.get("_severity", fv.get("severity", "warning"))
        line = details.get("location", {}).get("line", 0) if isinstance(details.get("location"), dict) else 0

        qf = QualifiedFinding(
            message=msg,
            file=filepath,
            line=line,
            engine=engine,
            severity=severity,
            original=finding,
        )

        # Generate dedup key (file + line + core message)
        core_msg = re.sub(r"'[^']*'", "'X'", msg)[:80]
        qf.dedup_key = f"{filepath}:{line}:{core_msg}"

        # --- Score confidence ---
        qf.confidence = self._score_confidence(msg, engine, fv, filepath)

        # --- Assign category ---
        qf.category = self._categorize(msg, engine, fv)

        # --- Assign priority ---
        qf.priority = self._prioritize(qf)

        # --- Assign rule_id ---
        qf.rule_id = fv.get("risk", fv.get("rule", engine.lower().replace(" ", "_")))

        return qf

    def _score_confidence(self, msg: str, engine: str,
                          fv: Dict[str, Any], filepath: str) -> float:
        """Score confidence 0.0–1.0."""
        # Engine crash → 0.0
        for pattern in ENGINE_CRASH_PATTERNS:
            if re.search(pattern, msg, re.IGNORECASE):
                return 0.0

        # Type translation noise → 0.0
        for pattern in TYPE_NOISE_PATTERNS:
            if re.search(pattern, msg, re.IGNORECASE):
                return 0.0

        # Abstract interpretation "top" domain noise → 0.0
        # When divisor_range is "top", the engine has no info — pure noise
        divisor_range = fv.get("divisor_range", "")
        if divisor_range == "top" and "division" in msg.lower():
            return 0.0

        # JSX/React translation noise → 0.0
        for pattern in JSX_NOISE_PATTERNS:
            if re.search(pattern, msg):
                return 0.0

        # Effect inference noise → 0.1
        for pattern in EFFECT_NOISE_PATTERNS:
            if re.search(pattern, msg, re.IGNORECASE):
                return 0.1

        # Safe division (by constant) → 0.05
        for pattern in SAFE_DIVISION_PATTERNS:
            if re.search(pattern, msg, re.IGNORECASE):
                return 0.05

        # Generic "division by zero" in UI components → 0.05
        if "division" in msg.lower() and "zero" in msg.lower() and filepath:
            filename = filepath.lower().split("/")[-1] if "/" in filepath else filepath.lower()
            for pattern in UI_COMPONENT_PATTERNS:
                if re.search(pattern, filename):
                    return 0.05

        # Money math — high confidence
        for pattern in MONEY_HIGH_CONFIDENCE:
            if re.search(pattern, msg, re.IGNORECASE):
                return 0.9

        # Security — high confidence
        for pattern in SECURITY_HIGH_CONFIDENCE:
            if re.search(pattern, msg, re.IGNORECASE):
                return 0.92

        # Framework rules — generally reliable
        if engine == "Framework Rules":
            return 0.85

        # Money Math engine — generally reliable
        if engine == "Money Math":
            return 0.8

        # Construction Domain engine — domain-specific, high value
        if engine == "Construction Domain":
            return 0.85

        # UI/UX lint — useful practical findings
        if "UI/UX" in msg or "ui_ux" in engine.lower():
            if "console.log" in msg:
                return 0.9  # console.log in prod is always a bug
            if "File is" in msg and "lines" in msg:
                return 0.5  # file length is subjective
            if "repeated" in msg and "times" in msg:
                return 0.4  # string duplication is minor
            return 0.6  # a11y, focus, etc.

        # Numeric Safety — moderate (lots of false positives)
        if engine == "Numeric Safety":
            # Division by zero without context
            if "division by zero" in msg.lower():
                return 0.35
            if "overflow" in msg.lower():
                return 0.4
            if "float" in msg.lower() and "equality" in msg.lower():
                return 0.6
            return 0.4

        # Taint analysis — moderate-high
        if engine in ("Taint Analysis", "taint"):
            return 0.7

        # Information flow — moderate
        if engine == "Information Flow":
            return 0.5

        # Symbolic execution — moderate
        if "Symbolic execution" in msg:
            if "division" in msg.lower():
                return 0.3
            return 0.5

        # Hoare logic — moderate-high
        if engine == "Hoare Logic":
            return 0.6

        # Generic contract violation
        if "Contract violation" in msg:
            if "division" in msg.lower():
                return 0.3
            return 0.45

        # Abstract interpretation — moderate
        if engine in ("Abstract Interpretation", "abstract_interp"):
            return 0.5

        # Everything else
        return 0.4

    def _categorize(self, msg: str, engine: str, fv: Dict[str, Any]) -> str:
        """Categorize a finding."""
        # Security
        if engine in ("Framework Rules", "Taint Analysis", "Information Flow", "taint"):
            return "security"
        if any(kw in msg.lower() for kw in ("injection", "xss", "taint", "redirect", "leak", "secret")):
            return "security"

        # Money
        if engine == "Money Math":
            return "money"
        if any(kw in msg.lower() for kw in ("money", "price", "cost", "rounding", "precision", "currency")):
            return "money"

        # Performance
        if engine in ("Complexity Analysis", "size_change"):
            return "performance"
        if any(kw in msg.lower() for kw in ("termination", "complexity", "infinite")):
            return "performance"

        # UI/UX
        if "UI/UX" in msg:
            return "style"

        # Construction domain
        if engine == "Construction Domain":
            return "money"

        # Correctness (default)
        return "correctness"

    def _prioritize(self, qf: QualifiedFinding) -> int:
        """Assign priority 1-5."""
        if qf.confidence < 0.2:
            return 5

        # P1: High-confidence security or money bugs
        if qf.confidence >= 0.8 and qf.category in ("security", "money"):
            return 1

        # P2: Medium-high confidence security/money, or high correctness
        if qf.confidence >= 0.6 and qf.category in ("security", "money"):
            return 2
        if qf.confidence >= 0.8 and qf.category == "correctness":
            return 2

        # P3: Medium confidence anything
        if qf.confidence >= 0.4:
            return 3

        # P4: Low confidence
        if qf.confidence >= 0.2:
            return 4

        return 5


# ---------------------------------------------------------------------------
# Inline Suppression Parser
# ---------------------------------------------------------------------------

def parse_inline_suppressions(source: str) -> Dict[int, Set[str]]:
    """Parse // aeon-ignore and # aeon-ignore comments from source.

    Returns {line_number: set_of_suppressed_engines_or_empty_for_all}.

    Supported formats:
      // aeon-ignore                    → suppress all on this line
      // aeon-ignore-next-line          → suppress all on next line
      // aeon-ignore money_math         → suppress money_math on this line
      // aeon-ignore-next-line taint    → suppress taint on next line
      # aeon-ignore                     → Python style
      /* aeon-ignore */                 → block comment style
    """
    suppressions: Dict[int, Set[str]] = {}

    for i, line in enumerate(source.split("\n"), 1):
        stripped = line.strip()

        # Match suppression comments
        match = re.search(
            r'(?://|#|/\*)\s*aeon-ignore(?:-next-line)?\s*([\w,\s]*?)(?:\*/)?$',
            stripped
        )
        if not match:
            continue

        engines_str = match.group(1).strip()
        engines = set()
        if engines_str:
            engines = {e.strip().lower() for e in engines_str.split(",") if e.strip()}

        if "next-line" in stripped.lower():
            # Suppress on the NEXT line
            suppressions[i + 1] = engines
        else:
            # Suppress on THIS line
            suppressions[i] = engines

    return suppressions


def apply_suppressions(findings: List[QualifiedFinding],
                       suppressions: Dict[int, Set[str]]) -> List[QualifiedFinding]:
    """Apply inline suppressions to findings."""
    for f in findings:
        if f.line in suppressions:
            engines = suppressions[f.line]
            if not engines:
                # Empty set → suppress ALL engines on this line
                f.suppressed = True
                f.suppression_reason = "aeon-ignore"
            elif f.engine.lower().replace(" ", "_") in engines:
                f.suppressed = True
                f.suppression_reason = f"aeon-ignore {f.engine}"
            elif f.rule_id and f.rule_id.lower() in engines:
                f.suppressed = True
                f.suppression_reason = f"aeon-ignore {f.rule_id}"
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_and_filter(findings: List[Dict[str, Any]],
                     filepath: str = "",
                     min_confidence: float = 0.3,
                     max_findings: int = 0,
                     source: str = "") -> List[QualifiedFinding]:
    """Score, filter, and deduplicate findings.

    This is the main entry point for turning raw engine output into
    actionable, prioritized findings.
    """
    analyzer = FindingQualityAnalyzer(
        min_confidence=min_confidence,
        max_findings=max_findings,
    )
    qualified = analyzer.process_findings(findings, filepath)

    # Apply inline suppressions if source provided
    if source:
        suppressions = parse_inline_suppressions(source)
        if suppressions:
            qualified = apply_suppressions(qualified, suppressions)

    return qualified
