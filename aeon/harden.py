"""AEON Harden — Gradual Adoption Engine.

Point AEON at an existing codebase and incrementally add verified contracts.
No rewrite needed — just progressive hardening.

Usage:
    aeon harden <dir>                    # Show hardening plan
    aeon harden <dir> --apply            # Apply critical-phase hardening
    aeon harden <dir> --phase critical   # Apply specific phase
    aeon harden <dir> --report           # Markdown report
    aeon harden <file> --function foo    # Harden specific function
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Tuple


@dataclass
class HardenTarget:
    """A function identified for hardening."""
    file: str
    name: str
    line: int
    language: str
    risk_score: float           # 0.0-1.0
    risk_factors: List[str] = field(default_factory=list)
    suggested_contracts: List[str] = field(default_factory=list)
    current_coverage: float = 0.0  # verification coverage


@dataclass
class HardenPlan:
    """Phased plan for hardening a codebase."""
    total_functions: int
    already_verified: int
    targets: List[HardenTarget] = field(default_factory=list)
    phases: Dict[str, List[HardenTarget]] = field(default_factory=dict)
    coverage_by_phase: Dict[str, float] = field(default_factory=dict)


@dataclass
class HardenResult:
    """Result of applying hardening to a target."""
    target: HardenTarget
    contracts_added: List[str] = field(default_factory=list)
    verification_status: str = "unverified"
    source_patch: str = ""


# ---------------------------------------------------------------------------
# Risk patterns — used to score functions
# ---------------------------------------------------------------------------

RISK_PATTERNS: Dict[str, List[Tuple[str, float, str]]] = {
    "python": [
        (r'\beval\s*\(', 1.0, "eval() — arbitrary code execution"),
        (r'\bexec\s*\(', 1.0, "exec() — arbitrary code execution"),
        (r'\bos\.system\s*\(', 0.95, "os.system() — shell injection risk"),
        (r'subprocess\.(call|run|Popen)', 0.9, "subprocess — command injection risk"),
        (r'open\s*\(', 0.5, "file I/O — path traversal risk"),
        (r'\bsql\b.*\bexecute\b|\bexecute\b.*\bsql\b', 0.9, "SQL execution — injection risk"),
        (r'\.format\(|f".*\{', 0.3, "string interpolation — injection risk"),
        (r'except\s*:', 0.4, "bare except — swallows all errors"),
        (r'except\s+Exception\s*:', 0.3, "broad except — may hide bugs"),
        (r'password|secret|token|api_key', 0.7, "handles secrets"),
        (r'def\s+login|def\s+auth|def\s+verify', 0.8, "authentication logic"),
        (r'def\s+pay|def\s+charge|def\s+transfer|def\s+withdraw', 0.9, "financial transaction"),
        (r'request\.(args|form|json|data)', 0.7, "handles user input"),
        (r'pickle\.loads?|yaml\.load\(', 0.85, "deserialization — code execution risk"),
        (r'random\.(random|randint|choice)', 0.3, "non-cryptographic randomness"),
    ],
    "javascript": [
        (r'\beval\s*\(', 1.0, "eval() — code injection"),
        (r'innerHTML\s*=', 0.9, "innerHTML — XSS risk"),
        (r'document\.write\s*\(', 0.85, "document.write — XSS risk"),
        (r'\.exec\s*\(|child_process', 0.9, "shell execution"),
        (r'req\.(body|params|query)', 0.7, "handles user input"),
        (r'\.query\s*\(.*\+|\.query\s*\(.*\$\{', 0.9, "SQL string concat"),
    ],
    "java": [
        (r'Runtime\.getRuntime\(\)\.exec', 0.95, "command execution"),
        (r'PreparedStatement|Statement.*execute', 0.7, "SQL execution"),
        (r'ObjectInputStream|readObject', 0.85, "deserialization"),
        (r'@RequestMapping|@GetMapping|@PostMapping', 0.6, "HTTP handler"),
    ],
    "go": [
        (r'exec\.Command', 0.9, "command execution"),
        (r'os\.Remove|os\.RemoveAll', 0.7, "file deletion"),
        (r'http\.Handle|http\.ListenAndServe', 0.5, "HTTP handler"),
        (r'unsafe\.Pointer', 0.8, "unsafe pointer"),
    ],
    "rust": [
        (r'\bunsafe\b', 0.8, "unsafe block"),
        (r'\.unwrap\(\)', 0.4, "unwrap — may panic"),
        (r'std::process::Command', 0.85, "command execution"),
    ],
    "swift": [
        (r'Process\(\)|NSTask', 0.85, "process execution"),
        (r'force.*unwrap|!', 0.4, "force unwrap — may crash"),
        (r'try!', 0.5, "force try — unhandled error"),
    ],
    "c": [
        (r'\bgets\s*\(', 1.0, "gets() — buffer overflow"),
        (r'\bstrcpy\s*\(', 0.9, "strcpy — buffer overflow"),
        (r'\bsprintf\s*\(', 0.85, "sprintf — buffer overflow"),
        (r'\bmalloc\s*\(', 0.5, "manual memory allocation"),
        (r'\bfree\s*\(', 0.5, "manual memory free"),
        (r'\bsystem\s*\(', 0.95, "system() — shell injection"),
    ],
}

# Contracts to suggest based on detected patterns
CONTRACT_SUGGESTIONS: Dict[str, List[str]] = {
    "division": ["requires divisor != 0"],
    "array_access": ["requires 0 <= index < len(array)"],
    "null_deref": ["requires value is not None"],
    "file_io": ["requires path.exists()", "ensures file_handle is closed"],
    "user_input": ["requires input matches safe_pattern", "requires len(input) <= MAX_LENGTH"],
    "auth": ["requires user.is_authenticated", "ensures session.is_valid"],
    "financial": ["requires amount > 0", "ensures balance >= 0", "ensures sum(balances) == total"],
    "memory": ["ensures allocated memory is freed", "requires pointer is not null"],
    "crypto": ["requires key_length >= MIN_KEY_LENGTH", "ensures timing_safe_comparison"],
}


# ---------------------------------------------------------------------------
# Extension-to-language mapping
# ---------------------------------------------------------------------------

EXT_TO_LANG: Dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "javascript",
    ".java": "java", ".go": "go", ".rs": "rust", ".swift": "swift",
    ".c": "c", ".cpp": "c", ".h": "c", ".rb": "python",
    ".kt": "java", ".scala": "java", ".php": "javascript",
    ".dart": "javascript",
}

FUNCTION_PATTERNS: Dict[str, str] = {
    "python": r'^\s*(?:async\s+)?def\s+(\w+)\s*\(',
    "javascript": r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(|(\w+)\s*\([^)]*\)\s*\{)',
    "java": r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(',
    "go": r'^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(',
    "rust": r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)',
    "swift": r'(?:func|class\s+func|static\s+func)\s+(\w+)',
    "c": r'^[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{',
}


class CodeHardener:
    """Gradually harden existing codebases with formal verification."""

    def analyze(self, path: str, language: Optional[str] = None) -> HardenPlan:
        """Analyze a codebase and generate a hardening plan."""
        root = Path(path)
        targets: List[HardenTarget] = []

        if root.is_file():
            targets.extend(self._analyze_file(str(root), language))
        else:
            for dirpath, _dirs, files in os.walk(str(root)):
                # Skip common non-source directories
                if any(skip in dirpath for skip in [
                    "node_modules", ".git", "__pycache__", "venv",
                    ".venv", "vendor", "build", "dist",
                ]):
                    continue
                for fname in files:
                    fpath = os.path.join(dirpath, fname)
                    lang = language or EXT_TO_LANG.get(Path(fname).suffix.lower())
                    if lang:
                        targets.extend(self._analyze_file(fpath, lang))

        targets.sort(key=lambda t: t.risk_score, reverse=True)

        phases: Dict[str, List[HardenTarget]] = {
            "critical": [], "high": [], "medium": [], "low": [],
        }
        for t in targets:
            if t.risk_score >= 0.8:
                phases["critical"].append(t)
            elif t.risk_score >= 0.6:
                phases["high"].append(t)
            elif t.risk_score >= 0.3:
                phases["medium"].append(t)
            else:
                phases["low"].append(t)

        total = len(targets)
        coverage: Dict[str, float] = {}
        verified_so_far = 0
        for phase_name in ["critical", "high", "medium", "low"]:
            verified_so_far += len(phases[phase_name])
            coverage[phase_name] = (verified_so_far / total * 100) if total else 0.0

        return HardenPlan(
            total_functions=total,
            already_verified=0,
            targets=targets,
            phases=phases,
            coverage_by_phase=coverage,
        )

    def harden_function(self, filepath: str, function_name: str,
                        language: Optional[str] = None) -> HardenResult:
        """Harden a single function by generating contracts."""
        lang = language or EXT_TO_LANG.get(Path(filepath).suffix.lower(), "python")
        targets = self._analyze_file(filepath, lang)
        target = None
        for t in targets:
            if t.name == function_name:
                target = t
                break
        if not target:
            target = HardenTarget(
                file=filepath, name=function_name, line=0,
                language=lang, risk_score=0.0,
            )
        return HardenResult(
            target=target,
            contracts_added=target.suggested_contracts,
            verification_status="suggested",
            source_patch=self._generate_patch(target, lang),
        )

    def generate_report(self, plan: HardenPlan) -> str:
        """Generate a markdown hardening report."""
        lines = [
            "# AEON Hardening Report",
            "",
            f"**Total Functions:** {plan.total_functions}",
            f"**Already Verified:** {plan.already_verified}",
            "",
            "## Risk Distribution",
            "",
            f"| Phase | Functions | Cumulative Coverage |",
            f"|-------|-----------|-------------------|",
        ]
        for phase in ["critical", "high", "medium", "low"]:
            count = len(plan.phases.get(phase, []))
            cov = plan.coverage_by_phase.get(phase, 0)
            lines.append(f"| {phase.upper()} | {count} | {cov:.1f}% |")

        for phase in ["critical", "high", "medium", "low"]:
            targets = plan.phases.get(phase, [])
            if not targets:
                continue
            lines.append(f"\n## Phase: {phase.upper()}")
            lines.append("")
            for t in targets[:20]:
                lines.append(f"### `{t.name}` ({t.file}:{t.line})")
                lines.append(f"Risk Score: **{t.risk_score:.2f}**")
                if t.risk_factors:
                    lines.append("Risk Factors:")
                    for rf in t.risk_factors:
                        lines.append(f"  - {rf}")
                if t.suggested_contracts:
                    lines.append("Suggested Contracts:")
                    for sc in t.suggested_contracts:
                        lines.append(f"  - `{sc}`")
                lines.append("")

        return "\n".join(lines)

    # -- internal ----------------------------------------------------------

    def _analyze_file(self, filepath: str, language: Optional[str] = None) -> List[HardenTarget]:
        lang = language or EXT_TO_LANG.get(Path(filepath).suffix.lower())
        if not lang:
            return []
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return []

        functions = self._extract_functions(source, lang)
        patterns = RISK_PATTERNS.get(lang, [])
        targets: List[HardenTarget] = []

        for func_name, func_line, func_body in functions:
            risk_score = 0.0
            risk_factors: List[str] = []
            contracts: List[str] = []

            for pattern, weight, description in patterns:
                if re.search(pattern, func_body, re.I):
                    risk_score = max(risk_score, weight)
                    risk_factors.append(description)

            # Complexity heuristic: lines of code
            loc = len(func_body.strip().split("\n"))
            if loc > 50:
                risk_score = max(risk_score, 0.4)
                risk_factors.append(f"high complexity ({loc} lines)")
            elif loc > 100:
                risk_score = max(risk_score, 0.6)
                risk_factors.append(f"very high complexity ({loc} lines)")

            # Infer contracts
            if re.search(r'/\s*[a-z]|//\s*0|%\s*[a-z]', func_body):
                contracts.append("requires divisor != 0")
            if re.search(r'\[.*\]|\bindex\b|\boffset\b', func_body):
                contracts.append("requires 0 <= index < len(collection)")
            if re.search(r'is\s+None|== None|!= None|is not None', func_body):
                contracts.append("requires value is not None")
            if re.search(r'password|secret|token|api.?key', func_body, re.I):
                contracts.extend(CONTRACT_SUGGESTIONS.get("auth", []))
            if re.search(r'amount|balance|price|charge|transfer', func_body, re.I):
                contracts.extend(CONTRACT_SUGGESTIONS.get("financial", []))
            if re.search(r'open\s*\(|read|write', func_body, re.I):
                contracts.extend(CONTRACT_SUGGESTIONS.get("file_io", []))

            # Deduplicate
            contracts = list(dict.fromkeys(contracts))

            if risk_score > 0 or contracts:
                targets.append(HardenTarget(
                    file=filepath, name=func_name, line=func_line,
                    language=lang, risk_score=risk_score,
                    risk_factors=risk_factors,
                    suggested_contracts=contracts,
                ))

        return targets

    def _extract_functions(self, source: str, language: str) -> List[Tuple[str, int, str]]:
        """Extract (name, line_number, body_text) for each function."""
        pattern = FUNCTION_PATTERNS.get(language)
        if not pattern:
            return []

        results: List[Tuple[str, int, str]] = []
        lines = source.split("\n")
        func_starts: List[Tuple[str, int]] = []

        for i, line in enumerate(lines, 1):
            m = re.search(pattern, line)
            if m:
                name = next((g for g in m.groups() if g), None)
                if name and not name.startswith("_"):
                    func_starts.append((name, i))

        for idx, (name, start) in enumerate(func_starts):
            if idx + 1 < len(func_starts):
                end = func_starts[idx + 1][1] - 1
            else:
                end = len(lines)
            body = "\n".join(lines[start - 1:end])
            results.append((name, start, body))

        return results

    def _generate_patch(self, target: HardenTarget, language: str) -> str:
        """Generate a suggested patch for adding contracts."""
        if not target.suggested_contracts:
            return ""
        if language == "python":
            doc_lines = ['    """']
            for c in target.suggested_contracts:
                doc_lines.append(f"    {c}")
            doc_lines.append('    """')
            return f"# Add to {target.name} at {target.file}:{target.line}\n" + "\n".join(doc_lines)
        else:
            comment = "//" if language in ("javascript", "java", "go", "rust", "swift", "c", "cpp") else "#"
            lines = [f"// Add to {target.name} at {target.file}:{target.line}"]
            for c in target.suggested_contracts:
                lines.append(f"{comment} @contract {c}")
            return "\n".join(lines)
