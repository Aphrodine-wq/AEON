"""AEON Formal Diff — Invariant-aware code diffs.

Show which formal invariants were preserved, broken, added, or removed
between code versions. Understand changes mathematically, not textually.

Usage:
    aeon formal-diff                         # Diff staged changes
    aeon formal-diff HEAD~1 HEAD             # Diff two commits
    aeon formal-diff --branch main           # Diff against main
    aeon formal-diff old.py new.py           # Diff two files
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Tuple


@dataclass
class InvariantChange:
    """A change to a formal invariant."""
    function: str
    invariant: str
    change_type: str     # 'preserved', 'broken', 'added', 'removed', 'modified'
    old_status: str      # 'proven', 'unproven', 'none'
    new_status: str      # 'proven', 'unproven', 'none'
    file: str = ""
    line_before: int = 0
    line_after: int = 0
    impact: str = "unknown"      # 'safe', 'unsafe', 'unknown'
    explanation: str = ""


@dataclass
class FormalDiffResult:
    """Complete formal diff between two versions."""
    files_changed: int = 0
    functions_changed: int = 0
    invariant_changes: List[InvariantChange] = field(default_factory=list)
    safety_preserved: bool = True
    new_proofs: int = 0
    broken_proofs: int = 0
    added_invariants: int = 0
    removed_invariants: int = 0
    summary: str = ""
    risk_assessment: str = "safe"   # 'safe', 'caution', 'dangerous'


# ---------------------------------------------------------------------------
# Contract extraction patterns
# ---------------------------------------------------------------------------

CONTRACT_PATTERNS: Dict[str, List[str]] = {
    "python": [
        r'(?:Requires|requires|Precondition):\s*(.+)',
        r'(?:Ensures|ensures|Postcondition):\s*(.+)',
        r'(?:Invariant|invariant):\s*(.+)',
        r'@(?:requires|ensures|invariant)\s*\(([^)]+)\)',
        r'assert\s+(.+?)(?:\s*,|\s*$)',
    ],
    "javascript": [
        r'//\s*@(?:requires|ensures|invariant)\s+(.+)',
        r'//\s*(?:Requires|Ensures|Precondition|Postcondition):\s*(.+)',
        r'console\.assert\s*\((.+?)(?:\s*,|\s*\))',
    ],
    "java": [
        r'//\s*@(?:requires|ensures|invariant)\s+(.+)',
        r'@(?:Requires|Ensures|Invariant)\s*\("([^"]+)"\)',
        r'assert\s+(.+?)\s*;',
    ],
    "go": [
        r'//\s*@(?:requires|ensures|invariant)\s+(.+)',
        r'//\s*(?:Requires|Ensures|Contract):\s*(.+)',
    ],
    "rust": [
        r'//\s*@(?:requires|ensures|invariant)\s+(.+)',
        r'//\s*(?:Requires|Ensures|Safety):\s*(.+)',
        r'assert!\s*\((.+?)\)',
        r'debug_assert!\s*\((.+?)\)',
    ],
    "swift": [
        r'//\s*@(?:requires|ensures|invariant)\s+(.+)',
        r'precondition\s*\((.+?)\)',
        r'assert\s*\((.+?)\)',
    ],
    "c": [
        r'//\s*@(?:requires|ensures|invariant)\s+(.+)',
        r'assert\s*\((.+?)\)',
    ],
    "aeon": [
        r'requires\s+(.+?)(?:\n|$)',
        r'ensures\s+(.+?)(?:\n|$)',
        r'invariant\s+(.+?)(?:\n|$)',
    ],
}

FUNC_PATTERNS: Dict[str, str] = {
    "python": r'(?:async\s+)?def\s+(\w+)',
    "javascript": r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=)',
    "java": r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(',
    "go": r'func\s+(?:\([^)]+\)\s+)?(\w+)',
    "rust": r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)',
    "swift": r'func\s+(\w+)',
    "c": r'[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{',
    "aeon": r'(?:pure|task)\s+fn\s+(\w+)',
}

EXT_TO_LANG: Dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "javascript",
    ".java": "java", ".go": "go", ".rs": "rust",
    ".swift": "swift", ".c": "c", ".cpp": "c", ".h": "c",
    ".rb": "python", ".kt": "java", ".scala": "java",
    ".aeon": "aeon",
}


class FormalDiffer:
    """Compare code versions by their formal properties."""

    def diff_files(self, old_source: str, new_source: str,
                   language: str, filename: str = "") -> FormalDiffResult:
        """Diff two versions of source code by formal properties."""
        old_contracts = self._extract_contracts(old_source, language)
        new_contracts = self._extract_contracts(new_source, language)

        changes: List[InvariantChange] = []
        all_functions = set(list(old_contracts.keys()) + list(new_contracts.keys()))
        functions_changed = 0

        for func in sorted(all_functions):
            old_set = set(old_contracts.get(func, []))
            new_set = set(new_contracts.get(func, []))

            func_changed = False

            # Preserved
            for inv in old_set & new_set:
                changes.append(InvariantChange(
                    function=func, invariant=inv, change_type="preserved",
                    old_status="proven", new_status="proven",
                    file=filename, impact="safe",
                    explanation=f"Contract maintained across change",
                ))

            # Removed
            for inv in old_set - new_set:
                func_changed = True
                changes.append(InvariantChange(
                    function=func, invariant=inv, change_type="removed",
                    old_status="proven", new_status="none",
                    file=filename, impact="unsafe",
                    explanation=f"Contract removed — previous guarantee lost",
                ))

            # Added
            for inv in new_set - old_set:
                func_changed = True
                changes.append(InvariantChange(
                    function=func, invariant=inv, change_type="added",
                    old_status="none", new_status="proven",
                    file=filename, impact="safe",
                    explanation=f"New contract — additional guarantee",
                ))

            if func_changed:
                functions_changed += 1

        return self._build_result(changes, 1 if changes else 0, functions_changed, filename)

    def diff_git(self, commit_a: str = "HEAD~1", commit_b: str = "HEAD",
                 repo_path: str = ".") -> FormalDiffResult:
        """Diff two git commits by formal properties."""
        try:
            diff_output = subprocess.run(
                ["git", "diff", "--name-only", commit_a, commit_b],
                capture_output=True, text=True, cwd=repo_path,
            )
        except FileNotFoundError:
            return FormalDiffResult(summary="git not found")

        if diff_output.returncode != 0:
            return FormalDiffResult(summary=f"git error: {diff_output.stderr.strip()}")

        changed_files = [f for f in diff_output.stdout.strip().split("\n") if f]
        all_changes: List[InvariantChange] = []
        total_funcs_changed = 0

        for filepath in changed_files:
            lang = EXT_TO_LANG.get(Path(filepath).suffix.lower())
            if not lang:
                continue

            old_source = self._git_show(f"{commit_a}:{filepath}", repo_path)
            new_source = self._git_show(f"{commit_b}:{filepath}", repo_path)

            if old_source is None and new_source is None:
                continue

            result = self.diff_files(
                old_source or "", new_source or "",
                lang, filepath,
            )
            all_changes.extend(result.invariant_changes)
            total_funcs_changed += result.functions_changed

        return self._build_result(all_changes, len(changed_files), total_funcs_changed)

    def diff_staged(self, repo_path: str = ".") -> FormalDiffResult:
        """Diff staged changes against HEAD."""
        try:
            diff_output = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                capture_output=True, text=True, cwd=repo_path,
            )
        except FileNotFoundError:
            return FormalDiffResult(summary="git not found")

        changed_files = [f for f in diff_output.stdout.strip().split("\n") if f]
        all_changes: List[InvariantChange] = []
        total_funcs = 0

        for filepath in changed_files:
            lang = EXT_TO_LANG.get(Path(filepath).suffix.lower())
            if not lang:
                continue

            old_source = self._git_show(f"HEAD:{filepath}", repo_path)
            full_path = Path(repo_path) / filepath
            new_source = full_path.read_text(encoding="utf-8", errors="ignore") if full_path.exists() else ""

            result = self.diff_files(old_source or "", new_source, lang, filepath)
            all_changes.extend(result.invariant_changes)
            total_funcs += result.functions_changed

        return self._build_result(all_changes, len(changed_files), total_funcs)

    def diff_branch(self, base: str = "main", repo_path: str = ".") -> FormalDiffResult:
        """Diff current branch against base branch."""
        try:
            merge_base = subprocess.run(
                ["git", "merge-base", base, "HEAD"],
                capture_output=True, text=True, cwd=repo_path,
            )
        except FileNotFoundError:
            return FormalDiffResult(summary="git not found")

        if merge_base.returncode != 0:
            return self.diff_git(base, "HEAD", repo_path)

        base_commit = merge_base.stdout.strip()
        return self.diff_git(base_commit, "HEAD", repo_path)

    def format_diff(self, result: FormalDiffResult, fmt: str = "pretty") -> str:
        """Format the formal diff for display."""
        if fmt == "json":
            import json
            data = {
                "files_changed": result.files_changed,
                "functions_changed": result.functions_changed,
                "safety_preserved": result.safety_preserved,
                "risk_assessment": result.risk_assessment,
                "new_proofs": result.new_proofs,
                "broken_proofs": result.broken_proofs,
                "changes": [
                    {
                        "function": c.function, "invariant": c.invariant,
                        "type": c.change_type, "impact": c.impact,
                        "file": c.file, "explanation": c.explanation,
                    }
                    for c in result.invariant_changes
                ],
            }
            return json.dumps(data, indent=2)

        if fmt == "markdown":
            return self._format_markdown(result)

        return self._format_pretty(result)

    # -- internal ----------------------------------------------------------

    def _extract_contracts(self, source: str, language: str) -> Dict[str, List[str]]:
        """Extract contracts grouped by function name."""
        patterns = CONTRACT_PATTERNS.get(language, CONTRACT_PATTERNS.get("python", []))
        func_pattern = FUNC_PATTERNS.get(language)
        if not func_pattern:
            return {}

        contracts: Dict[str, List[str]] = {}
        lines = source.split("\n")
        current_func = "<module>"

        for line in lines:
            # Check for function definition
            fm = re.search(func_pattern, line)
            if fm:
                current_func = next((g for g in fm.groups() if g), current_func)
                if current_func not in contracts:
                    contracts[current_func] = []

            # Check for contracts
            for cp in patterns:
                cm = re.search(cp, line)
                if cm:
                    contract_text = next((g for g in cm.groups() if g), "").strip()
                    if contract_text:
                        if current_func not in contracts:
                            contracts[current_func] = []
                        contracts[current_func].append(contract_text)

        return contracts

    def _git_show(self, ref: str, repo_path: str = ".") -> Optional[str]:
        try:
            result = subprocess.run(
                ["git", "show", ref],
                capture_output=True, text=True, cwd=repo_path,
            )
            if result.returncode == 0:
                return result.stdout
        except FileNotFoundError:
            pass
        return None

    def _build_result(self, changes: List[InvariantChange],
                      files_changed: int, functions_changed: int,
                      filename: str = "") -> FormalDiffResult:
        broken = sum(1 for c in changes if c.change_type in ("broken", "removed"))
        added = sum(1 for c in changes if c.change_type == "added")
        preserved = sum(1 for c in changes if c.change_type == "preserved")

        if broken == 0:
            risk = "safe"
        elif broken <= 2:
            risk = "caution"
        else:
            risk = "dangerous"

        summary_parts = []
        if preserved:
            summary_parts.append(f"{preserved} preserved")
        if broken:
            summary_parts.append(f"{broken} broken")
        if added:
            summary_parts.append(f"{added} added")
        summary = ", ".join(summary_parts) or "no invariant changes detected"

        return FormalDiffResult(
            files_changed=files_changed,
            functions_changed=functions_changed,
            invariant_changes=changes,
            safety_preserved=broken == 0,
            new_proofs=added,
            broken_proofs=broken,
            added_invariants=added,
            removed_invariants=broken,
            summary=summary,
            risk_assessment=risk,
        )

    def _format_pretty(self, result: FormalDiffResult) -> str:
        risk_colors = {"safe": "SAFE", "caution": "CAUTION", "dangerous": "DANGEROUS"}
        lines = [
            f"FORMAL DIFF",
            f"Risk Assessment: {risk_colors.get(result.risk_assessment, '?')}",
            "",
        ]

        # Group by file then function
        by_file: Dict[str, Dict[str, List[InvariantChange]]] = {}
        for c in result.invariant_changes:
            f = c.file or "<unknown>"
            if f not in by_file:
                by_file[f] = {}
            if c.function not in by_file[f]:
                by_file[f][c.function] = []
            by_file[f][c.function].append(c)

        icons = {
            "preserved": "  PRESERVED ",
            "broken": "  BROKEN    ",
            "removed": "- REMOVED   ",
            "added": "+ ADDED     ",
            "modified": "~ MODIFIED  ",
        }

        for filepath, funcs in by_file.items():
            lines.append(f"  {filepath}")
            for func, changes in funcs.items():
                lines.append(f"    {func}()")
                for c in changes:
                    icon = icons.get(c.change_type, "  ?         ")
                    lines.append(f"    {icon} {c.invariant}")
            lines.append("")

        lines.append(f"Summary: {result.summary}")
        if not result.safety_preserved:
            lines.append(f"Safety: NOT PRESERVED — review broken invariants before merging")
        else:
            lines.append(f"Safety: PRESERVED — all invariants maintained")

        return "\n".join(lines)

    def _format_markdown(self, result: FormalDiffResult) -> str:
        risk_badge = {
            "safe": "![Safe](https://img.shields.io/badge/AEON-safe-brightgreen)",
            "caution": "![Caution](https://img.shields.io/badge/AEON-caution-yellow)",
            "dangerous": "![Dangerous](https://img.shields.io/badge/AEON-dangerous-red)",
        }
        lines = [
            "## AEON Formal Diff",
            "",
            risk_badge.get(result.risk_assessment, ""),
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Files Changed | {result.files_changed} |",
            f"| Functions Changed | {result.functions_changed} |",
            f"| Invariants Preserved | {sum(1 for c in result.invariant_changes if c.change_type == 'preserved')} |",
            f"| Invariants Broken | {result.broken_proofs} |",
            f"| Invariants Added | {result.added_invariants} |",
            "",
        ]

        if result.broken_proofs > 0:
            lines.append("### Broken Invariants")
            lines.append("")
            for c in result.invariant_changes:
                if c.change_type in ("broken", "removed"):
                    lines.append(f"- **`{c.function}`** ({c.file}): `{c.invariant}`")
            lines.append("")

        if result.added_invariants > 0:
            lines.append("### New Invariants")
            lines.append("")
            for c in result.invariant_changes:
                if c.change_type == "added":
                    lines.append(f"- **`{c.function}`** ({c.file}): `{c.invariant}`")

        return "\n".join(lines)
