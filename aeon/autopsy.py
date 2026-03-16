"""AEON Autopsy — Incident-to-Invariant Engine.

Feed logs, stack traces, and postmortem data into AEON. It reconstructs
violated assumptions and generates permanent contracts + regression tests.
Every outage becomes formal knowledge that prevents recurrence.

Usage:
    aeon autopsy trace.log                 # Analyze a log/trace file
    aeon autopsy trace.log --source-root . # Trace to source
    aeon autopsy trace.log --output report # Full markdown report
    cat error.log | aeon autopsy --stdin   # Pipe logs in
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Tuple


@dataclass
class StackFrame:
    """A single frame in a stack trace."""
    file: str
    line: int
    function: str
    code: str = ""


@dataclass
class IncidentData:
    """Parsed incident information."""
    error_type: str
    error_message: str
    stack_trace: List[StackFrame] = field(default_factory=list)
    relevant_variables: Dict[str, str] = field(default_factory=dict)
    timestamp: str = ""
    source: str = "stacktrace"  # 'log', 'stacktrace', 'postmortem'
    language: str = "unknown"


@dataclass
class ViolatedAssumption:
    """An assumption that was violated causing the incident."""
    description: str
    file: str
    function: str
    line: int
    assumption_type: str  # 'null_check', 'bounds', 'type', 'state', 'concurrency', 'resource'
    confidence: float = 0.0


@dataclass
class GeneratedContract:
    """A contract generated to prevent recurrence."""
    contract: str          # e.g. "requires b != 0"
    target_function: str
    target_file: str
    reason: str            # Why this contract prevents the bug


@dataclass
class GeneratedTest:
    """A regression test generated from the incident."""
    test_name: str
    test_code: str
    language: str


@dataclass
class AutopsyResult:
    """Complete autopsy of an incident."""
    incident: IncidentData
    violated_assumptions: List[ViolatedAssumption] = field(default_factory=list)
    generated_contracts: List[GeneratedContract] = field(default_factory=list)
    generated_tests: List[GeneratedTest] = field(default_factory=list)
    root_cause_analysis: str = ""
    severity: str = "medium"


# ---------------------------------------------------------------------------
# Error pattern -> contract mapping
# ---------------------------------------------------------------------------

ERROR_CONTRACT_MAP: Dict[str, Dict] = {
    # Python
    "ZeroDivisionError": {
        "type": "bounds",
        "contracts": ["requires divisor != 0"],
        "description": "Division by zero",
    },
    "TypeError.*NoneType": {
        "type": "null_check",
        "contracts": ["requires value is not None"],
        "description": "Operation on None value",
    },
    "AttributeError.*NoneType": {
        "type": "null_check",
        "contracts": ["requires object is not None"],
        "description": "Attribute access on None",
    },
    "IndexError": {
        "type": "bounds",
        "contracts": ["requires 0 <= index < len(collection)"],
        "description": "Index out of bounds",
    },
    "KeyError": {
        "type": "bounds",
        "contracts": ["requires key in dictionary"],
        "description": "Missing dictionary key",
    },
    "ValueError": {
        "type": "type",
        "contracts": ["requires value matches expected format"],
        "description": "Invalid value",
    },
    "OverflowError": {
        "type": "bounds",
        "contracts": ["requires value <= MAX_VALUE"],
        "description": "Numeric overflow",
    },
    "FileNotFoundError": {
        "type": "resource",
        "contracts": ["requires path.exists()"],
        "description": "File not found",
    },
    "PermissionError": {
        "type": "resource",
        "contracts": ["requires has_permission(path)"],
        "description": "Permission denied",
    },
    "TimeoutError": {
        "type": "state",
        "contracts": ["ensures completes_within(timeout)"],
        "description": "Operation timed out",
    },
    "ConnectionError": {
        "type": "resource",
        "contracts": ["requires service.is_available()"],
        "description": "Connection failed",
    },
    "MemoryError": {
        "type": "resource",
        "contracts": ["requires estimated_memory <= available_memory"],
        "description": "Out of memory",
    },
    # Java
    "NullPointerException": {
        "type": "null_check",
        "contracts": ["requires object != null"],
        "description": "Null pointer dereference",
    },
    "ArrayIndexOutOfBoundsException": {
        "type": "bounds",
        "contracts": ["requires 0 <= index < array.length"],
        "description": "Array index out of bounds",
    },
    "ClassCastException": {
        "type": "type",
        "contracts": ["requires object instanceof TargetType"],
        "description": "Invalid type cast",
    },
    "StackOverflowError": {
        "type": "state",
        "contracts": ["ensures recursion_depth < MAX_DEPTH"],
        "description": "Stack overflow from deep recursion",
    },
    "ConcurrentModificationException": {
        "type": "concurrency",
        "contracts": ["requires exclusive_access(collection)"],
        "description": "Concurrent modification of collection",
    },
    # JavaScript
    "TypeError.*undefined": {
        "type": "null_check",
        "contracts": ["requires value !== undefined", "requires value !== null"],
        "description": "Operation on undefined",
    },
    "RangeError": {
        "type": "bounds",
        "contracts": ["requires value within valid range"],
        "description": "Value out of range",
    },
    # Go
    "runtime error.*index out of range": {
        "type": "bounds",
        "contracts": ["requires 0 <= index < len(slice)"],
        "description": "Slice index out of range",
    },
    "runtime error.*invalid memory address": {
        "type": "null_check",
        "contracts": ["requires pointer != nil"],
        "description": "Nil pointer dereference",
    },
    # Rust
    "thread.*panicked.*index out of bounds": {
        "type": "bounds",
        "contracts": ["requires index < collection.len()"],
        "description": "Index out of bounds",
    },
    "thread.*panicked.*unwrap.*None": {
        "type": "null_check",
        "contracts": ["requires option.is_some()"],
        "description": "Unwrap on None value",
    },
}


class IncidentAutopsy:
    """Analyze incidents and generate protective contracts."""

    def parse_stacktrace(self, text: str) -> IncidentData:
        """Parse a stack trace from various formats."""
        # Try each parser in order
        # Order: check for language-specific markers first
        # JS: "at func (file:line:col)" with .js files
        # Rust: "thread 'x' panicked"
        # Go: "goroutine" or "runtime error"
        # Java: "at pkg.Class(File.java:N)"
        # Python: 'File "x", line N, in func' (most generic — last)
        for parser in [
            self._parse_rust_panic,
            self._parse_go_panic,
            self._parse_javascript_error,
            self._parse_java_stacktrace,
            self._parse_python_traceback,
        ]:
            result = parser(text)
            if result and result.error_type:
                return result

        # Fallback: extract whatever we can
        return self._parse_generic(text)

    def parse_log(self, log_text: str) -> List[IncidentData]:
        """Parse log output to extract error patterns."""
        incidents: List[IncidentData] = []
        # Split on common log patterns
        error_blocks = re.split(
            r'(?=\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}.*(?:ERROR|FATAL|CRITICAL|PANIC))',
            log_text,
        )
        for block in error_blocks:
            block = block.strip()
            if not block:
                continue
            # Extract timestamp
            ts_m = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)', block)
            timestamp = ts_m.group(1) if ts_m else ""
            # Try to parse as a stack trace
            incident = self.parse_stacktrace(block)
            if incident.error_type:
                incident.timestamp = timestamp
                incident.source = "log"
                incidents.append(incident)

        # If no structured errors found, try the whole thing
        if not incidents:
            incident = self.parse_stacktrace(log_text)
            if incident.error_type:
                incident.source = "log"
                incidents.append(incident)

        return incidents

    def analyze(self, incident: IncidentData, source_root: Optional[str] = None) -> AutopsyResult:
        """Perform full autopsy on an incident."""
        assumptions = self._identify_violated_assumptions(incident)
        contracts = self._generate_contracts(incident, assumptions)
        tests = self._generate_tests(incident)
        rca = self._root_cause_analysis(incident, assumptions)
        severity = self._assess_severity(incident)

        return AutopsyResult(
            incident=incident,
            violated_assumptions=assumptions,
            generated_contracts=contracts,
            generated_tests=tests,
            root_cause_analysis=rca,
            severity=severity,
        )

    def autopsy_from_file(self, filepath: str, source_root: Optional[str] = None) -> AutopsyResult:
        """Run autopsy from a log/trace file."""
        text = Path(filepath).read_text(encoding="utf-8", errors="ignore")
        incidents = self.parse_log(text)
        if not incidents:
            incident = self.parse_stacktrace(text)
        else:
            incident = incidents[0]  # Primary incident
        return self.analyze(incident, source_root)

    def format_report(self, result: AutopsyResult) -> str:
        """Format autopsy result as markdown report."""
        lines = [
            "# AEON Incident Autopsy",
            "",
            f"**Severity:** {result.severity.upper()}",
            f"**Error:** `{result.incident.error_type}: {result.incident.error_message}`",
            f"**Language:** {result.incident.language}",
        ]
        if result.incident.timestamp:
            lines.append(f"**Timestamp:** {result.incident.timestamp}")

        if result.incident.stack_trace:
            lines.append("\n## Stack Trace")
            lines.append("```")
            for frame in result.incident.stack_trace:
                lines.append(f"  {frame.file}:{frame.line} in {frame.function}")
                if frame.code:
                    lines.append(f"    > {frame.code}")
            lines.append("```")

        lines.append("\n## Root Cause Analysis")
        lines.append(result.root_cause_analysis)

        if result.violated_assumptions:
            lines.append("\n## Violated Assumptions")
            for va in result.violated_assumptions:
                lines.append(f"\n### {va.description}")
                lines.append(f"- **Type:** {va.assumption_type}")
                lines.append(f"- **Location:** `{va.file}:{va.line}` in `{va.function}`")
                lines.append(f"- **Confidence:** {va.confidence:.0%}")

        if result.generated_contracts:
            lines.append("\n## Generated Contracts")
            lines.append("")
            lines.append("Add these contracts to prevent recurrence:")
            lines.append("")
            for gc in result.generated_contracts:
                lines.append(f"**`{gc.target_function}`** ({gc.target_file}):")
                lines.append(f"```")
                lines.append(f"{gc.contract}")
                lines.append(f"```")
                lines.append(f"_Reason: {gc.reason}_")
                lines.append("")

        if result.generated_tests:
            lines.append("\n## Regression Tests")
            for gt in result.generated_tests:
                lines.append(f"\n### {gt.test_name}")
                lines.append(f"```{gt.language}")
                lines.append(gt.test_code)
                lines.append("```")

        return "\n".join(lines)

    # -- Stack trace parsers -----------------------------------------------

    def _parse_python_traceback(self, text: str) -> IncidentData:
        frames: List[StackFrame] = []
        # Match: File "path", line N, in func
        for m in re.finditer(
            r'File "([^"]+)", line (\d+), in (\w+)\n\s+(.+)',
            text,
        ):
            frames.append(StackFrame(
                file=m.group(1), line=int(m.group(2)),
                function=m.group(3), code=m.group(4).strip(),
            ))
        # Match error line
        err_m = re.search(r'^(\w+(?:Error|Exception|Warning)):\s*(.+)', text, re.M)
        if not err_m and not frames:
            return IncidentData(error_type="", error_message="")
        return IncidentData(
            error_type=err_m.group(1) if err_m else "UnknownError",
            error_message=err_m.group(2).strip() if err_m else "",
            stack_trace=frames,
            language="python",
        )

    def _parse_java_stacktrace(self, text: str) -> IncidentData:
        # Require Java-specific "at package.Class.method(File.java:N)" pattern
        if not re.search(r'at\s+[\w.$]+\([\w.]+\.java:\d+\)', text):
            return IncidentData(error_type="", error_message="")
        err_m = re.search(r'(?:Exception in thread "[^"]+"\s+)?(\w+(?:\.\w+)*(?:Exception|Error)):\s*(.*)', text)
        if not err_m:
            return IncidentData(error_type="", error_message="")
        frames: List[StackFrame] = []
        for m in re.finditer(r'at\s+([\w.$]+)\(([\w.]+):(\d+)\)', text):
            full_method = m.group(1)
            parts = full_method.rsplit(".", 1)
            func = parts[-1] if len(parts) > 1 else full_method
            frames.append(StackFrame(
                file=m.group(2), line=int(m.group(3)), function=func,
            ))
        return IncidentData(
            error_type=err_m.group(1).split(".")[-1],
            error_message=err_m.group(2).strip(),
            stack_trace=frames,
            language="java",
        )

    def _parse_javascript_error(self, text: str) -> IncidentData:
        err_m = re.search(r'((?:Type|Range|Reference|Syntax)Error):\s*(.+)', text)
        if not err_m:
            return IncidentData(error_type="", error_message="")
        # Must have JS-style stack frames (file:line:col) to distinguish from Python
        if not re.search(r'at\s+.*[\w./\\-]+:\d+:\d+', text):
            return IncidentData(error_type="", error_message="")
        frames: List[StackFrame] = []
        for m in re.finditer(r'at\s+(?:(\w+)\s+)?\(?([\w./\\-]+):(\d+):\d+\)?', text):
            frames.append(StackFrame(
                file=m.group(2), line=int(m.group(3)),
                function=m.group(1) or "<anonymous>",
            ))
        return IncidentData(
            error_type=err_m.group(1),
            error_message=err_m.group(2).strip(),
            stack_trace=frames,
            language="javascript",
        )

    def _parse_go_panic(self, text: str) -> IncidentData:
        err_m = re.search(r'panic:\s*(.+)', text)
        if not err_m:
            # Try runtime error
            err_m = re.search(r'(runtime error:.+)', text)
        if not err_m:
            return IncidentData(error_type="", error_message="")
        frames: List[StackFrame] = []
        for m in re.finditer(r'([\w./\\-]+\.go):(\d+)', text):
            frames.append(StackFrame(
                file=m.group(1), line=int(m.group(2)), function="",
            ))
        return IncidentData(
            error_type="panic",
            error_message=err_m.group(1).strip(),
            stack_trace=frames,
            language="go",
        )

    def _parse_rust_panic(self, text: str) -> IncidentData:
        err_m = re.search(r"thread '([^']+)' panicked at '([^']+)'", text)
        if not err_m:
            err_m = re.search(r"thread '([^']+)' panicked at (.+?)(?:,|\n)", text)
        if not err_m:
            return IncidentData(error_type="", error_message="")
        frames: List[StackFrame] = []
        for m in re.finditer(r'([\w./\\-]+\.rs):(\d+)', text):
            frames.append(StackFrame(
                file=m.group(1), line=int(m.group(2)), function="",
            ))
        return IncidentData(
            error_type="panic",
            error_message=err_m.group(2).strip(),
            stack_trace=frames,
            language="rust",
        )

    def _parse_generic(self, text: str) -> IncidentData:
        err_m = re.search(r'(\w+(?:Error|Exception|Fault|Panic))[\s:]+(.+?)(?:\n|$)', text)
        if err_m:
            return IncidentData(
                error_type=err_m.group(1),
                error_message=err_m.group(2).strip(),
            )
        return IncidentData(error_type="UnknownError", error_message=text[:200])

    # -- Analysis ----------------------------------------------------------

    def _identify_violated_assumptions(self, incident: IncidentData) -> List[ViolatedAssumption]:
        assumptions: List[ViolatedAssumption] = []
        error_key = f"{incident.error_type}: {incident.error_message}"

        for pattern, info in ERROR_CONTRACT_MAP.items():
            if re.search(pattern, error_key, re.I) or re.search(pattern, incident.error_type, re.I):
                frame = incident.stack_trace[-1] if incident.stack_trace else StackFrame("unknown", 0, "unknown")
                assumptions.append(ViolatedAssumption(
                    description=info["description"],
                    file=frame.file,
                    function=frame.function,
                    line=frame.line,
                    assumption_type=info["type"],
                    confidence=0.9,
                ))
                break

        if not assumptions and incident.stack_trace:
            frame = incident.stack_trace[-1]
            assumptions.append(ViolatedAssumption(
                description=f"Unhandled {incident.error_type}",
                file=frame.file,
                function=frame.function,
                line=frame.line,
                assumption_type="state",
                confidence=0.5,
            ))

        return assumptions

    def _generate_contracts(self, incident: IncidentData,
                            assumptions: List[ViolatedAssumption]) -> List[GeneratedContract]:
        contracts: List[GeneratedContract] = []
        error_key = f"{incident.error_type}: {incident.error_message}"

        for pattern, info in ERROR_CONTRACT_MAP.items():
            if re.search(pattern, error_key, re.I) or re.search(pattern, incident.error_type, re.I):
                frame = incident.stack_trace[-1] if incident.stack_trace else StackFrame("unknown", 0, "unknown")
                for contract_text in info["contracts"]:
                    contracts.append(GeneratedContract(
                        contract=contract_text,
                        target_function=frame.function,
                        target_file=frame.file,
                        reason=f"Prevents {info['description']} ({incident.error_type})",
                    ))
                break

        return contracts

    def _generate_tests(self, incident: IncidentData) -> List[GeneratedTest]:
        tests: List[GeneratedTest] = []
        lang = incident.language
        func = incident.stack_trace[-1].function if incident.stack_trace else "target_function"
        error_type = incident.error_type

        if lang == "python":
            test_code = (
                f"def test_{func}_prevents_{error_type.lower()}():\n"
                f'    """Regression test: {error_type} in {func}."""\n'
                f"    # Reproduce the conditions that caused the incident\n"
                f"    # {incident.error_message}\n"
                f"    with pytest.raises({error_type}):\n"
                f"        {func}()  # TODO: add failing arguments from incident\n"
            )
        elif lang == "java":
            test_code = (
                f"@Test(expected = {error_type}.class)\n"
                f"public void test_{func}_prevents_{error_type}() {{\n"
                f"    // Regression: {incident.error_message}\n"
                f"    {func}();  // TODO: add failing arguments\n"
                f"}}\n"
            )
        elif lang == "javascript":
            test_code = (
                f"test('{func} prevents {error_type}', () => {{\n"
                f"    // Regression: {incident.error_message}\n"
                f"    expect(() => {func}()).toThrow({error_type});\n"
                f"}});\n"
            )
        elif lang == "go":
            test_code = (
                f"func Test_{func}_prevents_panic(t *testing.T) {{\n"
                f"    // Regression: {incident.error_message}\n"
                f"    defer func() {{\n"
                f"        if r := recover(); r == nil {{\n"
                f'            t.Errorf("{func} should have panicked")\n'
                f"        }}\n"
                f"    }}()\n"
                f"    {func}()  // TODO: add failing arguments\n"
                f"}}\n"
            )
        else:
            test_code = (
                f"// Regression test for {error_type} in {func}\n"
                f"// {incident.error_message}\n"
                f"// TODO: implement test for {lang}\n"
            )

        tests.append(GeneratedTest(
            test_name=f"test_{func}_{error_type.lower()}_regression",
            test_code=test_code,
            language=lang,
        ))
        return tests

    def _root_cause_analysis(self, incident: IncidentData,
                              assumptions: List[ViolatedAssumption]) -> str:
        lines = [f"A `{incident.error_type}` occurred"]
        if incident.stack_trace:
            frame = incident.stack_trace[-1]
            lines[0] += f" in `{frame.function}` at `{frame.file}:{frame.line}`"
        lines[0] += "."
        lines.append(f"\n**Error message:** {incident.error_message}")

        if assumptions:
            lines.append("\n**Root cause:** The following assumption(s) were violated:")
            for a in assumptions:
                lines.append(f"- {a.description} (confidence: {a.confidence:.0%})")

        lines.append(
            "\n**Prevention:** Add the generated contracts to enforce these assumptions "
            "at compile time. The contracts will cause AEON to flag any code path that "
            "could violate them, eliminating this class of error permanently."
        )
        return "\n".join(lines)

    def _assess_severity(self, incident: IncidentData) -> str:
        critical_errors = {"NullPointerException", "SegmentationFault", "StackOverflowError", "MemoryError"}
        high_errors = {"ZeroDivisionError", "IndexError", "ArrayIndexOutOfBoundsException",
                       "ConcurrentModificationException"}
        if incident.error_type in critical_errors or "panic" in incident.error_type.lower():
            return "critical"
        if incident.error_type in high_errors:
            return "high"
        if "Error" in incident.error_type:
            return "medium"
        return "low"
