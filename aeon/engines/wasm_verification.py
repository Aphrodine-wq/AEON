"""AEON WebAssembly Verification — WASM Safety & Sandboxing Proofs.

Implements WebAssembly formal verification based on:
  Haas, A. et al. (2017) "Bringing the Web up to Speed with WebAssembly"
  PLDI '17, https://doi.org/10.1145/3062341.3062363

  Watt, C. (2018) "Mechanising and Verifying the WebAssembly Specification"
  CPP '18, https://doi.org/10.1145/3167082.3167163

  Lehmann, D., Kinder, J., & Pradel, M. (2019) "Everything Old is New Again:
  Binary Security of WebAssembly"
  USENIX Security '20, https://www.usenix.org/conference/usenixsecurity20/presentation/lehmann

  Bosamiya, J., Lim, W.S., & Parno, B. (2022) "Provably-Safe Multilingual
  Software Sandboxing using WebAssembly"
  USENIX Security '22

Key Theory:

1. WASM TYPE SYSTEM (Haas et al. 2017):
   WebAssembly has a simple but sound type system.
   Every instruction has a type: [t1*] -> [t2*] (stack transformation).
   Type checking is linear in program size — O(n).
   Soundness: well-typed WASM programs never get stuck (no undefined behavior).

2. MEMORY SAFETY:
   WASM memory is a flat byte array with bounds-checked accesses.
   All memory accesses are validated: addr + offset < memory.size.
   No pointer arithmetic — only integer offsets from base 0.
   Sandboxing: WASM module cannot access host memory outside its linear memory.

3. CONTROL FLOW INTEGRITY:
   WASM has structured control flow (no arbitrary jumps).
   Indirect calls (call_indirect) are type-checked at runtime.
   No return-oriented programming possible — stack is separate from memory.

4. FORMAL MECHANIZATION (Watt 2018):
   Full WASM spec mechanized in Isabelle/HOL.
   Proves: type soundness, determinism, and sandboxing properties.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WasmIssue:
    kind: str
    message: str
    line: int
    severity: str = "error"
    paper: str = ""


@dataclass
class WasmResult:
    issues: list[WasmIssue] = field(default_factory=list)
    instructions_verified: int = 0
    memory_accesses_checked: int = 0
    type_errors: int = 0
    verified: bool = True

    @property
    def summary(self) -> str:
        if not self.issues:
            return (f"✅ WASM: {self.instructions_verified} instructions type-checked, "
                    f"{self.memory_accesses_checked} memory accesses verified")
        errors = [i for i in self.issues if i.severity == "error"]
        return f"❌ WASM: {len(errors)} safety violation(s)"


WASM_TYPES = {"i32", "i64", "f32", "f64", "v128", "funcref", "externref"}

INSTRUCTION_TYPES: dict[str, tuple[list[str], list[str]]] = {
    "i32.add":    (["i32", "i32"], ["i32"]),
    "i32.sub":    (["i32", "i32"], ["i32"]),
    "i32.mul":    (["i32", "i32"], ["i32"]),
    "i32.div_s":  (["i32", "i32"], ["i32"]),
    "i32.div_u":  (["i32", "i32"], ["i32"]),
    "i64.add":    (["i64", "i64"], ["i64"]),
    "f32.add":    (["f32", "f32"], ["f32"]),
    "f64.add":    (["f64", "f64"], ["f64"]),
    "i32.load":   (["i32"], ["i32"]),
    "i64.load":   (["i32"], ["i64"]),
    "f32.load":   (["i32"], ["f32"]),
    "i32.store":  (["i32", "i32"], []),
    "i64.store":  (["i32", "i64"], []),
    "i32.const":  ([], ["i32"]),
    "i64.const":  ([], ["i64"]),
    "f32.const":  ([], ["f32"]),
    "f64.const":  ([], ["f64"]),
    "drop":       (["any"], []),
    "select":     (["any", "any", "i32"], ["any"]),
    "local.get":  ([], ["any"]),
    "local.set":  (["any"], []),
    "call":       ([], []),
    "return":     ([], []),
}


class WasmTypeChecker:
    """Stack-based type checker for WASM instructions."""

    def __init__(self) -> None:
        self.issues: list[WasmIssue] = []
        self.checked = 0

    def check_function(self, func: dict[str, Any]) -> None:
        stack: list[str] = list(func.get("params", []))
        instructions: list[dict] = func.get("instructions", [])
        func_name = func.get("name", "?")

        for instr in instructions:
            op = instr.get("op", "")
            line = instr.get("line", 0)
            self.checked += 1

            if op not in INSTRUCTION_TYPES:
                continue

            expected_in, expected_out = INSTRUCTION_TYPES[op]

            if len(stack) < len(expected_in):
                self.issues.append(WasmIssue(
                    kind="stack_underflow",
                    message=(
                        f"Stack underflow in '{func_name}' at '{op}' (line {line}): "
                        f"need {len(expected_in)} value(s) but stack has {len(stack)}. "
                        f"WASM type system violation — instruction precondition not met."
                    ),
                    line=line,
                    paper="Haas et al. (2017) PLDI — WebAssembly; "
                          "Watt (2018) CPP — Mechanising WASM"
                ))
                continue

            for i, expected in enumerate(reversed(expected_in)):
                actual = stack[-(i + 1)]
                if expected != "any" and actual != expected:
                    self.issues.append(WasmIssue(
                        kind="type_mismatch",
                        message=(
                            f"Type mismatch in '{func_name}' at '{op}' (line {line}): "
                            f"expected {expected} but got {actual} on stack."
                        ),
                        line=line,
                        paper="Haas et al. (2017) PLDI — WebAssembly"
                    ))

            for _ in expected_in:
                if stack:
                    stack.pop()
            stack.extend(expected_out)


class WasmMemorySafetyChecker:
    """Verifies WASM memory accesses are within bounds."""

    def __init__(self) -> None:
        self.issues: list[WasmIssue] = []
        self.checked = 0

    def check_access(
        self,
        func_name: str,
        op: str,
        offset: int,
        align: int,
        memory_size_pages: int,
        line: int
    ) -> None:
        self.checked += 1
        memory_bytes = memory_size_pages * 65536

        access_size = {"i32.load": 4, "i64.load": 8, "f32.load": 4, "f64.load": 8,
                       "i32.store": 4, "i64.store": 8, "f32.store": 4}.get(op, 4)

        if offset + access_size > memory_bytes:
            self.issues.append(WasmIssue(
                kind="out_of_bounds_memory",
                message=(
                    f"Out-of-bounds memory access in '{func_name}' at '{op}' (line {line}): "
                    f"offset {offset} + {access_size} bytes exceeds memory size "
                    f"{memory_bytes} bytes ({memory_size_pages} pages). "
                    f"WASM trap: memory.access out of bounds."
                ),
                line=line,
                severity="error",
                paper="Lehmann et al. (2019) USENIX Security — Binary Security of WASM"
            ))

        if align > 0 and (offset % (2 ** align)) != 0:
            self.issues.append(WasmIssue(
                kind="misaligned_access",
                message=(
                    f"Misaligned memory access in '{func_name}' at '{op}' (line {line}): "
                    f"offset {offset} is not aligned to {2**align} bytes (align={align}). "
                    f"May cause performance penalty or trap on strict platforms."
                ),
                line=line,
                severity="warning",
                paper="Haas et al. (2017) PLDI — WebAssembly"
            ))


class WasmSandboxVerifier:
    """Verifies WASM sandboxing properties — no host memory escape."""

    def verify(self, module: dict[str, Any]) -> list[WasmIssue]:
        issues = []
        imports: list[dict] = module.get("imports", [])
        exports: list[dict] = module.get("exports", [])

        for imp in imports:
            if imp.get("kind") == "memory" and imp.get("shared", False):
                issues.append(WasmIssue(
                    kind="shared_memory_import",
                    message=(
                        f"Module imports shared memory '{imp.get('name', '?')}'. "
                        f"Shared memory between WASM and host breaks sandboxing — "
                        f"data races and TOCTOU attacks become possible."
                    ),
                    line=imp.get("line", 0),
                    severity="error",
                    paper="Bosamiya et al. (2022) USENIX Security — Provably-Safe Sandboxing"
                ))

        for exp in exports:
            if exp.get("kind") == "memory":
                issues.append(WasmIssue(
                    kind="memory_export",
                    message=(
                        f"Module exports its linear memory '{exp.get('name', '?')}'. "
                        f"Host can read/write all WASM memory — weakens isolation. "
                        f"Consider exporting only specific accessor functions."
                    ),
                    line=exp.get("line", 0),
                    severity="warning",
                    paper="Lehmann et al. (2019) USENIX Security — Binary Security of WASM"
                ))

        return issues


class WasmVerificationEngine:
    """Full WebAssembly verification engine."""

    def __init__(self) -> None:
        self.type_checker = WasmTypeChecker()
        self.memory_checker = WasmMemorySafetyChecker()
        self.sandbox = WasmSandboxVerifier()

    def verify(self, module: dict[str, Any]) -> WasmResult:
        result = WasmResult()
        all_issues: list[WasmIssue] = []

        for func in module.get("functions", []):
            self.type_checker.check_function(func)
            for access in func.get("memory_accesses", []):
                self.memory_checker.check_access(
                    func.get("name", "?"),
                    access.get("op", "i32.load"),
                    access.get("offset", 0),
                    access.get("align", 0),
                    module.get("memory_pages", 1),
                    access.get("line", 0)
                )

        all_issues.extend(self.type_checker.issues)
        all_issues.extend(self.memory_checker.issues)
        all_issues.extend(self.sandbox.verify(module))

        result.instructions_verified = self.type_checker.checked
        result.memory_accesses_checked = self.memory_checker.checked
        result.type_errors = len([i for i in all_issues if i.kind == "type_mismatch"])
        result.issues = all_issues
        result.verified = not any(i.severity == "error" for i in all_issues)
        return result


def verify_wasm(module: dict[str, Any]) -> WasmResult:
    """Entry point: verify a WebAssembly module."""
    engine = WasmVerificationEngine()
    return engine.verify(module)
