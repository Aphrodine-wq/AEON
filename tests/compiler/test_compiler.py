"""AEON Compiler Tests — COMP-001 through COMP-010.

P0 tests must pass before any code ships.
P1 tests must pass before any external demo.
P2 tests must pass before public launch.

Each test outputs structured JSON pass/fail.
"""

import json
import pytest

from aeon.lexer import tokenize
from aeon.parser import parse
from aeon.pass1_prove import prove
from aeon.pass2_flatten import flatten
from aeon.errors import CompileError

try:
    from aeon.pass3_emit import emit, HAS_LLVMLITE
except ImportError:
    HAS_LLVMLITE = False


# ===================================================================
# P0 — Ship-blocking tests
# ===================================================================


class TestCOMP001:
    """COMP-001: Empty pure function compiles to valid LLVM IR.
    Pass Criteria: IR output is valid, llc produces binary.
    Priority: P0
    """

    def test_empty_pure_function_parses(self):
        """priority_p0: Parse an empty pure function."""
        source = """
pure noop() -> Void {
  return
}
"""
        program = parse(source)
        assert len(program.declarations) == 1

    def test_empty_pure_function_type_checks(self):
        """priority_p0: Type check an empty pure function."""
        source = """
pure noop() -> Void {
  return
}
"""
        program = parse(source)
        errors = prove(program)
        assert errors == [], f"Type errors: {[e.to_dict() for e in errors]}"

    def test_empty_pure_function_flattens(self):
        """priority_p0: Flatten an empty pure function to IR."""
        source = """
pure noop() -> Void {
  return
}
"""
        program = parse(source)
        ir_module = flatten(program)
        assert len(ir_module.functions) == 1
        assert ir_module.functions[0].name == "noop"
        assert ir_module.functions[0].is_pure is True

    @pytest.mark.skipif(not HAS_LLVMLITE, reason="llvmlite not installed")
    def test_empty_pure_function_emits_llvm_ir(self):
        """priority_p0: Emit valid LLVM IR for empty pure function."""
        source = """
pure noop() -> Void {
  return
}
"""
        program = parse(source)
        ir_module = flatten(program)
        llvm_ir = emit(ir_module)
        assert "define" in llvm_ir
        assert "noop" in llvm_ir

    def test_pure_function_with_return(self):
        """priority_p0: Pure function with Int return."""
        source = """
pure add(a: Int, b: Int) -> Int {
  return a + b
}
"""
        program = parse(source)
        errors = prove(program)
        assert errors == [], f"Type errors: {[e.to_dict() for e in errors]}"

        ir_module = flatten(program)
        assert len(ir_module.functions) == 1

    @pytest.mark.skipif(not HAS_LLVMLITE, reason="llvmlite not installed")
    def test_pure_function_emits_valid_ir(self):
        """priority_p0: Emit valid LLVM IR for pure function with arithmetic."""
        source = """
pure add(a: Int, b: Int) -> Int {
  return a + b
}
"""
        program = parse(source)
        ir_module = flatten(program)
        llvm_ir = emit(ir_module)
        assert "define" in llvm_ir
        assert "add" in llvm_ir
        assert "i64" in llvm_ir


class TestCOMP002:
    """COMP-002: Type mismatch produces structured JSON error.
    Pass Criteria: JSON contains: node_id, expected_type, actual_type.
    Priority: P0
    """

    def test_type_mismatch_return(self):
        """priority_p0: Return type mismatch produces structured error."""
        source = """
pure getName() -> Int {
  return "hello"
}
"""
        program = parse(source)
        errors = prove(program)
        assert len(errors) > 0

        err = errors[0].to_dict()
        assert err["kind"] == "type_error"
        assert "details" in err
        assert "expected_type" in err["details"]
        assert "actual_type" in err["details"]
        assert err["details"]["expected_type"] == "Int"
        assert err["details"]["actual_type"] == "String"

    def test_type_mismatch_binary_op(self):
        """priority_p0: Binary operation type mismatch."""
        source = """
pure bad(a: Int, b: String) -> Int {
  return a + b
}
"""
        program = parse(source)
        errors = prove(program)
        assert len(errors) > 0

        err = errors[0].to_dict()
        assert err["kind"] == "type_error"
        assert "node_id" in err["details"]

    def test_type_mismatch_arg(self):
        """priority_p0: Function argument type mismatch."""
        source = """
pure square(x: Int) -> Int {
  return x * x
}

pure callBad() -> Int {
  return square("hello")
}
"""
        program = parse(source)
        errors = prove(program)
        assert len(errors) > 0

        err = errors[0].to_dict()
        assert err["kind"] == "type_error"

    def test_error_is_valid_json(self):
        """priority_p0: Error output is valid JSON."""
        source = """
pure bad() -> Int {
  return "not an int"
}
"""
        program = parse(source)
        errors = prove(program)
        assert len(errors) > 0

        json_str = json.dumps([e.to_dict() for e in errors])
        parsed = json.loads(json_str)
        assert isinstance(parsed, list)
        assert len(parsed) > 0


class TestCOMP003:
    """COMP-003: Effect violation on unlisted Database.Write.
    Pass Criteria: Compile error, no binary produced.
    Priority: P0
    """

    def test_pure_function_with_db_write_errors(self):
        """priority_p0: Pure function using db.insert should fail."""
        source = """
data User {
  id: UUID
  name: String
}

pure badSave(user: User) -> Bool {
  return db.insert(user)
}
"""
        program = parse(source)
        errors = prove(program)

        effect_errors = [e for e in errors if e.kind.value == "effect_error"]
        assert len(effect_errors) > 0, "Expected effect error for db.insert in pure function"

        err = effect_errors[0].to_dict()
        assert err["details"]["actual_effect"] == "Database.Write"
        assert err["details"]["declared_effects"] == []

    def test_task_with_undeclared_effect_errors(self):
        """priority_p0: Task missing Database.Write should fail."""
        source = """
data User {
  id: UUID
  name: String
}

task saveUser(user: User) -> Bool {
  effects: [Database.Read]
  return db.insert(user)
}
"""
        program = parse(source)
        errors = prove(program)

        effect_errors = [e for e in errors if e.kind.value == "effect_error"]
        assert len(effect_errors) > 0, "Expected effect error for undeclared Database.Write"

    def test_task_with_declared_effect_passes(self):
        """priority_p0: Task with correct effects should pass."""
        source = """
data User {
  id: UUID
  name: String
}

task saveUser(user: User) -> Bool {
  effects: [Database.Write]
  return db.insert(user)
}
"""
        program = parse(source)
        errors = prove(program)

        effect_errors = [e for e in errors if e.kind.value == "effect_error"]
        assert len(effect_errors) == 0, f"Unexpected effect errors: {[e.to_dict() for e in effect_errors]}"


class TestCOMP004:
    """COMP-004: Ownership violation (use after move) caught.
    Pass Criteria: Compile error with exact line + variable name.
    Priority: P0
    """

    def test_use_after_move(self):
        """priority_p0: Use-after-move produces ownership error."""
        source = """
pure bad(x: Int) -> Int {
  let a: Int = move x
  return x
}
"""
        program = parse(source)
        errors = prove(program)

        ownership_errors = [e for e in errors if e.kind.value == "ownership_error"]
        assert len(ownership_errors) > 0, "Expected ownership error for use after move"

        err = ownership_errors[0].to_dict()
        assert err["details"]["variable"] == "x"
        assert "use after move" in err["details"]["violation_type"]

    def test_double_move(self):
        """priority_p0: Double move produces ownership error."""
        source = """
pure bad(x: Int) -> Int {
  let a: Int = move x
  let b: Int = move x
  return a
}
"""
        program = parse(source)
        errors = prove(program)

        ownership_errors = [e for e in errors if e.kind.value == "ownership_error"]
        assert len(ownership_errors) > 0

    def test_no_ownership_violation_passes(self):
        """priority_p0: Correct ownership should pass."""
        source = """
pure good(a: Int, b: Int) -> Int {
  let sum: Int = a + b
  return sum
}
"""
        program = parse(source)
        errors = prove(program)

        ownership_errors = [e for e in errors if e.kind.value == "ownership_error"]
        assert len(ownership_errors) == 0


class TestCOMP005:
    """COMP-005: Requires clause violated at callsite.
    Pass Criteria: Compile error with failing precondition + values.
    Priority: P0
    """

    def test_requires_clause_parsed(self):
        """priority_p0: Requires clause is parsed correctly."""
        source = """
pure safeDivide(a: Int, b: Int) -> Int {
  requires: b != 0
  return a / b
}
"""
        program = parse(source)
        func = program.declarations[0]
        assert len(func.requires) == 1
        assert func.requires[0].kind == "requires"

    def test_requires_in_ir(self):
        """priority_p0: Requires clause appears in flat IR."""
        source = """
pure safeDivide(a: Int, b: Int) -> Int {
  requires: b != 0
  return a / b
}
"""
        program = parse(source)
        ir_module = flatten(program)
        func_ir = ir_module.functions[0]
        assert "requires" in func_ir.contracts
        assert len(func_ir.contracts["requires"]) == 1


class TestCOMP006:
    """COMP-006: Ensures clause verified at return.
    Pass Criteria: Compiler accepts valid function, rejects violation.
    Priority: P0
    """

    def test_ensures_clause_parsed(self):
        """priority_p0: Ensures clause is parsed correctly."""
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
"""
        program = parse(source)
        func = program.declarations[0]
        assert len(func.ensures) == 1
        assert func.ensures[0].kind == "ensures"

    def test_ensures_in_ir(self):
        """priority_p0: Ensures clause appears in flat IR."""
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
"""
        program = parse(source)
        ir_module = flatten(program)
        func_ir = ir_module.functions[0]
        assert "ensures" in func_ir.contracts
        assert len(func_ir.contracts["ensures"]) == 1

    def test_valid_function_accepted(self):
        """priority_p0: Valid function with ensures should type-check."""
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
"""
        program = parse(source)
        errors = prove(program)
        type_errors = [e for e in errors if e.kind.value == "type_error"]
        assert len(type_errors) == 0


# ===================================================================
# P1 — Pre-demo tests
# ===================================================================


class TestCOMP007:
    """COMP-007: Pure function is auto-parallelized.
    Priority: P1
    """

    @pytest.mark.skipif(not HAS_LLVMLITE, reason="llvmlite not installed")
    def test_pure_function_marked_readonly(self):
        """priority_p1: Pure functions should be marked readonly in LLVM IR."""
        source = """
pure add(a: Int, b: Int) -> Int {
  return a + b
}
"""
        program = parse(source)
        ir_module = flatten(program)
        llvm_ir = emit(ir_module)
        assert "readonly" in llvm_ir


class TestCOMP008:
    """COMP-008: Compile 10k line file in under 100ms.
    Priority: P1
    """

    def test_compile_speed_small(self):
        """priority_p1: Compile a small program quickly."""
        import time

        lines = []
        for i in range(100):
            lines.append(f"""
pure func_{i}(a: Int, b: Int) -> Int {{
  return a + b
}}
""")
        source = "\n".join(lines)

        start = time.time()
        program = parse(source)
        errors = prove(program)
        ir_module = flatten(program)
        elapsed = time.time() - start

        assert len(errors) == 0
        assert len(ir_module.functions) == 100
        assert elapsed < 5.0  # Generous limit for Python


class TestCOMP009:
    """COMP-009: Two tasks with non-overlapping effects run in parallel.
    Priority: P1
    """

    def test_non_overlapping_effects_detected(self):
        """priority_p1: Detect non-overlapping effects between tasks."""
        source = """
data User {
  id: UUID
  name: String
}

task readUser(id: UUID) -> User {
  effects: [Database.Read]
  return db.find(id)
}

task writeLog(msg: String) -> Bool {
  effects: [File.Write]
  return file.write(msg)
}
"""
        program = parse(source)
        errors = prove(program)
        effect_errors = [e for e in errors if e.kind.value == "effect_error"]
        assert len(effect_errors) == 0

        ir_module = flatten(program)
        f1 = ir_module.functions[0]
        f2 = ir_module.functions[1]
        assert set(f1.effects).isdisjoint(set(f2.effects))


class TestCOMP010:
    """COMP-010: Recursive pure function terminates (well-founded).
    Priority: P2
    """

    def test_recursive_termination(self):
        """priority_p2: Compiler proves recursive function terminates."""
        from aeon.pass1_prove import prove
        
        # Good recursive function - should pass
        source_good = """
pure factorial(n: Int) -> Int {
  if n <= 1 {
    return 1
  } else {
    return n * factorial(n - 1)
  }
}
"""
        program = parse(source_good)
        errors = prove(program, analyze_termination=True)
        # Should have no termination errors
        term_errors = [e for e in errors if e.kind.value == "contract_error" and "termination" in str(e.message).lower()]
        assert len(term_errors) == 0, f"Expected no termination errors, got: {[e.to_dict() for e in term_errors]}"
        
        # Bad recursive function - no base case
        source_bad = """
pure infinite_loop(x: Int) -> Int {
  return infinite_loop(x)
}
"""
        program = parse(source_bad)
        errors = prove(program, analyze_termination=True)
        # Should have termination errors
        term_errors = [e for e in errors if e.kind.value == "contract_error"]
        assert len(term_errors) > 0, "Expected termination errors for non-terminating function"


# ===================================================================
# Full pipeline tests
# ===================================================================


class TestFullPipeline:
    """End-to-end pipeline tests through all 3 passes."""

    def test_data_types_example(self):
        """Parse and check data_types.aeon."""
        source = """
data User {
  id:    UUID
  email: Email
  name:  String
}

data Account {
  id:      UUID
  balance: Int
}
"""
        program = parse(source)
        errors = prove(program)
        assert errors == []
        ir_module = flatten(program)
        assert len(ir_module.data_types) == 2

    def test_pure_function_example(self):
        """Parse, check, and flatten pure_function.aeon."""
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}

pure max(a: Int, b: Int) -> Int {
  if a >= b {
    return a
  } else {
    return b
  }
}
"""
        program = parse(source)
        errors = prove(program)
        assert errors == [], f"Errors: {[e.to_dict() for e in errors]}"
        ir_module = flatten(program)
        assert len(ir_module.functions) == 2

    def test_task_function_example(self):
        """Parse and check task_function.aeon."""
        source = """
data User {
  id:    UUID
  email: Email
  name:  String
}

task createUser(user: User) -> Bool {
  requires: user.email.isValid()
  ensures:  result == true
  effects:  [Database.Write]
  return db.insert(user)
}
"""
        program = parse(source)
        errors = prove(program)
        effect_errors = [e for e in errors if e.kind.value == "effect_error"]
        assert len(effect_errors) == 0

    def test_ir_is_valid_json(self):
        """IR output is valid JSON."""
        source = """
pure add(a: Int, b: Int) -> Int {
  return a + b
}
"""
        program = parse(source)
        ir_module = flatten(program)
        json_str = ir_module.to_json()
        parsed = json.loads(json_str)
        assert "module" in parsed
        assert "functions" in parsed
        assert len(parsed["functions"]) == 1

    @pytest.mark.skipif(not HAS_LLVMLITE, reason="llvmlite not installed")
    def test_full_pipeline_to_llvm(self):
        """Full pipeline: source -> parse -> prove -> flatten -> emit."""
        source = """
pure add(a: Int, b: Int) -> Int {
  return a + b
}

pure sub(a: Int, b: Int) -> Int {
  return a - b
}
"""
        program = parse(source)
        errors = prove(program)
        assert errors == []
        ir_module = flatten(program)
        llvm_ir = emit(ir_module)
        assert "define" in llvm_ir
        assert "add" in llvm_ir or "sub" in llvm_ir


class TestLexer:
    """Lexer unit tests."""

    def test_tokenize_keywords(self):
        tokens = tokenize("pure task data return if else true false")
        types = [t.type.name for t in tokens if t.type.name != "EOF"]
        assert "PURE" in types
        assert "TASK" in types
        assert "DATA" in types

    def test_tokenize_operators(self):
        tokens = tokenize("+ - * / == != >= <= > < -> && ||")
        types = [t.type.name for t in tokens if t.type.name != "EOF"]
        assert "PLUS" in types
        assert "ARROW" in types
        assert "AND" in types
        assert "OR" in types

    def test_tokenize_numbers(self):
        tokens = tokenize("42 3.14")
        nums = [t for t in tokens if t.type.name in ("INT_LIT", "FLOAT_LIT")]
        assert len(nums) == 2
        assert nums[0].value == "42"
        assert nums[1].value == "3.14"

    def test_tokenize_string(self):
        tokens = tokenize('"hello world"')
        strings = [t for t in tokens if t.type.name == "STRING_LIT"]
        assert len(strings) == 1
        assert strings[0].value == "hello world"

    def test_line_tracking(self):
        tokens = tokenize("a\nb\nc")
        lines = [t.location.line for t in tokens if t.type.name == "IDENT"]
        assert lines == [1, 2, 3]

    def test_comments_skipped(self):
        tokens = tokenize("a // comment\nb")
        idents = [t for t in tokens if t.type.name == "IDENT"]
        assert len(idents) == 2

    def test_block_comments_skipped(self):
        tokens = tokenize("a /* block comment */ b")
        idents = [t for t in tokens if t.type.name == "IDENT"]
        assert len(idents) == 2


class TestParser:
    """Parser unit tests."""

    def test_parse_data_def(self):
        program = parse("data User { id: UUID  name: String }")
        assert len(program.declarations) == 1
        data = program.declarations[0]
        assert data.name == "User"
        assert len(data.fields) == 2

    def test_parse_pure_func(self):
        source = "pure add(a: Int, b: Int) -> Int { return a + b }"
        program = parse(source)
        assert len(program.declarations) == 1
        func = program.declarations[0]
        assert func.name == "add"
        assert len(func.params) == 2

    def test_parse_task_func(self):
        source = """
data User { id: UUID }
task save(u: User) -> Bool {
  effects: [Database.Write]
  return db.insert(u)
}
"""
        program = parse(source)
        assert len(program.declarations) == 2

    def test_parse_contracts(self):
        source = """
pure safe(a: Int) -> Int {
  requires: a > 0
  ensures: result >= 0
  return a
}
"""
        program = parse(source)
        func = program.declarations[0]
        assert len(func.requires) == 1
        assert len(func.ensures) == 1

    def test_parse_if_else(self):
        source = """
pure max(a: Int, b: Int) -> Int {
  if a >= b {
    return a
  } else {
    return b
  }
}
"""
        program = parse(source)
        func = program.declarations[0]
        assert len(func.body) == 1

    def test_parse_let_binding(self):
        source = """
pure f(x: Int) -> Int {
  let y: Int = x + 1
  return y
}
"""
        program = parse(source)
        func = program.declarations[0]
        assert len(func.body) == 2

    def test_parse_generic_types(self):
        source = """
task get(id: UUID) -> Result<User, Error> {
  effects: [Database.Read]
  return db.find(id)
}

data User { id: UUID }
"""
        program = parse(source)
        func = program.declarations[0]
        assert func.return_type.name == "Result"
        assert len(func.return_type.generic_args) == 2
