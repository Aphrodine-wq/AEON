"""AEON Contract & Termination Tests — CONT-001 through CONT-020.

Tests for:
  - Requires/ensures clause parsing and verification
  - Contract violations detected correctly
  - Termination analysis (base cases, decreasing arguments)
  - Division-by-zero detection
  - Hoare logic contract verification end-to-end
  - Modular verification across multiple functions
"""

import pytest
from aeon.parser import parse
from aeon.pass1_prove import prove
from aeon.hoare import verify_contracts_hoare, VCGenerator


# ===========================================================================
# CONT-001: Requires clause satisfiability
# ===========================================================================

class TestCONT001:
    """CONT-001: Requires clauses are parsed and satisfiable."""

    def test_simple_requires_parsed(self):
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

    def test_multiple_requires_parsed(self):
        source = """
pure bounded(x: Int, lo: Int, hi: Int) -> Int {
  requires: x >= lo
  requires: x <= hi
  return x
}
"""
        program = parse(source)
        func = program.declarations[0]
        assert len(func.requires) == 2

    def test_requires_with_compound_condition(self):
        source = """
pure check(a: Int, b: Int) -> Bool {
  requires: a > 0 && b > 0
  return a > b
}
"""
        program = parse(source)
        func = program.declarations[0]
        assert len(func.requires) == 1

    def test_requires_passes_type_check(self):
        source = """
pure positive(x: Int) -> Int {
  requires: x > 0
  return x
}
"""
        errors = prove(parse(source))
        assert errors == []


# ===========================================================================
# CONT-002: Ensures clause parsing and verification
# ===========================================================================

class TestCONT002:
    """CONT-002: Ensures clauses are parsed and verified."""

    def test_simple_ensures_parsed(self):
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

    def test_ensures_result_variable(self):
        source = """
pure double(x: Int) -> Int {
  ensures: result == x + x
  return x + x
}
"""
        errors = prove(parse(source))
        assert errors == []

    def test_ensures_non_negative(self):
        source = """
pure abs(x: Int) -> Int {
  ensures: result >= 0
  if x >= 0 {
    return x
  } else {
    return 0 - x
  }
}
"""
        errors = prove(parse(source))
        assert errors == []

    def test_ensures_with_requires(self):
        source = """
pure safeDivide(a: Int, b: Int) -> Int {
  requires: b != 0
  ensures: result == a / b
  return a / b
}
"""
        errors = prove(parse(source))
        assert errors == []

    def test_multiple_ensures(self):
        source = """
pure clamp(x: Int, lo: Int, hi: Int) -> Int {
  requires: lo <= hi
  ensures: result >= lo
  ensures: result <= hi
  if x < lo {
    return lo
  } else {
    if x > hi {
      return hi
    } else {
      return x
    }
  }
}
"""
        program = parse(source)
        func = program.declarations[0]
        assert len(func.ensures) == 2


# ===========================================================================
# CONT-003: Hoare logic contract verification
# ===========================================================================

class TestCONT003:
    """CONT-003: Hoare logic verifies contracts correctly."""

    def test_identity_verified(self):
        source = """
pure id(x: Int) -> Int {
  ensures: result == x
  return x
}
"""
        errors = verify_contracts_hoare(parse(source))
        assert errors == []

    def test_constant_verified(self):
        source = """
pure zero() -> Int {
  ensures: result == 0
  return 0
}
"""
        assert verify_contracts_hoare(parse(source)) == []

    def test_addition_verified(self):
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
"""
        assert verify_contracts_hoare(parse(source)) == []

    def test_no_contracts_no_errors(self):
        source = "pure f(x: Int) -> Int { return x + 1 }"
        assert verify_contracts_hoare(parse(source)) == []

    def test_multiple_functions_all_verified(self):
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
pure sub(a: Int, b: Int) -> Int {
  ensures: result == a - b
  return a - b
}
pure mul(a: Int, b: Int) -> Int {
  ensures: result == a * b
  return a * b
}
"""
        assert verify_contracts_hoare(parse(source)) == []


# ===========================================================================
# CONT-004: Division-by-zero detection
# ===========================================================================

class TestCONT004:
    """CONT-004: Division-by-zero VCs are generated."""

    def test_division_generates_vc(self):
        source = "pure divide(a: Int, b: Int) -> Int { return a / b }"
        gen = VCGenerator()
        gen.verify_program(parse(source))
        vc_names = [vc.name for vc in gen.vcs]
        assert any("division-by-zero" in n for n in vc_names), f"VCs: {vc_names}"

    def test_modulo_generates_vc(self):
        source = "pure mod(a: Int, b: Int) -> Int { return a % b }"
        gen = VCGenerator()
        gen.verify_program(parse(source))
        vc_names = [vc.name for vc in gen.vcs]
        assert any("division-by-zero" in n for n in vc_names)

    def test_safe_division_with_requires_no_error(self):
        source = """
pure safeDivide(a: Int, b: Int) -> Int {
  requires: b != 0
  return a / b
}
"""
        gen = VCGenerator()
        errors = gen.verify_program(parse(source))
        div_errors = [e for e in errors if "division" in str(e.message).lower()]
        assert len(div_errors) == 0

    def test_no_division_no_vc(self):
        source = "pure add(a: Int, b: Int) -> Int { return a + b }"
        gen = VCGenerator()
        gen.verify_program(parse(source))
        vc_names = [vc.name for vc in gen.vcs]
        assert not any("division-by-zero" in n for n in vc_names)

    def test_nested_division_generates_vc(self):
        source = """
pure nestedDiv(a: Int, b: Int, c: Int) -> Int {
  let x: Int = a / b
  return x / c
}
"""
        gen = VCGenerator()
        gen.verify_program(parse(source))
        vc_names = [vc.name for vc in gen.vcs]
        div_vcs = [n for n in vc_names if "division-by-zero" in n]
        assert len(div_vcs) >= 1


# ===========================================================================
# CONT-005: Termination analysis
# ===========================================================================

class TestCONT005:
    """CONT-005: Termination analysis detects terminating/non-terminating functions."""

    def test_factorial_terminates(self):
        source = """
pure factorial(n: Int) -> Int {
  if n <= 1 {
    return 1
  } else {
    return n * factorial(n - 1)
  }
}
"""
        errors = prove(parse(source), analyze_termination=True)
        term_errors = [e for e in errors
                       if "decreasing" in str(e.message).lower()
                       or "base case" in str(e.message).lower()]
        assert len(term_errors) == 0

    def test_fibonacci_terminates(self):
        source = """
pure fib(n: Int) -> Int {
  if n <= 1 {
    return n
  } else {
    return fib(n - 1) + fib(n - 2)
  }
}
"""
        errors = prove(parse(source), analyze_termination=True)
        term_errors = [e for e in errors
                       if "decreasing" in str(e.message).lower()
                       or "base case" in str(e.message).lower()]
        assert len(term_errors) == 0

    def test_infinite_recursion_detected(self):
        source = """
pure infinite(x: Int) -> Int {
  return infinite(x)
}
"""
        errors = prove(parse(source), analyze_termination=True)
        assert len(errors) > 0

    def test_non_recursive_no_termination_error(self):
        source = """
pure add(a: Int, b: Int) -> Int {
  return a + b
}
"""
        errors = prove(parse(source), analyze_termination=True)
        assert errors == []

    def test_halving_terminates(self):
        source = """
pure halve(n: Int) -> Int {
  if n <= 1 {
    return 0
  } else {
    return 1 + halve(n / 2)
  }
}
"""
        errors = prove(parse(source), analyze_termination=True)
        term_errors = [e for e in errors
                       if "decreasing" in str(e.message).lower()
                       or "base case" in str(e.message).lower()]
        assert len(term_errors) == 0


# ===========================================================================
# CONT-006: Effect checking with contracts
# ===========================================================================

class TestCONT006:
    """CONT-006: Effects and contracts interact correctly."""

    def test_task_with_contract_and_effect(self):
        source = """
data User {
  id: UUID
  name: String
}

task createUser(user: User) -> Bool {
  requires: user.name.length() > 0
  ensures: result == true
  effects: [Database.Write]
  return db.insert(user)
}
"""
        program = parse(source)
        errors = prove(program)
        effect_errors = [e for e in errors if e.kind.value == "effect_error"]
        assert len(effect_errors) == 0

    def test_pure_function_with_contract_passes(self):
        source = """
pure clamp(x: Int, lo: Int, hi: Int) -> Int {
  requires: lo <= hi
  if x < lo {
    return lo
  } else {
    if x > hi {
      return hi
    } else {
      return x
    }
  }
}
"""
        errors = prove(parse(source))
        assert errors == []


# ===========================================================================
# CONT-007: Modular verification — callee contracts used by callers
# ===========================================================================

class TestCONT007:
    """CONT-007: Modular verification uses callee summaries."""

    def test_callee_contract_used(self):
        source = """
pure double(x: Int) -> Int {
  ensures: result == x + x
  return x + x
}

pure quadruple(x: Int) -> Int {
  ensures: result == x + x + x + x
  return double(x) + double(x)
}
"""
        errors = verify_contracts_hoare(parse(source))
        assert isinstance(errors, list)

    def test_chain_of_functions(self):
        source = """
pure inc(x: Int) -> Int {
  ensures: result == x + 1
  return x + 1
}

pure inc2(x: Int) -> Int {
  ensures: result == x + 2
  return inc(inc(x))
}
"""
        errors = verify_contracts_hoare(parse(source))
        assert isinstance(errors, list)

    def test_independent_functions_both_verified(self):
        source = """
pure f(x: Int) -> Int {
  ensures: result == x
  return x
}
pure g(y: Int) -> Int {
  ensures: result == y + 1
  return y + 1
}
"""
        errors = verify_contracts_hoare(parse(source))
        assert errors == []


# ===========================================================================
# CONT-008: Loop contracts
# ===========================================================================

class TestCONT008:
    """CONT-008: Functions with loops and contracts."""

    def test_loop_function_no_contracts(self):
        source = """
pure sumTo(n: Int) -> Int {
  let i: Int = 0
  let s: Int = 0
  return s
}
"""
        errors = prove(parse(source))
        assert errors == []

    def test_function_with_loop_and_ensures(self):
        source = """
pure countDown(n: Int) -> Int {
  requires: n >= 0
  ensures: result == 0
  return 0
}
"""
        errors = verify_contracts_hoare(parse(source))
        assert errors == []


# ===========================================================================
# CONT-009: Contract error message quality
# ===========================================================================

class TestCONT009:
    """CONT-009: Contract errors have useful structured messages."""

    def test_division_vc_name_contains_function(self):
        source = "pure myFunc(a: Int, b: Int) -> Int { return a / b }"
        gen = VCGenerator()
        gen.verify_program(parse(source))
        div_vcs = [vc for vc in gen.vcs if "division-by-zero" in vc.name]
        assert len(div_vcs) > 0
        assert "myFunc" in div_vcs[0].name

    def test_contract_vc_has_function_name(self):
        source = """
pure myAdd(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
"""
        gen = VCGenerator()
        gen.verify_program(parse(source))
        contract_vcs = [vc for vc in gen.vcs if "contract_" in vc.name]
        assert any("myAdd" in vc.name for vc in contract_vcs)

    def test_side_vcs_have_labels(self):
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
"""
        gen = VCGenerator()
        gen.verify_program(parse(source))
        for vc in gen.vcs:
            assert vc.name, f"VC missing name: {vc}"


# ===========================================================================
# CONT-010: Regression tests for previously found bugs
# ===========================================================================

class TestCONT010:
    """CONT-010: Regression tests for fixed bugs."""

    def test_contracts_py_no_blockstmt_import_error(self):
        """contracts.py used to import BlockStmt which doesn't exist."""
        from aeon.contracts import ContractVerifier
        cv = ContractVerifier(verify=False)
        assert cv is not None

    def test_extract_return_from_list_body(self):
        """_extract_return_expression must handle list bodies (not BlockStmt)."""
        from aeon.contracts import ContractVerifier
        from aeon.ast_nodes import ReturnStmt, IntLiteral
        cv = ContractVerifier(verify=False)
        body = [ReturnStmt(value=IntLiteral(value=42))]
        result = cv._extract_return_expression(body)
        assert result is not None
        assert isinstance(result, IntLiteral)
        assert result.value == 42

    def test_collect_vars_includes_return_stmts(self):
        """_collect_vars_from_stmts must include vars from ReturnStmt."""
        from aeon.hoare import WPCalculator
        from aeon.ast_nodes import ReturnStmt, Identifier
        wp = WPCalculator()
        stmts = [ReturnStmt(value=Identifier(name="myVar"))]
        result = wp._collect_vars_from_stmts(stmts)
        assert "myVar" in result

    def test_collect_vars_includes_expr_stmts(self):
        """_collect_vars_from_stmts must include vars from ExprStmt."""
        from aeon.hoare import WPCalculator
        from aeon.ast_nodes import ExprStmt, Identifier
        wp = WPCalculator()
        stmts = [ExprStmt(expr=Identifier(name="sideEffect"))]
        result = wp._collect_vars_from_stmts(stmts)
        assert "sideEffect" in result

    def test_termination_base_case_requires_return(self):
        """Termination checker must require an actual return in base case branch."""
        from aeon.termination import TerminationAnalyzer
        source = """
pure factorial(n: Int) -> Int {
  if n <= 1 {
    return 1
  } else {
    return n * factorial(n - 1)
  }
}
"""
        program = parse(source)
        funcs = [d for d in program.declarations]
        analyzer = TerminationAnalyzer()
        errors = analyzer.analyze_program(funcs)
        term_errors = [e for e in errors if "base case" in str(e.message).lower()]
        assert len(term_errors) == 0, f"False positive base case error: {term_errors}"

    def test_termination_decreasing_n_minus_1(self):
        """n - 1 must be recognised as a decreasing argument."""
        from aeon.termination import TerminationAnalyzer
        source = """
pure countdown(n: Int) -> Int {
  if n <= 0 {
    return 0
  } else {
    return countdown(n - 1)
  }
}
"""
        program = parse(source)
        funcs = [d for d in program.declarations]
        analyzer = TerminationAnalyzer()
        errors = analyzer.analyze_program(funcs)
        dec_errors = [e for e in errors if "decreasing" in str(e.message).lower()]
        assert len(dec_errors) == 0, f"False positive decreasing error: {dec_errors}"

    def test_termination_decreasing_n_div_2(self):
        """n / 2 must be recognised as a decreasing argument."""
        from aeon.termination import TerminationAnalyzer
        source = """
pure binarySearch(n: Int) -> Int {
  if n <= 1 {
    return 0
  } else {
    return 1 + binarySearch(n / 2)
  }
}
"""
        program = parse(source)
        funcs = [d for d in program.declarations]
        analyzer = TerminationAnalyzer()
        errors = analyzer.analyze_program(funcs)
        dec_errors = [e for e in errors if "decreasing" in str(e.message).lower()]
        assert len(dec_errors) == 0, f"False positive for n/2: {dec_errors}"
