"""AEON Hoare Logic Engine Tests — HOARE-001 through HOARE-020."""

import pytest
from aeon.parser import parse
from aeon.pass1_prove import prove
from aeon.hoare import (
    FormulaKind,
    F_TRUE, F_FALSE, F_VAR, F_INT, F_BOOL, F_FLOAT,
    F_AND, F_OR, F_NOT, F_IMPLIES, F_BINOP, F_UNOP,
    F_ITE, F_FORALL, F_EXISTS, F_IFF,
    F_ARRAY_SELECT, F_ARRAY_STORE, F_ARRAY_LEN,
    F_SEP_STAR, F_POINTS_TO, F_EMP, F_LIST_SEG,
    F_RANKING, F_LEX_RANK, F_GHOST,
    substitute, collect_free_vars,
    WPCalculator, VCGenerator, SummaryTable, FunctionSummary,
    HoareCache, verify_contracts_hoare,
    RankingFunction,
)
from aeon.ast_nodes import (
    ReturnStmt, LetStmt, AssignStmt, IfStmt, WhileStmt,
    Identifier, IntLiteral, BoolLiteral, BinaryOp,
    ContractClause,
)


class TestFormulas:
    """HOARE-001: Formula constructors and simplification laws."""

    def test_true_false_kinds(self):
        assert F_TRUE().kind == FormulaKind.TRUE
        assert F_FALSE().kind == FormulaKind.FALSE

    def test_var(self):
        v = F_VAR("x")
        assert v.kind == FormulaKind.VAR and v.name == "x"

    def test_int_const(self):
        c = F_INT(42)
        assert c.kind == FormulaKind.INT_CONST and c.int_val == 42

    def test_and_flattens(self):
        a = F_AND(F_VAR("x"), F_AND(F_VAR("y"), F_VAR("z")))
        assert a.kind == FormulaKind.AND and len(a.children) == 3

    def test_and_absorbs_true(self):
        assert F_AND(F_TRUE(), F_VAR("x")) == F_VAR("x")

    def test_and_short_circuits_false(self):
        assert F_AND(F_FALSE(), F_VAR("x")).kind == FormulaKind.FALSE

    def test_or_flattens(self):
        o = F_OR(F_VAR("a"), F_OR(F_VAR("b"), F_VAR("c")))
        assert o.kind == FormulaKind.OR and len(o.children) == 3

    def test_or_absorbs_false(self):
        assert F_OR(F_FALSE(), F_VAR("x")) == F_VAR("x")

    def test_or_short_circuits_true(self):
        assert F_OR(F_TRUE(), F_VAR("x")).kind == FormulaKind.TRUE

    def test_not_double_negation(self):
        assert F_NOT(F_NOT(F_VAR("x"))) == F_VAR("x")

    def test_not_true_is_false(self):
        assert F_NOT(F_TRUE()).kind == FormulaKind.FALSE

    def test_implies_false_antecedent(self):
        assert F_IMPLIES(F_FALSE(), F_VAR("x")).kind == FormulaKind.TRUE

    def test_implies_true_consequent(self):
        assert F_IMPLIES(F_VAR("x"), F_TRUE()).kind == FormulaKind.TRUE

    def test_sep_star_flattens_emp(self):
        s = F_SEP_STAR(F_EMP(), F_POINTS_TO(F_VAR("x"), F_INT(1)))
        assert s.kind == FormulaKind.POINTS_TO

    def test_lex_rank(self):
        lr = F_LEX_RANK(F_VAR("i"), F_VAR("j"))
        assert lr.kind == FormulaKind.LEX_RANK and len(lr.children) == 2

    def test_ghost(self):
        g = F_GHOST("ghost_x")
        assert g.kind == FormulaKind.GHOST and g.name == "ghost_x"

    def test_array_select(self):
        assert F_ARRAY_SELECT(F_VAR("a"), F_INT(0)).kind == FormulaKind.ARRAY_SELECT

    def test_array_store(self):
        assert F_ARRAY_STORE(F_VAR("a"), F_INT(0), F_INT(99)).kind == FormulaKind.ARRAY_STORE

    def test_iff(self):
        assert F_IFF(F_VAR("p"), F_VAR("q")).kind == FormulaKind.IFF

    def test_forall(self):
        f = F_FORALL("x", F_BINOP(">=", F_VAR("x"), F_INT(0)))
        assert f.kind == FormulaKind.FORALL and f.quant_var == "x"

    def test_exists(self):
        f = F_EXISTS("x", F_BINOP("==", F_VAR("x"), F_INT(0)))
        assert f.kind == FormulaKind.EXISTS and f.quant_var == "x"


class TestSubstitution:
    """HOARE-002: substitute(formula, var, expr) implements Q[x/e]."""

    def test_var_match(self):
        assert substitute(F_VAR("x"), "x", F_INT(5)) == F_INT(5)

    def test_var_no_match(self):
        assert substitute(F_VAR("y"), "x", F_INT(5)) == F_VAR("y")

    def test_in_binop(self):
        f = F_BINOP("+", F_VAR("x"), F_INT(1))
        result = substitute(f, "x", F_INT(3))
        assert str(result) == "(3 + 1)"

    def test_in_and(self):
        f = F_AND(F_BINOP(">=", F_VAR("x"), F_INT(0)),
                  F_BINOP("<=", F_VAR("x"), F_INT(10)))
        result = substitute(f, "x", F_INT(5))
        assert "5" in str(result)

    def test_capture_avoidance_forall(self):
        f = F_FORALL("x", F_BINOP(">=", F_VAR("x"), F_INT(0)))
        assert substitute(f, "x", F_INT(99)) == f

    def test_capture_avoidance_exists(self):
        f = F_EXISTS("y", F_BINOP("==", F_VAR("y"), F_VAR("x")))
        assert substitute(f, "y", F_INT(7)) == f

    def test_constants_unchanged(self):
        for f in [F_TRUE(), F_FALSE(), F_INT(0), F_FLOAT(1.0), F_BOOL(True)]:
            assert substitute(f, "x", F_INT(99)) == f

    def test_in_implies(self):
        f = F_IMPLIES(F_BINOP(">", F_VAR("n"), F_INT(0)),
                      F_BINOP(">=", F_VAR("n"), F_INT(1)))
        result = substitute(f, "n", F_INT(5))
        assert "5" in str(result)


class TestFreeVars:
    """HOARE-003: collect_free_vars returns correct free variable sets."""

    def test_var(self):
        assert collect_free_vars(F_VAR("x")) == {"x"}

    def test_constants_empty(self):
        for f in [F_TRUE(), F_FALSE(), F_INT(0), F_FLOAT(1.0), F_BOOL(True)]:
            assert collect_free_vars(f) == set()

    def test_binop(self):
        assert collect_free_vars(F_BINOP("+", F_VAR("x"), F_VAR("y"))) == {"x", "y"}

    def test_forall_binds(self):
        f = F_FORALL("x", F_BINOP(">=", F_VAR("x"), F_VAR("y")))
        assert collect_free_vars(f) == {"y"}

    def test_exists_binds(self):
        f = F_EXISTS("z", F_BINOP("==", F_VAR("z"), F_VAR("w")))
        assert collect_free_vars(f) == {"w"}

    def test_nested_and(self):
        f = F_AND(F_VAR("a"), F_VAR("b"), F_VAR("c"))
        assert collect_free_vars(f) == {"a", "b", "c"}


class TestWPCalculator:
    """HOARE-004/005/006: WPCalculator assignment, if, block rules."""

    def test_wp_return_substitutes_result(self):
        wp = WPCalculator()
        stmt = ReturnStmt(value=IntLiteral(value=42))
        post = F_BINOP("==", F_VAR("result"), F_INT(42))
        result = wp.wp(stmt, post)
        # wp(return 42, result==42) = (42==42) at the Formula IR level
        # The Formula IR doesn't auto-evaluate arithmetic equalities,
        # so we check that 'result' was substituted with 42
        assert "result" not in str(result), f"result not substituted: {result}"
        assert "42" in str(result)

    def test_wp_return_no_value(self):
        wp = WPCalculator()
        stmt = ReturnStmt(value=None)
        post = F_VAR("Q")
        assert wp.wp(stmt, post) == post

    def test_wp_let_substitutes(self):
        wp = WPCalculator()
        stmt = LetStmt(name="y", value=BinaryOp(op="+", left=Identifier(name="x"), right=IntLiteral(value=1)))
        post = F_BINOP(">=", F_VAR("y"), F_INT(0))
        result = wp.wp(stmt, post)
        assert "x" in str(result) or "1" in str(result)

    def test_wp_assign_simple(self):
        wp = WPCalculator()
        stmt = AssignStmt(
            target=Identifier(name="x"),
            value=IntLiteral(value=5),
        )
        post = F_BINOP("==", F_VAR("x"), F_INT(5))
        result = wp.wp(stmt, post)
        # wp(x := 5, x == 5) = (5 == 5) — x substituted with 5
        assert "x" not in str(result), f"x not substituted: {result}"
        assert "5" in str(result)

    def test_wp_if_structure(self):
        wp = WPCalculator()
        cond = BinaryOp(op=">", left=Identifier(name="x"), right=IntLiteral(value=0))
        then_body = [ReturnStmt(value=Identifier(name="x"))]
        else_body = [ReturnStmt(value=BinaryOp(op="-", left=IntLiteral(value=0), right=Identifier(name="x")))]
        stmt = IfStmt(condition=cond, then_body=then_body, else_body=else_body)
        post = F_BINOP(">=", F_VAR("result"), F_INT(0))
        result = wp.wp(stmt, post)
        assert result is not None

    def test_wp_empty_block(self):
        wp = WPCalculator()
        post = F_VAR("Q")
        assert wp.wp_block([], post) == post

    def test_wp_block_composition(self):
        wp = WPCalculator()
        stmts = [
            LetStmt(name="a", value=IntLiteral(value=3)),
            ReturnStmt(value=Identifier(name="a")),
        ]
        post = F_BINOP("==", F_VAR("result"), F_INT(3))
        result = wp.wp_block(stmts, post)
        # wp(let a=3; return a, result==3) = (3==3) — both a and result substituted
        assert "result" not in str(result), f"result not substituted: {result}"
        assert "3" in str(result)


class TestSPCalculator:
    """HOARE-007: Strongest postcondition (forward reasoning)."""

    def test_sp_let(self):
        wp = WPCalculator()
        stmt = LetStmt(name="y", value=BinaryOp(op="+", left=Identifier(name="x"), right=IntLiteral(value=1)))
        pre = F_BINOP(">=", F_VAR("x"), F_INT(0))
        result = wp.sp(stmt, pre)
        assert "y" in str(result)

    def test_sp_empty_block(self):
        wp = WPCalculator()
        pre = F_VAR("P")
        assert wp.sp_block([], pre) == pre

    def test_sp_if_disjunction(self):
        wp = WPCalculator()
        cond = BinaryOp(op=">", left=Identifier(name="x"), right=IntLiteral(value=0))
        then_body = [ReturnStmt(value=Identifier(name="x"))]
        else_body = [ReturnStmt(value=IntLiteral(value=0))]
        stmt = IfStmt(condition=cond, then_body=then_body, else_body=else_body)
        result = wp.sp(stmt, F_TRUE())
        assert result.kind in (FormulaKind.OR, FormulaKind.AND, FormulaKind.TRUE)


class TestVCGenerator:
    """HOARE-008/009: VCGenerator contract verification and division VCs."""

    def test_trivially_true_contract(self):
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
"""
        errors = verify_contracts_hoare(parse(source))
        assert errors == []

    def test_identity_contract(self):
        source = """
pure id(x: Int) -> Int {
  ensures: result == x
  return x
}
"""
        assert verify_contracts_hoare(parse(source)) == []

    def test_constant_return_contract(self):
        source = """
pure zero() -> Int {
  ensures: result == 0
  return 0
}
"""
        assert verify_contracts_hoare(parse(source)) == []

    def test_no_contracts_no_errors(self):
        source = "pure add(a: Int, b: Int) -> Int { return a + b }"
        assert verify_contracts_hoare(parse(source)) == []

    def test_division_emits_side_vc(self):
        source = "pure divide(a: Int, b: Int) -> Int { return a / b }"
        gen = VCGenerator()
        gen.verify_program(parse(source))
        vc_names = [vc.name for vc in gen.vcs]
        assert any("division-by-zero" in n for n in vc_names), f"VCs: {vc_names}"

    def test_modulo_emits_side_vc(self):
        source = "pure modulo(a: Int, b: Int) -> Int { return a % b }"
        gen = VCGenerator()
        gen.verify_program(parse(source))
        vc_names = [vc.name for vc in gen.vcs]
        assert any("division-by-zero" in n for n in vc_names)

    def test_multiple_functions_verified(self):
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
pure sub(a: Int, b: Int) -> Int {
  ensures: result == a - b
  return a - b
}
"""
        assert verify_contracts_hoare(parse(source)) == []


class TestSummaryTable:
    """HOARE-010: SummaryTable stores and retrieves summaries."""

    def test_register_and_get(self):
        table = SummaryTable()
        s = FunctionSummary("add", ["a", "b"], F_TRUE(), F_TRUE())
        table.register(s)
        assert table.get("add") is not None

    def test_get_missing_returns_none(self):
        assert SummaryTable().get("nonexistent") is None

    def test_has(self):
        table = SummaryTable()
        table.register(FunctionSummary("f", [], F_TRUE(), F_TRUE()))
        assert table.has("f") and not table.has("g")

    def test_instantiate_substitutes_args(self):
        s = FunctionSummary(
            "double", ["x"],
            F_BINOP(">=", F_VAR("x"), F_INT(0)),
            F_BINOP("==", F_VAR("result"), F_BINOP("*", F_INT(2), F_VAR("x"))),
        )
        _, post = s.instantiate([F_INT(5)])
        assert "5" in str(post)

    def test_all_names(self):
        table = SummaryTable()
        for name in ["f", "g", "h"]:
            table.register(FunctionSummary(name, [], F_TRUE(), F_TRUE()))
        assert set(table.all_names()) == {"f", "g", "h"}


class TestHoareCache:
    """HOARE-011: HoareCache incremental verification."""

    def test_store_and_lookup(self):
        cache = HoareCache()
        source = "pure f(x: Int) -> Int { return x }"
        func = parse(source).declarations[0]
        cache.store(func, "h1", [], [])
        assert cache.lookup(func, "h1") == ([], [])

    def test_lookup_miss_different_hash(self):
        cache = HoareCache()
        source = "pure f(x: Int) -> Int { return x }"
        func = parse(source).declarations[0]
        cache.store(func, "h1", [], [])
        assert cache.lookup(func, "h2") is None

    def test_invalidate_removes_entries(self):
        cache = HoareCache()
        source = "pure f(x: Int) -> Int { return x }"
        func = parse(source).declarations[0]
        cache.store(func, "h1", [], [])
        cache.invalidate("f")
        assert cache.lookup(func, "h1") is None

    def test_dependency_invalidation(self):
        cache = HoareCache()
        cache.register_dependency("caller", "callee")
        source = "pure caller(x: Int) -> Int { return x }"
        func = parse(source).declarations[0]
        cache.store(func, "h1", [], [])
        cache.invalidate_dependents("callee")
        assert cache.lookup(func, "h1") is None


class TestRankingFunction:
    """HOARE-012: RankingFunction lex decrease formula."""

    def test_scalar_str(self):
        rf = RankingFunction(formula=F_VAR("n"), variables=["n"])
        assert str(rf) == "n"

    def test_lex_str(self):
        rf = RankingFunction(
            formula=F_LEX_RANK(F_VAR("i"), F_VAR("j")),
            variables=["i", "j"],
            is_lexicographic=True,
            components=[F_VAR("i"), F_VAR("j")],
        )
        assert "i" in str(rf) and "j" in str(rf)

    def test_lex_decrease_two_components(self):
        rf = RankingFunction(
            formula=F_LEX_RANK(F_VAR("i"), F_VAR("j")),
            variables=["i", "j"],
            is_lexicographic=True,
            components=[F_VAR("i"), F_VAR("j")],
        )
        dec = rf.lex_decrease_formula([F_VAR("v0"), F_VAR("v1")], [F_VAR("i"), F_VAR("j")])
        assert dec.kind == FormulaKind.OR and len(dec.children) == 2

    def test_lex_decrease_single(self):
        rf = RankingFunction(formula=F_VAR("n"), variables=["n"],
                             is_lexicographic=True, components=[F_VAR("n")])
        dec = rf.lex_decrease_formula([F_VAR("v0")], [F_VAR("n")])
        assert dec.kind == FormulaKind.BINOP and dec.op == "<"

    def test_lex_decrease_empty(self):
        rf = RankingFunction(formula=F_TRUE(), variables=[])
        assert rf.lex_decrease_formula([], []).kind == FormulaKind.FALSE


class TestTarjanSCC:
    """HOARE-013: Tarjan SCC for call graph analysis."""

    def test_non_recursive_singleton_sccs(self):
        source = "pure f(x: Int) -> Int { return x }\npure g(x: Int) -> Int { return x + 1 }"
        program = parse(source)
        functions = list(program.declarations)
        gen = VCGenerator()
        cg = gen._build_call_graph(functions)
        sccs = gen._tarjan_sccs(functions, cg)
        assert len(sccs) == 2
        for scc in sccs:
            assert len(scc) == 1

    def test_recursive_function_singleton_scc(self):
        source = """
pure factorial(n: Int) -> Int {
  if n <= 1 { return 1 } else { return n * factorial(n - 1) }
}
"""
        program = parse(source)
        functions = list(program.declarations)
        gen = VCGenerator()
        cg = gen._build_call_graph(functions)
        sccs = gen._tarjan_sccs(functions, cg)
        assert len(sccs) == 1

    def test_call_graph_captures_direct_calls(self):
        source = """
pure helper(x: Int) -> Int { return x + 1 }
pure main(x: Int) -> Int { return helper(x) }
"""
        program = parse(source)
        functions = list(program.declarations)
        gen = VCGenerator()
        cg = gen._build_call_graph(functions)
        assert "helper" in cg.get("main", set())


class TestProofCertificates:
    """HOARE-014: ProofCertificate Lean4/Coq export."""

    def test_certificates_produced(self):
        source = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
"""
        gen = VCGenerator()
        gen.verify_program(parse(source))
        assert isinstance(gen.certificates, list)

    def test_lean4_export(self):
        source = """
pure id(x: Int) -> Int {
  ensures: result == x
  return x
}
"""
        from aeon.hoare import export_proof_certificates
        output = export_proof_certificates(parse(source), format="lean4")
        assert isinstance(output, str)
        assert "AEON" in output

    def test_coq_export(self):
        source = """
pure id(x: Int) -> Int {
  ensures: result == x
  return x
}
"""
        from aeon.hoare import export_proof_certificates
        output = export_proof_certificates(parse(source), format="coq")
        assert isinstance(output, str)


class TestCounterexampleExplanations:
    """HOARE-015: Counterexample explanations are informative."""

    def test_division_by_zero_explanation(self):
        source = "pure divide(a: Int, b: Int) -> Int { return a / b }"
        gen = VCGenerator()
        gen.verify_program(parse(source))
        div_vcs = [vc for vc in gen.vcs if "division-by-zero" in vc.name]
        assert len(div_vcs) > 0

    def test_no_false_positives_on_safe_division(self):
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


class TestWPWhile:
    """HOARE-016: WPCalculator while loop handling."""

    def test_wp_while_returns_invariant(self):
        wp = WPCalculator()
        cond = BinaryOp(op="<", left=Identifier(name="i"), right=IntLiteral(value=10))
        body = [
            AssignStmt(
                target=Identifier(name="i"),
                value=BinaryOp(op="+", left=Identifier(name="i"), right=IntLiteral(value=1)),
            )
        ]
        stmt = WhileStmt(condition=cond, body=body)
        post = F_BINOP(">=", F_VAR("i"), F_INT(0))
        result = wp.wp(stmt, post)
        assert result is not None

    def test_wp_while_generates_side_vcs(self):
        wp = WPCalculator()
        cond = BinaryOp(op="<", left=Identifier(name="i"), right=IntLiteral(value=5))
        body = [
            AssignStmt(
                target=Identifier(name="i"),
                value=BinaryOp(op="+", left=Identifier(name="i"), right=IntLiteral(value=1)),
            )
        ]
        stmt = WhileStmt(condition=cond, body=body)
        wp.wp(stmt, F_TRUE())
        vc_labels = [label for label, _ in wp._side_vcs]
        assert any("loop" in l or "ranking" in l for l in vc_labels), f"Side VCs: {vc_labels}"


class TestCollectVarsFromStmts:
    """HOARE-017: _collect_vars_from_stmts covers all statement types."""

    def test_collects_let_name(self):
        wp = WPCalculator()
        stmts = [LetStmt(name="x", value=IntLiteral(value=0))]
        result = wp._collect_vars_from_stmts(stmts)
        assert "x" in result

    def test_collects_assign_target(self):
        wp = WPCalculator()
        stmts = [AssignStmt(target=Identifier(name="y"), value=IntLiteral(value=1))]
        result = wp._collect_vars_from_stmts(stmts)
        assert "y" in result

    def test_collects_return_vars(self):
        wp = WPCalculator()
        stmts = [ReturnStmt(value=Identifier(name="z"))]
        result = wp._collect_vars_from_stmts(stmts)
        assert "z" in result

    def test_collects_nested_while(self):
        wp = WPCalculator()
        inner_cond = BinaryOp(op="<", left=Identifier(name="j"), right=IntLiteral(value=5))
        inner_body = [AssignStmt(target=Identifier(name="j"),
                                  value=BinaryOp(op="+", left=Identifier(name="j"), right=IntLiteral(value=1)))]
        outer_cond = BinaryOp(op="<", left=Identifier(name="i"), right=IntLiteral(value=10))
        outer_body = [WhileStmt(condition=inner_cond, body=inner_body)]
        stmts = [WhileStmt(condition=outer_cond, body=outer_body)]
        result = wp._collect_vars_from_stmts(stmts)
        assert "i" in result and "j" in result


class TestEndToEndHoare:
    """HOARE-018: End-to-end Hoare verification via pass1_prove."""

    def test_abs_function(self):
        source = """
pure abs(x: Int) -> Int {
  if x >= 0 {
    return x
  } else {
    return 0 - x
  }
}
"""
        errors = prove(parse(source))
        assert errors == []

    def test_max_function(self):
        source = """
pure max(a: Int, b: Int) -> Int {
  if a >= b {
    return a
  } else {
    return b
  }
}
"""
        errors = prove(parse(source))
        assert errors == []

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
        term_errors = [e for e in errors if "termination" in str(e.message).lower()
                       or "decreasing" in str(e.message).lower()]
        assert len(term_errors) == 0

    def test_infinite_loop_detected(self):
        source = """
pure infinite(x: Int) -> Int {
  return infinite(x)
}
"""
        errors = prove(parse(source), analyze_termination=True)
        assert len(errors) > 0

    def test_safe_divide_contract(self):
        source = """
pure safeDivide(a: Int, b: Int) -> Int {
  requires: b != 0
  return a / b
}
"""
        errors = prove(parse(source))
        assert errors == []
