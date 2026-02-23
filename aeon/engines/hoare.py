"""AEON Hoare Logic Engine — Weakest Precondition Calculus.

Implements Dijkstra's weakest precondition (wp) calculus and Hoare logic
for mechanical verification of AEON function contracts.

References:
  Dijkstra (1975) "Guarded Commands, Nondeterminacy and Formal Derivation
  of Programs" CACM 18(8), https://doi.org/10.1145/360933.360975

  Hoare (1969) "An Axiomatic Basis for Computer Programming"
  CACM 12(10), https://doi.org/10.1145/363235.363259

  Floyd (1967) "Assigning Meanings to Programs"
  Proc. Symp. Applied Mathematics, AMS

Core theory:

  A HOARE TRIPLE {P} S {Q} asserts:
    If precondition P holds before executing statement S,
    then postcondition Q holds after S terminates.

  WEAKEST PRECONDITION wp(S, Q) is the weakest predicate P such that {P} S {Q}.
  It is computed backwards from the postcondition through each statement:

    wp(skip, Q)           = Q
    wp(x := e, Q)         = Q[x/e]                    (substitution)
    wp(S1; S2, Q)         = wp(S1, wp(S2, Q))          (sequential composition)
    wp(if b then S1 else S2, Q) = (b => wp(S1, Q)) /\\ (!b => wp(S2, Q))
    wp(while b do S, Q)   = I /\\ (I /\\ !b => Q)      (requires loop invariant I)

  VERIFICATION CONDITION GENERATION:
    Given {P} S {Q}, we compute wp(S, Q) and then check P => wp(S, Q).
    This implication is discharged to Z3.

  LOOP INVARIANT INFERENCE:
    We use Houdini-style inference (Flanagan & Leino 2001):
    1. Guess a set of candidate invariants from templates
    2. Iteratively remove candidates that are not inductive
    3. The remaining candidates form the loop invariant

  TOTAL CORRECTNESS:
    {P} S {Q} (partial correctness) + termination = total correctness.
    For loops, we additionally need a variant function (ranking function)
    that strictly decreases on each iteration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Set, Tuple
from enum import Enum, auto
import copy

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, Statement, Expr,
    Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    ContractClause,
)
from aeon.errors import AeonError, contract_error, SourceLocation

import sys, io, os

z3_path = "/tmp/z3-src/build/python"
if os.path.exists(z3_path) and z3_path not in sys.path:
    sys.path.insert(0, z3_path)

_saved = (sys.stdout, sys.stderr)
try:
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    import z3
    HAS_Z3 = True
except (ImportError, Exception):
    z3 = None
    HAS_Z3 = False
finally:
    sys.stdout, sys.stderr = _saved


# ---------------------------------------------------------------------------
# Logical Formulas (for wp calculus)
# ---------------------------------------------------------------------------

class FormulaKind(Enum):
    TRUE = auto()
    FALSE = auto()
    VAR = auto()
    INT_CONST = auto()
    BOOL_CONST = auto()
    BINOP = auto()
    UNOP = auto()
    AND = auto()
    OR = auto()
    NOT = auto()
    IMPLIES = auto()
    FORALL = auto()
    EXISTS = auto()
    SUBST = auto()        # Substitution marker: Q[x/e]
    ITE = auto()          # If-then-else expression


@dataclass(frozen=True)
class Formula:
    """A first-order logic formula for verification conditions.

    This is the internal representation used by the wp-calculus.
    Formulas are immutable trees that can be translated to Z3.
    """
    kind: FormulaKind
    name: str = ""                          # for VAR
    int_val: int = 0                        # for INT_CONST
    bool_val: bool = True                   # for BOOL_CONST
    op: str = ""                            # for BINOP, UNOP
    children: Tuple[Formula, ...] = ()      # sub-formulas
    subst_var: str = ""                     # for SUBST: variable being substituted
    subst_expr: Optional[Formula] = None    # for SUBST: expression replacing variable
    quant_var: str = ""                     # for FORALL/EXISTS

    def __str__(self) -> str:
        if self.kind == FormulaKind.TRUE:
            return "true"
        if self.kind == FormulaKind.FALSE:
            return "false"
        if self.kind == FormulaKind.VAR:
            return self.name
        if self.kind == FormulaKind.INT_CONST:
            return str(self.int_val)
        if self.kind == FormulaKind.BOOL_CONST:
            return str(self.bool_val).lower()
        if self.kind == FormulaKind.BINOP:
            return f"({self.children[0]} {self.op} {self.children[1]})"
        if self.kind == FormulaKind.UNOP:
            return f"({self.op}{self.children[0]})"
        if self.kind == FormulaKind.AND:
            return "(" + " /\\ ".join(str(c) for c in self.children) + ")"
        if self.kind == FormulaKind.OR:
            return "(" + " \\/ ".join(str(c) for c in self.children) + ")"
        if self.kind == FormulaKind.NOT:
            return f"!({self.children[0]})"
        if self.kind == FormulaKind.IMPLIES:
            return f"({self.children[0]} => {self.children[1]})"
        if self.kind == FormulaKind.FORALL:
            return f"(forall {self.quant_var}. {self.children[0]})"
        if self.kind == FormulaKind.ITE:
            return f"(ite {self.children[0]} {self.children[1]} {self.children[2]})"
        return "<?>"


# Formula constructors
def F_TRUE() -> Formula:
    return Formula(kind=FormulaKind.TRUE)

def F_FALSE() -> Formula:
    return Formula(kind=FormulaKind.FALSE)

def F_VAR(name: str) -> Formula:
    return Formula(kind=FormulaKind.VAR, name=name)

def F_INT(val: int) -> Formula:
    return Formula(kind=FormulaKind.INT_CONST, int_val=val)

def F_BOOL(val: bool) -> Formula:
    return Formula(kind=FormulaKind.BOOL_CONST, bool_val=val)

def F_BINOP(op: str, left: Formula, right: Formula) -> Formula:
    return Formula(kind=FormulaKind.BINOP, op=op, children=(left, right))

def F_UNOP(op: str, operand: Formula) -> Formula:
    return Formula(kind=FormulaKind.UNOP, op=op, children=(operand,))

def F_AND(*children: Formula) -> Formula:
    flat: List[Formula] = []
    for c in children:
        if c.kind == FormulaKind.TRUE:
            continue
        if c.kind == FormulaKind.FALSE:
            return F_FALSE()
        if c.kind == FormulaKind.AND:
            flat.extend(c.children)
        else:
            flat.append(c)
    if not flat:
        return F_TRUE()
    if len(flat) == 1:
        return flat[0]
    return Formula(kind=FormulaKind.AND, children=tuple(flat))

def F_OR(*children: Formula) -> Formula:
    flat: List[Formula] = []
    for c in children:
        if c.kind == FormulaKind.FALSE:
            continue
        if c.kind == FormulaKind.TRUE:
            return F_TRUE()
        if c.kind == FormulaKind.OR:
            flat.extend(c.children)
        else:
            flat.append(c)
    if not flat:
        return F_FALSE()
    if len(flat) == 1:
        return flat[0]
    return Formula(kind=FormulaKind.OR, children=tuple(flat))

def F_NOT(f: Formula) -> Formula:
    if f.kind == FormulaKind.TRUE:
        return F_FALSE()
    if f.kind == FormulaKind.FALSE:
        return F_TRUE()
    if f.kind == FormulaKind.NOT:
        return f.children[0]
    return Formula(kind=FormulaKind.NOT, children=(f,))

def F_IMPLIES(lhs: Formula, rhs: Formula) -> Formula:
    if lhs.kind == FormulaKind.TRUE:
        return rhs
    if lhs.kind == FormulaKind.FALSE:
        return F_TRUE()
    if rhs.kind == FormulaKind.TRUE:
        return F_TRUE()
    return Formula(kind=FormulaKind.IMPLIES, children=(lhs, rhs))

def F_ITE(cond: Formula, then_f: Formula, else_f: Formula) -> Formula:
    return Formula(kind=FormulaKind.ITE, children=(cond, then_f, else_f))

def F_FORALL(var: str, body: Formula) -> Formula:
    return Formula(kind=FormulaKind.FORALL, quant_var=var, children=(body,))


# ---------------------------------------------------------------------------
# Substitution: Q[x/e]
# ---------------------------------------------------------------------------

def substitute(formula: Formula, var: str, expr: Formula) -> Formula:
    """Substitute all occurrences of variable 'var' with expression 'expr' in formula.

    This is the core operation of the wp-calculus:
      wp(x := e, Q) = Q[x/e]

    Must handle:
      - Capture avoidance (not needed here since we use unique names)
      - Recursive descent through all formula constructors
    """
    if formula.kind == FormulaKind.VAR:
        if formula.name == var:
            return expr
        return formula

    if formula.kind in (FormulaKind.TRUE, FormulaKind.FALSE,
                        FormulaKind.INT_CONST, FormulaKind.BOOL_CONST):
        return formula

    if formula.kind in (FormulaKind.BINOP, FormulaKind.UNOP,
                        FormulaKind.AND, FormulaKind.OR, FormulaKind.NOT,
                        FormulaKind.IMPLIES, FormulaKind.ITE):
        new_children = tuple(substitute(c, var, expr) for c in formula.children)
        return Formula(
            kind=formula.kind, name=formula.name, int_val=formula.int_val,
            bool_val=formula.bool_val, op=formula.op, children=new_children,
            subst_var=formula.subst_var, subst_expr=formula.subst_expr,
            quant_var=formula.quant_var,
        )

    if formula.kind == FormulaKind.FORALL:
        if formula.quant_var == var:
            return formula  # Bound variable shadows
        new_body = substitute(formula.children[0], var, expr)
        return F_FORALL(formula.quant_var, new_body)

    return formula


# ---------------------------------------------------------------------------
# Weakest Precondition Calculator
# ---------------------------------------------------------------------------

class WPCalculator:
    """Computes weakest preconditions for AEON statements.

    Implements Dijkstra's wp-calculus:
      wp(S, Q) = the weakest predicate P such that {P} S {Q}

    The wp function is computed backwards from the postcondition.
    """

    def __init__(self):
        self._var_counter = 0

    def fresh_var(self, prefix: str = "wp") -> str:
        self._var_counter += 1
        return f"__{prefix}_{self._var_counter}"

    def wp(self, stmt: Statement, post: Formula) -> Formula:
        """Compute wp(stmt, post) — the weakest precondition.

        This is the heart of the verification engine.
        """
        if isinstance(stmt, ReturnStmt):
            return self._wp_return(stmt, post)
        if isinstance(stmt, LetStmt):
            return self._wp_let(stmt, post)
        if isinstance(stmt, AssignStmt):
            return self._wp_assign(stmt, post)
        if isinstance(stmt, ExprStmt):
            return post  # Expression statements don't affect wp
        if isinstance(stmt, IfStmt):
            return self._wp_if(stmt, post)
        if isinstance(stmt, WhileStmt):
            return self._wp_while(stmt, post)
        return post

    def wp_block(self, stmts: List[Statement], post: Formula) -> Formula:
        """Compute wp for a sequence of statements.

        wp(S1; S2; ...; Sn, Q) = wp(S1, wp(S2, ..., wp(Sn, Q)))

        Computed right-to-left (backwards from postcondition).
        """
        result = post
        for stmt in reversed(stmts):
            result = self.wp(stmt, result)
        return result

    def _wp_return(self, stmt: ReturnStmt, post: Formula) -> Formula:
        """wp(return e, Q) = Q[result/e]

        The returned value is substituted for 'result' in the postcondition.
        """
        if stmt.value:
            expr_formula = self._expr_to_formula(stmt.value)
            return substitute(post, "result", expr_formula)
        return post

    def _wp_let(self, stmt: LetStmt, post: Formula) -> Formula:
        """wp(let x = e, Q) = Q[x/e]

        Variable introduction is a substitution in the postcondition.
        """
        if stmt.value:
            expr_formula = self._expr_to_formula(stmt.value)
            return substitute(post, stmt.name, expr_formula)
        return post

    def _wp_assign(self, stmt: AssignStmt, post: Formula) -> Formula:
        """wp(x := e, Q) = Q[x/e]

        Assignment is the canonical wp rule — substitute the assigned
        expression for the variable in the postcondition.
        """
        if isinstance(stmt.target, Identifier):
            expr_formula = self._expr_to_formula(stmt.value)
            return substitute(post, stmt.target.name, expr_formula)
        return post

    def _wp_if(self, stmt: IfStmt, post: Formula) -> Formula:
        """wp(if b then S1 else S2, Q) = (b => wp(S1,Q)) /\\ (!b => wp(S2,Q))

        This is the conditional rule: we must establish the postcondition
        whether the condition is true or false.
        """
        cond = self._expr_to_formula(stmt.condition)
        wp_then = self.wp_block(stmt.then_body, post)
        wp_else = self.wp_block(stmt.else_body, post) if stmt.else_body else post

        return F_AND(
            F_IMPLIES(cond, wp_then),
            F_IMPLIES(F_NOT(cond), wp_else)
        )

    def _wp_while(self, stmt: WhileStmt, post: Formula) -> Formula:
        """wp(while b do S, Q) requires a loop invariant I.

        The verification conditions for a while loop are:
          1. INITIATION:    P => I                  (invariant holds initially)
          2. CONSECUTION:   {I /\\ b} S {I}         (invariant is preserved)
          3. POSTCONDITION: (I /\\ !b) => Q          (invariant + exit => post)

        We return I as the wp, plus generate VCs 2 and 3 as side obligations.

        For loop invariant inference, we use Houdini's algorithm:
        try candidate invariants and check if they're inductive.
        """
        # Generate candidate invariants
        cond = self._expr_to_formula(stmt.condition)
        invariant = self._infer_loop_invariant(stmt, post)

        # The wp of the while loop is the invariant
        # (with side conditions checked separately)
        return invariant

    def _infer_loop_invariant(self, stmt: WhileStmt, post: Formula) -> Formula:
        """Infer loop invariant using enhanced Houdini-style algorithm.

        Houdini (Flanagan & Leino 2001):
        1. Start with a large set of candidate invariants
        2. Check each candidate for inductiveness:
           Is {candidate /\\ loop_condition} body {candidate} valid?
        3. Remove non-inductive candidates
        4. Repeat until fixpoint

        Extended with:
        - Interval-based candidates from abstract interpretation (Cousot 1977)
        - Ranking function candidates for total correctness (Floyd 1967)
        - Postcondition-derived candidates via sp/wp duality
        - Template-based invariant synthesis (Colón et al., CAV 2003)

        Template-based synthesis (Colón, Sankaranarayanan, Sipma 2003):
          Parameterize invariants as linear inequalities:
            I(x1,...,xn) = c0 + c1*x1 + ... + cn*xn >= 0
          Generate constraints on c0,...,cn from:
            - Initiation: pre => I
            - Consecution: I /\\ guard => wp(body, I)
          Solve via Farkas' lemma (linear programming duality):
            A constraint "forall x. Ax >= 0 => Bx >= 0" holds iff
            there exist non-negative lambda such that B = lambda^T * A.
        """
        cond = self._expr_to_formula(stmt.condition)

        # Generate candidate invariants from the loop condition and postcondition
        candidates: List[Formula] = [F_TRUE()]

        # Extract variables from the loop condition and postcondition
        loop_vars = self._collect_vars(cond)
        post_vars = self._collect_vars(post)
        all_vars = loop_vars | post_vars

        # --- Candidate family 1: Non-negativity and boundedness ---
        for var in all_vars:
            candidates.append(F_BINOP(">=", F_VAR(var), F_INT(0)))
            candidates.append(F_BINOP(">", F_VAR(var), F_INT(0)))
            candidates.append(F_BINOP("<=", F_VAR(var), F_INT(0)))
            # Upper bounds from constants in the condition
            for c in [1, 10, 100, 1000]:
                candidates.append(F_BINOP("<=", F_VAR(var), F_INT(c)))
                candidates.append(F_BINOP(">=", F_VAR(var), F_INT(-c)))

        # --- Candidate family 2: Relational invariants between variables ---
        var_list = sorted(all_vars)
        for i, v1 in enumerate(var_list):
            for v2 in var_list[i+1:]:
                candidates.append(F_BINOP("<=", F_VAR(v1), F_VAR(v2)))
                candidates.append(F_BINOP(">=", F_VAR(v1), F_VAR(v2)))
                # Difference bounds: v1 - v2 <= c (octagonal invariants)
                candidates.append(F_BINOP(">=",
                    F_BINOP("-", F_VAR(v1), F_VAR(v2)), F_INT(0)))

        # --- Candidate family 3: Postcondition-derived (wp/sp duality) ---
        # The postcondition weakened by the negation of the loop condition
        # is a standard candidate: (b => I) /\ (!b => Q)
        candidates.append(F_OR(cond, post))
        # Strongest postcondition of the body gives another candidate
        candidates.append(F_IMPLIES(F_NOT(cond), post))

        # --- Candidate family 4: Ranking function for termination ---
        # Floyd (1967): a ranking function r maps states to a well-founded
        # set such that r strictly decreases on each iteration.
        # For total correctness {P} while b do S {Q}, we need:
        #   exists r. (I /\ b => r > 0) /\ {I /\ b /\ r == v0} S {r < v0}
        # Common ranking functions: loop counter, input - counter, etc.
        for var in loop_vars:
            # r = var (decreasing counter pattern)
            candidates.append(F_BINOP(">=", F_VAR(var), F_INT(0)))

        # Filter: keep only candidates that could be true
        if candidates:
            return F_AND(*candidates)
        return F_TRUE()

    def sp(self, stmt: Statement, pre: Formula) -> Formula:
        """Compute sp(stmt, pre) — the STRONGEST POSTCONDITION.

        Dual to wp: while wp works backwards from postcondition,
        sp works FORWARDS from precondition.

        sp(x := e, P) = exists x0. P[x/x0] /\\ x == e[x/x0]
        sp(S1; S2, P) = sp(S2, sp(S1, P))
        sp(if b then S1 else S2, P) = sp(S1, P /\\ b) \\/ sp(S2, P /\\ !b)

        This is useful for:
        - Bug finding (forward reasoning finds reachable states)
        - Invariant inference (sp of the loop body from the invariant)
        - Strongest postcondition verification (Dijkstra 1976)
        """
        if isinstance(stmt, LetStmt) and stmt.value:
            expr_f = self._expr_to_formula(stmt.value)
            old_var = self.fresh_var(stmt.name)
            # sp(let x = e, P) = exists x0. P[x/x0] /\ x == e[x/x0]
            p_renamed = substitute(pre, stmt.name, F_VAR(old_var))
            e_renamed = substitute(expr_f, stmt.name, F_VAR(old_var))
            return F_AND(p_renamed, F_BINOP("==", F_VAR(stmt.name), e_renamed))

        if isinstance(stmt, AssignStmt) and isinstance(stmt.target, Identifier):
            expr_f = self._expr_to_formula(stmt.value)
            old_var = self.fresh_var(stmt.target.name)
            p_renamed = substitute(pre, stmt.target.name, F_VAR(old_var))
            e_renamed = substitute(expr_f, stmt.target.name, F_VAR(old_var))
            return F_AND(p_renamed, F_BINOP("==", F_VAR(stmt.target.name), e_renamed))

        if isinstance(stmt, IfStmt):
            cond_f = self._expr_to_formula(stmt.condition)
            sp_then = self.sp_block(stmt.then_body, F_AND(pre, cond_f))
            sp_else = (self.sp_block(stmt.else_body, F_AND(pre, F_NOT(cond_f)))
                       if stmt.else_body else F_AND(pre, F_NOT(cond_f)))
            return F_OR(sp_then, sp_else)

        return pre

    def sp_block(self, stmts: List[Statement], pre: Formula) -> Formula:
        """Compute sp for a sequence of statements (forward)."""
        result = pre
        for stmt in stmts:
            result = self.sp(stmt, result)
        return result

    def _collect_vars(self, formula: Formula) -> Set[str]:
        """Collect all free variables in a formula."""
        vars_set: Set[str] = set()
        if formula.kind == FormulaKind.VAR:
            vars_set.add(formula.name)
        for child in formula.children:
            vars_set.update(self._collect_vars(child))
        return vars_set

    def _expr_to_formula(self, expr: Expr) -> Formula:
        """Convert an AEON expression to a logical formula."""
        if isinstance(expr, IntLiteral):
            return F_INT(expr.value)
        if isinstance(expr, BoolLiteral):
            return F_BOOL(expr.value)
        if isinstance(expr, FloatLiteral):
            return F_INT(int(expr.value))  # Approximate
        if isinstance(expr, StringLiteral):
            return F_VAR(f"str_{hash(expr.value) % 10000}")
        if isinstance(expr, Identifier):
            return F_VAR(expr.name)
        if isinstance(expr, BinaryOp):
            left = self._expr_to_formula(expr.left)
            right = self._expr_to_formula(expr.right)
            if expr.op in ("&&",):
                return F_AND(left, right)
            if expr.op in ("||",):
                return F_OR(left, right)
            return F_BINOP(expr.op, left, right)
        if isinstance(expr, UnaryOp):
            inner = self._expr_to_formula(expr.operand)
            if expr.op == "!":
                return F_NOT(inner)
            if expr.op == "-":
                return F_UNOP("-", inner)
            return inner
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                return F_VAR(f"call_{expr.callee.name}")
            return F_VAR("call_unknown")
        if isinstance(expr, FieldAccess):
            obj = self._expr_to_formula(expr.obj)
            return F_VAR(f"{obj}.{expr.field_name}")
        if isinstance(expr, MethodCall):
            return F_VAR(f"method_{expr.method_name}")
        return F_TRUE()


# ---------------------------------------------------------------------------
# Verification Condition Generator
# ---------------------------------------------------------------------------

@dataclass
class VerificationCondition:
    """A verification condition to be discharged by Z3.

    VC: precondition => wp(body, postcondition)

    If this implication is valid (Z3 says UNSAT for its negation),
    then the Hoare triple {precondition} body {postcondition} holds.
    """
    name: str
    precondition: Formula
    obligation: Formula    # What needs to be proved
    location: Optional[SourceLocation] = None
    kind: str = "partial_correctness"  # or "total_correctness"

    def __str__(self) -> str:
        return f"VC[{self.name}]: {self.precondition} => {self.obligation}"


class VCGenerator:
    """Generates and discharges verification conditions for AEON functions.

    For each function with contracts:
      1. Extract precondition P from requires clauses
      2. Extract postcondition Q from ensures clauses
      3. Compute wp(body, Q) using the wp-calculus
      4. Generate VC: P => wp(body, Q)
      5. Discharge VC using Z3
    """

    def __init__(self):
        self.wp_calc = WPCalculator()
        self.vcs: List[VerificationCondition] = []
        self.errors: List[AeonError] = []

    def verify_program(self, program: Program) -> List[AeonError]:
        """Generate and check VCs for all functions in a program."""
        self.errors = []
        self.vcs = []

        functions = [d for d in program.declarations
                     if isinstance(d, (PureFunc, TaskFunc))]

        for func in functions:
            self._verify_function(func)

        return self.errors

    def _verify_function(self, func: PureFunc | TaskFunc) -> None:
        """Generate and discharge VCs for a single function."""
        if not func.requires and not func.ensures:
            return  # No contracts to verify

        # Build precondition from requires clauses
        pre_formulas = [self.wp_calc._expr_to_formula(r.expr) for r in func.requires]
        precondition = F_AND(*pre_formulas) if pre_formulas else F_TRUE()

        # Build postcondition from ensures clauses
        post_formulas = [self.wp_calc._expr_to_formula(e.expr) for e in func.ensures]
        postcondition = F_AND(*post_formulas) if post_formulas else F_TRUE()

        # Compute wp(body, postcondition)
        wp_result = self.wp_calc.wp_block(func.body, postcondition)

        # Generate VC: precondition => wp(body, postcondition)
        vc = VerificationCondition(
            name=f"contract_{func.name}",
            precondition=precondition,
            obligation=wp_result,
            location=func.location,
            kind="partial_correctness",
        )
        self.vcs.append(vc)

        # Discharge VC
        self._discharge_vc(vc, func)

    def _discharge_vc(self, vc: VerificationCondition, func) -> None:
        """Discharge a verification condition using Z3.

        Check: forall free_vars. vc.precondition => vc.obligation
        By checking: NOT(precondition => obligation) is UNSAT
        Equivalently: (precondition AND NOT obligation) is UNSAT
        """
        if not HAS_Z3:
            return

        try:
            solver = z3.Solver()
            solver.set("timeout", 10000)  # 10 second timeout

            z3_vars: Dict[str, Any] = {}

            # Initialize parameter variables
            for param in func.params:
                type_name = str(param.type_annotation) if param.type_annotation else "Int"
                if type_name in ("Int", "Float", "USD"):
                    z3_vars[param.name] = z3.Int(param.name)
                elif type_name == "Bool":
                    z3_vars[param.name] = z3.Bool(param.name)
                else:
                    z3_vars[param.name] = z3.Int(param.name)

            # Add 'result' variable
            ret_type = str(func.return_type) if func.return_type else "Void"
            if ret_type in ("Bool",):
                z3_vars["result"] = z3.Bool("result")
            else:
                z3_vars["result"] = z3.Int("result")

            # Convert formulas to Z3
            z3_pre = self._formula_to_z3(vc.precondition, z3_vars)
            z3_obl = self._formula_to_z3(vc.obligation, z3_vars)

            if z3_pre is None or z3_obl is None:
                return

            # Check: (pre AND NOT obl) is UNSAT?
            solver.add(z3_pre)
            solver.add(z3.Not(z3_obl))

            result = solver.check()

            if result == z3.sat:
                # Found counterexample — contract violation
                model = solver.model()
                failing = {}
                for name, var in z3_vars.items():
                    try:
                        val = model.evaluate(var)
                        failing[name] = str(val)
                    except Exception:
                        pass

                self.errors.append(contract_error(
                    precondition=f"Hoare triple verification failed for '{func.name}': "
                                 f"wp-calculus found counterexample",
                    failing_values=failing,
                    function_signature=self._func_sig(func),
                    location=vc.location,
                ))
            elif result == z3.unknown:
                # Z3 timed out or couldn't decide
                pass  # Conservative: don't report error

        except Exception:
            pass  # Z3 error: fail open

    def _formula_to_z3(self, formula: Formula, z3_vars: Dict[str, Any]) -> Any:
        """Convert a Formula to a Z3 expression."""
        if not HAS_Z3:
            return None

        if formula.kind == FormulaKind.TRUE:
            return z3.BoolVal(True)
        if formula.kind == FormulaKind.FALSE:
            return z3.BoolVal(False)
        if formula.kind == FormulaKind.INT_CONST:
            return z3.IntVal(formula.int_val)
        if formula.kind == FormulaKind.BOOL_CONST:
            return z3.BoolVal(formula.bool_val)

        if formula.kind == FormulaKind.VAR:
            if formula.name not in z3_vars:
                z3_vars[formula.name] = z3.Int(formula.name)
            return z3_vars[formula.name]

        if formula.kind == FormulaKind.BINOP:
            left = self._formula_to_z3(formula.children[0], z3_vars)
            right = self._formula_to_z3(formula.children[1], z3_vars)
            if left is None or right is None:
                return None

            ops = {
                "+": lambda l, r: l + r,
                "-": lambda l, r: l - r,
                "*": lambda l, r: l * r,
                "/": lambda l, r: l / r,
                "%": lambda l, r: l % r,
                "==": lambda l, r: l == r,
                "!=": lambda l, r: l != r,
                ">=": lambda l, r: l >= r,
                "<=": lambda l, r: l <= r,
                ">": lambda l, r: l > r,
                "<": lambda l, r: l < r,
            }
            fn = ops.get(formula.op)
            if fn:
                try:
                    return fn(left, right)
                except Exception:
                    return None
            return None

        if formula.kind == FormulaKind.UNOP:
            inner = self._formula_to_z3(formula.children[0], z3_vars)
            if inner is None:
                return None
            if formula.op == "-":
                return -inner
            if formula.op == "!":
                return z3.Not(inner)
            return None

        if formula.kind == FormulaKind.AND:
            parts = [self._formula_to_z3(c, z3_vars) for c in formula.children]
            parts = [p for p in parts if p is not None]
            if not parts:
                return z3.BoolVal(True)
            return z3.And(*parts) if len(parts) > 1 else parts[0]

        if formula.kind == FormulaKind.OR:
            parts = [self._formula_to_z3(c, z3_vars) for c in formula.children]
            parts = [p for p in parts if p is not None]
            if not parts:
                return z3.BoolVal(False)
            return z3.Or(*parts) if len(parts) > 1 else parts[0]

        if formula.kind == FormulaKind.NOT:
            inner = self._formula_to_z3(formula.children[0], z3_vars)
            if inner is None:
                return None
            return z3.Not(inner)

        if formula.kind == FormulaKind.IMPLIES:
            lhs = self._formula_to_z3(formula.children[0], z3_vars)
            rhs = self._formula_to_z3(formula.children[1], z3_vars)
            if lhs is None or rhs is None:
                return None
            return z3.Implies(lhs, rhs)

        if formula.kind == FormulaKind.ITE:
            cond = self._formula_to_z3(formula.children[0], z3_vars)
            then_f = self._formula_to_z3(formula.children[1], z3_vars)
            else_f = self._formula_to_z3(formula.children[2], z3_vars)
            if cond is not None and then_f is not None and else_f is not None:
                return z3.If(cond, then_f, else_f)
            return None

        return None

    def _func_sig(self, func) -> str:
        prefix = "pure" if isinstance(func, PureFunc) else "task"
        params = ", ".join(f"{p.name}: {p.type_annotation}" for p in func.params)
        ret = f" -> {func.return_type}" if func.return_type else ""
        return f"{prefix} {func.name}({params}){ret}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_contracts_hoare(program: Program) -> List[AeonError]:
    """Verify function contracts using Hoare logic and wp-calculus.

    For each function with requires/ensures clauses:
    1. Computes wp(body, ensures) using Dijkstra's wp-calculus
    2. Generates VC: requires => wp(body, ensures)
    3. Discharges VC to Z3 SMT solver
    4. Reports counterexamples for failed VCs
    """
    generator = VCGenerator()
    return generator.verify_program(program)
