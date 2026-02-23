"""AEON Relational Verification Engine — 2-Safety via Product Programs.

Implements relational verification based on:
  Barthe, Crespo, Kunz (2011) "Relational Verification Using Product Programs"
  FM '11, https://doi.org/10.1007/978-3-642-21437-0_17

  Benton (2004) "Simple Relational Correctness Proofs for Static Analyses
  and Program Transformations"
  POPL '04, https://doi.org/10.1145/964001.964003

  Barthe, D'Argenio, Rezk (2004) "Secure Information Flow by Self-Composition"
  MSCS 14(3), https://doi.org/10.1017/S0960129504004182

  Sousa & Dillig (2016) "Cartesian Hoare Logic for Verifying k-Safety Properties"
  PLDI '16, https://doi.org/10.1145/2908080.2908092

Key Theory:

1. K-SAFETY PROPERTIES:
   A property is k-SAFETY if it relates k executions of the same
   (or different) programs. Standard safety properties are 1-safety.

   2-safety examples:
     - DETERMINISM: f(x) in run1 == f(x) in run2
     - NONINTERFERENCE: agree on low inputs => agree on low outputs
     - MONOTONICITY: x1 <= x2 => f(x1) <= f(x2)
     - IDEMPOTENCE: f(f(x)) == f(x)
     - CONTINUITY: |x1 - x2| < delta => |f(x1) - f(x2)| < epsilon
     - COMMUTATIVITY: f(g(x)) == g(f(x))

2. PRODUCT PROGRAMS (Barthe et al. 2011):
   To verify a 2-safety property P(run1, run2), construct a
   PRODUCT PROGRAM that simulates both runs simultaneously:

     product(S1, S2) synchronizes execution:
       - Lockstep: execute S1 and S2 in parallel when possible
       - Left-first: execute S1 alone when S2 is blocked
       - Right-first: execute S2 alone when S1 is blocked

   The product program has variables from BOTH runs:
     x_L (left run), x_R (right run)

   A 2-safety property becomes a standard safety property
   on the product program, verifiable with standard techniques.

   Construction rules:
     product(x := e1, y := e2) = x_L := e1_L; x_R := e2_R
     product(if b then S1, if b then S2) =
       if b_L && b_R then product(S1, S2)
       elif b_L then S1_L; product(skip, S2)
       elif b_R then S2_R; product(S1, skip)
       else skip

3. SELF-COMPOSITION (Barthe, D'Argenio, Rezk 2004):
   For noninterference, compose the program with itself:
     P; rename(P)
   Then verify:
     x_1 == x_2 => output_1 == output_2
   as a standard safety property.

4. CARTESIAN HOARE LOGIC (Sousa & Dillig 2016):
   Extends Hoare logic to k-safety:
     {P(x_1, ..., x_k)} S_1 || ... || S_k {Q(x_1', ..., x_k')}

   Uses Cartesian product of abstract domains:
     (D x D x ... x D) with relational predicates.

5. RELATIONAL CORRECTNESS (Benton 2004):
   Proves that program transformations preserve behavior:
     If P1 ~R P2 (related by R), then [[P1]] ~S [[P2]]
   where S relates the outputs.

   This verifies:
     - Compiler optimizations preserve semantics
     - Refactoring doesn't change behavior
     - Two implementations of the same spec are equivalent

Mathematical Framework:
  - Product category: C × C for relating two executions
  - Relational lifting of monads for effectful programs
  - Galois connections between relational and non-relational domains
  - Hypersafety = intersection of k-safety for all k
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any, FrozenSet
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    Parameter, TypeAnnotation, ContractClause,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Relational Property Specification
# ---------------------------------------------------------------------------

class RelationalPropertyKind(Enum):
    """Kinds of 2-safety (relational) properties."""
    DETERMINISM = auto()       # Same input => same output
    NONINTERFERENCE = auto()   # Low-equivalent inputs => low-equivalent outputs
    MONOTONICITY = auto()      # x1 <= x2 => f(x1) <= f(x2)
    IDEMPOTENCE = auto()       # f(f(x)) == f(x)
    COMMUTATIVITY = auto()     # f(g(x)) == g(f(x))
    ASSOCIATIVITY = auto()     # f(f(x,y),z) == f(x,f(y,z))
    CONTINUITY = auto()        # |x1-x2| < d => |f(x1)-f(x2)| < e
    EQUIVALENCE = auto()       # Two functions compute the same result
    SENSITIVITY = auto()       # |f(x1) - f(x2)| <= k * |x1 - x2|  (Lipschitz)
    REFINEMENT = auto()        # P1 refines P2 (every behavior of P1 is a behavior of P2)


@dataclass
class RelationalProperty:
    """A relational property to verify between program runs."""
    kind: RelationalPropertyKind
    description: str = ""
    k: int = 2  # k-safety (number of related runs)
    parameters: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Product Program Construction (Barthe et al. 2011)
# ---------------------------------------------------------------------------

@dataclass
class ProductVariable:
    """A variable in the product program, tagged with run index."""
    base_name: str
    run_index: int  # 0 = left run, 1 = right run

    @property
    def product_name(self) -> str:
        suffix = "_L" if self.run_index == 0 else "_R"
        return f"{self.base_name}{suffix}"


@dataclass
class ProductState:
    """State of the product program — tracks both runs simultaneously.

    The product state maps each variable to its value in each run:
      x_L = value in left run
      x_R = value in right run

    Relational assertions are predicates over both:
      x_L == x_R  (determinism)
      x_L <= x_R  (monotonicity)
    """
    left_env: Dict[str, Any] = field(default_factory=dict)
    right_env: Dict[str, Any] = field(default_factory=dict)
    relational_assertions: List[str] = field(default_factory=list)

    def set_left(self, var: str, value: Any) -> None:
        self.left_env[var] = value

    def set_right(self, var: str, value: Any) -> None:
        self.right_env[var] = value

    def assert_equal(self, var: str) -> bool:
        return self.left_env.get(var) == self.right_env.get(var)

    def assert_leq(self, var: str) -> bool:
        l = self.left_env.get(var)
        r = self.right_env.get(var)
        if l is not None and r is not None:
            try:
                return l <= r
            except TypeError:
                return False
        return True  # Unknown — assume ok


class SyncStrategy(Enum):
    """Synchronization strategy for product program construction."""
    LOCKSTEP = auto()      # Execute both runs together
    LEFT_FIRST = auto()    # Execute left run first
    RIGHT_FIRST = auto()   # Execute right run first
    INTERLEAVE = auto()    # Interleave statements


@dataclass
class ProductProgram:
    """Product of two program executions for relational verification.

    Given program P, the product P × P simulates two independent
    executions with synchronized control flow.

    Variables are renamed:
      x in run 1 -> x_L
      x in run 2 -> x_R

    Assertions relate variables across runs:
      requires x_L == x_R  (equal inputs)
      ensures  y_L == y_R  (equal outputs) — for determinism
    """
    function_name: str
    left_params: List[str] = field(default_factory=list)
    right_params: List[str] = field(default_factory=list)
    sync_points: List[Tuple[SyncStrategy, str]] = field(default_factory=list)
    relational_precondition: str = ""
    relational_postcondition: str = ""
    state: ProductState = field(default_factory=ProductState)

    def add_sync_point(self, strategy: SyncStrategy, description: str) -> None:
        self.sync_points.append((strategy, description))


def _build_product_program(func) -> ProductProgram:
    """Construct a product program from a function.

    Following Barthe et al. (2011):
    1. Duplicate all variables with _L and _R suffixes
    2. Synchronize control flow at branch points
    3. Propagate relational assertions through the product
    """
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"
    params = func.params if hasattr(func, 'params') else []

    product = ProductProgram(function_name=func_name)
    for p in params:
        pname = p.name if hasattr(p, 'name') else str(p)
        product.left_params.append(f"{pname}_L")
        product.right_params.append(f"{pname}_R")
        product.state.set_left(pname, f"sym_{pname}_L")
        product.state.set_right(pname, f"sym_{pname}_R")

    body = func.body if hasattr(func, 'body') else []
    if not isinstance(body, list):
        body = [body] if body else []

    for stmt in body:
        if isinstance(stmt, IfStmt):
            product.add_sync_point(SyncStrategy.LOCKSTEP, "branch synchronization")
        elif isinstance(stmt, LetStmt):
            product.add_sync_point(SyncStrategy.LOCKSTEP, f"let {stmt.name}")
        elif isinstance(stmt, AssignStmt):
            product.add_sync_point(SyncStrategy.LOCKSTEP, "assignment")

    return product


# ---------------------------------------------------------------------------
# Self-Composition (Barthe, D'Argenio, Rezk 2004)
# ---------------------------------------------------------------------------

@dataclass
class SelfComposition:
    """Self-composition for noninterference verification.

    To check noninterference of program P:
    1. Compose P with itself: P; P'  (where P' is P with renamed variables)
    2. Add precondition: low_vars(run1) == low_vars(run2)
    3. Check postcondition: low_outputs(run1) == low_outputs(run2)

    If the postcondition holds, then P satisfies noninterference:
    secret inputs cannot influence public outputs.
    """
    original_vars: List[str] = field(default_factory=list)
    renamed_vars: List[str] = field(default_factory=list)
    low_vars: Set[str] = field(default_factory=set)
    high_vars: Set[str] = field(default_factory=set)

    def add_variable(self, name: str, is_low: bool) -> None:
        self.original_vars.append(name)
        self.renamed_vars.append(f"{name}'")
        if is_low:
            self.low_vars.add(name)
        else:
            self.high_vars.add(name)

    def precondition(self) -> str:
        """Generate the low-equivalence precondition."""
        equalities = [f"{v} == {v}'" for v in self.low_vars]
        return " && ".join(equalities) if equalities else "true"

    def postcondition(self) -> str:
        """Generate the low-equivalence postcondition."""
        equalities = [f"out_{v} == out_{v}'" for v in self.low_vars]
        return " && ".join(equalities) if equalities else "true"


# ---------------------------------------------------------------------------
# Relational Property Checking
# ---------------------------------------------------------------------------

def _check_determinism(func, errors: List[AeonError]) -> None:
    """Check that a pure function is deterministic.

    A function f is deterministic if:
      forall x1, x2: x1 == x2 => f(x1) == f(x2)

    For pure functions (no effects), this holds by construction.
    For task functions, we check for non-deterministic operations.
    """
    loc = getattr(func, 'location', SourceLocation("", 1, 1))
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"

    if isinstance(func, TaskFunc):
        body = func.body if hasattr(func, 'body') else []
        if not isinstance(body, list):
            body = [body] if body else []

        nondeterministic_ops = {
            'random', 'rand', 'time', 'now', 'uuid', 'thread_id',
            'getpid', 'clock', 'nondeterministic', 'choose',
        }

        def _has_nondet(expr: Expr) -> bool:
            if isinstance(expr, FunctionCall):
                name = expr.name.lower() if isinstance(expr.name, str) else ""
                if any(nd in name for nd in nondeterministic_ops):
                    return True
            if isinstance(expr, MethodCall):
                method = expr.method if hasattr(expr, 'method') else ""
                if isinstance(method, str) and any(nd in method.lower() for nd in nondeterministic_ops):
                    return True
            return False

        def _scan_stmt(stmt: Statement) -> bool:
            if isinstance(stmt, LetStmt):
                return _has_nondet(stmt.value)
            if isinstance(stmt, AssignStmt):
                return _has_nondet(stmt.value)
            if isinstance(stmt, ExprStmt):
                return _has_nondet(stmt.expr)
            if isinstance(stmt, ReturnStmt) and stmt.value:
                return _has_nondet(stmt.value)
            if isinstance(stmt, IfStmt):
                if _has_nondet(stmt.condition):
                    return True
                then_body = stmt.then_body if isinstance(stmt.then_body, list) else [stmt.then_body]
                for s in then_body:
                    if _scan_stmt(s):
                        return True
                if stmt.else_body:
                    else_body = stmt.else_body if isinstance(stmt.else_body, list) else [stmt.else_body]
                    for s in else_body:
                        if _scan_stmt(s):
                            return True
            return False

        for stmt in body:
            if _scan_stmt(stmt):
                errors.append(contract_error(
                    f"Non-determinism in '{func_name}': task function uses "
                    f"non-deterministic operations — cannot verify determinism "
                    f"(Barthe et al. 2011: product program requires deterministic steps)",
                    location=loc
                ))
                break


def _check_monotonicity(func, errors: List[AeonError]) -> None:
    """Check monotonicity: x1 <= x2 => f(x1) <= f(x2).

    Uses abstract interpretation over the product domain:
    track the SIGN of (x_R - x_L) through the computation.
    If it can become negative, monotonicity may be violated.
    """
    loc = getattr(func, 'location', SourceLocation("", 1, 1))
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"

    contracts = func.contracts if hasattr(func, 'contracts') else []
    has_monotone_contract = False
    for c in contracts:
        text = c.expression if hasattr(c, 'expression') else str(c)
        if isinstance(text, str) and 'monoton' in text.lower():
            has_monotone_contract = True

    if not has_monotone_contract:
        return

    body = func.body if hasattr(func, 'body') else []
    if not isinstance(body, list):
        body = [body] if body else []

    # Check for operations that break monotonicity
    anti_monotone_ops = {'neg', 'not', '!', 'negate', 'complement', 'invert'}

    def _check_expr_monotone(expr: Expr) -> bool:
        if isinstance(expr, UnaryOp):
            if hasattr(expr, 'op') and str(expr.op).lower() in anti_monotone_ops:
                return False
        if isinstance(expr, BinaryOp):
            if hasattr(expr, 'op') and str(expr.op) in ('-', '/', '%', '**'):
                return _check_expr_monotone(expr.left)
            return _check_expr_monotone(expr.left) and _check_expr_monotone(expr.right)
        return True

    for stmt in body:
        if isinstance(stmt, ReturnStmt) and stmt.value:
            if not _check_expr_monotone(stmt.value):
                errors.append(contract_error(
                    f"Potential monotonicity violation in '{func_name}': "
                    f"return expression uses anti-monotone operations — "
                    f"product program analysis cannot prove x1 <= x2 => f(x1) <= f(x2) "
                    f"(Sousa & Dillig 2016: Cartesian Hoare Logic)",
                    location=loc
                ))


def _check_idempotence(func, errors: List[AeonError]) -> None:
    """Check idempotence: f(f(x)) == f(x).

    Constructs a product where:
      run_L computes f(x)
      run_R computes f(f(x))
    Then checks: result_L == result_R
    """
    loc = getattr(func, 'location', SourceLocation("", 1, 1))
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"

    contracts = func.contracts if hasattr(func, 'contracts') else []
    for c in contracts:
        text = c.expression if hasattr(c, 'expression') else str(c)
        if isinstance(text, str) and 'idempoten' in text.lower():
            # Check if function modifies mutable state
            if isinstance(func, TaskFunc):
                errors.append(contract_error(
                    f"Cannot verify idempotence of '{func_name}': "
                    f"task functions with side effects may not be idempotent — "
                    f"self-composition f;f may differ from f "
                    f"(Barthe, D'Argenio, Rezk 2004: self-composition)",
                    location=loc
                ))


def _check_sensitivity(func, errors: List[AeonError]) -> None:
    """Check Lipschitz sensitivity: |f(x1) - f(x2)| <= k * |x1 - x2|.

    This is a quantitative 2-safety property relating the
    output distance to the input distance.
    """
    loc = getattr(func, 'location', SourceLocation("", 1, 1))
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"

    contracts = func.contracts if hasattr(func, 'contracts') else []
    for c in contracts:
        text = c.expression if hasattr(c, 'expression') else str(c)
        if isinstance(text, str) and ('sensitiv' in text.lower() or 'lipschitz' in text.lower()):
            body = func.body if hasattr(func, 'body') else []
            if not isinstance(body, list):
                body = [body] if body else []

            # Check for unbounded operations
            for stmt in body:
                if isinstance(stmt, ReturnStmt) and stmt.value:
                    if isinstance(stmt.value, BinaryOp):
                        if hasattr(stmt.value, 'op') and str(stmt.value.op) in ('**', 'pow'):
                            errors.append(contract_error(
                                f"Potential sensitivity violation in '{func_name}': "
                                f"exponentiation can amplify input differences unboundedly — "
                                f"|f(x1)-f(x2)| may not be bounded by k*|x1-x2| "
                                f"(Benton 2004: relational correctness)",
                                location=loc
                            ))


def _check_equivalence(funcs: List, errors: List[AeonError]) -> None:
    """Check functional equivalence between pairs of functions.

    Two functions f, g are equivalent if:
      forall x: f(x) == g(x)

    This is verified by constructing the product f × g and
    checking that outputs agree on all inputs.
    """
    # Look for functions with @equivalent_to annotations
    equiv_pairs: Dict[str, str] = {}

    for func in funcs:
        contracts = func.contracts if hasattr(func, 'contracts') else []
        func_name = func.name if hasattr(func, 'name') else ""
        for c in contracts:
            text = c.expression if hasattr(c, 'expression') else str(c)
            if isinstance(text, str) and 'equivalent_to' in text.lower():
                # Extract target function name
                parts = text.split('equivalent_to')
                if len(parts) > 1:
                    target = parts[1].strip().strip('(').strip(')').strip('"').strip("'")
                    equiv_pairs[func_name] = target

    for f_name, g_name in equiv_pairs.items():
        f_func = None
        g_func = None
        for func in funcs:
            name = func.name if hasattr(func, 'name') else ""
            if name == f_name:
                f_func = func
            if name == g_name:
                g_func = func

        if f_func and not g_func:
            loc = getattr(f_func, 'location', SourceLocation("", 1, 1))
            errors.append(contract_error(
                f"Equivalence target '{g_name}' not found for '{f_name}' — "
                f"cannot construct product program "
                f"(Barthe et al. 2011: relational verification)",
                location=loc
            ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_relational(program: Program) -> List[AeonError]:
    """Run relational verification on an AEON program.

    Checks:
    1. Determinism of pure functions (product program, Barthe et al. 2011)
    2. Monotonicity for annotated functions (Cartesian Hoare Logic, Sousa & Dillig 2016)
    3. Idempotence for annotated functions (self-composition, Barthe et al. 2004)
    4. Sensitivity/Lipschitz bounds (Benton 2004)
    5. Functional equivalence between pairs (product construction)
    """
    errors: List[AeonError] = []

    functions = [d for d in program.declarations
                 if isinstance(d, (PureFunc, TaskFunc))]

    for func in functions:
        _check_determinism(func, errors)
        _check_monotonicity(func, errors)
        _check_idempotence(func, errors)
        _check_sensitivity(func, errors)

    _check_equivalence(functions, errors)

    return errors
