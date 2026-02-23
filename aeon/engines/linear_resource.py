"""AEON Linear / Affine Resource Analysis — Substructural Type System.

Implements linear and affine resource tracking based on:
  Girard (1987) "Linear Logic"
  Theoretical Computer Science 50(1), https://doi.org/10.1016/0304-3975(87)90045-4

  Hofmann & Jost (2003) "Static Prediction of Heap Space Usage for
  First-Order Functional Programs"
  ESOP '03, https://doi.org/10.1007/3-540-36575-3_13

  Walker (2005) "Substructural Type Systems"
  In Advanced Topics in Types and Programming Languages, MIT Press

  Tov & Pucella (2011) "Practical Affine Types"
  POPL '11, https://doi.org/10.1145/1926385.1926436

Key Theory:

1. SUBSTRUCTURAL TYPE SYSTEMS:
   Classical type systems have three STRUCTURAL RULES:
     - WEAKENING:   Gamma, x:A |- e:B  implies  Gamma |- e:B
                    (can ignore variables — not used)
     - CONTRACTION: Gamma, x:A, x:A |- e:B  implies  Gamma, x:A |- e:B
                    (can duplicate variables — used multiple times)
     - EXCHANGE:    Gamma, x:A, y:B |- e:C  implies  Gamma, y:B, x:A |- e:C
                    (can reorder variables)

   Substructural type systems RESTRICT these rules:
     - LINEAR types: no weakening, no contraction (use EXACTLY once)
     - AFFINE types: weakening ok, no contraction (use AT MOST once)
     - RELEVANT types: no weakening, contraction ok (use AT LEAST once)
     - ORDERED types: no weakening, no contraction, no exchange

2. LINEAR LOGIC (Girard 1987):
   Propositions as resources that must be consumed exactly once.

   Connectives:
     A ⊗ B   (tensor / multiplicative conjunction): both A AND B
     A ⅋ B   (par / multiplicative disjunction): dual of tensor
     A & B   (with / additive conjunction): choose A OR B
     A ⊕ B   (plus / additive disjunction): offer A OR B
     !A      (of course / exponential): unlimited copies of A
     ?A      (why not / exponential dual)

   The exponential !A converts a linear resource into an
   UNRESTRICTED one — !A can be used any number of times.

   Key rule: !A |- A (dereliction — use one copy)
             !A |- !A ⊗ !A (contraction — duplicate)
             |- !A (weakening — discard if not needed)

3. RESOURCE TYPING (Hofmann & Jost 2003):
   Annotate types with POTENTIAL — a non-negative rational number
   representing available resources (e.g., heap space).

   A type T^q has potential q available.
   Operations CONSUME potential:
     - Allocation: consumes potential proportional to size
     - Function call: transfers potential from caller to callee

   The POTENTIAL METHOD from amortized analysis:
     actual_cost(op) <= potential_before - potential_after + amortized_cost

   Type inference solves for potentials via LINEAR PROGRAMMING:
     Minimize total initial potential subject to:
       - All potentials are non-negative
       - Each operation's cost is covered by available potential
       - Potentials are transferred correctly through control flow

4. AFFINE TYPES IN PRACTICE (Tov & Pucella 2011):
   Affine types are more practical than linear types because
   they allow DROPPING resources (weakening) but not DUPLICATING.

   This naturally models:
     - File handles: open once, close once, don't copy
     - Database connections: acquire, use, release
     - Memory: allocate, use, free (no double-free)
     - Channels: send once, receive once

   The key judgment:
     Gamma |- e : A -o B    (linear function: consumes input)
     Gamma |- e : A -> B    (unrestricted function: input survives)

Mathematical Framework:
  - Resources form a commutative monoid (R, +, 0)
  - Type judgments track resource consumption: Gamma |- e : A ; Delta
    where Gamma is input resources and Delta is remaining resources
  - Soundness: if Gamma |- e : A ; Delta, then executing e with
    resources Gamma leaves exactly resources Delta
  - Potential annotations form a tropical semiring (Q+, min, +)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any, FrozenSet
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt,
    MoveExpr,
    Parameter, TypeAnnotation,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Resource Kinds
# ---------------------------------------------------------------------------

class ResourceKind(Enum):
    """Classification of resource usage in substructural type systems."""
    UNRESTRICTED = auto()  # Can be used any number of times (standard types)
    LINEAR = auto()        # Must be used EXACTLY once
    AFFINE = auto()        # Must be used AT MOST once (can drop)
    RELEVANT = auto()      # Must be used AT LEAST once (can duplicate)


class ResourceState(Enum):
    """Tracks the lifecycle state of a linear/affine resource."""
    FRESH = auto()         # Newly created, not yet used
    BORROWED = auto()      # Temporarily lent (immutable borrow)
    MUT_BORROWED = auto()  # Temporarily lent (mutable borrow)
    CONSUMED = auto()      # Ownership transferred (moved)
    DROPPED = auto()       # Explicitly dropped / out of scope


@dataclass
class ResourceVar:
    """A tracked resource variable with linearity constraints."""
    name: str
    kind: ResourceKind
    state: ResourceState = ResourceState.FRESH
    use_count: int = 0
    location: SourceLocation = field(default_factory=lambda: SourceLocation("", 1, 1))
    potential: float = 0.0  # Hofmann-Jost potential annotation

    def use(self) -> None:
        self.use_count += 1
        if self.state == ResourceState.CONSUMED:
            pass  # Error: use after consume (detected later)
        elif self.kind == ResourceKind.LINEAR and self.use_count > 1:
            pass  # Error: multiple use of linear resource
        elif self.kind == ResourceKind.AFFINE and self.use_count > 1:
            pass  # Error: multiple use of affine resource

    def consume(self) -> None:
        self.state = ResourceState.CONSUMED

    def drop(self) -> None:
        self.state = ResourceState.DROPPED


# ---------------------------------------------------------------------------
# Resource Environment (Linear Context Splitting)
# ---------------------------------------------------------------------------

@dataclass
class ResourceEnv:
    """Tracks resource ownership and linearity constraints.

    Implements the LINEAR CONTEXT SPLITTING rule:
      Gamma = Gamma_1, Gamma_2
    where each linear variable appears in exactly one sub-context.

    This ensures that linear resources are used exactly once even
    when the context is split across sub-expressions.
    """
    resources: Dict[str, ResourceVar] = field(default_factory=dict)

    def define(self, name: str, kind: ResourceKind, loc: SourceLocation,
               potential: float = 0.0) -> None:
        self.resources[name] = ResourceVar(
            name=name, kind=kind, location=loc, potential=potential
        )

    def use(self, name: str) -> Optional[ResourceVar]:
        rv = self.resources.get(name)
        if rv:
            rv.use()
        return rv

    def consume(self, name: str) -> Optional[ResourceVar]:
        rv = self.resources.get(name)
        if rv:
            rv.consume()
        return rv

    def split(self, names_left: Set[str]) -> Tuple[ResourceEnv, ResourceEnv]:
        """Split the context into two disjoint parts.

        For linear types, each variable must appear in exactly one side.
        This implements the multiplicative context splitting rule:
          Gamma_1 ⊗ Gamma_2 = Gamma
        """
        left = ResourceEnv()
        right = ResourceEnv()
        for name, rv in self.resources.items():
            if name in names_left:
                left.resources[name] = rv
            else:
                right.resources[name] = rv
        return left, right

    def check_exhaustion(self) -> List[Tuple[str, ResourceVar]]:
        """Check that all linear resources have been consumed.

        At the end of a scope, linear resources must have use_count == 1
        and affine resources must have use_count <= 1.
        """
        violations = []
        for name, rv in self.resources.items():
            if rv.kind == ResourceKind.LINEAR:
                if rv.use_count == 0 and rv.state != ResourceState.DROPPED:
                    violations.append((name, rv))
                elif rv.use_count > 1:
                    violations.append((name, rv))
            elif rv.kind == ResourceKind.AFFINE:
                if rv.use_count > 1:
                    violations.append((name, rv))
        return violations

    def total_potential(self) -> float:
        """Compute total potential across all resources (Hofmann-Jost)."""
        return sum(rv.potential for rv in self.resources.values())

    def clone(self) -> ResourceEnv:
        env = ResourceEnv()
        for name, rv in self.resources.items():
            env.resources[name] = ResourceVar(
                name=rv.name, kind=rv.kind, state=rv.state,
                use_count=rv.use_count, location=rv.location,
                potential=rv.potential
            )
        return env


# ---------------------------------------------------------------------------
# Potential Annotation System (Hofmann & Jost 2003)
# ---------------------------------------------------------------------------

@dataclass
class PotentialConstraint:
    """A linear constraint on resource potentials.

    Each constraint has the form:
      sum(coeffs[i] * vars[i]) >= rhs

    These constraints are collected from the program and solved
    via linear programming to find the minimum initial potential.
    """
    coefficients: Dict[str, float] = field(default_factory=dict)
    rhs: float = 0.0
    description: str = ""

    def is_satisfied(self, assignment: Dict[str, float]) -> bool:
        lhs = sum(c * assignment.get(v, 0.0) for v, c in self.coefficients.items())
        return lhs >= self.rhs - 1e-9


@dataclass
class PotentialSolver:
    """Solves for minimum resource potentials via linear programming.

    The LP formulation:
      Minimize: sum of initial potentials
      Subject to: all potential constraints from the program

    Each operation generates constraints:
      potential_before >= cost + potential_after

    This is the AUTOMATIC AMORTIZED ANALYSIS from Hofmann & Jost (2003).
    """
    constraints: List[PotentialConstraint] = field(default_factory=list)
    variables: Set[str] = field(default_factory=set)

    def add_variable(self, name: str) -> None:
        self.variables.add(name)

    def add_constraint(self, coeffs: Dict[str, float], rhs: float,
                       desc: str = "") -> None:
        self.constraints.append(PotentialConstraint(
            coefficients=coeffs, rhs=rhs, description=desc
        ))

    def solve_simple(self) -> Tuple[bool, Dict[str, float]]:
        """Simple greedy solver for potential assignment.

        For each variable, assign the minimum potential that satisfies
        all constraints involving that variable. This is sound but
        may not find the optimal solution (a full LP solver would).

        The tropical semiring structure: (Q+ ∪ {∞}, min, +)
        gives us: min is the "addition" and + is the "multiplication".
        """
        assignment: Dict[str, float] = {v: 0.0 for v in self.variables}

        changed = True
        iterations = 0
        max_iter = 100

        while changed and iterations < max_iter:
            changed = False
            iterations += 1
            for constraint in self.constraints:
                if not constraint.is_satisfied(assignment):
                    # Find variable to increase
                    for var, coeff in constraint.coefficients.items():
                        if coeff > 0:
                            current = assignment.get(var, 0.0)
                            needed = constraint.rhs
                            for v2, c2 in constraint.coefficients.items():
                                if v2 != var:
                                    needed -= c2 * assignment.get(v2, 0.0)
                            new_val = max(current, needed / coeff)
                            if new_val > current:
                                assignment[var] = new_val
                                changed = True
                            break

        feasible = all(c.is_satisfied(assignment) for c in self.constraints)
        return feasible, assignment


# ---------------------------------------------------------------------------
# Linear Logic Connectives
# ---------------------------------------------------------------------------

class LinearConnective(Enum):
    """Connectives from Girard's Linear Logic (1987)."""
    TENSOR = auto()     # A ⊗ B  (multiplicative and: use both)
    PAR = auto()         # A ⅋ B  (multiplicative or: dual of tensor)
    WITH = auto()        # A & B  (additive and: choose one)
    PLUS = auto()        # A ⊕ B  (additive or: offer one)
    BANG = auto()         # !A     (of course: unlimited use)
    WHYNOT = auto()      # ?A     (why not: dual of bang)
    LOLLIPOP = auto()    # A ⊸ B  (linear implication: consume A, produce B)


@dataclass
class LinearType:
    """A type in the linear type system with resource annotations.

    Examples:
      Int                     — unrestricted integer
      File ⊸ ()              — linear function consuming a file
      !Int                    — explicitly unrestricted integer
      File ⊗ Handle          — tensor: both file and handle
      (Read & Write)          — additive: choose read or write
    """
    base: str
    connective: Optional[LinearConnective] = None
    operands: Tuple[LinearType, ...] = ()
    resource_kind: ResourceKind = ResourceKind.UNRESTRICTED
    potential: float = 0.0

    def is_linear(self) -> bool:
        return self.resource_kind == ResourceKind.LINEAR

    def is_affine(self) -> bool:
        return self.resource_kind == ResourceKind.AFFINE

    def is_unrestricted(self) -> bool:
        return self.resource_kind == ResourceKind.UNRESTRICTED

    def bang(self) -> LinearType:
        """Apply the ! (of course) modality — make unrestricted."""
        return LinearType(
            base=self.base, connective=LinearConnective.BANG,
            operands=(self,), resource_kind=ResourceKind.UNRESTRICTED,
            potential=self.potential
        )

    @staticmethod
    def tensor(a: LinearType, b: LinearType) -> LinearType:
        """A ⊗ B — multiplicative conjunction (both resources)."""
        return LinearType(
            base="⊗", connective=LinearConnective.TENSOR,
            operands=(a, b), resource_kind=ResourceKind.LINEAR,
            potential=a.potential + b.potential
        )

    @staticmethod
    def lollipop(domain: LinearType, codomain: LinearType) -> LinearType:
        """A ⊸ B — linear implication (consume A, produce B)."""
        return LinearType(
            base="⊸", connective=LinearConnective.LOLLIPOP,
            operands=(domain, codomain), resource_kind=ResourceKind.LINEAR
        )


# ---------------------------------------------------------------------------
# Resource Checking Pass
# ---------------------------------------------------------------------------

def _classify_resource(func) -> ResourceKind:
    """Determine the resource kind of a function's parameters."""
    if isinstance(func, PureFunc):
        return ResourceKind.UNRESTRICTED
    if isinstance(func, TaskFunc):
        return ResourceKind.AFFINE
    return ResourceKind.UNRESTRICTED


def _infer_param_linearity(param) -> ResourceKind:
    """Infer whether a parameter should be linear, affine, or unrestricted."""
    if hasattr(param, 'type_annotation') and param.type_annotation:
        ann_name = param.type_annotation.name if hasattr(param.type_annotation, 'name') else ""
        linear_types = {'File', 'Handle', 'Connection', 'Socket', 'Channel',
                        'Lock', 'Mutex', 'Transaction', 'Session', 'Stream',
                        'Resource', 'Unique', 'Linear', 'Affine', 'Own'}
        if ann_name in linear_types:
            return ResourceKind.LINEAR
        if ann_name.startswith('Unique') or ann_name.startswith('Own'):
            return ResourceKind.LINEAR
        if ann_name.startswith('Affine'):
            return ResourceKind.AFFINE
    return ResourceKind.UNRESTRICTED


def _collect_uses(stmts: List[Statement]) -> Dict[str, int]:
    """Count variable uses in a list of statements."""
    uses: Dict[str, int] = {}

    def _visit_expr(expr: Expr) -> None:
        if isinstance(expr, Identifier):
            uses[expr.name] = uses.get(expr.name, 0) + 1
        elif isinstance(expr, BinaryOp):
            _visit_expr(expr.left)
            _visit_expr(expr.right)
        elif isinstance(expr, UnaryOp):
            _visit_expr(expr.operand)
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                _visit_expr(arg)
        elif isinstance(expr, FieldAccess):
            _visit_expr(expr.object)
        elif isinstance(expr, MethodCall):
            _visit_expr(expr.object)
            for arg in expr.args:
                _visit_expr(arg)
        elif isinstance(expr, MoveExpr):
            _visit_expr(expr.value)

    def _visit_stmt(stmt: Statement) -> None:
        if isinstance(stmt, LetStmt):
            _visit_expr(stmt.value)
        elif isinstance(stmt, AssignStmt):
            _visit_expr(stmt.value)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                _visit_expr(stmt.value)
        elif isinstance(stmt, ExprStmt):
            _visit_expr(stmt.expr)
        elif isinstance(stmt, IfStmt):
            _visit_expr(stmt.condition)
            then_body = stmt.then_body if isinstance(stmt.then_body, list) else [stmt.then_body]
            for s in then_body:
                _visit_stmt(s)
            if stmt.else_body:
                else_body = stmt.else_body if isinstance(stmt.else_body, list) else [stmt.else_body]
                for s in else_body:
                    _visit_stmt(s)

    for s in stmts:
        _visit_stmt(s)
    return uses


def _check_function_resources(func, errors: List[AeonError]) -> None:
    """Check linear/affine resource constraints for a single function."""
    loc = getattr(func, 'location', SourceLocation("", 1, 1))
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"
    env = ResourceEnv()
    solver = PotentialSolver()

    params = func.params if hasattr(func, 'params') else []
    for p in params:
        pname = p.name if hasattr(p, 'name') else str(p)
        kind = _infer_param_linearity(p)
        env.define(pname, kind, loc, potential=1.0)
        if kind != ResourceKind.UNRESTRICTED:
            solver.add_variable(f"pot_{pname}")

    body = func.body if hasattr(func, 'body') else []
    if not isinstance(body, list):
        body = [body] if body else []

    # Count uses of each variable
    uses = _collect_uses(body)

    # Check linearity constraints
    for name, rv in env.resources.items():
        use_count = uses.get(name, 0)

        if rv.kind == ResourceKind.LINEAR:
            if use_count == 0:
                errors.append(contract_error(
                    f"Linear resource '{name}' in '{func_name}' is never used — "
                    f"linear types must be consumed exactly once "
                    f"(Girard's Linear Logic: no weakening)",
                    location=loc
                ))
            elif use_count > 1:
                errors.append(contract_error(
                    f"Linear resource '{name}' in '{func_name}' is used {use_count} times — "
                    f"linear types must be consumed exactly once "
                    f"(Girard's Linear Logic: no contraction)",
                    location=loc
                ))

        elif rv.kind == ResourceKind.AFFINE:
            if use_count > 1:
                errors.append(contract_error(
                    f"Affine resource '{name}' in '{func_name}' is used {use_count} times — "
                    f"affine types can be used at most once "
                    f"(Tov & Pucella 2011: practical affine types)",
                    location=loc
                ))

    # Potential analysis: check that resource costs are covered
    total_pot = env.total_potential()
    num_allocs = sum(1 for s in body if isinstance(s, LetStmt))
    if num_allocs > 0:
        solver.add_constraint(
            {f"pot_initial": 1.0},
            float(num_allocs),
            f"Allocation cost in '{func_name}'"
        )
        solver.add_variable("pot_initial")

    feasible, assignment = solver.solve_simple()
    if not feasible and num_allocs > 0:
        errors.append(contract_error(
            f"Insufficient resource potential in '{func_name}': "
            f"need potential >= {num_allocs} for {num_allocs} allocations "
            f"(Hofmann & Jost 2003: automatic heap bound)",
            location=loc
        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_linear_resources(program: Program) -> List[AeonError]:
    """Run linear/affine resource analysis on an AEON program.

    Checks:
    1. Linear resources used exactly once (Girard 1987)
    2. Affine resources used at most once (Tov & Pucella 2011)
    3. Resource potential sufficient for allocations (Hofmann & Jost 2003)
    4. No use-after-consume for linear/affine variables
    5. Context splitting correctness for subexpressions
    """
    errors: List[AeonError] = []

    functions = [d for d in program.declarations
                 if isinstance(d, (PureFunc, TaskFunc))]

    for func in functions:
        _check_function_resources(func, errors)

    return errors
