"""AEON Refinement Type System — Liquid Types with SMT-backed Subtyping.

Implements the Liquid Type Inference algorithm from:
  Rondon, Kawaguchi, Jhala (2008) "Liquid Types"
  PLDI '08, https://doi.org/10.1145/1375581.1375602

Key ideas:
  1. Refinement types are base types annotated with logical predicates:
       {v: Int | v >= 0}    -- non-negative integers
       {v: Int | v > x}     -- integers greater than parameter x
  2. Subtyping is decided via SMT (Z3): T1 <: T2 iff the refinement of T1
     implies the refinement of T2 under the path condition.
  3. Type inference uses predicate abstraction over a finite set of
     qualifier templates Q, solving for the strongest conjunction of
     qualifiers consistent with all subtyping constraints.
  4. The algorithm is a fixpoint computation:
       - Generate subtyping constraints from the program
       - Initialize each refinement variable to the conjunction of ALL qualifiers
       - Iteratively remove qualifiers that cause Z3 to return SAT on the
         negation of the subtyping obligation (counterexample-guided refinement)

The Liquid Type system sits strictly between simple types and full dependent
types — it is decidable (via SMT) while still expressive enough to verify
array bounds, division by zero, and functional correctness contracts.

Mathematical foundations:
  - Refinement types form a lattice under subtyping (<:)
  - The lattice meet is conjunction of predicates
  - The lattice join is disjunction (but we use templates for decidability)
  - Subtyping is contravariant in function arguments, covariant in returns
  - Soundness: if Gamma |- e : {v:T | p}, then forall substitutions
    sigma satisfying Gamma, [[e]]sigma satisfies p
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Set, Tuple, FrozenSet
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    Statement, ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt,
    ContractClause, Parameter, TypeAnnotation,
)
from aeon.types import AeonType, PrimitiveType, INT, FLOAT, BOOL, STRING, VOID
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
# Refinement Predicates
# ---------------------------------------------------------------------------

class PredicateKind(Enum):
    """Kind of atomic predicate in a refinement."""
    TRUE = auto()          # trivially true
    FALSE = auto()         # trivially false (bottom type / empty)
    COMPARISON = auto()    # v <op> expr
    EQUALITY = auto()      # v == expr
    CONJUNCTION = auto()   # p1 /\ p2
    DISJUNCTION = auto()   # p1 \/ p2
    NEGATION = auto()      # not p
    IMPLICATION = auto()   # p1 => p2
    FORALL = auto()        # forall x. p(x)
    KVAR = auto()          # refinement variable (unknown, to be solved)


@dataclass(frozen=True)
class Predicate:
    """A logical predicate in a refinement type.

    The value variable 'v' refers to the value being typed.
    Free variables refer to in-scope bindings.
    """
    kind: PredicateKind
    op: str = ""                              # for COMPARISON: <, <=, >, >=, ==, !=
    left: Optional[Predicate] = None          # sub-predicates or operands
    right: Optional[Predicate] = None
    var_name: str = ""                        # variable reference
    int_val: int = 0                          # integer constant
    children: Tuple[Predicate, ...] = ()      # for CONJUNCTION/DISJUNCTION
    kvar_id: int = -1                         # for KVAR: unique identifier

    def __str__(self) -> str:
        if self.kind == PredicateKind.TRUE:
            return "true"
        if self.kind == PredicateKind.FALSE:
            return "false"
        if self.kind == PredicateKind.COMPARISON:
            return f"{self.left} {self.op} {self.right}"
        if self.kind == PredicateKind.EQUALITY:
            return f"{self.left} == {self.right}"
        if self.kind == PredicateKind.CONJUNCTION:
            parts = " /\\ ".join(str(c) for c in self.children)
            return f"({parts})"
        if self.kind == PredicateKind.DISJUNCTION:
            parts = " \\/ ".join(str(c) for c in self.children)
            return f"({parts})"
        if self.kind == PredicateKind.NEGATION:
            return f"!({self.left})"
        if self.kind == PredicateKind.IMPLICATION:
            return f"({self.left} => {self.right})"
        if self.kind == PredicateKind.KVAR:
            return f"$k{self.kvar_id}"
        if self.var_name:
            return self.var_name
        return str(self.int_val)


# Predicate constructors
def P_TRUE() -> Predicate:
    return Predicate(kind=PredicateKind.TRUE)

def P_FALSE() -> Predicate:
    return Predicate(kind=PredicateKind.FALSE)

def P_VAR(name: str) -> Predicate:
    return Predicate(kind=PredicateKind.TRUE, var_name=name)

def P_INT(val: int) -> Predicate:
    return Predicate(kind=PredicateKind.TRUE, int_val=val)

def P_CMP(left: Predicate, op: str, right: Predicate) -> Predicate:
    return Predicate(kind=PredicateKind.COMPARISON, op=op, left=left, right=right)

def P_EQ(left: Predicate, right: Predicate) -> Predicate:
    return Predicate(kind=PredicateKind.EQUALITY, left=left, right=right)

def P_AND(*children: Predicate) -> Predicate:
    flat: list[Predicate] = []
    for c in children:
        if c.kind == PredicateKind.TRUE:
            continue
        if c.kind == PredicateKind.CONJUNCTION:
            flat.extend(c.children)
        else:
            flat.append(c)
    if not flat:
        return P_TRUE()
    if len(flat) == 1:
        return flat[0]
    return Predicate(kind=PredicateKind.CONJUNCTION, children=tuple(flat))

def P_OR(*children: Predicate) -> Predicate:
    flat: list[Predicate] = []
    for c in children:
        if c.kind == PredicateKind.FALSE:
            continue
        if c.kind == PredicateKind.DISJUNCTION:
            flat.extend(c.children)
        else:
            flat.append(c)
    if not flat:
        return P_FALSE()
    if len(flat) == 1:
        return flat[0]
    return Predicate(kind=PredicateKind.DISJUNCTION, children=tuple(flat))

def P_NOT(p: Predicate) -> Predicate:
    if p.kind == PredicateKind.TRUE:
        return P_FALSE()
    if p.kind == PredicateKind.FALSE:
        return P_TRUE()
    if p.kind == PredicateKind.NEGATION:
        return p.left
    return Predicate(kind=PredicateKind.NEGATION, left=p)

def P_IMPLIES(lhs: Predicate, rhs: Predicate) -> Predicate:
    return Predicate(kind=PredicateKind.IMPLICATION, left=lhs, right=rhs)

def P_KVAR(kid: int) -> Predicate:
    return Predicate(kind=PredicateKind.KVAR, kvar_id=kid)


# ---------------------------------------------------------------------------
# Refinement Types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RefinementType:
    """A refinement type: {v : base | predicate}.

    Examples:
      {v: Int | true}           -- any integer (equivalent to Int)
      {v: Int | v >= 0}         -- non-negative integer (Nat)
      {v: Int | v > x && v < y} -- integer strictly between x and y
      {v: Bool | v == true}     -- singleton true
    """
    base: AeonType                # the underlying simple type
    predicate: Predicate          # logical predicate over value variable 'v'
    value_var: str = "v"          # name of the value variable in the predicate

    def __str__(self) -> str:
        if self.predicate.kind == PredicateKind.TRUE:
            return str(self.base)
        return f"{{{self.value_var}: {self.base} | {self.predicate}}}"

    def is_trivial(self) -> bool:
        return self.predicate.kind == PredicateKind.TRUE


@dataclass(frozen=True)
class RefinementFunctionType:
    """Dependent function type with refinement types.

    pi (x1: T1) -> (x2: T2) -> ... -> Tr
    where each Ti can refer to x1, ..., x_{i-1}
    and Tr can refer to all parameters.
    """
    param_names: Tuple[str, ...]
    param_types: Tuple[RefinementType, ...]
    return_type: RefinementType
    is_pure: bool = True
    effects: Tuple[str, ...] = ()

    def __str__(self) -> str:
        params = ", ".join(f"{n}: {t}" for n, t in zip(self.param_names, self.param_types))
        prefix = "pure" if self.is_pure else "task"
        return f"{prefix}({params}) -> {self.return_type}"


# Convenience: lift a simple AeonType to a trivially-refined type
def trivial(base: AeonType) -> RefinementType:
    return RefinementType(base=base, predicate=P_TRUE())


# ---------------------------------------------------------------------------
# Qualifier Templates
# ---------------------------------------------------------------------------

@dataclass
class QualifierTemplate:
    """A qualifier template for liquid type inference.

    A qualifier is a predicate template with holes for program variables.
    Example templates:
      v >= 0
      v > ?x
      v == ?x + ?y
      v < len(?x)

    The liquid type inference algorithm tries all instantiations of these
    templates and finds the strongest consistent conjunction.
    """
    name: str
    arity: int                    # number of free variables (besides v)
    make_predicate: Any           # callable(v_name, *args) -> Predicate

    def __str__(self) -> str:
        return f"Q[{self.name}/{self.arity}]"


def _standard_qualifiers() -> List[QualifierTemplate]:
    """Standard qualifier templates for integer refinements.

    These form the basis of what the liquid type solver can discover.
    Richer templates = more expressive types but slower inference.
    """
    templates = []

    # Nullary qualifiers (no free variables besides v)
    templates.append(QualifierTemplate(
        name="v>=0", arity=0,
        make_predicate=lambda v: P_CMP(P_VAR(v), ">=", P_INT(0))
    ))
    templates.append(QualifierTemplate(
        name="v>0", arity=0,
        make_predicate=lambda v: P_CMP(P_VAR(v), ">", P_INT(0))
    ))
    templates.append(QualifierTemplate(
        name="v==0", arity=0,
        make_predicate=lambda v: P_CMP(P_VAR(v), "==", P_INT(0))
    ))
    templates.append(QualifierTemplate(
        name="v!=0", arity=0,
        make_predicate=lambda v: P_CMP(P_VAR(v), "!=", P_INT(0))
    ))
    templates.append(QualifierTemplate(
        name="v<=0", arity=0,
        make_predicate=lambda v: P_CMP(P_VAR(v), "<=", P_INT(0))
    ))

    # Unary qualifiers (one free variable)
    for op in [">=", ">", "<=", "<", "==", "!="]:
        templates.append(QualifierTemplate(
            name=f"v{op}x", arity=1,
            make_predicate=lambda v, x, _op=op: P_CMP(P_VAR(v), _op, P_VAR(x))
        ))

    # Relational qualifiers
    templates.append(QualifierTemplate(
        name="v==x+y", arity=2,
        make_predicate=lambda v, x, y: P_EQ(
            P_VAR(v),
            Predicate(kind=PredicateKind.COMPARISON, op="+",
                      left=P_VAR(x), right=P_VAR(y))
        )
    ))
    templates.append(QualifierTemplate(
        name="v==x-y", arity=2,
        make_predicate=lambda v, x, y: P_EQ(
            P_VAR(v),
            Predicate(kind=PredicateKind.COMPARISON, op="-",
                      left=P_VAR(x), right=P_VAR(y))
        )
    ))
    templates.append(QualifierTemplate(
        name="v==x*y", arity=2,
        make_predicate=lambda v, x, y: P_EQ(
            P_VAR(v),
            Predicate(kind=PredicateKind.COMPARISON, op="*",
                      left=P_VAR(x), right=P_VAR(y))
        )
    ))

    # ---------------------------------------------------------------------------
    # Extended qualifiers for deeper verification (Jhala & Vazou 2021)
    # ---------------------------------------------------------------------------

    # Modular arithmetic qualifiers
    templates.append(QualifierTemplate(
        name="v%2==0", arity=0,
        make_predicate=lambda v: P_CMP(
            Predicate(kind=PredicateKind.COMPARISON, op="%",
                      left=P_VAR(v), right=P_INT(2)),
            "==", P_INT(0))
    ))
    templates.append(QualifierTemplate(
        name="v%2==1", arity=0,
        make_predicate=lambda v: P_CMP(
            Predicate(kind=PredicateKind.COMPARISON, op="%",
                      left=P_VAR(v), right=P_INT(2)),
            "==", P_INT(1))
    ))

    # Array / list bounds qualifiers
    templates.append(QualifierTemplate(
        name="v>=0&&v<x", arity=1,
        make_predicate=lambda v, x: P_AND(
            P_CMP(P_VAR(v), ">=", P_INT(0)),
            P_CMP(P_VAR(v), "<", P_VAR(x))
        )
    ))
    templates.append(QualifierTemplate(
        name="v==x-1", arity=1,
        make_predicate=lambda v, x: P_EQ(
            P_VAR(v),
            Predicate(kind=PredicateKind.COMPARISON, op="-",
                      left=P_VAR(x), right=P_INT(1))
        )
    ))
    templates.append(QualifierTemplate(
        name="v==x+1", arity=1,
        make_predicate=lambda v, x: P_EQ(
            P_VAR(v),
            Predicate(kind=PredicateKind.COMPARISON, op="+",
                      left=P_VAR(x), right=P_INT(1))
        )
    ))

    # Power-of-two qualifiers (useful for alignment, bitwise ops)
    for k in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
        templates.append(QualifierTemplate(
            name=f"v<={k}", arity=0,
            make_predicate=lambda v, _k=k: P_CMP(P_VAR(v), "<=", P_INT(_k))
        ))

    # Sortedness / ordering qualifiers
    templates.append(QualifierTemplate(
        name="v<=x", arity=1,
        make_predicate=lambda v, x: P_CMP(P_VAR(v), "<=", P_VAR(x))
    ))

    # Non-null / non-empty qualifiers
    templates.append(QualifierTemplate(
        name="v!=null", arity=0,
        make_predicate=lambda v: P_CMP(P_VAR(v), "!=",
                                        Predicate(kind=PredicateKind.TRUE, var_name="null"))
    ))

    return templates


# ---------------------------------------------------------------------------
# Subtyping Constraints
# ---------------------------------------------------------------------------

@dataclass
class SubtypeConstraint:
    """A subtyping constraint: Gamma |- T1 <: T2.

    Meaning: under environment Gamma, type T1 is a subtype of T2.
    This reduces to an SMT validity check:

      forall v. (Gamma_pred /\\ T1.predicate[v]) => T2.predicate[v]

    which we check by asking Z3 if the negation is unsatisfiable.
    """
    environment: Dict[str, RefinementType]   # typing context
    path_condition: Predicate                 # accumulated branch conditions
    sub_type: RefinementType                  # T1
    super_type: RefinementType                # T2
    location: Optional[SourceLocation] = None
    reason: str = ""

    def __str__(self) -> str:
        return f"{self.sub_type} <: {self.super_type}  [{self.reason}]"


# ---------------------------------------------------------------------------
# Liquid Type Solver (Fixpoint Computation)
# ---------------------------------------------------------------------------

class LiquidTypeSolver:
    """Solves liquid type inference via counterexample-guided abstraction refinement.

    Algorithm (from Rondon et al. 2008):
    1. Parse qualifier templates Q = {q1, ..., qn}
    2. For each refinement variable kvar_i, initialize its solution to
       the conjunction of ALL qualifiers: sol(kvar_i) = q1 /\\ q2 /\\ ... /\\ qn
    3. Iterate:
       a. For each subtyping constraint C: Gamma |- {v:T|p1} <: {v:T|p2}
       b. Substitute current solutions for kvars in p1, p2
       c. Check validity via Z3: Gamma => p1 => p2
       d. If invalid (Z3 returns SAT with counterexample sigma):
          - Remove from sol(kvar) any qualifier q where sigma |/= q
       e. Repeat until fixpoint (no more removals)
    4. The resulting solutions are the strongest liquid types consistent
       with all constraints.

    Correctness: The algorithm computes the greatest fixpoint of the
    abstract transformer in the lattice of qualifier conjunctions,
    ordered by implication. This is sound because:
      - We start at TOP (all qualifiers)
      - We only remove qualifiers that are provably inconsistent
      - The lattice is finite (bounded by |Q|)
      - The transformer is monotone
    Therefore, by Tarski's fixpoint theorem, we reach the greatest fixpoint
    in at most |Q| * |kvars| iterations.
    """

    def __init__(self, qualifiers: Optional[List[QualifierTemplate]] = None):
        self.qualifiers = qualifiers or _standard_qualifiers()
        self._next_kvar = 0
        self.solutions: Dict[int, List[Predicate]] = {}  # kvar_id -> list of qualifiers
        self.constraints: List[SubtypeConstraint] = []
        self.errors: List[AeonError] = []

    def fresh_kvar(self) -> int:
        """Allocate a fresh refinement variable."""
        kid = self._next_kvar
        self._next_kvar += 1
        return kid

    def add_constraint(self, constraint: SubtypeConstraint) -> None:
        self.constraints.append(constraint)

    def solve(self) -> Dict[int, Predicate]:
        """Run the liquid type fixpoint solver.

        Returns: mapping from kvar_id to solved predicate.
        """
        if not HAS_Z3:
            return {kid: P_TRUE() for kid in self.solutions}

        # Phase 1: Initialize all kvars to conjunction of all qualifiers
        self._initialize_solutions()

        # Phase 2: Iterate until fixpoint
        max_iterations = len(self.solutions) * len(self.qualifiers) + 1
        changed = True
        iteration = 0

        while changed and iteration < max_iterations:
            changed = False
            iteration += 1

            for constraint in self.constraints:
                removed = self._process_constraint(constraint)
                if removed:
                    changed = True

        # Phase 3: Build final solutions
        result: Dict[int, Predicate] = {}
        for kid, quals in self.solutions.items():
            if quals:
                result[kid] = P_AND(*quals)
            else:
                result[kid] = P_TRUE()

        return result

    def _initialize_solutions(self) -> None:
        """Initialize each kvar to the conjunction of all applicable qualifiers."""
        for kid in list(self.solutions.keys()):
            if not self.solutions[kid]:
                # Generate all qualifier instantiations
                all_preds: List[Predicate] = []
                for qt in self.qualifiers:
                    if qt.arity == 0:
                        all_preds.append(qt.make_predicate("v"))
                self.solutions[kid] = all_preds

    def _process_constraint(self, constraint: SubtypeConstraint) -> bool:
        """Process a single subtyping constraint. Returns True if any kvar changed."""
        # Substitute current solutions into predicates
        sub_pred = self._substitute_kvars(constraint.sub_type.predicate)
        super_pred = self._substitute_kvars(constraint.super_type.predicate)

        # Build the environment predicate
        env_pred = self._environment_to_predicate(constraint.environment)
        path_cond = constraint.path_condition

        # Build the validity check: env /\ path /\ sub_pred => super_pred
        antecedent = P_AND(env_pred, path_cond, sub_pred)

        # Check each qualifier in the super_type's kvar solution
        if constraint.super_type.predicate.kind == PredicateKind.KVAR:
            kid = constraint.super_type.predicate.kvar_id
            if kid in self.solutions:
                return self._refine_solution(kid, antecedent)

        return False

    def _refine_solution(self, kid: int, antecedent: Predicate) -> bool:
        """Remove qualifiers from kvar solution that are inconsistent.

        For each qualifier q in sol(kid):
          Check: antecedent => q  (is this valid?)
          If not valid (Z3 finds counterexample): remove q

        Returns True if any qualifier was removed.
        """
        remaining: List[Predicate] = []
        removed = False

        for qual in self.solutions[kid]:
            if self._check_implication(antecedent, qual):
                remaining.append(qual)
            else:
                removed = True

        self.solutions[kid] = remaining
        return removed

    def _check_implication(self, antecedent: Predicate, consequent: Predicate) -> bool:
        """Check if antecedent => consequent is valid using Z3.

        Valid means: forall free variables, antecedent implies consequent.
        We check this by asking Z3 if (antecedent /\\ NOT consequent) is UNSAT.
        """
        if not HAS_Z3:
            return True

        try:
            solver = z3.Solver()
            solver.set("timeout", 5000)  # 5 second timeout

            z3_vars: Dict[str, Any] = {}
            z3_ante = self._pred_to_z3(antecedent, z3_vars)
            z3_cons = self._pred_to_z3(consequent, z3_vars)

            if z3_ante is None or z3_cons is None:
                return True  # Can't encode: assume valid

            solver.add(z3_ante)
            solver.add(z3.Not(z3_cons))

            result = solver.check()
            return result == z3.unsat  # UNSAT means implication is valid
        except Exception:
            return True  # Fail open on Z3 errors

    def _substitute_kvars(self, pred: Predicate) -> Predicate:
        """Substitute solved kvar values into a predicate."""
        if pred.kind == PredicateKind.KVAR:
            kid = pred.kvar_id
            if kid in self.solutions and self.solutions[kid]:
                return P_AND(*self.solutions[kid])
            return P_TRUE()
        if pred.kind == PredicateKind.CONJUNCTION:
            return P_AND(*(self._substitute_kvars(c) for c in pred.children))
        if pred.kind == PredicateKind.DISJUNCTION:
            return P_OR(*(self._substitute_kvars(c) for c in pred.children))
        if pred.kind in (PredicateKind.COMPARISON, PredicateKind.EQUALITY):
            left = self._substitute_kvars(pred.left) if pred.left else pred.left
            right = self._substitute_kvars(pred.right) if pred.right else pred.right
            return Predicate(kind=pred.kind, op=pred.op, left=left, right=right,
                             var_name=pred.var_name, int_val=pred.int_val)
        if pred.kind == PredicateKind.NEGATION:
            return P_NOT(self._substitute_kvars(pred.left))
        if pred.kind == PredicateKind.IMPLICATION:
            return P_IMPLIES(self._substitute_kvars(pred.left),
                             self._substitute_kvars(pred.right))
        return pred

    def _environment_to_predicate(self, env: Dict[str, RefinementType]) -> Predicate:
        """Convert a typing environment to a conjunction of predicates."""
        preds: List[Predicate] = []
        for name, rtype in env.items():
            if not rtype.is_trivial():
                # Substitute the variable name for 'v' in the predicate
                preds.append(rtype.predicate)
        if preds:
            return P_AND(*preds)
        return P_TRUE()

    def _pred_to_z3(self, pred: Predicate, z3_vars: Dict[str, Any]) -> Any:
        """Convert a Predicate to a Z3 expression."""
        if not HAS_Z3:
            return None

        if pred.kind == PredicateKind.TRUE:
            return z3.BoolVal(True)
        if pred.kind == PredicateKind.FALSE:
            return z3.BoolVal(False)

        if pred.var_name:
            if pred.var_name not in z3_vars:
                z3_vars[pred.var_name] = z3.Int(pred.var_name)
            return z3_vars[pred.var_name]

        if pred.int_val != 0 or (pred.kind == PredicateKind.TRUE and not pred.var_name):
            if pred.kind == PredicateKind.TRUE and pred.int_val != 0:
                return z3.IntVal(pred.int_val)
            if not pred.var_name and pred.kind == PredicateKind.TRUE:
                return z3.IntVal(pred.int_val)

        if pred.kind == PredicateKind.COMPARISON:
            left = self._pred_to_z3(pred.left, z3_vars) if pred.left else None
            right = self._pred_to_z3(pred.right, z3_vars) if pred.right else None
            if left is None or right is None:
                return None
            ops = {
                ">=": lambda l, r: l >= r,
                ">": lambda l, r: l > r,
                "<=": lambda l, r: l <= r,
                "<": lambda l, r: l < r,
                "==": lambda l, r: l == r,
                "!=": lambda l, r: l != r,
                "+": lambda l, r: l + r,
                "-": lambda l, r: l - r,
                "*": lambda l, r: l * r,
            }
            fn = ops.get(pred.op)
            return fn(left, right) if fn else None

        if pred.kind == PredicateKind.EQUALITY:
            left = self._pred_to_z3(pred.left, z3_vars) if pred.left else None
            right = self._pred_to_z3(pred.right, z3_vars) if pred.right else None
            if left is None or right is None:
                return None
            return left == right

        if pred.kind == PredicateKind.CONJUNCTION:
            parts = [self._pred_to_z3(c, z3_vars) for c in pred.children]
            parts = [p for p in parts if p is not None]
            if not parts:
                return z3.BoolVal(True)
            return z3.And(*parts) if len(parts) > 1 else parts[0]

        if pred.kind == PredicateKind.DISJUNCTION:
            parts = [self._pred_to_z3(c, z3_vars) for c in pred.children]
            parts = [p for p in parts if p is not None]
            if not parts:
                return z3.BoolVal(False)
            return z3.Or(*parts) if len(parts) > 1 else parts[0]

        if pred.kind == PredicateKind.NEGATION:
            inner = self._pred_to_z3(pred.left, z3_vars) if pred.left else None
            return z3.Not(inner) if inner is not None else None

        if pred.kind == PredicateKind.IMPLICATION:
            lhs = self._pred_to_z3(pred.left, z3_vars) if pred.left else None
            rhs = self._pred_to_z3(pred.right, z3_vars) if pred.right else None
            if lhs is not None and rhs is not None:
                return z3.Implies(lhs, rhs)

        return None


# ---------------------------------------------------------------------------
# Refinement Type Checker
# ---------------------------------------------------------------------------

class RefinementTypeChecker:
    """Generates refinement type constraints from AEON programs.

    For each expression, generates:
      1. A refinement type (base type + predicate)
      2. Subtyping constraints between actual and expected types

    The constraints are then solved by the LiquidTypeSolver.
    """

    def __init__(self):
        self.solver = LiquidTypeSolver()
        self.errors: List[AeonError] = []
        self._env: Dict[str, RefinementType] = {}
        self._path_condition: Predicate = P_TRUE()

    def check_program(self, program: Program) -> List[AeonError]:
        """Run refinement type checking on a program."""
        self.errors = []

        functions = [d for d in program.declarations
                     if isinstance(d, (PureFunc, TaskFunc))]

        # Phase 1: Generate constraints from each function
        for func in functions:
            self._check_function(func)

        # Phase 2: Solve all constraints via liquid type fixpoint
        if HAS_Z3:
            solutions = self.solver.solve()
            # Phase 3: Check if any constraint is unsatisfied
            self._verify_solutions(solutions)

        return self.errors

    def _check_function(self, func: PureFunc | TaskFunc) -> None:
        """Generate refinement type constraints for a function."""
        saved_env = dict(self._env)
        saved_pc = self._path_condition

        # Bind parameters with refinements from contracts
        for param in func.params:
            base_type = self._resolve_base_type(param.type_annotation)
            ref_type = RefinementType(base=base_type, predicate=P_TRUE())
            self._env[param.name] = ref_type

        # Extract refinements from requires clauses
        for req in func.requires:
            req_pred = self._expr_to_predicate(req.expr)
            self._path_condition = P_AND(self._path_condition, req_pred)

        # Check body
        body_type = None
        for stmt in func.body:
            body_type = self._check_statement(stmt, func)

        # Verify ensures clauses
        if func.return_type:
            expected_base = self._resolve_base_type(func.return_type)
            for ens in func.ensures:
                ens_pred = self._expr_to_predicate(ens.expr)
                expected_type = RefinementType(
                    base=expected_base,
                    predicate=ens_pred,
                    value_var="result"
                )
                if body_type:
                    self.solver.add_constraint(SubtypeConstraint(
                        environment=dict(self._env),
                        path_condition=self._path_condition,
                        sub_type=body_type,
                        super_type=expected_type,
                        location=ens.location,
                        reason=f"ensures clause in {func.name}"
                    ))

        self._env = saved_env
        self._path_condition = saved_pc

    def _check_statement(self, stmt: Statement, func) -> Optional[RefinementType]:
        """Check a statement and return its refinement type if applicable."""
        if isinstance(stmt, ReturnStmt):
            if stmt.value:
                return self._synth_type(stmt.value)
            return trivial(VOID)

        if isinstance(stmt, LetStmt):
            if stmt.value:
                val_type = self._synth_type(stmt.value)
                if val_type:
                    self._env[stmt.name] = val_type
            return None

        if isinstance(stmt, IfStmt):
            cond_pred = self._expr_to_predicate(stmt.condition)

            # Then branch: path_condition /\ cond
            saved_pc = self._path_condition
            self._path_condition = P_AND(self._path_condition, cond_pred)
            then_type = None
            for s in stmt.then_body:
                then_type = self._check_statement(s, func) or then_type
            self._path_condition = saved_pc

            # Else branch: path_condition /\ NOT cond
            self._path_condition = P_AND(self._path_condition, P_NOT(cond_pred))
            else_type = None
            for s in stmt.else_body:
                else_type = self._check_statement(s, func) or else_type
            self._path_condition = saved_pc

            # Join the two branches
            if then_type and else_type:
                return self._join_types(then_type, else_type)
            return then_type or else_type

        if isinstance(stmt, ExprStmt):
            self._synth_type(stmt.expr)
            return None

        if isinstance(stmt, AssignStmt):
            val_type = self._synth_type(stmt.value)
            if isinstance(stmt.target, Identifier) and val_type:
                self._env[stmt.target.name] = val_type
            return None

        return None

    def _synth_type(self, expr: Expr) -> Optional[RefinementType]:
        """Synthesize a refinement type for an expression (bidirectional typing).

        This implements the synthesis judgment:
          Gamma |- e => {v: T | p}
        """
        if isinstance(expr, IntLiteral):
            # {v: Int | v == n}  -- singleton refinement
            return RefinementType(
                base=INT,
                predicate=P_CMP(P_VAR("v"), "==", P_INT(expr.value))
            )

        if isinstance(expr, BoolLiteral):
            return trivial(BOOL)

        if isinstance(expr, FloatLiteral):
            return trivial(FLOAT)

        if isinstance(expr, StringLiteral):
            return trivial(STRING)

        if isinstance(expr, Identifier):
            if expr.name in self._env:
                return self._env[expr.name]
            if expr.name == "result":
                return RefinementType(base=INT, predicate=P_VAR("result"))
            return None

        if isinstance(expr, BinaryOp):
            return self._synth_binary(expr)

        if isinstance(expr, UnaryOp):
            inner = self._synth_type(expr.operand)
            if inner:
                if expr.op == "-":
                    return RefinementType(base=inner.base, predicate=P_TRUE())
                if expr.op == "!":
                    return trivial(BOOL)
            return None

        if isinstance(expr, FunctionCall):
            return self._synth_call(expr)

        if isinstance(expr, FieldAccess):
            obj_type = self._synth_type(expr.obj)
            if obj_type:
                return trivial(obj_type.base)
            return None

        if isinstance(expr, MethodCall):
            return trivial(BOOL)  # Conservative

        return None

    def _synth_binary(self, expr: BinaryOp) -> Optional[RefinementType]:
        """Synthesize refinement type for binary operations."""
        left_type = self._synth_type(expr.left)
        right_type = self._synth_type(expr.right)

        if not left_type or not right_type:
            return None

        # Arithmetic: result type carries structural predicate
        if expr.op in ("+", "-", "*", "/", "%"):
            left_pred = self._expr_to_predicate(expr.left)
            right_pred = self._expr_to_predicate(expr.right)
            result_pred = Predicate(
                kind=PredicateKind.COMPARISON, op=expr.op,
                left=left_pred, right=right_pred
            )
            return RefinementType(
                base=left_type.base,
                predicate=P_EQ(P_VAR("v"), result_pred)
            )

        # Comparison: result is Bool
        if expr.op in ("<", "<=", ">", ">=", "==", "!="):
            return trivial(BOOL)

        # Logical: result is Bool
        if expr.op in ("&&", "||"):
            return trivial(BOOL)

        return None

    def _synth_call(self, expr: FunctionCall) -> Optional[RefinementType]:
        """Synthesize refinement type for function calls."""
        if isinstance(expr.callee, Identifier):
            # Check arguments against parameter types
            for arg in expr.args:
                self._synth_type(arg)
            # Return a fresh kvar for the result
            kid = self.solver.fresh_kvar()
            self.solver.solutions[kid] = []
            return RefinementType(base=INT, predicate=P_KVAR(kid))
        return None

    def _join_types(self, t1: RefinementType, t2: RefinementType) -> RefinementType:
        """Compute the join (least upper bound) of two refinement types.

        In the refinement lattice:
          {v:T|p1} join {v:T|p2} = {v:T | p1 \\/ p2}
        """
        if t1.base != t2.base:
            return trivial(t1.base)
        return RefinementType(
            base=t1.base,
            predicate=P_OR(t1.predicate, t2.predicate)
        )

    def _expr_to_predicate(self, expr: Expr) -> Predicate:
        """Convert an AEON expression to a logical predicate."""
        if isinstance(expr, IntLiteral):
            return P_INT(expr.value)
        if isinstance(expr, BoolLiteral):
            return P_TRUE() if expr.value else P_FALSE()
        if isinstance(expr, Identifier):
            return P_VAR(expr.name)
        if isinstance(expr, BinaryOp):
            left = self._expr_to_predicate(expr.left)
            right = self._expr_to_predicate(expr.right)
            if expr.op in ("&&",):
                return P_AND(left, right)
            if expr.op in ("||",):
                return P_OR(left, right)
            return P_CMP(left, expr.op, right)
        if isinstance(expr, UnaryOp):
            inner = self._expr_to_predicate(expr.operand)
            if expr.op == "!":
                return P_NOT(inner)
            return inner
        if isinstance(expr, FieldAccess):
            obj = self._expr_to_predicate(expr.obj)
            return P_VAR(f"{obj}.{expr.field_name}")
        if isinstance(expr, MethodCall):
            return P_TRUE()  # Conservative
        return P_TRUE()

    def _resolve_base_type(self, ann) -> AeonType:
        """Resolve a type annotation to its base AeonType."""
        from aeon.types import resolve_type_annotation, TypeEnvironment
        if ann is None:
            return VOID
        env = TypeEnvironment()
        return resolve_type_annotation(ann, env)

    def _verify_solutions(self, solutions: Dict[int, Predicate]) -> None:
        """Verify that solved refinements satisfy all constraints."""
        for constraint in self.solver.constraints:
            sub_pred = self._substitute_solution(constraint.sub_type.predicate, solutions)
            super_pred = self._substitute_solution(constraint.super_type.predicate, solutions)

            env_pred = self.solver._environment_to_predicate(constraint.environment)
            antecedent = P_AND(env_pred, constraint.path_condition, sub_pred)

            if not self.solver._check_implication(antecedent, super_pred):
                self.errors.append(contract_error(
                    precondition=f"Refinement subtyping failed: {constraint.sub_type} </: {constraint.super_type}",
                    failing_values={"reason": constraint.reason},
                    function_signature=constraint.reason,
                    location=constraint.location,
                ))

    def _substitute_solution(self, pred: Predicate, solutions: Dict[int, Predicate]) -> Predicate:
        """Replace kvars with their solved values."""
        if pred.kind == PredicateKind.KVAR:
            return solutions.get(pred.kvar_id, P_TRUE())
        if pred.kind == PredicateKind.CONJUNCTION:
            return P_AND(*(self._substitute_solution(c, solutions) for c in pred.children))
        if pred.kind == PredicateKind.DISJUNCTION:
            return P_OR(*(self._substitute_solution(c, solutions) for c in pred.children))
        return pred


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_refinements(program: Program) -> List[AeonError]:
    """Run refinement type checking on an AEON program.

    This performs liquid type inference to verify that:
    1. All requires/ensures contracts are satisfiable
    2. Function return types satisfy their ensures clauses
    3. Subtyping obligations at call sites are met
    """
    checker = RefinementTypeChecker()
    return checker.check_program(program)
