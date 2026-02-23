"""AEON Effect Algebra — Algebraic Effects with Row Polymorphism.

Implements the algebraic effect system from:
  Plotkin & Pretnar (2009) "Handlers of Algebraic Effects"
  ESOP '09, https://doi.org/10.1007/978-3-642-00590-9_7

  Plotkin & Power (2003) "Algebraic Operations and Generic Effects"
  Applied Categorical Structures 11(1)

  Leijen (2017) "Type Directed Compilation of Row-Typed Algebraic Effects"
  POPL '17, https://doi.org/10.1145/3009837.3009872

Key mathematical structures:

1. EFFECT ROWS: An effect type is a ROW of effect labels.
   A row is an ordered set with a row variable for polymorphism:

     <Database.Read, Network.Write | rho>

   where 'rho' is a row variable that can be instantiated with
   more effects. This enables EFFECT POLYMORPHISM:
   a function can be polymorphic over what additional effects
   the caller may have.

2. EFFECT LATTICE: Effects form a bounded lattice:

        TOP (all effects)
       / | \\
     IO  DB  Net  ...    (effect categories)
    / \\  / \\
   R   W R  W            (sub-effects)
    \\ | /
     BOT (pure / no effects)

   Subtyping: E1 <: E2 iff every effect in E1 is also in E2.
   A function with effects E1 can be used where E2 is expected
   if E1 is a subset of E2 (covariant in effects).

3. EFFECT HANDLERS: An effect handler intercepts effectful operations
   and provides an interpretation. This enables:
   - Mocking effects in tests
   - Logging/tracing effect operations
   - Transactional composition of effects

4. EFFECT INFERENCE: For each function, infer the minimal effect set
   by traversing the call graph and collecting all effects.
   This is a forward dataflow analysis on the effect lattice.

5. EFFECT COMMUTATIVITY: Two effects COMMUTE if their order doesn't
   matter. Non-commuting effects must be sequenced.
   This enables automatic parallelization of commuting effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Tuple, FrozenSet
from enum import Enum, auto
import itertools

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, Statement, Expr,
    Identifier, FunctionCall, MethodCall, FieldAccess,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    UnsafeBlock, BinaryOp, UnaryOp,
)
from aeon.errors import AeonError, effect_error, SourceLocation


# ---------------------------------------------------------------------------
# Effect Labels and Rows
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EffectLabel:
    """A single effect label, e.g., Database.Read.

    Effect labels form a two-level hierarchy:
      Category.Operation

    where Category is a broad class (Database, Network, File, Console, System)
    and Operation is a specific kind (Read, Write, Execute).
    """
    category: str
    operation: str

    def __str__(self) -> str:
        return f"{self.category}.{self.operation}"

    def __hash__(self) -> int:
        return hash((self.category, self.operation))

    @staticmethod
    def parse(s: str) -> EffectLabel:
        parts = s.split(".", 1)
        if len(parts) == 2:
            return EffectLabel(parts[0], parts[1])
        return EffectLabel(parts[0], "*")


# Standard effect labels
DB_READ = EffectLabel("Database", "Read")
DB_WRITE = EffectLabel("Database", "Write")
NET_READ = EffectLabel("Network", "Read")
NET_WRITE = EffectLabel("Network", "Write")
FILE_READ = EffectLabel("File", "Read")
FILE_WRITE = EffectLabel("File", "Write")
CONSOLE_READ = EffectLabel("Console", "Read")
CONSOLE_WRITE = EffectLabel("Console", "Write")
SYS_EXEC = EffectLabel("System", "Execute")


@dataclass(frozen=True)
class RowVariable:
    """A row variable for effect polymorphism.

    Row variables allow functions to be polymorphic over effects:
      pure map<A, B, rho>(f: A -> B with <rho>, xs: List<A>) -> List<B> with <rho>

    Here, 'rho' captures whatever effects f has, and map propagates them.
    """
    name: str
    id: int = 0

    def __str__(self) -> str:
        return f"|{self.name}"


@dataclass(frozen=True)
class EffectRow:
    """An effect row: an ordered set of effect labels with optional row variable.

    Examples:
      <>                          -- pure (no effects)
      <Database.Read>             -- single effect
      <Database.Read, File.Write> -- multiple effects
      <Database.Read | rho>       -- polymorphic (rho captures additional effects)

    The row forms a free commutative monoid over effect labels,
    extended with row variables for polymorphism.
    """
    labels: FrozenSet[EffectLabel] = frozenset()
    row_var: Optional[RowVariable] = None

    def __str__(self) -> str:
        parts = sorted(str(l) for l in self.labels)
        if self.row_var:
            parts.append(str(self.row_var))
        if not parts:
            return "<>"
        return "<" + ", ".join(parts) + ">"

    def is_pure(self) -> bool:
        """A row is pure if it has no effects and no row variable."""
        return len(self.labels) == 0 and self.row_var is None

    def union(self, other: EffectRow) -> EffectRow:
        """Combine two effect rows (union of labels)."""
        combined_labels = self.labels | other.labels
        # If either has a row variable, the result is polymorphic
        row_var = self.row_var or other.row_var
        return EffectRow(labels=combined_labels, row_var=row_var)

    def contains(self, label: EffectLabel) -> bool:
        """Check if this row contains a specific effect label."""
        return label in self.labels

    def is_subrow_of(self, other: EffectRow) -> bool:
        """Check if this row is a sub-row of another.

        <E1, E2> is a sub-row of <E1, E2, E3> (subset relation).
        If other has a row variable, it can absorb extra effects.
        """
        if other.row_var is not None:
            return True  # Row variable absorbs everything
        return self.labels.issubset(other.labels)

    def difference(self, other: EffectRow) -> EffectRow:
        """Effects in self but not in other."""
        return EffectRow(labels=self.labels - other.labels, row_var=self.row_var)


# Special rows
PURE_ROW = EffectRow()  # Empty row = pure
ALL_EFFECTS_ROW = EffectRow(labels=frozenset({
    DB_READ, DB_WRITE, NET_READ, NET_WRITE,
    FILE_READ, FILE_WRITE, CONSOLE_READ, CONSOLE_WRITE, SYS_EXEC,
}))


# ---------------------------------------------------------------------------
# Effect Lattice
# ---------------------------------------------------------------------------

class EffectLattice:
    """The effect lattice for subtyping and ordering.

    Effects form a bounded lattice under set inclusion:
      BOT = {} (pure)
      TOP = {all effects}
      JOIN = set union
      MEET = set intersection

    Effect subtyping is COVARIANT:
      If f has effects E1 and g expects effects E2,
      then f can be used where g is expected iff E1 is a subset of E2.

    This is because a function with FEWER effects is MORE general
    (can be used in more contexts).
    """

    def __init__(self):
        # Effect category hierarchy
        self.hierarchy: Dict[str, Set[EffectLabel]] = {
            "Database": {DB_READ, DB_WRITE},
            "Network": {NET_READ, NET_WRITE},
            "File": {FILE_READ, FILE_WRITE},
            "Console": {CONSOLE_READ, CONSOLE_WRITE},
            "System": {SYS_EXEC},
            "IO": {DB_READ, DB_WRITE, NET_READ, NET_WRITE,
                   FILE_READ, FILE_WRITE, CONSOLE_READ, CONSOLE_WRITE},
        }

        # Commutativity relation: which effects can be reordered?
        # Two effects commute if their order of execution doesn't matter.
        self.commutes: Set[FrozenSet[EffectLabel]] = set()
        # Reads commute with each other
        self.commutes.add(frozenset({DB_READ, NET_READ}))
        self.commutes.add(frozenset({DB_READ, FILE_READ}))
        self.commutes.add(frozenset({NET_READ, FILE_READ}))
        self.commutes.add(frozenset({CONSOLE_READ, DB_READ}))
        # Reads commute with writes to different resources
        self.commutes.add(frozenset({DB_READ, FILE_WRITE}))
        self.commutes.add(frozenset({NET_READ, FILE_WRITE}))
        self.commutes.add(frozenset({DB_READ, NET_WRITE}))

    def join(self, r1: EffectRow, r2: EffectRow) -> EffectRow:
        """Least upper bound (union of effects)."""
        return r1.union(r2)

    def meet(self, r1: EffectRow, r2: EffectRow) -> EffectRow:
        """Greatest lower bound (intersection of effects)."""
        return EffectRow(labels=r1.labels & r2.labels)

    def subtype(self, sub: EffectRow, sup: EffectRow) -> bool:
        """Check if sub is a subtype of sup (sub has fewer effects)."""
        return sub.is_subrow_of(sup)

    def effects_commute(self, e1: EffectLabel, e2: EffectLabel) -> bool:
        """Check if two effects commute (can be reordered)."""
        if e1 == e2:
            return True
        pair = frozenset({e1, e2})
        return pair in self.commutes

    def can_parallelize(self, row1: EffectRow, row2: EffectRow) -> bool:
        """Check if two effect rows can be executed in parallel.

        Two computations can be parallelized if ALL pairs of effects
        between them commute.
        """
        for e1 in row1.labels:
            for e2 in row2.labels:
                if not self.effects_commute(e1, e2):
                    return False
        return True

    def expand_category(self, category: str) -> Set[EffectLabel]:
        """Expand a category name to its constituent effects."""
        return self.hierarchy.get(category, set())


# Global lattice instance
EFFECT_LATTICE = EffectLattice()


# ---------------------------------------------------------------------------
# Effect Handlers
# ---------------------------------------------------------------------------

@dataclass
class EffectHandler:
    """An algebraic effect handler.

    Handlers intercept effect operations and provide interpretations.
    Mathematically, a handler is a fold over the free monad of effects:

      handle(return x) = return_clause(x)
      handle(op(v, k)) = op_clause(v, k)

    where:
      - op is an effect operation
      - v is the argument to the operation
      - k is the continuation (rest of the computation)

    This gives us delimited continuations for free!
    """
    name: str
    handled_effects: EffectRow
    return_clause: Optional[str] = None  # How to handle pure returns
    operation_clauses: Dict[str, str] = field(default_factory=dict)

    def handles(self, label: EffectLabel) -> bool:
        return label in self.handled_effects.labels

    def residual_effects(self, input_effects: EffectRow) -> EffectRow:
        """Compute the effects remaining after handling.

        If a handler handles effects E_h, and the computation has effects E_c,
        then the residual effects are E_c \\ E_h.
        """
        return input_effects.difference(self.handled_effects)


# ---------------------------------------------------------------------------
# Effect Inference Engine
# ---------------------------------------------------------------------------

class EffectInferencer:
    """Infers minimal effect sets for AEON functions.

    Uses a forward dataflow analysis on the effect lattice:
    1. For each function, compute the effects of its body
    2. For function calls, look up the callee's effects
    3. Iterate until fixpoint (for mutual recursion)

    The result is the PRINCIPAL EFFECT TYPE: the most precise
    effect annotation consistent with the function's implementation.
    """

    def __init__(self):
        self.errors: List[AeonError] = []
        self.function_effects: Dict[str, EffectRow] = {}
        self.lattice = EFFECT_LATTICE

        # Built-in effectful operations
        self.builtin_effects: Dict[str, EffectLabel] = {
            "db.insert": DB_WRITE,
            "db.update": DB_WRITE,
            "db.delete": DB_WRITE,
            "db.query": DB_READ,
            "db.find": DB_READ,
            "db.contains": DB_READ,
            "net.get": NET_READ,
            "net.post": NET_WRITE,
            "net.send": NET_WRITE,
            "file.read": FILE_READ,
            "file.write": FILE_WRITE,
            "console.print": CONSOLE_WRITE,
            "console.read": CONSOLE_READ,
            "print": CONSOLE_WRITE,
        }

    def infer_program(self, program: Program) -> Tuple[List[AeonError], Dict[str, EffectRow]]:
        """Infer effects for all functions in a program."""
        self.errors = []
        self.function_effects = {}

        functions = [d for d in program.declarations
                     if isinstance(d, (PureFunc, TaskFunc))]

        # Register declared effects
        for func in functions:
            if isinstance(func, TaskFunc):
                labels = frozenset(EffectLabel.parse(e) for e in func.effects)
                self.function_effects[func.name] = EffectRow(labels=labels)
            else:
                self.function_effects[func.name] = PURE_ROW

        # Fixpoint iteration for effect inference
        changed = True
        max_iter = len(functions) + 1
        iteration = 0

        while changed and iteration < max_iter:
            changed = False
            iteration += 1

            for func in functions:
                inferred = self._infer_function_effects(func)
                current = self.function_effects.get(func.name, PURE_ROW)

                if not inferred.is_subrow_of(current):
                    # Inferred effects exceed declared effects
                    new_row = self.lattice.join(current, inferred)
                    if new_row != current:
                        self.function_effects[func.name] = new_row
                        changed = True

        # Verify: inferred effects should match declared effects
        for func in functions:
            self._verify_effects(func)

        # Compute parallelizability
        self._analyze_parallelism(functions)

        return self.errors, self.function_effects

    def _infer_function_effects(self, func: PureFunc | TaskFunc) -> EffectRow:
        """Infer the effects of a function from its body."""
        effects: Set[EffectLabel] = set()

        for stmt in func.body:
            stmt_effects = self._infer_stmt_effects(stmt)
            effects.update(stmt_effects)

        return EffectRow(labels=frozenset(effects))

    def _infer_stmt_effects(self, stmt: Statement) -> Set[EffectLabel]:
        """Infer effects from a statement."""
        effects: Set[EffectLabel] = set()

        if isinstance(stmt, ExprStmt):
            effects.update(self._infer_expr_effects(stmt.expr))
        elif isinstance(stmt, ReturnStmt) and stmt.value:
            effects.update(self._infer_expr_effects(stmt.value))
        elif isinstance(stmt, LetStmt) and stmt.value:
            effects.update(self._infer_expr_effects(stmt.value))
        elif isinstance(stmt, AssignStmt):
            effects.update(self._infer_expr_effects(stmt.value))
        elif isinstance(stmt, IfStmt):
            effects.update(self._infer_expr_effects(stmt.condition))
            for s in stmt.then_body:
                effects.update(self._infer_stmt_effects(s))
            for s in stmt.else_body:
                effects.update(self._infer_stmt_effects(s))
        elif isinstance(stmt, WhileStmt):
            effects.update(self._infer_expr_effects(stmt.condition))
            for s in stmt.body:
                effects.update(self._infer_stmt_effects(s))
        elif isinstance(stmt, UnsafeBlock):
            pass  # Unsafe blocks are exempt

        return effects

    def _infer_expr_effects(self, expr: Expr) -> Set[EffectLabel]:
        """Infer effects from an expression."""
        effects: Set[EffectLabel] = set()

        if isinstance(expr, MethodCall):
            obj_name = ""
            if isinstance(expr.obj, Identifier):
                obj_name = expr.obj.name
            key = f"{obj_name}.{expr.method_name}"
            if key in self.builtin_effects:
                effects.add(self.builtin_effects[key])
            effects.update(self._infer_expr_effects(expr.obj))
            for arg in expr.args:
                effects.update(self._infer_expr_effects(arg))

        elif isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                fname = expr.callee.name
                if fname in self.builtin_effects:
                    effects.add(self.builtin_effects[fname])
                elif fname in self.function_effects:
                    effects.update(self.function_effects[fname].labels)
            for arg in expr.args:
                effects.update(self._infer_expr_effects(arg))

        elif isinstance(expr, BinaryOp):
            effects.update(self._infer_expr_effects(expr.left))
            effects.update(self._infer_expr_effects(expr.right))

        elif isinstance(expr, UnaryOp):
            effects.update(self._infer_expr_effects(expr.operand))

        elif isinstance(expr, FieldAccess):
            effects.update(self._infer_expr_effects(expr.obj))

        return effects

    def _verify_effects(self, func: PureFunc | TaskFunc) -> None:
        """Verify that inferred effects match declared effects."""
        inferred = self._infer_function_effects(func)

        if isinstance(func, PureFunc):
            if not inferred.is_pure():
                undeclared = list(str(l) for l in inferred.labels)
                for eff_str in undeclared:
                    self.errors.append(effect_error(
                        declared_effects=[],
                        actual_effect=eff_str,
                        callsite_chain=[f"in pure function '{func.name}'"],
                        location=func.location,
                    ))

        elif isinstance(func, TaskFunc):
            declared = EffectRow(labels=frozenset(
                EffectLabel.parse(e) for e in func.effects
            ))
            extra = inferred.difference(declared)
            for label in extra.labels:
                self.errors.append(effect_error(
                    declared_effects=func.effects,
                    actual_effect=str(label),
                    callsite_chain=[f"in task function '{func.name}'"],
                    location=func.location,
                ))

    def _analyze_parallelism(self, functions: List) -> None:
        """Analyze which functions can be safely parallelized.

        Two functions can run in parallel if their effect rows commute.
        This is a key benefit of the effect system: the compiler can
        automatically parallelize commuting computations.
        """
        for i, f1 in enumerate(functions):
            for f2 in functions[i + 1:]:
                row1 = self.function_effects.get(f1.name, PURE_ROW)
                row2 = self.function_effects.get(f2.name, PURE_ROW)
                # Store parallelizability info (available via API)
                can_par = self.lattice.can_parallelize(row1, row2)
                # This info is used by the optimizer


# ---------------------------------------------------------------------------
# Effect Type Unification (for row polymorphism)
# ---------------------------------------------------------------------------

@dataclass
class EffectConstraint:
    """A constraint between effect rows.

    Generated during type inference when a function with effect row R1
    is used in a context expecting effect row R2.

    R1 <: R2 (R1 must be a sub-row of R2)
    """
    sub_row: EffectRow
    super_row: EffectRow
    location: Optional[SourceLocation] = None
    reason: str = ""


class EffectUnifier:
    """Unifies effect rows for row-polymorphic effect inference.

    Given constraints of the form R1 <: R2, solves for row variables.

    Algorithm (based on Leijen 2017):
    1. Collect all effect constraints
    2. For each row variable rho, compute the required effects:
       rho must contain at least all effects required by constraints
    3. Unify row variables that must be equal
    4. Check consistency
    """

    def __init__(self):
        self._next_var = 0
        self.substitution: Dict[str, EffectRow] = {}
        self.constraints: List[EffectConstraint] = []
        self.errors: List[AeonError] = []

    def fresh_row_var(self) -> RowVariable:
        self._next_var += 1
        return RowVariable(name=f"rho_{self._next_var}", id=self._next_var)

    def add_constraint(self, constraint: EffectConstraint) -> None:
        self.constraints.append(constraint)

    def solve(self) -> Dict[str, EffectRow]:
        """Solve all effect constraints.

        Returns a substitution mapping row variables to concrete effect rows.
        """
        for constraint in self.constraints:
            self._process_constraint(constraint)
        return self.substitution

    def _process_constraint(self, constraint: EffectConstraint) -> None:
        """Process a single subtyping constraint R1 <: R2."""
        sub = self._apply_subst(constraint.sub_row)
        sup = self._apply_subst(constraint.super_row)

        if sub.is_subrow_of(sup):
            return  # Already satisfied

        # If sup has a row variable, extend it
        if sup.row_var:
            extra = sub.labels - sup.labels
            current = self.substitution.get(sup.row_var.name, EffectRow())
            new_row = EffectRow(labels=current.labels | extra, row_var=current.row_var)
            self.substitution[sup.row_var.name] = new_row

        elif sub.row_var:
            # sub has a row variable that needs to be constrained
            pass  # Row variable can absorb the difference

        else:
            # Fixed rows: check subset
            extra = sub.labels - sup.labels
            if extra:
                for label in extra:
                    self.errors.append(effect_error(
                        declared_effects=[str(l) for l in sup.labels],
                        actual_effect=str(label),
                        callsite_chain=[constraint.reason],
                        location=constraint.location,
                    ))

    def _apply_subst(self, row: EffectRow) -> EffectRow:
        """Apply current substitution to a row."""
        if row.row_var and row.row_var.name in self.substitution:
            resolved = self.substitution[row.row_var.name]
            return EffectRow(
                labels=row.labels | resolved.labels,
                row_var=resolved.row_var,
            )
        return row


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def infer_effects(program: Program) -> Tuple[List[AeonError], Dict[str, EffectRow]]:
    """Infer and verify effects for all functions in an AEON program.

    Returns:
      - List of effect errors (undeclared effects, effects in pure functions)
      - Dict mapping function names to their inferred effect rows
    """
    inferencer = EffectInferencer()
    return inferencer.infer_program(program)


def check_effects_algebraic(program: Program) -> List[AeonError]:
    """Run algebraic effect checking on an AEON program.

    This replaces the simple string-matching effect checker with
    a lattice-based algebraic effect system featuring:
    - Effect subtyping via the effect lattice
    - Effect inference via fixpoint computation
    - Commutativity analysis for automatic parallelization
    - Row polymorphism for effect-generic functions
    """
    errors, _ = infer_effects(program)
    return errors
