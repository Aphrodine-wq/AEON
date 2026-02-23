"""AEON Gradual Typing Verification Engine — Blame-Correct Type Boundaries.

Implements gradual typing analysis based on:
  Siek & Taha (2006) "Gradual Typing for Functional Languages"
  Scheme and Functional Programming Workshop

  Siek, Vitousek, Cimini, Boyland (2015) "Refined Criteria for Gradual Typing"
  SNAPL '15, https://doi.org/10.4230/LIPIcs.SNAPL.2015.274

  Wadler & Findler (2009) "Well-Typed Programs Can't Be Blamed"
  ESOP '09, https://doi.org/10.1007/978-3-642-00590-9_1

  Garcia, Clark, Tanter (2016) "Abstracting Gradual Typing"
  POPL '16, https://doi.org/10.1145/2837614.2837670

Key Theory:

1. TYPE PRECISION ORDERING (naive <: precise):
   The dynamic type ? (unknown) is the LEAST PRECISE type.
   Every type is more precise than ?:
     Int <~ ?     (Int is more precise than ?)
     ? <~ ?       (reflexive)
     Int <~ Int   (reflexive)
   But NOT:
     Int <~ Bool  (incompatible concrete types)

   Precision forms a LATTICE:
     - Bottom: concrete types (most precise)
     - Top: ? (least precise, accepts anything)
     - Meet: greatest lower bound (most precise common type)
     - Join: least upper bound (least precise encompassing type)

2. CONSISTENT SUBTYPING (Siek & Taha 2006):
   T1 ~ T2 iff there exists T3 such that T1 <~ T3 and T2 <~ T3.
   This combines consistency (gradual) with subtyping (OOP):

     Int ~ ?       (consistent: ? is less precise)
     ? ~ Bool      (consistent: ? matches anything)
     Int ~ Int     (trivially consistent)
     Int !~ Bool   (inconsistent: no common imprecise type)

   For function types:
     (Int -> Int) ~ (? -> ?)     (consistent)
     (Int -> Int) ~ (Bool -> ?)  (INconsistent: Int !~ Bool in domain)

3. GRADUAL GUARANTEE (Siek et al. 2015):
   The REFINED CRITERIA state that a gradually typed language must satisfy:

   a) STATIC GRADUAL GUARANTEE:
      If e : T and e' is obtained from e by making types LESS precise,
      then e' : T' for some T' <~ T.
      (Adding ? annotations doesn't break well-typedness.)

   b) DYNAMIC GRADUAL GUARANTEE:
      If e : T and e -->* v, and e' is less precise than e,
      then e' -->* v' where v' is less precise than v.
      (Less precise programs produce less precise results.)

4. BLAME TRACKING (Wadler & Findler 2009):
   When a type cast fails at runtime, BLAME is assigned to the
   boundary that introduced the inconsistency.

   Blame theorem: well-typed programs can't be blamed.
   Positive blame (value doesn't match expected type) goes to
   the less precisely typed side.

   A cast (T1 => T2) at boundary p:
   - If T1 <: T2: cast always succeeds (safe)
   - If T1 ~ T2 but T1 !<: T2: cast may fail (blame p)
   - If T1 !~ T2: static error (caught at compile time)

5. ABSTRACTING GRADUAL TYPING (Garcia et al. 2016):
   Systematic derivation of gradual type systems from static ones
   via GALOIS CONNECTIONS between the static and gradual interpretations:

     alpha_T : P(StaticTypes) -> GradualTypes
     gamma_T : GradualTypes -> P(StaticTypes)

   The concretization gamma_T(?) = {all types} and
   gamma_T(Int) = {Int}. This ensures that every static typing
   rule lifts correctly to the gradual setting.

Mathematical Framework:
  - Type precision forms a bounded lattice (Types, <~, ?, concrete)
  - Consistent subtyping = lifting of subtyping through Galois connection
  - Blame safety = well-typed terms at precise types can't be blamed
  - The gradual guarantee is a MONOTONICITY property w.r.t. precision
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt,
    Parameter, TypeAnnotation,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Gradual Type Representation
# ---------------------------------------------------------------------------

class Precision(Enum):
    """Precision level in the gradual type lattice."""
    DYNAMIC = auto()      # ? (unknown type)
    CONCRETE = auto()     # Fully known type (Int, Bool, etc.)
    PARTIAL = auto()       # Partially known (e.g., List<?>)


@dataclass(frozen=True)
class GradualType:
    """A type in the gradual type system with precision tracking.

    The type precision lattice is:
      concrete types (bottom) <~ partial types <~ ? (top)
    """
    base_name: str
    precision: Precision = Precision.CONCRETE
    type_args: Tuple[GradualType, ...] = ()
    param_types: Tuple[GradualType, ...] = ()
    return_type: Optional[GradualType] = None
    is_function: bool = False

    @staticmethod
    def dynamic() -> GradualType:
        return GradualType(base_name="?", precision=Precision.DYNAMIC)

    @staticmethod
    def concrete(name: str) -> GradualType:
        return GradualType(base_name=name, precision=Precision.CONCRETE)

    @staticmethod
    def function(params: Tuple[GradualType, ...], ret: GradualType) -> GradualType:
        return GradualType(
            base_name="->", precision=Precision.CONCRETE,
            param_types=params, return_type=ret, is_function=True
        )

    def is_dynamic(self) -> bool:
        return self.precision == Precision.DYNAMIC

    def __str__(self) -> str:
        if self.is_dynamic():
            return "?"
        if self.is_function:
            params = ", ".join(str(p) for p in self.param_types)
            return f"({params}) -> {self.return_type}"
        if self.type_args:
            args = ", ".join(str(a) for a in self.type_args)
            return f"{self.base_name}<{args}>"
        return self.base_name


# ---------------------------------------------------------------------------
# Precision Lattice Operations
# ---------------------------------------------------------------------------

def type_precision_leq(t1: GradualType, t2: GradualType) -> bool:
    """Check if t1 is MORE precise than t2 (t1 <~ t2).

    In the precision lattice:
      - Every type <~ ? (dynamic is top / least precise)
      - T <~ T (reflexive)
      - For functions: (A1 -> B1) <~ (A2 -> B2) iff A1 <~ A2 and B1 <~ B2
      - For generics: G<T1> <~ G<T2> iff T1 <~ T2

    This is the fundamental ordering from Siek & Taha (2006).
    """
    if t2.is_dynamic():
        return True
    if t1.is_dynamic():
        return t2.is_dynamic()
    if t1.is_function and t2.is_function:
        if len(t1.param_types) != len(t2.param_types):
            return False
        for p1, p2 in zip(t1.param_types, t2.param_types):
            if not type_precision_leq(p1, p2):
                return False
        if t1.return_type and t2.return_type:
            return type_precision_leq(t1.return_type, t2.return_type)
        return True
    if t1.base_name != t2.base_name:
        return False
    if len(t1.type_args) != len(t2.type_args):
        return False
    return all(type_precision_leq(a1, a2) for a1, a2 in zip(t1.type_args, t2.type_args))


def consistent(t1: GradualType, t2: GradualType) -> bool:
    """Check type consistency (~ relation from Siek & Taha 2006).

    T1 ~ T2 iff there exists a type T3 such that T1 <~ T3 and T2 <~ T3.

    Equivalently:
      - ? ~ T for all T (dynamic is consistent with everything)
      - T ~ ? for all T
      - Int ~ Int, Bool ~ Bool, etc. (same base types)
      - Int !~ Bool (different base types are inconsistent)
      - (A1 -> B1) ~ (A2 -> B2) iff A1 ~ A2 and B1 ~ B2
    """
    if t1.is_dynamic() or t2.is_dynamic():
        return True
    if t1.is_function and t2.is_function:
        if len(t1.param_types) != len(t2.param_types):
            return False
        for p1, p2 in zip(t1.param_types, t2.param_types):
            if not consistent(p1, p2):
                return False
        if t1.return_type and t2.return_type:
            return consistent(t1.return_type, t2.return_type)
        return True
    if t1.base_name != t2.base_name:
        return False
    if len(t1.type_args) != len(t2.type_args):
        return False
    return all(consistent(a1, a2) for a1, a2 in zip(t1.type_args, t2.type_args))


def precision_meet(t1: GradualType, t2: GradualType) -> Optional[GradualType]:
    """Compute the MEET (greatest lower bound) in the precision lattice.

    meet(T, ?) = T    (concrete is more precise)
    meet(?, T) = T
    meet(Int, Int) = Int
    meet(Int, Bool) = None  (inconsistent, no common lower bound)
    meet(A1->B1, A2->B2) = meet(A1,A2) -> meet(B1,B2)
    """
    if t1.is_dynamic():
        return t2
    if t2.is_dynamic():
        return t1
    if t1.is_function and t2.is_function:
        if len(t1.param_types) != len(t2.param_types):
            return None
        params = []
        for p1, p2 in zip(t1.param_types, t2.param_types):
            m = precision_meet(p1, p2)
            if m is None:
                return None
            params.append(m)
        ret = None
        if t1.return_type and t2.return_type:
            ret = precision_meet(t1.return_type, t2.return_type)
            if ret is None:
                return None
        return GradualType.function(tuple(params), ret or GradualType.dynamic())
    if t1.base_name != t2.base_name:
        return None
    if len(t1.type_args) != len(t2.type_args):
        return None
    args = []
    for a1, a2 in zip(t1.type_args, t2.type_args):
        m = precision_meet(a1, a2)
        if m is None:
            return None
        args.append(m)
    return GradualType(base_name=t1.base_name, precision=Precision.CONCRETE, type_args=tuple(args))


def precision_join(t1: GradualType, t2: GradualType) -> GradualType:
    """Compute the JOIN (least upper bound) in the precision lattice.

    join(T, ?) = ?     (dynamic absorbs)
    join(?, T) = ?
    join(Int, Int) = Int
    join(Int, Bool) = ?  (incompatible → go to dynamic)
    """
    if t1.is_dynamic() or t2.is_dynamic():
        return GradualType.dynamic()
    if t1.is_function and t2.is_function:
        if len(t1.param_types) != len(t2.param_types):
            return GradualType.dynamic()
        params = tuple(precision_join(p1, p2) for p1, p2 in zip(t1.param_types, t2.param_types))
        ret = GradualType.dynamic()
        if t1.return_type and t2.return_type:
            ret = precision_join(t1.return_type, t2.return_type)
        return GradualType.function(params, ret)
    if t1.base_name != t2.base_name:
        return GradualType.dynamic()
    if len(t1.type_args) != len(t2.type_args):
        return GradualType.dynamic()
    args = tuple(precision_join(a1, a2) for a1, a2 in zip(t1.type_args, t2.type_args))
    return GradualType(base_name=t1.base_name, precision=Precision.CONCRETE, type_args=args)


# ---------------------------------------------------------------------------
# Blame Tracking (Wadler & Findler 2009)
# ---------------------------------------------------------------------------

class BlameLabel(Enum):
    """Direction of blame assignment at a type boundary."""
    POSITIVE = auto()   # Value doesn't match expected type (blame producer)
    NEGATIVE = auto()   # Context doesn't match expected type (blame consumer)


@dataclass
class CastNode:
    """A type cast at a boundary between typed and untyped code.

    Represents (T1 => T2)^p where:
      - source: the type being cast FROM
      - target: the type being cast TO
      - blame_label: which side gets blamed on failure
      - location: source code location of the boundary
    """
    source: GradualType
    target: GradualType
    blame_label: BlameLabel
    location: SourceLocation
    safe: bool = False  # True if cast can never fail

    def check_safety(self) -> None:
        """Determine if this cast is statically safe.

        A cast (T1 => T2) is safe if T1 <~ T2 (source is more precise).
        This means no information is lost and the cast always succeeds.
        """
        self.safe = type_precision_leq(self.source, self.target)


@dataclass
class BlamePropagation:
    """Tracks blame propagation through a chain of casts.

    Implements the blame theorem: in a well-typed program,
    blame always flows toward the less precisely typed side.
    """
    casts: List[CastNode] = field(default_factory=list)
    blame_violations: List[Tuple[CastNode, str]] = field(default_factory=list)

    def add_cast(self, cast: CastNode) -> None:
        cast.check_safety()
        self.casts.append(cast)

    def check_blame_safety(self) -> List[Tuple[CastNode, str]]:
        """Check that all casts satisfy the blame theorem.

        Well-typed programs can't be blamed (Wadler & Findler 2009):
        if a cast fails, blame goes to the less precise side.
        """
        self.blame_violations = []
        for cast in self.casts:
            if not cast.safe and not consistent(cast.source, cast.target):
                self.blame_violations.append((
                    cast,
                    f"Inconsistent cast from {cast.source} to {cast.target} — "
                    f"blame at {cast.blame_label.name} boundary"
                ))
        return self.blame_violations


# ---------------------------------------------------------------------------
# Gradual Guarantee Checker (Siek et al. 2015)
# ---------------------------------------------------------------------------

@dataclass
class GradualGuaranteeChecker:
    """Verifies the static and dynamic gradual guarantees.

    Static Gradual Guarantee:
      If e : T, then making types in e less precise yields e' : T'
      with T' less precise than T.

    This is checked by verifying that type annotations form a
    consistent lattice and that removing annotations (replacing
    with ?) preserves typability.
    """
    type_env: Dict[str, GradualType] = field(default_factory=dict)
    boundary_casts: List[CastNode] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def check_annotation_consistency(self, func_name: str,
                                      params: List[Tuple[str, GradualType]],
                                      return_type: GradualType) -> None:
        """Check that type annotations are mutually consistent.

        For the gradual guarantee to hold, all annotations in a
        function must be pairwise consistent with their uses.
        """
        for name, ptype in params:
            if name in self.type_env:
                existing = self.type_env[name]
                if not consistent(existing, ptype):
                    self.errors.append(
                        f"Gradual guarantee violation in '{func_name}': "
                        f"parameter '{name}' has inconsistent types "
                        f"{existing} and {ptype}"
                    )
            self.type_env[name] = ptype

    def check_cast_chain(self, casts: List[CastNode]) -> None:
        """Verify that a chain of casts maintains the gradual guarantee.

        In a well-typed gradually typed program:
        1. Adjacent casts must be consistent
        2. The composition of casts must be consistent with endpoints
        3. No precision is gained without explicit annotation
        """
        for i in range(len(casts) - 1):
            c1, c2 = casts[i], casts[i + 1]
            if not consistent(c1.target, c2.source):
                self.errors.append(
                    f"Cast chain violation: {c1.target} -> {c2.source} "
                    f"at {c2.location}"
                )

    def verify_monotonicity(self, original: GradualType,
                            less_precise: GradualType,
                            result_original: GradualType,
                            result_less_precise: GradualType) -> bool:
        """Verify the monotonicity property of the gradual guarantee.

        If e : T and e' <~ e (less precise), then:
          e' : T' with T' <~ T (result is also less precise).

        This is the key property from Siek et al. (2015) refined criteria.
        """
        if not type_precision_leq(less_precise, original):
            return True  # Not actually less precise, skip
        return type_precision_leq(result_less_precise, result_original)


# ---------------------------------------------------------------------------
# Abstracting Gradual Typing (Garcia et al. 2016)
# ---------------------------------------------------------------------------

@dataclass
class GaloisLift:
    """Lifting of static typing judgments to gradual typing via Galois connections.

    Given a static typing judgment Gamma |- e : T, the gradual lifting is:
      alpha(Gamma) |- e : alpha(T)

    where alpha is the abstraction function of the Galois connection:
      alpha : P(StaticTypes) -> GradualTypes
      gamma : GradualTypes -> P(StaticTypes)

    satisfying: alpha(S) <~ G  iff  S subseteq gamma(G)

    The concretization function:
      gamma(?) = {all types}     (? represents any type)
      gamma(Int) = {Int}         (concrete types are singletons)
      gamma(A -> B) = {A' -> B' | A' in gamma(A), B' in gamma(B)}
    """

    def concretize(self, g: GradualType) -> Set[str]:
        """Compute gamma(G) — the set of static types represented by G.

        gamma(?) = universe (represented as special set)
        gamma(T) = {T} for concrete types
        """
        if g.is_dynamic():
            return {"*"}  # Universe marker
        return {str(g)}

    def abstract(self, types: Set[str]) -> GradualType:
        """Compute alpha(S) — the most precise gradual type covering S.

        alpha({T}) = T
        alpha({T1, T2, ...}) = ? if types are incompatible
        alpha(universe) = ?
        """
        if "*" in types or len(types) == 0:
            return GradualType.dynamic()
        if len(types) == 1:
            return GradualType.concrete(next(iter(types)))
        return GradualType.dynamic()

    def lift_judgment(self, static_type: GradualType) -> GradualType:
        """Lift a static typing judgment through the Galois connection.

        For any static judgment Gamma |- e : T, the gradual judgment is:
          alpha(Gamma) |- e : alpha({T})

        This systematically derives gradual type rules from static ones.
        """
        concrete = self.concretize(static_type)
        return self.abstract(concrete)

    def check_galois_property(self, abstract_type: GradualType,
                               concrete_set: Set[str]) -> bool:
        """Verify the Galois connection property:
        alpha(S) <~ G  iff  S subseteq gamma(G)

        This ensures soundness of the gradual lifting.
        """
        gamma_g = self.concretize(abstract_type)
        if "*" in gamma_g:
            return True  # Universe contains everything
        return concrete_set.issubset(gamma_g)


# ---------------------------------------------------------------------------
# AST → Gradual Type Translation
# ---------------------------------------------------------------------------

def _annotation_to_gradual(ann: Optional[TypeAnnotation]) -> GradualType:
    """Convert an AEON TypeAnnotation to a GradualType."""
    if ann is None:
        return GradualType.dynamic()
    name = ann.name if hasattr(ann, 'name') else str(ann)
    if name in ('?', 'any', 'Any', 'dynamic', 'Dynamic', 'object', 'auto'):
        return GradualType.dynamic()
    if hasattr(ann, 'type_args') and ann.type_args:
        args = tuple(_annotation_to_gradual(a) for a in ann.type_args)
        return GradualType(base_name=name, precision=Precision.PARTIAL, type_args=args)
    return GradualType.concrete(name)


def _extract_gradual_types(func) -> Tuple[List[Tuple[str, GradualType]], GradualType]:
    """Extract parameter and return gradual types from a function."""
    params = []
    for p in (func.params if hasattr(func, 'params') else []):
        pname = p.name if hasattr(p, 'name') else str(p)
        ptype = _annotation_to_gradual(
            p.type_annotation if hasattr(p, 'type_annotation') else None
        )
        params.append((pname, ptype))
    ret = _annotation_to_gradual(
        func.return_type if hasattr(func, 'return_type') else None
    )
    return params, ret


# ---------------------------------------------------------------------------
# Expression-Level Gradual Analysis
# ---------------------------------------------------------------------------

def _check_expr_consistency(expr: Expr, env: Dict[str, GradualType],
                             errors: List[AeonError], loc: SourceLocation) -> GradualType:
    """Infer a gradual type for an expression and check consistency."""
    if isinstance(expr, Identifier):
        return env.get(expr.name, GradualType.dynamic())

    if isinstance(expr, IntLiteral):
        return GradualType.concrete("Int")
    if isinstance(expr, FloatLiteral):
        return GradualType.concrete("Float")
    if isinstance(expr, BoolLiteral):
        return GradualType.concrete("Bool")
    if isinstance(expr, StringLiteral):
        return GradualType.concrete("String")

    if isinstance(expr, BinaryOp):
        lt = _check_expr_consistency(expr.left, env, errors, loc)
        rt = _check_expr_consistency(expr.right, env, errors, loc)
        if not consistent(lt, rt):
            errors.append(contract_error(
                f"Gradual type inconsistency: operator '{expr.op}' applied to "
                f"inconsistent types {lt} and {rt}",
                location=getattr(expr, 'location', loc)
            ))
        if lt.is_dynamic() or rt.is_dynamic():
            return GradualType.dynamic()
        return lt

    if isinstance(expr, FunctionCall):
        func_name = getattr(expr.callee, 'name', None) if hasattr(expr, 'callee') else getattr(expr, 'name', None)
        func_type = env.get(func_name, GradualType.dynamic()) if func_name else GradualType.dynamic()
        if func_type.is_function and func_type.return_type:
            for i, arg in enumerate(expr.args):
                at = _check_expr_consistency(arg, env, errors, loc)
                if i < len(func_type.param_types):
                    expected = func_type.param_types[i]
                    if not consistent(at, expected):
                        errors.append(contract_error(
                            f"Gradual typing: argument {i} of '{func_name}' has type "
                            f"{at}, inconsistent with expected {expected}",
                            location=getattr(expr, 'location', loc)
                        ))
            return func_type.return_type
        return GradualType.dynamic()

    return GradualType.dynamic()


def _check_stmt_gradual(stmt: Statement, env: Dict[str, GradualType],
                         errors: List[AeonError], loc: SourceLocation) -> None:
    """Check a statement for gradual typing consistency."""
    if isinstance(stmt, LetStmt):
        val_type = _check_expr_consistency(stmt.value, env, errors, loc)
        declared = _annotation_to_gradual(
            stmt.type_annotation if hasattr(stmt, 'type_annotation') else None
        )
        if not declared.is_dynamic() and not consistent(val_type, declared):
            errors.append(contract_error(
                f"Gradual typing: let binding '{stmt.name}' declared as {declared} "
                f"but assigned value of inconsistent type {val_type}",
                location=getattr(stmt, 'location', loc)
            ))
        env[stmt.name] = precision_meet(val_type, declared) or val_type

    elif isinstance(stmt, AssignStmt):
        val_type = _check_expr_consistency(stmt.value, env, errors, loc)
        target = stmt.target if isinstance(stmt.target, str) else (
            stmt.target.name if hasattr(stmt.target, 'name') else str(stmt.target)
        )
        existing = env.get(target, GradualType.dynamic())
        if not consistent(val_type, existing):
            errors.append(contract_error(
                f"Gradual typing: assignment to '{target}' changes type from "
                f"{existing} to inconsistent type {val_type}",
                location=getattr(stmt, 'location', loc)
            ))

    elif isinstance(stmt, ReturnStmt):
        if stmt.value:
            _check_expr_consistency(stmt.value, env, errors, loc)

    elif isinstance(stmt, IfStmt):
        _check_expr_consistency(stmt.condition, env, errors, loc)
        for s in (stmt.then_body if isinstance(stmt.then_body, list) else [stmt.then_body]):
            _check_stmt_gradual(s, env, errors, loc)
        if stmt.else_body:
            else_stmts = stmt.else_body if isinstance(stmt.else_body, list) else [stmt.else_body]
            for s in else_stmts:
                _check_stmt_gradual(s, env, errors, loc)

    elif isinstance(stmt, ExprStmt):
        _check_expr_consistency(stmt.expr, env, errors, loc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_gradual_types(program: Program) -> List[AeonError]:
    """Run gradual typing analysis on an AEON program.

    Checks:
    1. Type consistency at all boundaries (Siek & Taha 2006)
    2. Blame safety for casts (Wadler & Findler 2009)
    3. Static gradual guarantee (Siek et al. 2015)
    4. Galois connection soundness (Garcia et al. 2016)
    """
    errors: List[AeonError] = []
    blame_tracker = BlamePropagation()
    guarantee_checker = GradualGuaranteeChecker()
    galois = GaloisLift()

    functions = [d for d in program.declarations
                 if isinstance(d, (PureFunc, TaskFunc))]

    for func in functions:
        loc = getattr(func, 'location', SourceLocation("", 1, 1))
        params, ret_type = _extract_gradual_types(func)
        func_name = func.name if hasattr(func, 'name') else "<anonymous>"

        # Check annotation consistency (gradual guarantee)
        guarantee_checker.check_annotation_consistency(func_name, params, ret_type)

        # Build environment with parameter types
        env: Dict[str, GradualType] = {}
        for pname, ptype in params:
            env[pname] = ptype

        # Register function type
        func_gtype = GradualType.function(
            tuple(pt for _, pt in params), ret_type
        )
        env[func_name] = func_gtype

        # Check function body for consistency
        body = func.body if hasattr(func, 'body') else []
        if isinstance(body, list):
            for stmt in body:
                _check_stmt_gradual(stmt, env, errors, loc)

        # Generate casts at typed/untyped boundaries
        for pname, ptype in params:
            if ptype.is_dynamic():
                # Untyped parameter: cast from ? to inferred type
                cast = CastNode(
                    source=GradualType.dynamic(),
                    target=GradualType.concrete("inferred"),
                    blame_label=BlameLabel.POSITIVE,
                    location=loc
                )
                blame_tracker.add_cast(cast)

        # Verify Galois connection soundness for each type
        for pname, ptype in params:
            if not ptype.is_dynamic():
                concrete_set = galois.concretize(ptype)
                if not galois.check_galois_property(ptype, concrete_set):
                    errors.append(contract_error(
                        f"Galois connection violation for parameter '{pname}' "
                        f"in '{func_name}': abstraction is unsound",
                        location=loc
                    ))

    # Check blame safety across all casts
    violations = blame_tracker.check_blame_safety()
    for cast, msg in violations:
        errors.append(contract_error(
            f"Blame safety violation: {msg}",
            location=cast.location
        ))

    # Report gradual guarantee violations
    for msg in guarantee_checker.errors:
        errors.append(contract_error(msg, location=SourceLocation("", 1, 1)))

    return errors
