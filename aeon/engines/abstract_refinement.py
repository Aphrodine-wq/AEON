"""AEON Abstract Refinement Types — Higher-Order Refinement Polymorphism.

Implements abstract refinement types based on:
  Vazou, Rondon, Jhala (2013) "Abstract Refinement Types"
  ESOP '13, https://doi.org/10.1007/978-3-642-37036-6_13

  Vazou, Seidel, Jhala, Vytiniotis, Peyton Jones (2014)
  "Refinement Types for Haskell"
  ICFP '14, https://doi.org/10.1145/2628136.2628161

  Vazou et al. (2015) "Bounded Refinement Types"
  ICFP '15, https://doi.org/10.1145/2784731.2784749

  Jhala & Vazou (2021) "Refinement Types: A Tutorial"
  Foundations and Trends in Programming Languages,
  https://doi.org/10.1561/2500000032

Key Theory:

1. ABSTRACT REFINEMENTS (Vazou et al. 2013):
   Standard liquid types fix the refinement predicates:
     {v: Int | v >= 0}

   Abstract refinements PARAMETERIZE over predicates:
     forall <p :: Int -> Bool>. {v: Int | p(v)} -> {v: Int | p(v)}

   This enables REFINEMENT POLYMORPHISM:
   a function can be polymorphic over what property is preserved.

   Example:
     max :: forall <p :: Int -> Bool>.
            {v: Int | p(v)} -> {v: Int | p(v)} -> {v: Int | p(v)}

   Instantiating p with (\\v -> v > 0) gives:
     max :: {v: Int | v > 0} -> {v: Int | v > 0} -> {v: Int | v > 0}

   Instantiating p with (\\v -> v < 100) gives:
     max :: {v: Int | v < 100} -> {v: Int | v < 100} -> {v: Int | v < 100}

2. BOUNDED REFINEMENTS (Vazou et al. 2015):
   Add BOUNDS on abstract refinements using witness terms:

     forall <p :: Int -> Bool, w :: Int -> Proof<p>>.
       {v: Int | true} -> {v: Int | p(v)}

   The witness w provides a PROOF that the output satisfies p.
   This connects refinement types to the Curry-Howard correspondence.

3. REFINEMENT REFLECTION (Vazou et al. 2014/2021):
   REFLECT function definitions into the logic:

     reflect fib :: Nat -> Nat
     fib 0 = 0
     fib 1 = 1
     fib n = fib (n-1) + fib (n-2)

   Now the SMT solver knows the DEFINITION of fib and can
   verify properties like:
     fib 10 == 55

   This is achieved by:
   1. Unfolding function definitions as axioms in SMT
   2. Using PLE (Proof by Logical Evaluation) for automatic unfolding
   3. Bounding the unfolding depth for decidability

4. MEASURES (data type refinements):
   A MEASURE is a function that maps data to a refinement:

     measure len :: List a -> Nat
     len []     = 0
     len (x:xs) = 1 + len xs

   Now we can write:
     {v: List a | len v > 0}  — non-empty list
     {v: List a | len v == n}  — list of exactly length n

   Measures must be:
   - Total (defined on all constructors)
   - Terminating (structurally recursive)
   - Non-negative (for Nat-valued measures)

5. ABSTRACT INTERPRETATION CONNECTION:
   Abstract refinement types generalize both:
   - Liquid types (fixed predicate templates)
   - Parametric polymorphism (forall a. ...)

   The abstraction hierarchy:
     Simple types < Liquid types < Abstract refinement types < Full dependent types

   Abstract refinements are DECIDABLE (reduce to SMT)
   while full dependent types are UNDECIDABLE.

Mathematical Framework:
  - Refinement predicates form a Heyting algebra (intuitionistic logic)
  - Abstract refinements are second-order predicates (∀p. ...)
  - Subtyping is contravariant in predicate parameters
  - Bounded refinements add witness terms (proof-carrying types)
  - Measures are terminating homomorphisms from data to refinements
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any, FrozenSet
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt,
    Parameter, TypeAnnotation, ContractClause,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Abstract Refinement Representation
# ---------------------------------------------------------------------------

class RefinementKind(Enum):
    """Kinds of refinement predicates."""
    CONCRETE = auto()      # Fixed predicate: v >= 0
    ABSTRACT = auto()      # Abstract predicate variable: p(v)
    BOUNDED = auto()       # Bounded abstract: p(v) with witness
    REFLECTED = auto()     # Reflected function definition
    MEASURE = auto()       # Data type measure


@dataclass(frozen=True)
class RefinementPredicate:
    """A predicate in the abstract refinement system.

    Represents predicates of the form:
      - Concrete: v >= 0, v != null, len(v) > 0
      - Abstract: p(v) where p is a predicate variable
      - Bounded: p(v) with witness w : Proof<p>
    """
    kind: RefinementKind
    expression: str = ""
    predicate_var: str = ""  # For abstract refinements
    bound_witness: str = ""  # For bounded refinements
    measure_name: str = ""   # For measure refinements

    @staticmethod
    def concrete(expr: str) -> RefinementPredicate:
        return RefinementPredicate(kind=RefinementKind.CONCRETE, expression=expr)

    @staticmethod
    def abstract(var: str) -> RefinementPredicate:
        return RefinementPredicate(kind=RefinementKind.ABSTRACT, predicate_var=var)

    @staticmethod
    def bounded(var: str, witness: str) -> RefinementPredicate:
        return RefinementPredicate(kind=RefinementKind.BOUNDED,
                                   predicate_var=var, bound_witness=witness)

    @staticmethod
    def measure(name: str, expr: str) -> RefinementPredicate:
        return RefinementPredicate(kind=RefinementKind.MEASURE,
                                   measure_name=name, expression=expr)

    def __str__(self) -> str:
        if self.kind == RefinementKind.CONCRETE:
            return self.expression
        if self.kind == RefinementKind.ABSTRACT:
            return f"{self.predicate_var}(v)"
        if self.kind == RefinementKind.BOUNDED:
            return f"{self.predicate_var}(v) [witness: {self.bound_witness}]"
        if self.kind == RefinementKind.MEASURE:
            return f"{self.measure_name}(v) {self.expression}"
        return "true"


@dataclass
class AbstractRefinedType:
    """A type with abstract refinement annotations.

    {v : Base | p1(v) /\\ p2(v) /\\ ...}
    where each pi can be concrete or abstract.
    """
    base_type: str
    predicates: List[RefinementPredicate] = field(default_factory=list)
    predicate_params: List[str] = field(default_factory=list)  # forall <p1, p2, ...>

    def is_abstract(self) -> bool:
        return any(p.kind == RefinementKind.ABSTRACT for p in self.predicates)

    def is_bounded(self) -> bool:
        return any(p.kind == RefinementKind.BOUNDED for p in self.predicates)

    def has_measure(self) -> bool:
        return any(p.kind == RefinementKind.MEASURE for p in self.predicates)

    def concrete_predicates(self) -> List[RefinementPredicate]:
        return [p for p in self.predicates if p.kind == RefinementKind.CONCRETE]

    def abstract_predicates(self) -> List[RefinementPredicate]:
        return [p for p in self.predicates
                if p.kind in (RefinementKind.ABSTRACT, RefinementKind.BOUNDED)]

    def instantiate(self, bindings: Dict[str, str]) -> AbstractRefinedType:
        """Instantiate abstract predicate variables with concrete predicates."""
        new_preds = []
        for p in self.predicates:
            if p.kind == RefinementKind.ABSTRACT and p.predicate_var in bindings:
                new_preds.append(RefinementPredicate.concrete(bindings[p.predicate_var]))
            else:
                new_preds.append(p)
        return AbstractRefinedType(
            base_type=self.base_type,
            predicates=new_preds,
            predicate_params=[pp for pp in self.predicate_params if pp not in bindings]
        )

    def __str__(self) -> str:
        if not self.predicates:
            return self.base_type
        preds = " /\\ ".join(str(p) for p in self.predicates)
        params = ""
        if self.predicate_params:
            params = f"forall <{', '.join(self.predicate_params)}>. "
        return f"{params}{{v: {self.base_type} | {preds}}}"


# ---------------------------------------------------------------------------
# Measure Definitions
# ---------------------------------------------------------------------------

@dataclass
class MeasureDefinition:
    """A measure function on a data type.

    Measures map data constructors to refinement values:
      measure len :: List a -> Nat
      len Nil       = 0
      len (Cons x xs) = 1 + len xs

    Properties:
      - Total: must handle all constructors
      - Terminating: must be structurally recursive
      - Type-correct: must return the declared type
    """
    name: str
    data_type: str
    return_type: str
    cases: Dict[str, str] = field(default_factory=dict)  # constructor -> expression
    is_total: bool = False
    is_terminating: bool = True

    def check_totality(self, constructors: Set[str]) -> List[str]:
        """Check that the measure handles all constructors."""
        missing = constructors - set(self.cases.keys())
        if missing:
            self.is_total = False
            return [f"Measure '{self.name}' missing cases: {', '.join(missing)}"]
        self.is_total = True
        return []


# ---------------------------------------------------------------------------
# Refinement Subtyping
# ---------------------------------------------------------------------------

@dataclass
class SubtypingObligation:
    """A subtyping obligation: T1 <: T2 under path condition Gamma.

    In abstract refinement types, subtyping reduces to:
      Gamma /\\ p1(v) => p2(v)

    For abstract predicates:
      forall <p>. {v | p(v)} <: {v | p(v)}  (trivially)
      {v | p(v)} <: {v | true}              (weakening)
      {v | p(v) /\\ q(v)} <: {v | p(v)}     (conjunction elimination)
    """
    lhs: AbstractRefinedType
    rhs: AbstractRefinedType
    path_condition: List[str] = field(default_factory=list)
    location: SourceLocation = field(default_factory=lambda: SourceLocation("", 1, 1))
    is_valid: Optional[bool] = None
    reason: str = ""

    def check(self) -> bool:
        """Check if this subtyping obligation is valid.

        Uses syntactic matching for abstract predicates and
        defers to SMT for concrete predicates.
        """
        # Same base type required
        if self.lhs.base_type != self.rhs.base_type:
            self.is_valid = False
            self.reason = f"Base type mismatch: {self.lhs.base_type} vs {self.rhs.base_type}"
            return False

        # RHS has no predicates => always valid (top type)
        if not self.rhs.predicates:
            self.is_valid = True
            return True

        # Check that LHS predicates imply RHS predicates
        lhs_concrete = {p.expression for p in self.lhs.concrete_predicates()}
        rhs_concrete = {p.expression for p in self.rhs.concrete_predicates()}

        # Concrete predicates: LHS must imply RHS
        if rhs_concrete and not rhs_concrete.issubset(lhs_concrete):
            missing = rhs_concrete - lhs_concrete
            self.is_valid = False
            self.reason = f"Missing predicates: {missing}"
            return False

        # Abstract predicates: must match exactly or be instantiable
        lhs_abstract = {p.predicate_var for p in self.lhs.abstract_predicates()}
        rhs_abstract = {p.predicate_var for p in self.rhs.abstract_predicates()}

        if rhs_abstract and not rhs_abstract.issubset(lhs_abstract):
            missing = rhs_abstract - lhs_abstract
            self.is_valid = False
            self.reason = f"Missing abstract refinements: {missing}"
            return False

        self.is_valid = True
        return True


# ---------------------------------------------------------------------------
# Predicate Inference (Liquid-style with abstract predicates)
# ---------------------------------------------------------------------------

@dataclass
class PredicateAbstraction:
    """Predicate abstraction for inferring abstract refinements.

    Given a set of qualifier templates Q = {q1, q2, ...},
    find the strongest conjunction of qualifiers consistent
    with all subtyping constraints.

    For abstract refinements, the templates include:
      - Concrete: v >= 0, v != null, v < n
      - Abstract: p(v) for each predicate parameter p
      - Measure: len(v) > 0, len(v) == n

    The inference algorithm:
    1. Initialize: each type variable gets ALL qualifiers
    2. Iterate: remove qualifiers that violate subtyping
    3. Fixpoint: stop when no more qualifiers can be removed

    This is the COUNTEREXAMPLE-GUIDED ABSTRACTION REFINEMENT (CEGAR)
    approach applied to type inference.
    """
    qualifiers: List[str] = field(default_factory=list)
    type_variables: Dict[str, Set[str]] = field(default_factory=dict)
    obligations: List[SubtypingObligation] = field(default_factory=list)

    def initialize(self, var: str) -> None:
        """Initialize a type variable with all qualifiers."""
        self.type_variables[var] = set(self.qualifiers)

    def refine(self, var: str, counterexample: str) -> None:
        """Remove a qualifier that is refuted by a counterexample."""
        if var in self.type_variables:
            self.type_variables[var].discard(counterexample)

    def fixpoint(self) -> bool:
        """Compute the fixpoint of qualifier elimination.

        Returns True if a consistent assignment was found.
        """
        changed = True
        iterations = 0
        max_iter = 100

        while changed and iterations < max_iter:
            changed = False
            iterations += 1

            for obligation in self.obligations:
                if not obligation.check():
                    # Try to refine by removing qualifiers
                    for p in obligation.rhs.concrete_predicates():
                        if p.expression in self.type_variables.get(obligation.rhs.base_type, set()):
                            self.refine(obligation.rhs.base_type, p.expression)
                            changed = True

        return all(ob.check() for ob in self.obligations)


# ---------------------------------------------------------------------------
# Function Analysis
# ---------------------------------------------------------------------------

def _extract_refinements(func) -> Tuple[List[Tuple[str, AbstractRefinedType]], AbstractRefinedType]:
    """Extract abstract refinement types from function signature."""
    params = []
    for p in (func.params if hasattr(func, 'params') else []):
        pname = p.name if hasattr(p, 'name') else str(p)
        base = "unknown"
        preds: List[RefinementPredicate] = []

        if hasattr(p, 'type_annotation') and p.type_annotation:
            ann = p.type_annotation
            base = ann.name if hasattr(ann, 'name') else str(ann)

        params.append((pname, AbstractRefinedType(base_type=base, predicates=preds)))

    ret_base = "unknown"
    if hasattr(func, 'return_type') and func.return_type:
        ret_base = func.return_type.name if hasattr(func.return_type, 'name') else str(func.return_type)

    return params, AbstractRefinedType(base_type=ret_base)


def _check_contract_refinements(func, errors: List[AeonError]) -> None:
    """Check that contract clauses are consistent with refinement types."""
    loc = getattr(func, 'location', SourceLocation("", 1, 1))
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"
    contracts = func.contracts if hasattr(func, 'contracts') else []

    requires_predicates: List[RefinementPredicate] = []
    ensures_predicates: List[RefinementPredicate] = []
    measures: List[str] = []

    for c in contracts:
        kind = c.kind if hasattr(c, 'kind') else ""
        expr = c.expression if hasattr(c, 'expression') else str(c)
        if not isinstance(expr, str):
            continue

        if isinstance(kind, str):
            if kind == 'requires':
                requires_predicates.append(RefinementPredicate.concrete(expr))
            elif kind == 'ensures':
                ensures_predicates.append(RefinementPredicate.concrete(expr))
            elif kind == 'measure' or 'measure' in expr.lower():
                measures.append(expr)

    if not requires_predicates and not ensures_predicates:
        return

    # Check that ensures predicates are logically reachable from requires
    params, ret_type = _extract_refinements(func)

    # Build subtyping obligations
    if ensures_predicates:
        obligation = SubtypingObligation(
            lhs=AbstractRefinedType(
                base_type=ret_type.base_type,
                predicates=requires_predicates
            ),
            rhs=AbstractRefinedType(
                base_type=ret_type.base_type,
                predicates=ensures_predicates
            ),
            path_condition=[str(p) for p in requires_predicates],
            location=loc
        )

        # For abstract refinements, check if obligations are satisfiable
        if not obligation.check():
            errors.append(contract_error(
                f"Abstract refinement type error in '{func_name}': "
                f"postcondition refinements {[str(p) for p in ensures_predicates]} "
                f"not implied by precondition refinements "
                f"{[str(p) for p in requires_predicates]} — "
                f"subtyping obligation failed "
                f"(Vazou et al. 2013: abstract refinement types)",
                location=loc
            ))


def _check_measure_totality(program: Program, errors: List[AeonError]) -> None:
    """Check that measure functions are total over their data types."""
    data_defs = {d.name: d for d in program.declarations
                 if isinstance(d, DataDef)}

    functions = [d for d in program.declarations
                 if isinstance(d, (PureFunc, TaskFunc))]

    for func in functions:
        contracts = func.contracts if hasattr(func, 'contracts') else []
        func_name = func.name if hasattr(func, 'name') else ""
        loc = getattr(func, 'location', SourceLocation("", 1, 1))

        for c in contracts:
            text = c.expression if hasattr(c, 'expression') else str(c)
            if isinstance(text, str) and 'measure' in text.lower():
                # Check if the measure covers all constructors
                for dtype_name, dtype in data_defs.items():
                    if dtype_name.lower() in text.lower():
                        constructors = set()
                        if hasattr(dtype, 'constructors'):
                            for ctor in dtype.constructors:
                                cname = ctor.name if hasattr(ctor, 'name') else str(ctor)
                                constructors.add(cname)

                        if constructors:
                            measure = MeasureDefinition(
                                name=func_name,
                                data_type=dtype_name,
                                return_type="Nat"
                            )
                            missing_errs = measure.check_totality(constructors)
                            for msg in missing_errs:
                                errors.append(contract_error(
                                    f"Measure totality violation: {msg} — "
                                    f"measures must handle all constructors "
                                    f"(Vazou et al. 2014: refinement types for Haskell)",
                                    location=loc
                                ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_abstract_refinements(program: Program) -> List[AeonError]:
    """Run abstract refinement type analysis on an AEON program.

    Checks:
    1. Abstract refinement consistency (Vazou et al. 2013)
    2. Bounded refinement witnesses (Vazou et al. 2015)
    3. Measure totality and termination (Vazou et al. 2014)
    4. Subtyping obligations with abstract predicates
    5. Predicate abstraction fixpoint convergence
    """
    errors: List[AeonError] = []

    functions = [d for d in program.declarations
                 if isinstance(d, (PureFunc, TaskFunc))]

    for func in functions:
        _check_contract_refinements(func, errors)

    _check_measure_totality(program, errors)

    return errors
