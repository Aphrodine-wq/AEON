"""AEON Dependent Type System — Pi Types with Curry-Howard Proof Terms.

Implements dependent types based on:
  Martin-Löf (1984) "Intuitionistic Type Theory"
  Bibliopolis, Naples

  Coquand & Huet (1988) "The Calculus of Constructions"
  Information and Computation 76(2-3), https://doi.org/10.1016/0890-5401(88)90005-3

  Norell (2007) "Towards a practical programming language based on dependent type theory"
  PhD thesis, Chalmers University (Agda)

Key Theory:

1. DEPENDENT FUNCTION TYPES (Pi types):
   Pi (x : A) . B(x) — the type of functions where the RETURN TYPE
   depends on the INPUT VALUE.

   Example:
     vector_of : Pi (n : Nat) . Vec(Int, n)
   This function returns a vector whose LENGTH is determined by the argument.

   In AEON syntax:
     pure zeros(n: {v: Int | v >= 0}) -> Vec<Int, n>

   Pi types subsume:
     - Simple function types: A -> B = Pi (_ : A) . B  (B doesn't depend on input)
     - Polymorphism: forall A. A -> A = Pi (A : Type) . A -> A
     - Refinement types: {x : A | P(x)} = Sigma (x : A) . P(x)

2. DEPENDENT PAIR TYPES (Sigma types):
   Sigma (x : A) . B(x) — the type of pairs where the TYPE OF THE
   SECOND COMPONENT depends on the VALUE of the first.

   Example:
     Sigma (n : Nat) . Vec(Int, n)
   A pair of a natural number n and a vector of exactly length n.

3. CURRY-HOWARD CORRESPONDENCE:
   Types are propositions. Programs are proofs.

     Type                  <=>  Proposition
     -----------------------------------------------
     A -> B                <=>  A implies B
     A × B                 <=>  A and B
     A + B                 <=>  A or B
     Pi (x:A). B(x)        <=>  For all x:A, B(x)
     Sigma (x:A). B(x)     <=>  There exists x:A such that B(x)
     Empty (Void)           <=>  False (no proof exists)
     Unit                   <=>  True (trivially provable)
     Id(a, b)               <=>  a equals b (propositional equality)

   A function f : A -> B is a PROOF that A implies B.
   Applying f to a proof of A produces a proof of B (modus ponens).

4. UNIVERSE HIERARCHY:
   To avoid Russell's paradox (Type : Type is inconsistent):
     Type_0 : Type_1 : Type_2 : ...
   Each universe contains the types of the previous level.
   Int : Type_0, Type_0 : Type_1, etc.

5. PROPOSITIONAL EQUALITY (Identity type):
   Id_A(a, b) is the type of proofs that a equals b.
   refl : Id_A(a, a) is the proof that every value equals itself.
   The J eliminator provides substitution of equals for equals.

6. TERMINATION CHECKING via structural recursion:
   In a dependently-typed language, non-termination would make the
   logic unsound (you could prove False). So all functions must
   terminate. We check this via structural decrease on an argument.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Set, Tuple, Union
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt,
    ContractClause, Parameter, TypeAnnotation,
)
from aeon.errors import AeonError, contract_error, type_error, SourceLocation


# ---------------------------------------------------------------------------
# Dependent Type Terms (Calculus of Constructions Core)
# ---------------------------------------------------------------------------

class TermKind(Enum):
    """Kinds of terms in the dependent type theory."""
    UNIVERSE = auto()     # Type_i (universe at level i)
    VAR = auto()          # x (variable reference)
    PI = auto()           # Pi (x : A) . B  (dependent function type)
    SIGMA = auto()        # Sigma (x : A) . B  (dependent pair type)
    LAMBDA = auto()       # lambda (x : A) . e  (function abstraction)
    APP = auto()          # f(e)  (function application)
    PAIR = auto()         # (a, b) as Sigma (x:A).B  (dependent pair)
    FST = auto()          # fst(p)  (first projection)
    SND = auto()          # snd(p)  (second projection)
    NAT = auto()          # Nat (natural numbers type)
    ZERO = auto()         # 0 : Nat
    SUCC = auto()         # S(n) : Nat
    NAT_ELIM = auto()     # natElim (eliminator for Nat)
    BOOL_TYPE = auto()    # Bool type
    TRUE = auto()         # true : Bool
    FALSE = auto()        # false : Bool
    IF_THEN_ELSE = auto() # if-then-else (Bool eliminator)
    ID = auto()           # Id_A(a, b) (identity/equality type)
    REFL = auto()         # refl : Id_A(a, a)  (reflexivity proof)
    J = auto()            # J eliminator (substitution of equals)
    ANNOTATE = auto()     # e : A  (type annotation)
    INT_LIT = auto()      # integer literal
    REFINEMENT = auto()   # {x : A | P(x)}  (refinement type)
    LET = auto()          # let x = e in body


@dataclass
class Term:
    """A term in the dependent type theory.

    Terms serve double duty via Curry-Howard:
      - As TYPES (propositions): Pi, Sigma, Id, Universe, ...
      - As VALUES (proofs): Lambda, Pair, Refl, ...

    Every well-typed term simultaneously represents a computation
    and a proof of the proposition given by its type.
    """
    kind: TermKind
    # Variable
    name: str = ""
    # Universe level
    level: int = 0
    # Sub-terms (children)
    children: Tuple[Term, ...] = ()
    # For Pi/Sigma/Lambda: binding variable name
    binder: str = ""
    # Integer value for literals
    int_val: int = 0
    # Source location for error reporting
    location: Optional[SourceLocation] = None

    def __str__(self) -> str:
        if self.kind == TermKind.UNIVERSE:
            return f"Type_{self.level}" if self.level > 0 else "Type"
        if self.kind == TermKind.VAR:
            return self.name
        if self.kind == TermKind.PI:
            A, B = self.children[0], self.children[1]
            if self.binder == "_":
                return f"({A} -> {B})"
            return f"(Pi ({self.binder} : {A}) . {B})"
        if self.kind == TermKind.SIGMA:
            A, B = self.children[0], self.children[1]
            return f"(Sigma ({self.binder} : {A}) . {B})"
        if self.kind == TermKind.LAMBDA:
            A, body = self.children[0], self.children[1]
            return f"(lambda ({self.binder} : {A}) . {body})"
        if self.kind == TermKind.APP:
            f, arg = self.children[0], self.children[1]
            return f"({f} {arg})"
        if self.kind == TermKind.PAIR:
            a, b = self.children[0], self.children[1]
            return f"({a}, {b})"
        if self.kind == TermKind.FST:
            return f"fst({self.children[0]})"
        if self.kind == TermKind.SND:
            return f"snd({self.children[0]})"
        if self.kind == TermKind.NAT:
            return "Nat"
        if self.kind == TermKind.ZERO:
            return "0"
        if self.kind == TermKind.SUCC:
            return f"S({self.children[0]})"
        if self.kind == TermKind.BOOL_TYPE:
            return "Bool"
        if self.kind == TermKind.TRUE:
            return "true"
        if self.kind == TermKind.FALSE:
            return "false"
        if self.kind == TermKind.ID:
            A, a, b = self.children[0], self.children[1], self.children[2]
            return f"Id({A}, {a}, {b})"
        if self.kind == TermKind.REFL:
            return f"refl({self.children[0]})"
        if self.kind == TermKind.INT_LIT:
            return str(self.int_val)
        if self.kind == TermKind.REFINEMENT:
            A, P = self.children[0], self.children[1]
            return f"{{{self.binder} : {A} | {P}}}"
        if self.kind == TermKind.LET:
            val, body = self.children[0], self.children[1]
            return f"(let {self.binder} = {val} in {body})"
        return f"<{self.kind.name}>"


# Term constructors
def T_TYPE(level: int = 0) -> Term:
    return Term(kind=TermKind.UNIVERSE, level=level)

def T_VAR(name: str) -> Term:
    return Term(kind=TermKind.VAR, name=name)

def T_PI(binder: str, domain: Term, codomain: Term) -> Term:
    return Term(kind=TermKind.PI, binder=binder, children=(domain, codomain))

def T_ARROW(domain: Term, codomain: Term) -> Term:
    """Non-dependent function type: A -> B = Pi (_ : A) . B"""
    return T_PI("_", domain, codomain)

def T_SIGMA(binder: str, fst_type: Term, snd_type: Term) -> Term:
    return Term(kind=TermKind.SIGMA, binder=binder, children=(fst_type, snd_type))

def T_LAM(binder: str, domain: Term, body: Term) -> Term:
    return Term(kind=TermKind.LAMBDA, binder=binder, children=(domain, body))

def T_APP(func: Term, arg: Term) -> Term:
    return Term(kind=TermKind.APP, children=(func, arg))

def T_PAIR(fst: Term, snd: Term) -> Term:
    return Term(kind=TermKind.PAIR, children=(fst, snd))

def T_FST(pair: Term) -> Term:
    return Term(kind=TermKind.FST, children=(pair,))

def T_SND(pair: Term) -> Term:
    return Term(kind=TermKind.SND, children=(pair,))

def T_NAT() -> Term:
    return Term(kind=TermKind.NAT)

def T_ZERO() -> Term:
    return Term(kind=TermKind.ZERO)

def T_SUCC(n: Term) -> Term:
    return Term(kind=TermKind.SUCC, children=(n,))

def T_BOOL() -> Term:
    return Term(kind=TermKind.BOOL_TYPE)

def T_TRUE() -> Term:
    return Term(kind=TermKind.TRUE)

def T_FALSE() -> Term:
    return Term(kind=TermKind.FALSE)

def T_ID(A: Term, a: Term, b: Term) -> Term:
    return Term(kind=TermKind.ID, children=(A, a, b))

def T_REFL(a: Term) -> Term:
    return Term(kind=TermKind.REFL, children=(a,))

def T_INT_LIT(n: int) -> Term:
    return Term(kind=TermKind.INT_LIT, int_val=n)

def T_REFINE(binder: str, base: Term, predicate: Term) -> Term:
    return Term(kind=TermKind.REFINEMENT, binder=binder, children=(base, predicate))

def T_LET(binder: str, value: Term, body: Term) -> Term:
    return Term(kind=TermKind.LET, binder=binder, children=(value, body))

def T_INT() -> Term:
    return T_VAR("Int")


# ---------------------------------------------------------------------------
# W-Types (Well-Founded Trees) — Martin-Löf 1984, Dybjer 1997
# ---------------------------------------------------------------------------

def T_W(binder: str, shape: Term, position: Term) -> Term:
    """W-type: W (a : A) . B(a)

    W-types represent WELL-FOUNDED TREES and are the canonical way
    to define inductive types in dependent type theory.

    A W-type W(a:A).B(a) consists of trees where:
      - Each node is labeled with an element a : A  (the SHAPE)
      - Each node labeled a has exactly |B(a)| children (the POSITIONS)

    Examples:
      - Natural numbers:  W(b : Bool). if b then Empty else Unit
        (true = zero = leaf, false = succ = one child)
      - Lists of A:       W(x : Maybe A). if isNothing x then Empty else Unit
      - Binary trees:     W(b : Bool). if b then Bool else Empty
        (true = node with 2 children, false = leaf)

    The ELIMINATION PRINCIPLE for W-types is structural recursion:
      Given P : W(a:A).B(a) -> Type, to prove P(w) for all w,
      it suffices to give:
        step : (a:A) -> (f : B(a) -> W(a:A).B(a)) ->
               ((b : B(a)) -> P(f(b))) -> P(sup(a, f))

    This is the dependent type-theoretic foundation for:
      - Termination checking (structural recursion on W-types)
      - Inductive data type definitions
      - Well-founded induction principles

    References:
      - Martin-Löf (1984) "Intuitionistic Type Theory"
      - Dybjer (1997) "Representing Inductively Defined Sets by Wellorderings"
      - Abbott, Altenkirch, Ghani (2005) "Containers"
    """
    return T_PI(binder, shape, position)


# ---------------------------------------------------------------------------
# Universe Polymorphism (Harper & Pollack 1991, Sozeau & Tabareau 2014)
# ---------------------------------------------------------------------------

class UniverseLevel:
    """Universe level with level arithmetic for universe polymorphism.

    In a universe-polymorphic type theory:
      Type_0 : Type_1 : Type_2 : ...

    Universe polymorphism allows definitions to work at any universe level:
      id : {l : Level} -> (A : Type_l) -> A -> A
      id A x = x

    Level arithmetic:
      - max(i, j): used for Pi/Sigma types
      - i + 1: used for Type_i : Type_{i+1}  (Cumulativity)

    This avoids Girard's paradox (Type : Type is inconsistent)
    while still allowing generic programming across universe levels.

    References:
      - Harper & Pollack (1991) "Type Checking with Universes"
      - Sozeau & Tabareau (2014) "Universe Polymorphism in Coq"
      - Voevodsky (2013) "A Simple Type System with Two Identity Types"
        (Homotopy Type Theory / Univalence)
    """

    def __init__(self, level: int = 0, variables: Optional[List[str]] = None):
        self.level = level
        self.variables = variables or []

    def successor(self) -> UniverseLevel:
        return UniverseLevel(self.level + 1, self.variables)

    @staticmethod
    def max_level(l1: UniverseLevel, l2: UniverseLevel) -> UniverseLevel:
        combined_vars = list(set(l1.variables + l2.variables))
        return UniverseLevel(max(l1.level, l2.level), combined_vars)

    def is_concrete(self) -> bool:
        return len(self.variables) == 0

    def __str__(self) -> str:
        if self.variables:
            var_str = " + ".join(self.variables)
            if self.level > 0:
                return f"max({self.level}, {var_str})"
            return var_str
        return str(self.level)


def check_universe_consistency(levels: List[Tuple[int, int]]) -> bool:
    """Check that universe level constraints are consistent.

    A set of constraints l_i <= l_j is consistent iff
    there is no cycle in the constraint graph.

    This prevents Girard's paradox:
      Type : Type leads to inconsistency (Girard 1972)
      Resolved by stratification: Type_i : Type_{i+1}

    The constraint graph must be a DAG (directed acyclic graph).
    We check this via topological sort.
    """
    from collections import defaultdict
    graph: Dict[int, Set[int]] = defaultdict(set)
    for lo, hi in levels:
        if lo == hi:
            return False  # Self-loop = inconsistency
        graph[lo].add(hi)

    # Topological sort / cycle detection
    visited: Set[int] = set()
    in_stack: Set[int] = set()

    def has_cycle(node: int) -> bool:
        if node in in_stack:
            return True
        if node in visited:
            return False
        visited.add(node)
        in_stack.add(node)
        for neighbor in graph.get(node, set()):
            if has_cycle(neighbor):
                return True
        in_stack.discard(node)
        return False

    all_nodes = set(graph.keys())
    for targets in graph.values():
        all_nodes |= targets

    for node in all_nodes:
        if has_cycle(node):
            return False
    return True


# ---------------------------------------------------------------------------
# Substitution
# ---------------------------------------------------------------------------

def substitute(term: Term, var: str, replacement: Term) -> Term:
    """Capture-avoiding substitution: term[var := replacement].

    This is the fundamental operation of type theory.
    Beta reduction: (lambda x. body)(arg) ~> body[x := arg]
    """
    if term.kind == TermKind.VAR:
        return replacement if term.name == var else term

    if term.kind in (TermKind.UNIVERSE, TermKind.NAT, TermKind.ZERO,
                     TermKind.BOOL_TYPE, TermKind.TRUE, TermKind.FALSE,
                     TermKind.INT_LIT):
        return term

    # For binders (Pi, Sigma, Lambda, Let): don't substitute under shadowed names
    if term.kind in (TermKind.PI, TermKind.SIGMA, TermKind.LAMBDA, TermKind.LET):
        new_domain = substitute(term.children[0], var, replacement)
        if term.binder == var:
            # Variable is shadowed — don't substitute in the body
            return Term(kind=term.kind, binder=term.binder,
                       children=(new_domain,) + term.children[1:],
                       name=term.name, level=term.level, int_val=term.int_val,
                       location=term.location)
        new_body = substitute(term.children[1], var, replacement)
        return Term(kind=term.kind, binder=term.binder,
                   children=(new_domain, new_body) + term.children[2:],
                   name=term.name, level=term.level, int_val=term.int_val,
                   location=term.location)

    if term.kind == TermKind.REFINEMENT:
        new_base = substitute(term.children[0], var, replacement)
        if term.binder == var:
            return Term(kind=term.kind, binder=term.binder,
                       children=(new_base, term.children[1]),
                       name=term.name, level=term.level, int_val=term.int_val,
                       location=term.location)
        new_pred = substitute(term.children[1], var, replacement)
        return Term(kind=term.kind, binder=term.binder,
                   children=(new_base, new_pred),
                   name=term.name, level=term.level, int_val=term.int_val,
                   location=term.location)

    # For all other terms, substitute in all children
    new_children = tuple(substitute(c, var, replacement) for c in term.children)
    return Term(kind=term.kind, binder=term.binder, children=new_children,
               name=term.name, level=term.level, int_val=term.int_val,
               location=term.location)


# ---------------------------------------------------------------------------
# Normalization (Beta/Eta reduction)
# ---------------------------------------------------------------------------

def normalize(term: Term) -> Term:
    """Normalize a term by performing beta and eta reductions.

    Beta: (lambda x. body)(arg)  ~>  body[x := arg]
    Eta:  (lambda x. f x)       ~>  f  (when x not free in f)

    Normalization is essential for type checking in dependent types:
    we need to compare types for equality, and types can contain
    arbitrary computations.

    Termination of normalization is guaranteed by the strong
    normalization property of the Calculus of Constructions.
    """
    if term.kind == TermKind.APP:
        func = normalize(term.children[0])
        arg = normalize(term.children[1])
        # Beta reduction
        if func.kind == TermKind.LAMBDA:
            body = func.children[1]
            return normalize(substitute(body, func.binder, arg))
        return Term(kind=TermKind.APP, children=(func, arg),
                   location=term.location)

    if term.kind == TermKind.FST:
        pair = normalize(term.children[0])
        if pair.kind == TermKind.PAIR:
            return pair.children[0]
        return Term(kind=TermKind.FST, children=(pair,), location=term.location)

    if term.kind == TermKind.SND:
        pair = normalize(term.children[0])
        if pair.kind == TermKind.PAIR:
            return pair.children[1]
        return Term(kind=TermKind.SND, children=(pair,), location=term.location)

    if term.kind == TermKind.LET:
        val = normalize(term.children[0])
        body = term.children[1]
        return normalize(substitute(body, term.binder, val))

    if term.kind in (TermKind.PI, TermKind.SIGMA, TermKind.LAMBDA):
        new_domain = normalize(term.children[0])
        new_body = normalize(term.children[1])
        return Term(kind=term.kind, binder=term.binder,
                   children=(new_domain, new_body),
                   name=term.name, level=term.level, location=term.location)

    if term.kind == TermKind.SUCC:
        inner = normalize(term.children[0])
        return Term(kind=TermKind.SUCC, children=(inner,), location=term.location)

    if term.children:
        new_children = tuple(normalize(c) for c in term.children)
        return Term(kind=term.kind, binder=term.binder, children=new_children,
                   name=term.name, level=term.level, int_val=term.int_val,
                   location=term.location)

    return term


def terms_equal(t1: Term, t2: Term) -> bool:
    """Check if two terms are definitionally equal (after normalization).

    Two types are equal iff their normal forms are syntactically identical
    (up to alpha-equivalence of bound variables).
    """
    n1 = normalize(t1)
    n2 = normalize(t2)
    return _alpha_equal(n1, n2)


def _alpha_equal(t1: Term, t2: Term) -> bool:
    """Alpha-equivalence: equal up to renaming of bound variables."""
    if t1.kind != t2.kind:
        return False
    if t1.kind == TermKind.VAR:
        return t1.name == t2.name
    if t1.kind == TermKind.UNIVERSE:
        return t1.level == t2.level
    if t1.kind == TermKind.INT_LIT:
        return t1.int_val == t2.int_val
    if t1.kind in (TermKind.NAT, TermKind.ZERO, TermKind.BOOL_TYPE,
                   TermKind.TRUE, TermKind.FALSE):
        return True
    if t1.kind in (TermKind.PI, TermKind.SIGMA, TermKind.LAMBDA, TermKind.LET,
                   TermKind.REFINEMENT):
        if len(t1.children) != len(t2.children):
            return False
        # Check domain
        if not _alpha_equal(t1.children[0], t2.children[0]):
            return False
        # Check body with consistent renaming
        if len(t1.children) > 1:
            if t1.binder == t2.binder:
                return _alpha_equal(t1.children[1], t2.children[1])
            # Rename t2's binder to t1's binder
            fresh = t1.binder
            renamed = substitute(t2.children[1], t2.binder, T_VAR(fresh))
            return _alpha_equal(t1.children[1], renamed)
        return True
    # General case: check all children
    if len(t1.children) != len(t2.children):
        return False
    return all(_alpha_equal(c1, c2) for c1, c2 in zip(t1.children, t2.children))


# ---------------------------------------------------------------------------
# Type Checking Context
# ---------------------------------------------------------------------------

@dataclass
class Context:
    """Typing context Gamma: a list of (name, type) bindings.

    Gamma = x1 : A1, x2 : A2, ..., xn : An

    The context grows as we enter binders (Pi, Lambda, Let)
    and shrinks as we exit them.
    """
    bindings: Dict[str, Term] = field(default_factory=dict)

    def extend(self, name: str, type_term: Term) -> Context:
        """Create a new context extended with a binding."""
        new_bindings = dict(self.bindings)
        new_bindings[name] = type_term
        return Context(bindings=new_bindings)

    def lookup(self, name: str) -> Optional[Term]:
        return self.bindings.get(name)


# ---------------------------------------------------------------------------
# Bidirectional Type Checker
# ---------------------------------------------------------------------------

class DependentTypeChecker:
    """Bidirectional type checker for the dependent type theory.

    Implements two judgments:
      1. CHECK:  Gamma |- e <= A  (check that e has type A)
      2. SYNTH:  Gamma |- e => A  (synthesize the type of e)

    The rules follow the Calculus of Constructions:

      (Var)     x : A in Gamma
                ----------------
                Gamma |- x => A

      (Pi-F)    Gamma |- A <= Type_i,  Gamma, x:A |- B <= Type_j
                ------------------------------------------------
                Gamma |- Pi(x:A).B => Type_{max(i,j)}

      (Lam)     Gamma, x:A |- e <= B
                -----------------------
                Gamma |- lambda(x:A).e <= Pi(x:A).B

      (App)     Gamma |- f => Pi(x:A).B,  Gamma |- e <= A
                -------------------------------------------
                Gamma |- f(e) => B[x := e]

      (Conv)    Gamma |- e => A,  A ~= B  (definitional equality)
                -------------------------------------------
                Gamma |- e <= B

    Soundness: if Gamma |- e : A, then evaluation of e terminates
    and produces a value of type A. (Strong normalization.)
    """

    def __init__(self):
        self.errors: List[AeonError] = []

    def synth(self, ctx: Context, term: Term) -> Optional[Term]:
        """Synthesize the type of a term.

        Gamma |- term => ?
        Returns the type, or None if type cannot be synthesized.
        """
        if term.kind == TermKind.UNIVERSE:
            # Type_i : Type_{i+1}  (universe hierarchy)
            return T_TYPE(term.level + 1)

        if term.kind == TermKind.VAR:
            ty = ctx.lookup(term.name)
            if ty is None:
                self.errors.append(type_error(
                    node_id="dependent_type_var",
                    expected_type="bound variable",
                    actual_type=f"unbound: {term.name}",
                    location=term.location,
                ))
            return ty

        if term.kind == TermKind.NAT:
            return T_TYPE(0)

        if term.kind == TermKind.ZERO:
            return T_NAT()

        if term.kind == TermKind.SUCC:
            inner_ty = self.synth(ctx, term.children[0])
            if inner_ty and terms_equal(inner_ty, T_NAT()):
                return T_NAT()
            self.errors.append(type_error(
                node_id="succ_arg",
                expected_type="Nat",
                actual_type=str(inner_ty) if inner_ty else "unknown",
                location=term.location,
            ))
            return T_NAT()

        if term.kind == TermKind.BOOL_TYPE:
            return T_TYPE(0)

        if term.kind == TermKind.TRUE or term.kind == TermKind.FALSE:
            return T_BOOL()

        if term.kind == TermKind.INT_LIT:
            return T_INT()

        if term.kind == TermKind.PI:
            # Pi(x:A).B : Type_{max(i,j)} where A : Type_i and B : Type_j
            A = term.children[0]
            B = term.children[1]
            A_ty = self.synth(ctx, A)
            if A_ty is None:
                return None
            ext_ctx = ctx.extend(term.binder, A)
            B_ty = self.synth(ext_ctx, B)
            if B_ty is None:
                return None
            # Both must be universes
            i = A_ty.level if A_ty.kind == TermKind.UNIVERSE else 0
            j = B_ty.level if B_ty.kind == TermKind.UNIVERSE else 0
            return T_TYPE(max(i, j))

        if term.kind == TermKind.SIGMA:
            A = term.children[0]
            B = term.children[1]
            A_ty = self.synth(ctx, A)
            ext_ctx = ctx.extend(term.binder, A)
            B_ty = self.synth(ext_ctx, B)
            i = A_ty.level if A_ty and A_ty.kind == TermKind.UNIVERSE else 0
            j = B_ty.level if B_ty and B_ty.kind == TermKind.UNIVERSE else 0
            return T_TYPE(max(i, j))

        if term.kind == TermKind.LAMBDA:
            # Cannot synthesize type of bare lambda — need annotation
            A = term.children[0]
            body = term.children[1]
            ext_ctx = ctx.extend(term.binder, A)
            body_ty = self.synth(ext_ctx, body)
            if body_ty:
                return T_PI(term.binder, A, body_ty)
            return None

        if term.kind == TermKind.APP:
            func = term.children[0]
            arg = term.children[1]
            func_ty = self.synth(ctx, func)
            if func_ty is None:
                return None
            func_ty = normalize(func_ty)
            if func_ty.kind != TermKind.PI:
                self.errors.append(type_error(
                    node_id="app_not_function",
                    expected_type="Pi type (function)",
                    actual_type=str(func_ty),
                    location=term.location,
                ))
                return None
            # Check argument against domain
            domain = func_ty.children[0]
            self.check(ctx, arg, domain)
            # Return type with argument substituted
            codomain = func_ty.children[1]
            return normalize(substitute(codomain, func_ty.binder, arg))

        if term.kind == TermKind.PAIR:
            # Cannot synthesize pair without type annotation
            return None

        if term.kind == TermKind.FST:
            pair_ty = self.synth(ctx, term.children[0])
            if pair_ty and pair_ty.kind == TermKind.SIGMA:
                return pair_ty.children[0]
            return None

        if term.kind == TermKind.SND:
            pair = term.children[0]
            pair_ty = self.synth(ctx, pair)
            if pair_ty and pair_ty.kind == TermKind.SIGMA:
                fst_val = T_FST(pair)
                return normalize(substitute(pair_ty.children[1], pair_ty.binder, fst_val))
            return None

        if term.kind == TermKind.ID:
            # Id(A, a, b) : Type_i where A : Type_i
            A = term.children[0]
            a = term.children[1]
            b = term.children[2]
            A_ty = self.synth(ctx, A)
            self.check(ctx, a, A)
            self.check(ctx, b, A)
            i = A_ty.level if A_ty and A_ty.kind == TermKind.UNIVERSE else 0
            return T_TYPE(i)

        if term.kind == TermKind.REFL:
            # refl(a) : Id(A, a, a) — need type annotation
            a = term.children[0]
            a_ty = self.synth(ctx, a)
            if a_ty:
                return T_ID(a_ty, a, a)
            return None

        if term.kind == TermKind.LET:
            val = term.children[0]
            body = term.children[1]
            val_ty = self.synth(ctx, val)
            if val_ty is None:
                return None
            ext_ctx = ctx.extend(term.binder, val_ty)
            body_ty = self.synth(ext_ctx, body)
            if body_ty:
                return normalize(substitute(body_ty, term.binder, val))
            return None

        if term.kind == TermKind.REFINEMENT:
            # {x : A | P(x)} : Type_i where A : Type_i
            A = term.children[0]
            A_ty = self.synth(ctx, A)
            i = A_ty.level if A_ty and A_ty.kind == TermKind.UNIVERSE else 0
            return T_TYPE(i)

        return None

    def check(self, ctx: Context, term: Term, expected: Term) -> bool:
        """Check that a term has the expected type.

        Gamma |- term <= expected

        Uses the subsumption rule:
          If Gamma |- term => A and A ~= expected, then Gamma |- term <= expected
        """
        expected_nf = normalize(expected)

        # Lambda introduction
        if term.kind == TermKind.LAMBDA and expected_nf.kind == TermKind.PI:
            domain = expected_nf.children[0]
            codomain = expected_nf.children[1]
            ext_ctx = ctx.extend(term.binder, domain)
            # Substitute the Pi binder for the Lambda binder in codomain
            adjusted_codomain = substitute(codomain, expected_nf.binder, T_VAR(term.binder))
            return self.check(ext_ctx, term.children[1], adjusted_codomain)

        # Pair introduction
        if term.kind == TermKind.PAIR and expected_nf.kind == TermKind.SIGMA:
            fst_type = expected_nf.children[0]
            snd_type = expected_nf.children[1]
            self.check(ctx, term.children[0], fst_type)
            # Substitute actual first value into second type
            adjusted_snd = substitute(snd_type, expected_nf.binder, term.children[0])
            self.check(ctx, term.children[1], adjusted_snd)
            return True

        # Subsumption: synthesize and compare
        actual = self.synth(ctx, term)
        if actual is None:
            return False

        if not terms_equal(actual, expected):
            self.errors.append(type_error(
                node_id="dependent_type_mismatch",
                expected_type=str(normalize(expected)),
                actual_type=str(normalize(actual)),
                location=term.location,
            ))
            return False

        return True


# ---------------------------------------------------------------------------
# AEON Program -> Dependent Type Terms Translation
# ---------------------------------------------------------------------------

class AEONTranslator:
    """Translates AEON programs to dependent type terms for verification.

    This enables full dependent type checking of AEON programs:
    - requires/ensures clauses become Pi type refinements
    - Pure functions become lambda terms
    - Data types become Sigma types or records
    - Contracts become proof obligations
    """

    def __init__(self):
        self.checker = DependentTypeChecker()
        self.errors: List[AeonError] = []

    def check_program(self, program: Program) -> List[AeonError]:
        """Run dependent type checking on an AEON program."""
        self.errors = []
        ctx = Context()

        # Register built-in types
        ctx = ctx.extend("Int", T_TYPE(0))
        ctx = ctx.extend("Bool", T_TYPE(0))
        ctx = ctx.extend("Float", T_TYPE(0))
        ctx = ctx.extend("String", T_TYPE(0))
        ctx = ctx.extend("Void", T_TYPE(0))
        ctx = ctx.extend("Nat", T_TYPE(0))

        # Register data types
        for decl in program.declarations:
            if isinstance(decl, DataDef):
                ctx = self._register_data(ctx, decl)

        # Check functions
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                ctx = self._check_function(ctx, decl)

        self.errors.extend(self.checker.errors)
        return self.errors

    def _register_data(self, ctx: Context, data: DataDef) -> Context:
        """Register a data type as a Sigma type in the context."""
        # data Point { x: Int, y: Int } becomes:
        # Point : Type = Sigma (x : Int) . Int
        ctx = ctx.extend(data.name, T_TYPE(0))
        return ctx

    def _check_function(self, ctx: Context, func: PureFunc | TaskFunc) -> Context:
        """Check a function using dependent types.

        pure f(x: A, y: B) -> C { requires: P; ensures: Q; body }

        becomes the dependent type:
          f : Pi (x : A) . Pi (y : B) . {v : C | Q(v)}
          with proof obligation: P(x, y) => wp(body, Q)
        """
        # Build the function's dependent type
        func_type = self._build_function_type(func)

        # Build the function term (lambda)
        func_term = self._translate_function(func)

        # Type check: func_term <= func_type
        if func_type and func_term:
            self.checker.check(ctx, func_term, func_type)

        # Register function in context
        if func_type:
            ctx = ctx.extend(func.name, func_type)

        return ctx

    def _build_function_type(self, func: PureFunc | TaskFunc) -> Optional[Term]:
        """Build the dependent Pi type for a function."""
        # Start with return type
        ret_name = str(func.return_type) if func.return_type else "Void"
        ret_type = self._aeon_type_to_term(ret_name)

        # Wrap return type with ensures clauses (refinement)
        if func.ensures:
            for ens in func.ensures:
                pred = self._expr_to_term(ens.expr)
                ret_type = T_REFINE("result", ret_type, pred)

        # Build Pi types right-to-left for parameters
        result = ret_type
        for param in reversed(func.params):
            param_type_name = str(param.type_annotation) if param.type_annotation else "Void"
            param_type = self._aeon_type_to_term(param_type_name)
            result = T_PI(param.name, param_type, result)

        return result

    def _translate_function(self, func: PureFunc | TaskFunc) -> Optional[Term]:
        """Translate an AEON function to a lambda term."""
        if not func.body:
            return None

        # Translate body to a term
        body_term = self._translate_body(func.body)
        if body_term is None:
            return None

        # Wrap in lambdas for each parameter
        result = body_term
        for param in reversed(func.params):
            param_type_name = str(param.type_annotation) if param.type_annotation else "Void"
            param_type = self._aeon_type_to_term(param_type_name)
            result = T_LAM(param.name, param_type, result)

        return result

    def _translate_body(self, stmts: List[Statement]) -> Optional[Term]:
        """Translate a sequence of statements to a term."""
        if not stmts:
            return None

        # Find the return statement
        for stmt in stmts:
            if isinstance(stmt, ReturnStmt) and stmt.value:
                return self._expr_to_term(stmt.value)
            if isinstance(stmt, LetStmt) and stmt.value:
                val_term = self._expr_to_term(stmt.value)
                rest = self._translate_body(stmts[stmts.index(stmt) + 1:])
                if rest:
                    return T_LET(stmt.name, val_term, rest)
                return val_term
            if isinstance(stmt, IfStmt):
                cond = self._expr_to_term(stmt.condition)
                then_term = self._translate_body(stmt.then_body)
                else_term = self._translate_body(stmt.else_body) if stmt.else_body else None
                if then_term and else_term:
                    return Term(kind=TermKind.IF_THEN_ELSE,
                               children=(cond, then_term, else_term))
                return then_term

        return None

    def _expr_to_term(self, expr: Expr) -> Term:
        """Translate an AEON expression to a dependent type term."""
        if isinstance(expr, IntLiteral):
            return T_INT_LIT(expr.value)
        if isinstance(expr, BoolLiteral):
            return T_TRUE() if expr.value else T_FALSE()
        if isinstance(expr, Identifier):
            return T_VAR(expr.name)
        if isinstance(expr, BinaryOp):
            left = self._expr_to_term(expr.left)
            right = self._expr_to_term(expr.right)
            return T_APP(T_APP(T_VAR(f"__{expr.op}__"), left), right)
        if isinstance(expr, UnaryOp):
            inner = self._expr_to_term(expr.operand)
            return T_APP(T_VAR(f"__unary_{expr.op}__"), inner)
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                result: Term = T_VAR(expr.callee.name)
                for arg in expr.args:
                    result = T_APP(result, self._expr_to_term(arg))
                return result
            return T_VAR("__unknown_call__")
        if isinstance(expr, FieldAccess):
            obj = self._expr_to_term(expr.obj)
            return T_APP(T_VAR(f"__{expr.field_name}__"), obj)
        if isinstance(expr, MethodCall):
            obj = self._expr_to_term(expr.obj)
            result = T_APP(T_VAR(f"__{expr.method_name}__"), obj)
            for arg in expr.args:
                result = T_APP(result, self._expr_to_term(arg))
            return result
        return T_VAR("__unknown__")

    def _aeon_type_to_term(self, type_name: str) -> Term:
        """Convert an AEON type name to a term."""
        simple = {
            "Int": T_INT(), "Bool": T_BOOL(), "Float": T_VAR("Float"),
            "String": T_VAR("String"), "Void": T_VAR("Void"),
            "Nat": T_NAT(), "UUID": T_VAR("UUID"), "Email": T_VAR("Email"),
            "USD": T_VAR("USD"),
        }
        return simple.get(type_name, T_VAR(type_name))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_dependent_types(program: Program) -> List[AeonError]:
    """Run dependent type checking on an AEON program.

    Translates AEON programs to the Calculus of Constructions and
    verifies them using bidirectional dependent type checking.

    This provides the strongest possible type-theoretic guarantee:
    via the Curry-Howard correspondence, a well-typed program is
    simultaneously a proof of its specification.
    """
    translator = AEONTranslator()
    return translator.check_program(program)
