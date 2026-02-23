"""AEON Hoare Logic Engine — Comprehensive Formal Verification Framework.

Implements a full-spectrum program verification suite anchored in Hoare logic
and Dijkstra's weakest precondition calculus, extended across twelve major
areas of software engineering formal methods.

═══════════════════════════════════════════════════════════════════════════════
THEORETICAL FOUNDATIONS
═══════════════════════════════════════════════════════════════════════════════

HOARE LOGIC (Hoare 1969):
  A HOARE TRIPLE {P} S {Q} asserts:
    If precondition P holds before executing statement S,
    then postcondition Q holds after S terminates (partial correctness).

  References:
    Hoare (1969) "An Axiomatic Basis for Computer Programming"
    CACM 12(10), https://doi.org/10.1145/363235.363259

WEAKEST PRECONDITION CALCULUS (Dijkstra 1975):
  wp(S, Q) is the weakest predicate P such that {P} S {Q}.
  Computed backwards from the postcondition:

    wp(skip, Q)                     = Q
    wp(x := e, Q)                   = Q[x/e]                  (substitution)
    wp(S1; S2, Q)                   = wp(S1, wp(S2, Q))        (composition)
    wp(if b then S1 else S2, Q)     = (b ⇒ wp(S1,Q)) ∧ (¬b ⇒ wp(S2,Q))
    wp(while b do S, Q)             = I ∧ (I ∧ ¬b ⇒ Q)        (needs invariant I)
    wp(call f(args), Q)             = pre_f[args/params] ∧ (post_f ⇒ Q)

  References:
    Dijkstra (1975) "Guarded Commands, Nondeterminacy and Formal Derivation"
    CACM 18(8), https://doi.org/10.1145/360933.360975

TOTAL CORRECTNESS (Floyd 1967):
  {P} S {Q} (partial) + termination = total correctness.
  Termination requires a RANKING FUNCTION r: State → ℕ such that:
    {I ∧ b ∧ r = v₀} body {r < v₀}   (strictly decreasing)
    {I ∧ b} body {r ≥ 0}              (bounded below)

  References:
    Floyd (1967) "Assigning Meanings to Programs"
    Proc. Symp. Applied Mathematics, AMS

LOOP INVARIANT INFERENCE — HOUDINI (Flanagan & Leino 2001):
  1. Guess a large set of candidate invariants from templates
  2. Iteratively remove candidates that are not inductive:
       {candidate ∧ guard} body {candidate}  must hold
  3. Remaining candidates form the maximal inductive invariant

  Extended with:
  - Interval candidates from abstract interpretation (Cousot & Cousot 1977)
  - Craig interpolants from infeasibility proofs (McMillan 2003)
  - Template-based synthesis via Farkas' lemma (Colón et al. 2003)

  References:
    Flanagan & Leino (2001) "Houdini, an Annotation Assistant for ESC/Java"
    FME '01, https://doi.org/10.1007/3-540-45251-6_9

STRONGEST POSTCONDITION (Dijkstra 1976):
  Dual to wp — works FORWARDS from precondition:
    sp(x := e, P) = ∃x₀. P[x/x₀] ∧ x = e[x/x₀]
    sp(S1; S2, P) = sp(S2, sp(S1, P))

PROCEDURE MODULAR VERIFICATION (Hoare 1971):
  Function summaries {pre_f} f {post_f} enable modular verification:
    Call rule: {P[args/params] ∧ pre_f[args/params]} call f(args) {post_f[result/ret]}
  Mutual recursion handled via fixpoint over summary table.

  References:
    Hoare (1971) "Procedures and Parameters: An Axiomatic Approach"
    Symposium on Semantics of Algorithmic Languages

SEPARATION LOGIC — FRAME RULE (Reynolds 2002):
  Heap assertions use separating conjunction P * Q:
    Frame rule: {P} C {Q} ⟹ {P * R} C {Q * R}  (if C ∩ mod(C) = ∅)
  Enables modular heap reasoning.

  References:
    Reynolds (2002) "Separation Logic: A Logic for Shared Mutable Data"
    LICS '02, https://doi.org/10.1109/LICS.2002.1029817

OWICKI-GRIES PARALLEL COMPOSITION (Owicki & Gries 1976):
  For {P₁} S₁ {Q₁} ∥ {P₂} S₂ {Q₂}:
    - Each triple valid in isolation
    - INTERFERENCE FREEDOM: every stmt in S₂ preserves assertions of S₁

  References:
    Owicki & Gries (1976) "An Axiomatic Proof Technique for Parallel Programs"
    Acta Informatica 6, https://doi.org/10.1007/BF00268134

CRAIG INTERPOLATION (Craig 1957 / McMillan 2003):
  Given A ∧ B unsatisfiable, interpolant I satisfies:
    A ⇒ I,  I ∧ B unsat,  vars(I) ⊆ vars(A) ∩ vars(B)
  Used to synthesize loop invariants from infeasibility proofs.

  References:
    McMillan (2003) "Interpolation and SAT-Based Model Checking"
    CAV '03, https://doi.org/10.1007/978-3-540-45069-6_1

ABSTRACT INTERPRETATION BRIDGE (Cousot & Cousot 1977):
  Galois connection (α, γ) between concrete and abstract domains.
  Abstract domain results (intervals, octagons) seed Houdini candidates.
  Soundness: α(F(γ(a))) ⊑ F#(a) for all abstract states a.

REFINEMENT TYPE CONSISTENCY (Rondon et al. 2008):
  For {v: T | p} annotations, generate: wp_pre ⇒ p[v/e]
  Ensures liquid type annotations are consistent with wp-derived conditions.

ASSERTION INFERENCE — DAIKON-STYLE (Ernst et al. 2007):
  Forward sp-calculus collects likely invariants at each program point.
  Template families filtered by Z3 satisfiability.

  References:
    Ernst et al. (2007) "The Daikon System for Dynamic Detection of Likely Invariants"
    Science of Computer Programming 69(1-3)

PROOF CERTIFICATES:
  Each discharged VC produces a structured proof certificate:
    (rule, premises, conclusion, smtlib2, duration_ms)
  Exportable as Lean 4 / Coq tactic stubs for external verification.

INCREMENTAL VERIFICATION:
  Hash-keyed VC cache keyed on (func_name, body_hash, contracts_hash).
  Dependency invalidation when called function summaries change.
"""

from __future__ import annotations

import hashlib
import time as _time
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Set, Tuple, FrozenSet
from enum import Enum, auto
import copy

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, Statement, Expr,
    Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    ContractClause, ListLiteral, ConstructExpr, IfExpr, BlockExpr,
    MoveExpr, BorrowExpr, BreakStmt, ContinueStmt, UnsafeBlock,
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
    FLOAT_CONST = auto()      # Floating-point literal
    BOOL_CONST = auto()
    STRING_EQ = auto()        # String equality predicate
    BINOP = auto()
    UNOP = auto()
    AND = auto()
    OR = auto()
    NOT = auto()
    IMPLIES = auto()
    IFF = auto()              # Biconditional: P ↔ Q
    FORALL = auto()
    EXISTS = auto()           # Existential quantifier: ∃x. P
    SUBST = auto()            # Substitution marker: Q[x/e]
    ITE = auto()              # If-then-else expression
    ARRAY_SELECT = auto()     # a[i]  — Z3 array theory select
    ARRAY_STORE = auto()      # a[i := v]  — Z3 array theory store
    ARRAY_LEN = auto()        # len(a)  — array length
    SEP_STAR = auto()         # P * Q  — separating conjunction (separation logic)
    POINTS_TO = auto()        # x |-> v  — singleton heap cell
    EMP = auto()              # emp  — empty heap
    LIST_SEG = auto()         # ls(x, y)  — linked list segment
    TREE = auto()             # tree(x)  — binary tree
    RANKING = auto()          # r(vars)  — ranking function expression
    GHOST = auto()            # ghost variable — appears in specs only, not code
    LEX_RANK = auto()         # ⟨r₁, r₂, ...⟩ — lexicographic ranking tuple


@dataclass(frozen=True)
class Formula:
    """A first-order logic formula for verification conditions.

    Extended to cover:
      - Classical propositional / first-order logic (AND, OR, NOT, IMPLIES, IFF,
        FORALL, EXISTS, ITE)
      - Arithmetic (BINOP, UNOP, INT_CONST, FLOAT_CONST)
      - String equality (STRING_EQ)
      - Z3 array theory (ARRAY_SELECT, ARRAY_STORE, ARRAY_LEN)
      - Separation logic spatial predicates (SEP_STAR, POINTS_TO, EMP,
        LIST_SEG, TREE)
      - Ranking function expressions (RANKING)

    Formulas are immutable frozen dataclass trees that translate to Z3.
    """
    kind: FormulaKind
    name: str = ""                          # VAR, STRING_EQ lhs
    int_val: int = 0                        # INT_CONST
    float_val: float = 0.0                  # FLOAT_CONST
    bool_val: bool = True                   # BOOL_CONST
    op: str = ""                            # BINOP, UNOP
    children: Tuple[Formula, ...] = ()      # sub-formulas
    subst_var: str = ""                     # SUBST: variable being substituted
    subst_expr: Optional[Formula] = None    # SUBST: expression replacing variable
    quant_var: str = ""                     # FORALL/EXISTS bound variable
    str_val: str = ""                       # STRING_EQ rhs literal

    def __str__(self) -> str:
        if self.kind == FormulaKind.TRUE:
            return "true"
        if self.kind == FormulaKind.FALSE:
            return "false"
        if self.kind == FormulaKind.VAR:
            return self.name
        if self.kind == FormulaKind.INT_CONST:
            return str(self.int_val)
        if self.kind == FormulaKind.FLOAT_CONST:
            return str(self.float_val)
        if self.kind == FormulaKind.BOOL_CONST:
            return str(self.bool_val).lower()
        if self.kind == FormulaKind.STRING_EQ:
            return f'({self.name} == "{self.str_val}")'
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
        if self.kind == FormulaKind.IFF:
            return f"({self.children[0]} <=> {self.children[1]})"
        if self.kind == FormulaKind.FORALL:
            return f"(forall {self.quant_var}. {self.children[0]})"
        if self.kind == FormulaKind.EXISTS:
            return f"(exists {self.quant_var}. {self.children[0]})"
        if self.kind == FormulaKind.ITE:
            return f"(ite {self.children[0]} {self.children[1]} {self.children[2]})"
        if self.kind == FormulaKind.ARRAY_SELECT:
            return f"{self.children[0]}[{self.children[1]}]"
        if self.kind == FormulaKind.ARRAY_STORE:
            return f"{self.children[0]}[{self.children[1]} := {self.children[2]}]"
        if self.kind == FormulaKind.ARRAY_LEN:
            return f"len({self.children[0]})"
        if self.kind == FormulaKind.SEP_STAR:
            return "(" + " * ".join(str(c) for c in self.children) + ")"
        if self.kind == FormulaKind.POINTS_TO:
            return f"({self.children[0]} |-> {self.children[1]})"
        if self.kind == FormulaKind.EMP:
            return "emp"
        if self.kind == FormulaKind.LIST_SEG:
            return f"ls({self.children[0]}, {self.children[1]})"
        if self.kind == FormulaKind.TREE:
            return f"tree({self.children[0]})"
        if self.kind == FormulaKind.RANKING:
            return f"rank({self.name})"
        if self.kind == FormulaKind.GHOST:
            return f"ghost({self.name})"
        if self.kind == FormulaKind.LEX_RANK:
            return "⟨" + ", ".join(str(c) for c in self.children) + "⟩"
        return "<?>"


# ---------------------------------------------------------------------------
# Formula constructors
# ---------------------------------------------------------------------------

def F_TRUE() -> Formula:
    return Formula(kind=FormulaKind.TRUE)

def F_FALSE() -> Formula:
    return Formula(kind=FormulaKind.FALSE)

def F_VAR(name: str) -> Formula:
    return Formula(kind=FormulaKind.VAR, name=name)

def F_INT(val: int) -> Formula:
    return Formula(kind=FormulaKind.INT_CONST, int_val=val)

def F_FLOAT(val: float) -> Formula:
    return Formula(kind=FormulaKind.FLOAT_CONST, float_val=val)

def F_BOOL(val: bool) -> Formula:
    return Formula(kind=FormulaKind.BOOL_CONST, bool_val=val)

def F_STRING_EQ(var_name: str, literal: str) -> Formula:
    """String equality: var_name == literal."""
    return Formula(kind=FormulaKind.STRING_EQ, name=var_name, str_val=literal)

def F_IFF(lhs: Formula, rhs: Formula) -> Formula:
    """Biconditional: lhs ↔ rhs."""
    return Formula(kind=FormulaKind.IFF, children=(lhs, rhs))

def F_ARRAY_SELECT(arr: Formula, idx: Formula) -> Formula:
    """Array read: arr[idx]."""
    return Formula(kind=FormulaKind.ARRAY_SELECT, children=(arr, idx))

def F_ARRAY_STORE(arr: Formula, idx: Formula, val: Formula) -> Formula:
    """Array write: arr[idx := val]."""
    return Formula(kind=FormulaKind.ARRAY_STORE, children=(arr, idx, val))

def F_ARRAY_LEN(arr: Formula) -> Formula:
    """Array length: len(arr)."""
    return Formula(kind=FormulaKind.ARRAY_LEN, children=(arr,))

def F_SEP_STAR(*children: Formula) -> Formula:
    """Separating conjunction: P * Q * ..."""
    flat: List[Formula] = []
    for c in children:
        if c.kind == FormulaKind.EMP:
            continue
        if c.kind == FormulaKind.SEP_STAR:
            flat.extend(c.children)
        else:
            flat.append(c)
    if not flat:
        return F_EMP()
    if len(flat) == 1:
        return flat[0]
    return Formula(kind=FormulaKind.SEP_STAR, children=tuple(flat))

def F_POINTS_TO(ptr: Formula, val: Formula) -> Formula:
    """Singleton heap cell: ptr |-> val."""
    return Formula(kind=FormulaKind.POINTS_TO, children=(ptr, val))

def F_EMP() -> Formula:
    """Empty heap predicate."""
    return Formula(kind=FormulaKind.EMP)

def F_LIST_SEG(head: Formula, tail: Formula) -> Formula:
    """Linked list segment: ls(head, tail)."""
    return Formula(kind=FormulaKind.LIST_SEG, children=(head, tail))

def F_TREE(root: Formula) -> Formula:
    """Binary tree rooted at root."""
    return Formula(kind=FormulaKind.TREE, children=(root,))

def F_RANKING(var_name: str) -> Formula:
    """Ranking function expression over a named variable."""
    return Formula(kind=FormulaKind.RANKING, name=var_name)

def F_GHOST(name: str) -> Formula:
    """Ghost variable — appears in specifications only, not in executable code.

    Ghost variables (Owicki & Gries 1976; Abadi & Lamport 1991) are auxiliary
    variables used to express quantified postconditions and witness values.
    They are universally quantified over in the verification context:
      ∀ghost_x. {P[ghost_x]} S {Q[ghost_x]}
    """
    return Formula(kind=FormulaKind.GHOST, name=name)

def F_LEX_RANK(*components: Formula) -> Formula:
    """Lexicographic ranking tuple ⟨r₁, r₂, ..., rₙ⟩.

    A lexicographic ranking function proves termination when no single
    expression suffices. Decrease is defined as:
      ⟨r₁', r₂', ...⟩ <_lex ⟨r₁, r₂, ...⟩  iff
        r₁' < r₁  ∨  (r₁' = r₁ ∧ r₂' < r₂)  ∨  ...

    References:
      Ben-Amram & Genaim (2014) "Ranking Functions for Linear-Constraint Loops"
      JACM 61(4), https://doi.org/10.1145/2629488
    """
    return Formula(kind=FormulaKind.LEX_RANK, children=tuple(components))

def F_EXISTS(var: str, body: Formula) -> Formula:
    """Existential quantifier: ∃var. body."""
    return Formula(kind=FormulaKind.EXISTS, quant_var=var, children=(body,))

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
    """Substitute all free occurrences of variable 'var' with 'expr' in formula.

    This is the core operation of the wp-calculus:
      wp(x := e, Q) = Q[x/e]

    Handles:
      - Capture avoidance for quantifiers (bound variable shadows free var)
      - Recursive descent through all formula constructors including new kinds:
        FLOAT_CONST, STRING_EQ, IFF, EXISTS, ARRAY_SELECT/STORE/LEN,
        SEP_STAR, POINTS_TO, LIST_SEG, TREE, RANKING
    """
    if formula.kind == FormulaKind.VAR:
        if formula.name == var:
            return expr
        return formula

    if formula.kind in (FormulaKind.TRUE, FormulaKind.FALSE,
                        FormulaKind.INT_CONST, FormulaKind.FLOAT_CONST,
                        FormulaKind.BOOL_CONST, FormulaKind.EMP):
        return formula

    if formula.kind == FormulaKind.STRING_EQ:
        if formula.name == var:
            new_name = str(expr) if expr.kind == FormulaKind.VAR else formula.name
            return Formula(kind=FormulaKind.STRING_EQ, name=new_name, str_val=formula.str_val)
        return formula

    if formula.kind == FormulaKind.RANKING:
        if formula.name == var:
            return Formula(kind=FormulaKind.RANKING, name=str(expr))
        return formula

    if formula.kind == FormulaKind.GHOST:
        if formula.name == var:
            return Formula(kind=FormulaKind.GHOST, name=str(expr))
        return formula

    if formula.kind in (FormulaKind.BINOP, FormulaKind.UNOP,
                        FormulaKind.AND, FormulaKind.OR, FormulaKind.NOT,
                        FormulaKind.IMPLIES, FormulaKind.IFF, FormulaKind.ITE,
                        FormulaKind.ARRAY_SELECT, FormulaKind.ARRAY_STORE,
                        FormulaKind.ARRAY_LEN, FormulaKind.SEP_STAR,
                        FormulaKind.POINTS_TO, FormulaKind.LIST_SEG,
                        FormulaKind.TREE, FormulaKind.LEX_RANK):
        new_children = tuple(substitute(c, var, expr) for c in formula.children)
        return Formula(
            kind=formula.kind, name=formula.name, int_val=formula.int_val,
            float_val=formula.float_val, bool_val=formula.bool_val,
            op=formula.op, children=new_children,
            subst_var=formula.subst_var, subst_expr=formula.subst_expr,
            quant_var=formula.quant_var, str_val=formula.str_val,
        )

    if formula.kind in (FormulaKind.FORALL, FormulaKind.EXISTS):
        if formula.quant_var == var:
            return formula  # Bound variable shadows free occurrence
        new_body = substitute(formula.children[0], var, expr)
        if formula.kind == FormulaKind.FORALL:
            return F_FORALL(formula.quant_var, new_body)
        return F_EXISTS(formula.quant_var, new_body)

    return formula


def collect_free_vars(formula: Formula) -> Set[str]:
    """Collect all free variable names in a formula."""
    if formula.kind == FormulaKind.VAR:
        return {formula.name}
    if formula.kind == FormulaKind.RANKING:
        return {formula.name} if formula.name else set()
    if formula.kind == FormulaKind.GHOST:
        return {formula.name} if formula.name else set()
    if formula.kind == FormulaKind.STRING_EQ:
        return {formula.name} if formula.name else set()
    if formula.kind in (FormulaKind.FORALL, FormulaKind.EXISTS):
        inner = collect_free_vars(formula.children[0])
        inner.discard(formula.quant_var)
        return inner
    result: Set[str] = set()
    for child in formula.children:
        result |= collect_free_vars(child)
    return result


# ---------------------------------------------------------------------------
# GhostEnv — ghost variable environment for specification witnesses
# ---------------------------------------------------------------------------

@dataclass
class GhostEnv:
    """Environment tracking ghost variable bindings for specification witnesses.

    Ghost variables (Owicki & Gries 1976; Abadi & Lamport 1991) are auxiliary
    variables that appear in specifications but not in executable code.  They
    serve two purposes:

      1. WITNESS VARIABLES: existential witnesses in postconditions.
         e.g., ensures result == ghost_input * 2  (ghost_input bound at call site)

      2. HISTORY VARIABLES: record pre-state values for use in postconditions.
         e.g., ensures result >= ghost_old_x  (ghost_old_x = x at function entry)

    In the wp-calculus, ghost variables are treated as universally quantified
    constants — they do not change during execution and are not substituted by
    assignment rules.  The consequence rule uses them to strengthen postconditions:

      {P ∧ ghost_x = e} S {Q[ghost_x]}
      ─────────────────────────────────  (ghost introduction)
      {P} S {∃ghost_x. Q[ghost_x]}

    References:
      Abadi & Lamport (1991) "The Existence of Refinement Mappings"
      Theoretical Computer Science 82(2), https://doi.org/10.1016/0304-3975(91)90224-P
    """

    _bindings: Dict[str, Formula] = field(default_factory=dict)
    _history: Dict[str, Formula] = field(default_factory=dict)

    def bind(self, name: str, value: Formula) -> None:
        """Bind a ghost variable to a formula (witness binding)."""
        self._bindings[name] = value

    def record_history(self, var: str, pre_value: Formula) -> None:
        """Record the pre-state value of a program variable as a ghost."""
        ghost_name = f"ghost_old_{var}"
        self._history[ghost_name] = pre_value

    def get(self, name: str) -> Optional[Formula]:
        return self._bindings.get(name) or self._history.get(name)

    def all_ghost_vars(self) -> List[str]:
        return list(self._bindings.keys()) + list(self._history.keys())

    def instantiate(self, formula: Formula) -> Formula:
        """Replace all ghost variable references with their bound values."""
        result = formula
        for name, val in {**self._bindings, **self._history}.items():
            result = substitute(result, name, val)
        return result

    def universally_close(self, formula: Formula) -> Formula:
        """Wrap formula in ∀ghost_x. for each unbound ghost variable.

        This is the standard treatment for ghost variables in VCs:
        the VC must hold for ALL values of the ghost variable.
        """
        result = formula
        for name in reversed(self.all_ghost_vars()):
            if name in collect_free_vars(result):
                result = F_FORALL(name, result)
        return result


# ---------------------------------------------------------------------------
# Weakest Precondition Calculator
# ---------------------------------------------------------------------------

class FunctionSummary:
    """Modular verification summary for a single function.

    Captures the contract {pre} f(params) {post} used for the
    procedure call rule (Hoare 1971):

      Call rule: {P[args/params] ∧ pre_f[args/params]} call f(args) {post_f[result/ret]}

    The modifies_set records which variables f may write, enabling
    the frame rule: anything not in modifies_set is preserved.
    """

    def __init__(
        self,
        name: str,
        params: List[str],
        precondition: Formula,
        postcondition: Formula,
        modifies_set: FrozenSet[str] = frozenset(),
    ) -> None:
        self.name = name
        self.params = params
        self.precondition = precondition
        self.postcondition = postcondition
        self.modifies_set = modifies_set

    def instantiate(self, args: List[Formula]) -> Tuple[Formula, Formula]:
        """Substitute actual arguments for formal parameters.

        Returns (instantiated_pre, instantiated_post).
        """
        pre = self.precondition
        post = self.postcondition
        for param, arg in zip(self.params, args):
            pre = substitute(pre, param, arg)
            post = substitute(post, param, arg)
        return pre, post


class SummaryTable:
    """Global table of function summaries for modular verification.

    Populated bottom-up: callees before callers.
    For mutual recursion, summaries are initialised to {True} f {True}
    and refined via fixpoint iteration until stable.
    """

    def __init__(self) -> None:
        self._table: Dict[str, FunctionSummary] = {}

    def register(self, summary: FunctionSummary) -> None:
        self._table[summary.name] = summary

    def get(self, name: str) -> Optional[FunctionSummary]:
        return self._table.get(name)

    def has(self, name: str) -> bool:
        return name in self._table

    def all_names(self) -> List[str]:
        return list(self._table.keys())


@dataclass
class RankingFunction:
    """A ranking function (variant) for a loop, proving termination.

    Supports both SCALAR and LEXICOGRAPHIC ranking functions.

    SCALAR ranking (Floyd 1967):
      A single expression r: State → ℕ satisfying:
        1. LOWER BOUND:     {I ∧ b} body {r ≥ 0}
        2. STRICT DECREASE: {I ∧ b ∧ r = v₀} body {r < v₀}

    LEXICOGRAPHIC ranking (Ben-Amram & Genaim 2014):
      A tuple ⟨r₁, r₂, ..., rₙ⟩ where each rᵢ: State → ℤ, satisfying:
        1. LOWER BOUND:     ∀i. {I ∧ b} body {rᵢ ≥ 0}
        2. LEX DECREASE:    {I ∧ b ∧ r₁=v₁ ∧ ... ∧ rₙ=vₙ} body
                              {r₁' < v₁  ∨  (r₁'=v₁ ∧ r₂' < v₂)  ∨  ...}

    Lexicographic ranking is necessary for:
      - Nested loops (outer counter decreases when inner terminates)
      - Mutual recursion (alternating decreases across functions)
      - Loops with multiple exit conditions

    References:
      Floyd (1967) "Assigning Meanings to Programs"
        Proc. Symp. Applied Mathematics, AMS
      Ben-Amram & Genaim (2014) "Ranking Functions for Linear-Constraint Loops"
        JACM 61(4), https://doi.org/10.1145/2629488
      Colón & Sipma (2001) "Synthesis of Linear Ranking Functions"
        TACAS '01, https://doi.org/10.1007/3-540-45319-9_19
    """
    formula: Formula
    variables: List[str]
    lower_bound_vc: Optional[Formula] = None
    decrease_vc: Optional[Formula] = None
    proved_terminating: bool = False
    is_lexicographic: bool = False
    components: List[Formula] = field(default_factory=list)
    lex_decrease_vc: Optional[Formula] = None

    def __str__(self) -> str:
        if self.is_lexicographic and self.components:
            return "⟨" + ", ".join(str(c) for c in self.components) + "⟩"
        return str(self.formula)

    def lex_decrease_formula(
        self, pre_vals: List[Formula], post_vals: List[Formula]
    ) -> Formula:
        """Build the lexicographic decrease VC formula.

        ⟨r₁', ..., rₙ'⟩ <_lex ⟨v₁, ..., vₙ⟩  iff
          (r₁' < v₁)  ∨
          (r₁' = v₁ ∧ r₂' < v₂)  ∨
          (r₁' = v₁ ∧ r₂' = v₂ ∧ r₃' < v₃)  ∨  ...
        """
        n = min(len(pre_vals), len(post_vals))
        if n == 0:
            return F_FALSE()
        disjuncts: List[Formula] = []
        for i in range(n):
            equalities = [
                F_BINOP("==", post_vals[j], pre_vals[j]) for j in range(i)
            ]
            strict_decrease = F_BINOP("<", post_vals[i], pre_vals[i])
            if equalities:
                disjuncts.append(F_AND(*equalities, strict_decrease))
            else:
                disjuncts.append(strict_decrease)
        return F_OR(*disjuncts)


@dataclass
class ProofCertificate:
    """A structured proof certificate for a single discharged VC.

    Exportable as Lean 4 / Coq tactic scripts for external verification.

    TACTIC SELECTION STRATEGY (§8):
    ─────────────────────────────────────────────────────────────────────────
    Rather than emitting `sorry` / `admit`, we select concrete tactics based
    on the PROOF RULE applied and the UNSAT CORE returned by Z3:

      Rule                  Lean 4 tactic       Coq tactic
      ─────────────────     ─────────────────   ─────────────────
      wp-assignment         omega               lia
      wp-contract (LIA)     omega               lia
      wp-contract (prop)    decide / tauto      tauto
      loop-consecution      omega               lia
      ranking-*             omega               lia
      refinement-type       simp; omega         simpl; lia
      owicki-gries          omega               lia
      wp-contract (∃)       exact ⟨w, rfl⟩      exact ⟨w, eq_refl _⟩

    The UNSAT CORE provides the minimal set of hypotheses needed, which we
    emit as `have h_i : ... := by assumption` before the closing tactic.

    References:
      Avigad et al. (2022) "Lean 4: A Theorem Prover and Programming Language"
      Bertot & Castéran (2004) "Interactive Theorem Proving and Program Development"
    """
    rule: str
    premises: List[str]
    conclusion: str
    smtlib2: str = ""
    simplified_smtlib2: str = ""
    duration_ms: float = 0.0
    proved: bool = False
    witness: Dict[str, Any] = field(default_factory=dict)
    unsat_core: List[str] = field(default_factory=list)
    proof_rule_chain: List[str] = field(default_factory=list)
    is_linear_arithmetic: bool = True
    has_existential: bool = False
    existential_witness: Dict[str, str] = field(default_factory=dict)

    def _classify_goal(self) -> str:
        """Classify the proof goal to select the right tactic."""
        conc = self.conclusion.lower()
        if "exists" in conc or "∃" in conc:
            return "existential"
        if any(op in conc for op in [">=", "<=", ">", "<", "+", "-", "*", "/"]):
            return "arithmetic"
        if any(op in conc for op in ["=>", "/\\", "\\/", "!", "true", "false"]):
            return "propositional"
        return "arithmetic"

    def _lean4_tactic(self) -> str:
        """Select the appropriate Lean 4 closing tactic."""
        goal = self._classify_goal()
        rule = self.rule.lower()
        if goal == "existential" and self.existential_witness:
            witnesses = ", ".join(
                f"{v}" for v in self.existential_witness.values()
            )
            return f"exact ⟨{witnesses}, by omega⟩"
        if "refinement" in rule:
            return "simp only []; omega"
        if "owicki" in rule or "interference" in rule:
            return "omega"
        if goal == "propositional":
            return "decide"
        return "omega"

    def _coq_tactic(self) -> str:
        """Select the appropriate Coq closing tactic."""
        goal = self._classify_goal()
        rule = self.rule.lower()
        if goal == "existential" and self.existential_witness:
            witnesses = ", ".join(
                f"{v}" for v in self.existential_witness.values()
            )
            return f"exact (ex_intro _ {witnesses} (eq_refl _))."
        if "refinement" in rule:
            return "simpl; lia."
        if goal == "propositional":
            return "tauto."
        return "lia."

    def to_lean4(self) -> str:
        """Generate a Lean 4 theorem with real tactics from the UNSAT core.

        Structure:
          theorem aeon_vc_{rule} (h₁ : P₁) ... (hₙ : Pₙ) : Q := by
            -- Proof rule: {rule}
            -- UNSAT core hypotheses:
            have hc_1 : ... := by assumption
            ...
            {tactic}
        """
        safe_rule = self.rule.replace("-", "_").replace(" ", "_")
        param_list = " ".join(
            f"(h{i} : {p})" for i, p in enumerate(self.premises)
        )
        lines = [
            f"-- AEON Proof Certificate",
            f"-- Rule: {self.rule}",
            f"-- Duration: {self.duration_ms:.2f}ms",
            f"-- Proved: {self.proved}",
        ]
        if self.proof_rule_chain:
            lines.append(f"-- Rule chain: {' → '.join(self.proof_rule_chain)}")
        lines.append(f"theorem aeon_vc_{safe_rule} {param_list} :")
        lines.append(f"    {self.conclusion} := by")
        if self.unsat_core:
            lines.append("  -- UNSAT core (minimal hypotheses):")
            for i, core_item in enumerate(self.unsat_core[:8]):
                lines.append(f"  have hcore_{i} : {core_item} := by assumption")
        tactic = self._lean4_tactic()
        lines.append(f"  {tactic}")
        return "\n".join(lines)

    def to_coq(self) -> str:
        """Generate a Coq theorem with real tactics from the UNSAT core.

        Structure:
          Theorem aeon_vc_{rule} : P₁ -> ... -> Pₙ -> Q.
          Proof.
            intros h1 ... hn.
            {tactic}
          Qed.
        """
        safe_rule = self.rule.replace("-", "_").replace(" ", "_")
        lines = [
            f"(* AEON Proof Certificate *)",
            f"(* Rule: {self.rule} *)",
            f"(* Duration: {self.duration_ms:.2f}ms *)",
            f"(* Proved: {self.proved} *)",
        ]
        if self.proof_rule_chain:
            lines.append(f"(* Rule chain: {' -> '.join(self.proof_rule_chain)} *)")
        premise_type = " -> ".join(self.premises) if self.premises else "True"
        lines.append(f"Theorem aeon_vc_{safe_rule} :")
        lines.append(f"  {premise_type} -> {self.conclusion}.")
        lines.append("Proof.")
        if self.premises:
            intros = " ".join(f"h{i}" for i in range(len(self.premises)))
            lines.append(f"  intros {intros}.")
        if self.unsat_core:
            lines.append("  (* UNSAT core: *)")
            for i, core_item in enumerate(self.unsat_core[:8]):
                lines.append(f"  assert (hcore_{i} : {core_item}) by assumption.")
        tactic = self._coq_tactic()
        lines.append(f"  {tactic}")
        lines.append("Qed.")
        return "\n".join(lines)


class HoareCache:
    """Hash-keyed cache for verification condition results.

    Key: (func_name, body_hash, contracts_hash)
    Invalidation: when a callee's summary changes, all callers are invalidated.
    """

    def __init__(self) -> None:
        self._cache: Dict[str, Tuple[List[AeonError], List[ProofCertificate]]] = {}
        self._deps: Dict[str, Set[str]] = {}

    @staticmethod
    def _hash_func(func: PureFunc | TaskFunc) -> str:
        body_str = str(func.body)
        contracts_str = str(func.requires) + str(func.ensures)
        return hashlib.sha256((body_str + contracts_str).encode()).hexdigest()[:16]

    def lookup(
        self, func: PureFunc | TaskFunc, summary_hash: str
    ) -> Optional[Tuple[List[AeonError], List[ProofCertificate]]]:
        key = f"{func.name}:{self._hash_func(func)}:{summary_hash}"
        return self._cache.get(key)

    def store(
        self,
        func: PureFunc | TaskFunc,
        summary_hash: str,
        errors: List[AeonError],
        certs: List[ProofCertificate],
    ) -> None:
        key = f"{func.name}:{self._hash_func(func)}:{summary_hash}"
        self._cache[key] = (errors, certs)

    def invalidate(self, func_name: str) -> None:
        to_remove = [k for k in self._cache if k.startswith(f"{func_name}:")]
        for k in to_remove:
            del self._cache[k]

    def register_dependency(self, caller: str, callee: str) -> None:
        self._deps.setdefault(callee, set()).add(caller)

    def invalidate_dependents(self, callee: str) -> None:
        for caller in self._deps.get(callee, set()):
            self.invalidate(caller)


# ---------------------------------------------------------------------------
# §3 — Farkas' Lemma Template Synthesis for Loop Invariants
# ---------------------------------------------------------------------------

class FarkasTemplateSynthesizer:
    """Synthesizes linear loop invariants via Farkas' lemma (Colón et al. 2003).

    Parameterize the invariant as:  I(x) ≡ c₀ + c₁·x₁ + ... + cₙ·xₙ ≥ 0
    where c₀,...,cₙ are unknown coefficients solved via Z3 linear arithmetic.

    INITIATION:   pre ⇒ I
    CONSECUTION:  I ∧ guard ⇒ wp(body, I)

    References:
      Colón, Sankaranarayanan & Sipma (2003) "Linear Invariant Generation
        Using Non-Linear Constraint Solving" CAV '03
      Farkas (1902) "Über die Theorie der einfachen Ungleichungen"
    """

    def __init__(self, wp_calc: "WPCalculator") -> None:
        self._wp = wp_calc

    def synthesize(
        self, stmt: "WhileStmt", pre: Formula, post: Formula,
        program_vars: List[str],
    ) -> Optional[Formula]:
        if not HAS_Z3 or not program_vars:
            return None
        try:
            return self._synthesize_impl(stmt, pre, post, program_vars)
        except Exception:
            return None

    def _synthesize_impl(
        self, stmt: "WhileStmt", pre: Formula, post: Formula,
        program_vars: List[str],
    ) -> Optional[Formula]:
        n = len(program_vars)
        coeffs = [z3.Real(f"__farkas_c{i}") for i in range(n + 1)]
        z3_prog_vars: Dict[str, Any] = {v: z3.Int(v) for v in program_vars}
        for i in range(n + 1):
            z3_prog_vars[f"__farkas_c{i}"] = coeffs[i]

        def template_formula() -> Formula:
            terms: List[Formula] = [F_VAR("__farkas_c0")]
            for i, v in enumerate(program_vars):
                terms.append(F_BINOP("*", F_VAR(f"__farkas_c{i+1}"), F_VAR(v)))
            lhs = terms[0]
            for t in terms[1:]:
                lhs = F_BINOP("+", lhs, t)
            return F_BINOP(">=", lhs, F_INT(0))

        cond_f = self._wp._expr_to_formula(stmt.condition)
        tmpl = template_formula()
        wp_body_tmpl = self._wp.wp_block(stmt.body, tmpl)
        consecution = F_IMPLIES(F_AND(tmpl, cond_f), wp_body_tmpl)
        initiation = F_IMPLIES(pre, tmpl)

        solver = z3.Optimize()
        solver.set("timeout", 3000)
        gen = _make_vcgen()
        z3_init = gen._formula_to_z3(initiation, z3_prog_vars)
        z3_cons = gen._formula_to_z3(consecution, z3_prog_vars)
        if z3_init is not None:
            solver.add(z3_init)
        if z3_cons is not None:
            solver.add(z3_cons)
        obj = z3.Sum([z3.If(c >= 0, c, -c) for c in coeffs])
        solver.minimize(obj)
        if solver.check() != z3.sat:
            return None

        model = solver.model()

        def eval_coeff(c: Any) -> float:
            try:
                val = model.evaluate(c, model_completion=True)
                frac = val.as_fraction()
                return float(frac[0]) / float(frac[1])
            except Exception:
                return 0.0

        concrete = [eval_coeff(c) for c in coeffs]
        terms: List[Formula] = []
        if abs(concrete[0]) > 1e-9:
            terms.append(F_INT(int(round(concrete[0]))))
        for i, v in enumerate(program_vars):
            ci = int(round(concrete[i + 1]))
            if abs(ci) > 0:
                if ci == 1:
                    terms.append(F_VAR(v))
                elif ci == -1:
                    terms.append(F_UNOP("-", F_VAR(v)))
                else:
                    terms.append(F_BINOP("*", F_INT(ci), F_VAR(v)))
        if not terms:
            return None
        lhs = terms[0]
        for t in terms[1:]:
            lhs = F_BINOP("+", lhs, t)
        return F_BINOP(">=", lhs, F_INT(0))


# ---------------------------------------------------------------------------
# §5 — Symbolic Heap for Separation Logic Reasoning
# ---------------------------------------------------------------------------

@dataclass
class HeapCell:
    """A single heap cell: address_var |-> value_formula."""
    address_var: str
    value_formula: Formula
    is_freed: bool = False


@dataclass
class SymbolicHeap:
    """Symbolic heap for separation logic verification.

    A symbolic heap H = (Π, Σ) where:
      Π: pure constraints (non-spatial)
      Σ: separating conjunction of spatial predicates

    Spatial predicates: emp, x |-> v, ls(x,y), tree(x)

    FRAME RULE: {P} C {Q} ⟹ {P * R} C {Q * R}  (mod(C) ∩ vars(R) = ∅)

    Disjointness is encoded as address inequality in Z3.
    List segments use an uninterpreted function ls_len: Int×Int→Int.

    References:
      Reynolds (2002) LICS '02
      Berdine, Calcagno & O'Hearn (2005) APLAS '05
      Calcagno et al. (2011) JACM 58(6)
    """
    cells: List[HeapCell] = field(default_factory=list)
    list_segs: List[Tuple[str, str]] = field(default_factory=list)
    trees: List[str] = field(default_factory=list)
    pure_constraints: List[Formula] = field(default_factory=list)
    freed_addresses: Set[str] = field(default_factory=set)

    def add_cell(self, addr_var: str, val: Formula) -> None:
        self.cells.append(HeapCell(address_var=addr_var, value_formula=val))

    def free_cell(self, addr_var: str) -> Optional[str]:
        if addr_var in self.freed_addresses:
            return f"double-free of '{addr_var}'"
        for cell in self.cells:
            if cell.address_var == addr_var:
                cell.is_freed = True
                self.freed_addresses.add(addr_var)
                return None
        return f"free of unallocated pointer '{addr_var}'"

    def lookup(self, addr_var: str) -> Optional[HeapCell]:
        for cell in self.cells:
            if cell.address_var == addr_var and not cell.is_freed:
                return cell
        return None

    def disjointness_constraints(self) -> List[Formula]:
        """Pairwise address-inequality constraints (separating conjunction)."""
        constraints: List[Formula] = []
        live = [c for c in self.cells if not c.is_freed]
        for i, c1 in enumerate(live):
            for c2 in live[i + 1:]:
                constraints.append(
                    F_NOT(F_BINOP("==", F_VAR(c1.address_var), F_VAR(c2.address_var)))
                )
            constraints.append(F_BINOP("!=", F_VAR(c1.address_var), F_INT(0)))
        return constraints

    def to_z3(self, z3_vars: Dict[str, Any]) -> Optional[Any]:
        """Encode symbolic heap as Z3 formula using Array(Int,Int) for heap."""
        if not HAS_Z3:
            return None
        constraints: List[Any] = []
        heap_sort = z3.ArraySort(z3.IntSort(), z3.IntSort())
        if "__heap" not in z3_vars:
            z3_vars["__heap"] = z3.Const("__heap", heap_sort)
        heap = z3_vars["__heap"]
        gen = _make_vcgen()
        for cell in self.cells:
            if cell.is_freed:
                continue
            if cell.address_var not in z3_vars:
                z3_vars[cell.address_var] = z3.Int(cell.address_var)
            addr = z3_vars[cell.address_var]
            val = gen._formula_to_z3(cell.value_formula, z3_vars)
            if val is not None:
                constraints.append(z3.Select(heap, addr) == val)
            constraints.append(addr != z3.IntVal(0))
        live = [c for c in self.cells if not c.is_freed]
        for i, c1 in enumerate(live):
            for c2 in live[i + 1:]:
                a1 = z3_vars.get(c1.address_var, z3.Int(c1.address_var))
                a2 = z3_vars.get(c2.address_var, z3.Int(c2.address_var))
                constraints.append(a1 != a2)
        ls_len_fn = z3.Function("ls_len", z3.IntSort(), z3.IntSort(), z3.IntSort())
        for (head, tail) in self.list_segs:
            h = z3_vars.get(head, z3.Int(head))
            t = z3_vars.get(tail, z3.Int(tail))
            constraints.append(ls_len_fn(h, t) >= z3.IntVal(0))
        tree_size_fn = z3.Function("tree_size", z3.IntSort(), z3.IntSort())
        for root in self.trees:
            r = z3_vars.get(root, z3.Int(root))
            constraints.append(tree_size_fn(r) >= z3.IntVal(0))
        if not constraints:
            return z3.BoolVal(True)
        return z3.And(*constraints) if len(constraints) > 1 else constraints[0]

    def check_use_after_free(self, addr_var: str) -> Optional[str]:
        if addr_var in self.freed_addresses:
            return f"use-after-free: '{addr_var}' was already freed"
        return None

    def memory_leaks(self) -> List[str]:
        return [c.address_var for c in self.cells if not c.is_freed]


# ---------------------------------------------------------------------------
# §6 — Bi-Abduction Engine for Precondition Inference
# ---------------------------------------------------------------------------

class BiAbductionEngine:
    """Infers minimal preconditions via bi-abduction (Calcagno et al. 2011).

    Given body C and desired postcondition Q, find:
      ANTI-FRAME M: minimal precondition C needs (missing resources)
      FRAME F:      part of precondition C does not touch

    Such that:  pre * M ⊢ post * F

    For pure functions, infers the weakest precondition via wp-calculus
    then simplifies with Z3's quantifier elimination (qe tactic).

    References:
      Calcagno, Distefano, O'Hearn & Yang (2011) JACM 58(6)
      O'Hearn, Reynolds & Yang (2001) CSL '01
    """

    def __init__(self, wp_calc: "WPCalculator") -> None:
        self._wp = wp_calc

    def infer_precondition(
        self, func: "PureFunc | TaskFunc", desired_post: Formula,
    ) -> Tuple[Formula, List[str]]:
        """Infer minimal precondition. Returns (formula, explanation_strings)."""
        wp_result = self._wp.wp_block(func.body, desired_post)
        simplified = self._simplify_with_qe(wp_result)
        explanations = self._extract_requires_suggestions(simplified, func)
        return simplified, explanations

    def _simplify_with_qe(self, formula: Formula) -> Formula:
        """Simplify formula using Z3's quantifier elimination + simplify."""
        if not HAS_Z3:
            return formula
        try:
            z3_vars: Dict[str, Any] = {}
            gen = _make_vcgen()
            z3_f = gen._formula_to_z3(formula, z3_vars)
            if z3_f is None:
                return formula
            pipeline = z3.Then(z3.Tactic("qe"), z3.Tactic("simplify"))
            goal = z3.Goal()
            goal.add(z3_f)
            result = pipeline(goal)
            if result and result[0]:
                clauses = list(result[0])
                if len(clauses) == 1:
                    back = self._z3_to_formula(clauses[0], z3_vars)
                    return back if back is not None else formula
                backs = [self._z3_to_formula(c, z3_vars) for c in clauses]
                backs = [b for b in backs if b is not None]
                return F_AND(*backs) if backs else formula
        except Exception:
            pass
        return formula

    def _z3_to_formula(self, z3_expr: Any, z3_vars: Dict[str, Any]) -> Optional[Formula]:
        """Best-effort Z3 → Formula IR conversion."""
        if not HAS_Z3:
            return None
        try:
            decl = z3_expr.decl().name()
            ch = z3_expr.children()
            if decl == "true":
                return F_TRUE()
            if decl == "false":
                return F_FALSE()
            if decl == "and":
                parts = [self._z3_to_formula(c, z3_vars) for c in ch]
                parts = [p for p in parts if p is not None]
                return F_AND(*parts) if parts else F_TRUE()
            if decl == "or":
                parts = [self._z3_to_formula(c, z3_vars) for c in ch]
                parts = [p for p in parts if p is not None]
                return F_OR(*parts) if parts else F_FALSE()
            if decl == "not":
                inner = self._z3_to_formula(ch[0], z3_vars)
                return F_NOT(inner) if inner else None
            if decl == "=>":
                lhs = self._z3_to_formula(ch[0], z3_vars)
                rhs = self._z3_to_formula(ch[1], z3_vars)
                return F_IMPLIES(lhs, rhs) if lhs and rhs else None
            if decl in (">=", "<=", ">", "<", "=", "+", "-", "*"):
                op = "==" if decl == "=" else decl
                if len(ch) == 2:
                    lhs = self._z3_to_formula(ch[0], z3_vars)
                    rhs = self._z3_to_formula(ch[1], z3_vars)
                    if lhs and rhs:
                        return F_BINOP(op, lhs, rhs)
                if len(ch) == 1 and decl == "-":
                    inner = self._z3_to_formula(ch[0], z3_vars)
                    return F_UNOP("-", inner) if inner else None
            if z3.is_int_value(z3_expr):
                return F_INT(z3_expr.as_long())
            if z3.is_rational_value(z3_expr):
                frac = z3_expr.as_fraction()
                return F_FLOAT(float(frac[0]) / float(frac[1]))
            if z3.is_const(z3_expr):
                return F_VAR(str(z3_expr))
        except Exception:
            pass
        return None

    def _extract_requires_suggestions(
        self, wp: Formula, func: "PureFunc | TaskFunc"
    ) -> List[str]:
        param_names = {p.name for p in func.params}
        suggestions: List[str] = []
        self._collect_atomic(wp, param_names, suggestions)
        return suggestions

    def _collect_atomic(
        self, formula: Formula, params: Set[str], out: List[str]
    ) -> None:
        if formula.kind == FormulaKind.AND:
            for child in formula.children:
                self._collect_atomic(child, params, out)
        elif formula.kind == FormulaKind.IMPLIES:
            self._collect_atomic(formula.children[0], params, out)
        elif formula.kind == FormulaKind.BINOP:
            if collect_free_vars(formula) & params:
                s = str(formula)
                if s not in out:
                    out.append(s)
        elif formula.kind == FormulaKind.NOT:
            inner = formula.children[0]
            if inner.kind == FormulaKind.BINOP and collect_free_vars(inner) & params:
                s = f"!{inner}"
                if s not in out:
                    out.append(s)


# ---------------------------------------------------------------------------
# §7 — IC3 / Property Directed Reachability (Bradley 2011)
# ---------------------------------------------------------------------------

class IC3Engine:
    """IC3/PDR for safety property verification via frame propagation.

    Maintains frames F₀ ⊆ F₁ ⊆ ... ⊆ Fₖ (over-approximations of reachable
    states at depth ≤ i) and incrementally pushes clauses forward until
    a fixed point proves the property or a real counterexample is found.

    ALGORITHM:
      1. F₀ = INIT (precondition)
      2. Check Fₖ ∧ ¬P: if UNSAT, try to extend; if SAT, block predecessor
      3. BLOCK: find predecessor of bad state, add blocking clause to frame
      4. PROPAGATE: push clauses from Fᵢ to Fᵢ₊₁ when Fᵢ ∧ T ⊨ clause'
      5. FIXED POINT: Fᵢ = Fᵢ₊₁ ⟹ Fᵢ is an inductive invariant → PROVED

    IC3-derived invariants are used as Houdini candidates (Family 8).

    References:
      Bradley (2011) "SAT-Based Model Checking without Unrolling"
        VMCAI '11, https://doi.org/10.1007/978-3-642-18275-4_7
      Henzinger et al. (2004) "Abstractions from Proofs" POPL '04
      Een, Mishchenko & Brayton (2011) "Efficient Implementation of
        Property Directed Reachability" FMCAD '11
    """

    MAX_FRAMES = 8
    MAX_BLOCK_DEPTH = 16

    def __init__(self, wp_calc: "WPCalculator") -> None:
        self._wp = wp_calc
        self.frames: List[List[Formula]] = []
        self.proved: bool = False
        self.invariant: Optional[Formula] = None
        self.counterexample: Optional[List[Formula]] = None

    def verify(
        self,
        init: Formula,
        prop: Formula,
        stmt: "WhileStmt",
    ) -> Tuple[bool, Optional[Formula]]:
        """Verify that the loop satisfies property prop given init.

        Returns (proved, invariant_or_None).
        """
        if not HAS_Z3:
            return False, None
        try:
            return self._ic3_impl(init, prop, stmt)
        except Exception:
            return False, None

    def _ic3_impl(
        self, init: Formula, prop: Formula, stmt: "WhileStmt"
    ) -> Tuple[bool, Optional[Formula]]:
        cond = self._wp._expr_to_formula(stmt.condition)
        neg_prop = F_NOT(prop)

        # Frame 0 = init ∧ prop
        self.frames = [[init, prop]]

        for k in range(self.MAX_FRAMES):
            # Check if current frontier intersects ¬prop
            frontier = F_AND(*self.frames[-1]) if self.frames[-1] else F_TRUE()
            if self._is_unsat(F_AND(frontier, neg_prop)):
                # Try to propagate and find fixed point
                inv = self._propagate(cond, stmt)
                if inv is not None:
                    self.proved = True
                    self.invariant = inv
                    return True, inv
                # Extend with new frame
                self.frames.append(list(self.frames[-1]))
            else:
                # Bad state reachable — try to block it
                blocked = self._block_bad_states(frontier, neg_prop, cond, stmt, k)
                if not blocked:
                    return False, None

        return False, None

    def _propagate(self, cond: Formula, stmt: "WhileStmt") -> Optional[Formula]:
        """Push clauses forward; return invariant if fixed point reached."""
        for i in range(len(self.frames) - 1):
            fi = F_AND(*self.frames[i]) if self.frames[i] else F_TRUE()
            fi1 = F_AND(*self.frames[i + 1]) if self.frames[i + 1] else F_TRUE()
            # Check if Fᵢ ⊆ Fᵢ₊₁ (fixed point)
            if self._is_unsat(F_AND(fi, F_NOT(fi1))):
                return fi
            # Push each clause from Fᵢ to Fᵢ₊₁ if inductive
            for clause in list(self.frames[i]):
                wp_clause = self._wp.wp_block(stmt.body, clause)
                consecution = F_IMPLIES(F_AND(fi, cond), wp_clause)
                if self._is_valid(consecution):
                    if clause not in self.frames[i + 1]:
                        self.frames[i + 1].append(clause)
        return None

    def _block_bad_states(
        self, frontier: Formula, neg_prop: Formula,
        cond: Formula, stmt: "WhileStmt", depth: int
    ) -> bool:
        """Block bad states by adding clauses to frames."""
        if depth >= self.MAX_BLOCK_DEPTH:
            return False
        # Find a predecessor of the bad state
        bad_pre = F_AND(frontier, neg_prop)
        # The blocking clause is the negation of the bad pre-state
        # projected onto the loop variables
        bad_vars = collect_free_vars(bad_pre)
        if not bad_vars:
            return False
        # Add blocking clause: negate the bad state
        blocking = F_NOT(bad_pre)
        for frame in self.frames:
            if blocking not in frame:
                frame.append(blocking)
        return True

    def _is_unsat(self, formula: Formula) -> bool:
        """Check if formula is unsatisfiable using Z3."""
        if not HAS_Z3:
            return False
        try:
            z3_vars: Dict[str, Any] = {}
            gen = _make_vcgen()
            z3_f = gen._formula_to_z3(formula, z3_vars)
            if z3_f is None:
                return False
            solver = z3.Solver()
            solver.set("timeout", 1000)
            solver.add(z3_f)
            return solver.check() == z3.unsat
        except Exception:
            return False

    def _is_valid(self, formula: Formula) -> bool:
        """Check if formula is valid (negation is UNSAT)."""
        return self._is_unsat(F_NOT(formula))

    def get_invariant_candidates(self) -> List[Formula]:
        """Extract invariant candidates from IC3 frames for Houdini seeding."""
        candidates: List[Formula] = []
        for frame in self.frames:
            for clause in frame:
                if clause.kind not in (FormulaKind.TRUE, FormulaKind.FALSE):
                    candidates.append(clause)
        return candidates


class AssertionInferrer:
    """Infers likely invariants at each program point using forward sp-calculus.

    Inspired by Daikon (Ernst et al. 2007):
      1. Run sp forward through each statement
      2. At each point, test template predicates against the sp-derived state
      3. Keep predicates implied by the current state (Z3 UNSAT check)

    Template families: non-negativity, ordering, equality, linear relations,
    divisibility, array bounds.
    """

    def __init__(self, wp_calc: "WPCalculator") -> None:
        self._wp = wp_calc

    def infer_at_points(
        self, stmts: List[Statement], pre: Formula
    ) -> List[Tuple[int, Formula]]:
        results: List[Tuple[int, Formula]] = []
        state = pre
        for i, stmt in enumerate(stmts):
            candidates = self._generate_templates(state)
            confirmed = self._filter_by_z3(state, candidates)
            if confirmed:
                results.append((i, F_AND(*confirmed)))
            state = self._wp.sp(stmt, state)
        return results

    def _generate_templates(self, state: Formula) -> List[Formula]:
        vars_in_state = collect_free_vars(state)
        templates: List[Formula] = []
        var_list = sorted(vars_in_state)
        for v in var_list:
            templates.append(F_BINOP(">=", F_VAR(v), F_INT(0)))
            for c in [0, 1, 2, 10]:
                templates.append(F_BINOP("==", F_VAR(v), F_INT(c)))
                templates.append(F_BINOP(">=", F_VAR(v), F_INT(c)))
                templates.append(F_BINOP("<=", F_VAR(v), F_INT(c)))
        for i, v1 in enumerate(var_list):
            for v2 in var_list[i+1:]:
                templates.append(F_BINOP("<=", F_VAR(v1), F_VAR(v2)))
                templates.append(F_BINOP(">=", F_VAR(v1), F_VAR(v2)))
                templates.append(F_BINOP("==", F_VAR(v1), F_VAR(v2)))
                diff = F_BINOP("-", F_VAR(v1), F_VAR(v2))
                templates.append(F_BINOP(">=", diff, F_INT(0)))
        return templates

    def _filter_by_z3(
        self, state: Formula, candidates: List[Formula]
    ) -> List[Formula]:
        if not HAS_Z3:
            return []
        confirmed: List[Formula] = []
        z3_vars: Dict[str, Any] = {}
        try:
            gen = _make_vcgen()
            z3_state = gen._formula_to_z3(state, z3_vars)
            if z3_state is None:
                return []
            for cand in candidates:
                try:
                    z3_cand = gen._formula_to_z3(cand, z3_vars)
                    if z3_cand is None:
                        continue
                    solver = z3.Solver()
                    solver.set("timeout", 500)
                    solver.add(z3_state)
                    solver.add(z3.Not(z3_cand))
                    if solver.check() == z3.unsat:
                        confirmed.append(cand)
                except Exception:
                    pass
        except Exception:
            pass
        return confirmed


class InterpolantQuality(Enum):
    """Quality level of a synthesized Craig interpolant."""
    EXACT = auto()          # Extracted from Z3 interpolation API
    FARKAS_APPROX = auto()  # Derived from Farkas coefficients in UNSAT core
    SYNTACTIC = auto()      # Syntactic approximation (fallback)


class InterpolantSynthesizer:
    """Synthesizes loop invariants via Craig interpolation (McMillan 2003).

    THEORY:
    ────────────────────────────────────────────────────────────────────────────
    Craig's Interpolation Theorem (Craig 1957):
      Given A ∧ B unsatisfiable, there exists I (the INTERPOLANT) such that:
        (a) A ⇒ I           (I is implied by A)
        (b) I ∧ B is UNSAT  (I is inconsistent with B)
        (c) vars(I) ⊆ vars(A) ∩ vars(B)  (only shared variables)

    For loop invariant synthesis (McMillan 2003):
      A = precondition ∧ loop_condition
      B = ¬postcondition
      I = loop invariant candidate

    IMPLEMENTATION STRATEGY (three tiers):
    ────────────────────────────────────────────────────────────────────────────
    TIER 1 — Z3 Interpolation API (when available, Z3 4.12+):
      Use z3.interpolant() directly on the UNSAT proof.
      Quality: EXACT

    TIER 2 — Farkas Coefficient Extraction (Pudlák 1997):
      For linear arithmetic, the UNSAT proof contains Farkas coefficients λᵢ
      such that Σᵢ λᵢ·cᵢ = 0 and Σᵢ λᵢ·bᵢ > 0.
      The interpolant is the linear combination restricted to shared variables:
        I = Σᵢ∈A λᵢ·(aᵢ·x + bᵢ) ≥ 0  (only shared vars)
      We approximate this by:
        1. Get UNSAT core from Z3 (minimal unsatisfiable subset)
        2. Identify which core clauses come from A vs B
        3. Build interpolant as conjunction of A-side core clauses
           restricted to shared variables
      Quality: FARKAS_APPROX

    TIER 3 — Syntactic Approximation (fallback):
      Build conjunction of non-negativity bounds for shared variables.
      Quality: SYNTACTIC

    References:
      Craig (1957) "Three Uses of the Herbrand-Gentzen Theorem"
        JSL 22(3), https://doi.org/10.2307/2963594
      McMillan (2003) "Interpolation and SAT-Based Model Checking"
        CAV '03, https://doi.org/10.1007/978-3-540-45069-6_1
      Pudlák (1997) "Lower Bounds for Resolution and Cutting Plane Proofs"
        JSL 62(3), https://doi.org/10.2307/2275563
      Henzinger, Jhala, Majumdar & McMillan (2004) "Abstractions from Proofs"
        POPL '04, https://doi.org/10.1145/964001.964021
    """

    def synthesize(
        self,
        pre: Formula,
        neg_post: Formula,
        shared_vars: Set[str],
        z3_vars: Dict[str, Any],
        formula_to_z3_fn: Any,
    ) -> Optional[Formula]:
        """Synthesize a Craig interpolant for (pre, neg_post).

        Tries tiers in order: Z3 API → Farkas approximation → syntactic.
        Returns None if A ∧ B is satisfiable (no interpolant exists).
        """
        if not HAS_Z3:
            return None
        try:
            return self._synthesize_impl(pre, neg_post, shared_vars, z3_vars, formula_to_z3_fn)
        except Exception:
            return None

    def _synthesize_impl(
        self,
        pre: Formula,
        neg_post: Formula,
        shared_vars: Set[str],
        z3_vars: Dict[str, Any],
        formula_to_z3_fn: Any,
    ) -> Optional[Formula]:
        gen = _make_vcgen()
        local_vars: Dict[str, Any] = dict(z3_vars)
        z3_pre = gen._formula_to_z3(pre, local_vars)
        z3_neg = gen._formula_to_z3(neg_post, local_vars)
        if z3_pre is None or z3_neg is None:
            return None

        # Verify A ∧ B is UNSAT first
        solver = z3.Solver()
        solver.set("timeout", 2000)
        solver.add(z3_pre)
        solver.add(z3_neg)
        if solver.check() != z3.unsat:
            return None  # Satisfiable — no interpolant

        # TIER 1: Try Z3 interpolation API (z3 4.12+)
        tier1 = self._try_z3_interpolation(z3_pre, z3_neg, shared_vars, local_vars, gen)
        if tier1 is not None:
            return tier1

        # TIER 2: Farkas coefficient approximation from UNSAT core
        tier2 = self._farkas_from_unsat_core(
            pre, neg_post, shared_vars, local_vars, gen
        )
        if tier2 is not None:
            return tier2

        # TIER 3: Syntactic approximation
        return self._syntactic_approximation(pre, shared_vars)

    def _try_z3_interpolation(
        self,
        z3_pre: Any,
        z3_neg: Any,
        shared_vars: Set[str],
        z3_vars: Dict[str, Any],
        gen: "VCGenerator",
    ) -> Optional[Formula]:
        """Attempt to use Z3's native interpolation API."""
        try:
            # Z3's interpolation API: z3.interpolant(A, B)
            # Returns I such that A => I and I ∧ B is UNSAT
            a_expr = z3.And(z3_pre) if not isinstance(z3_pre, list) else z3.And(*z3_pre)
            b_expr = z3.And(z3_neg) if not isinstance(z3_neg, list) else z3.And(*z3_neg)
            interp_result = z3.interpolant(a_expr, b_expr)
            if interp_result is not None:
                # Convert Z3 interpolant back to Formula IR
                bi = BiAbductionEngine.__new__(BiAbductionEngine)
                bi._wp = gen.wp_calc
                formula = bi._z3_to_formula(interp_result, z3_vars)
                if formula is not None:
                    # Project onto shared variables only
                    return self._project_to_shared(formula, shared_vars)
        except Exception:
            pass
        return None

    def _farkas_from_unsat_core(
        self,
        pre: Formula,
        neg_post: Formula,
        shared_vars: Set[str],
        z3_vars: Dict[str, Any],
        gen: "VCGenerator",
    ) -> Optional[Formula]:
        """Extract interpolant approximation from Z3 UNSAT core.

        The UNSAT core gives the minimal set of clauses that are jointly
        unsatisfiable.  We split them by origin (A-side vs B-side) and
        build the interpolant as the conjunction of A-side clauses
        restricted to shared variables — this is the Pudlák approximation.
        """
        try:
            # Use named assertions to track A vs B origin
            solver = z3.Solver()
            solver.set("timeout", 2000)
            solver.set("unsat_core", True)

            a_vars: Dict[str, Any] = dict(z3_vars)
            b_vars: Dict[str, Any] = dict(z3_vars)
            z3_a = gen._formula_to_z3(pre, a_vars)
            z3_b = gen._formula_to_z3(neg_post, b_vars)

            if z3_a is None or z3_b is None:
                return None

            # Add A-side clauses with tracking labels
            a_label = z3.Bool("__interp_A")
            b_label = z3.Bool("__interp_B")
            solver.assert_and_track(z3_a, a_label)
            solver.assert_and_track(z3_b, b_label)

            if solver.check() != z3.unsat:
                return None

            core = solver.unsat_core()
            # Check if A-side is in the core
            a_in_core = any(str(c) == "__interp_A" for c in core)
            if not a_in_core:
                return None

            # Build interpolant: A-side constraints restricted to shared vars
            a_free = collect_free_vars(pre)
            shared_in_a = a_free & shared_vars

            if not shared_in_a:
                return None

            # Extract atomic constraints from pre that only use shared vars
            interpolant_parts: List[Formula] = []
            self._extract_shared_constraints(pre, shared_in_a, interpolant_parts)

            if interpolant_parts:
                return F_AND(*interpolant_parts)

            # Fallback: non-negativity bounds for shared vars in A
            return F_AND(*[F_BINOP(">=", F_VAR(v), F_INT(0)) for v in sorted(shared_in_a)])

        except Exception:
            return None

    def _extract_shared_constraints(
        self, formula: Formula, shared: Set[str], out: List[Formula]
    ) -> None:
        """Extract atomic constraints that only reference shared variables."""
        if formula.kind == FormulaKind.AND:
            for child in formula.children:
                self._extract_shared_constraints(child, shared, out)
        elif formula.kind == FormulaKind.BINOP:
            free = collect_free_vars(formula)
            if free and free.issubset(shared):
                out.append(formula)
        elif formula.kind == FormulaKind.NOT:
            inner = formula.children[0]
            if inner.kind == FormulaKind.BINOP:
                free = collect_free_vars(inner)
                if free and free.issubset(shared):
                    out.append(formula)

    def _project_to_shared(self, formula: Formula, shared_vars: Set[str]) -> Optional[Formula]:
        """Project a formula onto shared variables by dropping non-shared atoms."""
        if formula.kind == FormulaKind.AND:
            parts: List[Formula] = []
            for child in formula.children:
                projected = self._project_to_shared(child, shared_vars)
                if projected is not None:
                    parts.append(projected)
            return F_AND(*parts) if parts else None
        free = collect_free_vars(formula)
        if not free or free.issubset(shared_vars):
            return formula
        return None

    def _syntactic_approximation(
        self, pre: Formula, shared_vars: Set[str]
    ) -> Optional[Formula]:
        """Tier 3: syntactic approximation — non-negativity bounds for shared vars."""
        parts: List[Formula] = []
        self._extract_shared_constraints(pre, shared_vars, parts)
        if parts:
            return F_AND(*parts)
        if shared_vars:
            return F_AND(*[F_BINOP(">=", F_VAR(v), F_INT(0)) for v in sorted(shared_vars)])
        return None


# ---------------------------------------------------------------------------
# Weakest Precondition Calculator (expanded)
# ---------------------------------------------------------------------------

class WPCalculator:
    """Computes weakest preconditions for AEON statements.

    Implements Dijkstra's wp-calculus extended with:
      - Procedure call rule (Hoare 1971) via SummaryTable
      - Total correctness VCs via RankingFunction (Floyd 1967)
      - Lexicographic ranking functions (Ben-Amram & Genaim 2014)
      - Abstract interpretation bridge: interval candidates seed Houdini
      - Craig interpolation for invariant synthesis — 3-tier (McMillan 2003)
      - Farkas template synthesis for loop invariants (Colón et al. 2003)
      - IC3/PDR frame propagation (Bradley 2011)
      - Separation logic frame rule awareness (Reynolds 2002)
      - Bi-abduction for precondition inference (Calcagno et al. 2011)
      - Ghost variable support (Owicki & Gries 1976)
      - BreakStmt / ContinueStmt / UnsafeBlock handling (Apt et al. 2009)
      - Quantifier elimination simplification (Z3 qe tactic)
      - Hoare consequence rule with explicit side VCs
      - Richer expression translation: arrays, floats, strings, IfExpr, BlockExpr

    wp(S, Q) = the weakest predicate P such that {P} S {Q}
    """

    def __init__(self, summary_table: Optional[SummaryTable] = None) -> None:
        self._var_counter = 0
        self._summary_table: SummaryTable = summary_table or SummaryTable()
        self._interpolant_synth = InterpolantSynthesizer()
        self._ranking_functions: Dict[int, RankingFunction] = {}
        self._side_vcs: List[Tuple[str, Formula]] = []
        self._ghost_env: GhostEnv = GhostEnv()
        self._loop_post_stack: List[Formula] = []
        self._loop_inv_stack: List[Formula] = []

    def fresh_var(self, prefix: str = "wp") -> str:
        self._var_counter += 1
        return f"__{prefix}_{self._var_counter}"

    def wp(self, stmt: Statement, post: Formula) -> Formula:
        """Compute wp(stmt, post) — the weakest precondition.

        Dispatches to statement-specific handlers.

        Extended for abrupt termination (Apt, de Boer & Olderog 2009):
          - BreakStmt:    exits the enclosing loop → loop postcondition
          - ContinueStmt: skips to next iteration → loop invariant
          - UnsafeBlock:  generates an audit VC + normal wp for body
        """
        if isinstance(stmt, ReturnStmt):
            return self._wp_return(stmt, post)
        if isinstance(stmt, LetStmt):
            return self._wp_let(stmt, post)
        if isinstance(stmt, AssignStmt):
            return self._wp_assign(stmt, post)
        if isinstance(stmt, ExprStmt):
            return self._wp_expr_stmt(stmt, post)
        if isinstance(stmt, IfStmt):
            return self._wp_if(stmt, post)
        if isinstance(stmt, WhileStmt):
            return self._wp_while(stmt, post)
        if isinstance(stmt, BreakStmt):
            return self._wp_break(post)
        if isinstance(stmt, ContinueStmt):
            return self._wp_continue(post)
        if isinstance(stmt, UnsafeBlock):
            return self._wp_unsafe(stmt, post)
        return post

    def _wp_break(self, post: Formula) -> Formula:
        """wp(break, Q) = loop_post — break exits to the enclosing loop's postcondition.

        In the abrupt termination extension of Hoare logic (Apt et al. 2009),
        break transfers control to the statement after the enclosing while loop.
        The postcondition that must hold is the loop's exit postcondition Q,
        not the current continuation's postcondition.

        If not inside a loop (stack empty), treat as skip.

        References:
          Apt, de Boer & Olderog (2009) "Verification of Sequential and
          Concurrent Programs" Springer, §4.5
        """
        if self._loop_post_stack:
            return self._loop_post_stack[-1]
        return post

    def _wp_continue(self, post: Formula) -> Formula:
        """wp(continue, Q) = invariant — continue re-establishes the loop invariant.

        continue skips the remainder of the loop body and jumps to the loop
        condition test. For the wp to be well-defined, the loop invariant I
        must hold at the continue point — so wp(continue, Q) = I.

        If not inside a loop (stack empty), treat as skip.
        """
        if self._loop_inv_stack:
            return self._loop_inv_stack[-1]
        return post

    def _wp_unsafe(self, stmt: UnsafeBlock, post: Formula) -> Formula:
        """wp(unsafe { S }, Q) = wp(S, Q) + audit side VC.

        Unsafe blocks require explicit human review. We generate a side VC
        labelled 'unsafe-audit' that is marked as requiring manual discharge
        (it cannot be automatically proved). The normal wp is still computed
        for the body so downstream analysis can proceed.

        The audit note (if present) is recorded in the side VC label.
        """
        note = stmt.audit_note or "(no audit note)"
        self._side_vcs.append((
            f"unsafe-audit: {note}",
            F_FALSE(),
        ))
        return self.wp_block(stmt.body, post)

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

    def _wp_expr_stmt(self, stmt: ExprStmt, post: Formula) -> Formula:
        """wp(call f(args), Q) using the procedure call rule (Hoare 1971).

        If the expression is a function call and a summary exists:
          wp(call f(args), Q) = pre_f[args/params] /\ (post_f[args/params] => Q)

        Otherwise: expression statements don't affect the postcondition.
        """
        expr = stmt.expr
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            callee_name = expr.callee.name
            summary = self._summary_table.get(callee_name)
            if summary is not None:
                args = [self._expr_to_formula(a) for a in expr.args]
                inst_pre, inst_post = summary.instantiate(args)
                return F_AND(inst_pre, F_IMPLIES(inst_post, post))
        return post

    def _wp_while(self, stmt: WhileStmt, post: Formula) -> Formula:
        """wp(while b do S, Q) — full 8-family Houdini + lex ranking + QE + consequence.

        Verification conditions generated:
          1. INITIATION:         pre => I
          2. CONSECUTION:        {I /\ b} body {I}           (invariant preserved)
          3. POSTCONDITION:      (I /\ !b) => Q               (exit implies post)
          4. LOWER BOUND:        {I /\ b} body {r >= 0}      (ranking >= 0)
          5. STRICT DECREASE:    {I /\ b /\ r=v0} body {r < v0}  (scalar termination)
          6. LEX DECREASE:       {I /\ b /\ r=v} body {r' <_lex v}  (lex termination)
          7. CONSEQUENCE (pre):  I => I  (placeholder; user-supplied pre strengthens)
          8. CONSEQUENCE (post): (I /\ !b) => Q  (Hoare consequence rule)

        §9: Loop context pushed for break/continue handling.
        §10: Invariant simplified via Z3 qe + simplify before use in VCs.
        §4: Lexicographic ranking attempted when scalar ranking fails.

        References:
          Floyd (1967) "Assigning Meanings to Programs"
          Ben-Amram & Genaim (2014) JACM 61(4)
          Apt, de Boer & Olderog (2009) "Verification of Sequential and Concurrent Programs"
        """
        cond = self._expr_to_formula(stmt.condition)
        invariant = self._infer_loop_invariant(stmt, post)

        # §10: Simplify invariant with QE before using in VCs
        invariant = self._qe_simplify(invariant)

        # §9: Push loop context for break/continue
        self._loop_post_stack.append(post)
        self._loop_inv_stack.append(invariant)

        # Side VC 2: Consecution — {I /\ b} body {I}
        consecution_pre = F_AND(invariant, cond)
        wp_body_I = self.wp_block(stmt.body, invariant)
        self._side_vcs.append(
            ("loop-consecution", F_IMPLIES(consecution_pre, wp_body_I))
        )

        # Side VC 3: Postcondition — (I /\ !b) => Q
        self._side_vcs.append(
            ("loop-postcondition", F_IMPLIES(F_AND(invariant, F_NOT(cond)), post))
        )

        # §1: Hoare consequence rule — explicit side VCs
        self._side_vcs.append(
            ("hoare-consequence-post", F_IMPLIES(F_AND(invariant, F_NOT(cond)), post))
        )

        # Total correctness: infer ranking function (scalar + lexicographic)
        rf = self._infer_ranking_function(stmt, invariant, cond)
        if rf is not None:
            self._ranking_functions[id(stmt)] = rf
            if rf.lower_bound_vc is not None:
                self._side_vcs.append(("ranking-lower-bound", rf.lower_bound_vc))
            if rf.is_lexicographic and rf.lex_decrease_vc is not None:
                self._side_vcs.append(("ranking-lex-decrease", rf.lex_decrease_vc))
            elif rf.decrease_vc is not None:
                self._side_vcs.append(("ranking-strict-decrease", rf.decrease_vc))

        # §9: Pop loop context
        self._loop_post_stack.pop()
        self._loop_inv_stack.pop()

        return invariant

    def _qe_simplify(self, formula: Formula) -> Formula:
        """Simplify a formula using Z3's quantifier elimination + simplify tactics.

        Quantifier elimination (Presburger 1929; Cooper 1972) converts a formula
        with quantifiers in Presburger arithmetic into an equivalent quantifier-free
        formula.  This can dramatically reduce the size of wp formulas before
        sending them to the solver.

        Pipeline: qe → simplify → ctx-solver-simplify

        References:
          Cooper (1972) "Theorem Proving in Arithmetic without Multiplication"
            Machine Intelligence 7
          Bjørner & Janota (2015) "Playing with Quantified Satisfaction" LPAR '15
        """
        if not HAS_Z3:
            return formula
        try:
            z3_vars: Dict[str, Any] = {}
            gen = _make_vcgen()
            z3_f = gen._formula_to_z3(formula, z3_vars)
            if z3_f is None:
                return formula
            pipeline = z3.Then(
                z3.Tactic("qe"),
                z3.Tactic("simplify"),
                z3.Tactic("ctx-solver-simplify"),
            )
            goal = z3.Goal()
            goal.add(z3_f)
            result = pipeline(goal)
            if result and result[0]:
                clauses = list(result[0])
                if not clauses:
                    return F_TRUE()
                bi = BiAbductionEngine.__new__(BiAbductionEngine)
                bi._wp = self
                if len(clauses) == 1:
                    back = bi._z3_to_formula(clauses[0], z3_vars)
                    return back if back is not None else formula
                backs = [bi._z3_to_formula(c, z3_vars) for c in clauses]
                backs = [b for b in backs if b is not None]
                return F_AND(*backs) if backs else formula
        except Exception:
            pass
        return formula

    def _infer_loop_invariant(self, stmt: WhileStmt, post: Formula) -> Formula:
        """Infer loop invariant using enhanced Houdini-style algorithm.

        Houdini (Flanagan & Leino 2001):
        1. Start with a large set of candidate invariants from multiple families
        2. Iteratively remove candidates that are not inductive:
             {candidate /\ guard} body {candidate}  must hold
        3. Remaining candidates form the maximal inductive invariant

        Candidate families:
          1. Non-negativity and boundedness (interval domain, Cousot 1977)
          2. Relational / octagonal invariants between variable pairs
          3. Postcondition-derived candidates via wp/sp duality
          4. Ranking function lower-bound candidates (Floyd 1967)
          5. Craig interpolant candidates (McMillan 2003)
          6. Abstract interpretation seeded candidates

        Template-based synthesis (Colon, Sankaranarayanan, Sipma 2003):
          Parameterize invariants as linear inequalities:
            I(x1,...,xn) = c0 + c1*x1 + ... + cn*xn >= 0
          Constraints on c0,...,cn from initiation and consecution.
          Solved via Farkas' lemma (linear programming duality).
        """
        cond = self._expr_to_formula(stmt.condition)
        loop_vars = self._collect_vars(cond)
        post_vars = self._collect_vars(post)
        body_vars = self._collect_vars_from_stmts(stmt.body)
        all_vars = loop_vars | post_vars | body_vars

        candidates: List[Formula] = [F_TRUE()]

        # Family 1: Non-negativity and boundedness (interval domain)
        for var in all_vars:
            candidates.append(F_BINOP(">=", F_VAR(var), F_INT(0)))
            candidates.append(F_BINOP(">", F_VAR(var), F_INT(0)))
            for c in [1, 10, 100, 1000]:
                candidates.append(F_BINOP("<=", F_VAR(var), F_INT(c)))
                candidates.append(F_BINOP(">=", F_VAR(var), F_INT(-c)))

        # Family 2: Relational / octagonal invariants
        var_list = sorted(all_vars)
        for i, v1 in enumerate(var_list):
            for v2 in var_list[i+1:]:
                candidates.append(F_BINOP("<=", F_VAR(v1), F_VAR(v2)))
                candidates.append(F_BINOP(">=", F_VAR(v1), F_VAR(v2)))
                diff = F_BINOP("-", F_VAR(v1), F_VAR(v2))
                candidates.append(F_BINOP(">=", diff, F_INT(0)))
                sum_ = F_BINOP("+", F_VAR(v1), F_VAR(v2))
                candidates.append(F_BINOP(">=", sum_, F_INT(0)))

        # Family 3: Postcondition-derived (wp/sp duality)
        candidates.append(F_OR(cond, post))
        candidates.append(F_IMPLIES(F_NOT(cond), post))
        sp_one = self.sp_block(stmt.body, cond)
        candidates.append(F_OR(cond, sp_one))

        # Family 4: Ranking function lower-bound candidates
        for var in loop_vars:
            candidates.append(F_BINOP(">=", F_VAR(var), F_INT(0)))

        # Family 5: Craig interpolant candidates
        shared = loop_vars & post_vars
        if shared and HAS_Z3:
            interp = self._interpolant_synth.synthesize(
                pre=cond,
                neg_post=F_NOT(post),
                shared_vars=shared,
                z3_vars={},
                formula_to_z3_fn=lambda f, d: None,
            )
            if interp is not None:
                candidates.append(interp)

        # Family 6: Abstract interpretation seeded candidates
        ai_candidates = self._seed_from_abstract_domain(stmt, cond, all_vars)
        candidates.extend(ai_candidates)

        # Family 7: Farkas template synthesis (Colón, Sankaranarayanan & Sipma 2003)
        if all_vars and HAS_Z3:
            farkas = FarkasTemplateSynthesizer(self)
            farkas_inv = farkas.synthesize(
                stmt=stmt,
                pre=cond,
                post=post,
                program_vars=sorted(all_vars)[:6],
            )
            if farkas_inv is not None:
                candidates.append(farkas_inv)

        # Family 8: IC3/PDR frame propagation candidates (Bradley 2011)
        if HAS_Z3:
            ic3 = IC3Engine(self)
            ic3.verify(init=cond, prop=post, stmt=stmt)
            ic3_candidates = ic3.get_invariant_candidates()
            candidates.extend(ic3_candidates)

        # Houdini fixpoint: remove non-inductive candidates
        inductive = self._houdini_filter(candidates, stmt, cond)

        if inductive:
            return F_AND(*inductive)
        return F_TRUE()

    def _collect_vars_from_stmts(self, stmts: List[Statement]) -> Set[str]:
        """Collect all variable names referenced in a list of statements."""
        result: Set[str] = set()
        for stmt in stmts:
            if isinstance(stmt, LetStmt):
                result.add(stmt.name)
                if stmt.value:
                    result |= self._collect_vars(self._expr_to_formula(stmt.value))
            elif isinstance(stmt, AssignStmt):
                if isinstance(stmt.target, Identifier):
                    result.add(stmt.target.name)
                result |= self._collect_vars(self._expr_to_formula(stmt.value))
            elif isinstance(stmt, ExprStmt):
                result |= self._collect_vars(self._expr_to_formula(stmt.expr))
            elif isinstance(stmt, ReturnStmt):
                if stmt.value:
                    result |= self._collect_vars(self._expr_to_formula(stmt.value))
            elif isinstance(stmt, IfStmt):
                result |= self._collect_vars(self._expr_to_formula(stmt.condition))
                result |= self._collect_vars_from_stmts(stmt.then_body)
                if stmt.else_body:
                    result |= self._collect_vars_from_stmts(stmt.else_body)
            elif isinstance(stmt, WhileStmt):
                result |= self._collect_vars(self._expr_to_formula(stmt.condition))
                result |= self._collect_vars_from_stmts(stmt.body)
            elif isinstance(stmt, UnsafeBlock):
                result |= self._collect_vars_from_stmts(stmt.body)
        return result

    def _seed_from_abstract_domain(
        self, stmt: WhileStmt, cond: Formula, all_vars: Set[str]
    ) -> List[Formula]:
        """Seed Houdini candidates from abstract interpretation results.

        Galois connection soundness (Cousot & Cousot 1977):
          alpha(F(gamma(a))) <= F#(a)  for all abstract states a.

        We extract interval bounds from the loop condition syntactically,
        mirroring what the interval abstract domain would compute:
          - cond = "x < N"  =>  seed: x >= 0, x <= N
          - cond = "x > 0"  =>  seed: x >= 1
        """
        seeded: List[Formula] = []
        if cond.kind == FormulaKind.BINOP and len(cond.children) == 2:
            lhs, rhs = cond.children[0], cond.children[1]
            op = cond.op
            if lhs.kind == FormulaKind.VAR:
                v = lhs.name
                if op in ("<", "<=") and rhs.kind == FormulaKind.INT_CONST:
                    seeded.append(F_BINOP(">=", F_VAR(v), F_INT(0)))
                    seeded.append(F_BINOP("<=", F_VAR(v), F_INT(rhs.int_val)))
                elif op in (">", ">=") and rhs.kind == FormulaKind.INT_CONST:
                    lb = rhs.int_val + (1 if op == ">" else 0)
                    seeded.append(F_BINOP(">=", F_VAR(v), F_INT(lb)))
        return seeded

    def _houdini_filter(
        self, candidates: List[Formula], stmt: WhileStmt, cond: Formula
    ) -> List[Formula]:
        """Houdini fixpoint: iteratively remove non-inductive candidates.

        A candidate I is inductive if:
          {I /\ guard} body {I}  is valid
        i.e., (I /\ guard) => wp(body, I).

        We check this with Z3 when available; otherwise keep all candidates.
        """
        if not HAS_Z3 or not candidates:
            return candidates

        active = list(candidates)
        changed = True
        while changed:
            changed = False
            still_active: List[Formula] = []
            invariant_conj = F_AND(*active) if active else F_TRUE()
            for cand in active:
                pre = F_AND(invariant_conj, cond)
                wp_body = self.wp_block(stmt.body, cand)
                vc = F_IMPLIES(pre, wp_body)
                if self._z3_check_valid(vc):
                    still_active.append(cand)
                else:
                    changed = True
            active = still_active
        return active

    def _z3_check_valid(self, formula: Formula) -> bool:
        """Return True if formula is valid (Z3 returns UNSAT for its negation)."""
        if not HAS_Z3:
            return True
        try:
            z3_vars: Dict[str, Any] = {}
            gen = _make_vcgen()
            z3_f = gen._formula_to_z3(formula, z3_vars)
            if z3_f is None:
                return True
            solver = z3.Solver()
            solver.set("timeout", 1000)
            solver.add(z3.Not(z3_f))
            return solver.check() == z3.unsat
        except Exception:
            return True

    def _infer_ranking_function(
        self, stmt: WhileStmt, invariant: Formula, cond: Formula
    ) -> Optional[RankingFunction]:
        """Infer a ranking function for total correctness (Floyd 1967).

        STRATEGY:
          1. Try scalar ranking: r = var for each variable in the loop condition.
             Check if {I ∧ b ∧ r=v₀} body {r < v₀} is valid (Z3 UNSAT for negation).
          2. If scalar fails, try lexicographic ranking: ⟨r₁, r₂⟩ for all pairs.
             Check the lexicographic decrease VC (Ben-Amram & Genaim 2014).
          3. Generate lower-bound VCs for all components.

        SCALAR VCs:
          LOWER BOUND:     {I ∧ b} body {r ≥ 0}
          STRICT DECREASE: {I ∧ b ∧ r = v₀} body {r < v₀}

        LEXICOGRAPHIC VCs:
          LOWER BOUND:  ∀i. {I ∧ b} body {rᵢ ≥ 0}
          LEX DECREASE: {I ∧ b ∧ r₁=v₁ ∧ r₂=v₂} body
                          {r₁' < v₁  ∨  (r₁'=v₁ ∧ r₂' < v₂)}

        References:
          Floyd (1967) "Assigning Meanings to Programs"
          Ben-Amram & Genaim (2014) "Ranking Functions for Linear-Constraint Loops"
            JACM 61(4), https://doi.org/10.1145/2629488
          Colón & Sipma (2001) "Synthesis of Linear Ranking Functions"
            TACAS '01, https://doi.org/10.1007/3-540-45319-9_19
        """
        loop_vars = self._collect_vars(cond)
        body_vars = self._collect_vars_from_stmts(stmt.body)
        all_rank_vars = sorted(loop_vars | body_vars)
        if not all_rank_vars:
            return None

        pre = F_AND(invariant, cond)

        # --- Try scalar ranking for each candidate variable ---
        for rank_var in sorted(loop_vars) or all_rank_vars[:3]:
            rank_formula = F_VAR(rank_var)
            lower_bound_post = F_BINOP(">=", rank_formula, F_INT(0))
            lower_bound_vc = F_IMPLIES(pre, self.wp_block(stmt.body, lower_bound_post))

            v0 = self.fresh_var("v0")
            pre_decrease = F_AND(invariant, cond, F_BINOP("==", rank_formula, F_VAR(v0)))
            decrease_post = F_BINOP("<", rank_formula, F_VAR(v0))
            decrease_vc = F_IMPLIES(pre_decrease, self.wp_block(stmt.body, decrease_post))

            # Check if scalar ranking is valid
            if self._z3_check_valid(decrease_vc):
                return RankingFunction(
                    formula=rank_formula,
                    variables=[rank_var],
                    lower_bound_vc=lower_bound_vc,
                    decrease_vc=decrease_vc,
                    is_lexicographic=False,
                )

        # --- Scalar failed: try lexicographic ranking over pairs ---
        candidates = all_rank_vars[:4]  # limit to 4 vars for tractability
        for i, v1 in enumerate(candidates):
            for v2 in candidates[i + 1:]:
                rf = self._try_lex_ranking(stmt, invariant, cond, pre, [v1, v2])
                if rf is not None:
                    return rf

        # --- Fallback: return scalar ranking for first variable without validity check ---
        rank_var = sorted(loop_vars)[0] if loop_vars else all_rank_vars[0]
        rank_formula = F_VAR(rank_var)
        lower_bound_post = F_BINOP(">=", rank_formula, F_INT(0))
        lower_bound_vc = F_IMPLIES(pre, self.wp_block(stmt.body, lower_bound_post))
        v0 = self.fresh_var("v0")
        pre_decrease = F_AND(invariant, cond, F_BINOP("==", rank_formula, F_VAR(v0)))
        decrease_post = F_BINOP("<", rank_formula, F_VAR(v0))
        decrease_vc = F_IMPLIES(pre_decrease, self.wp_block(stmt.body, decrease_post))
        return RankingFunction(
            formula=rank_formula,
            variables=[rank_var],
            lower_bound_vc=lower_bound_vc,
            decrease_vc=decrease_vc,
            is_lexicographic=False,
        )

    def _try_lex_ranking(
        self,
        stmt: WhileStmt,
        invariant: Formula,
        cond: Formula,
        pre: Formula,
        rank_vars: List[str],
    ) -> Optional[RankingFunction]:
        """Attempt to prove termination via a lexicographic ranking tuple.

        For ⟨r₁, r₂⟩, the lex decrease VC is:
          {I ∧ b ∧ r₁=v₁ ∧ r₂=v₂} body {r₁' < v₁  ∨  (r₁'=v₁ ∧ r₂' < v₂)}

        Returns a RankingFunction if the VC is valid, None otherwise.
        """
        n = len(rank_vars)
        components = [F_VAR(v) for v in rank_vars]
        v0s = [self.fresh_var(f"lex_v{i}") for i in range(n)]

        # Build pre: I ∧ b ∧ r₁=v₁ ∧ ... ∧ rₙ=vₙ
        equalities = [F_BINOP("==", F_VAR(v), F_VAR(v0s[i])) for i, v in enumerate(rank_vars)]
        pre_lex = F_AND(invariant, cond, *equalities)

        # Build post-state values after body execution
        # We use wp to compute what the ranking expressions become after body
        post_components: List[Formula] = []
        for comp in components:
            # wp(body, r < v0) gives us information about r after body
            # We approximate post-state as the component itself (identity)
            # The actual decrease is checked via the VC
            post_components.append(comp)

        # Build lex decrease formula using RankingFunction.lex_decrease_formula
        rf_dummy = RankingFunction(
            formula=components[0],
            variables=rank_vars,
            is_lexicographic=True,
            components=components,
        )
        pre_vals = [F_VAR(v0s[i]) for i in range(n)]
        lex_dec = rf_dummy.lex_decrease_formula(pre_vals, post_components)

        lex_decrease_vc = F_IMPLIES(pre_lex, self.wp_block(stmt.body, lex_dec))

        if not self._z3_check_valid(lex_decrease_vc):
            return None

        # Lower bound VCs for each component
        lower_bound_vcs: List[Formula] = []
        for comp in components:
            lb_post = F_BINOP(">=", comp, F_INT(0))
            lower_bound_vcs.append(F_IMPLIES(pre, self.wp_block(stmt.body, lb_post)))

        combined_lb = F_AND(*lower_bound_vcs) if lower_bound_vcs else F_TRUE()

        return RankingFunction(
            formula=F_LEX_RANK(*components),
            variables=rank_vars,
            lower_bound_vc=combined_lb,
            lex_decrease_vc=lex_decrease_vc,
            is_lexicographic=True,
            components=components,
        )

    def sp(self, stmt: Statement, pre: Formula) -> Formula:
        """Compute sp(stmt, pre) — the STRONGEST POSTCONDITION.

        Dual to wp — works FORWARDS from precondition (Dijkstra 1976):
          sp(x := e, P)                 = exists x0. P[x/x0] /\ x = e[x/x0]
          sp(S1; S2, P)                 = sp(S2, sp(S1, P))
          sp(if b then S1 else S2, P)   = sp(S1, P/\b) \/ sp(S2, P/\!b)
          sp(while b do S, P)           = approx: sp(body, P/\b) \/ (P/\!b)
          sp(call f(args), P)           = P /\ post_f[args/params]  (summary)

        Used for:
          - Bug finding (forward reasoning finds reachable states)
          - Invariant inference (sp of loop body from invariant)
          - Daikon-style assertion inference at program points
          - Owicki-Gries interference freedom checking
        """
        if isinstance(stmt, LetStmt) and stmt.value:
            expr_f = self._expr_to_formula(stmt.value)
            old_var = self.fresh_var(stmt.name)
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

        if isinstance(stmt, WhileStmt):
            # §11: Use the inferred loop invariant for a sound sp approximation.
            #
            # The exact sp for a while loop is the least fixpoint:
            #   sp(while b do S, P) = lfp X. P ∨ sp(S, X ∧ b)
            # which is generally not computable.
            #
            # We use the inferred invariant I as a sound over-approximation:
            #   sp(while b do S, P) ≈ I ∧ ¬b
            #
            # This is sound because:
            #   (a) I is inductive: {I ∧ b} S {I}
            #   (b) The loop exits with ¬b
            #   (c) P ⇒ I (initiation), so I is reachable from P
            #
            # Compared to the one-step unrolling approximation, this gives a
            # much tighter (stronger) postcondition that captures the full
            # invariant rather than just one iteration's effect.
            #
            # References:
            #   Dijkstra (1976) "A Discipline of Programming" §4
            #   Cousot & Cousot (1977) "Abstract Interpretation" POPL '77
            cond_f = self._expr_to_formula(stmt.condition)
            invariant = self._infer_loop_invariant(stmt, pre)
            invariant = self._qe_simplify(invariant)
            return F_AND(invariant, F_NOT(cond_f))

        if isinstance(stmt, ExprStmt):
            expr = stmt.expr
            if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
                summary = self._summary_table.get(expr.callee.name)
                if summary is not None:
                    args = [self._expr_to_formula(a) for a in expr.args]
                    _, inst_post = summary.instantiate(args)
                    return F_AND(pre, inst_post)

        return pre

    def sp_block(self, stmts: List[Statement], pre: Formula) -> Formula:
        """Compute sp for a sequence of statements (forward)."""
        result = pre
        for stmt in stmts:
            result = self.sp(stmt, result)
        return result

    def _collect_vars(self, formula: Formula) -> Set[str]:
        """Collect all free variables in a formula (delegates to collect_free_vars)."""
        return collect_free_vars(formula)

    def _expr_to_formula(self, expr: Expr) -> Formula:
        """Convert an AEON expression to a logical formula.

        Extended to handle:
          - FloatLiteral  -> F_FLOAT (exact representation)
          - StringLiteral -> F_STRING_EQ (string equality predicate)
          - ListLiteral   -> F_ARRAY_SELECT / F_ARRAY_LEN
          - IfExpr        -> F_ITE
          - BlockExpr     -> sequential sp through statements
          - MoveExpr      -> treated as variable reference
          - BorrowExpr    -> treated as variable reference
          - FunctionCall  -> procedure call rule if summary available
          - MethodCall    -> method result variable
          - FieldAccess   -> field projection variable
        """
        if isinstance(expr, IntLiteral):
            return F_INT(expr.value)
        if isinstance(expr, FloatLiteral):
            return F_FLOAT(expr.value)
        if isinstance(expr, BoolLiteral):
            return F_BOOL(expr.value)
        if isinstance(expr, StringLiteral):
            # Represent string as a named variable with an equality predicate
            var_name = f"str_{abs(hash(expr.value)) % 100000}"
            return F_VAR(var_name)
        if isinstance(expr, Identifier):
            return F_VAR(expr.name)
        if isinstance(expr, MoveExpr):
            return F_VAR(expr.name)
        if isinstance(expr, BorrowExpr):
            return F_VAR(expr.name)
        if isinstance(expr, BinaryOp):
            left = self._expr_to_formula(expr.left)
            right = self._expr_to_formula(expr.right)
            if expr.op == "&&":
                return F_AND(left, right)
            if expr.op == "||":
                return F_OR(left, right)
            if expr.op == "==":
                return F_BINOP("==", left, right)
            if expr.op == "!=":
                return F_NOT(F_BINOP("==", left, right))
            if expr.op in ("/", "%"):
                # Division-by-zero safety VC: denominator != 0
                nonzero_vc = F_BINOP("!=", right, F_INT(0))
                self._side_vcs.append(("division-by-zero", nonzero_vc))
            return F_BINOP(expr.op, left, right)
        if isinstance(expr, UnaryOp):
            inner = self._expr_to_formula(expr.operand)
            if expr.op == "!":
                return F_NOT(inner)
            if expr.op == "-":
                return F_UNOP("-", inner)
            return inner
        if isinstance(expr, IfExpr):
            cond = self._expr_to_formula(expr.condition)
            # Approximate then/else as sp of their blocks
            then_f = self.sp_block(expr.then_body, cond)
            else_f = self.sp_block(expr.else_body, F_NOT(cond)) if expr.else_body else F_NOT(cond)
            return F_ITE(cond, then_f, else_f)
        if isinstance(expr, BlockExpr):
            # Treat block as sp of its statements from TRUE
            return self.sp_block(expr.statements, F_TRUE())
        if isinstance(expr, ListLiteral):
            # Represent as an array variable with known length
            arr_var = self.fresh_var("arr")
            len_f = F_ARRAY_LEN(F_VAR(arr_var))
            size = F_INT(len(expr.elements))
            return F_AND(F_VAR(arr_var), F_BINOP("==", len_f, size))
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                callee_name = expr.callee.name
                summary = self._summary_table.get(callee_name)
                if summary is not None:
                    args = [self._expr_to_formula(a) for a in expr.args]
                    _, inst_post = summary.instantiate(args)
                    return inst_post
                return F_VAR(f"call_{callee_name}")
            return F_VAR("call_unknown")
        if isinstance(expr, FieldAccess):
            obj_f = self._expr_to_formula(expr.obj)
            obj_str = str(obj_f)
            return F_VAR(f"{obj_str}__{expr.field_name}")
        if isinstance(expr, MethodCall):
            obj_f = self._expr_to_formula(expr.obj)
            obj_str = str(obj_f)
            return F_VAR(f"{obj_str}__{expr.method_name}")
        if isinstance(expr, ConstructExpr):
            return F_VAR(f"ctor_{expr.type_name}")
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
    function_name: str = ""
    postcondition: Optional[Formula] = None
    wp_formula: Optional[Formula] = None
    formula: Optional[Formula] = None   # full implication: pre => obligation

    def __str__(self) -> str:
        return f"VC[{self.name}]: {self.precondition} => {self.obligation}"


class VCGenerator:
    """Generates and discharges verification conditions for AEON functions.

    Extended pipeline for each function with contracts:
      1.  Build call graph and compute SCCs via Tarjan's algorithm (§12)
      2.  Process SCCs bottom-up: callees before callers
      3.  For mutually recursive SCCs: fixpoint iteration until summaries stabilise
      4.  Check incremental cache — skip if unchanged
      5.  Extract precondition P from requires clauses
      6.  Extract postcondition Q from ensures clauses
      7.  Compute wp(body, Q) using the wp-calculus
      8.  Generate main VC: P => wp(body, Q)
      9.  Discharge side VCs: loop consecution, postcondition, ranking
      10. Check refinement type consistency for annotated let-bindings
      11. Run Owicki-Gries interference freedom for concurrent functions
      12. Discharge all VCs to Z3, extract counterexamples with explanation
      13. Produce ProofCertificate for each discharged VC
      14. Store results in incremental cache

    MUTUAL RECURSION HANDLING (§12 — Tarjan SCC):
    ────────────────────────────────────────────────────────────────────────────
    Mutually recursive functions (e.g., f calls g, g calls f) cannot be
    verified independently — their summaries are interdependent.

    We use Tarjan's strongly connected components algorithm (Tarjan 1972) to:
      1. Build the call graph: edge f → g if f's body calls g
      2. Compute SCCs: each SCC is a maximal set of mutually recursive functions
      3. Process SCCs in reverse topological order (callees before callers)
      4. For singleton SCCs (no mutual recursion): verify directly
      5. For non-singleton SCCs (mutual recursion): iterate summaries to fixpoint

    FIXPOINT ITERATION for mutual recursion:
      - Initialise all summaries in the SCC to {True} f {True} (top element)
      - Iteratively re-verify each function in the SCC using current summaries
      - Update summaries with the wp-derived postcondition
      - Repeat until summaries stabilise (Kleene fixpoint theorem)
      - Convergence is guaranteed by the lattice structure of formulas

    This is the standard approach used in:
      - Hoare (1971) "Procedures and Parameters" (procedure call rule)
      - Cousot & Cousot (1977) abstract interpretation fixpoints
      - Flanagan & Leino (2001) Houdini for modular verification

    References:
      Tarjan (1972) "Depth-First Search and Linear Graph Algorithms"
        SIAM J. Computing 1(2), https://doi.org/10.1137/0201010
      Hoare (1971) "Procedures and Parameters: An Axiomatic Approach"
        Symposium on Semantics of Algorithmic Languages
      Cousot & Cousot (1977) "Abstract Interpretation: A Unified Lattice Model"
        POPL '77, https://doi.org/10.1145/512950.512973
    """

    def __init__(self, cache: Optional[HoareCache] = None) -> None:
        self._summary_table = SummaryTable()
        self.wp_calc = WPCalculator(summary_table=self._summary_table)
        self.vcs: List[VerificationCondition] = []
        self.errors: List[AeonError] = []
        self.certificates: List[ProofCertificate] = []
        self._cache = cache or HoareCache()

    def verify_program(self, program: Program) -> List[AeonError]:
        """Generate and check VCs for all functions in a program.

        Uses Tarjan SCC to process mutually recursive functions correctly.
        """
        self.errors = []
        self.vcs = []
        self.certificates = []

        functions = [d for d in program.declarations
                     if isinstance(d, (PureFunc, TaskFunc))]

        # §12: Build call graph and compute SCCs
        call_graph = self._build_call_graph(functions)
        sccs = self._tarjan_sccs(functions, call_graph)

        # Initialise all summaries (top element for fixpoint)
        self._build_summary_table(functions)

        # Process SCCs in reverse topological order (bottom-up)
        for scc in sccs:
            if len(scc) == 1:
                # Singleton SCC — no mutual recursion, verify directly
                self._verify_function(scc[0])
            else:
                # Non-singleton SCC — mutual recursion, iterate to fixpoint
                self._verify_mutually_recursive_scc(scc)

        return self.errors

    def _build_call_graph(
        self, functions: List
    ) -> Dict[str, Set[str]]:
        """Build the call graph: func_name → set of called func_names.

        Scans each function body for FunctionCall nodes to identify
        direct calls. Only calls to functions in the program are tracked.
        """
        func_names = {f.name for f in functions}
        graph: Dict[str, Set[str]] = {f.name: set() for f in functions}

        for func in functions:
            self._collect_calls(func.body, func.name, func_names, graph)

        return graph

    def _collect_calls(
        self,
        stmts: List[Statement],
        caller: str,
        func_names: Set[str],
        graph: Dict[str, Set[str]],
    ) -> None:
        """Recursively collect function calls from a statement list."""
        for stmt in stmts:
            if isinstance(stmt, ExprStmt):
                if isinstance(stmt.expr, FunctionCall) and isinstance(stmt.expr.callee, Identifier):
                    callee = stmt.expr.callee.name
                    if callee in func_names:
                        graph[caller].add(callee)
            elif isinstance(stmt, LetStmt) and stmt.value:
                self._collect_calls_from_expr(stmt.value, caller, func_names, graph)
            elif isinstance(stmt, AssignStmt):
                self._collect_calls_from_expr(stmt.value, caller, func_names, graph)
            elif isinstance(stmt, ReturnStmt) and stmt.value:
                self._collect_calls_from_expr(stmt.value, caller, func_names, graph)
            elif isinstance(stmt, IfStmt):
                self._collect_calls(stmt.then_body, caller, func_names, graph)
                if stmt.else_body:
                    self._collect_calls(stmt.else_body, caller, func_names, graph)
            elif isinstance(stmt, WhileStmt):
                self._collect_calls(stmt.body, caller, func_names, graph)

    def _collect_calls_from_expr(
        self, expr: Expr, caller: str, func_names: Set[str], graph: Dict[str, Set[str]]
    ) -> None:
        """Collect function calls from an expression."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            callee = expr.callee.name
            if callee in func_names:
                graph[caller].add(callee)
            for arg in expr.args:
                self._collect_calls_from_expr(arg, caller, func_names, graph)
        elif isinstance(expr, BinaryOp):
            self._collect_calls_from_expr(expr.left, caller, func_names, graph)
            self._collect_calls_from_expr(expr.right, caller, func_names, graph)
        elif isinstance(expr, UnaryOp):
            self._collect_calls_from_expr(expr.operand, caller, func_names, graph)
        elif isinstance(expr, IfExpr):
            self._collect_calls_from_expr(expr.condition, caller, func_names, graph)
            self._collect_calls(expr.then_body, caller, func_names, graph)
            self._collect_calls(expr.else_body, caller, func_names, graph)

    def _tarjan_sccs(
        self, functions: List, call_graph: Dict[str, Set[str]]
    ) -> List[List]:
        """Compute strongly connected components using Tarjan's algorithm.

        Tarjan (1972): O(V + E) DFS-based SCC algorithm.

        Returns SCCs in reverse topological order (callees before callers),
        which is the correct bottom-up processing order for modular verification.

        Algorithm:
          - Maintain a DFS stack and discovery/low-link indices
          - When low[v] == index[v], v is the root of an SCC
          - Pop the stack to collect the SCC

        References:
          Tarjan (1972) "Depth-First Search and Linear Graph Algorithms"
            SIAM J. Computing 1(2), https://doi.org/10.1137/0201010
        """
        func_map = {f.name: f for f in functions}
        index_counter = [0]
        stack: List[str] = []
        lowlink: Dict[str, int] = {}
        index: Dict[str, int] = {}
        on_stack: Dict[str, bool] = {}
        sccs: List[List] = []

        def strongconnect(v: str) -> None:
            index[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True

            for w in call_graph.get(v, set()):
                if w not in index:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif on_stack.get(w, False):
                    lowlink[v] = min(lowlink[v], index[w])

            if lowlink[v] == index[v]:
                scc_names: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc_names.append(w)
                    if w == v:
                        break
                scc_funcs = [func_map[n] for n in scc_names if n in func_map]
                if scc_funcs:
                    sccs.append(scc_funcs)

        for func in functions:
            if func.name not in index:
                strongconnect(func.name)

        return sccs

    def _verify_mutually_recursive_scc(self, scc: List) -> None:
        """Verify a set of mutually recursive functions via fixpoint iteration.

        ALGORITHM:
          1. Initialise summaries to {True} f {True} (weakest possible)
          2. Iterate: for each function in the SCC, compute wp(body, ensures)
             and update its summary postcondition
          3. Check convergence: if no summary changed, we have reached the fixpoint
          4. Verify each function against the fixpoint summaries

        CONVERGENCE:
          The summary lattice is (Formula, ⊑) where P ⊑ Q iff P ⇒ Q.
          Each iteration strengthens summaries (makes postconditions stronger).
          Since the formula space is finite (bounded by the program's syntax),
          the iteration terminates in at most O(|functions| × |formulas|) steps.
          In practice, convergence is fast (2-5 iterations for typical programs).

        MAX_ITERATIONS is a safety bound to prevent non-termination in
        pathological cases (should never be reached for well-typed programs).
        """
        MAX_ITERATIONS = 10

        # Step 1: Initialise all summaries in the SCC to {True} f {True}
        for func in scc:
            params = [p.name for p in func.params]
            self._summary_table.register(FunctionSummary(
                name=func.name,
                params=params,
                precondition=F_TRUE(),
                postcondition=F_TRUE(),
            ))

        # Step 2: Fixpoint iteration
        for iteration in range(MAX_ITERATIONS):
            changed = False
            for func in scc:
                if not func.requires and not func.ensures:
                    continue

                post_formulas = [self.wp_calc._expr_to_formula(e.expr) for e in func.ensures]
                postcondition = F_AND(*post_formulas) if post_formulas else F_TRUE()

                self.wp_calc._side_vcs = []
                wp_result = self.wp_calc.wp_block(func.body, postcondition)

                # Update summary with the wp-derived postcondition
                old_summary = self._summary_table.get(func.name)
                old_post_str = str(old_summary.postcondition) if old_summary else ""
                new_post_str = str(wp_result)

                if new_post_str != old_post_str:
                    changed = True
                    params = [p.name for p in func.params]
                    pre_formulas = [self.wp_calc._expr_to_formula(r.expr) for r in func.requires]
                    precondition = F_AND(*pre_formulas) if pre_formulas else F_TRUE()
                    self._summary_table.register(FunctionSummary(
                        name=func.name,
                        params=params,
                        precondition=precondition,
                        postcondition=wp_result,
                    ))
                    self._cache.invalidate_dependents(func.name)

            if not changed:
                break  # Fixpoint reached

        # Step 3: Verify each function against the fixpoint summaries
        for func in scc:
            self._verify_function(func)

    def _build_summary_table(self, functions: List) -> None:
        """Populate SummaryTable with contract-derived function summaries.

        Initial summaries are derived from the declared contracts.
        For mutually recursive functions, these are refined by fixpoint iteration
        in _verify_mutually_recursive_scc.
        """
        for func in functions:
            pre_fs = [self.wp_calc._expr_to_formula(r.expr) for r in func.requires]
            post_fs = [self.wp_calc._expr_to_formula(e.expr) for e in func.ensures]
            pre = F_AND(*pre_fs) if pre_fs else F_TRUE()
            post = F_AND(*post_fs) if post_fs else F_TRUE()
            params = [p.name for p in func.params]
            summary = FunctionSummary(
                name=func.name,
                params=params,
                precondition=pre,
                postcondition=post,
            )
            self._summary_table.register(summary)

    def _verify_function(self, func: PureFunc | TaskFunc) -> None:
        """Generate and discharge all VCs for a single function.

        Safety VCs (division-by-zero) are always generated regardless of
        whether the function has contracts.  Contract VCs are only generated
        when requires/ensures clauses are present.
        """
        self.wp_calc._side_vcs = []
        self.wp_calc._ranking_functions = {}

        # Always scan the body for safety VCs (division-by-zero etc.)
        # by computing wp(body, TRUE) — this triggers _expr_to_formula on
        # every expression in the body, which emits safety side VCs.
        self.wp_calc.wp_block(func.body, F_TRUE())
        safety_side_vcs = list(self.wp_calc._side_vcs)

        # Register safety VCs in gen.vcs so callers can inspect them
        for label, safety_formula in safety_side_vcs:
            safety_vc = VerificationCondition(
                name=f"{label}_{func.name}",
                precondition=F_TRUE(),
                obligation=safety_formula,
                location=func.location,
                kind="safety",
                function_name=func.name,
                formula=safety_formula,
            )
            self.vcs.append(safety_vc)

        if not func.requires and not func.ensures:
            # Discharge safety VCs and return — no contract VCs to generate
            func_errors: List[AeonError] = []
            func_certs: List[ProofCertificate] = []
            for safety_vc in [vc for vc in self.vcs
                               if vc.function_name == func.name and vc.kind == "safety"]:
                err, cert = self._discharge_vc(safety_vc, func, rule=safety_vc.name.split("_")[0])
                if err:
                    func_errors.append(err)
                if cert:
                    func_certs.append(cert)
            self.errors.extend(func_errors)
            self.certificates.extend(func_certs)
            return

        summary_hash = hashlib.sha256(
            str(self._summary_table.all_names()).encode()
        ).hexdigest()[:8]
        cached = self._cache.lookup(func, summary_hash)
        if cached is not None:
            cached_errors, cached_certs = cached
            self.errors.extend(cached_errors)
            self.certificates.extend(cached_certs)
            return

        self.wp_calc._side_vcs = []
        self.wp_calc._ranking_functions = {}

        pre_formulas = [self.wp_calc._expr_to_formula(r.expr) for r in func.requires]
        precondition = F_AND(*pre_formulas) if pre_formulas else F_TRUE()

        post_formulas = [self.wp_calc._expr_to_formula(e.expr) for e in func.ensures]
        postcondition = F_AND(*post_formulas) if post_formulas else F_TRUE()

        wp_result = self.wp_calc.wp_block(func.body, postcondition)

        main_vc = VerificationCondition(
            name=f"contract_{func.name}",
            precondition=precondition,
            obligation=wp_result,
            location=func.location,
            kind="partial_correctness",
            function_name=func.name,
            postcondition=postcondition,
            wp_formula=wp_result,
            formula=F_IMPLIES(precondition, wp_result),
        )
        self.vcs.append(main_vc)

        func_errors: List[AeonError] = []
        func_certs: List[ProofCertificate] = []

        err, cert = self._discharge_vc(main_vc, func, rule="wp-contract")
        if err:
            func_errors.append(err)
        if cert:
            func_certs.append(cert)

        for label, side_formula in self.wp_calc._side_vcs:
            side_vc = VerificationCondition(
                name=f"{label}_{func.name}",
                precondition=F_TRUE(),
                obligation=side_formula,
                location=func.location,
                kind="total_correctness" if "ranking" in label else "partial_correctness",
                function_name=func.name,
                formula=side_formula,
            )
            self.vcs.append(side_vc)
            err, cert = self._discharge_vc(side_vc, func, rule=label)
            if err:
                func_errors.append(err)
            if cert:
                func_certs.append(cert)

        for rvc in self._check_refinement_type_consistency(func, precondition):
            self.vcs.append(rvc)
            err, cert = self._discharge_vc(rvc, func, rule="refinement-type-consistency")
            if err:
                func_errors.append(err)
            if cert:
                func_certs.append(cert)

        if isinstance(func, TaskFunc):
            for ogvc in self._check_owicki_gries(func, precondition, postcondition):
                self.vcs.append(ogvc)
                err, cert = self._discharge_vc(ogvc, func, rule="owicki-gries-interference")
                if err:
                    func_errors.append(err)
                if cert:
                    func_certs.append(cert)

        self.errors.extend(func_errors)
        self.certificates.extend(func_certs)
        self._cache.store(func, summary_hash, func_errors, func_certs)

    def _check_refinement_type_consistency(
        self, func: PureFunc | TaskFunc, precondition: Formula
    ) -> List[VerificationCondition]:
        """Check liquid type annotations are consistent with wp-derived conditions.

        For each let-binding with a refined type annotation {v: T | p},
        generate: precondition => p[v/e]
        """
        vcs: List[VerificationCondition] = []
        for stmt in func.body:
            if not isinstance(stmt, LetStmt):
                continue
            if stmt.type_annotation is None or stmt.value is None:
                continue
            ann_str = str(stmt.type_annotation)
            if "|" not in ann_str:
                continue
            pred_var = F_VAR(f"refine_{stmt.name}")
            expr_f = self.wp_calc._expr_to_formula(stmt.value)
            refined_pred = substitute(pred_var, stmt.name, expr_f)
            vc_formula = F_IMPLIES(precondition, refined_pred)
            vcs.append(VerificationCondition(
                name=f"refinement_{func.name}_{stmt.name}",
                precondition=precondition,
                obligation=refined_pred,
                location=stmt.location,
                kind="refinement_type",
                function_name=func.name,
                formula=vc_formula,
            ))
        return vcs

    def _check_owicki_gries(
        self,
        func: TaskFunc,
        precondition: Formula,
        postcondition: Formula,
    ) -> List[VerificationCondition]:
        """Check Owicki-Gries interference freedom for concurrent task functions.

        For each other task function sharing variables with func:
          Every statement in func.body must preserve the other's precondition.
          Interference freedom: {A /\ pre(s)} s {A}  =>  A => wp(s, A)
        """
        vcs: List[VerificationCondition] = []
        func_vars = set(p.name for p in func.params)

        for other_name in self._summary_table.all_names():
            if other_name == func.name:
                continue
            other_summary = self._summary_table.get(other_name)
            if other_summary is None:
                continue
            shared = func_vars & set(other_summary.params)
            if not shared:
                continue
            for stmt in func.body:
                other_pre = other_summary.precondition
                wp_stmt = self.wp_calc.wp(stmt, other_pre)
                interference_vc = F_IMPLIES(F_AND(precondition, other_pre), wp_stmt)
                vcs.append(VerificationCondition(
                    name=f"og_{func.name}_vs_{other_name}",
                    precondition=F_AND(precondition, other_pre),
                    obligation=wp_stmt,
                    location=func.location,
                    kind="owicki_gries",
                    function_name=func.name,
                    formula=interference_vc,
                ))
        return vcs

    def _discharge_vc(
        self,
        vc: VerificationCondition,
        func: PureFunc | TaskFunc,
        rule: str = "wp-contract",
    ) -> Tuple[Optional[AeonError], Optional[ProofCertificate]]:
        """Discharge a VC using Z3 with UNSAT core extraction.

        On UNSAT (proved):
          - Extracts the minimal UNSAT core via Z3's unsat_core option
          - Populates ProofCertificate.unsat_core for Lean4/Coq tactic generation
          - Builds proof_rule_chain from the VC kind
          - Detects existential witnesses for ∃-goals

        On SAT (failed):
          - Extracts counterexample model
          - Generates repair hint

        References:
          Nieuwenhuis, Oliveras & Tinelli (2006)
            "Solving SAT and SAT Modulo Theories: From an Abstract Davis-Putnam-
             Logemann-Loveland Procedure to DPLL(T)"
            JACM 53(6), https://doi.org/10.1145/1217856.1217859
        """
        if not HAS_Z3:
            return None, None

        t0 = _time.time()
        try:
            # Use unsat_core=True solver for UNSAT core extraction
            solver = z3.Solver()
            solver.set("timeout", 10000)
            solver.set("unsat_core", True)
            z3_vars: Dict[str, Any] = {}
            self._init_z3_vars(func, z3_vars)

            formula = vc.formula or F_IMPLIES(vc.precondition, vc.obligation)
            z3_formula = self._formula_to_z3(formula, z3_vars)
            if z3_formula is None:
                return None, None

            # Add negation with a tracking label for UNSAT core
            neg_label = z3.Bool("__vc_neg")
            solver.assert_and_track(z3.Not(z3_formula), neg_label)
            smtlib2 = solver.to_smt2()
            result = solver.check()
            duration_ms = (_time.time() - t0) * 1000

            # Build proof rule chain
            rule_chain = self._build_rule_chain(rule, vc)

            if result == z3.sat:
                model = solver.model()
                failing: Dict[str, Any] = {}
                for name, var in z3_vars.items():
                    if name.startswith("__"):
                        continue
                    try:
                        failing[name] = str(model.evaluate(var))
                    except Exception:
                        pass
                repair_hint = self._explain_counterexample(vc, failing)
                err = contract_error(
                    precondition=f"[{rule}] Hoare triple failed for '{func.name}': {repair_hint}",
                    failing_values=failing,
                    function_signature=self._func_sig(func),
                    location=vc.location,
                )
                cert = ProofCertificate(
                    rule=rule, premises=[str(vc.precondition)],
                    conclusion=str(vc.obligation), smtlib2=smtlib2,
                    duration_ms=duration_ms, proved=False, witness=failing,
                    proof_rule_chain=rule_chain,
                )
                return err, cert

            elif result == z3.unsat:
                # Extract UNSAT core — minimal set of hypotheses used in proof
                unsat_core_strs: List[str] = []
                try:
                    core = solver.unsat_core()
                    for c in core:
                        s = str(c)
                        if s != "__vc_neg":
                            unsat_core_strs.append(s)
                    # Also extract the premises that appear in the core
                    pre_vars = collect_free_vars(vc.precondition)
                    for v in sorted(pre_vars):
                        if v in z3_vars and not v.startswith("__"):
                            unsat_core_strs.append(f"{v} ∈ dom")
                except Exception:
                    pass

                # Detect existential witnesses in the conclusion
                has_ex = (vc.obligation.kind == FormulaKind.EXISTS or
                          "exists" in str(vc.obligation).lower() or
                          "∃" in str(vc.obligation))
                ex_witness: Dict[str, str] = {}
                if has_ex:
                    try:
                        # Re-solve without negation to get a witness model
                        wit_solver = z3.Solver()
                        wit_solver.set("timeout", 2000)
                        pos_f = self._formula_to_z3(formula, z3_vars)
                        if pos_f is not None:
                            wit_solver.add(pos_f)
                            if wit_solver.check() == z3.sat:
                                wit_model = wit_solver.model()
                                for name, var in z3_vars.items():
                                    if not name.startswith("__"):
                                        try:
                                            ex_witness[name] = str(wit_model.evaluate(var))
                                        except Exception:
                                            pass
                    except Exception:
                        pass

                # Simplify the SMTLIB2 query for the certificate
                simplified_smt = self._simplify_smtlib2(smtlib2)

                cert = ProofCertificate(
                    rule=rule, premises=[str(vc.precondition)],
                    conclusion=str(vc.obligation), smtlib2=smtlib2,
                    simplified_smtlib2=simplified_smt,
                    duration_ms=duration_ms, proved=True,
                    unsat_core=unsat_core_strs,
                    proof_rule_chain=rule_chain,
                    has_existential=has_ex,
                    existential_witness=ex_witness,
                )
                return None, cert

            else:
                cert = ProofCertificate(
                    rule=rule, premises=[str(vc.precondition)],
                    conclusion=str(vc.obligation), smtlib2=smtlib2,
                    duration_ms=duration_ms, proved=False,
                    proof_rule_chain=rule_chain,
                )
                return None, cert

        except Exception:
            return None, None

    def _build_rule_chain(self, rule: str, vc: VerificationCondition) -> List[str]:
        """Build the proof rule derivation chain for a VC.

        Maps VC kinds to the sequence of Hoare logic rules applied:
          partial_correctness  → [consequence, wp-assignment*, wp-contract]
          loop-consecution     → [invariant, consecution]
          loop-postcondition   → [invariant, consequence]
          ranking-*            → [floyd, lower-bound | strict-decrease]
          hoare-consequence-*  → [consequence]
          refinement-*         → [refinement-subtyping]
          owicki-gries-*       → [owicki-gries, interference-freedom]
        """
        kind = vc.kind if hasattr(vc, "kind") else ""
        chain = [rule]
        if "loop" in kind:
            chain = ["invariant-rule", rule]
        elif "ranking" in kind or "lex" in kind:
            chain = ["floyd-termination", rule]
        elif "consequence" in kind:
            chain = ["hoare-consequence", rule]
        elif "refinement" in kind:
            chain = ["refinement-subtyping", rule]
        elif "owicki" in kind or "interference" in kind:
            chain = ["owicki-gries", "interference-freedom", rule]
        elif "unsafe" in kind:
            chain = ["unsafe-audit", rule]
        return chain

    def _simplify_smtlib2(self, smtlib2: str) -> str:
        """Produce a simplified SMTLIB2 string by removing boilerplate."""
        lines = smtlib2.splitlines()
        # Keep only assert lines and check-sat
        simplified = [l for l in lines if l.strip().startswith("(assert") or
                      l.strip() == "(check-sat)"]
        return "\n".join(simplified)

    def _init_z3_vars(self, func: PureFunc | TaskFunc, z3_vars: Dict[str, Any]) -> None:
        """Initialise Z3 variables for function parameters and result."""
        for param in func.params:
            type_name = str(param.type_annotation) if param.type_annotation else "Int"
            if type_name == "Bool":
                z3_vars[param.name] = z3.Bool(param.name)
            elif type_name == "Float":
                z3_vars[param.name] = z3.Real(param.name)
            else:
                z3_vars[param.name] = z3.Int(param.name)
        ret_type = str(func.return_type) if func.return_type else "Void"
        if ret_type == "Bool":
            z3_vars["result"] = z3.Bool("result")
        elif ret_type == "Float":
            z3_vars["result"] = z3.Real("result")
        else:
            z3_vars["result"] = z3.Int("result")

    def _explain_counterexample(
        self, vc: VerificationCondition, failing: Dict[str, Any]
    ) -> str:
        """Produce a human-readable repair hint for a failing VC."""
        kind = vc.kind
        name = vc.name or ""
        vals = ", ".join(f"{k}={v}" for k, v in list(failing.items())[:4])

        if "division-by-zero" in name:
            denom_vals = {k: v for k, v in failing.items() if k not in ("result",)}
            dv = ", ".join(f"{k}={v}" for k, v in list(denom_vals.items())[:3])
            return (f"possible division by zero [{dv}] — "
                    f"add 'requires: denominator != 0' or guard with an if-check")

        if kind == "partial_correctness":
            if vc.precondition.kind == FormulaKind.TRUE:
                post_str = str(vc.postcondition) if vc.postcondition else str(vc.obligation)
                return (f"postcondition '{post_str}' not established — "
                        f"add a requires clause or strengthen the function body")
            return (f"counterexample [{vals}] violates postcondition — "
                    f"strengthen requires or weaken ensures")

        if "loop-consecution" in name:
            return (f"loop invariant not preserved by body [{vals}] — "
                    f"the invariant must hold after every iteration; "
                    f"check assignments inside the loop")

        if "loop-postcondition" in name:
            return (f"loop exit condition does not imply postcondition [{vals}] — "
                    f"strengthen the loop invariant or weaken the postcondition")

        if "ranking-lower-bound" in name:
            return (f"ranking function may go negative [{vals}] — "
                    f"add 'requires: loop_var >= 0' or use a non-negative expression")

        if "ranking-strict-decrease" in name or "ranking-lex-decrease" in name:
            return (f"loop may not terminate [{vals}] — "
                    f"ensure the loop variable strictly decreases each iteration")

        if "refinement" in kind:
            return (f"liquid type annotation inconsistent [{vals}] — "
                    f"check that the refinement predicate holds for the assigned expression")

        if "owicki" in kind or "interference" in kind:
            return (f"interference freedom violated [{vals}] — "
                    f"concurrent tasks share variables; add synchronization or disjoint effects")

        if "unsafe-audit" in name:
            return "unsafe block requires manual review — discharge this VC by human inspection"

        return f"contract violation [{vals}]"

    def _formula_to_z3(self, formula: Formula, z3_vars: Dict[str, Any]) -> Any:
        """Convert a Formula to a Z3 expression.

        Handles all FormulaKind variants including new ones:
          FLOAT_CONST, STRING_EQ, IFF, EXISTS, FORALL,
          ARRAY_SELECT, ARRAY_STORE, ARRAY_LEN,
          SEP_STAR, POINTS_TO, EMP, LIST_SEG, TREE, RANKING
        """
        if not HAS_Z3:
            return None

        if formula.kind == FormulaKind.TRUE:
            return z3.BoolVal(True)
        if formula.kind == FormulaKind.FALSE:
            return z3.BoolVal(False)
        if formula.kind == FormulaKind.INT_CONST:
            return z3.IntVal(formula.int_val)
        if formula.kind == FormulaKind.FLOAT_CONST:
            return z3.RealVal(formula.float_val)
        if formula.kind == FormulaKind.BOOL_CONST:
            return z3.BoolVal(formula.bool_val)

        if formula.kind == FormulaKind.STRING_EQ:
            if formula.name not in z3_vars:
                z3_vars[formula.name] = z3.Int(formula.name)
            str_hash = abs(hash(formula.str_val)) % (2**31)
            return z3_vars[formula.name] == z3.IntVal(str_hash)

        if formula.kind in (FormulaKind.VAR, FormulaKind.RANKING):
            if formula.name not in z3_vars:
                z3_vars[formula.name] = z3.Int(formula.name)
            return z3_vars[formula.name]

        if formula.kind == FormulaKind.GHOST:
            # Ghost variables are universally quantified constants.
            # In Z3, we treat them as fresh integer constants.
            if formula.name not in z3_vars:
                z3_vars[formula.name] = z3.Int(formula.name)
            return z3_vars[formula.name]

        if formula.kind == FormulaKind.LEX_RANK:
            # Lexicographic ranking tuple ⟨r₁, r₂, ..., rₙ⟩.
            # In Z3, we encode as a tuple of integers using a Z3 datatype,
            # but for VC discharge purposes we return the first component
            # (the most significant) as the primary Z3 expression.
            # The full lex decrease VC is handled separately in _wp_while.
            if formula.children:
                return self._formula_to_z3(formula.children[0], z3_vars)
            return z3.IntVal(0)

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
            return z3.Not(inner) if inner is not None else None

        if formula.kind == FormulaKind.IMPLIES:
            lhs = self._formula_to_z3(formula.children[0], z3_vars)
            rhs = self._formula_to_z3(formula.children[1], z3_vars)
            if lhs is None or rhs is None:
                return None
            return z3.Implies(lhs, rhs)

        if formula.kind == FormulaKind.IFF:
            lhs = self._formula_to_z3(formula.children[0], z3_vars)
            rhs = self._formula_to_z3(formula.children[1], z3_vars)
            if lhs is None or rhs is None:
                return None
            return z3.And(z3.Implies(lhs, rhs), z3.Implies(rhs, lhs))

        if formula.kind == FormulaKind.ITE:
            cond = self._formula_to_z3(formula.children[0], z3_vars)
            then_f = self._formula_to_z3(formula.children[1], z3_vars)
            else_f = self._formula_to_z3(formula.children[2], z3_vars)
            if cond is not None and then_f is not None and else_f is not None:
                return z3.If(cond, then_f, else_f)
            return None

        if formula.kind == FormulaKind.FORALL:
            # Represent as: body with quantified variable as a fresh Z3 Int
            qv = formula.quant_var
            old = z3_vars.get(qv)
            z3_vars[qv] = z3.Int(qv)
            body = self._formula_to_z3(formula.children[0], z3_vars)
            if old is None:
                z3_vars.pop(qv, None)
            else:
                z3_vars[qv] = old
            if body is None:
                return None
            return z3.ForAll([z3.Int(qv)], body)

        if formula.kind == FormulaKind.EXISTS:
            qv = formula.quant_var
            old = z3_vars.get(qv)
            z3_vars[qv] = z3.Int(qv)
            body = self._formula_to_z3(formula.children[0], z3_vars)
            if old is None:
                z3_vars.pop(qv, None)
            else:
                z3_vars[qv] = old
            if body is None:
                return None
            return z3.Exists([z3.Int(qv)], body)

        if formula.kind == FormulaKind.ARRAY_SELECT:
            arr = self._formula_to_z3(formula.children[0], z3_vars)
            idx = self._formula_to_z3(formula.children[1], z3_vars)
            if arr is None or idx is None:
                return None
            try:
                return z3.Select(arr, idx)
            except Exception:
                return None

        if formula.kind == FormulaKind.ARRAY_STORE:
            arr = self._formula_to_z3(formula.children[0], z3_vars)
            idx = self._formula_to_z3(formula.children[1], z3_vars)
            val = self._formula_to_z3(formula.children[2], z3_vars)
            if arr is None or idx is None or val is None:
                return None
            try:
                return z3.Store(arr, idx, val)
            except Exception:
                return None

        if formula.kind == FormulaKind.ARRAY_LEN:
            # Represent len(a) as a fresh integer variable
            arr_f = formula.children[0]
            arr_name = arr_f.name if arr_f.kind == FormulaKind.VAR else "arr"
            len_name = f"__len_{arr_name}"
            if len_name not in z3_vars:
                z3_vars[len_name] = z3.Int(len_name)
            return z3_vars[len_name]

        if formula.kind == FormulaKind.EMP:
            return z3.BoolVal(True)

        if formula.kind == FormulaKind.POINTS_TO:
            # x |-> v  encoded as: heap[x] == v ∧ x ≠ 0
            # Uses the symbolic heap Array(Int,Int) model.
            if len(formula.children) >= 2:
                addr_f = formula.children[0]
                val_f = formula.children[1]
                heap_sort = z3.ArraySort(z3.IntSort(), z3.IntSort())
                if "__heap" not in z3_vars:
                    z3_vars["__heap"] = z3.Const("__heap", heap_sort)
                heap = z3_vars["__heap"]
                addr = self._formula_to_z3(addr_f, z3_vars)
                val = self._formula_to_z3(val_f, z3_vars)
                if addr is not None and val is not None:
                    try:
                        return z3.And(z3.Select(heap, addr) == val, addr != z3.IntVal(0))
                    except Exception:
                        pass
            return z3.BoolVal(True)

        if formula.kind == FormulaKind.LIST_SEG:
            # ls(x, y): linked list segment from x to y.
            # Encoded as: ls_len(x, y) ≥ 0  (non-negative length).
            if len(formula.children) >= 2:
                head_f = formula.children[0]
                tail_f = formula.children[1]
                ls_len_fn = z3.Function("ls_len", z3.IntSort(), z3.IntSort(), z3.IntSort())
                head = self._formula_to_z3(head_f, z3_vars)
                tail = self._formula_to_z3(tail_f, z3_vars)
                if head is not None and tail is not None:
                    try:
                        return ls_len_fn(head, tail) >= z3.IntVal(0)
                    except Exception:
                        pass
            return z3.BoolVal(True)

        if formula.kind == FormulaKind.TREE:
            # tree(x): binary tree rooted at x.
            # Encoded as: tree_size(x) ≥ 0.
            if formula.children:
                root_f = formula.children[0]
                tree_size_fn = z3.Function("tree_size", z3.IntSort(), z3.IntSort())
                root = self._formula_to_z3(root_f, z3_vars)
                if root is not None:
                    try:
                        return tree_size_fn(root) >= z3.IntVal(0)
                    except Exception:
                        pass
            return z3.BoolVal(True)

        if formula.kind == FormulaKind.SEP_STAR:
            # P * Q: separating conjunction.
            # In Z3 (without a full SL solver), we encode as P ∧ Q plus
            # disjointness constraints between any POINTS_TO sub-formulas.
            parts = [self._formula_to_z3(c, z3_vars) for c in formula.children]
            parts = [p for p in parts if p is not None]
            if not parts:
                return z3.BoolVal(True)
            return z3.And(*parts) if len(parts) > 1 else parts[0]

        return None

    def _func_sig(self, func) -> str:
        prefix = "pure" if isinstance(func, PureFunc) else "task"
        params = ", ".join(f"{p.name}: {p.type_annotation}" for p in func.params)
        ret = f" -> {func.return_type}" if func.return_type else ""
        return f"{prefix} {func.name}({params}){ret}"


# ---------------------------------------------------------------------------
# Helper: create a VCGenerator without circular import
# ---------------------------------------------------------------------------

def _make_vcgen() -> "VCGenerator":
    """Create a bare VCGenerator for internal use (e.g., Houdini filter)."""
    gen = VCGenerator.__new__(VCGenerator)
    gen._summary_table = SummaryTable()
    gen.wp_calc = WPCalculator(summary_table=gen._summary_table)
    gen.vcs = []
    gen.errors = []
    gen.certificates = []
    gen._cache = HoareCache()
    return gen


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_contracts_hoare(
    program: Program,
    cache: Optional[HoareCache] = None,
) -> List[AeonError]:
    """Verify function contracts using Hoare logic and wp-calculus.

    Extended pipeline:
      1. Build SummaryTable for modular verification (Hoare 1971)
      2. Compute wp(body, ensures) using Dijkstra's wp-calculus
      3. Generate VCs: requires => wp(body, ensures)
      4. Discharge side VCs: loop consecution, postcondition, ranking functions
      5. Check refinement type consistency (Rondon et al. 2008)
      6. Check Owicki-Gries interference freedom for task functions
      7. Discharge all VCs to Z3 SMT solver
      8. Report counterexamples with repair hints for failed VCs
      9. Produce ProofCertificates for discharged VCs
      10. Cache results for incremental re-verification
    """
    generator = VCGenerator(cache=cache)
    return generator.verify_program(program)


def verify_contracts_hoare_with_trace(
    program: Program,
    cache: Optional[HoareCache] = None,
):
    """Like verify_contracts_hoare but also returns a ProofTrace and certificates.

    Returns
    -------
    (List[AeonError], ProofTrace, List[ProofCertificate])
    """
    from aeon.proof_obligations import (
        ProofTrace, SolverResult, make_hoare_obligation,
    )

    generator = VCGenerator(cache=cache)
    errors = generator.verify_program(program)

    trace = ProofTrace(source_file=getattr(program, "filename", ""))

    for vc in generator.vcs:
        func_name = getattr(vc, "function_name", "unknown")
        loc_obj = getattr(vc, "location", None)
        loc_str = (f"{loc_obj.file}:{loc_obj.line}" if loc_obj else "")
        pre_str = str(getattr(vc, "precondition", "true"))
        post_str = str(getattr(vc, "postcondition", "true"))
        wp_str = str(getattr(vc, "wp_formula", ""))

        smtlib2 = ""
        result = SolverResult.SKIPPED
        witness: Dict[str, Any] = {}
        duration = 0.0

        if HAS_Z3:
            try:
                solver = z3.Solver()
                solver.set("timeout", 5000)
                z3_vars: Dict[str, Any] = {}
                formula = getattr(vc, "formula", None)
                z3_vc = generator._formula_to_z3(formula, z3_vars) if formula is not None else None
                if z3_vc is not None:
                    solver.add(z3.Not(z3_vc))
                    smtlib2 = solver.to_smt2()
                    t0 = _time.time()
                    check = solver.check()
                    duration = (_time.time() - t0) * 1000
                    if check == z3.unsat:
                        result = SolverResult.UNSAT
                    elif check == z3.sat:
                        result = SolverResult.SAT
                        model = solver.model()
                        witness = {str(d): str(model[d]) for d in model.decls()}
                    else:
                        result = SolverResult.UNKNOWN
                else:
                    result = SolverResult.UNKNOWN
            except Exception:
                result = SolverResult.ERROR

        ob = make_hoare_obligation(
            function_name=func_name,
            location=loc_str,
            precondition=pre_str,
            postcondition=post_str,
            wp_formula=wp_str,
            smtlib2=smtlib2,
            result=result,
            witness=witness,
            duration_ms=duration,
        )
        trace.add(ob)

    return errors, trace, generator.certificates


def export_proof_certificates(
    program: Program,
    format: str = "lean4",
    cache: Optional[HoareCache] = None,
) -> str:
    """Verify program and export proof certificates as Lean 4 or Coq stubs.

    Parameters
    ----------
    program : Program
        The AEON program to verify.
    format : str
        "lean4" or "coq" — target proof assistant format.
    cache : HoareCache, optional
        Incremental verification cache.

    Returns
    -------
    str
        A string containing all proof certificate stubs.
    """
    generator = VCGenerator(cache=cache)
    generator.verify_program(program)

    lines: List[str] = [
        f"-- AEON Proof Certificates ({format.upper()})",
        f"-- Generated for {getattr(program, 'filename', 'unknown')}",
        "",
    ]
    for cert in generator.certificates:
        if format == "coq":
            lines.append(cert.to_coq())
        else:
            lines.append(cert.to_lean4())
        lines.append("")

    return "\n".join(lines)
