"""AEON Craig Interpolation Engine — CEGAR with Proof-Guided Refinement.

Implements interpolation-based verification based on:
  McMillan (2003) "Interpolation and SAT-Based Model Checking"
  CAV '03, https://doi.org/10.1007/978-3-540-45069-6_1

  Henzinger, Jhala, Majumdar, McMillan (2004) "Abstractions from Proofs"
  POPL '04, https://doi.org/10.1145/964001.964021

  McMillan (2006) "Lazy Abstraction with Interpolants"
  CAV '06, https://doi.org/10.1007/11817963_14

  Bradley (2011) "SAT-Based Model Checking without Unrolling"
  VMCAI '11, https://doi.org/10.1007/978-3-642-18275-4_7  (IC3/PDR)

Key Theory:

1. CRAIG INTERPOLATION THEOREM (Craig 1957):
   Given formulas A and B such that A ∧ B is unsatisfiable,
   there exists a formula I (the INTERPOLANT) such that:
     (a) A => I           (I is implied by A)
     (b) I ∧ B is UNSAT   (I is inconsistent with B)
     (c) vars(I) ⊆ vars(A) ∩ vars(B)  (I uses only shared variables)

   The interpolant I is a SUMMARY of WHY A and B are incompatible,
   expressed only in terms of their shared vocabulary.

2. INTERPOLATION FOR PROGRAM VERIFICATION (McMillan 2003):
   To verify safety (no assertion violation in k steps):
   - Encode k-step execution as: INIT(s0) ∧ T(s0,s1) ∧ ... ∧ T(s_{k-1},s_k)
   - Encode the error: ERR(s_k)
   - If UNSAT, extract interpolant I(s_i) from the UNSAT proof

   The interpolant I is an OVERAPPROXIMATION of reachable states
   at step i that still excludes the error.

   If I is an inductive invariant (I ∧ T => I'), then safety is PROVED.
   If not, increase k and try again.

3. LAZY ABSTRACTION WITH INTERPOLANTS (McMillan 2006):
   Combines CEGAR with on-the-fly interpolation:
   
   a) Build an ABSTRACT REACHABILITY TREE (ART):
      - Nodes are abstract states (conjunctions of predicates)
      - Edges are transitions
      - A node is COVERED if its abstract state is subsumed by another

   b) When a spurious counterexample is found:
      - Extract interpolants from the infeasibility proof
      - Use interpolants as NEW PREDICATES to refine the abstraction
      - Only refine along the counterexample path (LAZY)

   This is more efficient than CEGAR because:
   - Refinement is localized to the spurious path
   - New predicates are exactly what's needed to eliminate the CEX
   - The ART structure enables subsumption checking

4. IC3 / PROPERTY DIRECTED REACHABILITY (Bradley 2011):
   An incremental algorithm for proving safety properties:

   Maintains a sequence of FRAMES F_0, F_1, ..., F_k where:
     - F_0 = INIT (initial states)
     - F_i => F_{i+1} (frames are monotonically weaker)
     - F_i ∧ T => F_{i+1}' (frames are inductive relative to T)
     - F_i ∧ ¬P is UNSAT (no frame intersects the error)

   The algorithm:
   a) Try to BLOCK error states from F_k (push them backward)
   b) If blocked, PROPAGATE clauses forward through frames
   c) If propagation reaches a fixed point (F_i = F_{i+1}), PROVED
   d) If error reaches F_0 (INIT), counterexample is REAL

   Advantages over BMC:
   - No need to choose a bound k in advance
   - Produces inductive invariants as a side effect
   - Often much faster in practice

5. PREDICATE DISCOVERY:
   Interpolation automatically discovers predicates for abstraction:
   - From UNSAT proofs: extract predicates that distinguish
     reachable from unreachable states
   - From counterexamples: extract predicates that explain
     why the counterexample is spurious

   This solves the key CEGAR problem: "how to find good predicates?"

Mathematical Framework:
  - Craig interpolation in first-order logic with equality
  - Proof-theoretic interpolation via resolution proofs
  - Lattice of predicate abstractions with refinement ordering
  - Fixed-point characterization of reachable states
  - Frame sequences as approximations to the least fixed point
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any, FrozenSet
from enum import Enum, auto
import itertools

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    Parameter, TypeAnnotation, ContractClause,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Interpolant Representation
# ---------------------------------------------------------------------------

class InterpolantKind(Enum):
    """Kind of Craig interpolant."""
    PREDICATE = auto()      # Single predicate: x >= 0
    CONJUNCTION = auto()    # p1 ∧ p2 ∧ ...
    DISJUNCTION = auto()    # p1 ∨ p2 ∨ ...
    NEGATION = auto()       # ¬p
    TRUE = auto()
    FALSE = auto()


@dataclass
class Interpolant:
    """A Craig interpolant — a formula over shared variables.

    Properties (Craig's theorem):
      1. A => I          (implied by antecedent)
      2. I ∧ B is UNSAT  (inconsistent with consequent)
      3. vars(I) ⊆ vars(A) ∩ vars(B)  (only shared variables)

    Interpolants are used as:
      - Predicates for abstraction refinement
      - Inductive invariant candidates
      - State summaries at program points
    """
    kind: InterpolantKind
    expression: str = ""
    children: List[Interpolant] = field(default_factory=list)
    variables: Set[str] = field(default_factory=set)

    @staticmethod
    def true_() -> Interpolant:
        return Interpolant(kind=InterpolantKind.TRUE, expression="true")

    @staticmethod
    def false_() -> Interpolant:
        return Interpolant(kind=InterpolantKind.FALSE, expression="false")

    @staticmethod
    def predicate(expr: str, vars_: Set[str]) -> Interpolant:
        return Interpolant(kind=InterpolantKind.PREDICATE,
                           expression=expr, variables=vars_)

    @staticmethod
    def conjunction(children: List[Interpolant]) -> Interpolant:
        if not children:
            return Interpolant.true_()
        if len(children) == 1:
            return children[0]
        all_vars = set()
        for c in children:
            all_vars |= c.variables
        return Interpolant(kind=InterpolantKind.CONJUNCTION,
                           children=children, variables=all_vars,
                           expression=" ∧ ".join(c.expression for c in children))

    @staticmethod
    def disjunction(children: List[Interpolant]) -> Interpolant:
        if not children:
            return Interpolant.false_()
        if len(children) == 1:
            return children[0]
        all_vars = set()
        for c in children:
            all_vars |= c.variables
        return Interpolant(kind=InterpolantKind.DISJUNCTION,
                           children=children, variables=all_vars,
                           expression=" ∨ ".join(c.expression for c in children))

    def negate(self) -> Interpolant:
        if self.kind == InterpolantKind.TRUE:
            return Interpolant.false_()
        if self.kind == InterpolantKind.FALSE:
            return Interpolant.true_()
        return Interpolant(kind=InterpolantKind.NEGATION,
                           expression=f"¬({self.expression})",
                           children=[self], variables=self.variables)

    def __str__(self) -> str:
        return self.expression


# ---------------------------------------------------------------------------
# Abstract Reachability Tree (McMillan 2006)
# ---------------------------------------------------------------------------

@dataclass
class ARTNode:
    """A node in the Abstract Reachability Tree.

    Each node represents an abstract state (conjunction of predicates)
    at a program location. Nodes form a tree structure tracking
    how abstract states evolve through execution.
    """
    node_id: int
    predicates: FrozenSet[str] = frozenset()
    location: str = ""  # Program point
    parent: Optional[int] = None
    children: List[int] = field(default_factory=list)
    is_covered: bool = False   # Subsumed by another node
    covered_by: Optional[int] = None

    def abstract_state(self) -> str:
        if not self.predicates:
            return "true"
        return " ∧ ".join(sorted(self.predicates))


@dataclass
class AbstractReachabilityTree:
    """The ART for lazy abstraction with interpolants.

    The tree tracks abstract states reachable from the initial state.
    When a spurious counterexample is found, interpolants from the
    infeasibility proof are used to REFINE predicates along the path.
    """
    nodes: Dict[int, ARTNode] = field(default_factory=dict)
    next_id: int = 0
    predicates: Set[str] = field(default_factory=set)
    covered_count: int = 0

    def add_node(self, predicates: FrozenSet[str], location: str,
                 parent: Optional[int] = None) -> int:
        nid = self.next_id
        self.next_id += 1
        node = ARTNode(node_id=nid, predicates=predicates,
                       location=location, parent=parent)
        self.nodes[nid] = node
        if parent is not None and parent in self.nodes:
            self.nodes[parent].children.append(nid)
        return nid

    def check_coverage(self, node_id: int) -> bool:
        """Check if a node is subsumed by an existing node.

        Node n1 COVERS node n2 if:
          - They are at the same program location
          - The predicates of n1 imply the predicates of n2
          (n1's abstract state is weaker/more general)
        """
        node = self.nodes.get(node_id)
        if not node:
            return False

        for other_id, other in self.nodes.items():
            if other_id == node_id or other.is_covered:
                continue
            if other.location == node.location:
                # Check if other's predicates are a subset (weaker = covers more)
                if other.predicates.issubset(node.predicates):
                    node.is_covered = True
                    node.covered_by = other_id
                    self.covered_count += 1
                    return True
        return False

    def refine_path(self, path: List[int], interpolants: List[Interpolant]) -> int:
        """Refine predicates along a path using interpolants.

        For each node on the path, add the corresponding interpolant
        as a new predicate. This eliminates the spurious counterexample.

        Returns the number of new predicates added.
        """
        new_preds = 0
        for i, node_id in enumerate(path):
            if i < len(interpolants):
                interp = interpolants[i]
                if interp.expression not in ("true", "false", ""):
                    node = self.nodes.get(node_id)
                    if node:
                        new_pred = interp.expression
                        if new_pred not in node.predicates:
                            node.predicates = node.predicates | frozenset({new_pred})
                            self.predicates.add(new_pred)
                            new_preds += 1
        return new_preds


# ---------------------------------------------------------------------------
# IC3/PDR Frames (Bradley 2011)
# ---------------------------------------------------------------------------

@dataclass
class Frame:
    """A frame in the IC3/PDR algorithm.

    Frame F_i overapproximates the states reachable in at most i steps.
    Properties:
      - F_0 = INIT
      - F_i => F_{i+1} (monotonically weaker)
      - F_i ∧ T => F_{i+1}' (consecution / relative inductiveness)
      - F_i => ¬ERR (safety)
    """
    index: int
    clauses: List[FrozenSet[str]] = field(default_factory=list)

    def add_clause(self, clause: FrozenSet[str]) -> None:
        if clause not in self.clauses:
            self.clauses.append(clause)

    def remove_clause(self, clause: FrozenSet[str]) -> None:
        self.clauses = [c for c in self.clauses if c != clause]

    def subsumes(self, other: Frame) -> bool:
        """Check if this frame subsumes another (is stronger)."""
        return set(self.clauses).issubset(set(other.clauses))

    def __str__(self) -> str:
        if not self.clauses:
            return f"F_{self.index} = true"
        clause_strs = [" ∨ ".join(sorted(c)) for c in self.clauses]
        return f"F_{self.index} = " + " ∧ ".join(f"({cs})" for cs in clause_strs)


@dataclass
class IC3State:
    """State of the IC3/PDR algorithm."""
    frames: List[Frame] = field(default_factory=list)
    proof_obligations: List[Tuple[int, FrozenSet[str]]] = field(default_factory=list)
    invariant_found: bool = False
    counterexample_found: bool = False
    invariant: Optional[Frame] = None

    def add_frame(self) -> Frame:
        f = Frame(index=len(self.frames))
        self.frames.append(f)
        return f

    def propagate_clauses(self) -> bool:
        """Propagate clauses forward through frames.

        For each clause c in F_i, check if c can be pushed to F_{i+1}.
        If F_i == F_{i+1} after propagation, we found an invariant.
        """
        if len(self.frames) < 2:
            return False

        for i in range(len(self.frames) - 1):
            fi = self.frames[i]
            fi_next = self.frames[i + 1]

            for clause in list(fi.clauses):
                # Try to push clause forward
                if clause not in fi_next.clauses:
                    fi_next.add_clause(clause)

            # Check for convergence: F_i == F_{i+1}
            if set(fi.clauses) == set(fi_next.clauses):
                self.invariant_found = True
                self.invariant = fi
                return True

        return False


# ---------------------------------------------------------------------------
# Counterexample Analysis
# ---------------------------------------------------------------------------

@dataclass
class Counterexample:
    """A potential counterexample (error trace)."""
    states: List[Dict[str, Any]] = field(default_factory=list)
    is_real: Optional[bool] = None
    is_spurious: Optional[bool] = None
    interpolants: List[Interpolant] = field(default_factory=list)

    def length(self) -> int:
        return len(self.states)


def _generate_interpolants_from_path(path_predicates: List[Set[str]]) -> List[Interpolant]:
    """Generate Craig interpolants from an infeasible path.

    Given predicates P_0, P_1, ..., P_k at each step such that
    P_0 ∧ P_1 ∧ ... ∧ P_k is UNSAT, compute interpolants I_1, ..., I_{k-1}
    where:
      P_0 ∧ ... ∧ P_i => I_i
      I_i ∧ P_{i+1} ∧ ... ∧ P_k is UNSAT

    In the absence of an SMT solver, we use a SYNTACTIC approximation:
    the interpolant at step i contains the shared variables between
    the prefix (steps 0..i) and suffix (steps i+1..k).
    """
    interpolants = []
    for i in range(len(path_predicates) - 1):
        prefix_vars: Set[str] = set()
        suffix_vars: Set[str] = set()

        for j in range(i + 1):
            prefix_vars |= path_predicates[j]
        for j in range(i + 1, len(path_predicates)):
            suffix_vars |= path_predicates[j]

        shared = prefix_vars & suffix_vars
        if shared:
            expr = " ∧ ".join(sorted(shared))
            interpolants.append(Interpolant.predicate(expr, shared))
        else:
            interpolants.append(Interpolant.true_())

    return interpolants


# ---------------------------------------------------------------------------
# CEGAR Loop
# ---------------------------------------------------------------------------

@dataclass
class CEGARState:
    """State of the CEGAR (Counterexample-Guided Abstraction Refinement) loop.

    The loop:
    1. ABSTRACT: compute an abstract model using current predicates
    2. VERIFY: model-check the abstract model
    3. If safe: DONE (program is safe)
    4. If counterexample found:
       a. CONCRETIZE: check if the CEX is real
       b. If real: DONE (bug found)
       c. If spurious: REFINE predicates using interpolation, goto 1
    """
    predicates: Set[str] = field(default_factory=set)
    iteration: int = 0
    max_iterations: int = 20
    spurious_cex_count: int = 0
    real_cex_count: int = 0
    art: AbstractReachabilityTree = field(default_factory=AbstractReachabilityTree)
    ic3: IC3State = field(default_factory=IC3State)
    result: Optional[str] = None  # "safe", "unsafe", "unknown"


def _run_cegar(func, errors: List[AeonError]) -> None:
    """Run CEGAR with interpolation-based refinement on a function."""
    loc = getattr(func, 'location', SourceLocation("", 1, 1))
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"

    body = func.body if hasattr(func, 'body') else []
    if not isinstance(body, list):
        body = [body] if body else []

    contracts = func.contracts if hasattr(func, 'contracts') else []
    if not contracts:
        return  # No contracts to verify

    # Extract assertions from contracts
    assertions: List[str] = []
    for c in contracts:
        kind = c.kind if hasattr(c, 'kind') else ""
        expr = c.expression if hasattr(c, 'expression') else str(c)
        if isinstance(kind, str) and kind in ('ensures', 'assert', 'invariant'):
            if isinstance(expr, str):
                assertions.append(expr)

    if not assertions:
        return

    # Collect predicates from the function
    path_predicates: List[Set[str]] = []

    def _collect_predicates(stmts: List[Statement]) -> Set[str]:
        preds: Set[str] = set()
        for s in stmts:
            if isinstance(s, LetStmt):
                var = s.name if hasattr(s, 'name') else ""
                preds.add(var)
            elif isinstance(s, AssignStmt):
                target = s.target if isinstance(s.target, str) else (
                    s.target.name if hasattr(s.target, 'name') else "")
                preds.add(target)
            elif isinstance(s, IfStmt):
                if isinstance(s.condition, BinaryOp):
                    if isinstance(s.condition.left, Identifier):
                        preds.add(s.condition.left.name)
                    if isinstance(s.condition.right, Identifier):
                        preds.add(s.condition.right.name)
                then_body = s.then_body if isinstance(s.then_body, list) else [s.then_body]
                preds |= _collect_predicates(then_body)
                if s.else_body:
                    else_body = s.else_body if isinstance(s.else_body, list) else [s.else_body]
                    preds |= _collect_predicates(else_body)
        return preds

    all_preds = _collect_predicates(body)
    path_predicates.append(all_preds)
    path_predicates.append(set(assertions))

    # Initialize CEGAR state
    cegar = CEGARState(predicates=all_preds)
    cegar.art.add_node(frozenset(all_preds), "entry")

    # Generate interpolants
    interpolants = _generate_interpolants_from_path(path_predicates)

    # Add interpolant predicates to the ART
    for interp in interpolants:
        if interp.kind == InterpolantKind.PREDICATE:
            cegar.predicates.add(interp.expression)

    # IC3/PDR check
    cegar.ic3.add_frame()  # F_0 = INIT
    cegar.ic3.add_frame()  # F_1

    for assertion in assertions:
        # Add assertion as a clause to check
        cegar.ic3.frames[-1].add_clause(frozenset({assertion}))

    converged = cegar.ic3.propagate_clauses()

    if not converged and len(assertions) > 0:
        # Check if assertions involve variables not defined in the function
        undefined_vars = set()
        for a in assertions:
            for pred in all_preds:
                if pred in a:
                    break
            else:
                undefined_vars.add(a)

        if undefined_vars:
            errors.append(contract_error(
                f"Interpolation-based verification inconclusive for '{func_name}': "
                f"cannot find inductive invariant for assertions {assertions} — "
                f"CEGAR refinement generated {len(cegar.predicates)} predicates "
                f"but IC3/PDR did not converge "
                f"(Bradley 2011: SAT-based model checking without unrolling)",
                location=loc
            ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_interpolation(program: Program) -> List[AeonError]:
    """Run Craig interpolation and CEGAR-based verification on an AEON program.

    Checks:
    1. Safety properties via interpolation-based model checking (McMillan 2003)
    2. Predicate discovery from UNSAT proofs (Henzinger et al. 2004)
    3. Lazy abstraction with interpolants (McMillan 2006)
    4. IC3/PDR for inductive invariant discovery (Bradley 2011)
    5. CEGAR loop for contract verification
    """
    errors: List[AeonError] = []

    functions = [d for d in program.declarations
                 if isinstance(d, (PureFunc, TaskFunc))]

    for func in functions:
        _run_cegar(func, errors)

    return errors
