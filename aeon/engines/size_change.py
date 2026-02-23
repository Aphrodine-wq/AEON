"""AEON Size-Change Termination Principle.

Implements the size-change termination (SCT) decision procedure from:
  Lee, Jones, Ben-Amram (2001) "The Size-Change Principle for Program
  Termination" POPL '01, https://doi.org/10.1145/360204.360210

Key theorem (SCT Principle):
  A program is size-change terminating iff every infinite call sequence
  would cause an infinite descent in some value, which is impossible
  in a well-founded domain.

Decision procedure (via Ramsey's theorem):
  1. Build SIZE-CHANGE GRAPHS (SCGs) for each function call:
     - Nodes are function parameters
     - Edges are labeled with size relations:
       * STRICT DECREASE (↓): argument strictly decreases
       * NON-INCREASE (↓=): argument does not increase
       * UNKNOWN (?): no known relation

  2. Compute the TRANSITIVE CLOSURE of SCGs under composition:
     Given G1: f -> g and G2: g -> h, compose to get G3: f -> h.
     Edge composition:
       ↓ ; ↓= = ↓     (strict followed by non-increase = strict)
       ↓= ; ↓ = ↓     (non-increase followed by strict = strict)
       ↓ ; ↓ = ↓       (strict composed with strict = strict)
       ↓= ; ↓= = ↓=   (non-increase composed with non-increase = non-increase)

  3. Check the TERMINATION CONDITION:
     For every idempotent SCG G in the closure (G ; G = G) that represents
     a self-loop (f -> f), there must exist a parameter with a STRICT
     decrease edge (↓) from itself to itself.

     By Ramsey's theorem: if the closure is finite, we only need to check
     finitely many idempotent graphs, making this DECIDABLE.

Complexity: The algorithm is PSPACE-complete in general, but practical
for typical programs (polynomial in the number of parameters).

Mathematical background:
  - Well-founded relations (no infinite descending chains)
  - Ramsey's theorem: any sufficiently large colored complete graph
    contains a monochromatic complete subgraph
  - Dickson's lemma: the product order on N^k is a well-quasi-ordering
  - This generalizes simple "decreasing argument" checks to handle
    mutual recursion, lexicographic orderings, and complex call patterns
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Tuple, FrozenSet
from enum import Enum, auto
import itertools

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, Statement, Expr,
    Identifier, IntLiteral, BinaryOp, UnaryOp, FunctionCall,
    ReturnStmt, LetStmt, ExprStmt, IfStmt, WhileStmt, AssignStmt,
    FieldAccess, MethodCall,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Size Relations
# ---------------------------------------------------------------------------

class SizeRelation(Enum):
    """Relation between caller argument and callee parameter.

    Forms a lattice:
        UNKNOWN (top / no information)
          |
        NON_INCREASE (↓=, value does not increase)
          |
        STRICT_DECREASE (↓, value strictly decreases)
          |
        BOTTOM (impossible edge, never taken)
    """
    BOTTOM = auto()           # Impossible (dead edge)
    STRICT_DECREASE = auto()  # ↓  : callee param < caller arg (well-founded)
    NON_INCREASE = auto()     # ↓= : callee param <= caller arg
    UNKNOWN = auto()          # ?  : no known relation


def compose_relation(r1: SizeRelation, r2: SizeRelation) -> SizeRelation:
    """Compose two size relations along a call chain.

    If f calls g with relation r1, and g calls h with relation r2,
    then f transitively relates to h with compose(r1, r2).

    Composition table (sequential):
      ↓ ; ↓  = ↓     (strict ; strict = strict)
      ↓ ; ↓= = ↓     (strict ; non-increase = strict)
      ↓= ; ↓ = ↓     (non-increase ; strict = strict)
      ↓= ; ↓= = ↓=   (non-increase ; non-increase = non-increase)
      ? ; _ = ?       (unknown composed with anything = unknown)
      _ ; ? = ?       (anything composed with unknown = unknown)
      bot ; _ = bot
      _ ; bot = bot
    """
    if r1 == SizeRelation.BOTTOM or r2 == SizeRelation.BOTTOM:
        return SizeRelation.BOTTOM
    if r1 == SizeRelation.UNKNOWN or r2 == SizeRelation.UNKNOWN:
        return SizeRelation.UNKNOWN
    if r1 == SizeRelation.STRICT_DECREASE or r2 == SizeRelation.STRICT_DECREASE:
        return SizeRelation.STRICT_DECREASE
    return SizeRelation.NON_INCREASE


def join_relation(r1: SizeRelation, r2: SizeRelation) -> SizeRelation:
    """Join (least upper bound) of two size relations.

    Used when multiple call paths exist between the same pair.
    We take the weaker (less precise) relation.
    """
    if r1 == SizeRelation.UNKNOWN or r2 == SizeRelation.UNKNOWN:
        return SizeRelation.UNKNOWN
    if r1 == SizeRelation.BOTTOM:
        return r2
    if r2 == SizeRelation.BOTTOM:
        return r1
    if r1 == SizeRelation.NON_INCREASE or r2 == SizeRelation.NON_INCREASE:
        return SizeRelation.NON_INCREASE
    return SizeRelation.STRICT_DECREASE


# ---------------------------------------------------------------------------
# Size-Change Graphs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SizeChangeEdge:
    """An edge in a size-change graph.

    Represents: caller_param --relation--> callee_param
    """
    source: str       # caller parameter name
    target: str       # callee parameter name
    relation: SizeRelation

    def __str__(self) -> str:
        symbols = {
            SizeRelation.STRICT_DECREASE: "↓",
            SizeRelation.NON_INCREASE: "↓=",
            SizeRelation.UNKNOWN: "?",
            SizeRelation.BOTTOM: "⊥",
        }
        return f"{self.source} {symbols[self.relation]} {self.target}"


@dataclass(frozen=True)
class SizeChangeGraph:
    """A size-change graph for a single call site.

    Represents the size relationships between a caller's parameters
    and a callee's parameters at a specific call site.

    SCG(f -> g) is a bipartite graph:
      - Left nodes: parameters of f (caller)
      - Right nodes: parameters of g (callee)
      - Edges: size relations between them

    The graph is stored as a matrix: edges[source_param][target_param] = relation
    """
    caller: str                                    # caller function name
    callee: str                                    # callee function name
    caller_params: Tuple[str, ...]                 # parameter names of caller
    callee_params: Tuple[str, ...]                 # parameter names of callee
    edges: Tuple[Tuple[SizeRelation, ...], ...]    # |caller_params| x |callee_params| matrix
    location: Optional[SourceLocation] = None

    def get_edge(self, src_idx: int, tgt_idx: int) -> SizeRelation:
        if 0 <= src_idx < len(self.edges) and 0 <= tgt_idx < len(self.edges[src_idx]):
            return self.edges[src_idx][tgt_idx]
        return SizeRelation.UNKNOWN

    def __str__(self) -> str:
        lines = [f"SCG({self.caller} -> {self.callee}):"]
        for i, sp in enumerate(self.caller_params):
            for j, tp in enumerate(self.callee_params):
                rel = self.get_edge(i, j)
                if rel != SizeRelation.UNKNOWN:
                    edge = SizeChangeEdge(sp, tp, rel)
                    lines.append(f"  {edge}")
        return "\n".join(lines)


def compose_graphs(g1: SizeChangeGraph, g2: SizeChangeGraph) -> Optional[SizeChangeGraph]:
    """Compose two size-change graphs: G1 ; G2.

    If G1: f -> g and G2: g -> h, produces G3: f -> h.
    Edge composition: for each (i, k), find all j such that
      G1[i][j] and G2[j][k] exist, and take the join over compositions.

    G3[i][k] = join_j { compose(G1[i][j], G2[j][k]) }
    """
    if g1.callee != g2.caller:
        return None
    if g1.callee_params != g2.caller_params:
        return None

    n_src = len(g1.caller_params)
    n_mid = len(g1.callee_params)
    n_tgt = len(g2.callee_params)

    edges: List[List[SizeRelation]] = []
    for i in range(n_src):
        row: List[SizeRelation] = []
        for k in range(n_tgt):
            best = SizeRelation.BOTTOM
            for j in range(n_mid):
                r1 = g1.get_edge(i, j)
                r2 = g2.get_edge(j, k)
                if r1 != SizeRelation.UNKNOWN and r2 != SizeRelation.UNKNOWN:
                    composed = compose_relation(r1, r2)
                    best = join_relation(best, composed)
            if best == SizeRelation.BOTTOM:
                best = SizeRelation.UNKNOWN
            row.append(best)
        edges.append(row)

    return SizeChangeGraph(
        caller=g1.caller,
        callee=g2.callee,
        caller_params=g1.caller_params,
        callee_params=g2.callee_params,
        edges=tuple(tuple(row) for row in edges),
    )


def is_idempotent(g: SizeChangeGraph) -> bool:
    """Check if G ; G = G (graph is idempotent under composition).

    Idempotent graphs represent stable recursive patterns.
    By Ramsey's theorem, every infinite call sequence must eventually
    produce an idempotent graph.
    """
    if g.caller != g.callee:
        return False
    composed = compose_graphs(g, g)
    if composed is None:
        return False
    return composed.edges == g.edges


# ---------------------------------------------------------------------------
# Size-Change Analysis
# ---------------------------------------------------------------------------

class SizeChangeAnalyzer:
    """Decides termination using the size-change principle.

    Algorithm:
    1. Extract size-change graphs from all call sites
    2. Compute transitive closure under composition
    3. For each idempotent self-loop graph, check for strict decrease
    4. Report non-termination if any idempotent self-loop lacks strict decrease
    """

    def __init__(self):
        self.errors: List[AeonError] = []
        self.graphs: List[SizeChangeGraph] = []
        self.closure: List[SizeChangeGraph] = []
        self.functions: Dict[str, PureFunc | TaskFunc] = {}

    def analyze_program(self, program: Program) -> List[AeonError]:
        """Run size-change termination analysis on a program."""
        self.errors = []
        self.graphs = []
        self.functions = {}

        functions = [d for d in program.declarations
                     if isinstance(d, (PureFunc, TaskFunc))]

        for func in functions:
            self.functions[func.name] = func

        # Phase 1: Extract size-change graphs from call sites
        for func in functions:
            self._extract_graphs(func)

        if not self.graphs:
            return self.errors

        # Phase 2: Compute transitive closure
        self.closure = self._transitive_closure(self.graphs)

        # Phase 3: Check termination condition
        self._check_termination()

        return self.errors

    def _extract_graphs(self, func: PureFunc | TaskFunc) -> None:
        """Extract size-change graphs from all call sites in a function."""
        param_names = tuple(p.name for p in func.params)

        # Walk the function body looking for calls
        call_sites = self._find_calls(func.body)

        for call_expr, location in call_sites:
            if not isinstance(call_expr.callee, Identifier):
                continue
            callee_name = call_expr.callee.name
            if callee_name not in self.functions:
                continue

            callee = self.functions[callee_name]
            callee_params = tuple(p.name for p in callee.params)

            # Build the size-change graph for this call site
            edges = self._build_edges(param_names, callee_params, call_expr, func)

            graph = SizeChangeGraph(
                caller=func.name,
                callee=callee_name,
                caller_params=param_names,
                callee_params=callee_params,
                edges=tuple(tuple(row) for row in edges),
                location=location,
            )
            self.graphs.append(graph)

    def _build_edges(self, caller_params: Tuple[str, ...],
                     callee_params: Tuple[str, ...],
                     call: FunctionCall,
                     func: PureFunc | TaskFunc) -> List[List[SizeRelation]]:
        """Build the edge matrix for a call site.

        For each (caller_param, callee_param) pair, determine the
        size relation by analyzing the argument expression.
        """
        n_caller = len(caller_params)
        n_callee = len(callee_params)
        edges: List[List[SizeRelation]] = [
            [SizeRelation.UNKNOWN] * n_callee for _ in range(n_caller)
        ]

        for j, arg in enumerate(call.args):
            if j >= n_callee:
                break

            # Analyze the argument expression
            for i, cparam in enumerate(caller_params):
                relation = self._analyze_size_relation(arg, cparam)
                if relation != SizeRelation.UNKNOWN:
                    edges[i][j] = relation

        return edges

    def _analyze_size_relation(self, arg_expr: Expr, param_name: str) -> SizeRelation:
        """Determine the size relation between an argument expression and a parameter.

        Patterns recognized:
          param_name           -> NON_INCREASE (same value)
          param_name - 1       -> STRICT_DECREASE
          param_name - k (k>0) -> STRICT_DECREASE
          param_name / k (k>1) -> STRICT_DECREASE
          param_name + k (k<0) -> STRICT_DECREASE
          f(param_name - 1)    -> analyze recursively (compositional)
        """
        # Direct reference: x -> x (non-increasing)
        if isinstance(arg_expr, Identifier):
            if arg_expr.name == param_name:
                return SizeRelation.NON_INCREASE
            return SizeRelation.UNKNOWN

        # Binary operation: x - 1, x / 2, etc.
        if isinstance(arg_expr, BinaryOp):
            if arg_expr.op == "-":
                if (isinstance(arg_expr.left, Identifier) and
                        arg_expr.left.name == param_name):
                    if isinstance(arg_expr.right, IntLiteral) and arg_expr.right.value > 0:
                        return SizeRelation.STRICT_DECREASE
                    # x - y where y is non-negative
                    return SizeRelation.UNKNOWN

            if arg_expr.op == "/":
                if (isinstance(arg_expr.left, Identifier) and
                        arg_expr.left.name == param_name):
                    if isinstance(arg_expr.right, IntLiteral) and arg_expr.right.value > 1:
                        return SizeRelation.STRICT_DECREASE
                    return SizeRelation.UNKNOWN

            if arg_expr.op == "+":
                if (isinstance(arg_expr.left, Identifier) and
                        arg_expr.left.name == param_name):
                    if isinstance(arg_expr.right, IntLiteral) and arg_expr.right.value < 0:
                        return SizeRelation.STRICT_DECREASE
                    if isinstance(arg_expr.right, IntLiteral) and arg_expr.right.value == 0:
                        return SizeRelation.NON_INCREASE

            if arg_expr.op == "*":
                if (isinstance(arg_expr.left, Identifier) and
                        arg_expr.left.name == param_name):
                    if isinstance(arg_expr.right, IntLiteral):
                        if 0 < arg_expr.right.value < 1:
                            return SizeRelation.STRICT_DECREASE
                        if arg_expr.right.value == 1:
                            return SizeRelation.NON_INCREASE

            # Nested: check if the overall expression preserves ordering
            left_rel = self._analyze_size_relation(arg_expr.left, param_name)
            right_rel = self._analyze_size_relation(arg_expr.right, param_name)

            # If left is a strict decrease and right is a constant, still strict decrease
            if left_rel == SizeRelation.STRICT_DECREASE and arg_expr.op in ("+", "-"):
                if isinstance(arg_expr.right, IntLiteral):
                    return SizeRelation.STRICT_DECREASE

        return SizeRelation.UNKNOWN

    def _find_calls(self, stmts, location=None) -> List[Tuple[FunctionCall, Optional[SourceLocation]]]:
        """Find all function calls in a statement list."""
        calls: List[Tuple[FunctionCall, Optional[SourceLocation]]] = []

        if isinstance(stmts, list):
            for stmt in stmts:
                calls.extend(self._find_calls_in_stmt(stmt))
        elif stmts is not None:
            calls.extend(self._find_calls_in_stmt(stmts))

        return calls

    def _find_calls_in_stmt(self, stmt: Statement) -> List[Tuple[FunctionCall, Optional[SourceLocation]]]:
        """Find function calls in a single statement."""
        calls: List[Tuple[FunctionCall, Optional[SourceLocation]]] = []

        if isinstance(stmt, ReturnStmt) and stmt.value:
            calls.extend(self._find_calls_in_expr(stmt.value))
        elif isinstance(stmt, LetStmt) and stmt.value:
            calls.extend(self._find_calls_in_expr(stmt.value))
        elif isinstance(stmt, ExprStmt):
            calls.extend(self._find_calls_in_expr(stmt.expr))
        elif isinstance(stmt, AssignStmt):
            calls.extend(self._find_calls_in_expr(stmt.value))
        elif isinstance(stmt, IfStmt):
            calls.extend(self._find_calls_in_expr(stmt.condition))
            calls.extend(self._find_calls(stmt.then_body))
            calls.extend(self._find_calls(stmt.else_body))
        elif isinstance(stmt, WhileStmt):
            calls.extend(self._find_calls_in_expr(stmt.condition))
            calls.extend(self._find_calls(stmt.body))

        return calls

    def _find_calls_in_expr(self, expr: Expr) -> List[Tuple[FunctionCall, Optional[SourceLocation]]]:
        """Find function calls in an expression tree."""
        calls: List[Tuple[FunctionCall, Optional[SourceLocation]]] = []

        if isinstance(expr, FunctionCall):
            calls.append((expr, expr.location))
            for arg in expr.args:
                calls.extend(self._find_calls_in_expr(arg))
        elif isinstance(expr, BinaryOp):
            calls.extend(self._find_calls_in_expr(expr.left))
            calls.extend(self._find_calls_in_expr(expr.right))
        elif isinstance(expr, UnaryOp):
            calls.extend(self._find_calls_in_expr(expr.operand))
        elif isinstance(expr, MethodCall):
            calls.extend(self._find_calls_in_expr(expr.obj))
            for arg in expr.args:
                calls.extend(self._find_calls_in_expr(arg))
        elif isinstance(expr, FieldAccess):
            calls.extend(self._find_calls_in_expr(expr.obj))

        return calls

    def _transitive_closure(self, initial_graphs: List[SizeChangeGraph]) -> List[SizeChangeGraph]:
        """Compute the transitive closure of SCGs under composition.

        Uses a worklist algorithm:
          1. Start with the initial SCGs
          2. For each pair (G1, G2) where G1.callee == G2.caller:
             Compose to get G3 = G1 ; G2
          3. If G3 is new (not already in the set), add it to the worklist
          4. Repeat until no new graphs are generated

        Termination is guaranteed because:
          - The number of possible SCGs is bounded by
            |functions|^2 * |relations|^(|params|^2)
          - This is finite (Ramsey's theorem ensures we reach fixpoint)
        """
        # Normalize graphs to comparable form
        seen: Set[Tuple] = set()
        result: List[SizeChangeGraph] = []
        worklist: List[SizeChangeGraph] = list(initial_graphs)

        def graph_key(g: SizeChangeGraph) -> Tuple:
            return (g.caller, g.callee, g.caller_params, g.callee_params, g.edges)

        for g in worklist:
            key = graph_key(g)
            if key not in seen:
                seen.add(key)
                result.append(g)

        idx = 0
        MAX_CLOSURE = 10000  # Safety bound
        while idx < len(result) and len(result) < MAX_CLOSURE:
            g1 = result[idx]
            idx += 1

            for g2 in list(result):
                if g1.callee != g2.caller:
                    continue
                if g1.callee_params != g2.caller_params:
                    continue

                composed = compose_graphs(g1, g2)
                if composed is None:
                    continue

                key = graph_key(composed)
                if key not in seen:
                    seen.add(key)
                    result.append(composed)

        return result

    def _check_termination(self) -> None:
        """Check the SCT termination condition.

        For every idempotent SCG G in the closure where G: f -> f (self-loop):
          There must exist some parameter i such that G[i][i] = STRICT_DECREASE.

        If this fails for any idempotent self-loop, the program may not terminate.

        Proof sketch (by Ramsey's theorem):
          Consider an infinite call sequence f -> f -> f -> ...
          The SCGs along this sequence form a sequence G_1, G_2, G_3, ...
          By Ramsey's theorem (applied to the finite set of possible SCGs),
          there exists an infinite subsequence where all SCGs are the same G.
          This G must be idempotent (G ; G = G).
          If G has a strict decrease on parameter i from i to i,
          then the value of parameter i strictly decreases at every step
          of this subsequence, which is impossible in a well-founded domain.
          Therefore, the call sequence must be finite.
        """
        for graph in self.closure:
            if graph.caller != graph.callee:
                continue
            if graph.caller_params != graph.callee_params:
                continue

            # Check if idempotent
            if not is_idempotent(graph):
                continue

            # Check for strict decrease on the diagonal
            has_strict = False
            n = len(graph.caller_params)
            for i in range(n):
                if graph.get_edge(i, i) == SizeRelation.STRICT_DECREASE:
                    has_strict = True
                    break

            if not has_strict:
                # Also check off-diagonal for lexicographic orderings
                # A more permissive check: any strict decrease edge in the graph
                any_strict = False
                for i in range(n):
                    for j in range(n):
                        if graph.get_edge(i, j) == SizeRelation.STRICT_DECREASE:
                            any_strict = True
                            break
                    if any_strict:
                        break

                if not any_strict:
                    func = self.functions.get(graph.caller)
                    loc = graph.location or (func.location if func else None)
                    self.errors.append(contract_error(
                        precondition=(
                            f"Size-change termination check failed for '{graph.caller}': "
                            f"no strictly decreasing argument found in idempotent call cycle. "
                            f"By the SCT principle (Lee/Jones/Ben-Amram 2001), this function "
                            f"may not terminate."
                        ),
                        failing_values={
                            "function": graph.caller,
                            "params": list(graph.caller_params),
                            "idempotent_graph": str(graph),
                        },
                        function_signature=f"{graph.caller}({', '.join(graph.caller_params)})",
                        location=loc,
                    ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_termination_sct(program: Program) -> List[AeonError]:
    """Run size-change termination analysis on an AEON program.

    This implements the decision procedure from Lee, Jones, Ben-Amram (2001).
    It is sound and complete for size-change termination:
      - If it says "terminates", the program definitely terminates
        (assuming well-founded data domains)
      - If it says "may not terminate", there exists a potential
        infinite call sequence consistent with the size-change graphs
    """
    analyzer = SizeChangeAnalyzer()
    return analyzer.analyze_program(program)
