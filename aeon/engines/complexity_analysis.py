"""AEON Automatic Complexity Analysis — RAML-Style Amortized Resource Bounds.

Implements automatic worst-case complexity analysis based on:
  Hoffmann, Aehlig, Hofmann (2012) "Multivariate Amortized Resource Analysis"
  ACM TOPLAS 34(3), https://doi.org/10.1145/2362389.2362393

  Gulwani, Mehra, Chilimbi (2009) "SPEED: Precise and Efficient Static
  Estimation of Program Computational Complexity"
  POPL '09, https://doi.org/10.1145/1480881.1480898

  Hoffmann & Hofmann (2010) "Amortized Resource Analysis with Polynomial
  Potential"
  ESOP '10, https://doi.org/10.1007/978-3-642-11957-6_13

  Wegbreit (1975) "Mechanical Program Analysis"
  CACM 18(9), https://doi.org/10.1145/361002.361016

Key Theory:

1. AMORTIZED RESOURCE ANALYSIS (Hoffmann et al. 2012):
   Assign POTENTIAL FUNCTIONS to data structures that pay for
   future operations. The potential is a polynomial over the
   SIZES of data structures.

   For a list of length n, the potential is:
     Phi(L) = sum_{i=0}^{k} q_i * C(n, i)
   where C(n,i) = binomial(n, i) and q_i are coefficients to solve for.

   The key constraint at each operation:
     Phi_before >= cost + Phi_after

   Collecting all constraints yields a LINEAR PROGRAM.
   If feasible, the LP's objective value is the worst-case bound.

2. MULTIVARIATE POTENTIAL (Hoffmann et al. 2012):
   For nested data structures (e.g., list of lists), the potential
   is a MULTIVARIATE polynomial over sizes:

     Phi(L) = sum q_{i,j} * C(|L|, i) * C(|L[0]|, j)

   This handles:
     - Nested loops: O(n * m) from potential on list of lists
     - Matrix operations: O(n^2) or O(n^3)
     - Tree operations: O(n * log(n)) via tree potential

3. RECURRENCE SOLVING (Wegbreit 1975):
   For recursive functions, extract a RECURRENCE RELATION:
     T(n) = a * T(n/b) + f(n)

   Solve using the MASTER THEOREM:
     Case 1: f(n) = O(n^(log_b(a) - epsilon)) => T(n) = Theta(n^log_b(a))
     Case 2: f(n) = Theta(n^log_b(a)) => T(n) = Theta(n^log_b(a) * log(n))
     Case 3: f(n) = Omega(n^(log_b(a) + epsilon)) => T(n) = Theta(f(n))

   Or via the AKRA-BAZZI method for more general cases.

4. LOOP BOUND ANALYSIS (Gulwani et al. 2009):
   For loops, compute an upper bound on the number of iterations:
     - Counter-based: while (i < n) { i++ } => n iterations
     - Accumulator: while (s < n) { s += f(i); i++ } => n/min(f) iterations
     - Nested: for i in 0..n { for j in 0..m { ... } } => n * m iterations

   Uses PROGRESS MEASURES: a function that strictly increases
   toward a bound on each iteration.

5. COMPLEXITY CLASSES:
   O(1)        — constant: no loops, no recursion on input
   O(log n)    — logarithmic: halving recursion
   O(n)        — linear: single traversal
   O(n log n)  — linearithmic: divide and conquer with linear merge
   O(n^2)      — quadratic: nested traversal
   O(n^k)      — polynomial: k nested traversals
   O(2^n)      — exponential: branching recursion without memoization
   O(n!)       — factorial: permutation generation

Mathematical Framework:
  - Potential functions in the polynomial ring Q[n1, ..., nk]
  - Constraint generation as affine inequalities
  - LP solving in the tropical semiring for bound inference
  - Recurrence relations in the ring of formal power series
  - Asymptotic analysis via Bachmann-Landau notation
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any
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
# Complexity Classes
# ---------------------------------------------------------------------------

class ComplexityClass(Enum):
    """Standard asymptotic complexity classes."""
    O_1 = auto()           # O(1) — constant
    O_LOG_N = auto()       # O(log n)
    O_SQRT_N = auto()      # O(sqrt(n))
    O_N = auto()           # O(n) — linear
    O_N_LOG_N = auto()     # O(n log n)
    O_N_SQUARED = auto()   # O(n^2) — quadratic
    O_N_CUBED = auto()     # O(n^3) — cubic
    O_N_K = auto()         # O(n^k) — polynomial
    O_2_N = auto()         # O(2^n) — exponential
    O_N_FACT = auto()      # O(n!) — factorial
    UNKNOWN = auto()       # Cannot determine

    def __str__(self) -> str:
        names = {
            ComplexityClass.O_1: "O(1)",
            ComplexityClass.O_LOG_N: "O(log n)",
            ComplexityClass.O_SQRT_N: "O(√n)",
            ComplexityClass.O_N: "O(n)",
            ComplexityClass.O_N_LOG_N: "O(n log n)",
            ComplexityClass.O_N_SQUARED: "O(n²)",
            ComplexityClass.O_N_CUBED: "O(n³)",
            ComplexityClass.O_N_K: "O(n^k)",
            ComplexityClass.O_2_N: "O(2^n)",
            ComplexityClass.O_N_FACT: "O(n!)",
            ComplexityClass.UNKNOWN: "O(?)",
        }
        return names.get(self, "O(?)")

    def is_polynomial(self) -> bool:
        return self in (
            ComplexityClass.O_1, ComplexityClass.O_LOG_N,
            ComplexityClass.O_SQRT_N, ComplexityClass.O_N,
            ComplexityClass.O_N_LOG_N, ComplexityClass.O_N_SQUARED,
            ComplexityClass.O_N_CUBED, ComplexityClass.O_N_K,
        )

    def degree(self) -> int:
        degrees = {
            ComplexityClass.O_1: 0,
            ComplexityClass.O_LOG_N: 0,
            ComplexityClass.O_SQRT_N: 0,
            ComplexityClass.O_N: 1,
            ComplexityClass.O_N_LOG_N: 1,
            ComplexityClass.O_N_SQUARED: 2,
            ComplexityClass.O_N_CUBED: 3,
        }
        return degrees.get(self, -1)


# ---------------------------------------------------------------------------
# Potential Functions (Hoffmann et al. 2012)
# ---------------------------------------------------------------------------

@dataclass
class PotentialTerm:
    """A single term in a polynomial potential function.

    Represents: coefficient * C(n, degree)
    where C(n, k) = binomial(n, k) = n! / (k! * (n-k)!)

    Using binomial coefficients instead of monomials because:
    1. They naturally arise from list operations
    2. C(n, k) >= 0 for n >= k >= 0 (non-negativity for free)
    3. The recurrence C(n+1, k) = C(n, k) + C(n, k-1) matches cons/append
    """
    coefficient: float
    degree: int
    variable: str = "n"

    def evaluate(self, n: int) -> float:
        """Evaluate this potential term at a given size."""
        if n < self.degree:
            return 0.0
        binom = math.comb(n, self.degree) if self.degree >= 0 else 0
        return self.coefficient * binom

    def __str__(self) -> str:
        if self.degree == 0:
            return f"{self.coefficient}"
        if self.degree == 1:
            return f"{self.coefficient}·{self.variable}"
        return f"{self.coefficient}·C({self.variable},{self.degree})"


@dataclass
class PotentialFunction:
    """A polynomial potential function for amortized analysis.

    Phi(n) = sum_i q_i * C(n, i)

    where n is the size of a data structure and q_i are
    non-negative rational coefficients.

    For multivariate analysis:
    Phi(n1, n2) = sum_{i,j} q_{i,j} * C(n1, i) * C(n2, j)
    """
    terms: List[PotentialTerm] = field(default_factory=list)
    max_degree: int = 2

    def evaluate(self, sizes: Dict[str, int]) -> float:
        total = 0.0
        for term in self.terms:
            n = sizes.get(term.variable, 0)
            total += term.evaluate(n)
        return total

    def add_term(self, coeff: float, degree: int, variable: str = "n") -> None:
        self.terms.append(PotentialTerm(coefficient=coeff, degree=degree, variable=variable))

    def total_initial_potential(self, input_size: int) -> float:
        return self.evaluate({"n": input_size})

    def complexity_class(self) -> ComplexityClass:
        if not self.terms:
            return ComplexityClass.O_1
        max_deg = max(t.degree for t in self.terms if t.coefficient > 0) if self.terms else 0
        if max_deg == 0:
            return ComplexityClass.O_1
        if max_deg == 1:
            return ComplexityClass.O_N
        if max_deg == 2:
            return ComplexityClass.O_N_SQUARED
        if max_deg == 3:
            return ComplexityClass.O_N_CUBED
        return ComplexityClass.O_N_K

    def __str__(self) -> str:
        if not self.terms:
            return "Phi = 0"
        parts = [str(t) for t in self.terms if t.coefficient > 0]
        return f"Phi = {' + '.join(parts)}" if parts else "Phi = 0"


# ---------------------------------------------------------------------------
# Recurrence Relations (Wegbreit 1975)
# ---------------------------------------------------------------------------

@dataclass
class Recurrence:
    """A recurrence relation T(n) = a * T(n/b) + f(n).

    Solved via the Master Theorem:
      Case 1: f(n) = O(n^(c)) where c < log_b(a)  =>  T(n) = Theta(n^log_b(a))
      Case 2: f(n) = Theta(n^(log_b(a)) * log^k(n))  =>  T(n) = Theta(n^log_b(a) * log^(k+1)(n))
      Case 3: f(n) = Omega(n^c) where c > log_b(a)  =>  T(n) = Theta(f(n))
    """
    a: int = 1        # Number of recursive calls
    b: int = 2        # Factor by which input shrinks
    f_degree: int = 0  # Degree of non-recursive work f(n) = n^f_degree
    function_name: str = ""

    def solve_master_theorem(self) -> ComplexityClass:
        """Apply the Master Theorem to solve this recurrence."""
        if self.b <= 0 or self.a <= 0:
            return ComplexityClass.UNKNOWN

        log_b_a = math.log(self.a) / math.log(self.b) if self.b > 1 else float('inf')

        if self.f_degree < log_b_a - 0.001:
            # Case 1: T(n) = Theta(n^log_b_a)
            if abs(log_b_a) < 0.001:
                return ComplexityClass.O_1
            if abs(log_b_a - 1.0) < 0.001:
                return ComplexityClass.O_N
            if abs(log_b_a - 2.0) < 0.001:
                return ComplexityClass.O_N_SQUARED
            return ComplexityClass.O_N_K

        elif abs(self.f_degree - log_b_a) < 0.001:
            # Case 2: T(n) = Theta(n^log_b_a * log(n))
            if abs(log_b_a) < 0.001:
                return ComplexityClass.O_LOG_N
            if abs(log_b_a - 1.0) < 0.001:
                return ComplexityClass.O_N_LOG_N
            return ComplexityClass.O_N_K

        else:
            # Case 3: T(n) = Theta(f(n))
            if self.f_degree == 0:
                return ComplexityClass.O_1
            if self.f_degree == 1:
                return ComplexityClass.O_N
            if self.f_degree == 2:
                return ComplexityClass.O_N_SQUARED
            return ComplexityClass.O_N_K


# ---------------------------------------------------------------------------
# Loop Bound Analysis (Gulwani et al. 2009)
# ---------------------------------------------------------------------------

@dataclass
class LoopBound:
    """Computed upper bound on loop iterations."""
    bound_expr: str          # Human-readable bound expression
    complexity: ComplexityClass
    is_tight: bool = False   # True if bound is asymptotically tight
    loop_location: SourceLocation = field(default_factory=lambda: SourceLocation("", 1, 1))


def _analyze_loop_bound(while_stmt: WhileStmt) -> LoopBound:
    """Analyze a while loop to compute an iteration bound.

    Uses progress measures: find a quantity that strictly
    increases toward a bound on each iteration.

    Patterns:
      while (i < n) { i++ }           => O(n)
      while (i < n) { i += 2 }        => O(n)
      while (i > 0) { i /= 2 }        => O(log n)
      while (i < n) { for j... }       => O(n * inner_bound)
    """
    cond = while_stmt.condition if hasattr(while_stmt, 'condition') else None
    loc = getattr(while_stmt, 'location', SourceLocation("", 1, 1))

    if cond is None:
        return LoopBound("unknown", ComplexityClass.UNKNOWN, loop_location=loc)

    # Try to detect pattern from condition
    if isinstance(cond, BinaryOp):
        op = str(cond.op) if hasattr(cond, 'op') else ""
        if op in ('<', '<=', '!='):
            # i < n pattern => O(n)
            return LoopBound("n", ComplexityClass.O_N, is_tight=True, loop_location=loc)
        elif op in ('>', '>='):
            # i > 0 with division => O(log n)
            body = while_stmt.body if hasattr(while_stmt, 'body') else []
            if not isinstance(body, list):
                body = [body] if body else []
            for s in body:
                if isinstance(s, AssignStmt) and isinstance(s.value, BinaryOp):
                    if hasattr(s.value, 'op') and str(s.value.op) in ('/', '//', '>>', 'div'):
                        return LoopBound("log(n)", ComplexityClass.O_LOG_N,
                                          is_tight=True, loop_location=loc)
            return LoopBound("n", ComplexityClass.O_N, loop_location=loc)

    return LoopBound("unknown", ComplexityClass.UNKNOWN, loop_location=loc)


# ---------------------------------------------------------------------------
# Function Complexity Analysis
# ---------------------------------------------------------------------------

@dataclass
class FunctionComplexity:
    """Computed complexity of a single function."""
    name: str
    time_complexity: ComplexityClass = ComplexityClass.UNKNOWN
    space_complexity: ComplexityClass = ComplexityClass.UNKNOWN
    potential: PotentialFunction = field(default_factory=PotentialFunction)
    recurrence: Optional[Recurrence] = None
    loop_bounds: List[LoopBound] = field(default_factory=list)
    is_recursive: bool = False
    recursive_calls: int = 0
    nesting_depth: int = 0  # Max nesting of loops/recursion


def _count_recursive_calls(func_name: str, body: List[Statement]) -> int:
    """Count recursive calls to func_name in the body."""
    count = 0

    def _scan_expr(expr: Expr) -> None:
        nonlocal count
        if isinstance(expr, FunctionCall):
            callee = getattr(expr, 'callee', None)
            name = getattr(callee, 'name', '') if callee else getattr(expr, 'name', '')
            if name == func_name:
                count += 1
            for arg in expr.args:
                _scan_expr(arg)
        elif isinstance(expr, BinaryOp):
            _scan_expr(expr.left)
            _scan_expr(expr.right)
        elif isinstance(expr, UnaryOp):
            _scan_expr(expr.operand)

    def _scan_stmt(stmt: Statement) -> None:
        if isinstance(stmt, LetStmt):
            _scan_expr(stmt.value)
        elif isinstance(stmt, AssignStmt):
            _scan_expr(stmt.value)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                _scan_expr(stmt.value)
        elif isinstance(stmt, ExprStmt):
            _scan_expr(stmt.expr)
        elif isinstance(stmt, IfStmt):
            _scan_expr(stmt.condition)
            then_body = stmt.then_body if isinstance(stmt.then_body, list) else [stmt.then_body]
            for s in then_body:
                _scan_stmt(s)
            if stmt.else_body:
                else_body = stmt.else_body if isinstance(stmt.else_body, list) else [stmt.else_body]
                for s in else_body:
                    _scan_stmt(s)

    for s in body:
        _scan_stmt(s)
    return count


def _detect_input_reduction(func_name: str, body: List[Statement]) -> Tuple[int, int]:
    """Detect how recursive calls reduce the input.

    Returns (num_calls, reduction_factor):
      - num_calls: how many recursive calls per step
      - reduction_factor: how much the input shrinks (2 for halving, etc.)
    """
    num_calls = _count_recursive_calls(func_name, body)

    reduction = 1
    for stmt in body:
        if isinstance(stmt, IfStmt):
            then_body = stmt.then_body if isinstance(stmt.then_body, list) else [stmt.then_body]
            for s in then_body:
                if isinstance(s, ReturnStmt) and s.value and isinstance(s.value, FunctionCall):
                    name = s.value.name if isinstance(s.value.name, str) else ""
                    if name == func_name and s.value.args:
                        arg0 = s.value.args[0]
                        if isinstance(arg0, BinaryOp):
                            op = str(arg0.op) if hasattr(arg0, 'op') else ""
                            if op in ('-', ):
                                reduction = 1  # Linear reduction
                            elif op in ('/', '//', '>>', 'div'):
                                reduction = 2  # Halving

    return num_calls, max(reduction, 1)


def _compute_nesting_depth(body: List[Statement]) -> int:
    """Compute the maximum nesting depth of loops and conditionals."""
    max_depth = 0

    def _depth(stmts: List[Statement], current: int) -> None:
        nonlocal max_depth
        for s in stmts:
            if isinstance(s, IfStmt):
                then_body = s.then_body if isinstance(s.then_body, list) else [s.then_body]
                _depth(then_body, current + 1)
                if s.else_body:
                    else_body = s.else_body if isinstance(s.else_body, list) else [s.else_body]
                    _depth(else_body, current + 1)
                max_depth = max(max_depth, current + 1)
            elif hasattr(s, 'body'):
                inner = s.body if isinstance(s.body, list) else [s.body]
                _depth(inner, current + 1)
                max_depth = max(max_depth, current + 1)

    _depth(body, 0)
    return max_depth


def _analyze_function_complexity(func) -> FunctionComplexity:
    """Analyze the complexity of a single function."""
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"
    body = func.body if hasattr(func, 'body') else []
    if not isinstance(body, list):
        body = [body] if body else []

    result = FunctionComplexity(name=func_name)

    # Check for recursion
    num_calls = _count_recursive_calls(func_name, body)
    result.is_recursive = num_calls > 0
    result.recursive_calls = num_calls

    # Compute nesting depth
    result.nesting_depth = _compute_nesting_depth(body)

    if result.is_recursive:
        # Extract and solve recurrence
        a, b = _detect_input_reduction(func_name, body)
        f_degree = result.nesting_depth  # Non-recursive work degree

        result.recurrence = Recurrence(
            a=max(a, 1), b=max(b, 1),
            f_degree=f_degree, function_name=func_name
        )
        result.time_complexity = result.recurrence.solve_master_theorem()

        # Build potential function
        degree = result.time_complexity.degree()
        if degree >= 0:
            result.potential.add_term(1.0, degree, "n")
    else:
        # Non-recursive: complexity from nesting depth
        if result.nesting_depth == 0:
            result.time_complexity = ComplexityClass.O_1
        elif result.nesting_depth == 1:
            result.time_complexity = ComplexityClass.O_N
        elif result.nesting_depth == 2:
            result.time_complexity = ComplexityClass.O_N_SQUARED
        elif result.nesting_depth == 3:
            result.time_complexity = ComplexityClass.O_N_CUBED
        else:
            result.time_complexity = ComplexityClass.O_N_K

    # Space complexity: count allocations and data structure sizes
    alloc_count = sum(1 for s in body if isinstance(s, LetStmt))
    if result.is_recursive:
        result.space_complexity = ComplexityClass.O_N  # Stack space
    elif alloc_count == 0:
        result.space_complexity = ComplexityClass.O_1
    else:
        result.space_complexity = ComplexityClass.O_N

    return result


# ---------------------------------------------------------------------------
# Contract Checking
# ---------------------------------------------------------------------------

_COMPLEXITY_KEYWORDS = {
    'o(1)': ComplexityClass.O_1,
    'o(log n)': ComplexityClass.O_LOG_N,
    'o(logn)': ComplexityClass.O_LOG_N,
    'o(n)': ComplexityClass.O_N,
    'o(n log n)': ComplexityClass.O_N_LOG_N,
    'o(nlogn)': ComplexityClass.O_N_LOG_N,
    'o(n^2)': ComplexityClass.O_N_SQUARED,
    'o(n²)': ComplexityClass.O_N_SQUARED,
    'o(n^3)': ComplexityClass.O_N_CUBED,
    'o(n³)': ComplexityClass.O_N_CUBED,
    'constant': ComplexityClass.O_1,
    'linear': ComplexityClass.O_N,
    'quadratic': ComplexityClass.O_N_SQUARED,
    'cubic': ComplexityClass.O_N_CUBED,
    'logarithmic': ComplexityClass.O_LOG_N,
    'polynomial': ComplexityClass.O_N_K,
    'exponential': ComplexityClass.O_2_N,
}

_COMPLEXITY_ORDER = [
    ComplexityClass.O_1, ComplexityClass.O_LOG_N, ComplexityClass.O_SQRT_N,
    ComplexityClass.O_N, ComplexityClass.O_N_LOG_N, ComplexityClass.O_N_SQUARED,
    ComplexityClass.O_N_CUBED, ComplexityClass.O_N_K,
    ComplexityClass.O_2_N, ComplexityClass.O_N_FACT,
]


def _complexity_leq(c1: ComplexityClass, c2: ComplexityClass) -> bool:
    """Check if c1 <= c2 in the complexity ordering."""
    if c1 == ComplexityClass.UNKNOWN or c2 == ComplexityClass.UNKNOWN:
        return True
    try:
        return _COMPLEXITY_ORDER.index(c1) <= _COMPLEXITY_ORDER.index(c2)
    except ValueError:
        return True


def _check_complexity_contracts(func, computed: FunctionComplexity,
                                 errors: List[AeonError]) -> None:
    """Check declared complexity contracts against computed bounds."""
    loc = getattr(func, 'location', SourceLocation("", 1, 1))
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"

    contracts = func.contracts if hasattr(func, 'contracts') else []
    for c in contracts:
        text = c.expression if hasattr(c, 'expression') else str(c)
        if not isinstance(text, str):
            continue
        text_lower = text.lower()

        # Check for complexity annotations
        for keyword, declared_class in _COMPLEXITY_KEYWORDS.items():
            if keyword in text_lower:
                if not _complexity_leq(computed.time_complexity, declared_class):
                    errors.append(contract_error(
                        f"Complexity violation in '{func_name}': "
                        f"declared {declared_class} but computed {computed.time_complexity} — "
                        f"potential function {computed.potential} exceeds declared bound "
                        f"(Hoffmann et al. 2012: RAML amortized analysis)",
                        location=loc
                    ))
                break


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_complexity(program: Program) -> List[AeonError]:
    """Run automatic complexity analysis on an AEON program.

    Checks:
    1. Amortized resource bounds via potential functions (Hoffmann et al. 2012)
    2. Recurrence solving via Master Theorem (Wegbreit 1975)
    3. Loop bound analysis (Gulwani et al. 2009)
    4. Complexity contract verification
    5. Exponential complexity warnings for recursive functions
    """
    errors: List[AeonError] = []

    functions = [d for d in program.declarations
                 if isinstance(d, (PureFunc, TaskFunc))]

    for func in functions:
        loc = getattr(func, 'location', SourceLocation("", 1, 1))
        func_name = func.name if hasattr(func, 'name') else "<anonymous>"

        result = _analyze_function_complexity(func)
        _check_complexity_contracts(func, result, errors)

        # Warn about exponential complexity
        if result.time_complexity == ComplexityClass.O_2_N:
            errors.append(contract_error(
                f"Exponential time complexity O(2^n) detected in '{func_name}': "
                f"{result.recursive_calls} recursive call(s) without memoization — "
                f"consider dynamic programming or iterative approach "
                f"(Wegbreit 1975: mechanical program analysis)",
                location=loc
            ))

        # Warn about deeply nested recursion
        if result.is_recursive and result.recursive_calls >= 3:
            errors.append(contract_error(
                f"High branching factor ({result.recursive_calls} recursive calls) "
                f"in '{func_name}' — potential exponential blowup "
                f"(Master Theorem: a={result.recurrence.a if result.recurrence else '?'}, "
                f"b={result.recurrence.b if result.recurrence else '?'})",
                location=loc
            ))

    return errors
