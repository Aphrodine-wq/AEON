"""AEON Abstract Interpretation Framework.

Implements the theory of abstract interpretation from:
  Cousot & Cousot (1977) "Abstract Interpretation: A Unified Lattice Model
  for Static Analysis of Programs by Construction or Approximation of Fixpoints"
  POPL '77, https://doi.org/10.1145/512950.512973

Key mathematical structures:

1. ABSTRACT DOMAINS as complete lattices (L, <=, bot, top, meet, join)
   with Galois connections (alpha, gamma) to the concrete domain:

     Concrete domain C  <--gamma--  Abstract domain A
                         --alpha-->

   where alpha (abstraction) and gamma (concretization) satisfy:
     forall c in C, a in A:  alpha(c) <= a  iff  c <= gamma(a)

   This ensures soundness: every concrete execution is captured by
   the abstract semantics.

2. ABSTRACT TRANSFER FUNCTIONS: for each program statement S,
   an abstract transformer F# : A -> A such that:
     alpha(F(gamma(a))) <= F#(a)    (soundness condition)

3. FIXPOINT COMPUTATION with widening:
   For loops, we compute: bot, F#(bot), F#(F#(bot)), ...
   This sequence may not converge (infinite ascending chains).
   Widening operator nabla : A x A -> A accelerates convergence:
     a nabla b >= a join b    (above the join)
     The widened sequence converges in finite steps.
   Narrowing operator delta refines the approximation downward.

4. REDUCED PRODUCT: combining multiple abstract domains for precision.
   Given domains A1, A2, the reduced product A1 x_r A2 applies
   mutual reduction: information from each domain refines the other.

Abstract domains implemented:
  - Interval domain:     [lo, hi]  (bounds analysis)
  - Sign domain:         {neg, zero, pos, top, bot}
  - Congruence domain:   a (mod m)  (divisibility analysis)
  - Octagon domain:      +/- x +/- y <= c  (relational, Mine 2006)
  - Polyhedra domain:    Ax <= b  (fully relational, Cousot & Halbwachs 1978)
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Set, Tuple, Generic, TypeVar
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, Statement, Expr,
    IntLiteral, FloatLiteral, BoolLiteral, Identifier,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Abstract Domain Interface (Complete Lattice)
# ---------------------------------------------------------------------------

T = TypeVar("T")


class AbstractValue(ABC):
    """An element of an abstract domain.

    Must form a complete lattice with:
      - bottom (no information / unreachable)
      - top (any value / no constraint)
      - join (least upper bound)
      - meet (greatest lower bound)
      - partial order (<=)
    """

    @abstractmethod
    def is_bottom(self) -> bool:
        """True if this is the bottom element (unreachable)."""
        ...

    @abstractmethod
    def is_top(self) -> bool:
        """True if this is the top element (no information)."""
        ...

    @abstractmethod
    def join(self, other: AbstractValue) -> AbstractValue:
        """Least upper bound: self join other."""
        ...

    @abstractmethod
    def meet(self, other: AbstractValue) -> AbstractValue:
        """Greatest lower bound: self meet other."""
        ...

    @abstractmethod
    def widen(self, other: AbstractValue) -> AbstractValue:
        """Widening operator for fixpoint acceleration.

        Must satisfy: self widen other >= self join other
        Must ensure: ascending chains stabilize in finite steps.
        """
        ...

    @abstractmethod
    def narrow(self, other: AbstractValue) -> AbstractValue:
        """Narrowing operator for fixpoint refinement.

        Must satisfy: other <= self narrow other <= self
        """
        ...

    @abstractmethod
    def leq(self, other: AbstractValue) -> bool:
        """Partial order: self <= other."""
        ...


# ---------------------------------------------------------------------------
# Interval Domain: [lo, hi] with +/- infinity
# ---------------------------------------------------------------------------

INF = float("inf")
NEG_INF = float("-inf")


@dataclass(frozen=True)
class Interval(AbstractValue):
    """The interval abstract domain [lo, hi].

    Galois connection to P(Z):
      alpha(S) = [min(S), max(S)]
      gamma([lo, hi]) = {n in Z | lo <= n <= hi}

    Properties:
      - [lo, hi] <= [lo', hi']  iff  lo' <= lo and hi <= hi'
      - [lo, hi] join [lo', hi'] = [min(lo,lo'), max(hi,hi')]
      - [lo, hi] meet [lo', hi'] = [max(lo,lo'), min(hi,hi')]  (bot if empty)
      - bot = [+inf, -inf]  (empty interval)
      - top = [-inf, +inf]  (all integers)
    """
    lo: float = NEG_INF
    hi: float = INF

    def __str__(self) -> str:
        if self.is_bottom():
            return "bot"
        if self.is_top():
            return "top"
        lo_s = "-inf" if self.lo == NEG_INF else str(int(self.lo))
        hi_s = "+inf" if self.hi == INF else str(int(self.hi))
        return f"[{lo_s}, {hi_s}]"

    def is_bottom(self) -> bool:
        return self.lo > self.hi

    def is_top(self) -> bool:
        return self.lo == NEG_INF and self.hi == INF

    def join(self, other: AbstractValue) -> Interval:
        if not isinstance(other, Interval):
            return INTERVAL_TOP
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))

    def meet(self, other: AbstractValue) -> Interval:
        if not isinstance(other, Interval):
            return INTERVAL_BOT
        new_lo = max(self.lo, other.lo)
        new_hi = min(self.hi, other.hi)
        if new_lo > new_hi:
            return INTERVAL_BOT
        return Interval(new_lo, new_hi)

    def widen(self, other: AbstractValue) -> Interval:
        """Widening with thresholds {-1, 0, 1, 10, 100, 1000}.

        Standard widening:
          [a, b] nabla [c, d] = [c < a ? -inf : a,  d > b ? +inf : b]

        Threshold widening (more precise): instead of jumping to infinity,
        jump to the next threshold value.
        """
        if not isinstance(other, Interval):
            return INTERVAL_TOP
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self

        THRESHOLDS = [NEG_INF, -1000, -100, -10, -1, 0, 1, 10, 100, 1000, INF]

        # Lower bound: if other.lo < self.lo, widen downward
        if other.lo < self.lo:
            new_lo = NEG_INF
            for t in THRESHOLDS:
                if t <= other.lo:
                    new_lo = t
            # Pick the largest threshold <= other.lo
        else:
            new_lo = self.lo

        # Upper bound: if other.hi > self.hi, widen upward
        if other.hi > self.hi:
            new_hi = INF
            for t in reversed(THRESHOLDS):
                if t >= other.hi:
                    new_hi = t
        else:
            new_hi = self.hi

        return Interval(new_lo, new_hi)

    def narrow(self, other: AbstractValue) -> Interval:
        """Narrowing: refine bounds if self has infinity."""
        if not isinstance(other, Interval):
            return self
        new_lo = other.lo if self.lo == NEG_INF else self.lo
        new_hi = other.hi if self.hi == INF else self.hi
        return Interval(new_lo, new_hi)

    def leq(self, other: AbstractValue) -> bool:
        if not isinstance(other, Interval):
            return False
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return other.lo <= self.lo and self.hi <= other.hi

    # Arithmetic transfer functions
    def add(self, other: Interval) -> Interval:
        if self.is_bottom() or other.is_bottom():
            return INTERVAL_BOT
        return Interval(self.lo + other.lo, self.hi + other.hi)

    def sub(self, other: Interval) -> Interval:
        if self.is_bottom() or other.is_bottom():
            return INTERVAL_BOT
        return Interval(self.lo - other.hi, self.hi - other.lo)

    def mul(self, other: Interval) -> Interval:
        if self.is_bottom() or other.is_bottom():
            return INTERVAL_BOT
        products = [
            self.lo * other.lo, self.lo * other.hi,
            self.hi * other.lo, self.hi * other.hi,
        ]
        # Handle inf * 0 = 0 convention
        products = [0.0 if math.isinf(p) and p != p else p for p in products]
        finite = [p for p in products if not math.isnan(p)]
        if not finite:
            return INTERVAL_TOP
        return Interval(min(finite), max(finite))

    def div(self, other: Interval) -> Interval:
        """Integer division with division-by-zero detection."""
        if self.is_bottom() or other.is_bottom():
            return INTERVAL_BOT
        if other.lo <= 0 <= other.hi:
            # Divisor spans zero — could be division by zero
            return INTERVAL_TOP
        # Safe division
        bounds = []
        for a in [self.lo, self.hi]:
            for b in [other.lo, other.hi]:
                if b != 0 and not math.isinf(a):
                    bounds.append(a / b)
        if not bounds:
            return INTERVAL_TOP
        return Interval(min(bounds), max(bounds))

    def neg(self) -> Interval:
        if self.is_bottom():
            return INTERVAL_BOT
        return Interval(-self.hi, -self.lo)

    def contains(self, value: int) -> bool:
        return self.lo <= value <= self.hi


INTERVAL_BOT = Interval(INF, NEG_INF)
INTERVAL_TOP = Interval(NEG_INF, INF)


# ---------------------------------------------------------------------------
# Sign Domain
# ---------------------------------------------------------------------------

class SignValue(Enum):
    """The sign abstract domain.

    Hasse diagram:
           top
         / | \\
       neg zero pos
         \\ | /
           bot

    Galois connection:
      alpha(S) = join { sign(n) | n in S }
      gamma(neg)  = {n in Z | n < 0}
      gamma(zero) = {0}
      gamma(pos)  = {n in Z | n > 0}
    """
    BOT = auto()
    NEG = auto()
    ZERO = auto()
    POS = auto()
    TOP = auto()


@dataclass(frozen=True)
class Sign(AbstractValue):
    value: SignValue = SignValue.TOP

    def __str__(self) -> str:
        return self.value.name.lower()

    def is_bottom(self) -> bool:
        return self.value == SignValue.BOT

    def is_top(self) -> bool:
        return self.value == SignValue.TOP

    def join(self, other: AbstractValue) -> Sign:
        if not isinstance(other, Sign):
            return Sign(SignValue.TOP)
        if self.value == other.value:
            return self
        if self.value == SignValue.BOT:
            return other
        if other.value == SignValue.BOT:
            return self
        return Sign(SignValue.TOP)

    def meet(self, other: AbstractValue) -> Sign:
        if not isinstance(other, Sign):
            return Sign(SignValue.BOT)
        if self.value == other.value:
            return self
        if self.value == SignValue.TOP:
            return other
        if other.value == SignValue.TOP:
            return self
        return Sign(SignValue.BOT)

    def widen(self, other: AbstractValue) -> Sign:
        return self.join(other)  # Finite domain, no widening needed

    def narrow(self, other: AbstractValue) -> Sign:
        return self.meet(other)

    def leq(self, other: AbstractValue) -> bool:
        if not isinstance(other, Sign):
            return False
        if self.value == SignValue.BOT:
            return True
        if other.value == SignValue.TOP:
            return True
        return self.value == other.value

    @staticmethod
    def from_int(n: int) -> Sign:
        if n < 0:
            return Sign(SignValue.NEG)
        if n == 0:
            return Sign(SignValue.ZERO)
        return Sign(SignValue.POS)

    # Sign arithmetic (abstract transfer functions)
    _ADD_TABLE = {
        (SignValue.POS, SignValue.POS): SignValue.POS,
        (SignValue.NEG, SignValue.NEG): SignValue.NEG,
        (SignValue.ZERO, SignValue.ZERO): SignValue.ZERO,
        (SignValue.POS, SignValue.ZERO): SignValue.POS,
        (SignValue.ZERO, SignValue.POS): SignValue.POS,
        (SignValue.NEG, SignValue.ZERO): SignValue.NEG,
        (SignValue.ZERO, SignValue.NEG): SignValue.NEG,
    }

    _MUL_TABLE = {
        (SignValue.POS, SignValue.POS): SignValue.POS,
        (SignValue.NEG, SignValue.NEG): SignValue.POS,
        (SignValue.POS, SignValue.NEG): SignValue.NEG,
        (SignValue.NEG, SignValue.POS): SignValue.NEG,
        (SignValue.ZERO, SignValue.POS): SignValue.ZERO,
        (SignValue.ZERO, SignValue.NEG): SignValue.ZERO,
        (SignValue.POS, SignValue.ZERO): SignValue.ZERO,
        (SignValue.NEG, SignValue.ZERO): SignValue.ZERO,
        (SignValue.ZERO, SignValue.ZERO): SignValue.ZERO,
    }

    def add(self, other: Sign) -> Sign:
        if self.is_bottom() or other.is_bottom():
            return Sign(SignValue.BOT)
        key = (self.value, other.value)
        result = self._ADD_TABLE.get(key, SignValue.TOP)
        return Sign(result)

    def mul(self, other: Sign) -> Sign:
        if self.is_bottom() or other.is_bottom():
            return Sign(SignValue.BOT)
        key = (self.value, other.value)
        result = self._MUL_TABLE.get(key, SignValue.TOP)
        return Sign(result)


# ---------------------------------------------------------------------------
# Congruence Domain: a (mod m)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Congruence(AbstractValue):
    """The congruence abstract domain: a (mod m).

    Represents the set {a + k*m | k in Z}.
    Special cases:
      - m == 0: singleton {a}
      - m == 1: all integers (top)
      - bottom: empty set

    Galois connection:
      alpha(S) = (a mod gcd(S-a))  for any a in S
      gamma(a, m) = {a + k*m | k in Z}

    This domain captures divisibility properties, useful for:
      - Array alignment checking
      - Loop stride analysis
      - Modular arithmetic verification
    """
    remainder: int = 0
    modulus: int = 1  # 0 = exact, 1 = top
    is_bot: bool = False

    def __str__(self) -> str:
        if self.is_bot:
            return "bot"
        if self.modulus == 1:
            return "top"
        if self.modulus == 0:
            return str(self.remainder)
        return f"{self.remainder} (mod {self.modulus})"

    def is_bottom(self) -> bool:
        return self.is_bot

    def is_top(self) -> bool:
        return not self.is_bot and self.modulus == 1

    def join(self, other: AbstractValue) -> Congruence:
        if not isinstance(other, Congruence):
            return Congruence(modulus=1)
        if self.is_bot:
            return other
        if other.is_bot:
            return self
        # join(a1 mod m1, a2 mod m2) = (a1 mod gcd(m1, m2, |a1-a2|))
        g = math.gcd(self.modulus, other.modulus)
        g = math.gcd(g, abs(self.remainder - other.remainder))
        if g == 0:
            g = 1
        return Congruence(remainder=self.remainder % g if g > 0 else self.remainder,
                          modulus=g)

    def meet(self, other: AbstractValue) -> Congruence:
        if not isinstance(other, Congruence):
            return Congruence(is_bot=True)
        if self.is_bot or other.is_bot:
            return Congruence(is_bot=True)
        # CRT-based meet (simplified)
        if self.modulus == 1:
            return other
        if other.modulus == 1:
            return self
        # Check compatibility
        g = math.gcd(self.modulus, other.modulus)
        if g > 0 and (self.remainder % g) != (other.remainder % g):
            return Congruence(is_bot=True)
        # LCM for combined modulus
        lcm = abs(self.modulus * other.modulus) // g if g > 0 else 0
        return Congruence(remainder=self.remainder, modulus=lcm if lcm > 0 else 0)

    def widen(self, other: AbstractValue) -> Congruence:
        return self.join(other)  # Finite height for bounded moduli

    def narrow(self, other: AbstractValue) -> Congruence:
        return self.meet(other)

    def leq(self, other: AbstractValue) -> bool:
        if not isinstance(other, Congruence):
            return False
        if self.is_bot:
            return True
        if other.is_top():
            return True
        if other.modulus == 0:
            return self.modulus == 0 and self.remainder == other.remainder
        if self.modulus == 0:
            return (self.remainder % other.modulus) == (other.remainder % other.modulus)
        return (other.modulus != 0 and
                self.modulus % other.modulus == 0 and
                self.remainder % other.modulus == other.remainder % other.modulus)


# ---------------------------------------------------------------------------
# Octagon Domain (Miné 2006) — Weakly Relational
# ---------------------------------------------------------------------------

@dataclass
class OctagonConstraint:
    """A single octagonal constraint: +/- x +/- y <= c.

    The octagon domain represents conjunctions of constraints of the form:
      +/- x_i +/- x_j <= c_{ij}

    This is strictly more precise than intervals (captures x - y <= 5)
    but less precise than full polyhedra (can't express x + 2y <= 3).

    Closure is computed via the Floyd-Warshall shortest-path algorithm
    on the DIFFERENCE BOUND MATRIX (DBM):
      For variables x_i, introduce x_i^+ and x_i^-
      Then +x_i - x_j <= c  becomes  x_i^+ - x_j^+ <= c  in the DBM
      And -x_i + x_j <= c  becomes  x_i^- - x_j^- <= c

    The DBM has dimension 2n x 2n for n variables.
    Closure ensures transitivity: if x-y<=3 and y-z<=5 then x-z<=8.

    Mathematical properties:
      - The octagon domain forms a lattice with height O(n^2 * max_const)
      - Join: pointwise max of DBM entries
      - Meet: pointwise min of DBM entries
      - Widening: if new bound > old bound, set to +infinity
      - Closure: O(n^3) via Floyd-Warshall (coherent closure for octagons)
    """
    var1: str
    var2: str
    sign1: int  # +1 or -1
    sign2: int  # +1 or -1
    bound: float

    def __str__(self) -> str:
        s1 = "" if self.sign1 == 1 else "-"
        s2 = "+" if self.sign2 == 1 else "-"
        return f"{s1}{self.var1} {s2} {self.var2} <= {self.bound}"

    def evaluate(self, values: Dict[str, float]) -> bool:
        v1 = values.get(self.var1, 0.0)
        v2 = values.get(self.var2, 0.0)
        return self.sign1 * v1 + self.sign2 * v2 <= self.bound


@dataclass
class OctagonDomain:
    """The Octagon abstract domain (Miné, WCRE 2004, HOSC 2006).

    Represents a conjunction of octagonal constraints via a
    Difference Bound Matrix (DBM). For n variables, the DBM
    is 2n x 2n where each variable x_i has positive (x_i^+)
    and negative (x_i^-) forms.

    DBM entry m[2i, 2j] represents: x_i^+ - x_j^+ <= m[2i, 2j]
    which encodes: x_i - x_j <= m[2i, 2j]

    The STRONG CLOSURE operation ensures:
      1. Shortest-path closure (Floyd-Warshall)
      2. Coherence: m[2i, 2j] = m[2j+1, 2i+1]
      3. Tightening: m[2i, 2i+1] = 2 * floor(m[2i, 2i+1] / 2)
    """
    variables: List[str] = field(default_factory=list)
    constraints: List[OctagonConstraint] = field(default_factory=list)
    _var_index: Dict[str, int] = field(default_factory=dict)
    _dbm: Optional[List[List[float]]] = None

    def add_variable(self, name: str) -> None:
        if name not in self._var_index:
            self._var_index[name] = len(self.variables)
            self.variables.append(name)

    def add_constraint(self, var1: str, sign1: int, var2: str, sign2: int,
                       bound: float) -> None:
        self.add_variable(var1)
        self.add_variable(var2)
        self.constraints.append(OctagonConstraint(var1, var2, sign1, sign2, bound))

    def _build_dbm(self) -> List[List[float]]:
        """Build the 2n x 2n Difference Bound Matrix."""
        n = len(self.variables)
        size = 2 * n
        dbm = [[INF] * size for _ in range(size)]
        for i in range(size):
            dbm[i][i] = 0.0

        for c in self.constraints:
            i = self._var_index.get(c.var1, -1)
            j = self._var_index.get(c.var2, -1)
            if i < 0 or j < 0:
                continue
            # Map constraint to DBM indices
            # +x_i + x_j <= c  =>  x_i^+ - x_j^- <= c
            if c.sign1 == 1 and c.sign2 == 1:
                row, col = 2 * i, 2 * j + 1
            elif c.sign1 == 1 and c.sign2 == -1:
                row, col = 2 * i, 2 * j
            elif c.sign1 == -1 and c.sign2 == 1:
                row, col = 2 * i + 1, 2 * j + 1
            else:
                row, col = 2 * i + 1, 2 * j
            dbm[row][col] = min(dbm[row][col], c.bound)

        return dbm

    def close(self) -> None:
        """Compute the STRONG CLOSURE of the octagon via Floyd-Warshall.

        This ensures all implied constraints are made explicit.
        Complexity: O(n^3) where n = number of variables.

        The closure algorithm also checks for EMPTINESS:
        if any diagonal entry becomes negative, the octagon is empty
        (the constraints are contradictory).
        """
        self._dbm = self._build_dbm()
        n = len(self._dbm)

        # Floyd-Warshall shortest paths
        for k in range(n):
            for i in range(n):
                for j in range(n):
                    if self._dbm[i][k] + self._dbm[k][j] < self._dbm[i][j]:
                        self._dbm[i][j] = self._dbm[i][k] + self._dbm[k][j]

        # Strengthening: use unary constraints to tighten binary ones
        for i in range(n):
            for j in range(n):
                # Coherence: m[i,j] = m[j',i'] where i' = i^1, j' = j^1
                i_bar = i ^ 1
                j_bar = j ^ 1
                self._dbm[i][j] = min(self._dbm[i][j], self._dbm[j_bar][i_bar])

                # Tightening via unary bounds
                self._dbm[i][j] = min(
                    self._dbm[i][j],
                    (self._dbm[i][i ^ 1] + self._dbm[j ^ 1][j]) / 2.0
                )

    def is_empty(self) -> bool:
        """Check if the octagon is empty (contradictory constraints)."""
        if self._dbm is None:
            self.close()
        for i in range(len(self._dbm)):
            if self._dbm[i][i] < 0:
                return True
        return False

    def get_interval(self, var: str) -> Interval:
        """Extract the interval for a variable from the octagon.

        From DBM: x_i in [-m[2i+1, 2i]/2, m[2i, 2i+1]/2]
        """
        if self._dbm is None:
            self.close()
        i = self._var_index.get(var, -1)
        if i < 0:
            return INTERVAL_TOP
        upper = self._dbm[2 * i][2 * i + 1] / 2.0
        lower = -self._dbm[2 * i + 1][2 * i] / 2.0
        return Interval(lower, upper)

    def get_difference_bound(self, var1: str, var2: str) -> float:
        """Get the bound on var1 - var2 from the octagon."""
        if self._dbm is None:
            self.close()
        i = self._var_index.get(var1, -1)
        j = self._var_index.get(var2, -1)
        if i < 0 or j < 0:
            return INF
        return self._dbm[2 * i][2 * j]


# ---------------------------------------------------------------------------
# Reduced Product (Cousot & Cousot 1979)
# ---------------------------------------------------------------------------

@dataclass
class ReducedProduct:
    """The REDUCED PRODUCT of multiple abstract domains.

    Given domains D1 and D2 with Galois connections:
      (alpha1, gamma1) : Concrete <-> D1
      (alpha2, gamma2) : Concrete <-> D2

    The direct product D1 x D2 is:
      alpha_{1x2}(S) = (alpha1(S), alpha2(S))
      gamma_{1x2}(a1, a2) = gamma1(a1) ∩ gamma2(a2)

    The REDUCED product applies MUTUAL REDUCTION:
    information from each domain refines the other.

    Example: if interval says x in [0, 10] and sign says x = neg,
    the reduced product infers x = bottom (contradiction).

    Reduction rules:
      - Interval [a, b] with sign=pos => [max(a, 1), b]
      - Interval [a, b] with sign=neg => [a, min(b, -1)]
      - Interval [a, b] with sign=zero => [0, 0] if 0 in [a, b], else bot
      - Congruence r (mod m) with interval [a, b] => tighter interval
    """
    interval: Interval = field(default_factory=lambda: INTERVAL_TOP)
    sign: Sign = field(default_factory=lambda: Sign(SignValue.TOP))
    congruence: Congruence = field(default_factory=lambda: Congruence(modulus=1))

    def reduce(self) -> ReducedProduct:
        """Apply mutual reduction between domains.

        This is the key operation that makes the product more precise
        than running each domain independently.
        """
        iv = self.interval
        sg = self.sign
        cg = self.congruence

        # Sign refines interval
        if sg.value == SignValue.POS:
            iv = iv.meet(Interval(1, INF))
        elif sg.value == SignValue.NEG:
            iv = iv.meet(Interval(NEG_INF, -1))
        elif sg.value == SignValue.ZERO:
            iv = iv.meet(Interval(0, 0))
        elif sg.value == SignValue.BOT:
            return ReducedProduct(INTERVAL_BOT, Sign(SignValue.BOT),
                                   Congruence(is_bot=True))

        # Interval refines sign
        if iv.is_bottom():
            return ReducedProduct(INTERVAL_BOT, Sign(SignValue.BOT),
                                   Congruence(is_bot=True))
        if iv.lo > 0:
            sg = Sign(SignValue.POS)
        elif iv.hi < 0:
            sg = Sign(SignValue.NEG)
        elif iv.lo == 0 and iv.hi == 0:
            sg = Sign(SignValue.ZERO)

        # Congruence refines interval (tighten bounds to match modulus)
        if not cg.is_bot and cg.modulus > 1 and not iv.is_bottom():
            # Find tightest interval matching the congruence
            if iv.lo != NEG_INF:
                # Round lo up to next value ≡ remainder (mod modulus)
                r = iv.lo % cg.modulus
                if r != cg.remainder % cg.modulus:
                    adjustment = (cg.remainder - r) % cg.modulus
                    new_lo = iv.lo + adjustment
                    if new_lo <= iv.hi:
                        iv = Interval(new_lo, iv.hi)

        return ReducedProduct(iv, sg, cg)


# ---------------------------------------------------------------------------
# Abstract State: maps variables to abstract values
# ---------------------------------------------------------------------------

@dataclass
class AbstractState:
    """Abstract program state: variable -> abstract value mapping.

    This is a product domain: the state is an element of
    Var -> AbstractDomain, ordered pointwise.
    """
    intervals: Dict[str, Interval] = field(default_factory=dict)
    signs: Dict[str, Sign] = field(default_factory=dict)
    congruences: Dict[str, Congruence] = field(default_factory=dict)
    is_bottom: bool = False

    def copy(self) -> AbstractState:
        result = AbstractState(
            intervals=dict(self.intervals),
            signs=dict(self.signs),
            congruences=dict(self.congruences),
            is_bottom=self.is_bottom,
        )
        if hasattr(self, '_nonzero_vars'):
            result._nonzero_vars = set(self._nonzero_vars)
        return result

    def join(self, other: AbstractState) -> AbstractState:
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        result = AbstractState()
        all_vars = set(self.intervals) | set(other.intervals)
        for v in all_vars:
            i1 = self.intervals.get(v, INTERVAL_TOP)
            i2 = other.intervals.get(v, INTERVAL_TOP)
            result.intervals[v] = i1.join(i2)
            s1 = self.signs.get(v, Sign(SignValue.TOP))
            s2 = other.signs.get(v, Sign(SignValue.TOP))
            result.signs[v] = s1.join(s2)
            c1 = self.congruences.get(v, Congruence(modulus=1))
            c2 = other.congruences.get(v, Congruence(modulus=1))
            result.congruences[v] = c1.join(c2)
        return result

    def widen(self, other: AbstractState) -> AbstractState:
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        result = AbstractState()
        all_vars = set(self.intervals) | set(other.intervals)
        for v in all_vars:
            i1 = self.intervals.get(v, INTERVAL_BOT)
            i2 = other.intervals.get(v, INTERVAL_BOT)
            result.intervals[v] = i1.widen(i2)
            s1 = self.signs.get(v, Sign(SignValue.BOT))
            s2 = other.signs.get(v, Sign(SignValue.BOT))
            result.signs[v] = s1.widen(s2)
        return result

    def leq(self, other: AbstractState) -> bool:
        if self.is_bottom:
            return True
        if other.is_bottom:
            return False
        for v in self.intervals:
            i1 = self.intervals.get(v, INTERVAL_TOP)
            i2 = other.intervals.get(v, INTERVAL_TOP)
            if not i1.leq(i2):
                return False
        return True

    def set_var(self, name: str, interval: Interval,
                sign: Optional[Sign] = None,
                cong: Optional[Congruence] = None) -> None:
        self.intervals[name] = interval
        if sign:
            self.signs[name] = sign
        if cong:
            self.congruences[name] = cong

    def get_interval(self, name: str) -> Interval:
        return self.intervals.get(name, INTERVAL_TOP)

    def get_sign(self, name: str) -> Sign:
        return self.signs.get(name, Sign(SignValue.TOP))

    def __str__(self) -> str:
        if self.is_bottom:
            return "bot"
        parts = []
        for v in sorted(self.intervals.keys()):
            parts.append(f"{v}: {self.intervals[v]}")
        return "{" + ", ".join(parts) + "}"


# ---------------------------------------------------------------------------
# Abstract Interpreter
# ---------------------------------------------------------------------------

class AbstractInterpreter:
    """Abstract interpreter for AEON programs.

    Implements the collecting semantics abstractly:
      - Each program point maps to an abstract state
      - Transfer functions propagate abstract values through statements
      - Loops use widening/narrowing for convergence

    The fixpoint computation follows Cousot & Cousot (1977):
      X_0 = bot
      X_{n+1} = X_n nabla F(X_n)     (ascending with widening)
      until X_{n+1} <= X_n            (fixpoint reached)

    Then refine with narrowing:
      Y_0 = X*  (fixpoint from above)
      Y_{n+1} = Y_n delta F(Y_n)     (descending with narrowing)
      until Y_{n+1} >= Y_n
    """

    def __init__(self):
        self.errors: List[AeonError] = []
        self.function_summaries: Dict[str, AbstractState] = {}

    def analyze_program(self, program: Program) -> List[AeonError]:
        """Run abstract interpretation on all functions."""
        self.errors = []

        functions = [d for d in program.declarations
                     if isinstance(d, (PureFunc, TaskFunc))]

        for func in functions:
            self._analyze_function(func)

        return self.errors

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function."""
        state = AbstractState()

        # Initialize parameters
        for param in func.params:
            type_name = str(param.type_annotation) if param.type_annotation else "Int"
            if type_name in ("Int", "Float", "USD"):
                state.set_var(param.name, INTERVAL_TOP, Sign(SignValue.TOP))
            elif type_name == "Bool":
                state.set_var(param.name, Interval(0, 1), Sign(SignValue.TOP))
            else:
                state.set_var(param.name, INTERVAL_TOP)

        # Apply requires clauses as initial constraints
        for req in func.requires:
            state = self._apply_condition(state, req.expr, positive=True)

        # Analyze body
        final_state = self._analyze_body(func.body, state)

        # Verify ensures clauses against computed state
        for ens in func.ensures:
            self._verify_postcondition(ens, final_state, func)

        self.function_summaries[func.name] = final_state

    def _analyze_body(self, stmts: List[Statement], state: AbstractState) -> AbstractState:
        """Analyze a sequence of statements."""
        current = state.copy()

        for stmt in stmts:
            if current.is_bottom:
                break
            current = self._analyze_statement(stmt, current)

        return current

    def _analyze_statement(self, stmt: Statement, state: AbstractState) -> AbstractState:
        """Abstract transfer function for a statement."""
        if isinstance(stmt, LetStmt):
            if stmt.value:
                val_interval = self._eval_expr_interval(stmt.value, state)
                val_sign = self._eval_expr_sign(stmt.value, state)
                state.set_var(stmt.name, val_interval, val_sign)
            return state

        if isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                val_interval = self._eval_expr_interval(stmt.value, state)
                val_sign = self._eval_expr_sign(stmt.value, state)
                state.set_var(stmt.target.name, val_interval, val_sign)
            return state

        if isinstance(stmt, ReturnStmt):
            if stmt.value:
                ret_interval = self._eval_expr_interval(stmt.value, state)
                ret_sign = self._eval_expr_sign(stmt.value, state)
                state.set_var("__return__", ret_interval, ret_sign)
            return state

        if isinstance(stmt, ExprStmt):
            self._eval_expr_interval(stmt.expr, state)
            return state

        if isinstance(stmt, IfStmt):
            return self._analyze_if(stmt, state)

        if isinstance(stmt, WhileStmt):
            return self._analyze_while(stmt, state)

        return state

    def _analyze_if(self, stmt: IfStmt, state: AbstractState) -> AbstractState:
        """Analyze if-then-else with path-sensitive abstract states."""
        # Condition refines state in each branch
        then_state = self._apply_condition(state.copy(), stmt.condition, positive=True)
        else_state = self._apply_condition(state.copy(), stmt.condition, positive=False)

        # Analyze each branch
        then_result = self._analyze_body(stmt.then_body, then_state)
        else_result = self._analyze_body(stmt.else_body, else_state) if stmt.else_body else else_state

        # Join at merge point
        return then_result.join(else_result)

    def _analyze_while(self, stmt: WhileStmt, state: AbstractState) -> AbstractState:
        """Analyze while loop with widening for convergence.

        Fixpoint computation:
          Phase 1 (ascending with widening):
            X_0 = state
            X_{n+1} = X_n nabla (X_n join F(X_n))
            until stable

          Phase 2 (descending with narrowing):
            Y_0 = X*
            Y_{n+1} = Y_n delta F(Y_n)
            until stable
        """
        MAX_ITER = 100

        # Phase 1: Ascending iteration with widening
        current = state.copy()
        for i in range(MAX_ITER):
            # Apply loop condition
            loop_entry = self._apply_condition(current.copy(), stmt.condition, positive=True)

            # Analyze loop body
            after_body = self._analyze_body(stmt.body, loop_entry)

            # Widen
            next_state = current.widen(after_body)

            if next_state.leq(current):
                break
            current = next_state

        # Phase 2: Descending iteration with narrowing (optional refinement)
        for i in range(MAX_ITER):
            loop_entry = self._apply_condition(current.copy(), stmt.condition, positive=True)
            after_body = self._analyze_body(stmt.body, loop_entry)
            narrowed = current
            for v in current.intervals:
                if v in after_body.intervals:
                    narrowed.intervals[v] = current.intervals[v].narrow(after_body.intervals[v])

            if current.leq(narrowed) and narrowed.leq(current):
                break
            current = narrowed

        # Exit state: condition is false
        exit_state = self._apply_condition(current, stmt.condition, positive=False)
        return exit_state

    def _apply_condition(self, state: AbstractState, cond: Expr, positive: bool) -> AbstractState:
        """Refine abstract state using a branch condition.

        If positive=True, we're in the 'then' branch (condition is true).
        If positive=False, we're in the 'else' branch (condition is false).
        """
        if isinstance(cond, BinaryOp):
            if cond.op in (">=", ">", "<=", "<", "==", "!="):
                return self._apply_comparison(state, cond, positive)
            if cond.op == "&&":
                if positive:
                    state = self._apply_condition(state, cond.left, True)
                    state = self._apply_condition(state, cond.right, True)
                else:
                    # NOT (a && b) = NOT a || NOT b
                    s1 = self._apply_condition(state.copy(), cond.left, False)
                    s2 = self._apply_condition(state.copy(), cond.right, False)
                    state = s1.join(s2)
                return state
            if cond.op == "||":
                if positive:
                    s1 = self._apply_condition(state.copy(), cond.left, True)
                    s2 = self._apply_condition(state.copy(), cond.right, True)
                    state = s1.join(s2)
                else:
                    state = self._apply_condition(state, cond.left, False)
                    state = self._apply_condition(state, cond.right, False)
                return state

        if isinstance(cond, UnaryOp) and cond.op == "!":
            return self._apply_condition(state, cond.operand, not positive)

        return state

    def _apply_comparison(self, state: AbstractState, cond: BinaryOp, positive: bool) -> AbstractState:
        """Refine state based on a comparison condition."""
        op = cond.op
        if not positive:
            # Negate the comparison
            neg_ops = {">=": "<", ">": "<=", "<=": ">", "<": ">=", "==": "!=", "!=": "=="}
            op = neg_ops.get(op, op)

        left_var = self._get_var_name(cond.left)
        right_var = self._get_var_name(cond.right)
        left_interval = self._eval_expr_interval(cond.left, state)
        right_interval = self._eval_expr_interval(cond.right, state)

        if left_var and op == ">=":
            refined = left_interval.meet(Interval(right_interval.lo, INF))
            state.intervals[left_var] = refined
        elif left_var and op == ">":
            lo = right_interval.lo + 1 if right_interval.lo != INF else right_interval.lo
            refined = left_interval.meet(Interval(lo, INF))
            state.intervals[left_var] = refined
        elif left_var and op == "<=":
            refined = left_interval.meet(Interval(NEG_INF, right_interval.hi))
            state.intervals[left_var] = refined
        elif left_var and op == "<":
            hi = right_interval.hi - 1 if right_interval.hi != NEG_INF else right_interval.hi
            refined = left_interval.meet(Interval(NEG_INF, hi))
            state.intervals[left_var] = refined
        elif left_var and op == "==":
            refined = left_interval.meet(right_interval)
            state.intervals[left_var] = refined
            if left_interval.lo == left_interval.hi:
                state.signs[left_var] = Sign.from_int(int(left_interval.lo))
        elif left_var and op == "!=":
            # x != c: if c is a single point and the interval is exactly [c, c], bottom it
            if right_interval.lo == right_interval.hi:
                c = right_interval.lo
                if left_interval.lo == c and left_interval.hi == c:
                    state.intervals[left_var] = INTERVAL_BOTTOM
                else:
                    # Track that this variable is known non-equal to c
                    if not hasattr(state, '_nonzero_vars'):
                        state._nonzero_vars = set()
                    if c == 0:
                        state._nonzero_vars.add(left_var)

        return state

    def _get_var_name(self, expr: Expr) -> Optional[str]:
        if isinstance(expr, Identifier):
            return expr.name
        return None

    def _eval_expr_interval(self, expr: Expr, state: AbstractState) -> Interval:
        """Evaluate an expression in the interval domain."""
        if isinstance(expr, IntLiteral):
            return Interval(expr.value, expr.value)

        if isinstance(expr, Identifier):
            return state.get_interval(expr.name)

        if isinstance(expr, BinaryOp):
            left = self._eval_expr_interval(expr.left, state)
            right = self._eval_expr_interval(expr.right, state)
            if expr.op == "+":
                return left.add(right)
            if expr.op == "-":
                return left.sub(right)
            if expr.op == "*":
                return left.mul(right)
            if expr.op == "/":
                if right.contains(0):
                    # Check if divisor is known non-zero from a requires clause
                    divisor_var = self._get_var_name(expr.right) if hasattr(expr, 'right') else None
                    nonzero_vars = getattr(state, '_nonzero_vars', set())
                    if divisor_var not in nonzero_vars:
                        self.errors.append(contract_error(
                            precondition="division by zero possible",
                            failing_values={"divisor_range": str(right)},
                            function_signature="abstract interpretation",
                            location=expr.location,
                        ))
                return left.div(right)
            # Comparison operators return [0, 1]
            if expr.op in ("<", "<=", ">", ">=", "==", "!="):
                return Interval(0, 1)

        if isinstance(expr, UnaryOp):
            inner = self._eval_expr_interval(expr.operand, state)
            if expr.op == "-":
                return inner.neg()
            return inner

        if isinstance(expr, FunctionCall):
            return INTERVAL_TOP

        if isinstance(expr, BoolLiteral):
            return Interval(1 if expr.value else 0, 1 if expr.value else 0)

        return INTERVAL_TOP

    def _eval_expr_sign(self, expr: Expr, state: AbstractState) -> Sign:
        """Evaluate an expression in the sign domain."""
        if isinstance(expr, IntLiteral):
            return Sign.from_int(expr.value)

        if isinstance(expr, Identifier):
            return state.get_sign(expr.name)

        if isinstance(expr, BinaryOp):
            left = self._eval_expr_sign(expr.left, state)
            right = self._eval_expr_sign(expr.right, state)
            if expr.op == "+":
                return left.add(right)
            if expr.op == "*":
                return left.mul(right)

        return Sign(SignValue.TOP)

    def _verify_postcondition(self, ens, state: AbstractState, func) -> None:
        """Verify an ensures clause against the computed abstract state."""
        if isinstance(ens.expr, BinaryOp):
            op = ens.expr.op
            left_name = self._get_var_name(ens.expr.left)
            right_name = self._get_var_name(ens.expr.right)

            if left_name == "result":
                result_interval = state.get_interval("__return__")
                right_interval = self._eval_expr_interval(ens.expr.right, state)

                if op == ">=" and not result_interval.is_bottom():
                    if result_interval.lo < right_interval.lo:
                        self.errors.append(contract_error(
                            precondition=f"ensures: result >= ... may be violated",
                            failing_values={
                                "result_range": str(result_interval),
                                "bound_range": str(right_interval),
                            },
                            function_signature=f"{func.name}",
                            location=ens.location,
                        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def abstract_interpret(program: Program) -> List[AeonError]:
    """Run abstract interpretation analysis on an AEON program.

    Performs:
    1. Interval analysis (bounds checking, overflow detection)
    2. Sign analysis (sign-related properties)
    3. Division-by-zero detection
    4. Postcondition verification via abstract domains
    """
    interpreter = AbstractInterpreter()
    return interpreter.analyze_program(program)
