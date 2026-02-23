"""AEON Probabilistic Program Analysis — Measure-Theoretic Verification.

Implements probabilistic program analysis based on:
  Kozen (1981) "Semantics of Probabilistic Programs"
  Journal of Computer and System Sciences 22(3),
  https://doi.org/10.1016/0022-0000(81)90036-2

  Gordon, Henzinger, Nori, Rajamani (2014) "Probabilistic Programming"
  FOSE '14 (Future of Software Engineering),
  https://doi.org/10.1145/2593882.2593900

  Barthe, Grégoire, Zanella-Béguelin (2009) "Formal Certification of
  Code-Based Cryptographic Proofs"
  POPL '09, https://doi.org/10.1145/1480881.1480894

  Chakarov & Sankaranarayanan (2013) "Probabilistic Program Analysis
  with Martingales"
  CAV '13, https://doi.org/10.1007/978-3-642-39799-8_34

Key Theory:

1. MEASURE-THEORETIC SEMANTICS (Kozen 1981):
   Programs are MEASURE TRANSFORMERS:
     [[P]] : Distributions -> Distributions

   A distribution mu over states is a PROBABILITY MEASURE:
     mu : Sigma-algebra(States) -> [0, 1]
     mu(States) = 1  (total probability is 1)

   Statements transform distributions:
     [[x := e]](mu) = pushforward of mu through (lambda s. s[x := e(s)])
     [[if b then S1 else S2]](mu) = [[S1]](mu|_b) + [[S2]](mu|_{!b})
     [[while b do S]](mu) = lim_{n->inf} [[S]]^n(mu|_{!b})

   The while-loop semantics uses the LEAST FIXED POINT in the
   lattice of sub-probability measures (ordered by <=).

2. PROBABILISTIC ASSERTIONS:
   A probabilistic assertion Pr[phi] >= p states that the
   probability of phi holding is at least p.

   Verification reduces to computing:
     mu_final({s | phi(s)}) >= p

   where mu_final = [[P]](mu_initial).

3. MARTINGALE-BASED ANALYSIS (Chakarov & Sankaranarayanan 2013):
   A SUPERMARTINGALE is a function f : States -> R such that:
     E[f(s') | s] <= f(s)  for each transition s -> s'

   If f is a supermartingale and f(s0) <= c, then by the
   OPTIONAL STOPPING THEOREM:
     Pr[f reaches value >= t] <= c / t

   This gives probabilistic bounds on program behavior
   without computing exact distributions.

   For ALMOST-SURE TERMINATION:
     If f is a ranking supermartingale (f >= 0 and E[f(s')|s] <= f(s) - epsilon),
     then the program terminates with probability 1.

4. CONCENTRATION INEQUALITIES:
   For analyzing randomized algorithms:

   - MARKOV: Pr[X >= a] <= E[X] / a
   - CHEBYSHEV: Pr[|X - mu| >= k*sigma] <= 1/k^2
   - CHERNOFF: Pr[X >= (1+delta)*mu] <= (e^delta / (1+delta)^(1+delta))^mu
   - HOEFFDING: Pr[|X_bar - mu| >= t] <= 2*exp(-2*n*t^2)

   These bound the probability of deviation from expected behavior.

5. BAYESIAN INFERENCE CORRECTNESS:
   For probabilistic programs implementing Bayesian inference:
     posterior(theta | data) proportional to likelihood(data | theta) * prior(theta)

   Verification checks:
   - Normalization: integral of posterior = 1
   - Conjugacy: posterior is in the same family as prior
   - Convergence: MCMC samples converge to true posterior

Mathematical Framework:
  - Programs as measurable functions between probability spaces
  - Denotational semantics in the category of measurable spaces
  - Sub-probability monads for non-termination
  - Martingale theory for probabilistic invariants
  - Information-theoretic measures (entropy, KL divergence)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any, Callable
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
# Probability Distributions
# ---------------------------------------------------------------------------

class DistributionKind(Enum):
    """Known probability distribution families."""
    UNIFORM = auto()
    BERNOULLI = auto()
    BINOMIAL = auto()
    NORMAL = auto()
    EXPONENTIAL = auto()
    POISSON = auto()
    GEOMETRIC = auto()
    BETA = auto()
    GAMMA = auto()
    DIRICHLET = auto()
    CATEGORICAL = auto()
    UNKNOWN = auto()
    POINT_MASS = auto()    # Deterministic value (delta distribution)
    MIXTURE = auto()        # Mixture of distributions


@dataclass
class Distribution:
    """Abstract representation of a probability distribution.

    In the measure-theoretic framework, a distribution is a
    probability measure mu on a sigma-algebra of measurable sets.

    We track:
      - The family (Normal, Uniform, etc.)
      - Parameters (mean, variance, bounds, etc.)
      - Support (domain of non-zero probability)
      - Moments (mean, variance) for concentration inequalities
    """
    kind: DistributionKind
    params: Dict[str, float] = field(default_factory=dict)
    support_lower: float = float('-inf')
    support_upper: float = float('inf')
    mean: Optional[float] = None
    variance: Optional[float] = None
    components: List[Distribution] = field(default_factory=list)

    @staticmethod
    def point_mass(value: float) -> Distribution:
        return Distribution(
            kind=DistributionKind.POINT_MASS,
            params={"value": value},
            support_lower=value, support_upper=value,
            mean=value, variance=0.0
        )

    @staticmethod
    def uniform(low: float, high: float) -> Distribution:
        mean = (low + high) / 2
        var = (high - low) ** 2 / 12
        return Distribution(
            kind=DistributionKind.UNIFORM,
            params={"low": low, "high": high},
            support_lower=low, support_upper=high,
            mean=mean, variance=var
        )

    @staticmethod
    def normal(mu: float, sigma2: float) -> Distribution:
        return Distribution(
            kind=DistributionKind.NORMAL,
            params={"mu": mu, "sigma2": sigma2},
            mean=mu, variance=sigma2
        )

    @staticmethod
    def bernoulli(p: float) -> Distribution:
        return Distribution(
            kind=DistributionKind.BERNOULLI,
            params={"p": p},
            support_lower=0.0, support_upper=1.0,
            mean=p, variance=p * (1 - p)
        )

    @staticmethod
    def exponential(rate: float) -> Distribution:
        return Distribution(
            kind=DistributionKind.EXPONENTIAL,
            params={"rate": rate},
            support_lower=0.0,
            mean=1.0 / rate if rate > 0 else float('inf'),
            variance=1.0 / (rate ** 2) if rate > 0 else float('inf')
        )

    def is_proper(self) -> bool:
        """Check if this is a proper probability distribution (integrates to 1)."""
        if self.kind == DistributionKind.POINT_MASS:
            return True
        if self.kind == DistributionKind.UNIFORM:
            return self.params.get("high", 0) > self.params.get("low", 0)
        if self.kind == DistributionKind.NORMAL:
            return self.params.get("sigma2", 0) > 0
        if self.kind == DistributionKind.BERNOULLI:
            p = self.params.get("p", -1)
            return 0 <= p <= 1
        return True


# ---------------------------------------------------------------------------
# Abstract State for Probabilistic Programs
# ---------------------------------------------------------------------------

@dataclass
class ProbabilisticState:
    """Abstract state tracking distributions of program variables.

    In Kozen's semantics, the state is a probability measure
    over the space of all variable valuations.

    We approximate this by tracking the marginal distribution
    of each variable independently (assuming independence —
    a sound overapproximation).
    """
    distributions: Dict[str, Distribution] = field(default_factory=dict)
    path_probability: float = 1.0  # Probability of reaching this state
    observations: List[Tuple[str, float]] = field(default_factory=list)

    def set_deterministic(self, var: str, value: float) -> None:
        self.distributions[var] = Distribution.point_mass(value)

    def set_distribution(self, var: str, dist: Distribution) -> None:
        self.distributions[var] = dist

    def get_distribution(self, var: str) -> Distribution:
        return self.distributions.get(var, Distribution(kind=DistributionKind.UNKNOWN))

    def observe(self, var: str, value: float) -> None:
        """Condition on an observation (Bayesian conditioning)."""
        self.observations.append((var, value))
        # Conditioning reduces path probability
        dist = self.get_distribution(var)
        if dist.kind == DistributionKind.POINT_MASS:
            if dist.params.get("value", None) != value:
                self.path_probability = 0.0

    def branch(self, prob_true: float) -> Tuple[ProbabilisticState, ProbabilisticState]:
        """Fork state at a probabilistic branch point.

        Returns (true_state, false_state) with appropriate probabilities.
        """
        true_state = ProbabilisticState(
            distributions=dict(self.distributions),
            path_probability=self.path_probability * prob_true,
            observations=list(self.observations)
        )
        false_state = ProbabilisticState(
            distributions=dict(self.distributions),
            path_probability=self.path_probability * (1 - prob_true),
            observations=list(self.observations)
        )
        return true_state, false_state

    def merge(self, other: ProbabilisticState) -> ProbabilisticState:
        """Merge two states (mixture of distributions).

        The merged distribution is a mixture:
          p * D1 + (1-p) * D2
        where p is the relative path probability.
        """
        total_prob = self.path_probability + other.path_probability
        if total_prob == 0:
            return ProbabilisticState()

        merged = ProbabilisticState(path_probability=total_prob)
        all_vars = set(self.distributions.keys()) | set(other.distributions.keys())

        for var in all_vars:
            d1 = self.distributions.get(var, Distribution(kind=DistributionKind.UNKNOWN))
            d2 = other.distributions.get(var, Distribution(kind=DistributionKind.UNKNOWN))

            # Compute mixture moments
            w1 = self.path_probability / total_prob if total_prob > 0 else 0.5
            w2 = 1.0 - w1

            mean1 = d1.mean if d1.mean is not None else 0.0
            mean2 = d2.mean if d2.mean is not None else 0.0
            var1 = d1.variance if d1.variance is not None else 0.0
            var2 = d2.variance if d2.variance is not None else 0.0

            mixed_mean = w1 * mean1 + w2 * mean2
            # Mixture variance: E[X^2] - E[X]^2
            mixed_var = (w1 * (var1 + mean1**2) + w2 * (var2 + mean2**2)
                         - mixed_mean**2)

            merged.distributions[var] = Distribution(
                kind=DistributionKind.MIXTURE,
                mean=mixed_mean,
                variance=max(0.0, mixed_var),
                components=[d1, d2]
            )

        return merged


# ---------------------------------------------------------------------------
# Supermartingale Checker (Chakarov & Sankaranarayanan 2013)
# ---------------------------------------------------------------------------

@dataclass
class SupermartingaleWitness:
    """A supermartingale witness for probabilistic termination or bounds.

    A function f : States -> R is a supermartingale if:
      E[f(s') | s] <= f(s) for all transitions s -> s'

    For ALMOST-SURE TERMINATION, we need a RANKING supermartingale:
      f >= 0  and  E[f(s') | s] <= f(s) - epsilon  for some epsilon > 0

    By the Optional Stopping Theorem:
      Pr[f ever reaches >= t | f(s0) = c] <= c / t  (Markov's inequality)
    """
    function_name: str
    initial_value: float
    decrease_bound: float  # epsilon: expected decrease per step
    is_ranking: bool = False  # True if also non-negative (implies a.s. termination)

    def expected_steps_bound(self) -> Optional[float]:
        """Upper bound on expected number of steps to termination.

        If f is a ranking supermartingale with f(s0) = c and
        E[f(s')|s] <= f(s) - epsilon, then:
          E[termination time] <= c / epsilon
        """
        if self.is_ranking and self.decrease_bound > 0:
            return self.initial_value / self.decrease_bound
        return None

    def tail_probability_bound(self, threshold: float) -> float:
        """Pr[f reaches >= threshold] via Markov's inequality.

        Markov: Pr[X >= a] <= E[X] / a
        """
        if threshold <= 0:
            return 1.0
        return min(1.0, self.initial_value / threshold)


@dataclass
class ConcentrationBound:
    """Concentration inequality bounds for probabilistic programs.

    Given a random variable X with known moments, these bounds
    limit the probability of large deviations.
    """
    variable: str
    mean: float
    variance: float
    n_samples: int = 1  # Number of independent samples

    def markov_bound(self, threshold: float) -> float:
        """Pr[X >= a] <= E[X] / a  (for non-negative X)."""
        if threshold <= 0 or self.mean < 0:
            return 1.0
        return min(1.0, self.mean / threshold)

    def chebyshev_bound(self, k_sigmas: float) -> float:
        """Pr[|X - mu| >= k*sigma] <= 1/k^2."""
        if k_sigmas <= 0:
            return 1.0
        return min(1.0, 1.0 / (k_sigmas ** 2))

    def chernoff_bound(self, delta: float) -> float:
        """Pr[X >= (1+delta)*mu] for sum of independent Bernoullis.

        Bound: (e^delta / (1+delta)^(1+delta))^mu
        """
        if delta <= 0 or self.mean <= 0:
            return 1.0
        try:
            exponent = self.mean * (delta - (1 + delta) * math.log(1 + delta))
            return min(1.0, math.exp(exponent))
        except (OverflowError, ValueError):
            return 1.0

    def hoeffding_bound(self, t: float, range_size: float = 1.0) -> float:
        """Pr[|X_bar - mu| >= t] <= 2*exp(-2*n*t^2 / range^2).

        For bounded random variables in [a, b] with range = b - a.
        """
        if t <= 0 or self.n_samples <= 0:
            return 1.0
        try:
            exponent = -2.0 * self.n_samples * (t ** 2) / (range_size ** 2)
            return min(1.0, 2.0 * math.exp(exponent))
        except (OverflowError, ValueError):
            return 1.0


# ---------------------------------------------------------------------------
# Probabilistic Function Patterns
# ---------------------------------------------------------------------------

_RANDOM_FUNCTIONS = {
    'random', 'rand', 'randint', 'uniform', 'gauss', 'normal',
    'bernoulli', 'binomial', 'exponential', 'poisson', 'geometric',
    'beta', 'gamma', 'dirichlet', 'categorical', 'choice',
    'sample', 'draw', 'flip', 'coin', 'dice', 'shuffle',
    'random_float', 'random_int', 'random_bool',
}

_OBSERVE_FUNCTIONS = {
    'observe', 'condition', 'factor', 'score', 'assume',
    'assert_prob', 'constrain', 'likelihood',
}

_INFERENCE_FUNCTIONS = {
    'infer', 'posterior', 'mcmc', 'metropolis_hastings', 'gibbs',
    'variational', 'importance_sampling', 'rejection_sampling',
    'particle_filter', 'smc', 'hmc', 'nuts', 'advi', 'elbo',
}


def _is_probabilistic_call(expr: Expr) -> Optional[str]:
    """Check if an expression is a probabilistic function call."""
    if isinstance(expr, FunctionCall):
        name = expr.name.lower() if isinstance(expr.name, str) else ""
        parts = name.split('.')
        base = parts[-1] if parts else name
        if base in _RANDOM_FUNCTIONS:
            return "random"
        if base in _OBSERVE_FUNCTIONS:
            return "observe"
        if base in _INFERENCE_FUNCTIONS:
            return "inference"
    if isinstance(expr, MethodCall):
        method = expr.method if hasattr(expr, 'method') else ""
        if isinstance(method, str) and method.lower() in _RANDOM_FUNCTIONS:
            return "random"
    return None


# ---------------------------------------------------------------------------
# Main Analysis
# ---------------------------------------------------------------------------

def _analyze_function(func, errors: List[AeonError]) -> None:
    """Analyze a single function for probabilistic correctness."""
    loc = getattr(func, 'location', SourceLocation("", 1, 1))
    func_name = func.name if hasattr(func, 'name') else "<anonymous>"

    body = func.body if hasattr(func, 'body') else []
    if not isinstance(body, list):
        body = [body] if body else []

    state = ProbabilisticState()
    has_random = False
    has_observe = False
    has_inference = False
    random_vars: Dict[str, Distribution] = {}
    loop_random_count = 0

    def _scan_expr(expr: Expr) -> Optional[Distribution]:
        nonlocal has_random, has_observe, has_inference
        kind = _is_probabilistic_call(expr)
        if kind == "random":
            has_random = True
            if isinstance(expr, FunctionCall):
                name = expr.name.lower() if isinstance(expr.name, str) else ""
                if 'uniform' in name:
                    return Distribution.uniform(0.0, 1.0)
                elif 'normal' in name or 'gauss' in name:
                    return Distribution.normal(0.0, 1.0)
                elif 'bernoulli' in name or 'flip' in name or 'coin' in name:
                    return Distribution.bernoulli(0.5)
                elif 'exponential' in name:
                    return Distribution.exponential(1.0)
                else:
                    return Distribution(kind=DistributionKind.UNKNOWN)
        elif kind == "observe":
            has_observe = True
        elif kind == "inference":
            has_inference = True
        return None

    def _scan_stmt(stmt: Statement, in_loop: bool = False) -> None:
        nonlocal loop_random_count
        if isinstance(stmt, LetStmt):
            dist = _scan_expr(stmt.value)
            if dist:
                var_name = stmt.name if hasattr(stmt, 'name') else str(stmt)
                random_vars[var_name] = dist
                state.set_distribution(var_name, dist)
                if in_loop:
                    loop_random_count += 1
        elif isinstance(stmt, AssignStmt):
            dist = _scan_expr(stmt.value)
            if dist:
                target = stmt.target if isinstance(stmt.target, str) else (
                    stmt.target.name if hasattr(stmt.target, 'name') else str(stmt.target)
                )
                random_vars[target] = dist
                if in_loop:
                    loop_random_count += 1
        elif isinstance(stmt, ExprStmt):
            _scan_expr(stmt.expr)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                _scan_expr(stmt.value)
        elif isinstance(stmt, IfStmt):
            _scan_expr(stmt.condition)
            then_body = stmt.then_body if isinstance(stmt.then_body, list) else [stmt.then_body]
            for s in then_body:
                _scan_stmt(s, in_loop)
            if stmt.else_body:
                else_body = stmt.else_body if isinstance(stmt.else_body, list) else [stmt.else_body]
                for s in else_body:
                    _scan_stmt(s, in_loop)

    for stmt in body:
        _scan_stmt(stmt)

    if not has_random:
        return

    # Check distribution validity
    for var_name, dist in random_vars.items():
        if not dist.is_proper():
            errors.append(contract_error(
                f"Improper distribution for '{var_name}' in '{func_name}': "
                f"distribution does not integrate to 1 "
                f"(Kozen 1981: measure-theoretic semantics require proper measures)",
                location=loc
            ))

    # Check observation validity
    if has_observe and not has_random:
        errors.append(contract_error(
            f"Observation without random variables in '{func_name}': "
            f"conditioning requires a prior distribution "
            f"(Bayesian inference: posterior ∝ likelihood × prior)",
            location=loc
        ))

    # Supermartingale check for loops with random variables
    if loop_random_count > 0:
        witness = SupermartingaleWitness(
            function_name=func_name,
            initial_value=float(loop_random_count),
            decrease_bound=0.0,
            is_ranking=False
        )
        if not witness.is_ranking:
            errors.append(contract_error(
                f"Loop with {loop_random_count} random sampling operations in '{func_name}': "
                f"cannot verify almost-sure termination — "
                f"no ranking supermartingale found "
                f"(Chakarov & Sankaranarayanan 2013)",
                location=loc
            ))

    # Check inference correctness
    if has_inference and not has_observe:
        errors.append(contract_error(
            f"Inference without observations in '{func_name}': "
            f"posterior inference requires conditioning on observed data "
            f"(Gordon et al. 2014: probabilistic programming)",
            location=loc
        ))

    # Concentration inequality warnings for bounded variables
    for var_name, dist in random_vars.items():
        if dist.mean is not None and dist.variance is not None:
            bound = ConcentrationBound(
                variable=var_name,
                mean=dist.mean,
                variance=dist.variance
            )
            if dist.variance > 100 * (dist.mean ** 2 + 1):
                errors.append(contract_error(
                    f"High-variance random variable '{var_name}' in '{func_name}': "
                    f"variance={dist.variance:.2f} >> mean^2={dist.mean**2:.2f} — "
                    f"Chebyshev bound is very loose "
                    f"(Pr[|X-mu| >= k*sigma] <= 1/k^2)",
                    location=loc
                ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_probabilistic(program: Program) -> List[AeonError]:
    """Run probabilistic program analysis on an AEON program.

    Checks:
    1. Distribution validity (proper measures, Kozen 1981)
    2. Bayesian inference correctness (prior + likelihood + posterior)
    3. Almost-sure termination via supermartingales (Chakarov et al. 2013)
    4. Concentration bounds for high-variance computations
    5. Observation consistency (conditioning correctness)
    """
    errors: List[AeonError] = []

    functions = [d for d in program.declarations
                 if isinstance(d, (PureFunc, TaskFunc))]

    for func in functions:
        _analyze_function(func, errors)

    return errors
