"""AEON Verification Context — Inter-Engine Proof Sharing.

When multiple formal-methods engines run sequentially, each one independently
re-derives facts that earlier engines have already proved.  This module
provides a shared context object that accumulates *proven facts* so that
later engines can use them as additional hypotheses, improving both
precision and performance.

Example
-------
Abstract interpretation proves that variable ``x`` is always in [1, +∞).
The Hoare-logic engine can then assume ``x > 0`` without re-deriving it,
allowing it to discharge more verification conditions.

Design
------
The context is a lightweight, append-only store of:

1. **Interval facts** — ``{var: Interval}`` from abstract interpretation.
2. **Sign facts**     — ``{var: SignValue}`` from abstract interpretation.
3. **Nonzero vars**  — set of variables proven ≠ 0 (from any engine).
4. **Proved VCs**    — set of VC names already discharged (avoid re-checking).
5. **Proof obligations** — the full ``ProofTrace`` accumulated across all engines.
6. **Counterexample witnesses** — collected from all engines for ``--emit-witnesses``.

Thread safety: the context is designed for single-threaded sequential use
within one verification run.  For parallel scanning, each file gets its own
context instance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from aeon.proof_obligations import ProofObligation, ProofTrace, SolverResult


# ---------------------------------------------------------------------------
# Interval snapshot (avoids importing the full abstract_interp module here)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IntervalFact:
    """A proven interval bound on a variable: lo <= var <= hi."""
    var: str
    lo: float   # -inf represented as float('-inf')
    hi: float   # +inf represented as float('inf')

    def implies_nonzero(self) -> bool:
        return self.lo > 0 or self.hi < 0

    def implies_positive(self) -> bool:
        return self.lo > 0

    def implies_nonnegative(self) -> bool:
        return self.lo >= 0

    def to_smtlib2(self) -> str:
        parts = []
        if self.lo != float("-inf"):
            parts.append(f"(>= {self.var} {int(self.lo)})")
        if self.hi != float("inf"):
            parts.append(f"(<= {self.var} {int(self.hi)})")
        if not parts:
            return ""
        return "(and " + " ".join(parts) + ")" if len(parts) > 1 else parts[0]

    def to_human(self) -> str:
        lo_s = "-∞" if self.lo == float("-inf") else str(int(self.lo))
        hi_s = "+∞" if self.hi == float("inf") else str(int(self.hi))
        return f"{lo_s} ≤ {self.var} ≤ {hi_s}"


# ---------------------------------------------------------------------------
# Verification Context
# ---------------------------------------------------------------------------

class VerificationContext:
    """Shared proof context passed through all verification engines.

    Engines *read* previously proven facts to strengthen their own analysis,
    and *write* new facts they discover so subsequent engines benefit.

    Attributes
    ----------
    interval_facts : Dict[str, IntervalFact]
        Per-variable interval bounds proven by abstract interpretation.
    nonzero_vars : Set[str]
        Variables proven ≠ 0 by any engine.
    positive_vars : Set[str]
        Variables proven > 0 by any engine.
    nonneg_vars : Set[str]
        Variables proven ≥ 0 by any engine.
    proved_vcs : Set[str]
        VC names already discharged (skip re-checking).
    proof_trace : ProofTrace
        Accumulated proof obligations from all engines.
    witnesses : List[Dict[str, Any]]
        Counterexample witnesses collected from all engines.
    proven_termination : Set[str]
        Function names proven to terminate by size-change / Hoare.
    security_labels : Dict[str, str]
        Variable → security label (PUBLIC / SECRET / …) from info-flow.
    """

    def __init__(self, source_file: str = "") -> None:
        self.source_file = source_file
        self.interval_facts: Dict[str, IntervalFact] = {}
        self.nonzero_vars: Set[str] = set()
        self.positive_vars: Set[str] = set()
        self.nonneg_vars: Set[str] = set()
        self.proved_vcs: Set[str] = set()
        self.proof_trace: ProofTrace = ProofTrace(source_file=source_file)
        self.witnesses: List[Dict[str, Any]] = []
        self.proven_termination: Set[str] = set()
        self.security_labels: Dict[str, str] = {}
        # Per-function abstract states: func_name -> {var -> IntervalFact}
        self._function_intervals: Dict[str, Dict[str, IntervalFact]] = {}

    # ------------------------------------------------------------------
    # Writing facts (called by engines after they prove something)
    # ------------------------------------------------------------------

    def record_interval(self, var: str, lo: float, hi: float,
                        function: str = "") -> None:
        """Record a proven interval bound on a variable."""
        fact = IntervalFact(var=var, lo=lo, hi=hi)
        self.interval_facts[var] = fact
        if fact.implies_nonzero():
            self.nonzero_vars.add(var)
        if fact.implies_positive():
            self.positive_vars.add(var)
        if fact.implies_nonnegative():
            self.nonneg_vars.add(var)
        if function:
            self._function_intervals.setdefault(function, {})[var] = fact

    def record_nonzero(self, var: str) -> None:
        self.nonzero_vars.add(var)

    def record_positive(self, var: str) -> None:
        self.positive_vars.add(var)
        self.nonzero_vars.add(var)

    def record_nonneg(self, var: str) -> None:
        self.nonneg_vars.add(var)

    def mark_vc_proved(self, vc_name: str) -> None:
        self.proved_vcs.add(vc_name)

    def mark_termination_proved(self, function_name: str) -> None:
        self.proven_termination.add(function_name)

    def record_security_label(self, var: str, label: str) -> None:
        self.security_labels[var] = label

    def add_obligation(self, obligation: ProofObligation) -> None:
        self.proof_trace.add(obligation)

    def add_obligations(self, obligations: List[ProofObligation]) -> None:
        self.proof_trace.extend(obligations)

    def add_witness(self, engine: str, function: str, location: str,
                    vc: str, values: Dict[str, Any]) -> None:
        self.witnesses.append({
            "engine": engine,
            "function": function,
            "location": location,
            "vc": vc,
            "witness": values,
        })

    # ------------------------------------------------------------------
    # Reading facts (called by engines to strengthen their analysis)
    # ------------------------------------------------------------------

    def is_nonzero(self, var: str) -> bool:
        """Return True if any engine has proved var ≠ 0."""
        return var in self.nonzero_vars

    def is_positive(self, var: str) -> bool:
        """Return True if any engine has proved var > 0."""
        return var in self.positive_vars

    def is_nonneg(self, var: str) -> bool:
        """Return True if any engine has proved var ≥ 0."""
        return var in self.nonneg_vars

    def get_interval(self, var: str) -> Optional[IntervalFact]:
        return self.interval_facts.get(var)

    def get_function_intervals(self, function: str) -> Dict[str, IntervalFact]:
        return self._function_intervals.get(function, {})

    def vc_already_proved(self, vc_name: str) -> bool:
        return vc_name in self.proved_vcs

    def termination_proved(self, function_name: str) -> bool:
        return function_name in self.proven_termination

    def get_security_label(self, var: str) -> str:
        return self.security_labels.get(var, "PUBLIC")

    # ------------------------------------------------------------------
    # Hypothesis generation for downstream engines
    # ------------------------------------------------------------------

    def to_smtlib2_hypotheses(self, vars_of_interest: Optional[List[str]] = None) -> str:
        """Emit proven interval facts as SMTLIB2 assertions.

        These can be prepended to a solver query to give it the benefit
        of all facts proven by earlier engines.
        """
        lines = ["; Hypotheses from earlier verification engines"]
        targets = vars_of_interest or list(self.interval_facts.keys())
        for var in targets:
            fact = self.interval_facts.get(var)
            if fact:
                smt = fact.to_smtlib2()
                if smt:
                    lines.append(f"(assert {smt})  ; proven by abstract interpretation")
        for var in self.nonzero_vars:
            if var not in self.interval_facts:
                lines.append(f"(assert (distinct {var} 0))  ; proven nonzero")
        return "\n".join(lines)

    def summary(self) -> Dict[str, Any]:
        """Return a summary dict for reporting."""
        return {
            "interval_facts": {v: f.to_human() for v, f in self.interval_facts.items()},
            "nonzero_vars": sorted(self.nonzero_vars),
            "positive_vars": sorted(self.positive_vars),
            "nonneg_vars": sorted(self.nonneg_vars),
            "proved_vcs": sorted(self.proved_vcs),
            "proven_termination": sorted(self.proven_termination),
            "security_labels": self.security_labels,
            "proof_obligations": self.proof_trace.total,
            "obligations_proved": self.proof_trace.proved_count,
            "witnesses": len(self.witnesses),
        }
