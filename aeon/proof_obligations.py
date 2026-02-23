"""AEON Proof Obligations — Formal Verification Artifact Layer.

This module defines the data structures that capture the *proof artifacts*
produced by each formal-methods engine.  Rather than discarding intermediate
results after a pass/fail decision, AEON now preserves:

  1. The VERIFICATION CONDITION (VC) — the logical formula that must hold
     for the program to be correct at a given point.
  2. The SMTLIB2 QUERY — the exact string sent to Z3, so results are
     independently reproducible.
  3. The SOLVER RESPONSE — UNSAT (proved), SAT + model (counterexample),
     or UNKNOWN (timeout / resource limit).
  4. The PROOF RULE applied — the named theorem or inference rule that
     justified the VC generation (e.g., "wp-assignment", "Hoare-consequence",
     "Galois-soundness").
  5. The WITNESS — concrete input values that trigger a bug (when SAT).

Usage:
    from aeon.proof_obligations import ProofObligation, ProofTrace, SolverResult

    obligation = ProofObligation(
        engine="hoare",
        rule="wp-assignment",
        function_name="safe_divide",
        location=loc,
        vc_formula="b != 0 => (a / b) satisfies postcondition",
        smtlib2="(assert (not (=> (distinct b 0) true)))",
        result=SolverResult.UNSAT,
        explanation="Weakest precondition of assignment discharged by Z3.",
    )
    trace = ProofTrace()
    trace.add(obligation)
    print(trace.to_json())
    print(trace.to_ascii_table())
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Solver result enumeration
# ---------------------------------------------------------------------------

class SolverResult(str, Enum):
    """Outcome of an SMT / formal-methods query."""
    UNSAT = "UNSAT"          # Formula is unsatisfiable → property proved
    SAT = "SAT"              # Formula is satisfiable → counterexample found
    UNKNOWN = "UNKNOWN"      # Solver timed out or gave up
    SKIPPED = "SKIPPED"      # Engine disabled or Z3 unavailable
    ERROR = "ERROR"          # Internal engine error


# ---------------------------------------------------------------------------
# Core proof artifact
# ---------------------------------------------------------------------------

@dataclass
class ProofObligation:
    """A single formal verification obligation with its proof artifact.

    Attributes
    ----------
    engine : str
        Name of the analysis engine that generated this obligation
        (e.g., "hoare", "refinement_types", "symbolic_execution").
    rule : str
        The inference rule or theorem applied
        (e.g., "wp-assignment", "Hoare-consequence", "Galois-soundness",
        "CEGAR-fixpoint", "Ramsey-termination").
    function_name : str
        The function being verified.
    location : str
        Source location string "file:line:col".
    vc_formula : str
        Human-readable verification condition formula.
    smtlib2 : str
        The SMTLIB2 query string sent to Z3 (empty if Z3 unavailable).
    result : SolverResult
        Outcome of the solver query.
    witness : Dict[str, Any]
        Concrete variable assignments that satisfy the negated VC
        (i.e., trigger the bug).  Empty when result != SAT.
    explanation : str
        Plain-English explanation of what was checked and why.
    paper_ref : str
        Academic citation for the rule/theorem applied.
    proved : bool
        True iff the obligation was discharged (result == UNSAT).
    duration_ms : float
        Time taken by the solver in milliseconds.
    """
    engine: str
    rule: str
    function_name: str
    location: str
    vc_formula: str
    smtlib2: str = ""
    result: SolverResult = SolverResult.UNKNOWN
    witness: Dict[str, Any] = field(default_factory=dict)
    explanation: str = ""
    paper_ref: str = ""
    proved: bool = False
    duration_ms: float = 0.0

    def __post_init__(self) -> None:
        if self.result == SolverResult.UNSAT:
            self.proved = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["result"] = self.result.value
        return d

    def to_ascii(self) -> str:
        """Single-obligation ASCII summary for terminal output."""
        status = "✓ PROVED" if self.proved else ("✗ FAILED" if self.result == SolverResult.SAT else f"? {self.result.value}")
        lines = [
            f"  [{self.engine}] {status}",
            f"    Rule      : {self.rule}",
            f"    Function  : {self.function_name}  @{self.location}",
            f"    VC        : {self.vc_formula}",
        ]
        if self.explanation:
            lines.append(f"    Explain   : {textwrap.fill(self.explanation, width=72, subsequent_indent=' ' * 14)}")
        if self.paper_ref:
            lines.append(f"    Reference : {self.paper_ref}")
        if self.witness:
            lines.append(f"    Witness   : {json.dumps(self.witness)}")
        if self.smtlib2:
            lines.append(f"    SMTLIB2   : {self.smtlib2[:120]}{'…' if len(self.smtlib2) > 120 else ''}")
        if self.duration_ms:
            lines.append(f"    Solver ms : {self.duration_ms:.1f}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Proof trace — collection of obligations for one verification run
# ---------------------------------------------------------------------------

@dataclass
class ProofTrace:
    """Ordered collection of proof obligations from a verification run.

    Accumulates obligations from all engines and provides serialization
    to JSON, ASCII table, and SMTLIB2 bundle formats.
    """
    obligations: List[ProofObligation] = field(default_factory=list)
    source_file: str = ""
    aeon_version: str = "0.5.0"

    def add(self, obligation: ProofObligation) -> None:
        self.obligations.append(obligation)

    def extend(self, obligations: List[ProofObligation]) -> None:
        self.obligations.extend(obligations)

    # ------------------------------------------------------------------
    # Aggregate statistics
    # ------------------------------------------------------------------

    @property
    def total(self) -> int:
        return len(self.obligations)

    @property
    def proved_count(self) -> int:
        return sum(1 for o in self.obligations if o.proved)

    @property
    def failed_count(self) -> int:
        return sum(1 for o in self.obligations if o.result == SolverResult.SAT)

    @property
    def unknown_count(self) -> int:
        return sum(1 for o in self.obligations if o.result in (SolverResult.UNKNOWN, SolverResult.ERROR))

    @property
    def all_proved(self) -> bool:
        return self.total > 0 and self.proved_count == self.total

    def witnesses(self) -> List[Dict[str, Any]]:
        """Return all non-empty witnesses (counterexamples)."""
        return [
            {"engine": o.engine, "function": o.function_name,
             "location": o.location, "vc": o.vc_formula,
             "witness": o.witness}
            for o in self.obligations
            if o.witness
        ]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_file": self.source_file,
            "aeon_version": self.aeon_version,
            "summary": {
                "total": self.total,
                "proved": self.proved_count,
                "failed": self.failed_count,
                "unknown": self.unknown_count,
                "all_proved": self.all_proved,
            },
            "obligations": [o.to_dict() for o in self.obligations],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_ascii_table(self) -> str:
        """Render a compact ASCII table of all obligations."""
        if not self.obligations:
            return "  (no proof obligations recorded)\n"

        col_w = {"engine": 22, "rule": 28, "function": 20, "result": 8}
        header = (
            f"  {'Engine':<{col_w['engine']}} "
            f"{'Rule':<{col_w['rule']}} "
            f"{'Function':<{col_w['function']}} "
            f"{'Result':<{col_w['result']}}"
        )
        sep = "  " + "-" * (sum(col_w.values()) + 3)
        rows = [header, sep]
        for o in self.obligations:
            result_str = "✓ PROVED" if o.proved else ("✗ FAILED" if o.result == SolverResult.SAT else o.result.value)
            rows.append(
                f"  {o.engine:<{col_w['engine']}} "
                f"{o.rule:<{col_w['rule']}} "
                f"{o.function_name:<{col_w['function']}} "
                f"{result_str:<{col_w['result']}}"
            )
        rows.append(sep)
        rows.append(
            f"  {self.proved_count}/{self.total} obligations proved"
            + (f", {self.failed_count} failed" if self.failed_count else "")
            + (f", {self.unknown_count} unknown" if self.unknown_count else "")
        )
        return "\n".join(rows) + "\n"

    def to_smtlib2_bundle(self) -> str:
        """Emit all SMTLIB2 queries as a single annotated file."""
        parts = [
            "; AEON Proof Obligation Bundle",
            f"; Source: {self.source_file}",
            f"; Version: {self.aeon_version}",
            f"; Total obligations: {self.total}",
            "",
        ]
        for i, o in enumerate(self.obligations, 1):
            if not o.smtlib2:
                continue
            parts += [
                f"; --- Obligation {i}: {o.engine} / {o.rule} ---",
                f"; Function : {o.function_name}",
                f"; Location : {o.location}",
                f"; VC       : {o.vc_formula}",
                f"; Result   : {o.result.value}",
                o.smtlib2,
                "(reset)",
                "",
            ]
        return "\n".join(parts)

    def to_latex(self) -> str:
        """Emit a LaTeX verification report fragment."""
        def esc(s: str) -> str:
            return (s.replace("_", r"\_").replace("&", r"\&")
                     .replace("%", r"\%").replace("#", r"\#")
                     .replace("{", r"\{").replace("}", r"\}"))

        lines = [
            r"\subsection*{Proof Obligation Summary}",
            r"\begin{tabular}{llll}",
            r"\hline",
            r"\textbf{Engine} & \textbf{Rule} & \textbf{Function} & \textbf{Result} \\",
            r"\hline",
        ]
        for o in self.obligations:
            result_tex = r"\checkmark" if o.proved else r"\textbf{FAILED}"
            lines.append(
                f"  {esc(o.engine)} & {esc(o.rule)} & "
                f"\\texttt{{{esc(o.function_name)}}} & {result_tex} \\\\"
            )
        lines += [
            r"\hline",
            r"\end{tabular}",
            "",
            r"\subsubsection*{Verification Conditions}",
        ]
        for i, o in enumerate(self.obligations, 1):
            lines += [
                f"\\paragraph{{Obligation {i}: {esc(o.engine)} / {esc(o.rule)}}}",
                f"Function \\texttt{{{esc(o.function_name)}}}, location \\texttt{{{esc(o.location)}}}.",
                "",
                r"\begin{quote}",
                r"\textit{Verification condition:} " + esc(o.vc_formula),
                r"\end{quote}",
            ]
            if o.explanation:
                lines.append(r"\textit{Explanation:} " + esc(o.explanation))
            if o.paper_ref:
                lines.append(r"\textit{Reference:} " + esc(o.paper_ref))
            if o.witness:
                lines += [
                    r"\textit{Counterexample witness:}",
                    r"\begin{verbatim}",
                    json.dumps(o.witness, indent=2),
                    r"\end{verbatim}",
                ]
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Engine-specific obligation builders (convenience helpers)
# ---------------------------------------------------------------------------

_PAPER_REFS: Dict[str, str] = {
    "hoare":               "Hoare (1969) CACM 12(10); Dijkstra (1975) CACM 18(8)",
    "refinement_types":    "Rondon, Kawaguchi, Jhala (2008) PLDI",
    "abstract_interp":     "Cousot & Cousot (1977) POPL",
    "symbolic_execution":  "King (1976) CACM 19(7); Cadar et al. (2008) OSDI",
    "separation_logic":    "Reynolds (2002) LICS; O'Hearn (2019) POPL",
    "dependent_types":     "Martin-Löf (1984); Coquand & Huet (1988)",
    "size_change":         "Lee, Jones, Ben-Amram (2001) POPL",
    "information_flow":    "Volpano, Smith, Irvine (1996) JCS",
    "taint_analysis":      "Schwartz et al. (2010) IEEE S&P; Tripp et al. (2009) PLDI",
    "concurrency":         "Owicki & Gries (1976); Flanagan & Godefroid (2005) POPL",
    "shape_analysis":      "Sagiv, Reps, Wilhelm (2002) TOPLAS",
    "model_checking":      "Clarke et al. (1986) TOPLAS; Biere et al. (1999) TACAS",
    "category_semantics":  "Moggi (1991) Inf. & Comp.",
    "effect_algebra":      "Plotkin & Pretnar (2009) ESOP",
    "certified_compilation": "Leroy (2009) CACM (CompCert)",
}


def make_hoare_obligation(
    function_name: str,
    location: str,
    precondition: str,
    postcondition: str,
    wp_formula: str,
    smtlib2: str = "",
    result: SolverResult = SolverResult.UNKNOWN,
    witness: Optional[Dict[str, Any]] = None,
    duration_ms: float = 0.0,
) -> ProofObligation:
    """Build a Hoare-logic proof obligation."""
    vc = f"({precondition}) ⊢ wp(S, {postcondition})"
    explanation = (
        f"Weakest precondition of the function body must imply the postcondition. "
        f"wp formula: {wp_formula}"
    )
    return ProofObligation(
        engine="hoare",
        rule="wp-calculus / Hoare-consequence",
        function_name=function_name,
        location=location,
        vc_formula=vc,
        smtlib2=smtlib2,
        result=result,
        witness=witness or {},
        explanation=explanation,
        paper_ref=_PAPER_REFS["hoare"],
        duration_ms=duration_ms,
    )


def make_refinement_obligation(
    function_name: str,
    location: str,
    sub_type: str,
    super_type: str,
    smtlib2: str = "",
    result: SolverResult = SolverResult.UNKNOWN,
    witness: Optional[Dict[str, Any]] = None,
    duration_ms: float = 0.0,
) -> ProofObligation:
    """Build a liquid-type subtyping obligation."""
    vc = f"{sub_type}  <:  {super_type}"
    explanation = (
        "Liquid type subtyping: the refinement predicate of the actual type "
        "must imply the refinement predicate of the expected type under the "
        "current path condition (checked via Z3 UNSAT of the negation)."
    )
    return ProofObligation(
        engine="refinement_types",
        rule="CEGAR-fixpoint / liquid-subtyping",
        function_name=function_name,
        location=location,
        vc_formula=vc,
        smtlib2=smtlib2,
        result=result,
        witness=witness or {},
        explanation=explanation,
        paper_ref=_PAPER_REFS["refinement_types"],
        duration_ms=duration_ms,
    )


def make_symbolic_obligation(
    function_name: str,
    location: str,
    path_condition: str,
    property_checked: str,
    smtlib2: str = "",
    result: SolverResult = SolverResult.UNKNOWN,
    witness: Optional[Dict[str, Any]] = None,
    duration_ms: float = 0.0,
) -> ProofObligation:
    """Build a symbolic-execution path obligation."""
    vc = f"path_cond=({path_condition})  ∧  ¬({property_checked})  is SAT?"
    explanation = (
        "Symbolic execution checks whether the negation of the safety property "
        "is reachable along this path.  SAT means a concrete bug-triggering "
        "input exists (the witness).  UNSAT means the property holds on this path."
    )
    return ProofObligation(
        engine="symbolic_execution",
        rule="path-condition / King-1976",
        function_name=function_name,
        location=location,
        vc_formula=vc,
        smtlib2=smtlib2,
        result=result,
        witness=witness or {},
        explanation=explanation,
        paper_ref=_PAPER_REFS["symbolic_execution"],
        duration_ms=duration_ms,
    )


def make_abstract_interp_obligation(
    function_name: str,
    location: str,
    abstract_state: str,
    property_checked: str,
    result: SolverResult = SolverResult.UNKNOWN,
    duration_ms: float = 0.0,
) -> ProofObligation:
    """Build an abstract-interpretation safety obligation."""
    vc = f"γ({abstract_state}) ⊆ safe_states({property_checked})"
    explanation = (
        "Abstract interpretation over-approximates all reachable concrete states. "
        "The concretization γ of the fixpoint abstract state must be contained "
        "in the set of states satisfying the safety property."
    )
    return ProofObligation(
        engine="abstract_interp",
        rule="Galois-soundness / Cousot-Cousot-1977",
        function_name=function_name,
        location=location,
        vc_formula=vc,
        smtlib2="",
        result=result,
        explanation=explanation,
        paper_ref=_PAPER_REFS["abstract_interp"],
        duration_ms=duration_ms,
    )
