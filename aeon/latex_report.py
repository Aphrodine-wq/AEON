"""AEON LaTeX Verification Report Generator.

Generates a publication-quality LaTeX document from AEON verification results,
suitable for inclusion in course assignments, research papers, or appendices.

The report includes:
  - A summary table of all verification engines run
  - Per-engine proof obligation tables (theorem environments)
  - Verification condition formulas
  - Counterexample witnesses (if any)
  - Full bibliography of cited papers

Usage:
    from aeon.latex_report import generate_latex_report
    tex = generate_latex_report(source_path, proof_trace, abstract_trace, ctx)
    with open("report.tex", "w") as f:
        f.write(tex)

Or via CLI:
    aeon proof-trace examples/contracts.aeon --format latex > report.tex
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# LaTeX escaping
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    """Escape special LaTeX characters."""
    replacements = [
        ("\\", r"\textbackslash{}"),
        ("&", r"\&"),
        ("%", r"\%"),
        ("$", r"\$"),
        ("#", r"\#"),
        ("_", r"\_"),
        ("{", r"\{"),
        ("}", r"\}"),
        ("~", r"\textasciitilde{}"),
        ("^", r"\textasciicircum{}"),
        ("⊑", r"$\sqsubseteq$"),
        ("⊒", r"$\sqsupseteq$"),
        ("⊔", r"$\sqcup$"),
        ("⊓", r"$\sqcap$"),
        ("⊥", r"$\bot$"),
        ("⊤", r"$\top$"),
        ("∇", r"$\nabla$"),
        ("∧", r"$\wedge$"),
        ("∨", r"$\vee$"),
        ("¬", r"$\neg$"),
        ("⇒", r"$\Rightarrow$"),
        ("⟹", r"$\Longrightarrow$"),
        ("∀", r"$\forall$"),
        ("∃", r"$\exists$"),
        ("∈", r"$\in$"),
        ("≤", r"$\leq$"),
        ("≥", r"$\geq$"),
        ("≠", r"$\neq$"),
        ("→", r"$\rightarrow$"),
        ("←", r"$\leftarrow$"),
        ("↦", r"$\mapsto$"),
        ("α", r"$\alpha$"),
        ("β", r"$\beta$"),
        ("γ", r"$\gamma$"),
        ("Γ", r"$\Gamma$"),
        ("λ", r"$\lambda$"),
        ("σ", r"$\sigma$"),
        ("τ", r"$\tau$"),
        ("ρ", r"$\rho$"),
        ("π", r"$\pi$"),
        ("∞", r"$\infty$"),
        ("✓", r"$\checkmark$"),
        ("✗", r"$\times$"),
        ("\n", r"\\"),
    ]
    for old, new in replacements:
        s = s.replace(old, new)
    return s


def _tt(s: str) -> str:
    """Wrap in \\texttt{}."""
    return r"\texttt{" + _esc(s) + "}"


def _bf(s: str) -> str:
    """Wrap in \\textbf{}."""
    return r"\textbf{" + _esc(s) + "}"


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def _preamble(title: str, author: str = "AEON Verification System") -> str:
    return r"""\documentclass[11pt,a4paper]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{amsmath,amssymb,amsthm}
\usepackage{booktabs}
\usepackage{listings}
\usepackage{xcolor}
\usepackage{hyperref}
\usepackage{geometry}
\usepackage{microtype}
\usepackage{enumitem}

\geometry{margin=2.5cm}

\theoremstyle{definition}
\newtheorem{obligation}{Proof Obligation}[section]
\newtheorem{theorem}{Theorem}[section]
\newtheorem{definition}{Definition}[section]

\lstset{
  basicstyle=\ttfamily\small,
  breaklines=true,
  frame=single,
  backgroundcolor=\color{gray!10},
  keywordstyle=\color{blue},
  commentstyle=\color{gray},
  stringstyle=\color{orange!80!black},
}

\title{""" + _esc(title) + r"""}
\author{""" + _esc(author) + r"""}
\date{""" + datetime.now().strftime("%B %d, %Y") + r"""}

\begin{document}
\maketitle
\tableofcontents
\newpage
"""


def _postamble() -> str:
    return r"""
\end{document}
"""


def _section_summary(source_file: str, total: int, proved: int,
                     failed: int, unknown: int) -> str:
    status = r"\textcolor{green!60!black}{\textbf{ALL PROVED}}" if failed == 0 and unknown == 0 \
        else r"\textcolor{red}{\textbf{FAILED}}"
    return r"""
\section{Verification Summary}

\begin{center}
\begin{tabular}{ll}
\toprule
\textbf{Source file} & """ + _tt(source_file) + r""" \\
\textbf{Total obligations} & """ + str(total) + r""" \\
\textbf{Proved} & \textcolor{green!60!black}{""" + str(proved) + r"""} \\
\textbf{Failed} & \textcolor{red}{""" + str(failed) + r"""} \\
\textbf{Unknown} & """ + str(unknown) + r""" \\
\textbf{Overall status} & """ + status + r""" \\
\bottomrule
\end{tabular}
\end{center}

\medskip
\noindent
AEON applies """ + r"\textbf{15 peer-reviewed formal methods}" + r""" in a single
compilation pass.  Each method is implemented from its original publication and
generates machine-checkable proof obligations discharged by the Z3 SMT solver
\cite{demoura2008z3}.
"""


def _section_obligations(obligations: List[Dict[str, Any]]) -> str:
    if not obligations:
        return r"""
\section{Proof Obligations}
\textit{No proof obligations were generated (no contracts found).}
"""

    lines = [r"""
\section{Proof Obligations}

The following table summarises all proof obligations generated during
verification.  Each obligation corresponds to a formal theorem that must
hold for the program to be correct.

\begin{center}
\begin{tabular}{clllc}
\toprule
\textbf{\#} & \textbf{Engine} & \textbf{Rule} & \textbf{Function} & \textbf{Result} \\
\midrule"""]

    for i, ob in enumerate(obligations, 1):
        engine = _esc(ob.get("engine", ""))
        rule = _esc(ob.get("rule", ""))
        func = _tt(ob.get("function_name", ""))
        result = ob.get("result", "UNKNOWN")
        if result == "UNSAT":
            result_tex = r"\textcolor{green!60!black}{$\checkmark$ proved}"
        elif result == "SAT":
            result_tex = r"\textcolor{red}{$\times$ failed}"
        else:
            result_tex = r"\textit{" + _esc(result) + "}"
        lines.append(f"  {i} & {engine} & {rule} & {func} & {result_tex} \\\\")

    lines.append(r"""\bottomrule
\end{tabular}
\end{center}
""")

    lines.append(r"\subsection{Obligation Details}")

    for i, ob in enumerate(obligations, 1):
        engine = ob.get("engine", "")
        rule = ob.get("rule", "")
        func = ob.get("function_name", "")
        loc = ob.get("location", "")
        vc = ob.get("vc_formula", "")
        explanation = ob.get("explanation", "")
        paper_ref = ob.get("paper_ref", "")
        witness = ob.get("witness", {})
        smtlib2 = ob.get("smtlib2", "")
        result = ob.get("result", "UNKNOWN")
        duration = ob.get("duration_ms", 0.0)

        result_tex = (r"\textcolor{green!60!black}{\textbf{PROVED (UNSAT)}}"
                      if result == "UNSAT"
                      else r"\textcolor{red}{\textbf{FAILED (SAT)}}"
                      if result == "SAT"
                      else r"\textit{" + _esc(result) + "}")

        lines.append(r"""
\begin{obligation}[""" + _esc(f"{engine} / {rule}") + r"""]
\label{ob:""" + str(i) + r"""}
\begin{description}[leftmargin=3cm, style=nextline]
  \item[Function] """ + _tt(func) + (f" at {_tt(loc)}" if loc else "") + r"""
  \item[Engine] """ + _esc(engine) + r"""
  \item[Rule] \textit{""" + _esc(rule) + r"""}
  \item[Result] """ + result_tex + (f" ({duration:.1f} ms)" if duration else "") + r"""
  \item[VC formula] $""" + _esc(vc).replace(r"$", "") + r"""$
""")

        if explanation:
            lines.append(r"  \item[Explanation] " + _esc(explanation))

        if paper_ref:
            lines.append(r"  \item[Reference] \textit{" + _esc(paper_ref) + "}")

        if smtlib2:
            short = smtlib2[:400] + ("…" if len(smtlib2) > 400 else "")
            lines.append(r"""  \item[SMTLIB2 query]
\begin{lstlisting}[language={}]
""" + short + r"""
\end{lstlisting}""")

        if witness:
            lines.append(r"""  \item[Counterexample witness]
\begin{lstlisting}[language={}]
""" + json.dumps(witness, indent=2) + r"""
\end{lstlisting}""")

        lines.append(r"""\end{description}
\end{obligation}""")

    return "\n".join(lines)


def _section_abstract_trace(abstract_trace: Dict[str, List[Dict[str, Any]]]) -> str:
    if not abstract_trace:
        return ""

    lines = [r"""
\section{Abstract Domain Trace}

This section shows the per-statement evolution of the abstract state during
abstract interpretation (Cousot \& Cousot 1977 \cite{cousot1977}).
Each row shows the abstract state \emph{after} executing the statement,
in the interval, sign, and congruence domains.
"""]

    for func_name, steps in abstract_trace.items():
        lines.append(r"\subsection{Function \texttt{" + _esc(func_name) + "}}")
        lines.append(r"""
\begin{center}
\begin{tabular}{lll}
\toprule
\textbf{Program point} & \textbf{Statement} & \textbf{Abstract state (interval)} \\
\midrule""")

        for step in steps:
            point = _esc(step.get("point", ""))
            stmt = _esc(step.get("stmt", ""))
            state = step.get("state_after") or step.get("state", {})
            if state.get("_bottom"):
                state_str = r"$\bot$ (unreachable)"
            else:
                parts = []
                for var, info in sorted(state.items()):
                    iv = info.get("interval", "")
                    if iv:
                        parts.append(f"{_esc(var)}: {_esc(iv)}")
                state_str = ", ".join(parts) if parts else r"$\top$"
            lines.append(f"  {point} & {stmt} & {state_str} \\\\")

        lines.append(r"""\bottomrule
\end{tabular}
\end{center}
""")

    return "\n".join(lines)


def _section_context_summary(ctx_summary: Dict[str, Any]) -> str:
    if not ctx_summary:
        return ""

    lines = [r"""
\section{Shared Verification Context}

The following facts were proven by earlier engines and shared with
downstream engines as additional hypotheses, improving precision.
"""]

    intervals = ctx_summary.get("interval_facts", {})
    if intervals:
        lines.append(r"\subsection{Proven Interval Bounds}")
        lines.append(r"\begin{itemize}")
        for var, bound in sorted(intervals.items()):
            lines.append(r"  \item " + _tt(var) + r": $" + _esc(bound) + r"$")
        lines.append(r"\end{itemize}")

    nonzero = ctx_summary.get("nonzero_vars", [])
    if nonzero:
        lines.append(r"\subsection{Variables Proven Non-Zero}")
        lines.append(r"\begin{itemize}")
        for var in sorted(nonzero):
            lines.append(r"  \item " + _tt(var) + r" $\neq 0$")
        lines.append(r"\end{itemize}")

    termination = ctx_summary.get("proven_termination", [])
    if termination:
        lines.append(r"\subsection{Functions Proven to Terminate}")
        lines.append(r"\begin{itemize}")
        for fn in sorted(termination):
            lines.append(r"  \item " + _tt(fn))
        lines.append(r"\end{itemize}")

    return "\n".join(lines)


def _section_bibliography() -> str:
    return r"""
\section*{References}
\addcontentsline{toc}{section}{References}
\begin{thebibliography}{99}

\bibitem{cousot1977}
P.~Cousot and R.~Cousot.
\newblock Abstract interpretation: A unified lattice model for static analysis
  of programs by construction or approximation of fixpoints.
\newblock In \textit{POPL}, pages 238--252, 1977.

\bibitem{rondon2008}
P.~Rondon, M.~Kawaguchi, and R.~Jhala.
\newblock Liquid types.
\newblock In \textit{PLDI}, pages 159--169, 2008.

\bibitem{hoare1969}
C.~A.~R. Hoare.
\newblock An axiomatic basis for computer programming.
\newblock \textit{CACM}, 12(10):576--580, 1969.

\bibitem{dijkstra1975}
E.~W. Dijkstra.
\newblock Guarded commands, nondeterminacy and formal derivation of programs.
\newblock \textit{CACM}, 18(8):453--457, 1975.

\bibitem{king1976}
J.~C. King.
\newblock Symbolic execution and program testing.
\newblock \textit{CACM}, 19(7):385--394, 1976.

\bibitem{reynolds2002}
J.~C. Reynolds.
\newblock Separation logic: A logic for shared mutable data structures.
\newblock In \textit{LICS}, pages 55--74, 2002.

\bibitem{lee2001}
C.~S. Lee, N.~D. Jones, and A.~M. Ben-Amram.
\newblock The size-change principle for program termination.
\newblock In \textit{POPL}, pages 81--92, 2001.

\bibitem{martinlof1984}
P.~Martin-L\"{o}f.
\newblock \textit{Intuitionistic Type Theory}.
\newblock Bibliopolis, 1984.

\bibitem{coquand1988}
T.~Coquand and G.~Huet.
\newblock The calculus of constructions.
\newblock \textit{Information and Computation}, 76(2--3):95--120, 1988.

\bibitem{leroy2009}
X.~Leroy.
\newblock Formal verification of a realistic compiler.
\newblock \textit{CACM}, 52(7):107--115, 2009.

\bibitem{volpano1996}
D.~Volpano, C.~Smith, and G.~Irvine.
\newblock A sound type system for secure flow analysis.
\newblock \textit{Journal of Computer Security}, 4(2--3):167--187, 1996.

\bibitem{sagiv2002}
M.~Sagiv, T.~Reps, and R.~Wilhelm.
\newblock Parametric shape analysis via 3-valued logic.
\newblock \textit{TOPLAS}, 24(3):217--298, 2002.

\bibitem{biere1999}
A.~Biere, A.~Cimatti, E.~Clarke, and Y.~Zhu.
\newblock Symbolic model checking without BDDs.
\newblock In \textit{TACAS}, pages 193--207, 1999.

\bibitem{plotkin2009}
G.~Plotkin and M.~Pretnar.
\newblock Handlers of algebraic effects.
\newblock In \textit{ESOP}, pages 80--94, 2009.

\bibitem{moggi1991}
E.~Moggi.
\newblock Notions of computation and monads.
\newblock \textit{Information and Computation}, 93(1):55--92, 1991.

\bibitem{demoura2008z3}
L.~de~Moura and N.~Bj{\o}rner.
\newblock Z3: An efficient SMT solver.
\newblock In \textit{TACAS}, pages 337--340, 2008.

\bibitem{owicki1976}
S.~Owicki and D.~Gries.
\newblock An axiomatic proof technique for parallel programs.
\newblock \textit{Acta Informatica}, 6(4):319--340, 1976.

\bibitem{schwartz2010}
E.~J. Schwartz, T.~Avgerinos, and D.~Brumley.
\newblock All you ever wanted to know about dynamic taint analysis and forward
  symbolic execution (but might have been afraid to ask).
\newblock In \textit{IEEE S\&P}, pages 317--331, 2010.

\end{thebibliography}
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_latex_report(
    source_file: str,
    proof_trace=None,
    abstract_trace: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ctx=None,
    title: Optional[str] = None,
    author: str = "AEON Verification System",
) -> str:
    """Generate a complete LaTeX verification report.

    Parameters
    ----------
    source_file : str
        Path to the verified source file.
    proof_trace : ProofTrace, optional
        Proof obligations from Hoare logic / refinement types / symbolic execution.
    abstract_trace : dict, optional
        Per-function abstract domain traces from AbstractDomainInspector.
    ctx : VerificationContext, optional
        Shared verification context with inter-engine proven facts.
    title : str, optional
        Report title (defaults to "AEON Verification Report: <filename>").
    author : str
        Author string for the LaTeX document.

    Returns
    -------
    str
        Complete LaTeX document source.
    """
    import os
    filename = os.path.basename(source_file)
    if title is None:
        title = f"AEON Verification Report: {filename}"

    obligations = []
    total = proved = failed = unknown = 0

    if proof_trace is not None:
        total = proof_trace.total
        proved = proof_trace.proved_count
        failed = proof_trace.failed_count
        unknown = proof_trace.unknown_count
        obligations = [ob.to_dict() for ob in proof_trace.obligations]

    ctx_summary = ctx.summary() if ctx is not None else {}

    parts = [
        _preamble(title, author),
        _section_summary(source_file, total, proved, failed, unknown),
        _section_obligations(obligations),
    ]

    if abstract_trace:
        parts.append(_section_abstract_trace(abstract_trace))

    if ctx_summary:
        parts.append(_section_context_summary(ctx_summary))

    parts.append(_section_bibliography())
    parts.append(_postamble())

    return "\n".join(parts)
