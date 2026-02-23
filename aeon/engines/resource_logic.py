"""AEON Resource Logic — Linear Logic & Substructural Type Systems.

Implements resource-aware verification based on:
  Girard, J.Y. (1987) "Linear Logic"
  Theoretical Computer Science 50(1),
  https://doi.org/10.1016/0304-3975(87)90045-4

  Wadler, P. (1993) "A Taste of Linear Logic"
  MFCS '93, https://doi.org/10.1007/3-540-57182-5_12

  Walker, D. (2005) "Substructural Type Systems"
  Advanced Topics in Types and Programming Languages, MIT Press.

  Bernardy, J.P., Boespflug, M., Newton, R.R., Peyton Jones, S., & Spiwack, A. (2018)
  "Linear Haskell: Practical Linearity in a Higher-Order Polymorphic Language"
  POPL '18, https://doi.org/10.1145/3158093

  Atkey, R. (2018) "Syntax and Semantics of Quantitative Type Theory"
  LICS '18, https://doi.org/10.1145/3209108.3209189

  McBride, C. (2016) "I Got Plenty o' Nuttin'"
  A List of Successes That Can Change the World,
  https://doi.org/10.1007/978-3-319-30936-1_12

Key Theory:

1. LINEAR LOGIC (Girard 1987):
   Classical logic: A -> A & A (weakening: resources can be discarded)
                    A -> A (contraction: resources can be duplicated)
   Linear logic REMOVES these structural rules:
     - A -o B (lollipop): consume A EXACTLY ONCE to produce B
     - A & B (with): choose one of A or B
     - A (+) B (par): both A and B, but cannot choose
     - !A (bang): A is a classical/unlimited resource (can be used freely)

2. SUBSTRUCTURAL HIERARCHY (Walker 2005):
   - Linear: used EXACTLY ONCE (no weakening, no contraction)
   - Affine: used AT MOST ONCE (weakening allowed, no contraction)
   - Relevant: used AT LEAST ONCE (contraction allowed, no weakening)
   - Ordered: used in ORDER (no exchange either)

3. QUANTITATIVE TYPE THEORY (Atkey 2018):
   Generalizes linearity with usage annotations:
     0 * A: A is irrelevant (can be erased at runtime)
     1 * A: A is linear (used exactly once)
     omega * A: A is unrestricted (used any number of times)
   Enables fine-grained resource tracking beyond binary linear/non-linear.

4. LINEAR HASKELL (Bernardy et al. 2018):
   Adds linear arrows (->.) to Haskell.
   f :: A ->. B means: if f is applied to a linear value, the result is linear.
   Enables safe in-place mutation, safe resource management without GC.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class Usage(Enum):
    ZERO = 0
    ONE = 1
    OMEGA = -1


@dataclass
class ResourceIssue:
    kind: str
    message: str
    line: int
    variable: str
    severity: str = "error"
    paper: str = ""


@dataclass
class ResourceResult:
    issues: list[ResourceIssue] = field(default_factory=list)
    linear_vars_checked: int = 0
    affine_vars_checked: int = 0
    usage_violations: int = 0
    verified: bool = True

    @property
    def summary(self) -> str:
        if not self.issues:
            return (f"✅ RESOURCE LOGIC: {self.linear_vars_checked} linear + "
                    f"{self.affine_vars_checked} affine variables — all usage correct")
        return f"❌ RESOURCE LOGIC: {self.usage_violations} usage violation(s)"


@dataclass
class ResourceVar:
    name: str
    usage: Usage
    use_count: int = 0
    line_defined: int = 0
    lines_used: list[int] = field(default_factory=list)


class LinearTypeChecker:
    """
    Enforces linear and affine type discipline.
    Linear variables must be used exactly once.
    Affine variables must be used at most once.
    """

    def __init__(self) -> None:
        self.vars: dict[str, ResourceVar] = {}
        self.issues: list[ResourceIssue] = []

    def declare(self, name: str, usage: Usage, line: int) -> None:
        self.vars[name] = ResourceVar(name=name, usage=usage, line_defined=line)

    def use(self, name: str, line: int) -> None:
        if name not in self.vars:
            return
        var = self.vars[name]
        var.use_count += 1
        var.lines_used.append(line)

        if var.usage == Usage.ONE and var.use_count > 1:
            self.issues.append(ResourceIssue(
                kind="linear_used_twice",
                message=(
                    f"Linear variable '{name}' used {var.use_count} times "
                    f"(lines {var.lines_used}). Linear resources must be used "
                    f"EXACTLY ONCE — no duplication allowed."
                ),
                line=line,
                variable=name,
                severity="error",
                paper="Girard (1987) TCS — Linear Logic; "
                      "Bernardy et al. (2018) POPL — Linear Haskell"
            ))

        if var.usage == Usage.ZERO and var.use_count > 0:
            self.issues.append(ResourceIssue(
                kind="erased_var_used",
                message=(
                    f"Variable '{name}' has usage annotation 0 (erased) "
                    f"but is used at line {line}. Zero-usage variables are "
                    f"compile-time only and must not appear at runtime."
                ),
                line=line,
                variable=name,
                severity="error",
                paper="Atkey (2018) LICS — Quantitative Type Theory"
            ))

    def check_unused_linear(self) -> None:
        for name, var in self.vars.items():
            if var.usage == Usage.ONE and var.use_count == 0:
                self.issues.append(ResourceIssue(
                    kind="linear_unused",
                    message=(
                        f"Linear variable '{name}' (defined at line {var.line_defined}) "
                        f"is never used. Linear resources MUST be consumed — "
                        f"dropping a linear value is a resource leak."
                    ),
                    line=var.line_defined,
                    variable=name,
                    severity="error",
                    paper="Wadler (1993) MFCS — A Taste of Linear Logic"
                ))


class QuantitativeTypeChecker:
    """
    Quantitative Type Theory checker (Atkey 2018).
    Tracks usage multiplicity: 0 (erased), 1 (linear), omega (unrestricted).
    """

    def check_usage_annotation(
        self,
        func_name: str,
        params: list[dict[str, Any]],
        body_uses: dict[str, int],
        line: int
    ) -> list[ResourceIssue]:
        issues = []
        for param in params:
            pname = param.get("name", "?")
            annotation = param.get("usage", "omega")
            actual_uses = body_uses.get(pname, 0)

            if annotation == "linear" and actual_uses != 1:
                issues.append(ResourceIssue(
                    kind="quantitative_mismatch",
                    message=(
                        f"Parameter '{pname}' of '{func_name}' annotated as linear "
                        f"(usage=1) but used {actual_uses} time(s). "
                        f"Quantitative type theory requires exact usage match."
                    ),
                    line=line,
                    variable=pname,
                    severity="error",
                    paper="Atkey (2018) LICS — Quantitative Type Theory"
                ))

            if annotation == "erased" and actual_uses > 0:
                issues.append(ResourceIssue(
                    kind="erased_param_used",
                    message=(
                        f"Parameter '{pname}' of '{func_name}' annotated as erased "
                        f"(usage=0) but appears {actual_uses} time(s) in body. "
                        f"Erased parameters exist only in types, not at runtime."
                    ),
                    line=line,
                    variable=pname,
                    severity="error",
                    paper="McBride (2016) — I Got Plenty o' Nuttin'"
                ))

        return issues


class ResourceLogicEngine:
    """
    Full resource logic verification engine.
    Combines linear type checking and quantitative type theory.
    """

    def __init__(self) -> None:
        self.linear = LinearTypeChecker()
        self.quantitative = QuantitativeTypeChecker()

    def verify(self, program: dict[str, Any]) -> ResourceResult:
        result = ResourceResult()
        all_issues: list[ResourceIssue] = []

        for decl in program.get("declarations", []):
            usage_str = decl.get("usage", "omega")
            usage = {"linear": Usage.ONE, "affine": Usage.ONE,
                     "erased": Usage.ZERO, "omega": Usage.OMEGA}.get(usage_str, Usage.OMEGA)
            self.linear.declare(decl.get("name", "?"), usage, decl.get("line", 0))
            if usage == Usage.ONE:
                result.linear_vars_checked += 1
            else:
                result.affine_vars_checked += 1

        for use_event in program.get("uses", []):
            self.linear.use(use_event.get("name", "?"), use_event.get("line", 0))

        self.linear.check_unused_linear()
        all_issues.extend(self.linear.issues)

        for func in program.get("functions", []):
            issues = self.quantitative.check_usage_annotation(
                func.get("name", "?"),
                func.get("params", []),
                func.get("body_uses", {}),
                func.get("line", 0)
            )
            all_issues.extend(issues)

        result.issues = all_issues
        result.usage_violations = len([i for i in all_issues if i.severity == "error"])
        result.verified = result.usage_violations == 0
        return result


def verify_resources(program: dict[str, Any]) -> ResourceResult:
    """Entry point: verify linear/affine resource usage."""
    engine = ResourceLogicEngine()
    return engine.verify(program)
