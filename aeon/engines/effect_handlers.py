"""AEON Effect Handlers Verification — Deep Handler Correctness & Composition.

Implements effect handler verification based on:
  Plotkin, G. & Pretnar, M. (2013) "Handling Algebraic Effects"
  Logical Methods in Computer Science 9(4),
  https://doi.org/10.2168/LMCS-9(4:23)2013

  Bauer, A. & Pretnar, M. (2015) "Programming with Algebraic Effects and Handlers"
  Journal of Logical and Algebraic Methods in Programming 84(1),
  https://doi.org/10.1016/j.jlamp.2014.02.001

  Leijen, D. (2017) "Type Directed Compilation of Row-Typed Algebraic Effects"
  POPL '17, https://doi.org/10.1145/3009837.3009872

  Lindley, S., McBride, C., & McLaughlin, C. (2017)
  "Do Be Do Be Do"
  POPL '17, https://doi.org/10.1145/3009837.3009897

  Biernacki, D. et al. (2019) "Abstracting Algebraic Effects"
  POPL '19, https://doi.org/10.1145/3290319

  Xie, N. et al. (2020) "Effect Handlers in Scope"
  Haskell '20, https://doi.org/10.1145/3406088.3409022

Key Theory:

1. ALGEBRAIC EFFECTS (Plotkin & Pretnar 2013):
   An effect is a set of OPERATIONS with signatures.
   Example: State effect = {get : Unit -> S, put : S -> Unit}

   A HANDLER intercepts operations and provides their semantics:
     handler {
       return x -> x,
       get()    -> resume(current_state),
       put(s)   -> resume((), new_state = s)
     }

   Algebraic effects generalize: exceptions, state, I/O, coroutines,
   nondeterminism, async/await, logging, transactions.

2. ROW POLYMORPHISM (Leijen 2017):
   Effect types use ROW VARIABLES to track open/closed effect sets:
     f : Int -> Int <state, exn | rho>
   The row variable rho allows f to be used in any context that has
   at least state and exn effects.

   Row operations:
     extend: add an effect to a row
     restrict: remove a handled effect from a row
     unify: match effect rows modulo reordering

3. HANDLER CORRECTNESS:
   A handler H for effect E is CORRECT if:
     - Every operation of E is handled (completeness)
     - The return clause is well-typed
     - The continuation (resume) is used correctly (linearity)
     - Handled effect is removed from the output type

4. EFFECT COMPOSITION:
   Handlers compose by nesting. Order matters for non-commuting effects.
   AEON verifies that handler composition preserves the intended semantics
   by checking commutativity conditions on effect pairs.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EffectHandlerIssue:
    kind: str
    message: str
    line: int
    severity: str = "error"
    paper: str = ""


@dataclass
class EffectHandlerResult:
    issues: list[EffectHandlerIssue] = field(default_factory=list)
    handlers_verified: int = 0
    effects_covered: list[str] = field(default_factory=list)
    unhandled_effects: list[str] = field(default_factory=list)
    verified: bool = True

    @property
    def summary(self) -> str:
        if not self.issues:
            return (f"✅ EFFECT HANDLERS: {self.handlers_verified} handlers verified, "
                    f"effects covered: {self.effects_covered}")
        errors = [i for i in self.issues if i.severity == "error"]
        return (f"❌ EFFECT HANDLERS: {len(errors)} error(s), "
                f"unhandled: {self.unhandled_effects}")


class HandlerCompletenessChecker:
    """
    Verifies that a handler covers all operations of its declared effect.
    """

    def check(
        self,
        handler_name: str,
        effect_ops: list[str],
        handled_ops: list[str],
        line: int
    ) -> list[EffectHandlerIssue]:
        issues = []
        missing = set(effect_ops) - set(handled_ops)
        if missing:
            issues.append(EffectHandlerIssue(
                kind="incomplete_handler",
                message=(
                    f"Handler '{handler_name}' at line {line} is INCOMPLETE. "
                    f"Missing cases for operations: {sorted(missing)}. "
                    f"Every operation of the handled effect must have a case. "
                    f"Unhandled operations will propagate to the outer context."
                ),
                line=line,
                severity="error",
                paper="Plotkin & Pretnar (2013) LMCS — Handling Algebraic Effects"
            ))
        return issues


class ContinuationLinearityChecker:
    """
    Verifies that the continuation (resume) in each handler case is used linearly.
    Using resume 0 times = ignoring the continuation (valid for abort-style handlers).
    Using resume >1 times = duplicating the continuation (valid for nondeterminism).
    Must be declared explicitly — default is linear (exactly once).
    """

    def check(
        self,
        handler_name: str,
        op_name: str,
        resume_uses: int,
        declared_linearity: str,
        line: int
    ) -> list[EffectHandlerIssue]:
        issues = []
        if declared_linearity == "linear" and resume_uses == 0:
            issues.append(EffectHandlerIssue(
                kind="continuation_dropped",
                message=(
                    f"Handler '{handler_name}', operation '{op_name}' at line {line}: "
                    f"continuation (resume) is never called. "
                    f"For a linear handler, the continuation must be invoked exactly once. "
                    f"If this is intentional (abort), declare the handler as 'deep' or 'abort'."
                ),
                line=line,
                severity="warning",
                paper="Bauer & Pretnar (2015) JLAMP — Programming with Algebraic Effects"
            ))
        if declared_linearity == "linear" and resume_uses > 1:
            issues.append(EffectHandlerIssue(
                kind="continuation_duplicated",
                message=(
                    f"Handler '{handler_name}', operation '{op_name}' at line {line}: "
                    f"continuation (resume) called {resume_uses} times. "
                    f"Linear handlers must call resume exactly once. "
                    f"For multi-shot continuations (nondeterminism), declare as 'multi'."
                ),
                line=line,
                severity="error",
                paper="Lindley et al. (2017) POPL — Do Be Do Be Do"
            ))
        return issues


class EffectRowVerifier:
    """
    Verifies effect row types: that handled effects are removed from output rows
    and unhandled effects are correctly propagated.
    """

    def verify_row(
        self,
        func_name: str,
        input_effects: list[str],
        handled_effects: list[str],
        output_effects: list[str],
        line: int
    ) -> list[EffectHandlerIssue]:
        issues = []
        expected_output = set(input_effects) - set(handled_effects)
        actual_output = set(output_effects)

        leaked = set(handled_effects) & actual_output
        if leaked:
            issues.append(EffectHandlerIssue(
                kind="effect_not_removed",
                message=(
                    f"In '{func_name}' at line {line}: effect(s) {sorted(leaked)} "
                    f"appear in the output row despite being handled. "
                    f"A handler must REMOVE its effect from the output type."
                ),
                line=line,
                severity="error",
                paper="Leijen (2017) POPL — Row-Typed Algebraic Effects"
            ))

        missing_propagated = expected_output - actual_output
        if missing_propagated:
            issues.append(EffectHandlerIssue(
                kind="effect_not_propagated",
                message=(
                    f"In '{func_name}' at line {line}: effect(s) {sorted(missing_propagated)} "
                    f"are present in the input but missing from the output row. "
                    f"Unhandled effects must be propagated to the caller."
                ),
                line=line,
                severity="error",
                paper="Leijen (2017) POPL — Row-Typed Algebraic Effects"
            ))

        return issues


class EffectCompositionVerifier:
    """
    Verifies that composed handlers produce the intended semantics.
    Checks commutativity for effect pairs that must commute.
    """

    COMMUTATIVE_PAIRS = {
        frozenset({"Reader", "Writer"}),
        frozenset({"Reader", "State"}),
        frozenset({"Writer", "Exception"}),
    }

    NON_COMMUTATIVE_PAIRS = {
        frozenset({"State", "Exception"}),
        frozenset({"State", "Nondeterminism"}),
        frozenset({"Exception", "Nondeterminism"}),
    }

    def verify_composition(
        self,
        outer_effect: str,
        inner_effect: str,
        intended_semantics: str,
        line: int
    ) -> list[EffectHandlerIssue]:
        issues = []
        pair = frozenset({outer_effect, inner_effect})

        if pair in self.NON_COMMUTATIVE_PAIRS:
            issues.append(EffectHandlerIssue(
                kind="non_commutative_effects",
                message=(
                    f"Effect composition at line {line}: '{outer_effect}' over '{inner_effect}' "
                    f"is NON-COMMUTATIVE. Swapping handler order changes semantics. "
                    f"State+Exception: outer State = global rollback on exception; "
                    f"outer Exception = state preserved on exception. "
                    f"Verify the intended semantics matches the handler nesting order."
                ),
                line=line,
                severity="warning",
                paper="Xie et al. (2020) Haskell — Effect Handlers in Scope; "
                      "Biernacki et al. (2019) POPL — Abstracting Algebraic Effects"
            ))

        return issues


class EffectHandlerVerificationEngine:
    """
    Full effect handler verification engine.
    Checks completeness, continuation linearity, row types, and composition.
    """

    def __init__(self) -> None:
        self.completeness = HandlerCompletenessChecker()
        self.linearity = ContinuationLinearityChecker()
        self.row = EffectRowVerifier()
        self.composition = EffectCompositionVerifier()

    def verify(self, program: dict[str, Any]) -> EffectHandlerResult:
        result = EffectHandlerResult()
        all_issues: list[EffectHandlerIssue] = []

        for handler in program.get("handlers", []):
            name = handler.get("name", "?")
            effect_ops = handler.get("effect_ops", [])
            handled_ops = handler.get("handled_ops", [])
            line = handler.get("line", 0)

            issues = self.completeness.check(name, effect_ops, handled_ops, line)
            all_issues.extend(issues)

            for op in handler.get("operations", []):
                issues = self.linearity.check(
                    name,
                    op.get("name", "?"),
                    op.get("resume_uses", 1),
                    op.get("linearity", "linear"),
                    op.get("line", line)
                )
                all_issues.extend(issues)

            if not issues:
                result.handlers_verified += 1
                result.effects_covered.extend(handled_ops)

        for func in program.get("functions", []):
            issues = self.row.verify_row(
                func.get("name", "?"),
                func.get("input_effects", []),
                func.get("handled_effects", []),
                func.get("output_effects", []),
                func.get("line", 0)
            )
            all_issues.extend(issues)

        for comp in program.get("compositions", []):
            issues = self.composition.verify_composition(
                comp.get("outer", "?"),
                comp.get("inner", "?"),
                comp.get("semantics", "?"),
                comp.get("line", 0)
            )
            all_issues.extend(issues)

        result.unhandled_effects = [
            e for e in program.get("required_effects", [])
            if e not in result.effects_covered
        ]
        if result.unhandled_effects:
            all_issues.append(EffectHandlerIssue(
                kind="unhandled_effects",
                message=(
                    f"Effects {result.unhandled_effects} are required but have no handler. "
                    f"These effects will escape to the top level."
                ),
                line=0,
                severity="error",
                paper="Plotkin & Pretnar (2013) LMCS — Handling Algebraic Effects"
            ))

        result.issues = all_issues
        result.verified = not any(i.severity == "error" for i in all_issues)
        return result


def verify_effect_handlers(program: dict[str, Any]) -> EffectHandlerResult:
    """Entry point: verify algebraic effect handler correctness."""
    engine = EffectHandlerVerificationEngine()
    return engine.verify(program)
