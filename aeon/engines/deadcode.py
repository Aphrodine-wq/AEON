"""AEON Dead Code & Unreachable Path Detection Engine.

Implements dead code analysis based on:
  Allen (1970) "Control Flow Analysis"
  SIGPLAN Notices 5(7), https://doi.org/10.1145/390013.808479

  Knoop, Rüthing & Steffen (1994) "Partial Dead Code Elimination"
  PLDI '94, https://doi.org/10.1145/178243.178256

  Cytron et al. (1991) "Efficiently Computing Static Single
  Assignment Form and the Control Dependence Graph"
  TOPLAS 13(4), https://doi.org/10.1145/115372.115320

Key Theory:

1. UNREACHABLE CODE:
   Code after an unconditional return, throw, break, or continue
   can never execute. This is always a bug or leftover code.

2. UNUSED VARIABLES:
   Variables that are defined but never read waste memory and
   indicate incomplete refactoring or copy-paste errors.

3. UNUSED PARAMETERS:
   Function parameters that are never referenced in the body
   suggest API design issues or incomplete implementations.

4. REDUNDANT CONDITIONS:
   Conditions that are always true or always false (based on
   prior assignments or comparisons) indicate logic errors.

5. DUPLICATE BRANCHES:
   If/else branches with identical bodies are redundant—the
   condition is meaningless and the code should be simplified.

6. SELF-ASSIGNMENT:
   Assigning a variable to itself (x = x) is always a bug,
   typically from a typo or copy-paste error.

Detects:
  - Unreachable code after return/throw/break
  - Unused variables (defined but never read)
  - Unused function parameters
  - Redundant conditions (always true/false)
  - Duplicate if/else branches
  - Self-assignment (x = x)
  - Redundant re-assignment (x = a; x = b without reading x)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral, StringLiteral,
    FloatLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Dead Code Analyzer
# ---------------------------------------------------------------------------

class DeadCodeAnalyzer:
    """Detects dead code, unused variables, and redundant patterns."""

    def __init__(self):
        self.errors: List[AeonError] = []

    def check_program(self, program: Program) -> List[AeonError]:
        """Run dead code analysis on the entire program."""
        self.errors = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._check_function(decl)

        return self.errors

    def _check_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function for dead code issues."""
        # 1. Check for unreachable code after return/throw
        self._check_unreachable(func.body, func)

        # 2. Check for unused variables
        self._check_unused_variables(func)

        # 3. Check for unused parameters
        self._check_unused_params(func)

        # 4. Check for self-assignment
        self._check_self_assignment(func.body, func)

        # 5. Check for duplicate if/else branches
        self._check_duplicate_branches(func.body, func)

        # 6. Check for redundant re-assignment
        self._check_redundant_assignment(func.body, func)

        # 7. Check for redundant conditions
        self._check_redundant_conditions(func.body, func)

    def _check_unreachable(self, stmts: List[Statement],
                           func: PureFunc | TaskFunc) -> None:
        """Check for code after return/throw statements."""
        for i, stmt in enumerate(stmts):
            # If this is a return, check if there's code after it
            if isinstance(stmt, ReturnStmt):
                if i < len(stmts) - 1:
                    next_loc = getattr(stmts[i + 1], 'location',
                                       SourceLocation("<dead>", 0, 0))
                    self.errors.append(contract_error(
                        precondition=(
                            f"Unreachable code: statements after 'return' "
                            f"in '{func.name}' can never execute"
                        ),
                        failing_values={
                            "pattern": "code after return",
                            "unreachable_statements": len(stmts) - i - 1,
                            "engine": "Dead Code Detection",
                        },
                        function_signature=f"{func.name}",
                        location=next_loc,
                    ))
                    break  # Don't report further unreachable after first

            # Check for throw/raise/panic as expression statements
            if isinstance(stmt, ExprStmt):
                if self._is_terminating(stmt.expr):
                    if i < len(stmts) - 1:
                        next_loc = getattr(stmts[i + 1], 'location',
                                           SourceLocation("<dead>", 0, 0))
                        self.errors.append(contract_error(
                            precondition=(
                                f"Unreachable code: statements after "
                                f"'{self._get_call_name(stmt.expr)}' "
                                f"in '{func.name}' can never execute"
                            ),
                            failing_values={
                                "pattern": "code after throw/panic",
                                "engine": "Dead Code Detection",
                            },
                            function_signature=f"{func.name}",
                            location=next_loc,
                        ))
                        break

            # Recurse into if/while blocks
            if isinstance(stmt, IfStmt):
                self._check_unreachable(stmt.then_body, func)
                if stmt.else_body:
                    self._check_unreachable(stmt.else_body, func)
            elif isinstance(stmt, WhileStmt):
                self._check_unreachable(stmt.body, func)

    def _check_unused_variables(self, func: PureFunc | TaskFunc) -> None:
        """Check for variables that are defined but never used."""
        defined: Dict[str, SourceLocation] = {}
        used: Set[str] = set()

        # Collect definitions
        self._collect_definitions(func.body, defined)

        # Collect uses
        for stmt in func.body:
            self._collect_uses(stmt, used)

        # Report unused
        for var_name, def_loc in defined.items():
            if var_name not in used and not var_name.startswith("_"):
                self.errors.append(contract_error(
                    precondition=(
                        f"Unused variable: '{var_name}' is defined but "
                        f"never used in '{func.name}'"
                    ),
                    failing_values={
                        "variable": var_name,
                        "engine": "Dead Code Detection",
                    },
                    function_signature=f"{func.name}",
                    location=def_loc,
                ))

    def _check_unused_params(self, func: PureFunc | TaskFunc) -> None:
        """Check for function parameters that are never used."""
        if not func.params:
            return

        # Collect all variable uses in the body
        used: Set[str] = set()
        for stmt in func.body:
            self._collect_uses(stmt, used)

        for param in func.params:
            if param.name not in used and not param.name.startswith("_"):
                loc = getattr(param, 'location',
                              getattr(func, 'location', SourceLocation("<dead>", 0, 0)))
                self.errors.append(contract_error(
                    precondition=(
                        f"Unused parameter: '{param.name}' in '{func.name}' "
                        f"is never referenced"
                    ),
                    failing_values={
                        "parameter": param.name,
                        "engine": "Dead Code Detection",
                    },
                    function_signature=f"{func.name}",
                    location=loc,
                ))

    def _check_self_assignment(self, stmts: List[Statement],
                               func: PureFunc | TaskFunc) -> None:
        """Check for x = x patterns."""
        for stmt in stmts:
            if isinstance(stmt, AssignStmt):
                if (isinstance(stmt.target, Identifier) and
                    isinstance(stmt.value, Identifier) and
                    stmt.target.name == stmt.value.name):
                    loc = getattr(stmt, 'location', SourceLocation("<dead>", 0, 0))
                    self.errors.append(contract_error(
                        precondition=(
                            f"Self-assignment: '{stmt.target.name} = {stmt.value.name}' "
                            f"has no effect"
                        ),
                        failing_values={
                            "variable": stmt.target.name,
                            "pattern": "self-assignment",
                            "engine": "Dead Code Detection",
                        },
                        function_signature=f"{func.name}",
                        location=loc,
                    ))

            elif isinstance(stmt, LetStmt):
                if (stmt.value and isinstance(stmt.value, Identifier) and
                    stmt.name == stmt.value.name):
                    loc = getattr(stmt, 'location', SourceLocation("<dead>", 0, 0))
                    self.errors.append(contract_error(
                        precondition=(
                            f"Self-assignment: 'let {stmt.name} = {stmt.value.name}' "
                            f"has no effect"
                        ),
                        failing_values={
                            "variable": stmt.name,
                            "pattern": "self-assignment",
                            "engine": "Dead Code Detection",
                        },
                        function_signature=f"{func.name}",
                        location=loc,
                    ))

            elif isinstance(stmt, IfStmt):
                self._check_self_assignment(stmt.then_body, func)
                if stmt.else_body:
                    self._check_self_assignment(stmt.else_body, func)
            elif isinstance(stmt, WhileStmt):
                self._check_self_assignment(stmt.body, func)

    def _check_duplicate_branches(self, stmts: List[Statement],
                                   func: PureFunc | TaskFunc) -> None:
        """Check for if/else with identical branches."""
        for stmt in stmts:
            if isinstance(stmt, IfStmt):
                if stmt.else_body and stmt.then_body:
                    then_str = self._stmts_to_string(stmt.then_body)
                    else_str = self._stmts_to_string(stmt.else_body)
                    if then_str == else_str and then_str:
                        loc = getattr(stmt, 'location', SourceLocation("<dead>", 0, 0))
                        self.errors.append(contract_error(
                            precondition=(
                                f"Duplicate branches: if/else in '{func.name}' "
                                f"have identical bodies — the condition is redundant"
                            ),
                            failing_values={
                                "pattern": "duplicate branches",
                                "engine": "Dead Code Detection",
                            },
                            function_signature=f"{func.name}",
                            location=loc,
                        ))

                # Recurse
                self._check_duplicate_branches(stmt.then_body, func)
                if stmt.else_body:
                    self._check_duplicate_branches(stmt.else_body, func)

            elif isinstance(stmt, WhileStmt):
                self._check_duplicate_branches(stmt.body, func)

    def _check_redundant_assignment(self, stmts: List[Statement],
                                     func: PureFunc | TaskFunc) -> None:
        """Check for assignments overwritten without being read."""
        last_assigned: Dict[str, SourceLocation] = {}
        last_assigned_read: Set[str] = set()

        for stmt in stmts:
            if isinstance(stmt, LetStmt):
                # If this var was just assigned and not read since, flag it
                if stmt.name in last_assigned and stmt.name not in last_assigned_read:
                    prev_loc = last_assigned[stmt.name]
                    self.errors.append(contract_error(
                        precondition=(
                            f"Redundant assignment: '{stmt.name}' is assigned "
                            f"a new value before the previous value was used"
                        ),
                        failing_values={
                            "variable": stmt.name,
                            "pattern": "overwritten before read",
                            "engine": "Dead Code Detection",
                        },
                        function_signature=f"{func.name}",
                        location=prev_loc,
                    ))
                loc = getattr(stmt, 'location', SourceLocation("<dead>", 0, 0))
                last_assigned[stmt.name] = loc
                last_assigned_read.discard(stmt.name)

                # Collect reads from the value expression
                if stmt.value:
                    reads: Set[str] = set()
                    self._collect_expr_reads(stmt.value, reads)
                    last_assigned_read.update(reads & set(last_assigned.keys()))

            elif isinstance(stmt, AssignStmt):
                if isinstance(stmt.target, Identifier):
                    if stmt.target.name in last_assigned and stmt.target.name not in last_assigned_read:
                        prev_loc = last_assigned[stmt.target.name]
                        self.errors.append(contract_error(
                            precondition=(
                                f"Redundant assignment: '{stmt.target.name}' is reassigned "
                                f"before the previous value was used"
                            ),
                            failing_values={
                                "variable": stmt.target.name,
                                "pattern": "overwritten before read",
                                "engine": "Dead Code Detection",
                            },
                            function_signature=f"{func.name}",
                            location=prev_loc,
                        ))
                    loc = getattr(stmt, 'location', SourceLocation("<dead>", 0, 0))
                    last_assigned[stmt.target.name] = loc
                    last_assigned_read.discard(stmt.target.name)

                reads = set()
                self._collect_expr_reads(stmt.value, reads)
                last_assigned_read.update(reads & set(last_assigned.keys()))

            else:
                # Any other statement might read variables
                reads = set()
                self._collect_stmt_reads(stmt, reads)
                last_assigned_read.update(reads & set(last_assigned.keys()))

    def _check_redundant_conditions(self, stmts: List[Statement],
                                     func: PureFunc | TaskFunc) -> None:
        """Check for conditions that are always true or always false."""
        for stmt in stmts:
            if isinstance(stmt, IfStmt):
                # Check for literal true/false conditions
                if isinstance(stmt.condition, BoolLiteral):
                    loc = getattr(stmt, 'location', SourceLocation("<dead>", 0, 0))
                    if stmt.condition.value:
                        self.errors.append(contract_error(
                            precondition=(
                                f"Redundant condition: 'if true' — the else branch "
                                f"is unreachable"
                            ),
                            failing_values={
                                "condition": "always true",
                                "engine": "Dead Code Detection",
                            },
                            function_signature=f"{func.name}",
                            location=loc,
                        ))
                    else:
                        self.errors.append(contract_error(
                            precondition=(
                                f"Redundant condition: 'if false' — the then branch "
                                f"is unreachable"
                            ),
                            failing_values={
                                "condition": "always false",
                                "engine": "Dead Code Detection",
                            },
                            function_signature=f"{func.name}",
                            location=loc,
                        ))

                # Check for x == x (always true) or x != x (always false)
                if isinstance(stmt.condition, BinaryOp):
                    if (isinstance(stmt.condition.left, Identifier) and
                        isinstance(stmt.condition.right, Identifier) and
                        stmt.condition.left.name == stmt.condition.right.name):
                        loc = getattr(stmt, 'location', SourceLocation("<dead>", 0, 0))
                        if stmt.condition.op == "==":
                            self.errors.append(contract_error(
                                precondition=(
                                    f"Redundant condition: '{stmt.condition.left.name} == "
                                    f"{stmt.condition.right.name}' is always true"
                                ),
                                failing_values={
                                    "condition": "self-comparison (==)",
                                    "engine": "Dead Code Detection",
                                },
                                function_signature=f"{func.name}",
                                location=loc,
                            ))
                        elif stmt.condition.op == "!=":
                            self.errors.append(contract_error(
                                precondition=(
                                    f"Redundant condition: '{stmt.condition.left.name} != "
                                    f"{stmt.condition.right.name}' is always false"
                                ),
                                failing_values={
                                    "condition": "self-comparison (!=)",
                                    "engine": "Dead Code Detection",
                                },
                                function_signature=f"{func.name}",
                                location=loc,
                            ))

                self._check_redundant_conditions(stmt.then_body, func)
                if stmt.else_body:
                    self._check_redundant_conditions(stmt.else_body, func)

            elif isinstance(stmt, WhileStmt):
                # while false is always dead
                if isinstance(stmt.condition, BoolLiteral) and not stmt.condition.value:
                    loc = getattr(stmt, 'location', SourceLocation("<dead>", 0, 0))
                    self.errors.append(contract_error(
                        precondition=(
                            f"Dead loop: 'while false' body can never execute"
                        ),
                        failing_values={
                            "condition": "always false",
                            "engine": "Dead Code Detection",
                        },
                        function_signature=f"{func.name}",
                        location=loc,
                    ))

                self._check_redundant_conditions(stmt.body, func)

    # --- Helpers ---

    def _collect_definitions(self, stmts: List[Statement],
                             defs: Dict[str, SourceLocation]) -> None:
        """Collect variable definitions from a statement list."""
        for stmt in stmts:
            if isinstance(stmt, LetStmt):
                loc = getattr(stmt, 'location', SourceLocation("<dead>", 0, 0))
                defs[stmt.name] = loc
            elif isinstance(stmt, IfStmt):
                self._collect_definitions(stmt.then_body, defs)
                if stmt.else_body:
                    self._collect_definitions(stmt.else_body, defs)
            elif isinstance(stmt, WhileStmt):
                self._collect_definitions(stmt.body, defs)

    def _collect_uses(self, stmt: Statement, used: Set[str]) -> None:
        """Collect all variable references from a statement."""
        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._collect_expr_reads(stmt.value, used)
        elif isinstance(stmt, AssignStmt):
            self._collect_expr_reads(stmt.value, used)
            if isinstance(stmt.target, FieldAccess):
                self._collect_expr_reads(stmt.target.obj, used)
        elif isinstance(stmt, ExprStmt):
            self._collect_expr_reads(stmt.expr, used)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._collect_expr_reads(stmt.value, used)
        elif isinstance(stmt, IfStmt):
            self._collect_expr_reads(stmt.condition, used)
            for s in stmt.then_body:
                self._collect_uses(s, used)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._collect_uses(s, used)
        elif isinstance(stmt, WhileStmt):
            self._collect_expr_reads(stmt.condition, used)
            for s in stmt.body:
                self._collect_uses(s, used)

    def _collect_expr_reads(self, expr: Expr, reads: Set[str]) -> None:
        """Collect variable reads from an expression."""
        if isinstance(expr, Identifier):
            reads.add(expr.name)
        elif isinstance(expr, BinaryOp):
            self._collect_expr_reads(expr.left, reads)
            self._collect_expr_reads(expr.right, reads)
        elif isinstance(expr, UnaryOp):
            self._collect_expr_reads(expr.operand, reads)
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._collect_expr_reads(arg, reads)
            if isinstance(expr.callee, Identifier):
                reads.add(expr.callee.name)
        elif isinstance(expr, MethodCall):
            self._collect_expr_reads(expr.obj, reads)
            for arg in expr.args:
                self._collect_expr_reads(arg, reads)
        elif isinstance(expr, FieldAccess):
            self._collect_expr_reads(expr.obj, reads)

    def _collect_stmt_reads(self, stmt: Statement, reads: Set[str]) -> None:
        """Collect reads from any statement type."""
        if isinstance(stmt, ExprStmt):
            self._collect_expr_reads(stmt.expr, reads)
        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._collect_expr_reads(stmt.value, reads)
        elif isinstance(stmt, IfStmt):
            self._collect_expr_reads(stmt.condition, reads)
            for s in stmt.then_body:
                self._collect_stmt_reads(s, reads)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._collect_stmt_reads(s, reads)
        elif isinstance(stmt, WhileStmt):
            self._collect_expr_reads(stmt.condition, reads)
            for s in stmt.body:
                self._collect_stmt_reads(s, reads)

    def _is_terminating(self, expr: Expr) -> bool:
        """Check if expression terminates control flow (throw/panic/exit)."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name.lower() in {
                "throw", "raise", "panic", "abort", "exit",
                "die", "fatal", "unreachable",
                "sys_exit", "os_exit", "process_exit",
            }
        if isinstance(expr, MethodCall):
            return expr.method_name.lower() in {
                "throw", "raise", "panic", "abort", "exit",
                "die", "fatal",
            }
        return False

    def _get_call_name(self, expr: Expr) -> Optional[str]:
        """Extract function/method name."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name
        if isinstance(expr, MethodCall):
            return expr.method_name
        return None

    def _stmts_to_string(self, stmts: List[Statement]) -> str:
        """Convert statements to a rough string for comparison."""
        parts = []
        for stmt in stmts:
            if isinstance(stmt, ReturnStmt):
                val = self._expr_to_string(stmt.value) if stmt.value else ""
                parts.append(f"return {val}")
            elif isinstance(stmt, LetStmt):
                val = self._expr_to_string(stmt.value) if stmt.value else ""
                parts.append(f"let {stmt.name} = {val}")
            elif isinstance(stmt, AssignStmt):
                target = self._expr_to_string(stmt.target) if isinstance(stmt.target, Expr) else str(stmt.target)
                parts.append(f"{target} = {self._expr_to_string(stmt.value)}")
            elif isinstance(stmt, ExprStmt):
                parts.append(self._expr_to_string(stmt.expr))
        return "|".join(parts)

    def _expr_to_string(self, expr: Expr) -> str:
        """Convert expression to rough string for comparison."""
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, IntLiteral):
            return str(expr.value)
        if isinstance(expr, BoolLiteral):
            return str(expr.value)
        if isinstance(expr, StringLiteral):
            return f'"{expr.value}"'
        if isinstance(expr, BinaryOp):
            return f"({self._expr_to_string(expr.left)} {expr.op} {self._expr_to_string(expr.right)})"
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            args = ", ".join(self._expr_to_string(a) for a in expr.args)
            return f"{expr.callee.name}({args})"
        if isinstance(expr, MethodCall):
            obj = self._expr_to_string(expr.obj)
            args = ", ".join(self._expr_to_string(a) for a in expr.args)
            return f"{obj}.{expr.method_name}({args})"
        return "<expr>"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_deadcode(program: Program) -> List[AeonError]:
    """Run dead code analysis on an AEON program.

    Detects:
    - Unreachable code after return/throw
    - Unused variables and parameters
    - Self-assignment (x = x)
    - Duplicate if/else branches
    - Redundant conditions (always true/false)
    - Redundant re-assignment (overwritten before read)
    """
    analyzer = DeadCodeAnalyzer()
    return analyzer.check_program(program)
