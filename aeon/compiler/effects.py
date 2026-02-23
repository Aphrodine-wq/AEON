"""AEON Effect System.

Effects are declared explicitly on task functions.
Pure functions must have zero effects — any side effect is a compile error.
Effect categories: Database.Read, Database.Write, Network.Read, Network.Write,
                   File.Read, File.Write, Console.Write, etc.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from aeon.ast_nodes import (
    PureFunc, TaskFunc, Statement, Expr,
    ExprStmt, ReturnStmt, LetStmt, AssignStmt,
    IfStmt, WhileStmt, UnsafeBlock,
    FunctionCall, MethodCall, FieldAccess, Identifier,
    BinaryOp, UnaryOp,
)
from aeon.errors import AeonError, effect_error


# Well-known effect categories
KNOWN_EFFECTS = {
    "Database.Read", "Database.Write",
    "Network.Read", "Network.Write",
    "File.Read", "File.Write",
    "Console.Read", "Console.Write",
    "System.Execute",
}

# Map of known effectful built-in functions/methods to their required effects
EFFECTFUL_OPERATIONS: dict[str, str] = {
    "db.insert": "Database.Write",
    "db.update": "Database.Write",
    "db.delete": "Database.Write",
    "db.query": "Database.Read",
    "db.find": "Database.Read",
    "db.contains": "Database.Read",
    "net.get": "Network.Read",
    "net.post": "Network.Write",
    "net.send": "Network.Write",
    "file.read": "File.Read",
    "file.write": "File.Write",
    "console.print": "Console.Write",
    "console.read": "Console.Read",
    "print": "Console.Write",
}


class EffectChecker:
    """Checks that function effects match their declarations."""

    def __init__(self, function_effects: dict[str, list[str]] | None = None):
        self.function_effects = function_effects or {}
        self.errors: list[AeonError] = []

    def check_pure_function(self, func: PureFunc) -> list[AeonError]:
        """Pure functions must have zero effects."""
        self.errors = []
        detected = self._collect_effects(func.body, [])
        for eff, chain in detected:
            self.errors.append(effect_error(
                declared_effects=[],
                actual_effect=eff,
                callsite_chain=chain,
                location=func.location,
            ))
        return self.errors

    def check_task_function(self, func: TaskFunc) -> list[AeonError]:
        """Task functions must declare all effects."""
        self.errors = []
        declared = set(func.effects)
        detected = self._collect_effects(func.body, [])
        for eff, chain in detected:
            if eff not in declared:
                self.errors.append(effect_error(
                    declared_effects=func.effects,
                    actual_effect=eff,
                    callsite_chain=chain,
                    location=func.location,
                ))
        return self.errors

    def _collect_effects(self, stmts: list[Statement], chain: list[str]) -> list[tuple[str, list[str]]]:
        """Collect all effects from a list of statements."""
        found: list[tuple[str, list[str]]] = []
        for stmt in stmts:
            found.extend(self._check_stmt(stmt, chain))
        return found

    def _check_stmt(self, stmt: Statement, chain: list[str]) -> list[tuple[str, list[str]]]:
        found: list[tuple[str, list[str]]] = []

        if isinstance(stmt, ExprStmt):
            found.extend(self._check_expr(stmt.expr, chain))
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                found.extend(self._check_expr(stmt.value, chain))
        elif isinstance(stmt, LetStmt):
            if stmt.value:
                found.extend(self._check_expr(stmt.value, chain))
        elif isinstance(stmt, AssignStmt):
            found.extend(self._check_expr(stmt.value, chain))
        elif isinstance(stmt, IfStmt):
            found.extend(self._check_expr(stmt.condition, chain))
            found.extend(self._collect_effects(stmt.then_body, chain))
            found.extend(self._collect_effects(stmt.else_body, chain))
        elif isinstance(stmt, WhileStmt):
            found.extend(self._check_expr(stmt.condition, chain))
            found.extend(self._collect_effects(stmt.body, chain))
        elif isinstance(stmt, UnsafeBlock):
            pass  # Effects in unsafe blocks are allowed

        return found

    def _check_expr(self, expr: Expr, chain: list[str]) -> list[tuple[str, list[str]]]:
        found: list[tuple[str, list[str]]] = []

        if isinstance(expr, MethodCall):
            obj_name = ""
            if isinstance(expr.obj, Identifier):
                obj_name = expr.obj.name
            key = f"{obj_name}.{expr.method_name}"
            if key in EFFECTFUL_OPERATIONS:
                found.append((EFFECTFUL_OPERATIONS[key], chain + [key]))
            for arg in expr.args:
                found.extend(self._check_expr(arg, chain))
            found.extend(self._check_expr(expr.obj, chain))

        elif isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                fname = expr.callee.name
                if fname in EFFECTFUL_OPERATIONS:
                    found.append((EFFECTFUL_OPERATIONS[fname], chain + [fname]))
                elif fname in self.function_effects:
                    for eff in self.function_effects[fname]:
                        found.append((eff, chain + [fname]))
            for arg in expr.args:
                found.extend(self._check_expr(arg, chain))

        elif isinstance(expr, FieldAccess):
            found.extend(self._check_expr(expr.obj, chain))

        elif isinstance(expr, BinaryOp):
            found.extend(self._check_expr(expr.left, chain))
            found.extend(self._check_expr(expr.right, chain))

        elif isinstance(expr, UnaryOp):
            found.extend(self._check_expr(expr.operand, chain))

        return found
