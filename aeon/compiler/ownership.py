"""AEON Ownership & Borrow Checker.

Single-owner model similar to Rust. Use-after-move detection.
Borrow rules enforced at compile time. Zero garbage collector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from aeon.ast_nodes import (
    Statement, Expr, ReturnStmt, LetStmt, AssignStmt, ExprStmt,
    IfStmt, WhileStmt, UnsafeBlock, Identifier, FunctionCall,
    FieldAccess, MethodCall, BinaryOp, UnaryOp, MoveExpr, BorrowExpr,
    PureFunc, TaskFunc,
)
from aeon.errors import SourceLocation, ownership_error, CompileError, AeonError


class OwnerState(Enum):
    OWNED = auto()
    MOVED = auto()
    BORROWED = auto()
    MUT_BORROWED = auto()


@dataclass
class VarOwnership:
    name: str
    state: OwnerState = OwnerState.OWNED
    defined_at: Optional[SourceLocation] = None
    moved_at: Optional[SourceLocation] = None
    mutable: bool = False


class OwnershipChecker:
    """Checks ownership and borrow rules for a function body."""

    def __init__(self):
        self.scopes: list[dict[str, VarOwnership]] = [{}]
        self.errors: list[AeonError] = []
        self.in_unsafe = False

    def _current_scope(self) -> dict[str, VarOwnership]:
        return self.scopes[-1]

    def _lookup(self, name: str) -> Optional[VarOwnership]:
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def _push_scope(self) -> None:
        self.scopes.append({})

    def _pop_scope(self) -> None:
        self.scopes.pop()

    def define(self, name: str, mutable: bool = False, location: Optional[SourceLocation] = None) -> None:
        self._current_scope()[name] = VarOwnership(
            name=name, state=OwnerState.OWNED, defined_at=location, mutable=mutable,
        )

    def check_use(self, name: str, location: Optional[SourceLocation] = None) -> None:
        var = self._lookup(name)
        if var is None:
            return  # Name resolution handles undefined names
        if var.state == OwnerState.MOVED and not self.in_unsafe:
            self.errors.append(ownership_error(
                variable=name,
                violation_type="use after move",
                location=location,
            ))

    def check_move(self, name: str, location: Optional[SourceLocation] = None) -> None:
        var = self._lookup(name)
        if var is None:
            return
        if var.state == OwnerState.MOVED and not self.in_unsafe:
            self.errors.append(ownership_error(
                variable=name,
                violation_type="move of already moved value",
                location=location,
            ))
        else:
            var.state = OwnerState.MOVED
            var.moved_at = location

    def check_borrow(self, name: str, mutable: bool = False, location: Optional[SourceLocation] = None) -> None:
        var = self._lookup(name)
        if var is None:
            return
        if var.state == OwnerState.MOVED and not self.in_unsafe:
            self.errors.append(ownership_error(
                variable=name,
                violation_type="borrow of moved value",
                location=location,
            ))
        if mutable and not var.mutable:
            self.errors.append(ownership_error(
                variable=name,
                violation_type="mutable borrow of immutable variable",
                location=location,
            ))

    def check_assign(self, name: str, location: Optional[SourceLocation] = None) -> None:
        var = self._lookup(name)
        if var is None:
            return
        if not var.mutable and not self.in_unsafe:
            self.errors.append(ownership_error(
                variable=name,
                violation_type="assignment to immutable variable",
                location=location,
            ))

    # -------------------------------------------------------------------
    # Walk AST
    # -------------------------------------------------------------------

    def check_function(self, func: PureFunc | TaskFunc) -> list[AeonError]:
        self.errors = []
        self._push_scope()
        for param in func.params:
            self.define(param.name, mutable=False, location=param.location)
        for stmt in func.body:
            self._check_statement(stmt)
        self._pop_scope()
        return self.errors

    def _check_statement(self, stmt: Statement) -> None:
        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_expr(stmt.value)
            self.define(stmt.name, mutable=stmt.mutable, location=stmt.location)

        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                self.check_assign(stmt.target.name, stmt.location)
            self._check_expr(stmt.value)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._check_expr(stmt.value)

        elif isinstance(stmt, ExprStmt):
            self._check_expr(stmt.expr)

        elif isinstance(stmt, IfStmt):
            self._check_expr(stmt.condition)
            self._push_scope()
            for s in stmt.then_body:
                self._check_statement(s)
            self._pop_scope()
            if stmt.else_body:
                self._push_scope()
                for s in stmt.else_body:
                    self._check_statement(s)
                self._pop_scope()

        elif isinstance(stmt, WhileStmt):
            self._check_expr(stmt.condition)
            self._push_scope()
            for s in stmt.body:
                self._check_statement(s)
            self._pop_scope()

        elif isinstance(stmt, UnsafeBlock):
            prev = self.in_unsafe
            self.in_unsafe = True
            self._push_scope()
            for s in stmt.body:
                self._check_statement(s)
            self._pop_scope()
            self.in_unsafe = prev

    def _check_expr(self, expr: Expr) -> None:
        if isinstance(expr, Identifier):
            self.check_use(expr.name, expr.location)

        elif isinstance(expr, MoveExpr):
            self.check_move(expr.name, expr.location)

        elif isinstance(expr, BorrowExpr):
            self.check_borrow(expr.name, mutable=expr.mutable, location=expr.location)

        elif isinstance(expr, BinaryOp):
            self._check_expr(expr.left)
            self._check_expr(expr.right)

        elif isinstance(expr, UnaryOp):
            self._check_expr(expr.operand)

        elif isinstance(expr, FunctionCall):
            self._check_expr(expr.callee)
            for arg in expr.args:
                self._check_expr(arg)

        elif isinstance(expr, FieldAccess):
            self._check_expr(expr.obj)

        elif isinstance(expr, MethodCall):
            self._check_expr(expr.obj)
            for arg in expr.args:
                self._check_expr(arg)
