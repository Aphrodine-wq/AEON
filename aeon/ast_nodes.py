"""AEON AST Node definitions.

Three top-level constructs: data, pure, task.
Contracts (requires/ensures/effects) on every function.
Expressions and statements for function bodies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any

from aeon.errors import SourceLocation


# ---------------------------------------------------------------------------
# Type Annotations (in source)
# ---------------------------------------------------------------------------

@dataclass
class TypeAnnotation:
    name: str
    generic_args: list[TypeAnnotation] = field(default_factory=list)
    location: Optional[SourceLocation] = None

    def __str__(self) -> str:
        if self.generic_args:
            args = ", ".join(str(a) for a in self.generic_args)
            return f"{self.name}<{args}>"
        return self.name


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------

@dataclass
class Expr:
    location: Optional[SourceLocation] = None


@dataclass
class IntLiteral(Expr):
    value: int = 0


@dataclass
class FloatLiteral(Expr):
    value: float = 0.0


@dataclass
class StringLiteral(Expr):
    value: str = ""


@dataclass
class BoolLiteral(Expr):
    value: bool = False


@dataclass
class Identifier(Expr):
    name: str = ""


@dataclass
class BinaryOp(Expr):
    op: str = ""
    left: Expr = field(default_factory=Expr)
    right: Expr = field(default_factory=Expr)


@dataclass
class UnaryOp(Expr):
    op: str = ""
    operand: Expr = field(default_factory=Expr)


@dataclass
class FunctionCall(Expr):
    callee: Expr = field(default_factory=Expr)
    args: list[Expr] = field(default_factory=list)


@dataclass
class FieldAccess(Expr):
    obj: Expr = field(default_factory=Expr)
    field_name: str = ""


@dataclass
class MethodCall(Expr):
    obj: Expr = field(default_factory=Expr)
    method_name: str = ""
    args: list[Expr] = field(default_factory=list)


@dataclass
class ListLiteral(Expr):
    elements: list[Expr] = field(default_factory=list)


@dataclass
class ConstructExpr(Expr):
    type_name: str = ""
    fields: dict[str, Expr] = field(default_factory=dict)


@dataclass
class IfExpr(Expr):
    condition: Expr = field(default_factory=Expr)
    then_body: list[Statement] = field(default_factory=list)
    else_body: list[Statement] = field(default_factory=list)


@dataclass
class BlockExpr(Expr):
    statements: list[Statement] = field(default_factory=list)


@dataclass
class MoveExpr(Expr):
    name: str = ""


@dataclass
class BorrowExpr(Expr):
    name: str = ""
    mutable: bool = False


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------

@dataclass
class Statement:
    location: Optional[SourceLocation] = None


@dataclass
class ReturnStmt(Statement):
    value: Optional[Expr] = None


@dataclass
class LetStmt(Statement):
    name: str = ""
    type_annotation: Optional[TypeAnnotation] = None
    value: Optional[Expr] = None
    mutable: bool = False


@dataclass
class AssignStmt(Statement):
    target: Expr = field(default_factory=Expr)
    value: Expr = field(default_factory=Expr)


@dataclass
class ExprStmt(Statement):
    expr: Expr = field(default_factory=Expr)


@dataclass
class IfStmt(Statement):
    condition: Expr = field(default_factory=Expr)
    then_body: list[Statement] = field(default_factory=list)
    else_body: list[Statement] = field(default_factory=list)


@dataclass
class WhileStmt(Statement):
    condition: Expr = field(default_factory=Expr)
    body: list[Statement] = field(default_factory=list)


@dataclass
class BreakStmt(Statement):
    pass


@dataclass
class ContinueStmt(Statement):
    pass


@dataclass
class UnsafeBlock(Statement):
    body: list[Statement] = field(default_factory=list)
    audit_note: Optional[str] = None


# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

@dataclass
class Parameter:
    name: str
    type_annotation: TypeAnnotation
    location: Optional[SourceLocation] = None


# ---------------------------------------------------------------------------
# Contract Clauses
# ---------------------------------------------------------------------------

@dataclass
class ContractClause:
    kind: str  # "requires" | "ensures"
    expr: Expr
    location: Optional[SourceLocation] = None


# ---------------------------------------------------------------------------
# Top-Level Declarations
# ---------------------------------------------------------------------------

@dataclass
class Declaration:
    location: Optional[SourceLocation] = None


@dataclass
class FieldDef:
    name: str
    type_annotation: TypeAnnotation
    location: Optional[SourceLocation] = None


@dataclass
class DataDef(Declaration):
    name: str = ""
    fields: list[FieldDef] = field(default_factory=list)


@dataclass
class PureFunc(Declaration):
    name: str = ""
    params: list[Parameter] = field(default_factory=list)
    return_type: Optional[TypeAnnotation] = None
    requires: list[ContractClause] = field(default_factory=list)
    ensures: list[ContractClause] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)


@dataclass
class TaskFunc(Declaration):
    name: str = ""
    params: list[Parameter] = field(default_factory=list)
    return_type: Optional[TypeAnnotation] = None
    requires: list[ContractClause] = field(default_factory=list)
    ensures: list[ContractClause] = field(default_factory=list)
    effects: list[str] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Program (root node)
# ---------------------------------------------------------------------------

@dataclass
class Program:
    declarations: list[Declaration] = field(default_factory=list)
    filename: str = "<stdin>"
