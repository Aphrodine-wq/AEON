"""AEON AST Node definitions.

Top-level constructs: data, enum, pure, task, trait, impl, type, use.
Contracts (requires/ensures/effects) on every function.
Pattern matching, algebraic effects, pipelines, lambdas.
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
# Patterns (for match expressions)
# ---------------------------------------------------------------------------

@dataclass
class Pattern:
    """Base class for patterns."""
    location: Optional[SourceLocation] = None


@dataclass
class WildcardPattern(Pattern):
    """The _ pattern — matches anything."""
    pass


@dataclass
class LiteralPattern(Pattern):
    """Matches a literal value (Int, String, Bool)."""
    value: Any = None


@dataclass
class IdentPattern(Pattern):
    """Matches anything and binds to a name."""
    name: str = ""


@dataclass
class ConstructorPattern(Pattern):
    """Matches an enum variant:  Some(x)  |  None  |  Cons(head, tail)"""
    name: str = ""
    fields: list[Pattern] = field(default_factory=list)


@dataclass
class MatchArm:
    """A single arm of a match expression."""
    pattern: Pattern = field(default_factory=Pattern)
    guard: Optional[Expr] = None
    body: list[Statement] = field(default_factory=list)
    location: Optional[SourceLocation] = None


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


@dataclass
class LambdaExpr(Expr):
    """Lambda / anonymous function:  fn(x: Int, y: Int) -> Int => x + y"""
    params: list[Parameter] = field(default_factory=list)
    return_type: Optional[TypeAnnotation] = None
    body: Expr = field(default_factory=Expr)


@dataclass
class MatchExpr(Expr):
    """Pattern match expression:  match expr { Pat => body, ... }"""
    subject: Expr = field(default_factory=Expr)
    arms: list[MatchArm] = field(default_factory=list)


@dataclass
class PipeExpr(Expr):
    """Pipeline expression:  expr |> fn"""
    left: Expr = field(default_factory=Expr)
    right: Expr = field(default_factory=Expr)


@dataclass
class SpawnExpr(Expr):
    """Spawn a concurrent task:  spawn taskFn(args)"""
    call: Expr = field(default_factory=Expr)


@dataclass
class AwaitExpr(Expr):
    """Await a spawned task:  await handle"""
    expr: Expr = field(default_factory=Expr)


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
class ForStmt(Statement):
    """for x in collection { ... }"""
    var_name: str = ""
    iterable: Expr = field(default_factory=Expr)
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
# Enum Variant
# ---------------------------------------------------------------------------

@dataclass
class VariantDef:
    """A single variant of an enum: Cons(head: Int, tail: List<Int>) or None"""
    name: str = ""
    fields: list[FieldDef] = field(default_factory=list)
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
    type_params: list[str] = field(default_factory=list)


@dataclass
class EnumDef(Declaration):
    """enum Option<T> { Some(value: T), None }"""
    name: str = ""
    variants: list[VariantDef] = field(default_factory=list)
    type_params: list[str] = field(default_factory=list)


@dataclass
class PureFunc(Declaration):
    name: str = ""
    params: list[Parameter] = field(default_factory=list)
    return_type: Optional[TypeAnnotation] = None
    requires: list[ContractClause] = field(default_factory=list)
    ensures: list[ContractClause] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    type_params: list[str] = field(default_factory=list)


@dataclass
class TaskFunc(Declaration):
    name: str = ""
    params: list[Parameter] = field(default_factory=list)
    return_type: Optional[TypeAnnotation] = None
    requires: list[ContractClause] = field(default_factory=list)
    ensures: list[ContractClause] = field(default_factory=list)
    effects: list[str] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    type_params: list[str] = field(default_factory=list)


@dataclass
class TraitDef(Declaration):
    """trait Eq<T> { pure eq(self, other: T) -> Bool }"""
    name: str = ""
    type_params: list[str] = field(default_factory=list)
    methods: list[PureFunc | TaskFunc] = field(default_factory=list)


@dataclass
class ImplBlock(Declaration):
    """impl Eq<Int> for Int { ... }  or  impl MyStruct { ... }"""
    trait_name: Optional[str] = None
    target_type: str = ""
    type_args: list[TypeAnnotation] = field(default_factory=list)
    methods: list[PureFunc | TaskFunc] = field(default_factory=list)


@dataclass
class TypeAlias(Declaration):
    """type Name = Int"""
    name: str = ""
    type_params: list[str] = field(default_factory=list)
    target: TypeAnnotation = field(default_factory=lambda: TypeAnnotation(name="Void"))


@dataclass
class UseDecl(Declaration):
    """use std::collections::HashMap"""
    path: list[str] = field(default_factory=list)
    alias: Optional[str] = None


# ---------------------------------------------------------------------------
# Program (root node)
# ---------------------------------------------------------------------------

@dataclass
class Program:
    declarations: list[Declaration] = field(default_factory=list)
    filename: str = "<stdin>"
