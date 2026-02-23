"""AEON Type System.

Built-in types: Int, Float, String, Bool, UUID, Email, Void
Generic types: Result<T, E>, List<T>, Option<T>
Type environment with scoping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any


# ---------------------------------------------------------------------------
# Type Representations
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AeonType:
    """Base type."""
    def __str__(self) -> str:
        return "Unknown"

    def is_assignable_from(self, other: AeonType) -> bool:
        return self == other


@dataclass(frozen=True)
class PrimitiveType(AeonType):
    name: str = ""

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class GenericType(AeonType):
    name: str = ""
    args: tuple[AeonType, ...] = ()

    def __str__(self) -> str:
        if self.args:
            args_str = ", ".join(str(a) for a in self.args)
            return f"{self.name}<{args_str}>"
        return self.name

    def is_assignable_from(self, other: AeonType) -> bool:
        if isinstance(other, GenericType):
            return self.name == other.name and len(self.args) == len(other.args) and all(
                a.is_assignable_from(b) for a, b in zip(self.args, other.args)
            )
        return False


@dataclass(frozen=True)
class DataType(AeonType):
    name: str = ""
    fields: tuple[tuple[str, AeonType], ...] = ()

    def __str__(self) -> str:
        return self.name

    def get_field_type(self, field_name: str) -> Optional[AeonType]:
        for name, typ in self.fields:
            if name == field_name:
                return typ
        return None

    def is_assignable_from(self, other: AeonType) -> bool:
        if isinstance(other, DataType):
            return self.name == other.name
        return False


@dataclass(frozen=True)
class FunctionType(AeonType):
    param_types: tuple[AeonType, ...] = ()
    return_type: AeonType = field(default_factory=AeonType)
    is_pure: bool = True
    effects: tuple[str, ...] = ()

    def __str__(self) -> str:
        params = ", ".join(str(p) for p in self.param_types)
        prefix = "pure" if self.is_pure else "task"
        return f"{prefix}({params}) -> {self.return_type}"


@dataclass(frozen=True)
class ListType(AeonType):
    element_type: AeonType = field(default_factory=AeonType)

    def __str__(self) -> str:
        return f"List<{self.element_type}>"

    def is_assignable_from(self, other: AeonType) -> bool:
        if isinstance(other, ListType):
            return self.element_type.is_assignable_from(other.element_type)
        return False


# ---------------------------------------------------------------------------
# Built-in Types
# ---------------------------------------------------------------------------

INT = PrimitiveType("Int")
FLOAT = PrimitiveType("Float")
STRING = PrimitiveType("String")
BOOL = PrimitiveType("Bool")
VOID = PrimitiveType("Void")
UUID = PrimitiveType("UUID")
EMAIL = PrimitiveType("Email")
USD = PrimitiveType("USD")
ERROR = PrimitiveType("Error")

BUILTIN_TYPES: dict[str, AeonType] = {
    "Int": INT,
    "Float": FLOAT,
    "String": STRING,
    "Bool": BOOL,
    "Void": VOID,
    "UUID": UUID,
    "Email": EMAIL,
    "USD": USD,
    "Error": ERROR,
}


def make_result_type(ok: AeonType, err: AeonType) -> GenericType:
    return GenericType("Result", (ok, err))


def make_option_type(inner: AeonType) -> GenericType:
    return GenericType("Option", (inner,))


def make_list_type(element: AeonType) -> ListType:
    return ListType(element)


# ---------------------------------------------------------------------------
# Type Environment
# ---------------------------------------------------------------------------

class TypeEnvironment:
    """Scoped type environment for type checking."""

    def __init__(self, parent: Optional[TypeEnvironment] = None):
        self.parent = parent
        self._variables: dict[str, AeonType] = {}
        self._types: dict[str, AeonType] = {}
        self._functions: dict[str, FunctionType] = {}

    def define_variable(self, name: str, typ: AeonType) -> None:
        self._variables[name] = typ

    def lookup_variable(self, name: str) -> Optional[AeonType]:
        if name in self._variables:
            return self._variables[name]
        if self.parent:
            return self.parent.lookup_variable(name)
        return None

    def define_type(self, name: str, typ: AeonType) -> None:
        self._types[name] = typ

    def lookup_type(self, name: str) -> Optional[AeonType]:
        if name in self._types:
            return self._types[name]
        if self.parent:
            return self.parent.lookup_type(name)
        return BUILTIN_TYPES.get(name)

    def define_function(self, name: str, typ: FunctionType) -> None:
        self._functions[name] = typ

    def lookup_function(self, name: str) -> Optional[FunctionType]:
        if name in self._functions:
            return self._functions[name]
        if self.parent:
            return self.parent.lookup_function(name)
        return None

    def child_scope(self) -> TypeEnvironment:
        return TypeEnvironment(parent=self)


def resolve_type_annotation(annotation, env: TypeEnvironment) -> AeonType:
    """Resolve a TypeAnnotation AST node to an AeonType."""
    from aeon.ast_nodes import TypeAnnotation

    if not isinstance(annotation, TypeAnnotation):
        return VOID

    base = annotation.name

    if annotation.generic_args:
        if base == "Result" and len(annotation.generic_args) == 2:
            ok = resolve_type_annotation(annotation.generic_args[0], env)
            err = resolve_type_annotation(annotation.generic_args[1], env)
            return make_result_type(ok, err)
        elif base == "Option" and len(annotation.generic_args) == 1:
            inner = resolve_type_annotation(annotation.generic_args[0], env)
            return make_option_type(inner)
        elif base == "List" and len(annotation.generic_args) == 1:
            elem = resolve_type_annotation(annotation.generic_args[0], env)
            return make_list_type(elem)
        else:
            resolved_args = tuple(resolve_type_annotation(a, env) for a in annotation.generic_args)
            return GenericType(base, resolved_args)

    looked = env.lookup_type(base)
    if looked:
        return looked

    builtin = BUILTIN_TYPES.get(base)
    if builtin:
        return builtin

    return PrimitiveType(base)
