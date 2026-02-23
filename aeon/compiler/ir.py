"""AEON Flat IR — Typed Directed Acyclic Graph.

No nesting, no ambiguity. Each node is an operation with input refs and output type.
This IR is what the AI model reasons about at inference time.
JSON-serializable for AI consumption.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Any


class IROpKind(Enum):
    # Constants
    CONST_INT = "const_int"
    CONST_FLOAT = "const_float"
    CONST_STRING = "const_string"
    CONST_BOOL = "const_bool"

    # Arithmetic
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"
    MOD = "mod"
    NEG = "neg"

    # Comparison
    EQ = "eq"
    NEQ = "neq"
    LT = "lt"
    GT = "gt"
    LTE = "lte"
    GTE = "gte"

    # Logical
    AND = "and"
    OR = "or"
    NOT = "not"

    # Data flow
    PARAM = "param"
    VAR_REF = "var_ref"
    LET_BIND = "let_bind"
    ASSIGN = "assign"
    FIELD_GET = "field_get"
    FIELD_SET = "field_set"
    CONSTRUCT = "construct"

    # Control flow
    CALL = "call"
    METHOD_CALL = "method_call"
    RETURN = "return"
    BRANCH = "branch"
    PHI = "phi"
    JUMP = "jump"

    # Block
    BLOCK_START = "block_start"
    BLOCK_END = "block_end"
    FUNC_START = "func_start"
    FUNC_END = "func_end"

    # List
    LIST_NEW = "list_new"
    LIST_GET = "list_get"


@dataclass
class IRNode:
    """A single node in the flat IR DAG."""
    id: int
    op: IROpKind
    type_name: str = "Void"
    inputs: list[int] = field(default_factory=list)
    value: Any = None
    label: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "op": self.op.value,
            "type": self.type_name,
        }
        if self.inputs:
            d["inputs"] = self.inputs
        if self.value is not None:
            d["value"] = self.value
        if self.label:
            d["label"] = self.label
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class IRFunction:
    """A function in flat IR form."""
    name: str
    params: list[IRNode] = field(default_factory=list)
    return_type: str = "Void"
    nodes: list[IRNode] = field(default_factory=list)
    is_pure: bool = True
    effects: list[str] = field(default_factory=list)
    contracts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "return_type": self.return_type,
            "is_pure": self.is_pure,
            "effects": self.effects,
            "contracts": self.contracts,
            "params": [n.to_dict() for n in self.params],
            "nodes": [n.to_dict() for n in self.nodes],
        }


@dataclass
class IRDataType:
    """A data type definition in IR form."""
    name: str
    fields: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "fields": [{"name": n, "type": t} for n, t in self.fields],
        }


@dataclass
class IRModule:
    """Top-level IR module containing all functions and types."""
    name: str = "main"
    data_types: list[IRDataType] = field(default_factory=list)
    functions: list[IRFunction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.name,
            "data_types": [dt.to_dict() for dt in self.data_types],
            "functions": [f.to_dict() for f in self.functions],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
