"""Structured JSON error objects for the AEON compiler.

Every error is machine-readable — no raw strings. Each error type includes
enough context for the AI training loop to consume as a negative reward signal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class ErrorKind(Enum):
    SYNTAX_ERROR = "syntax_error"
    TYPE_ERROR = "type_error"
    OWNERSHIP_ERROR = "ownership_error"
    EFFECT_ERROR = "effect_error"
    CONTRACT_ERROR = "contract_error"
    NAME_ERROR = "name_error"
    INTERNAL_ERROR = "internal_error"


@dataclass
class SourceLocation:
    line: int
    column: int
    file: str = "<stdin>"

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.column}"


@dataclass
class AeonError:
    kind: ErrorKind
    message: str
    location: Optional[SourceLocation] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": self.kind.value,
            "message": self.message,
        }
        if self.location:
            d["location"] = {
                "file": self.location.file,
                "line": self.location.line,
                "column": self.location.column,
            }
        if self.details:
            d["details"] = self.details
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def __str__(self) -> str:
        loc = f" at {self.location}" if self.location else ""
        return f"[{self.kind.value}]{loc}: {self.message}"


def type_error(
    node_id: str,
    expected_type: str,
    actual_type: str,
    location: Optional[SourceLocation] = None,
    contract_ref: Optional[str] = None,
) -> AeonError:
    details: dict[str, Any] = {
        "node_id": node_id,
        "expected_type": expected_type,
        "actual_type": actual_type,
    }
    if contract_ref:
        details["contract_ref"] = contract_ref
    return AeonError(
        kind=ErrorKind.TYPE_ERROR,
        message=f"Expected type '{expected_type}', got '{actual_type}'",
        location=location,
        details=details,
    )


def ownership_error(
    variable: str,
    violation_type: str,
    location: Optional[SourceLocation] = None,
) -> AeonError:
    return AeonError(
        kind=ErrorKind.OWNERSHIP_ERROR,
        message=f"Ownership violation on variable '{variable}': {violation_type}",
        location=location,
        details={
            "variable": variable,
            "violation_type": violation_type,
        },
    )


def effect_error(
    declared_effects: list[str],
    actual_effect: str,
    callsite_chain: list[str],
    location: Optional[SourceLocation] = None,
) -> AeonError:
    return AeonError(
        kind=ErrorKind.EFFECT_ERROR,
        message=f"Effect '{actual_effect}' not declared. Declared: {declared_effects}",
        location=location,
        details={
            "declared_effects": declared_effects,
            "actual_effect": actual_effect,
            "callsite_chain": callsite_chain,
        },
    )


def contract_error(
    precondition: str,
    failing_values: dict[str, Any],
    function_signature: str,
    location: Optional[SourceLocation] = None,
) -> AeonError:
    return AeonError(
        kind=ErrorKind.CONTRACT_ERROR,
        message=f"Contract violation: {precondition}",
        location=location,
        details={
            "precondition": precondition,
            "failing_values": failing_values,
            "function_signature": function_signature,
        },
    )


def syntax_error(
    message: str,
    location: Optional[SourceLocation] = None,
) -> AeonError:
    return AeonError(
        kind=ErrorKind.SYNTAX_ERROR,
        message=message,
        location=location,
    )


def name_error(
    name: str,
    location: Optional[SourceLocation] = None,
) -> AeonError:
    return AeonError(
        kind=ErrorKind.NAME_ERROR,
        message=f"Undefined name '{name}'",
        location=location,
        details={"name": name},
    )


class AeonTypeError(AeonError):
    """Convenience subclass for type errors."""

    def __init__(self, message: str, location: Optional[SourceLocation] = None,
                 details: Optional[dict] = None):
        super().__init__(
            kind=ErrorKind.TYPE_ERROR,
            message=message,
            location=location,
            details=details or {},
        )


class AeonContractError(AeonError):
    """Convenience subclass for contract errors."""

    def __init__(self, message: str, location: Optional[SourceLocation] = None,
                 details: Optional[dict] = None):
        super().__init__(
            kind=ErrorKind.CONTRACT_ERROR,
            message=message,
            location=location,
            details=details or {},
        )


class CompileError(Exception):
    """Exception wrapping one or more AeonErrors."""

    def __init__(self, errors: list[AeonError] | AeonError):
        if isinstance(errors, AeonError):
            errors = [errors]
        self.errors = errors
        super().__init__(self._format())

    def _format(self) -> str:
        return "\n".join(str(e) for e in self.errors)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps([e.to_dict() for e in self.errors], indent=indent)
