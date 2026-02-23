"""AEON Swift Language Adapter — Regex-based Swift parser and translator.

Translates Swift source code into AEON AST for formal verification.
Uses regex-based parsing to avoid external dependencies.
"""

from __future__ import annotations

import re
from typing import List, Optional, Dict, Set, Tuple
from dataclasses import dataclass

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef, Parameter, TypeAnnotation,
    Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, ReturnStmt, LetStmt, ExprStmt, IfStmt,
    FunctionCall, FieldAccess, MethodCall, ContractClause,
)
from aeon.errors import AeonError, SourceLocation
from aeon.language_adapter import LanguageTranslator


# ---------------------------------------------------------------------------
# Swift Type Map
# ---------------------------------------------------------------------------

_SWIFT_TYPE_MAP: Dict[str, str] = {
    "Int": "Int", "Int8": "Int", "Int16": "Int", "Int32": "Int", "Int64": "Int",
    "UInt": "Int", "UInt8": "Int", "UInt16": "Int", "UInt32": "Int", "UInt64": "Int",
    "Float": "Float", "Double": "Float", "CGFloat": "Float",
    "Bool": "Bool",
    "String": "String", "Character": "String", "Substring": "String",
    "Void": "Void", "(": "Void",
    "Array": "List", "[": "List",
    "Optional": "Optional",
}

_SWIFT_SIDE_EFFECTS = {
    "print", "debugPrint", "fatalError", "preconditionFailure",
    "FileManager", "URLSession", "UserDefaults",
    "DispatchQueue", "NotificationCenter",
    "try", "throw",
}


# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------

_FUNC_PATTERN = re.compile(
    r'(?:(?:public|private|internal|fileprivate|open|static|class|override|mutating)\s+)*'
    r'func\s+(\w+)\s*'
    r'(?:<[^>]*>)?\s*'                          # generics
    r'\(([^)]*)\)\s*'                            # parameters
    r'(?:throws\s+)?(?:rethrows\s+)?'
    r'(?:->\s*([^\s{]+))?\s*\{',                 # return type
    re.MULTILINE
)

_STRUCT_PATTERN = re.compile(
    r'(?:(?:public|private|internal|fileprivate|open)\s+)?'
    r'(?:struct|class)\s+(\w+)\s*'
    r'(?:<[^>]*>)?\s*'                           # generics
    r'(?::\s*[^{]+)?\s*\{',                      # conformances
    re.MULTILINE
)

_ENUM_PATTERN = re.compile(
    r'(?:(?:public|private|internal|fileprivate|open)\s+)?'
    r'enum\s+(\w+)\s*'
    r'(?:<[^>]*>)?\s*'
    r'(?::\s*[^{]+)?\s*\{',
    re.MULTILINE
)

_PROPERTY_PATTERN = re.compile(
    r'(?:(?:public|private|internal|fileprivate|open|static|lazy|weak|unowned)\s+)*'
    r'(?:var|let)\s+(\w+)\s*:\s*([^={\n]+)',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'///?\s*(?:@|-)?\s*(?:requires?|precondition|ensures?|postcondition|invariant)\s*[:\-]?\s*(.*)',
    re.IGNORECASE
)

_GUARD_PATTERN = re.compile(
    r'guard\s+(.+?)\s+else\s*\{',
    re.MULTILINE
)

_PRECONDITION_CALL = re.compile(
    r'precondition\s*\((.+?)\)',
    re.MULTILINE
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _SwiftParser:
    """Regex-based Swift parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []
        self.structs: List[dict] = []

    def parse(self) -> None:
        self._parse_structs()
        self._parse_functions()

    def _parse_structs(self) -> None:
        for m in _STRUCT_PATTERN.finditer(self.source):
            name = m.group(1)
            body_start = m.end()
            body = self._extract_brace_block(body_start)
            fields = []
            for pm in _PROPERTY_PATTERN.finditer(body):
                fields.append({"name": pm.group(1), "type": pm.group(2).strip()})
            self.structs.append({"name": name, "fields": fields, "line": self.source[:m.start()].count('\n') + 1})

    def _parse_functions(self) -> None:
        for m in _FUNC_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2).strip()
            ret_type = m.group(3)
            body_start = m.end()
            body = self._extract_brace_block(body_start)
            line = self.source[:m.start()].count('\n') + 1

            params = self._parse_params(params_str)
            contracts = self._extract_contracts(m.start())
            contracts.extend(self._extract_guard_contracts(body))
            contracts.extend(self._extract_precondition_contracts(body))

            has_effects = any(kw in body for kw in _SWIFT_SIDE_EFFECTS)

            self.functions.append({
                "name": name,
                "params": params,
                "return_type": ret_type.strip() if ret_type else None,
                "body": body,
                "line": line,
                "contracts": contracts,
                "has_effects": has_effects,
            })

    def _parse_params(self, params_str: str) -> List[dict]:
        if not params_str.strip():
            return []
        params = []
        for part in self._split_params(params_str):
            part = part.strip()
            if not part:
                continue
            # Swift params: label name: Type or _ name: Type or name: Type
            match = re.match(r'(?:_\s+)?(\w+)\s*:\s*(.*)', part)
            if match:
                params.append({"name": match.group(1), "type": match.group(2).strip()})
            else:
                params.append({"name": part, "type": "Any"})
        return params

    def _split_params(self, s: str) -> List[str]:
        parts = []
        depth = 0
        current = ""
        for ch in s:
            if ch in ('(', '<', '['):
                depth += 1
            elif ch in (')', '>', ']'):
                depth -= 1
            elif ch == ',' and depth == 0:
                parts.append(current)
                current = ""
                continue
            current += ch
        if current.strip():
            parts.append(current)
        return parts

    def _extract_brace_block(self, start: int) -> str:
        depth = 1
        i = start
        while i < len(self.source) and depth > 0:
            if self.source[i] == '{':
                depth += 1
            elif self.source[i] == '}':
                depth -= 1
            i += 1
        return self.source[start:i - 1] if i > start else ""

    def _extract_contracts(self, func_start: int) -> List[dict]:
        contracts = []
        lines_before = self.source[:func_start].split('\n')
        for line in reversed(lines_before[-5:]):
            m = _CONTRACT_PATTERN.match(line.strip())
            if m:
                contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts

    def _extract_guard_contracts(self, body: str) -> List[dict]:
        contracts = []
        for m in _GUARD_PATTERN.finditer(body):
            contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts

    def _extract_precondition_contracts(self, body: str) -> List[dict]:
        contracts = []
        for m in _PRECONDITION_CALL.finditer(body):
            contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts


# ---------------------------------------------------------------------------
# Translator
# ---------------------------------------------------------------------------

class SwiftTranslator(LanguageTranslator):
    """Translates Swift source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "Swift"

    @property
    def file_extensions(self) -> List[str]:
        return [".swift"]

    @property
    def noise_patterns(self) -> List[str]:
        return [
            "Failed to register", "not defined", "Runtime",
        ]

    def translate(self, source: str) -> Program:
        parser = _SwiftParser(source)
        parser.parse()
        declarations = []

        for s in parser.structs:
            declarations.append(self._translate_struct(s))

        for f in parser.functions:
            declarations.append(self._translate_function(f))

        return Program(declarations=declarations)

    def _translate_struct(self, struct: dict) -> DataDef:
        fields = []
        for f in struct["fields"]:
            aeon_type = self._map_type(f["type"])
            fields.append(Parameter(
                name=f["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<swift>", struct.get("line", 0), 0),
            ))
        return DataDef(
            name=struct["name"],
            fields=fields,
            location=SourceLocation("<swift>", struct.get("line", 0), 0),
        )

    def _translate_function(self, func: dict) -> PureFunc | TaskFunc:
        params = []
        for p in func["params"]:
            aeon_type = self._map_type(p["type"])
            params.append(Parameter(
                name=p["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<swift>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = self._map_type(func["return_type"])
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<swift>", func["line"], 0)),
                location=SourceLocation("<swift>", func["line"], 0),
            ))

        loc = SourceLocation("<swift>", func["line"], 0)
        body = [ReturnStmt(value=IntLiteral(value=0, location=loc), location=loc)]

        if func.get("has_effects"):
            return TaskFunc(
                name=func["name"], params=params, return_type=ret_type,
                effects=["IO"], body=body, requires=contracts, ensures=[],
                location=loc,
            )
        return PureFunc(
            name=func["name"], params=params, return_type=ret_type,
            body=body, requires=contracts, ensures=[],
            location=loc,
        )

    def _map_type(self, swift_type: str) -> str:
        swift_type = swift_type.strip().rstrip('?').rstrip('!')
        for prefix, aeon in _SWIFT_TYPE_MAP.items():
            if swift_type.startswith(prefix):
                return aeon
        return "Any"


def verify_swift(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "swift", **kwargs)
