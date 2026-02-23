"""AEON Zig Language Adapter — Regex-based Zig parser and translator.

Translates Zig source code into AEON AST for formal verification.
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


_ZIG_TYPE_MAP: Dict[str, str] = {
    "i8": "Int", "i16": "Int", "i32": "Int", "i64": "Int", "i128": "Int",
    "u8": "Int", "u16": "Int", "u32": "Int", "u64": "Int", "u128": "Int",
    "isize": "Int", "usize": "Int", "comptime_int": "Int",
    "f16": "Float", "f32": "Float", "f64": "Float", "f128": "Float",
    "comptime_float": "Float",
    "bool": "Bool",
    "void": "Void", "noreturn": "Void",
    "[]": "List", "anytype": "Any", "type": "Any",
    "?": "Optional", "!": "Result",
}

_ZIG_SIDE_EFFECTS = {
    "std.debug", "std.log", "std.io", "std.fs",
    "std.os", "std.net", "std.http",
    "@import", "@cImport", "@ptrCast",
    "allocator", "alloc", "free", "create", "destroy",
    "std.heap", "std.mem",
    "std.Thread", "std.Mutex",
}

_FN_PATTERN = re.compile(
    r'(?:pub\s+|export\s+)?fn\s+(\w+)\s*\(([^)]*)\)\s*(\S+)?\s*\{',
    re.MULTILINE
)

_STRUCT_PATTERN = re.compile(
    r'(?:pub\s+)?const\s+(\w+)\s*=\s*(?:packed\s+|extern\s+)?struct\s*\{',
    re.MULTILINE
)

_ENUM_PATTERN = re.compile(
    r'(?:pub\s+)?const\s+(\w+)\s*=\s*enum\s*(?:\([^)]*\))?\s*\{',
    re.MULTILINE
)

_UNION_PATTERN = re.compile(
    r'(?:pub\s+)?const\s+(\w+)\s*=\s*(?:packed\s+|extern\s+)?union\s*(?:\([^)]*\))?\s*\{',
    re.MULTILINE
)

_FIELD_PATTERN = re.compile(
    r'(\w+)\s*:\s*([^,}=]+)',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'//\s*@(?:requires?|pre|ensures?|post|invariant)\s+(.*)',
    re.IGNORECASE
)

_ASSERT_PATTERN = re.compile(
    r'std\.debug\.assert\s*\((.+?)\)',
    re.MULTILINE
)


class _ZigParser:
    """Regex-based Zig parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []
        self.structs: List[dict] = []

    def parse(self) -> None:
        self._parse_structs()
        self._parse_functions()

    def _parse_structs(self) -> None:
        for pattern in [_STRUCT_PATTERN, _UNION_PATTERN]:
            for m in pattern.finditer(self.source):
                name = m.group(1)
                body_start = m.end()
                body = self._extract_brace_block(body_start)
                line = self.source[:m.start()].count('\n') + 1
                fields = []
                for fm in _FIELD_PATTERN.finditer(body):
                    fname = fm.group(1)
                    ftype = fm.group(2).strip().rstrip(',')
                    if fname not in ('fn', 'pub', 'const', 'var', 'comptime'):
                        fields.append({"name": fname, "type": ftype})
                self.structs.append({"name": name, "fields": fields, "line": line})

    def _parse_functions(self) -> None:
        for m in _FN_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2).strip()
            ret_type = m.group(3)
            body_start = m.end()
            body = self._extract_brace_block(body_start)
            line = self.source[:m.start()].count('\n') + 1

            params = self._parse_params(params_str)
            contracts = self._extract_contracts(m.start())
            contracts.extend(self._extract_asserts(body))

            has_effects = any(kw in body for kw in _ZIG_SIDE_EFFECTS)
            if ret_type and '!' in ret_type:
                has_effects = True

            self.functions.append({
                "name": name,
                "params": params,
                "return_type": ret_type.strip().lstrip('!').lstrip('?') if ret_type else None,
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
            # Zig params: name: type or comptime name: type
            part = re.sub(r'^comptime\s+', '', part)
            if ':' in part:
                name_type = part.split(':', 1)
                pname = name_type[0].strip()
                ptype = name_type[1].strip()
            else:
                pname = part
                ptype = "anytype"
            if pname and pname != '_':
                params.append({"name": pname, "type": ptype})
        return params

    def _split_params(self, s: str) -> List[str]:
        parts = []
        depth = 0
        current = ""
        for ch in s:
            if ch in ('(', '{', '['):
                depth += 1
            elif ch in (')', '}', ']'):
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
        for line in reversed(lines_before[-6:]):
            m = _CONTRACT_PATTERN.match(line.strip())
            if m:
                contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts

    def _extract_asserts(self, body: str) -> List[dict]:
        contracts = []
        for m in _ASSERT_PATTERN.finditer(body):
            contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts


class ZigTranslator(LanguageTranslator):
    """Translates Zig source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "Zig"

    @property
    def file_extensions(self) -> List[str]:
        return [".zig"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _ZigParser(source)
        parser.parse()
        declarations = []

        for s in parser.structs:
            fields = []
            for f in s["fields"]:
                aeon_type = self._map_type(f["type"])
                fields.append(Parameter(
                    name=f["name"],
                    type_annotation=TypeAnnotation(name=aeon_type),
                    location=SourceLocation("<zig>", s.get("line", 0), 0),
                ))
            declarations.append(DataDef(
                name=s["name"], fields=fields,
                location=SourceLocation("<zig>", s.get("line", 0), 0),
            ))

        for f in parser.functions:
            declarations.append(self._translate_function(f))
        return Program(declarations=declarations)

    def _translate_function(self, func: dict) -> PureFunc | TaskFunc:
        params = []
        for p in func["params"]:
            aeon_type = self._map_type(p["type"])
            params.append(Parameter(
                name=p["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<zig>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = self._map_type(func["return_type"])
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<zig>", func["line"], 0)),
                location=SourceLocation("<zig>", func["line"], 0),
            ))

        loc = SourceLocation("<zig>", func["line"], 0)
        body = [ReturnStmt(value=IntLiteral(value=0, location=loc), location=loc)]

        if func.get("has_effects"):
            return TaskFunc(
                name=func["name"], params=params, return_type=ret_type,
                effects=["IO"], body=body, requires=contracts, ensures=[],
                location=loc,
            )
        return PureFunc(
            name=func["name"], params=params, return_type=ret_type,
            body=body, requires=contracts, ensures=[], location=loc,
        )

    def _map_type(self, zig_type: str) -> str:
        zig_type = zig_type.strip()
        lower = zig_type.lower()
        for prefix, aeon in _ZIG_TYPE_MAP.items():
            if lower.startswith(prefix) or lower == prefix:
                return aeon
        if lower.startswith('['):
            return "List"
        if lower.startswith('*'):
            return "Any"
        return "Any"


def verify_zig(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "zig", **kwargs)
