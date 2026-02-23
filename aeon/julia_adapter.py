"""AEON Julia Language Adapter — Regex-based Julia parser and translator.

Translates Julia source code into AEON AST for formal verification.
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


_JULIA_TYPE_MAP: Dict[str, str] = {
    "int": "Int", "int8": "Int", "int16": "Int", "int32": "Int", "int64": "Int", "int128": "Int",
    "uint": "Int", "uint8": "Int", "uint16": "Int", "uint32": "Int", "uint64": "Int",
    "float16": "Float", "float32": "Float", "float64": "Float",
    "bigint": "Int", "bigfloat": "Float", "rational": "Float",
    "complex": "Float", "irrational": "Float",
    "bool": "Bool", "char": "String", "string": "String",
    "symbol": "String", "nothing": "Void", "void": "Void",
    "missing": "Void",
    "vector": "List", "array": "List", "matrix": "List",
    "tuple": "Any", "namedtuple": "Any",
    "dict": "Any", "set": "Any",
    "any": "Any", "number": "Float", "integer": "Int",
    "abstractfloat": "Float", "real": "Float",
    "io": "Any", "iostream": "Any",
    "nothing": "Void", "union{}": "Void",
}

_JULIA_SIDE_EFFECTS = {
    "println", "print", "show", "display", "write",
    "open", "close", "read", "readline", "readlines",
    "run", "pipeline", "download",
    "ccall", "@ccall",
    "Channel", "Task", "@async", "@spawn", "Threads.",
    "@distributed", "RemoteChannel",
    "Sockets.", "HTTP.",
}

_FUNC_PATTERN = re.compile(
    r'function\s+(\w[\w!?]*)\s*(?:\{[^}]*\})?\s*\(([^)]*)\)(?:\s*::\s*(\S+))?\s*$',
    re.MULTILINE
)

_SHORT_FUNC_PATTERN = re.compile(
    r'^(\w[\w!?]*)\s*\(([^)]*)\)(?:\s*::\s*(\S+))?\s*=\s*(.+)$',
    re.MULTILINE
)

_STRUCT_PATTERN = re.compile(
    r'(?:mutable\s+)?struct\s+(\w+)(?:\{[^}]*\})?(?:\s*<:\s*\w+)?\s*$',
    re.MULTILINE
)

_ABSTRACT_TYPE_PATTERN = re.compile(
    r'abstract\s+type\s+(\w+)(?:\s*<:\s*\w+)?\s+end',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'#\s*@(?:requires?|pre|ensures?|post|invariant)\s+(.*)',
    re.IGNORECASE
)

_ASSERT_PATTERN = re.compile(
    r'@assert\s+(.+?)(?:\s*$|\s*#)',
    re.MULTILINE
)

_DOCSTRING_PATTERN = re.compile(
    r'"""\s*(.*?)\s*"""',
    re.DOTALL
)


class _JuliaParser:
    """Regex-based Julia parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []
        self.structs: List[dict] = []

    def parse(self) -> None:
        self._parse_structs()
        self._parse_functions()
        self._parse_short_functions()

    def _parse_structs(self) -> None:
        for m in _STRUCT_PATTERN.finditer(self.source):
            name = m.group(1)
            body_start = m.end()
            body = self._extract_end_block(body_start)
            line = self.source[:m.start()].count('\n') + 1
            fields = []
            for fl in body.split('\n'):
                fl = fl.strip()
                if not fl or fl.startswith('#') or fl.startswith('function') or fl == 'end':
                    continue
                if '::' in fl:
                    parts = fl.split('::')
                    fname = parts[0].strip()
                    ftype = parts[1].strip()
                    fields.append({"name": fname, "type": ftype})
                elif fl and fl[0].islower():
                    fields.append({"name": fl, "type": "Any"})
            self.structs.append({"name": name, "fields": fields, "line": line})

    def _parse_functions(self) -> None:
        for m in _FUNC_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2).strip()
            ret_type = m.group(3)
            body_start = m.end()
            body = self._extract_end_block(body_start)
            line = self.source[:m.start()].count('\n') + 1

            params = self._parse_params(params_str)
            contracts = self._extract_contracts(m.start())
            contracts.extend(self._extract_asserts(body))

            has_effects = any(kw in body for kw in _JULIA_SIDE_EFFECTS)
            if name.endswith('!'):
                has_effects = True

            self.functions.append({
                "name": name,
                "params": params,
                "return_type": ret_type.strip() if ret_type else None,
                "body": body,
                "line": line,
                "contracts": contracts,
                "has_effects": has_effects,
            })

    def _parse_short_functions(self) -> None:
        for m in _SHORT_FUNC_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2).strip()
            ret_type = m.group(3)
            body = m.group(4).strip()
            line = self.source[:m.start()].count('\n') + 1

            # Skip if already parsed as full function
            if any(f["name"] == name and f["line"] == line for f in self.functions):
                continue

            params = self._parse_params(params_str)
            contracts = self._extract_contracts(m.start())

            has_effects = any(kw in body for kw in _JULIA_SIDE_EFFECTS)
            if name.endswith('!'):
                has_effects = True

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
            # Julia params: name::Type, name::Type=default, name
            part = re.sub(r'=.*$', '', part).strip()
            if '::' in part:
                name_type = part.split('::')
                pname = name_type[0].strip()
                ptype = name_type[1].strip()
            else:
                pname = part
                ptype = "Any"
            if pname and pname != '...':
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

    def _extract_end_block(self, start: int) -> str:
        depth = 1
        i = start
        block_re = re.compile(r'\b(function|if|for|while|begin|do|let|struct|module|macro|quote|try)\b')
        end_re = re.compile(r'\bend\b')
        while i < len(self.source) and depth > 0:
            rest = self.source[i:]
            bm = block_re.match(rest)
            em = end_re.match(rest)
            if bm:
                depth += 1
                i += len(bm.group())
            elif em:
                depth -= 1
                i += len(em.group())
            else:
                i += 1
        return self.source[start:max(start, i - 3)]

    def _extract_contracts(self, func_start: int) -> List[dict]:
        contracts = []
        lines_before = self.source[:func_start].split('\n')
        for line in reversed(lines_before[-8:]):
            m = _CONTRACT_PATTERN.match(line.strip())
            if m:
                contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts

    def _extract_asserts(self, body: str) -> List[dict]:
        contracts = []
        for m in _ASSERT_PATTERN.finditer(body):
            contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts


class JuliaTranslator(LanguageTranslator):
    """Translates Julia source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "Julia"

    @property
    def file_extensions(self) -> List[str]:
        return [".jl"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _JuliaParser(source)
        parser.parse()
        declarations = []

        for s in parser.structs:
            fields = []
            for f in s["fields"]:
                aeon_type = self._map_type(f["type"])
                fields.append(Parameter(
                    name=f["name"],
                    type_annotation=TypeAnnotation(name=aeon_type),
                    location=SourceLocation("<julia>", s.get("line", 0), 0),
                ))
            declarations.append(DataDef(
                name=s["name"], fields=fields,
                location=SourceLocation("<julia>", s.get("line", 0), 0),
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
                location=SourceLocation("<julia>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = self._map_type(func["return_type"])
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<julia>", func["line"], 0)),
                location=SourceLocation("<julia>", func["line"], 0),
            ))

        loc = SourceLocation("<julia>", func["line"], 0)
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

    def _map_type(self, jl_type: str) -> str:
        jl_type = jl_type.strip()
        lower = jl_type.lower()
        # Strip parametric types
        base = lower.split('{')[0].split('<')[0]
        for prefix, aeon in _JULIA_TYPE_MAP.items():
            if base == prefix or base.startswith(prefix):
                return aeon
        if lower.startswith('vector') or lower.startswith('array') or lower.startswith('matrix'):
            return "List"
        return "Any"


def verify_julia(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "julia", **kwargs)
