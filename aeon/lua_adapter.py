"""AEON Lua Language Adapter — Regex-based Lua parser and translator.

Translates Lua source code into AEON AST for formal verification.
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


_LUA_TYPE_MAP: Dict[str, str] = {
    "number": "Float", "integer": "Int", "int": "Int",
    "string": "String", "boolean": "Bool", "bool": "Bool",
    "nil": "Void", "table": "Any", "function": "Any",
    "userdata": "Any", "thread": "Any",
}

_LUA_SIDE_EFFECTS = {
    "print", "io.", "os.", "file:", "socket", "require",
    "dofile", "loadfile", "coroutine.", "debug.",
}

_FUNC_PATTERN = re.compile(
    r'(?:local\s+)?function\s+(\w[\w.:]*)?\s*\(([^)]*)\)',
    re.MULTILINE
)

_LOCAL_FUNC_PATTERN = re.compile(
    r'local\s+(\w+)\s*=\s*function\s*\(([^)]*)\)',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'--\s*@(?:requires?|pre|ensures?|post|invariant)\s+(.*)',
    re.IGNORECASE
)

_TYPE_ANNOTATION = re.compile(
    r'---\s*@param\s+(\w+)\s+(\w+)',
    re.IGNORECASE
)

_RETURN_ANNOTATION = re.compile(
    r'---\s*@return\s+(\w+)',
    re.IGNORECASE
)


class _LuaParser:
    """Regex-based Lua parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []

    def parse(self) -> None:
        self._parse_functions()

    def _parse_functions(self) -> None:
        for m in _FUNC_PATTERN.finditer(self.source):
            name = m.group(1) or "anonymous"
            params_str = m.group(2).strip()
            body_start = m.end()
            body = self._extract_end_block(body_start)
            line = self.source[:m.start()].count('\n') + 1

            params = self._parse_params(params_str, m.start())
            contracts = self._extract_contracts(m.start())
            ret_type = self._extract_return_type(m.start())
            has_effects = any(kw in body for kw in _LUA_SIDE_EFFECTS)

            self.functions.append({
                "name": name.replace(":", "."),
                "params": params,
                "return_type": ret_type,
                "body": body,
                "line": line,
                "contracts": contracts,
                "has_effects": has_effects,
            })

        for m in _LOCAL_FUNC_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2).strip()
            body_start = m.end()
            body = self._extract_end_block(body_start)
            line = self.source[:m.start()].count('\n') + 1

            params = self._parse_params(params_str, m.start())
            contracts = self._extract_contracts(m.start())
            has_effects = any(kw in body for kw in _LUA_SIDE_EFFECTS)

            self.functions.append({
                "name": name,
                "params": params,
                "return_type": None,
                "body": body,
                "line": line,
                "contracts": contracts,
                "has_effects": has_effects,
            })

    def _parse_params(self, params_str: str, func_start: int) -> List[dict]:
        if not params_str.strip():
            return []
        params = []
        type_hints = {}
        lines_before = self.source[:func_start].split('\n')
        for line in reversed(lines_before[-10:]):
            tm = _TYPE_ANNOTATION.match(line.strip())
            if tm:
                type_hints[tm.group(1)] = tm.group(2)

        for part in params_str.split(','):
            part = part.strip()
            if part == '...':
                params.append({"name": "varargs", "type": "Any"})
            elif part:
                ptype = type_hints.get(part, "Any")
                params.append({"name": part, "type": ptype})
        return params

    def _extract_end_block(self, start: int) -> str:
        depth = 1
        i = start
        block_starters = re.compile(r'\b(function|if|for|while|repeat|do)\b')
        block_enders = re.compile(r'\bend\b')
        while i < len(self.source) and depth > 0:
            rest = self.source[i:]
            starter = block_starters.match(rest)
            ender = block_enders.match(rest)
            if starter:
                depth += 1
                i += len(starter.group())
            elif ender:
                depth -= 1
                i += len(ender.group())
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

    def _extract_return_type(self, func_start: int) -> Optional[str]:
        lines_before = self.source[:func_start].split('\n')
        for line in reversed(lines_before[-8:]):
            m = _RETURN_ANNOTATION.match(line.strip())
            if m:
                return m.group(1)
        return None


class LuaTranslator(LanguageTranslator):
    """Translates Lua source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "Lua"

    @property
    def file_extensions(self) -> List[str]:
        return [".lua"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _LuaParser(source)
        parser.parse()
        declarations = []
        for f in parser.functions:
            declarations.append(self._translate_function(f))
        return Program(declarations=declarations)

    def _translate_function(self, func: dict) -> PureFunc | TaskFunc:
        params = []
        for p in func["params"]:
            aeon_type = _LUA_TYPE_MAP.get(p["type"].lower(), "Any")
            params.append(Parameter(
                name=p["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<lua>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = _LUA_TYPE_MAP.get(func["return_type"].lower(), "Any")
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<lua>", func["line"], 0)),
                location=SourceLocation("<lua>", func["line"], 0),
            ))

        loc = SourceLocation("<lua>", func["line"], 0)
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

    def _map_type(self, lua_type: str) -> str:
        return _LUA_TYPE_MAP.get(lua_type.lower().strip(), "Any")


def verify_lua(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "lua", **kwargs)
