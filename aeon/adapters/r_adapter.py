"""AEON R Language Adapter — Regex-based R parser and translator.

Translates R source code into AEON AST for formal verification.
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


_R_TYPE_MAP: Dict[str, str] = {
    "integer": "Int", "numeric": "Float", "double": "Float",
    "character": "String", "logical": "Bool", "complex": "Float",
    "list": "Any", "vector": "List", "data.frame": "Any",
    "matrix": "List", "array": "List", "factor": "Any",
    "null": "Void", "na": "Void", "function": "Any",
}

_R_SIDE_EFFECTS = {
    "print", "cat", "message", "warning", "stop",
    "write.", "read.", "file", "connection", "url",
    "sink", "source", "library", "require", "install.",
    "plot", "ggplot", "dev.", "pdf", "png",
    "Sys.", "system", "shell",
}

_FUNC_PATTERN = re.compile(
    r'(\w[\w.]*)\s*<-\s*function\s*\(([^)]*)\)\s*\{',
    re.MULTILINE
)

_FUNC_ASSIGN_PATTERN = re.compile(
    r'(\w[\w.]*)\s*=\s*function\s*\(([^)]*)\)\s*\{',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'#\s*@(?:requires?|pre|ensures?|post|invariant|param|return)\s+(.*)',
    re.IGNORECASE
)

_ROXYGEN_PARAM = re.compile(
    r"#'\s*@param\s+(\w+)\s+(\w+)",
    re.IGNORECASE
)

_ROXYGEN_RETURN = re.compile(
    r"#'\s*@return\s+(\w+)",
    re.IGNORECASE
)


class _RParser:
    """Regex-based R parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []

    def parse(self) -> None:
        for pattern in [_FUNC_PATTERN, _FUNC_ASSIGN_PATTERN]:
            for m in pattern.finditer(self.source):
                name = m.group(1)
                params_str = m.group(2).strip()
                body_start = m.end()
                body = self._extract_brace_block(body_start)
                line = self.source[:m.start()].count('\n') + 1

                params = self._parse_params(params_str, m.start())
                contracts = self._extract_contracts(m.start())
                ret_type = self._extract_return_type(m.start())
                has_effects = any(kw in body for kw in _R_SIDE_EFFECTS)

                self.functions.append({
                    "name": name,
                    "params": params,
                    "return_type": ret_type,
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
        for line in reversed(lines_before[-15:]):
            tm = _ROXYGEN_PARAM.match(line.strip())
            if tm:
                type_hints[tm.group(1)] = tm.group(2)

        for part in params_str.split(','):
            part = part.strip()
            if '=' in part:
                pname = part.split('=')[0].strip()
            elif part == '...':
                pname = "dots"
            else:
                pname = part
            if pname:
                ptype = type_hints.get(pname, "Any")
                params.append({"name": pname, "type": ptype})
        return params

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
        for line in reversed(lines_before[-10:]):
            m = _CONTRACT_PATTERN.match(line.strip())
            if m:
                contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts

    def _extract_return_type(self, func_start: int) -> Optional[str]:
        lines_before = self.source[:func_start].split('\n')
        for line in reversed(lines_before[-10:]):
            m = _ROXYGEN_RETURN.match(line.strip())
            if m:
                return m.group(1)
        return None


class RTranslator(LanguageTranslator):
    """Translates R source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "R"

    @property
    def file_extensions(self) -> List[str]:
        return [".R", ".r"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _RParser(source)
        parser.parse()
        declarations = []
        for f in parser.functions:
            declarations.append(self._translate_function(f))
        return Program(declarations=declarations)

    def _translate_function(self, func: dict) -> PureFunc | TaskFunc:
        params = []
        for p in func["params"]:
            aeon_type = _R_TYPE_MAP.get(p["type"].lower(), "Any")
            params.append(Parameter(
                name=p["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<r>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = _R_TYPE_MAP.get(func["return_type"].lower(), "Any")
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<r>", func["line"], 0)),
                location=SourceLocation("<r>", func["line"], 0),
            ))

        loc = SourceLocation("<r>", func["line"], 0)
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


def verify_r(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "r", **kwargs)
