"""AEON Scala Language Adapter — Regex-based Scala parser and translator.

Translates Scala source code into AEON AST for formal verification.
Uses regex-based parsing to avoid external dependencies.
"""

from __future__ import annotations

import re
from typing import List, Optional, Dict, Set
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
# Scala Type Map
# ---------------------------------------------------------------------------

_SCALA_TYPE_MAP: Dict[str, str] = {
    "Int": "Int", "Long": "Int", "Short": "Int", "Byte": "Int", "BigInt": "Int",
    "Float": "Float", "Double": "Float", "BigDecimal": "Float",
    "Boolean": "Bool",
    "String": "String", "Char": "String",
    "Unit": "Void", "Nothing": "Void",
    "List": "List", "Seq": "List", "Vector": "List", "Array": "List",
    "Set": "Set", "Map": "Map",
    "Option": "Optional", "Some": "Optional", "None": "Optional",
    "Future": "Future", "IO": "IO",
    "Either": "Result", "Try": "Result",
    "Any": "Any", "AnyVal": "Any", "AnyRef": "Any",
}

_SCALA_SIDE_EFFECTS = {
    "println", "print", "printf",
    "Source", "File", "FileWriter", "BufferedWriter",
    "Http", "Request", "Response",
    "Future", "Promise", "Await",
    "Actor", "ActorRef", "ActorSystem",
    "var ", "mutable",
    "throw",
}


# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------

_DEF_PATTERN = re.compile(
    r'(?:(?:private|protected|override|final|implicit|lazy|abstract)\s+)*'
    r'def\s+(\w+)\s*'
    r'(?:\[[^\]]*\])?\s*'                     # type params
    r'(?:\(([^)]*)\))?\s*'                     # params
    r'(?::\s*([^\s={]+))?\s*=?\s*[{\n]?',
    re.MULTILINE
)

_CLASS_PATTERN = re.compile(
    r'(?:(?:abstract|sealed|final|implicit)\s+)?'
    r'(?:case\s+)?class\s+(\w+)\s*'
    r'(?:\[[^\]]*\])?\s*'
    r'(?:\(([^)]*)\))?\s*'                     # constructor params
    r'(?:extends\s+[^{]+)?\s*(?:\{|$)',
    re.MULTILINE
)

_OBJECT_PATTERN = re.compile(
    r'(?:case\s+)?object\s+(\w+)\s*'
    r'(?:extends\s+[^{]+)?\s*\{',
    re.MULTILINE
)

_TRAIT_PATTERN = re.compile(
    r'(?:sealed\s+)?trait\s+(\w+)\s*'
    r'(?:\[[^\]]*\])?\s*'
    r'(?:extends\s+[^{]+)?\s*\{',
    re.MULTILINE
)

_VAL_PATTERN = re.compile(
    r'(?:(?:private|protected|override|lazy)\s+)*'
    r'val\s+(\w+)\s*:\s*([^=\n]+)',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'(?://|/\*\*?\s*\*?)\s*@(?:requires?|precondition|ensures?|postcondition)\s+(.*?)(?:\*/|\n)',
    re.IGNORECASE
)

_REQUIRE_CALL = re.compile(
    r'require\s*\((.+?)\)',
    re.MULTILINE
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _ScalaParser:
    """Regex-based Scala parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []
        self.classes: List[dict] = []

    def parse(self) -> None:
        self._parse_classes()
        self._parse_functions()

    def _parse_classes(self) -> None:
        for m in _CLASS_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2) or ""
            fields = []
            for part in self._split_params(params_str):
                part = part.strip()
                match = re.match(r'(?:val|var)?\s*(\w+)\s*:\s*(.*)', part)
                if match:
                    fields.append({"name": match.group(1), "type": match.group(2).strip()})
            self.classes.append({
                "name": name, "fields": fields,
                "line": self.source[:m.start()].count('\n') + 1,
            })

        for m in _TRAIT_PATTERN.finditer(self.source):
            self.classes.append({
                "name": m.group(1), "fields": [],
                "line": self.source[:m.start()].count('\n') + 1,
            })

    def _parse_functions(self) -> None:
        for m in _DEF_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2) or ""
            ret_type = m.group(3)
            body_start = m.end()

            # Try to extract body
            body = ""
            if body_start < len(self.source) and self.source[body_start - 1] == '{':
                body = self._extract_brace_block(body_start)
            else:
                # Expression body - take until next def/class/newline
                end = self.source.find('\n', body_start)
                if end > 0:
                    body = self.source[body_start:end]

            line = self.source[:m.start()].count('\n') + 1
            params = self._parse_params(params_str)
            contracts = self._extract_contracts(m.start())
            contracts.extend(self._extract_require_contracts(body))
            has_effects = any(kw in body for kw in _SCALA_SIDE_EFFECTS)

            self.functions.append({
                "name": name, "params": params,
                "return_type": ret_type.strip() if ret_type else None,
                "body": body, "line": line,
                "contracts": contracts, "has_effects": has_effects,
            })

    def _parse_params(self, params_str: str) -> List[dict]:
        if not params_str.strip():
            return []
        params = []
        for part in self._split_params(params_str):
            part = part.strip()
            match = re.match(r'(\w+)\s*:\s*(.*)', part)
            if match:
                params.append({"name": match.group(1), "type": match.group(2).strip()})
        return params

    def _split_params(self, s: str) -> List[str]:
        parts, depth, current = [], 0, ""
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
        depth, i = 1, start
        while i < len(self.source) and depth > 0:
            if self.source[i] == '{': depth += 1
            elif self.source[i] == '}': depth -= 1
            i += 1
        return self.source[start:i - 1] if i > start else ""

    def _extract_contracts(self, func_start: int) -> List[dict]:
        contracts = []
        lines_before = self.source[:func_start].split('\n')
        for line in reversed(lines_before[-8:]):
            m = _CONTRACT_PATTERN.match(line.strip())
            if m:
                contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts

    def _extract_require_contracts(self, body: str) -> List[dict]:
        contracts = []
        for m in _REQUIRE_CALL.finditer(body):
            contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts


# ---------------------------------------------------------------------------
# Translator
# ---------------------------------------------------------------------------

class ScalaTranslator(LanguageTranslator):
    """Translates Scala source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "Scala"

    @property
    def file_extensions(self) -> List[str]:
        return [".scala"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _ScalaParser(source)
        parser.parse()
        declarations = []

        for c in parser.classes:
            declarations.append(self._translate_class(c))
        for f in parser.functions:
            declarations.append(self._translate_function(f))

        return Program(declarations=declarations)

    def _translate_class(self, cls: dict) -> DataDef:
        fields = []
        for f in cls["fields"]:
            aeon_type = self._map_type(f["type"])
            fields.append(Parameter(
                name=f["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<scala>", cls.get("line", 0), 0),
            ))
        return DataDef(name=cls["name"], fields=fields,
                       location=SourceLocation("<scala>", cls.get("line", 0), 0))

    def _translate_function(self, func: dict) -> PureFunc | TaskFunc:
        params = []
        for p in func["params"]:
            aeon_type = self._map_type(p["type"])
            params.append(Parameter(
                name=p["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<scala>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = self._map_type(func["return_type"])
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<scala>", func["line"], 0)),
                location=SourceLocation("<scala>", func["line"], 0),
            ))

        loc = SourceLocation("<scala>", func["line"], 0)
        body = [ReturnStmt(value=IntLiteral(value=0, location=loc), location=loc)]

        if func.get("has_effects"):
            return TaskFunc(name=func["name"], params=params, return_type=ret_type,
                          effects=["IO"], body=body, requires=contracts, ensures=[], location=loc)
        return PureFunc(name=func["name"], params=params, return_type=ret_type,
                       body=body, requires=contracts, ensures=[], location=loc)

    def _map_type(self, scala_type: str) -> str:
        scala_type = scala_type.strip()
        for prefix, aeon in _SCALA_TYPE_MAP.items():
            if scala_type.startswith(prefix):
                return aeon
        return "Any"


def verify_scala(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "scala", **kwargs)
