"""AEON Dart Language Adapter — Regex-based Dart parser and translator.

Translates Dart source code into AEON AST for formal verification.
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
# Dart Type Map
# ---------------------------------------------------------------------------

_DART_TYPE_MAP: Dict[str, str] = {
    "int": "Int",
    "double": "Float", "num": "Float",
    "bool": "Bool",
    "String": "String",
    "void": "Void",
    "List": "List",
    "Map": "Map",
    "Set": "Set",
    "Future": "Future",
    "Stream": "Stream",
    "dynamic": "Any",
    "Object": "Any",
    "Null": "Void",
    "Never": "Void",
}

_DART_SIDE_EFFECTS = {
    "print", "debugPrint",
    "File", "Directory", "HttpClient", "HttpServer",
    "stdin", "stdout", "stderr",
    "Platform",
    "async", "await",
    "throw",
    "setState",
}


# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------

_FUNC_PATTERN = re.compile(
    r'(?:(?:static|abstract|external|factory)\s+)*'
    r'(?:(?:Future|Stream)\s*<\s*\w+\s*>\s+|(\w+(?:\?|<[^>]*>)?)\s+)?'  # return type
    r'(\w+)\s*'                                                            # name
    r'(?:<[^>]*>)?\s*'                                                     # generics
    r'\(([^)]*)\)\s*'                                                      # params
    r'(?:async\s*\*?\s*)?'
    r'\{',
    re.MULTILINE
)

_CLASS_PATTERN = re.compile(
    r'(?:(?:abstract|sealed|base|interface|final|mixin)\s+)*'
    r'class\s+(\w+)\s*'
    r'(?:<[^>]*>)?\s*'
    r'(?:extends\s+\w+(?:<[^>]*>)?)?\s*'
    r'(?:with\s+[^{]+)?\s*'
    r'(?:implements\s+[^{]+)?\s*\{',
    re.MULTILINE
)

_FIELD_PATTERN = re.compile(
    r'(?:(?:late|final|static|const)\s+)*'
    r'(\w+(?:\?|<[^>]*>)?)\s+(\w+)\s*[;=]',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'///?\s*(?:@|-)?\s*(?:requires?|precondition|ensures?|postcondition)\s*[:\-]?\s*(.*)',
    re.IGNORECASE
)

_ASSERT_PATTERN = re.compile(
    r'assert\s*\((.+?)\)',
    re.MULTILINE
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _DartParser:
    """Regex-based Dart parser."""

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
            body_start = m.end()
            body = self._extract_brace_block(body_start)
            fields = []
            for fm in _FIELD_PATTERN.finditer(body):
                ftype = fm.group(1)
                fname = fm.group(2)
                if fname not in ('return', 'if', 'else', 'for', 'while', 'switch', 'class'):
                    fields.append({"name": fname, "type": ftype})
            self.classes.append({
                "name": name, "fields": fields,
                "line": self.source[:m.start()].count('\n') + 1,
            })

    def _parse_functions(self) -> None:
        for m in _FUNC_PATTERN.finditer(self.source):
            ret_type = m.group(1)
            name = m.group(2)
            params_str = m.group(3).strip()

            # Skip constructors and common keywords
            if name in ('if', 'for', 'while', 'switch', 'catch', 'class'):
                continue

            body_start = m.end()
            body = self._extract_brace_block(body_start)
            line = self.source[:m.start()].count('\n') + 1

            params = self._parse_params(params_str)
            contracts = self._extract_contracts(m.start())
            contracts.extend(self._extract_assert_contracts(body))

            has_effects = any(kw in body for kw in _DART_SIDE_EFFECTS)
            is_async = 'async' in self.source[m.start():m.end()]

            self.functions.append({
                "name": name, "params": params,
                "return_type": ret_type, "body": body,
                "line": line, "contracts": contracts,
                "has_effects": has_effects or is_async,
            })

    def _parse_params(self, params_str: str) -> List[dict]:
        if not params_str.strip():
            return []
        # Remove curly/square brace parameter groups
        params_str = re.sub(r'[{}\[\]]', '', params_str)
        params = []
        for part in self._split_params(params_str):
            part = part.strip()
            if not part or part.startswith('//'):
                continue
            # Dart: Type name or required Type name
            match = re.match(r'(?:required\s+)?(\w+(?:\?|<[^>]*>)?)\s+(\w+)', part)
            if match:
                params.append({"name": match.group(2), "type": match.group(1)})
            else:
                # Positional without type
                match2 = re.match(r'(\w+)', part)
                if match2:
                    params.append({"name": match2.group(1), "type": "dynamic"})
        return params

    def _split_params(self, s: str) -> List[str]:
        parts, depth, current = [], 0, ""
        for ch in s:
            if ch in ('(', '<', '[', '{'):
                depth += 1
            elif ch in (')', '>', ']', '}'):
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
        for line in reversed(lines_before[-5:]):
            m = _CONTRACT_PATTERN.match(line.strip())
            if m:
                contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts

    def _extract_assert_contracts(self, body: str) -> List[dict]:
        contracts = []
        for m in _ASSERT_PATTERN.finditer(body):
            contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts


# ---------------------------------------------------------------------------
# Translator
# ---------------------------------------------------------------------------

class DartTranslator(LanguageTranslator):
    """Translates Dart source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "Dart"

    @property
    def file_extensions(self) -> List[str]:
        return [".dart"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _DartParser(source)
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
                location=SourceLocation("<dart>", cls.get("line", 0), 0),
            ))
        return DataDef(name=cls["name"], fields=fields,
                       location=SourceLocation("<dart>", cls.get("line", 0), 0))

    def _translate_function(self, func: dict) -> PureFunc | TaskFunc:
        params = []
        for p in func["params"]:
            aeon_type = self._map_type(p["type"])
            params.append(Parameter(
                name=p["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<dart>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = self._map_type(func["return_type"])
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<dart>", func["line"], 0)),
                location=SourceLocation("<dart>", func["line"], 0),
            ))

        loc = SourceLocation("<dart>", func["line"], 0)
        body = [ReturnStmt(value=IntLiteral(value=0, location=loc), location=loc)]

        if func.get("has_effects"):
            return TaskFunc(name=func["name"], params=params, return_type=ret_type,
                          effects=["IO"], body=body, requires=contracts, ensures=[], location=loc)
        return PureFunc(name=func["name"], params=params, return_type=ret_type,
                       body=body, requires=contracts, ensures=[], location=loc)

    def _map_type(self, dart_type: str) -> str:
        dart_type = dart_type.strip().rstrip('?')
        for prefix, aeon in _DART_TYPE_MAP.items():
            if dart_type.startswith(prefix):
                return aeon
        return "Any"


def verify_dart(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "dart", **kwargs)
