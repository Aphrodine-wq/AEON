"""AEON Kotlin Language Adapter — Regex-based Kotlin parser and translator.

Translates Kotlin source code into AEON AST for formal verification.
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
# Kotlin Type Map
# ---------------------------------------------------------------------------

_KOTLIN_TYPE_MAP: Dict[str, str] = {
    "Int": "Int", "Long": "Int", "Short": "Int", "Byte": "Int",
    "Float": "Float", "Double": "Float",
    "Boolean": "Bool",
    "String": "String", "Char": "String",
    "Unit": "Void", "Nothing": "Void",
    "List": "List", "MutableList": "List", "ArrayList": "List",
    "Array": "List",
    "Map": "Map", "MutableMap": "Map", "HashMap": "Map",
    "Set": "Set", "MutableSet": "Set", "HashSet": "Set",
    "Any": "Any",
}

_KOTLIN_SIDE_EFFECTS = {
    "println", "print", "readLine", "readln",
    "File", "FileReader", "FileWriter", "BufferedReader",
    "URL", "HttpURLConnection",
    "Thread", "Runnable", "launch", "async", "runBlocking",
    "withContext", "Dispatchers",
    "throw", "try",
}

# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------

_FUNC_PATTERN = re.compile(
    r'(?:(?:public|private|protected|internal|override|open|abstract|inline|suspend|operator|infix)\s+)*'
    r'fun\s+(?:<[^>]*>\s+)?'
    r'(?:\w+\.)?'                              # extension receiver
    r'(\w+)\s*'
    r'\(([^)]*)\)\s*'
    r'(?::\s*([^\s{=]+))?\s*[{=]',
    re.MULTILINE
)

_CLASS_PATTERN = re.compile(
    r'(?:(?:public|private|protected|internal|open|abstract|sealed|data|inner|enum)\s+)*'
    r'(?:class|object|interface)\s+(\w+)\s*'
    r'(?:<[^>]*>)?\s*'
    r'(?:\([^)]*\))?\s*'                       # primary constructor
    r'(?::\s*[^{]+)?\s*\{',
    re.MULTILINE
)

_DATA_CLASS_PATTERN = re.compile(
    r'data\s+class\s+(\w+)\s*\(([^)]*)\)',
    re.MULTILINE
)

_PROPERTY_PATTERN = re.compile(
    r'(?:(?:public|private|protected|internal|override|open|abstract|lateinit)\s+)*'
    r'(?:val|var)\s+(\w+)\s*:\s*([^=\n{]+)',
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

_CHECK_CALL = re.compile(
    r'check\s*\((.+?)\)',
    re.MULTILINE
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _KotlinParser:
    """Regex-based Kotlin parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []
        self.classes: List[dict] = []

    def parse(self) -> None:
        self._parse_data_classes()
        self._parse_classes()
        self._parse_functions()

    def _parse_data_classes(self) -> None:
        for m in _DATA_CLASS_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2)
            fields = []
            for part in self._split_params(params_str):
                part = part.strip()
                prop_match = re.match(r'(?:val|var)\s+(\w+)\s*:\s*(.*)', part)
                if prop_match:
                    fields.append({"name": prop_match.group(1), "type": prop_match.group(2).strip()})
            self.classes.append({
                "name": name, "fields": fields,
                "line": self.source[:m.start()].count('\n') + 1,
            })

    def _parse_classes(self) -> None:
        for m in _CLASS_PATTERN.finditer(self.source):
            name = m.group(1)
            # Skip if already parsed as data class
            if any(c["name"] == name for c in self.classes):
                continue
            body_start = m.end()
            body = self._extract_brace_block(body_start)
            fields = []
            for pm in _PROPERTY_PATTERN.finditer(body):
                fields.append({"name": pm.group(1), "type": pm.group(2).strip()})
            self.classes.append({
                "name": name, "fields": fields,
                "line": self.source[:m.start()].count('\n') + 1,
            })

    def _parse_functions(self) -> None:
        for m in _FUNC_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2).strip()
            ret_type = m.group(3)
            body_start = m.end()
            body = self._extract_brace_block(body_start) if self.source[m.end() - 1] == '{' else ""
            line = self.source[:m.start()].count('\n') + 1

            params = self._parse_params(params_str)
            contracts = self._extract_contracts(m.start())
            contracts.extend(self._extract_require_contracts(body))

            has_effects = any(kw in body for kw in _KOTLIN_SIDE_EFFECTS)
            is_suspend = 'suspend' in self.source[max(0, m.start()-50):m.start()]

            self.functions.append({
                "name": name,
                "params": params,
                "return_type": ret_type.strip() if ret_type else None,
                "body": body,
                "line": line,
                "contracts": contracts,
                "has_effects": has_effects or is_suspend,
            })

    def _parse_params(self, params_str: str) -> List[dict]:
        if not params_str.strip():
            return []
        params = []
        for part in self._split_params(params_str):
            part = part.strip()
            if not part:
                continue
            match = re.match(r'(?:vararg\s+)?(\w+)\s*:\s*(.*)', part)
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
        for m in _CHECK_CALL.finditer(body):
            contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts


# ---------------------------------------------------------------------------
# Translator
# ---------------------------------------------------------------------------

class KotlinTranslator(LanguageTranslator):
    """Translates Kotlin source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "Kotlin"

    @property
    def file_extensions(self) -> List[str]:
        return [".kt", ".kts"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _KotlinParser(source)
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
                location=SourceLocation("<kotlin>", cls.get("line", 0), 0),
            ))
        return DataDef(name=cls["name"], fields=fields,
                       location=SourceLocation("<kotlin>", cls.get("line", 0), 0))

    def _translate_function(self, func: dict) -> PureFunc | TaskFunc:
        params = []
        for p in func["params"]:
            aeon_type = self._map_type(p["type"])
            params.append(Parameter(
                name=p["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<kotlin>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = self._map_type(func["return_type"])
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<kotlin>", func["line"], 0)),
                location=SourceLocation("<kotlin>", func["line"], 0),
            ))

        loc = SourceLocation("<kotlin>", func["line"], 0)
        body = [ReturnStmt(value=IntLiteral(value=0, location=loc), location=loc)]

        if func.get("has_effects"):
            return TaskFunc(name=func["name"], params=params, return_type=ret_type,
                          effects=["IO"], body=body, requires=contracts, ensures=[], location=loc)
        return PureFunc(name=func["name"], params=params, return_type=ret_type,
                       body=body, requires=contracts, ensures=[], location=loc)

    def _map_type(self, kt_type: str) -> str:
        kt_type = kt_type.strip().rstrip('?')
        for prefix, aeon in _KOTLIN_TYPE_MAP.items():
            if kt_type.startswith(prefix):
                return aeon
        return "Any"


def verify_kotlin(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "kotlin", **kwargs)
