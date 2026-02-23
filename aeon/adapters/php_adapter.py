"""AEON PHP Language Adapter — Regex-based PHP parser and translator.

Translates PHP source code into AEON AST for formal verification.
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
# PHP Type Map
# ---------------------------------------------------------------------------

_PHP_TYPE_MAP: Dict[str, str] = {
    "int": "Int", "integer": "Int",
    "float": "Float", "double": "Float",
    "bool": "Bool", "boolean": "Bool",
    "string": "String",
    "void": "Void",
    "array": "List",
    "null": "Void",
    "mixed": "Any",
    "object": "Any",
    "callable": "Any",
    "iterable": "List",
    "self": "Any",
    "static": "Any",
}

_PHP_SIDE_EFFECTS = {
    "echo", "print", "print_r", "var_dump", "var_export",
    "file_get_contents", "file_put_contents", "fopen", "fclose", "fwrite", "fread",
    "curl_init", "curl_exec",
    "mysqli_", "PDO", "pg_",
    "mail", "header", "setcookie",
    "session_start", "session_destroy",
    "exec", "shell_exec", "system", "passthru",
    "unlink", "rename", "mkdir", "rmdir",
}


# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------

_FUNC_PATTERN = re.compile(
    r'(?:(?:public|private|protected|static|abstract|final)\s+)*'
    r'function\s+(\w+)\s*'
    r'\(([^)]*)\)\s*'
    r'(?::\s*\??\s*(\w+))?\s*\{',
    re.MULTILINE
)

_CLASS_PATTERN = re.compile(
    r'(?:(?:abstract|final)\s+)?'
    r'class\s+(\w+)\s*'
    r'(?:extends\s+\w+)?\s*'
    r'(?:implements\s+[^{]+)?\s*\{',
    re.MULTILINE
)

_PROPERTY_PATTERN = re.compile(
    r'(?:(?:public|private|protected|static|readonly)\s+)*'
    r'(?:\??\w+\s+)?\$(\w+)\s*[;=]',
    re.MULTILINE
)

_TYPED_PROPERTY = re.compile(
    r'(?:(?:public|private|protected|static|readonly)\s+)*'
    r'(\??\w+)\s+\$(\w+)',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'(?:\*|//)\s*@(?:requires?|precondition|ensures?|postcondition|param\s+\S+\s+\S+\s+must)\s+(.*)',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _PHPParser:
    """Regex-based PHP parser."""

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
            for pm in _TYPED_PROPERTY.finditer(body):
                fields.append({"name": pm.group(2), "type": pm.group(1).lstrip('?')})
            if not fields:
                for pm in _PROPERTY_PATTERN.finditer(body):
                    fields.append({"name": pm.group(1), "type": "mixed"})
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
            body = self._extract_brace_block(body_start)
            line = self.source[:m.start()].count('\n') + 1

            params = self._parse_params(params_str)
            contracts = self._extract_contracts(m.start())
            has_effects = any(kw in body for kw in _PHP_SIDE_EFFECTS)

            self.functions.append({
                "name": name, "params": params,
                "return_type": ret_type, "body": body,
                "line": line, "contracts": contracts,
                "has_effects": has_effects,
            })

    def _parse_params(self, params_str: str) -> List[dict]:
        if not params_str.strip():
            return []
        params = []
        for part in params_str.split(','):
            part = part.strip()
            if not part:
                continue
            # PHP param: ?Type $name or $name or Type $name = default
            match = re.match(r'(?:(\??\w+)\s+)?\$(\w+)', part)
            if match:
                ptype = match.group(1) or "mixed"
                params.append({"name": match.group(2), "type": ptype.lstrip('?')})
        return params

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
        for line in reversed(lines_before[-10:]):
            m = _CONTRACT_PATTERN.match(line.strip())
            if m:
                contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts


# ---------------------------------------------------------------------------
# Translator
# ---------------------------------------------------------------------------

class PHPTranslator(LanguageTranslator):
    """Translates PHP source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "PHP"

    @property
    def file_extensions(self) -> List[str]:
        return [".php"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _PHPParser(source)
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
                location=SourceLocation("<php>", cls.get("line", 0), 0),
            ))
        return DataDef(name=cls["name"], fields=fields,
                       location=SourceLocation("<php>", cls.get("line", 0), 0))

    def _translate_function(self, func: dict) -> PureFunc | TaskFunc:
        params = []
        for p in func["params"]:
            aeon_type = self._map_type(p["type"])
            params.append(Parameter(
                name=p["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<php>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = self._map_type(func["return_type"])
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<php>", func["line"], 0)),
                location=SourceLocation("<php>", func["line"], 0),
            ))

        loc = SourceLocation("<php>", func["line"], 0)
        body = [ReturnStmt(value=IntLiteral(value=0, location=loc), location=loc)]

        if func.get("has_effects"):
            return TaskFunc(name=func["name"], params=params, return_type=ret_type,
                          effects=["IO"], body=body, requires=contracts, ensures=[], location=loc)
        return PureFunc(name=func["name"], params=params, return_type=ret_type,
                       body=body, requires=contracts, ensures=[], location=loc)

    def _map_type(self, php_type: str) -> str:
        php_type = php_type.strip().lstrip('?').lower()
        return _PHP_TYPE_MAP.get(php_type, "Any")


def verify_php(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "php", **kwargs)
