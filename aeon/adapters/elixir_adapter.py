"""AEON Elixir Language Adapter — Regex-based Elixir parser and translator.

Translates Elixir source code into AEON AST for formal verification.
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


_ELIXIR_TYPE_MAP: Dict[str, str] = {
    "integer": "Int", "float": "Float", "number": "Float",
    "string": "String", "binary": "String", "boolean": "Bool",
    "atom": "String", "list": "List", "map": "Any",
    "tuple": "Any", "pid": "Any", "reference": "Any",
    "port": "Any", "nil": "Void", "any": "Any",
    "term": "Any", "keyword": "List", "charlist": "String",
    "iodata": "String", "iolist": "List",
}

_ELIXIR_SIDE_EFFECTS = {
    "IO.", "File.", "Path.", "System.", "Port.",
    "Process.", "Agent.", "GenServer.", "Task.",
    "send", "receive", "spawn", ":gen_tcp", ":gen_udp",
    "Ecto.", "Repo.", "Logger.",
}

_DEF_PATTERN = re.compile(
    r'(?:@spec\s+\w+\(([^)]*)\)\s*::\s*(\w[\w.]*)\s*\n\s*)?'
    r'def\s+(\w+)\s*\(([^)]*)\)',
    re.MULTILINE
)

_DEFP_PATTERN = re.compile(
    r'defp\s+(\w+)\s*\(([^)]*)\)',
    re.MULTILINE
)

_MODULE_PATTERN = re.compile(
    r'defmodule\s+([\w.]+)\s+do',
    re.MULTILINE
)

_STRUCT_PATTERN = re.compile(
    r'defstruct\s+\[([^\]]*)\]',
    re.MULTILINE
)

_TYPEDOC_PATTERN = re.compile(
    r'@doc\s+"""(.*?)"""',
    re.DOTALL
)

_SPEC_PATTERN = re.compile(
    r'@spec\s+(\w+)\(([^)]*)\)\s*::\s*([\w\s.|{}\[\]()]+)',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'#\s*@(?:requires?|pre|ensures?|post|invariant)\s+(.*)',
    re.IGNORECASE
)

_GUARD_PATTERN = re.compile(
    r'when\s+(.+?)(?:\s+do|\s*,)',
    re.MULTILINE
)


class _ElixirParser:
    """Regex-based Elixir parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []
        self.modules: List[dict] = []
        self.structs: List[dict] = []

    def parse(self) -> None:
        self._parse_modules()
        self._parse_specs()
        self._parse_functions()

    def _parse_modules(self) -> None:
        for m in _MODULE_PATTERN.finditer(self.source):
            name = m.group(1)
            line = self.source[:m.start()].count('\n') + 1
            self.modules.append({"name": name, "line": line})

        for m in _STRUCT_PATTERN.finditer(self.source):
            fields_str = m.group(1)
            line = self.source[:m.start()].count('\n') + 1
            fields = []
            for part in fields_str.split(','):
                part = part.strip().lstrip(':')
                if part:
                    fields.append({"name": part, "type": "Any"})
            self.structs.append({"name": "Struct", "fields": fields, "line": line})

    def _parse_specs(self) -> None:
        self._specs: Dict[str, dict] = {}
        for m in _SPEC_PATTERN.finditer(self.source):
            name = m.group(1)
            params_str = m.group(2).strip()
            ret = m.group(3).strip()
            param_types = [p.strip() for p in params_str.split(',') if p.strip()] if params_str else []
            self._specs[name] = {"param_types": param_types, "return_type": ret}

    def _parse_functions(self) -> None:
        for pattern in [_DEF_PATTERN, _DEFP_PATTERN]:
            for m in pattern.finditer(self.source):
                groups = m.groups()
                if len(groups) == 4:
                    name = groups[2]
                    params_str = groups[3].strip()
                else:
                    name = groups[0]
                    params_str = groups[1].strip()

                body_start = m.end()
                body = self._extract_do_block(body_start)
                line = self.source[:m.start()].count('\n') + 1

                params = self._parse_params(params_str, name)
                contracts = self._extract_contracts(m.start())
                guards = self._extract_guards(self.source[m.start():m.end() + 50])
                contracts.extend(guards)

                has_effects = any(kw in body for kw in _ELIXIR_SIDE_EFFECTS)
                ret_type = self._specs.get(name, {}).get("return_type")

                self.functions.append({
                    "name": name,
                    "params": params,
                    "return_type": ret_type,
                    "body": body,
                    "line": line,
                    "contracts": contracts,
                    "has_effects": has_effects,
                })

    def _parse_params(self, params_str: str, func_name: str) -> List[dict]:
        if not params_str.strip():
            return []
        params = []
        spec = self._specs.get(func_name, {})
        spec_types = spec.get("param_types", [])

        for i, part in enumerate(self._split_params(params_str)):
            part = part.strip()
            if not part:
                continue
            pname = re.sub(r'\\\\.*', '', part).strip().lstrip('_')
            if not pname:
                pname = f"arg{i}"
            ptype = spec_types[i] if i < len(spec_types) else "any"
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

    def _extract_do_block(self, start: int) -> str:
        rest = self.source[start:]
        do_match = re.search(r'\bdo\b', rest)
        if not do_match:
            end_match = re.search(r'\bend\b', rest)
            return rest[:end_match.start()] if end_match else rest[:200]

        body_start = start + do_match.end()
        depth = 1
        i = body_start
        do_re = re.compile(r'\b(do|fn)\b')
        end_re = re.compile(r'\bend\b')
        while i < len(self.source) and depth > 0:
            rest_i = self.source[i:]
            dm = do_re.match(rest_i)
            em = end_re.match(rest_i)
            if dm:
                depth += 1
                i += len(dm.group())
            elif em:
                depth -= 1
                i += len(em.group())
            else:
                i += 1
        return self.source[body_start:max(body_start, i - 3)]

    def _extract_contracts(self, func_start: int) -> List[dict]:
        contracts = []
        lines_before = self.source[:func_start].split('\n')
        for line in reversed(lines_before[-8:]):
            m = _CONTRACT_PATTERN.match(line.strip())
            if m:
                contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts

    def _extract_guards(self, text: str) -> List[dict]:
        contracts = []
        for m in _GUARD_PATTERN.finditer(text):
            contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts


class ElixirTranslator(LanguageTranslator):
    """Translates Elixir source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "Elixir"

    @property
    def file_extensions(self) -> List[str]:
        return [".ex", ".exs"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _ElixirParser(source)
        parser.parse()
        declarations = []

        for s in parser.structs:
            fields = []
            for f in s["fields"]:
                fields.append(Parameter(
                    name=f["name"],
                    type_annotation=TypeAnnotation(name="Any"),
                    location=SourceLocation("<elixir>", s.get("line", 0), 0),
                ))
            declarations.append(DataDef(
                name=s["name"], fields=fields,
                location=SourceLocation("<elixir>", s.get("line", 0), 0),
            ))

        for f in parser.functions:
            declarations.append(self._translate_function(f))
        return Program(declarations=declarations)

    def _translate_function(self, func: dict) -> PureFunc | TaskFunc:
        params = []
        for p in func["params"]:
            aeon_type = _ELIXIR_TYPE_MAP.get(p["type"].lower(), "Any")
            params.append(Parameter(
                name=p["name"],
                type_annotation=TypeAnnotation(name=aeon_type),
                location=SourceLocation("<elixir>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = _ELIXIR_TYPE_MAP.get(func["return_type"].lower(), "Any")
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<elixir>", func["line"], 0)),
                location=SourceLocation("<elixir>", func["line"], 0),
            ))

        loc = SourceLocation("<elixir>", func["line"], 0)
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


def verify_elixir(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "elixir", **kwargs)
