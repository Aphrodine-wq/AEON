"""AEON Haskell Language Adapter — Regex-based Haskell parser and translator.

Translates Haskell source code into AEON AST for formal verification.
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


_HASKELL_TYPE_MAP: Dict[str, str] = {
    "int": "Int", "integer": "Int", "word": "Int",
    "float": "Float", "double": "Float", "rational": "Float",
    "bool": "Bool", "char": "String", "string": "String",
    "text": "String", "bytestring": "String",
    "void": "Void", "()" : "Void", "unit": "Void",
    "maybe": "Optional", "either": "Result",
    "io": "IO", "stm": "IO", "st": "IO",
    "[": "List", "list": "List", "vector": "List",
    "map": "Any", "set": "Any", "hashmap": "Any",
}

_HASKELL_EFFECT_TYPES = {
    "IO", "STM", "ST", "MVar", "IORef", "TVar",
    "Handle", "Socket", "Chan", "TChan",
}

_TYPE_SIG_PATTERN = re.compile(
    r'^(\w+)\s*::\s*(.+)$',
    re.MULTILINE
)

_FUNC_DEF_PATTERN = re.compile(
    r'^(\w+)\s+((?:\w+\s+)*\w+)\s*=',
    re.MULTILINE
)

_FUNC_NO_ARGS_PATTERN = re.compile(
    r'^(\w+)\s*=\s*(?!.*::)',
    re.MULTILINE
)

_DATA_PATTERN = re.compile(
    r'^data\s+(\w+)(?:\s+\w+)*\s*=\s*(.+?)(?:\n\S|\Z)',
    re.MULTILINE | re.DOTALL
)

_NEWTYPE_PATTERN = re.compile(
    r'^newtype\s+(\w+)(?:\s+\w+)*\s*=\s*(\w+)\s+(\w+)',
    re.MULTILINE
)

_CLASS_PATTERN = re.compile(
    r'^class\s+(?:.*?=>\s*)?(\w+)\s+(\w+)',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'--\s*@(?:requires?|pre|ensures?|post|invariant|prop)\s+(.*)',
    re.IGNORECASE
)

_LIQUID_PATTERN = re.compile(
    r'\{-@\s*(.*?)\s*@-\}',
    re.DOTALL
)


class _HaskellParser:
    """Regex-based Haskell parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []
        self.data_types: List[dict] = []
        self._type_sigs: Dict[str, str] = {}

    def parse(self) -> None:
        self._parse_type_signatures()
        self._parse_data_types()
        self._parse_functions()

    def _parse_type_signatures(self) -> None:
        for m in _TYPE_SIG_PATTERN.finditer(self.source):
            name = m.group(1)
            sig = m.group(2).strip()
            if name[0].islower():  # Functions start lowercase in Haskell
                self._type_sigs[name] = sig

    def _parse_data_types(self) -> None:
        for m in _DATA_PATTERN.finditer(self.source):
            name = m.group(1)
            body = m.group(2).strip()
            line = self.source[:m.start()].count('\n') + 1
            constructors = []
            for ctor in body.split('|'):
                ctor = ctor.strip()
                parts = ctor.split()
                if parts:
                    constructors.append({"name": parts[0], "fields": parts[1:]})
            self.data_types.append({
                "name": name, "constructors": constructors, "line": line
            })

        for m in _NEWTYPE_PATTERN.finditer(self.source):
            name = m.group(1)
            ctor = m.group(2)
            field_type = m.group(3)
            line = self.source[:m.start()].count('\n') + 1
            self.data_types.append({
                "name": name,
                "constructors": [{"name": ctor, "fields": [field_type]}],
                "line": line
            })

    def _parse_functions(self) -> None:
        seen = set()
        for m in _FUNC_DEF_PATTERN.finditer(self.source):
            name = m.group(1)
            if name in seen or name[0].isupper() or name in ('module', 'import', 'data', 'type', 'newtype', 'class', 'instance', 'where', 'let', 'in', 'if', 'then', 'else', 'case', 'of', 'do'):
                continue
            seen.add(name)

            args_str = m.group(2).strip()
            line = self.source[:m.start()].count('\n') + 1
            body = self._extract_function_body(m.end())
            type_sig = self._type_sigs.get(name, "")
            params = self._parse_params_from_sig(args_str, type_sig)
            ret_type = self._extract_return_type(type_sig)
            contracts = self._extract_contracts(m.start())
            contracts.extend(self._extract_liquid_contracts(m.start()))

            has_effects = any(eff in type_sig for eff in _HASKELL_EFFECT_TYPES)

            self.functions.append({
                "name": name,
                "params": params,
                "return_type": ret_type,
                "body": body,
                "line": line,
                "contracts": contracts,
                "has_effects": has_effects,
                "type_sig": type_sig,
            })

    def _parse_params_from_sig(self, args_str: str, type_sig: str) -> List[dict]:
        arg_names = [a.strip() for a in args_str.split() if a.strip() and a.strip() != '=']
        param_types = []
        if type_sig:
            parts = [p.strip() for p in type_sig.split('->')]
            param_types = parts[:-1] if len(parts) > 1 else []

        params = []
        for i, name in enumerate(arg_names):
            ptype = param_types[i].strip() if i < len(param_types) else "Any"
            params.append({"name": name, "type": ptype})
        return params

    def _extract_return_type(self, type_sig: str) -> Optional[str]:
        if not type_sig:
            return None
        parts = [p.strip() for p in type_sig.split('->')]
        if len(parts) >= 2:
            ret = parts[-1].strip()
            ret = re.sub(r'^IO\s+', '', ret)
            ret = re.sub(r'^\(|\)$', '', ret)
            return ret
        return None

    def _extract_function_body(self, start: int) -> str:
        lines = self.source[start:].split('\n')
        body_lines = []
        for line in lines:
            if line and not line[0].isspace() and body_lines:
                break
            body_lines.append(line)
        return '\n'.join(body_lines[:50])

    def _extract_contracts(self, func_start: int) -> List[dict]:
        contracts = []
        lines_before = self.source[:func_start].split('\n')
        for line in reversed(lines_before[-8:]):
            m = _CONTRACT_PATTERN.match(line.strip())
            if m:
                contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts

    def _extract_liquid_contracts(self, func_start: int) -> List[dict]:
        contracts = []
        region = self.source[max(0, func_start - 500):func_start]
        for m in _LIQUID_PATTERN.finditer(region):
            text = m.group(1).strip()
            if text:
                contracts.append({"kind": "ensures", "expr": text})
        return contracts


class HaskellTranslator(LanguageTranslator):
    """Translates Haskell source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "Haskell"

    @property
    def file_extensions(self) -> List[str]:
        return [".hs", ".lhs"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _HaskellParser(source)
        parser.parse()
        declarations = []

        for dt in parser.data_types:
            fields = []
            for ctor in dt["constructors"]:
                for i, ftype in enumerate(ctor.get("fields", [])):
                    fields.append(Parameter(
                        name=f"{ctor['name']}_{i}",
                        type_annotation=TypeAnnotation(name=self._map_type(ftype)),
                        location=SourceLocation("<haskell>", dt.get("line", 0), 0),
                    ))
            declarations.append(DataDef(
                name=dt["name"], fields=fields,
                location=SourceLocation("<haskell>", dt.get("line", 0), 0),
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
                location=SourceLocation("<haskell>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = self._map_type(func["return_type"])
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<haskell>", func["line"], 0)),
                location=SourceLocation("<haskell>", func["line"], 0),
            ))

        loc = SourceLocation("<haskell>", func["line"], 0)
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

    def _map_type(self, hs_type: str) -> str:
        hs_type = hs_type.strip().strip('(').strip(')')
        lower = hs_type.lower().split()[0] if hs_type else ""
        for prefix, aeon in _HASKELL_TYPE_MAP.items():
            if lower.startswith(prefix):
                return aeon
        return "Any"


def verify_haskell(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "haskell", **kwargs)
