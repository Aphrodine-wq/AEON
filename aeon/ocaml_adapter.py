"""AEON OCaml Language Adapter — Regex-based OCaml parser and translator.

Translates OCaml source code into AEON AST for formal verification.
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


_OCAML_TYPE_MAP: Dict[str, str] = {
    "int": "Int", "float": "Float", "bool": "Bool",
    "string": "String", "char": "String", "bytes": "String",
    "unit": "Void", "list": "List", "array": "List",
    "option": "Optional", "result": "Result",
    "ref": "Any", "hashtbl": "Any", "map": "Any", "set": "Any",
}

_OCAML_SIDE_EFFECTS = {
    "print_", "Printf.", "Format.", "prerr_", "output_",
    "input_", "open_in", "open_out", "close_",
    "Unix.", "Sys.", "Filename.",
    "ref", ":=", "!",
    "Lwt.", "Async.",
    "Mutex.", "Thread.",
}

_LET_PATTERN = re.compile(
    r'^let\s+(?:rec\s+)?(\w+)\s+((?:\(?[\w:~?*]+\)?\s+)*)\s*(?::\s*([^=]+?))?\s*=',
    re.MULTILINE
)

_VAL_PATTERN = re.compile(
    r'^val\s+(\w+)\s*:\s*(.+)$',
    re.MULTILINE
)

_TYPE_PATTERN = re.compile(
    r'^type\s+(?:\'?\w+\s+)*(\w+)\s*=\s*(.+?)(?:\n\S|\nlet\s|\ntype\s|\Z)',
    re.MULTILINE | re.DOTALL
)

_MODULE_PATTERN = re.compile(
    r'^module\s+(\w+)',
    re.MULTILINE
)

_CONTRACT_PATTERN = re.compile(
    r'\(\*\s*@(?:requires?|pre|ensures?|post|invariant)\s+(.*?)\s*\*\)',
    re.IGNORECASE | re.DOTALL
)

_ASSERT_PATTERN = re.compile(
    r'assert\s*\((.+?)\)',
    re.MULTILINE
)


class _OCamlParser:
    """Regex-based OCaml parser."""

    def __init__(self, source: str):
        self.source = source
        self.functions: List[dict] = []
        self.types: List[dict] = []
        self._val_sigs: Dict[str, str] = {}

    def parse(self) -> None:
        self._parse_val_signatures()
        self._parse_types()
        self._parse_functions()

    def _parse_val_signatures(self) -> None:
        for m in _VAL_PATTERN.finditer(self.source):
            self._val_sigs[m.group(1)] = m.group(2).strip()

    def _parse_types(self) -> None:
        for m in _TYPE_PATTERN.finditer(self.source):
            name = m.group(1)
            body = m.group(2).strip()
            line = self.source[:m.start()].count('\n') + 1

            if '{' in body:
                # Record type
                fields = []
                for fm in re.finditer(r'(\w+)\s*:\s*([\w.\s()\'*]+)', body):
                    fields.append({"name": fm.group(1), "type": fm.group(2).strip()})
                self.types.append({"name": name, "fields": fields, "line": line})
            elif '|' in body:
                # Variant type
                fields = []
                for variant in body.split('|'):
                    variant = variant.strip()
                    if variant:
                        parts = variant.split()
                        vname = parts[0] if parts else variant
                        fields.append({"name": vname, "type": "Any"})
                self.types.append({"name": name, "fields": fields, "line": line})

    def _parse_functions(self) -> None:
        seen = set()
        for m in _LET_PATTERN.finditer(self.source):
            name = m.group(1)
            if name in seen or name in ('_', 'main'):
                if name == 'main':
                    pass  # Allow main
                elif name in seen:
                    continue
            seen.add(name)

            args_str = m.group(2).strip()
            type_annot = m.group(3)
            if not args_str and not type_annot:
                # Value binding, not a function (unless it has a function type)
                sig = self._val_sigs.get(name, "")
                if '->' not in sig:
                    continue

            line = self.source[:m.start()].count('\n') + 1
            body = self._extract_body(m.end())
            sig = self._val_sigs.get(name, type_annot or "")

            params = self._parse_params(args_str, sig)
            ret_type = self._extract_return_type(sig)
            contracts = self._extract_contracts(m.start())

            has_effects = any(kw in body for kw in _OCAML_SIDE_EFFECTS)
            if sig and any(eff in sig for eff in ('Lwt.t', 'Async', 'IO', 'ref')):
                has_effects = True

            self.functions.append({
                "name": name,
                "params": params,
                "return_type": ret_type,
                "body": body,
                "line": line,
                "contracts": contracts,
                "has_effects": has_effects,
            })

    def _parse_params(self, args_str: str, type_sig: str) -> List[dict]:
        if not args_str.strip():
            if type_sig and '->' in type_sig:
                parts = [p.strip() for p in type_sig.split('->')]
                return [{"name": f"arg{i}", "type": p} for i, p in enumerate(parts[:-1])]
            return []

        params = []
        sig_types = []
        if type_sig and '->' in type_sig:
            sig_types = [p.strip() for p in type_sig.split('->')]
            sig_types = sig_types[:-1]

        for i, part in enumerate(args_str.split()):
            part = part.strip().strip('(').strip(')')
            if not part or part == '()':
                continue
            if ':' in part:
                name_type = part.split(':')
                pname = name_type[0].strip()
                ptype = name_type[1].strip() if len(name_type) > 1 else "Any"
            else:
                pname = part
                ptype = sig_types[i] if i < len(sig_types) else "Any"
            params.append({"name": pname, "type": ptype})
        return params

    def _extract_return_type(self, type_sig: str) -> Optional[str]:
        if not type_sig or '->' not in type_sig:
            return None
        parts = [p.strip() for p in type_sig.split('->')]
        return parts[-1] if parts else None

    def _extract_body(self, start: int) -> str:
        rest = self.source[start:]
        lines = rest.split('\n')
        body_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('let ') and not stripped.startswith('let rec'):
                if body_lines:
                    break
            if stripped.startswith(';;'):
                break
            body_lines.append(line)
            if len(body_lines) > 50:
                break
        return '\n'.join(body_lines)

    def _extract_contracts(self, func_start: int) -> List[dict]:
        contracts = []
        region = self.source[max(0, func_start - 500):func_start]
        for m in _CONTRACT_PATTERN.finditer(region):
            contracts.append({"kind": "requires", "expr": m.group(1).strip()})
        return contracts


class OCamlTranslator(LanguageTranslator):
    """Translates OCaml source code into AEON AST."""

    @property
    def language_name(self) -> str:
        return "OCaml"

    @property
    def file_extensions(self) -> List[str]:
        return [".ml", ".mli"]

    @property
    def noise_patterns(self) -> List[str]:
        return ["Failed to register", "not defined", "Runtime"]

    def translate(self, source: str) -> Program:
        parser = _OCamlParser(source)
        parser.parse()
        declarations = []

        for t in parser.types:
            fields = []
            for f in t["fields"]:
                aeon_type = self._map_type(f["type"])
                fields.append(Parameter(
                    name=f["name"],
                    type_annotation=TypeAnnotation(name=aeon_type),
                    location=SourceLocation("<ocaml>", t.get("line", 0), 0),
                ))
            declarations.append(DataDef(
                name=t["name"], fields=fields,
                location=SourceLocation("<ocaml>", t.get("line", 0), 0),
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
                location=SourceLocation("<ocaml>", func["line"], 0),
            ))

        ret_type = None
        if func["return_type"]:
            mapped = self._map_type(func["return_type"])
            ret_type = TypeAnnotation(name=mapped)

        contracts = []
        for c in func.get("contracts", []):
            contracts.append(ContractClause(
                kind=c["kind"],
                expr=Identifier(name=c["expr"], location=SourceLocation("<ocaml>", func["line"], 0)),
                location=SourceLocation("<ocaml>", func["line"], 0),
            ))

        loc = SourceLocation("<ocaml>", func["line"], 0)
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

    def _map_type(self, ml_type: str) -> str:
        ml_type = ml_type.strip()
        lower = ml_type.lower().split()[0] if ml_type else ""
        # Strip type parameters
        lower = lower.strip("'").strip("(").strip(")")
        for prefix, aeon in _OCAML_TYPE_MAP.items():
            if lower.startswith(prefix) or lower.endswith(prefix):
                return aeon
        return "Any"


def verify_ocaml(source: str, **kwargs) -> "VerificationResult":
    from aeon.language_adapter import verify
    return verify(source, "ocaml", **kwargs)
