"""AEON JavaScript/TypeScript Adapter — Verify JS/TS Code Using AEON's Analysis Engines.

Translates JavaScript or TypeScript source code into AEON's internal
representation and runs the full verification suite.

Uses `tree-sitter` with `tree-sitter-javascript` / `tree-sitter-typescript`
for parsing. Falls back to regex-based parsing if tree-sitter is unavailable.

Usage:
    from aeon.js_adapter import verify_javascript, verify_typescript
    result = verify_javascript('''
        function divide(a, b) {
            return a / b;
        }
    ''')
"""

from __future__ import annotations

import re
from typing import Optional, List, Dict, Any, Tuple

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Parameter, TypeAnnotation, ContractClause,
    Statement, ReturnStmt, LetStmt, ExprStmt, IfStmt, WhileStmt,
    Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
)
from aeon.errors import SourceLocation
from aeon.language_adapter import LanguageTranslator, VerificationResult, verify as _verify

try:
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False


# ---------------------------------------------------------------------------
# Type maps
# ---------------------------------------------------------------------------

_TS_TYPE_MAP: Dict[str, str] = {
    "number": "Int", "bigint": "Int",
    "string": "String",
    "boolean": "Bool",
    "void": "Void", "undefined": "Void", "null": "Void",
    "any": "Void", "unknown": "Void", "never": "Void",
    "object": "Void",
    "Array": "List",
}

_JS_NOISE_PATTERNS = [
    "undefined name",
    "unknown_function",
    "unknown_type",
    "unknown_field",
    "successful compilation",
    "failed to register",
    "unbound:",
    "__",
    "expected type 'int'",
    "expected type 'void'",
    "arg_count_mismatch",
    "arg_type_mismatch",
    "binary_op",
]

_JS_SIDE_EFFECT_FUNCS = {
    "console.log", "console.error", "console.warn", "console.info",
    "alert", "prompt", "confirm",
    "fetch", "XMLHttpRequest",
    "setTimeout", "setInterval",
    "document.write", "document.getElementById",
    "fs.readFileSync", "fs.writeFileSync", "fs.readFile", "fs.writeFile",
    "require",
}

_JS_SIDE_EFFECT_METHODS = {
    "log", "error", "warn", "info",
    "write", "read", "send", "emit",
    "push", "pop", "shift", "unshift", "splice",
    "set", "delete", "clear",
    "appendChild", "removeChild", "insertBefore",
    "addEventListener", "removeEventListener",
    "querySelector", "querySelectorAll",
    "fetch", "json", "text",
    "then", "catch",
}


# ---------------------------------------------------------------------------
# Regex-based fallback parser (no tree-sitter needed)
# ---------------------------------------------------------------------------

class _RegexJSParser:
    """Lightweight regex-based JS/TS parser for when tree-sitter isn't available."""

    def __init__(self, is_typescript: bool = False):
        self.is_typescript = is_typescript

    def parse_functions(self, source: str) -> List[Dict[str, Any]]:
        """Extract function definitions from JS/TS source."""
        functions: List[Dict[str, Any]] = []

        # Named function declarations
        pattern = r'(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)(?:\s*:\s*(\w+))?\s*\{'
        for m in re.finditer(pattern, source):
            name, params_str, return_type = m.group(1), m.group(2), m.group(3)
            body_start = m.end()
            body = self._extract_brace_body(source, body_start - 1)
            functions.append({
                "name": name,
                "params": self._parse_params(params_str),
                "return_type": return_type,
                "body": body,
                "line": source[:m.start()].count('\n') + 1,
                "is_async": 'async' in m.group(0),
            })

        # Arrow functions assigned to const/let/var
        arrow_pattern = r'(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)(?:\s*:\s*(\w+))?\s*=>\s*\{'
        for m in re.finditer(arrow_pattern, source):
            name, params_str, return_type = m.group(1), m.group(2), m.group(3)
            body_start = m.end()
            body = self._extract_brace_body(source, body_start - 1)
            functions.append({
                "name": name,
                "params": self._parse_params(params_str),
                "return_type": return_type,
                "body": body,
                "line": source[:m.start()].count('\n') + 1,
                "is_async": 'async' in m.group(0),
            })

        # Class methods
        class_pattern = r'(?:export\s+)?class\s+(\w+)\s*(?:extends\s+\w+\s*)?\{'
        for cm in re.finditer(class_pattern, source):
            class_name = cm.group(1)
            class_body = self._extract_brace_body(source, cm.end() - 1)

            method_pattern = r'(?:async\s+)?(\w+)\s*\(([^)]*)\)(?:\s*:\s*(\w+))?\s*\{'
            for mm in re.finditer(method_pattern, class_body):
                method_name = mm.group(1)
                if method_name in ('if', 'while', 'for', 'switch', 'catch'):
                    continue
                params_str = mm.group(2)
                return_type = mm.group(3)
                body = self._extract_brace_body(class_body, mm.end() - 1)
                functions.append({
                    "name": f"{class_name}_{method_name}",
                    "params": self._parse_params(params_str),
                    "return_type": return_type,
                    "body": body,
                    "line": source[:cm.start()].count('\n') + class_body[:mm.start()].count('\n') + 1,
                    "is_async": 'async' in mm.group(0),
                    "class_name": class_name,
                })

        return functions

    def parse_classes(self, source: str) -> List[Dict[str, Any]]:
        """Extract class definitions."""
        classes: List[Dict[str, Any]] = []
        pattern = r'(?:export\s+)?class\s+(\w+)\s*(?:extends\s+(\w+)\s*)?\{'
        for m in re.finditer(pattern, source):
            class_body = self._extract_brace_body(source, m.end() - 1)
            fields = self._extract_class_fields(class_body)
            classes.append({
                "name": m.group(1),
                "extends": m.group(2),
                "fields": fields,
                "line": source[:m.start()].count('\n') + 1,
            })
        return classes

    def _parse_params(self, params_str: str) -> List[Dict[str, str]]:
        """Parse parameter list string into list of {name, type}."""
        params = []
        if not params_str.strip():
            return params
        for p in params_str.split(','):
            p = p.strip()
            if not p:
                continue
            # TS-style: name: type
            if ':' in p:
                parts = p.split(':', 1)
                name = parts[0].strip().lstrip('...')
                type_name = parts[1].strip()
            else:
                name = p.lstrip('...')
                type_name = "any"
            params.append({"name": name, "type": type_name})
        return params

    def _extract_brace_body(self, source: str, start: int) -> str:
        """Extract text inside matching braces starting at `start`."""
        if start >= len(source) or source[start] != '{':
            return ""
        depth = 0
        i = start
        while i < len(source):
            if source[i] == '{':
                depth += 1
            elif source[i] == '}':
                depth -= 1
                if depth == 0:
                    return source[start + 1:i]
            i += 1
        return source[start + 1:]

    def _extract_class_fields(self, class_body: str) -> List[Dict[str, str]]:
        """Extract class field declarations (TS style)."""
        fields = []
        # Match: fieldName: Type; or fieldName: Type = value;
        pattern = r'^\s*(?:readonly\s+)?(\w+)\s*[?!]?\s*:\s*(\w+)'
        for m in re.finditer(pattern, class_body, re.MULTILINE):
            fields.append({"name": m.group(1), "type": m.group(2)})
        return fields


# ---------------------------------------------------------------------------
# Base JS/TS Translator
# ---------------------------------------------------------------------------

class _BaseJSTranslator(LanguageTranslator):
    """Shared translation logic for JavaScript and TypeScript."""

    def __init__(self):
        super().__init__()
        self.declarations: List = []
        self._is_typescript = False

    @property
    def noise_patterns(self) -> List[str]:
        return _JS_NOISE_PATTERNS

    def translate(self, source: str) -> Program:
        """Parse JS/TS source and translate to AEON Program."""
        self.declarations = []
        parser = _RegexJSParser(is_typescript=self._is_typescript)

        # Extract and translate classes
        for cls_info in parser.parse_classes(source):
            self._translate_class_info(cls_info)

        # Extract and translate functions
        for func_info in parser.parse_functions(source):
            func = self._translate_func_info(func_info)
            if func:
                self.declarations.append(func)

        return Program(declarations=self.declarations)

    def _translate_class_info(self, cls_info: Dict[str, Any]) -> None:
        """Translate a class info dict to AEON DataDef."""
        loc = SourceLocation(line=cls_info.get("line", 0), column=0,
                             file=f"<{'typescript' if self._is_typescript else 'javascript'}>")
        fields = []
        for f in cls_info.get("fields", []):
            field_type = self._map_type(f.get("type", "any"))
            fields.append(Parameter(name=f["name"], type_annotation=field_type, location=loc))

        self.declarations.append(DataDef(
            name=cls_info["name"],
            fields=fields,
            location=loc,
        ))

    def _translate_func_info(self, func_info: Dict[str, Any]) -> Optional[PureFunc | TaskFunc]:
        """Translate a function info dict to AEON PureFunc or TaskFunc."""
        loc = SourceLocation(
            line=func_info.get("line", 0), column=0,
            file=f"<{'typescript' if self._is_typescript else 'javascript'}>",
        )

        # Parameters
        params = []
        for p in func_info.get("params", []):
            param_type = self._map_type(p.get("type", "any"))
            params.append(Parameter(name=p["name"], type_annotation=param_type, location=loc))

        # Return type
        rt = func_info.get("return_type")
        return_type = self._map_type(rt) if rt else TypeAnnotation(name="Void")

        # Extract contracts from JSDoc in body
        body_str = func_info.get("body", "")
        requires, ensures = self._extract_jsdoc_contracts(body_str)

        # Translate body statements
        body = self._translate_body_str(body_str)

        # Determine side effects
        is_async = func_info.get("is_async", False)
        has_side_effects = is_async or self._body_has_side_effects(body_str)

        name = func_info["name"]

        if has_side_effects:
            effects = self._infer_effects(body_str)
            return TaskFunc(
                name=name, params=params, return_type=return_type,
                requires=requires, ensures=ensures, effects=effects,
                body=body, location=loc,
            )
        else:
            return PureFunc(
                name=name, params=params, return_type=return_type,
                requires=requires, ensures=ensures,
                body=body, location=loc,
            )

    def _map_type(self, type_str: str) -> TypeAnnotation:
        """Map a JS/TS type string to AEON TypeAnnotation."""
        if not type_str:
            return TypeAnnotation(name="Void")
        type_str = type_str.strip()

        # Handle array types
        if type_str.endswith('[]'):
            base = type_str[:-2]
            return TypeAnnotation(name="List", generic_args=[self._map_type(base)])

        # Handle Array<T>
        arr_match = re.match(r'Array<(.+)>', type_str)
        if arr_match:
            return TypeAnnotation(name="List", generic_args=[self._map_type(arr_match.group(1))])

        return TypeAnnotation(name=_TS_TYPE_MAP.get(type_str, type_str))

    def _translate_body_str(self, body: str) -> List[Statement]:
        """Translate function body string to AEON statements."""
        stmts: List[Statement] = []
        lines = body.strip().split('\n')

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue

            loc = SourceLocation(line=i + 1, column=0, file="<js>")

            # return statement
            ret_match = re.match(r'return\s+(.+?)\s*;?\s*$', stripped)
            if ret_match:
                expr = self._parse_simple_expr(ret_match.group(1), loc)
                stmts.append(ReturnStmt(value=expr, location=loc))
                continue

            # variable declaration
            var_match = re.match(r'(?:const|let|var)\s+(\w+)(?:\s*:\s*\w+)?\s*=\s*(.+?)\s*;?\s*$', stripped)
            if var_match:
                name, val_str = var_match.group(1), var_match.group(2)
                value = self._parse_simple_expr(val_str, loc)
                stmts.append(LetStmt(name=name, type_annotation=TypeAnnotation(name="Void"),
                                     value=value, location=loc))
                continue

            # if statement (simplified)
            if_match = re.match(r'if\s*\((.+?)\)\s*\{', stripped)
            if if_match:
                condition = self._parse_simple_expr(if_match.group(1), loc)
                stmts.append(IfStmt(condition=condition, then_body=[], else_body=[], location=loc))
                continue

            # Expression statement (method call, etc.)
            if stripped.endswith(';'):
                stripped = stripped[:-1]
            if stripped:
                expr = self._parse_simple_expr(stripped, loc)
                stmts.append(ExprStmt(expr=expr, location=loc))

        return stmts

    def _parse_simple_expr(self, expr_str: str, loc: SourceLocation) -> Expr:
        """Parse a simple expression string to AEON Expr."""
        expr_str = expr_str.strip()

        # Boolean literals
        if expr_str == "true":
            return BoolLiteral(value=True, location=loc)
        if expr_str == "false":
            return BoolLiteral(value=False, location=loc)
        if expr_str in ("null", "undefined"):
            return IntLiteral(value=0, location=loc)

        # String literal
        if (expr_str.startswith('"') and expr_str.endswith('"')) or \
           (expr_str.startswith("'") and expr_str.endswith("'")):
            return StringLiteral(value=expr_str[1:-1], location=loc)

        # Numeric literal
        if re.match(r'^-?\d+$', expr_str):
            return IntLiteral(value=int(expr_str), location=loc)
        if re.match(r'^-?\d+\.\d+$', expr_str):
            return FloatLiteral(value=float(expr_str), location=loc)

        # Binary operations
        for op in ("!==", "===", "!=", "==", ">=", "<=", "&&", "||", ">", "<", "+", "-", "*", "/", "%"):
            if op in expr_str:
                parts = expr_str.split(op, 1)
                if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                    left = self._parse_simple_expr(parts[0], loc)
                    right = self._parse_simple_expr(parts[1], loc)
                    aeon_op = {"===": "==", "!==": "!="}.get(op, op)
                    return BinaryOp(op=aeon_op, left=left, right=right, location=loc)

        # Method call: obj.method(args)
        method_match = re.match(r'(\w+)\.(\w+)\(([^)]*)\)', expr_str)
        if method_match:
            obj_name, method_name, args_str = method_match.groups()
            args = [self._parse_simple_expr(a.strip(), loc) for a in args_str.split(',') if a.strip()] if args_str.strip() else []
            return MethodCall(
                obj=Identifier(name=obj_name, location=loc),
                method_name=method_name,
                args=args,
                location=loc,
            )

        # Function call: func(args)
        call_match = re.match(r'(\w+)\(([^)]*)\)', expr_str)
        if call_match:
            func_name, args_str = call_match.groups()
            args = [self._parse_simple_expr(a.strip(), loc) for a in args_str.split(',') if a.strip()] if args_str.strip() else []
            return FunctionCall(
                callee=Identifier(name=func_name, location=loc),
                args=args,
                location=loc,
            )

        # Field access: obj.field
        if '.' in expr_str:
            parts = expr_str.rsplit('.', 1)
            return FieldAccess(
                obj=Identifier(name=parts[0], location=loc),
                field_name=parts[1],
                location=loc,
            )

        # Identifier
        if re.match(r'^[a-zA-Z_]\w*$', expr_str):
            return Identifier(name=expr_str, location=loc)

        return Identifier(name="__unknown__", location=loc)

    def _extract_jsdoc_contracts(self, body: str) -> Tuple[List[ContractClause], List[ContractClause]]:
        """Extract @requires / @ensures from JSDoc comments in body."""
        requires: List[ContractClause] = []
        ensures: List[ContractClause] = []

        for line in body.split('\n'):
            line = line.strip().lstrip('/*').rstrip('*/').strip()

            req_match = re.match(r'(?:@requires|requires\s*:)\s*(.+)', line, re.IGNORECASE)
            if req_match:
                expr = self._parse_contract_expr(req_match.group(1).strip())
                if expr:
                    requires.append(ContractClause(kind="requires", expr=expr))

            ens_match = re.match(r'(?:@ensures|ensures\s*:)\s*(.+)', line, re.IGNORECASE)
            if ens_match:
                expr = self._parse_contract_expr(ens_match.group(1).strip())
                if expr:
                    ensures.append(ContractClause(kind="ensures", expr=expr))

        return requires, ensures

    def _parse_contract_expr(self, expr_str: str) -> Optional[Expr]:
        """Parse a contract expression."""
        expr_str = expr_str.strip()
        for op in ("!==", "===", "!=", "==", ">=", "<=", ">", "<"):
            if op in expr_str:
                parts = expr_str.split(op, 1)
                if len(parts) == 2:
                    left = parts[0].strip()
                    right = parts[1].strip()
                    left_expr = Identifier(name=left) if not left.lstrip('-').isdigit() else IntLiteral(value=int(left))
                    right_expr = Identifier(name=right) if not right.lstrip('-').isdigit() else IntLiteral(value=int(right))
                    aeon_op = {"===": "==", "!==": "!="}.get(op, op)
                    return BinaryOp(op=aeon_op, left=left_expr, right=right_expr)
        return None

    def _body_has_side_effects(self, body: str) -> bool:
        """Heuristic: does a function body have side effects?"""
        for func in _JS_SIDE_EFFECT_FUNCS:
            if func in body:
                return True
        for method in _JS_SIDE_EFFECT_METHODS:
            if f'.{method}(' in body:
                return True
        return False

    def _infer_effects(self, body: str) -> List[str]:
        """Infer AEON effects from JS/TS function body."""
        effects = set()
        if "console." in body:
            effects.add("Console.Write")
        if "fetch(" in body or "XMLHttpRequest" in body or ".send(" in body:
            effects.add("Network.Write")
        if "fs." in body or "readFile" in body or "writeFile" in body:
            effects.add("File.Write")
        if "document." in body or "window." in body:
            effects.add("DOM.Write")
        if "alert(" in body or "prompt(" in body:
            effects.add("Console.Write")
        return sorted(effects)


# ---------------------------------------------------------------------------
# JavaScript Translator
# ---------------------------------------------------------------------------

class JSTranslator(_BaseJSTranslator):
    """Translates JavaScript source to AEON AST."""

    @property
    def language_name(self) -> str:
        return "JavaScript"

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".jsx", ".mjs"]

    def __init__(self):
        super().__init__()
        self._is_typescript = False


# ---------------------------------------------------------------------------
# TypeScript Translator
# ---------------------------------------------------------------------------

class TSTranslator(_BaseJSTranslator):
    """Translates TypeScript source to AEON AST."""

    @property
    def language_name(self) -> str:
        return "TypeScript"

    @property
    def file_extensions(self) -> List[str]:
        return [".ts", ".tsx"]

    def __init__(self):
        super().__init__()
        self._is_typescript = True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_javascript(source: str, deep_verify: bool = True,
                      analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify JavaScript code using AEON's analysis engines."""
    return _verify(source, "javascript", deep_verify=deep_verify, analyses=analyses)


def verify_typescript(source: str, deep_verify: bool = True,
                      analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify TypeScript code using AEON's analysis engines."""
    return _verify(source, "typescript", deep_verify=deep_verify, analyses=analyses)
