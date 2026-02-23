"""AEON Go Adapter — Verify Go Code Using AEON's Analysis Engines.

Translates Go source code into AEON's internal representation and
runs the full verification suite. Uses regex-based parsing.

Usage:
    from aeon.go_adapter import verify_go
    result = verify_go('''
        func divide(a int, b int) int {
            return a / b
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


# ---------------------------------------------------------------------------
# Type maps
# ---------------------------------------------------------------------------

_GO_TYPE_MAP: Dict[str, str] = {
    "int": "Int", "int8": "Int", "int16": "Int", "int32": "Int", "int64": "Int",
    "uint": "Int", "uint8": "Int", "uint16": "Int", "uint32": "Int", "uint64": "Int",
    "float32": "Float", "float64": "Float",
    "bool": "Bool",
    "string": "String",
    "byte": "Int", "rune": "Int",
    "error": "String",
    "interface{}": "Void", "any": "Void",
}

_GO_NOISE_PATTERNS = [
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

_GO_SIDE_EFFECT_FUNCS = {
    "fmt.Println", "fmt.Printf", "fmt.Print", "fmt.Fprintf", "fmt.Sprintf",
    "log.Println", "log.Printf", "log.Fatal", "log.Fatalf",
    "os.Open", "os.Create", "os.Remove", "os.Mkdir", "os.MkdirAll",
    "os.ReadFile", "os.WriteFile",
    "io.ReadAll", "io.Copy", "io.WriteString",
    "http.Get", "http.Post", "http.ListenAndServe",
    "json.Marshal", "json.Unmarshal",
    "sql.Open",
    "panic", "recover",
}

_GO_SIDE_EFFECT_METHODS = {
    "Println", "Printf", "Print", "Write", "Read", "Close",
    "Scan", "Scanln", "Scanf",
    "Fatal", "Fatalf",
    "ServeHTTP", "ListenAndServe",
    "Query", "Exec", "QueryRow",
    "Send", "Recv",
    "Lock", "Unlock", "RLock", "RUnlock",
    "Add", "Done", "Wait",
}


# ---------------------------------------------------------------------------
# Regex-based Go parser
# ---------------------------------------------------------------------------

class _RegexGoParser:
    """Lightweight regex-based Go parser."""

    def parse_functions(self, source: str) -> List[Dict[str, Any]]:
        """Extract function definitions from Go source."""
        functions: List[Dict[str, Any]] = []

        # Regular functions: func name(params) returnType {
        pattern = r'func\s+(\w+)\s*\(([^)]*)\)\s*([^{\n]*?)\s*\{'
        for m in re.finditer(pattern, source):
            name = m.group(1)
            params_str = m.group(2)
            return_type = m.group(3).strip()
            body = self._extract_brace_body(source, m.end() - 1)

            # Extract contracts from preceding comments
            pre_comments = self._get_preceding_comments(source, m.start())

            functions.append({
                "name": name,
                "params": self._parse_params(params_str),
                "return_type": return_type if return_type else None,
                "body": body,
                "line": source[:m.start()].count('\n') + 1,
                "comments": pre_comments,
            })

        # Method receivers: func (r ReceiverType) name(params) returnType {
        method_pattern = r'func\s+\(\s*(\w+)\s+\*?(\w+)\s*\)\s+(\w+)\s*\(([^)]*)\)\s*([^{\n]*?)\s*\{'
        for m in re.finditer(method_pattern, source):
            receiver_name = m.group(1)
            receiver_type = m.group(2)
            name = m.group(3)
            params_str = m.group(4)
            return_type = m.group(5).strip()
            body = self._extract_brace_body(source, m.end() - 1)
            pre_comments = self._get_preceding_comments(source, m.start())

            functions.append({
                "name": f"{receiver_type}_{name}",
                "params": self._parse_params(params_str),
                "return_type": return_type if return_type else None,
                "body": body,
                "line": source[:m.start()].count('\n') + 1,
                "comments": pre_comments,
                "receiver_type": receiver_type,
            })

        return functions

    def parse_structs(self, source: str) -> List[Dict[str, Any]]:
        """Extract struct definitions."""
        structs: List[Dict[str, Any]] = []
        pattern = r'type\s+(\w+)\s+struct\s*\{'
        for m in re.finditer(pattern, source):
            struct_body = self._extract_brace_body(source, m.end() - 1)
            fields = self._parse_struct_fields(struct_body)
            structs.append({
                "name": m.group(1),
                "fields": fields,
                "line": source[:m.start()].count('\n') + 1,
            })
        return structs

    def _parse_params(self, params_str: str) -> List[Dict[str, str]]:
        """Parse Go parameter list."""
        params = []
        if not params_str.strip():
            return params

        # Go params can be: a int, b int  OR  a, b int
        parts = [p.strip() for p in params_str.split(',') if p.strip()]
        pending_names: List[str] = []

        for part in parts:
            tokens = part.split()
            if len(tokens) >= 2:
                # Last token is the type, everything before is names
                type_name = tokens[-1]
                names = tokens[:-1]
                # Apply type to pending names too
                for pn in pending_names:
                    params.append({"name": pn, "type": type_name})
                pending_names = []
                for n in names:
                    params.append({"name": n, "type": type_name})
            elif len(tokens) == 1:
                # Could be just a name (type comes later) or a type
                pending_names.append(tokens[0])

        # If any pending names remain, treat them as untyped
        for pn in pending_names:
            params.append({"name": pn, "type": "any"})

        return params

    def _parse_struct_fields(self, body: str) -> List[Dict[str, str]]:
        """Parse struct field declarations."""
        fields = []
        for line in body.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            tokens = line.split()
            if len(tokens) >= 2:
                field_name = tokens[0]
                field_type = tokens[1]
                fields.append({"name": field_name, "type": field_type})
        return fields

    def _extract_brace_body(self, source: str, start: int) -> str:
        """Extract text inside matching braces."""
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

    def _get_preceding_comments(self, source: str, pos: int) -> str:
        """Get comment lines immediately before a position."""
        lines = source[:pos].rstrip().split('\n')
        comments = []
        for line in reversed(lines):
            stripped = line.strip()
            if stripped.startswith('//'):
                comments.insert(0, stripped)
            else:
                break
        return '\n'.join(comments)


# ---------------------------------------------------------------------------
# Go Translator
# ---------------------------------------------------------------------------

class GoTranslator(LanguageTranslator):
    """Translates Go source code to AEON AST for verification."""

    @property
    def language_name(self) -> str:
        return "Go"

    @property
    def file_extensions(self) -> List[str]:
        return [".go"]

    @property
    def noise_patterns(self) -> List[str]:
        return _GO_NOISE_PATTERNS

    def __init__(self):
        super().__init__()
        self.declarations: List = []

    def translate(self, source: str) -> Program:
        """Parse Go source and translate to AEON Program."""
        self.declarations = []
        parser = _RegexGoParser()

        # Extract and translate structs
        for struct_info in parser.parse_structs(source):
            self._translate_struct(struct_info)

        # Extract and translate functions
        for func_info in parser.parse_functions(source):
            func = self._translate_func(func_info)
            if func:
                self.declarations.append(func)

        return Program(declarations=self.declarations)

    def _translate_struct(self, struct_info: Dict[str, Any]) -> None:
        """Translate a Go struct to AEON DataDef."""
        loc = SourceLocation(line=struct_info.get("line", 0), column=0, file="<go>")
        fields = []
        for f in struct_info.get("fields", []):
            field_type = self._map_type(f.get("type", "any"))
            fields.append(Parameter(name=f["name"], type_annotation=field_type, location=loc))

        self.declarations.append(DataDef(
            name=struct_info["name"],
            fields=fields,
            location=loc,
        ))

    def _translate_func(self, func_info: Dict[str, Any]) -> Optional[PureFunc | TaskFunc]:
        """Translate a Go function to AEON PureFunc or TaskFunc."""
        loc = SourceLocation(line=func_info.get("line", 0), column=0, file="<go>")

        # Parameters
        params = []
        for p in func_info.get("params", []):
            param_type = self._map_type(p.get("type", "any"))
            params.append(Parameter(name=p["name"], type_annotation=param_type, location=loc))

        # Return type
        rt = func_info.get("return_type")
        if rt:
            # Handle multiple return values: (int, error)
            rt = rt.strip('()')
            if ',' in rt:
                rt = rt.split(',')[0].strip()
            return_type = self._map_type(rt)
        else:
            return_type = TypeAnnotation(name="Void")

        # Extract contracts from comments
        requires, ensures = self._extract_contracts(func_info.get("comments", ""))

        # Translate body
        body = self._translate_body_str(func_info.get("body", ""))

        # Determine side effects
        body_str = func_info.get("body", "")
        has_side_effects = self._body_has_side_effects(body_str)

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
        """Map a Go type to AEON TypeAnnotation."""
        if not type_str:
            return TypeAnnotation(name="Void")
        type_str = type_str.strip().lstrip('*')

        # Handle slice types: []int
        if type_str.startswith('[]'):
            base = type_str[2:]
            return TypeAnnotation(name="List", generic_args=[self._map_type(base)])

        # Handle map types: map[K]V
        map_match = re.match(r'map\[(\w+)\](\w+)', type_str)
        if map_match:
            return TypeAnnotation(name="Map", generic_args=[
                self._map_type(map_match.group(1)),
                self._map_type(map_match.group(2)),
            ])

        return TypeAnnotation(name=_GO_TYPE_MAP.get(type_str, type_str))

    def _translate_body_str(self, body: str) -> List[Statement]:
        """Translate function body string to AEON statements."""
        stmts: List[Statement] = []
        lines = body.strip().split('\n')

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue

            loc = SourceLocation(line=i + 1, column=0, file="<go>")

            # return statement
            ret_match = re.match(r'return\s+(.+?)$', stripped)
            if ret_match:
                expr = self._parse_simple_expr(ret_match.group(1), loc)
                stmts.append(ReturnStmt(value=expr, location=loc))
                continue

            # Short variable declaration: name := expr
            short_var_match = re.match(r'(\w+)\s*:=\s*(.+?)$', stripped)
            if short_var_match:
                name, val_str = short_var_match.group(1), short_var_match.group(2)
                value = self._parse_simple_expr(val_str, loc)
                stmts.append(LetStmt(name=name, type_annotation=TypeAnnotation(name="Void"),
                                     value=value, location=loc))
                continue

            # var declaration: var name type = expr
            var_match = re.match(r'var\s+(\w+)\s+(\w+)(?:\s*=\s*(.+))?$', stripped)
            if var_match:
                name = var_match.group(1)
                type_name = var_match.group(2)
                val_str = var_match.group(3)
                value = self._parse_simple_expr(val_str, loc) if val_str else None
                stmts.append(LetStmt(name=name, type_annotation=self._map_type(type_name),
                                     value=value, location=loc))
                continue

            # if statement
            if_match = re.match(r'if\s+(.+?)\s*\{', stripped)
            if if_match:
                condition = self._parse_simple_expr(if_match.group(1), loc)
                stmts.append(IfStmt(condition=condition, then_body=[], else_body=[], location=loc))
                continue

            # for loop (as while)
            for_match = re.match(r'for\s+(.+?)\s*\{', stripped)
            if for_match:
                condition = self._parse_simple_expr(for_match.group(1), loc)
                stmts.append(WhileStmt(condition=condition, body=[], location=loc))
                continue

            # Expression statement
            if stripped and not stripped.startswith('{') and not stripped.startswith('}'):
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
        if expr_str == "nil":
            return IntLiteral(value=0, location=loc)

        # String literal
        if (expr_str.startswith('"') and expr_str.endswith('"')) or \
           (expr_str.startswith('`') and expr_str.endswith('`')):
            return StringLiteral(value=expr_str[1:-1], location=loc)

        # Numeric literal
        if re.match(r'^-?\d+$', expr_str):
            return IntLiteral(value=int(expr_str), location=loc)
        if re.match(r'^-?\d+\.\d+$', expr_str):
            return FloatLiteral(value=float(expr_str), location=loc)

        # Binary operations
        for op in ("!=", "==", ">=", "<=", "&&", "||", ">", "<", "+", "-", "*", "/", "%"):
            if op in expr_str:
                parts = expr_str.split(op, 1)
                if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                    left = self._parse_simple_expr(parts[0], loc)
                    right = self._parse_simple_expr(parts[1], loc)
                    return BinaryOp(op=op, left=left, right=right, location=loc)

        # Method call: obj.Method(args)
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

    def _extract_contracts(self, comments: str) -> Tuple[List[ContractClause], List[ContractClause]]:
        """Extract @requires / @ensures from Go comments."""
        requires: List[ContractClause] = []
        ensures: List[ContractClause] = []

        for line in comments.split('\n'):
            line = line.strip().lstrip('//').strip()

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
        for op in ("!=", "==", ">=", "<=", ">", "<"):
            if op in expr_str:
                parts = expr_str.split(op, 1)
                if len(parts) == 2:
                    left = parts[0].strip()
                    right = parts[1].strip()
                    left_expr = Identifier(name=left) if not left.lstrip('-').isdigit() else IntLiteral(value=int(left))
                    right_expr = Identifier(name=right) if not right.lstrip('-').isdigit() else IntLiteral(value=int(right))
                    return BinaryOp(op=op, left=left_expr, right=right_expr)
        return None

    def _body_has_side_effects(self, body: str) -> bool:
        """Heuristic: does a function body have side effects?"""
        for func in _GO_SIDE_EFFECT_FUNCS:
            if func in body:
                return True
        for method in _GO_SIDE_EFFECT_METHODS:
            if f'.{method}(' in body:
                return True
        # Go channels
        if '<-' in body:
            return True
        # go keyword (goroutine)
        if re.search(r'\bgo\s+', body):
            return True
        return False

    def _infer_effects(self, body: str) -> List[str]:
        """Infer AEON effects from Go function body."""
        effects = set()
        if "fmt." in body or "log." in body:
            effects.add("Console.Write")
        if "http." in body or "net." in body:
            effects.add("Network.Write")
        if "os." in body or "io." in body or "bufio." in body:
            effects.add("File.Write")
        if "sql." in body or "db." in body:
            effects.add("Database.Write")
        if "<-" in body:
            effects.add("Channel.Write")
        if "sync." in body:
            effects.add("Sync.Lock")
        return sorted(effects)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_go(source: str, deep_verify: bool = True,
              analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify Go code using AEON's analysis engines."""
    return _verify(source, "go", deep_verify=deep_verify, analyses=analyses)
