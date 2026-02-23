"""AEON Rust Adapter — Verify Rust Code Using AEON's Analysis Engines.

Translates Rust source code into AEON's internal representation and
runs the full verification suite. Uses regex-based parsing.

Usage:
    from aeon.rust_adapter import verify_rust
    result = verify_rust('''
        fn divide(a: i32, b: i32) -> i32 {
            a / b
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

_RUST_TYPE_MAP: Dict[str, str] = {
    "i8": "Int", "i16": "Int", "i32": "Int", "i64": "Int", "i128": "Int", "isize": "Int",
    "u8": "Int", "u16": "Int", "u32": "Int", "u64": "Int", "u128": "Int", "usize": "Int",
    "f32": "Float", "f64": "Float",
    "bool": "Bool",
    "String": "String", "str": "String", "&str": "String",
    "char": "String",
    "()": "Void",
    "Option": "Void",
    "Result": "Void",
}

_RUST_NOISE_PATTERNS = [
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

_RUST_SIDE_EFFECT_MACROS = {
    "println!", "print!", "eprintln!", "eprint!",
    "write!", "writeln!",
    "panic!", "todo!", "unimplemented!",
    "format!",
}

_RUST_SIDE_EFFECT_METHODS = {
    "read", "write", "read_to_string", "write_all", "flush",
    "open", "create", "remove_file", "create_dir", "remove_dir",
    "send", "recv", "try_send", "try_recv",
    "lock", "unlock", "read", "write",
    "spawn", "join",
    "push", "pop", "insert", "remove", "clear",
    "execute", "query", "prepare",
    "connect", "bind", "listen", "accept",
}


# ---------------------------------------------------------------------------
# Regex-based Rust parser
# ---------------------------------------------------------------------------

class _RegexRustParser:
    """Lightweight regex-based Rust parser."""

    def parse_functions(self, source: str) -> List[Dict[str, Any]]:
        """Extract function definitions from Rust source."""
        functions: List[Dict[str, Any]] = []

        # Regular functions: fn name(params) -> ReturnType {
        pattern = r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^{\n]+?))?\s*\{'
        for m in re.finditer(pattern, source):
            name = m.group(1)
            params_str = m.group(2)
            return_type = m.group(3)
            body = self._extract_brace_body(source, m.end() - 1)
            pre_comments = self._get_preceding_comments(source, m.start())

            functions.append({
                "name": name,
                "params": self._parse_params(params_str),
                "return_type": return_type.strip() if return_type else None,
                "body": body,
                "line": source[:m.start()].count('\n') + 1,
                "comments": pre_comments,
                "is_async": 'async' in m.group(0),
                "is_pub": m.group(0).strip().startswith('pub'),
            })

        # impl blocks — extract methods
        impl_pattern = r'impl\s+(?:<[^>]*>\s*)?(\w+)\s*(?:for\s+(\w+)\s*)?\{'
        for im in re.finditer(impl_pattern, source):
            impl_type = im.group(2) or im.group(1)
            impl_body = self._extract_brace_body(source, im.end() - 1)

            method_pattern = r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^{\n]+?))?\s*\{'
            for mm in re.finditer(method_pattern, impl_body):
                method_name = mm.group(1)
                params_str = mm.group(2)
                return_type = mm.group(3)
                body = self._extract_brace_body(impl_body, mm.end() - 1)

                # Remove &self, &mut self, self from params
                clean_params = re.sub(r'&?\s*(?:mut\s+)?self\s*,?\s*', '', params_str).strip()

                functions.append({
                    "name": f"{impl_type}_{method_name}",
                    "params": self._parse_params(clean_params),
                    "return_type": return_type.strip() if return_type else None,
                    "body": body,
                    "line": source[:im.start()].count('\n') + impl_body[:mm.start()].count('\n') + 1,
                    "comments": "",
                    "is_async": 'async' in mm.group(0),
                    "impl_type": impl_type,
                })

        return functions

    def parse_structs(self, source: str) -> List[Dict[str, Any]]:
        """Extract struct definitions."""
        structs: List[Dict[str, Any]] = []

        # Struct with fields
        pattern = r'(?:pub\s+)?struct\s+(\w+)\s*(?:<[^>]*>)?\s*\{'
        for m in re.finditer(pattern, source):
            struct_body = self._extract_brace_body(source, m.end() - 1)
            fields = self._parse_struct_fields(struct_body)
            structs.append({
                "name": m.group(1),
                "fields": fields,
                "line": source[:m.start()].count('\n') + 1,
            })

        # Tuple structs
        tuple_pattern = r'(?:pub\s+)?struct\s+(\w+)\s*\(([^)]*)\)\s*;'
        for m in re.finditer(tuple_pattern, source):
            types = [t.strip() for t in m.group(2).split(',') if t.strip()]
            fields = [{"name": f"field_{i}", "type": t.lstrip("pub ").strip()} for i, t in enumerate(types)]
            structs.append({
                "name": m.group(1),
                "fields": fields,
                "line": source[:m.start()].count('\n') + 1,
            })

        return structs

    def parse_enums(self, source: str) -> List[Dict[str, Any]]:
        """Extract enum definitions."""
        enums: List[Dict[str, Any]] = []
        pattern = r'(?:pub\s+)?enum\s+(\w+)\s*(?:<[^>]*>)?\s*\{'
        for m in re.finditer(pattern, source):
            enums.append({
                "name": m.group(1),
                "line": source[:m.start()].count('\n') + 1,
            })
        return enums

    def _parse_params(self, params_str: str) -> List[Dict[str, str]]:
        """Parse Rust parameter list: name: Type, name: Type."""
        params = []
        if not params_str.strip():
            return params

        for p in params_str.split(','):
            p = p.strip()
            if not p:
                continue
            if ':' in p:
                parts = p.split(':', 1)
                name = parts[0].strip().lstrip('mut ').strip()
                type_name = parts[1].strip().lstrip('&').lstrip('mut ').strip()
                params.append({"name": name, "type": type_name})

        return params

    def _parse_struct_fields(self, body: str) -> List[Dict[str, str]]:
        """Parse struct field declarations."""
        fields = []
        for line in body.strip().split('\n'):
            line = line.strip().rstrip(',')
            if not line or line.startswith('//') or line.startswith('#'):
                continue
            # pub field_name: Type
            match = re.match(r'(?:pub\s+)?(\w+)\s*:\s*(.+)', line)
            if match:
                fields.append({
                    "name": match.group(1),
                    "type": match.group(2).strip().rstrip(','),
                })
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
            if stripped.startswith('///') or stripped.startswith('//'):
                comments.insert(0, stripped)
            elif stripped.startswith('#['):
                comments.insert(0, stripped)
            else:
                break
        return '\n'.join(comments)


# ---------------------------------------------------------------------------
# Rust Translator
# ---------------------------------------------------------------------------

class RustTranslator(LanguageTranslator):
    """Translates Rust source code to AEON AST for verification."""

    @property
    def language_name(self) -> str:
        return "Rust"

    @property
    def file_extensions(self) -> List[str]:
        return [".rs"]

    @property
    def noise_patterns(self) -> List[str]:
        return _RUST_NOISE_PATTERNS

    def __init__(self):
        super().__init__()
        self.declarations: List = []

    def translate(self, source: str) -> Program:
        """Parse Rust source and translate to AEON Program."""
        self.declarations = []
        parser = _RegexRustParser()

        # Extract and translate structs
        for struct_info in parser.parse_structs(source):
            self._translate_struct(struct_info)

        # Extract enums as DataDefs
        for enum_info in parser.parse_enums(source):
            loc = SourceLocation(line=enum_info.get("line", 0), column=0, file="<rust>")
            self.declarations.append(DataDef(name=enum_info["name"], fields=[], location=loc))

        # Extract and translate functions
        for func_info in parser.parse_functions(source):
            func = self._translate_func(func_info)
            if func:
                self.declarations.append(func)

        return Program(declarations=self.declarations)

    def _translate_struct(self, struct_info: Dict[str, Any]) -> None:
        """Translate a Rust struct to AEON DataDef."""
        loc = SourceLocation(line=struct_info.get("line", 0), column=0, file="<rust>")
        fields = []
        for f in struct_info.get("fields", []):
            field_type = self._map_type(f.get("type", "()"))
            fields.append(Parameter(name=f["name"], type_annotation=field_type, location=loc))

        self.declarations.append(DataDef(
            name=struct_info["name"],
            fields=fields,
            location=loc,
        ))

    def _translate_func(self, func_info: Dict[str, Any]) -> Optional[PureFunc | TaskFunc]:
        """Translate a Rust function to AEON PureFunc or TaskFunc."""
        loc = SourceLocation(line=func_info.get("line", 0), column=0, file="<rust>")

        # Parameters
        params = []
        for p in func_info.get("params", []):
            param_type = self._map_type(p.get("type", "()"))
            params.append(Parameter(name=p["name"], type_annotation=param_type, location=loc))

        # Return type
        rt = func_info.get("return_type")
        if rt:
            # Strip Result<T, E> or Option<T> wrapper
            result_match = re.match(r'Result<([^,>]+)', rt)
            option_match = re.match(r'Option<([^>]+)>', rt)
            if result_match:
                return_type = self._map_type(result_match.group(1).strip())
            elif option_match:
                return_type = self._map_type(option_match.group(1).strip())
            else:
                return_type = self._map_type(rt)
        else:
            return_type = TypeAnnotation(name="Void")

        # Extract contracts from comments
        requires, ensures = self._extract_contracts(func_info.get("comments", ""))

        # Translate body
        body = self._translate_body_str(func_info.get("body", ""))

        # Determine side effects
        body_str = func_info.get("body", "")
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
        """Map a Rust type to AEON TypeAnnotation."""
        if not type_str:
            return TypeAnnotation(name="Void")
        type_str = type_str.strip().lstrip('&').lstrip('mut ').strip()

        # Handle Vec<T>
        vec_match = re.match(r'Vec<(.+)>', type_str)
        if vec_match:
            return TypeAnnotation(name="List", generic_args=[self._map_type(vec_match.group(1))])

        # Handle HashMap<K, V>
        map_match = re.match(r'HashMap<([^,]+),\s*(.+)>', type_str)
        if map_match:
            return TypeAnnotation(name="Map", generic_args=[
                self._map_type(map_match.group(1)),
                self._map_type(map_match.group(2)),
            ])

        # Handle Box<T>, Rc<T>, Arc<T>
        wrapper_match = re.match(r'(?:Box|Rc|Arc|RefCell|Mutex)<(.+)>', type_str)
        if wrapper_match:
            return self._map_type(wrapper_match.group(1))

        return TypeAnnotation(name=_RUST_TYPE_MAP.get(type_str, type_str))

    def _translate_body_str(self, body: str) -> List[Statement]:
        """Translate function body string to AEON statements."""
        stmts: List[Statement] = []
        lines = body.strip().split('\n')

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue

            loc = SourceLocation(line=i + 1, column=0, file="<rust>")

            # return statement (explicit)
            ret_match = re.match(r'return\s+(.+?);?\s*$', stripped)
            if ret_match:
                expr = self._parse_simple_expr(ret_match.group(1), loc)
                stmts.append(ReturnStmt(value=expr, location=loc))
                continue

            # let binding: let [mut] name [: Type] = expr;
            let_match = re.match(r'let\s+(?:mut\s+)?(\w+)(?:\s*:\s*\S+)?\s*=\s*(.+?)\s*;?\s*$', stripped)
            if let_match:
                name, val_str = let_match.group(1), let_match.group(2)
                value = self._parse_simple_expr(val_str, loc)
                stmts.append(LetStmt(name=name, type_annotation=TypeAnnotation(name="Void"),
                                     value=value, location=loc))
                continue

            # if statement
            if_match = re.match(r'if\s+(.+?)\s*\{', stripped)
            if if_match:
                condition = self._parse_simple_expr(if_match.group(1), loc)
                stmts.append(IfStmt(condition=condition, then_body=[], else_body=[], location=loc))
                continue

            # loop/while
            while_match = re.match(r'(?:while|loop)\s*(.+?)?\s*\{', stripped)
            if while_match:
                cond_str = while_match.group(1)
                condition = self._parse_simple_expr(cond_str, loc) if cond_str else BoolLiteral(value=True, location=loc)
                stmts.append(WhileStmt(condition=condition, body=[], location=loc))
                continue

            # Expression statement (including implicit return at end)
            if stripped.endswith(';'):
                stripped = stripped[:-1]
            if stripped and not stripped.startswith('{') and not stripped.startswith('}'):
                expr = self._parse_simple_expr(stripped, loc)
                # Last expression in body is implicit return
                if i == len(lines) - 1 or (i == len(lines) - 2 and not lines[-1].strip()):
                    stmts.append(ReturnStmt(value=expr, location=loc))
                else:
                    stmts.append(ExprStmt(expr=expr, location=loc))

        return stmts

    def _parse_simple_expr(self, expr_str: str, loc: SourceLocation) -> Expr:
        """Parse a simple expression to AEON Expr."""
        expr_str = expr_str.strip()

        if expr_str == "true":
            return BoolLiteral(value=True, location=loc)
        if expr_str == "false":
            return BoolLiteral(value=False, location=loc)
        if expr_str == "None" or expr_str == "()":
            return IntLiteral(value=0, location=loc)

        # String literal
        if (expr_str.startswith('"') and expr_str.endswith('"')):
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

        # Method call
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

        # Function/macro call
        call_match = re.match(r'(\w+!?)\(([^)]*)\)', expr_str)
        if call_match:
            func_name, args_str = call_match.groups()
            args = [self._parse_simple_expr(a.strip(), loc) for a in args_str.split(',') if a.strip()] if args_str.strip() else []
            return FunctionCall(
                callee=Identifier(name=func_name.rstrip('!'), location=loc),
                args=args,
                location=loc,
            )

        # Field access
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
        """Extract contracts from Rust doc comments (///)."""
        requires: List[ContractClause] = []
        ensures: List[ContractClause] = []

        for line in comments.split('\n'):
            line = line.strip().lstrip('/').strip()

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
        for macro in _RUST_SIDE_EFFECT_MACROS:
            if macro in body:
                return True
        for method in _RUST_SIDE_EFFECT_METHODS:
            if f'.{method}(' in body:
                return True
        # unsafe blocks
        if 'unsafe' in body:
            return True
        return False

    def _infer_effects(self, body: str) -> List[str]:
        """Infer AEON effects from Rust function body."""
        effects = set()
        if "println!" in body or "print!" in body or "eprintln!" in body:
            effects.add("Console.Write")
        if "std::net" in body or "reqwest" in body or "hyper" in body:
            effects.add("Network.Write")
        if "std::fs" in body or "File::" in body or "BufReader" in body:
            effects.add("File.Write")
        if "unsafe" in body:
            effects.add("Unsafe.Access")
        if "Mutex" in body or "RwLock" in body:
            effects.add("Sync.Lock")
        if "tokio" in body or ".await" in body:
            effects.add("Async.Await")
        return sorted(effects)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_rust(source: str, deep_verify: bool = True,
                analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify Rust code using AEON's analysis engines."""
    return _verify(source, "rust", deep_verify=deep_verify, analyses=analyses)
