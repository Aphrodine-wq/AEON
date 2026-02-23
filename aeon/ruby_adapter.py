"""AEON Ruby Adapter — Verify Ruby Code Using AEON's Analysis Engines.

Translates Ruby source code into AEON's internal representation and
runs the full verification suite. Uses regex-based parsing.

Usage:
    from aeon.ruby_adapter import verify_ruby
    result = verify_ruby('''
        def divide(a, b)
          a / b
        end
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
# Type maps (Ruby is dynamically typed, infer where possible)
# ---------------------------------------------------------------------------

_RUBY_TYPE_MAP: Dict[str, str] = {
    "Integer": "Int", "Fixnum": "Int", "Bignum": "Int",
    "Float": "Float",
    "String": "String",
    "Symbol": "String",
    "TrueClass": "Bool", "FalseClass": "Bool",
    "NilClass": "Void",
    "Array": "List",
    "Hash": "Map",
    "Numeric": "Int",
}

_RUBY_NOISE_PATTERNS = [
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

_RUBY_SIDE_EFFECT_METHODS = {
    "puts", "print", "p", "pp", "printf", "warn",
    "gets", "readline", "readlines",
    "open", "read", "write", "close", "delete", "rename",
    "each", "map!", "select!", "reject!", "sort!", "reverse!",
    "push", "pop", "shift", "unshift", "append", "prepend",
    "send", "receive",
    "save", "create", "update", "destroy", "delete",
    "raise", "fail",
    "system", "exec", "spawn",
    "require", "require_relative", "load",
}

_RUBY_SIDE_EFFECT_CLASSES = {
    "File", "Dir", "IO", "Socket", "TCPSocket", "UDPSocket",
    "Net::HTTP", "URI",
    "Thread", "Mutex",
}


# ---------------------------------------------------------------------------
# Regex-based Ruby parser
# ---------------------------------------------------------------------------

class _RegexRubyParser:
    """Lightweight regex-based Ruby parser."""

    def parse_functions(self, source: str) -> List[Dict[str, Any]]:
        """Extract method/function definitions from Ruby source."""
        functions: List[Dict[str, Any]] = []

        # Module/top-level methods: def name(params)
        pattern = r'def\s+(\w+[!?]?)\s*(?:\(([^)]*)\))?\s*$'
        for m in re.finditer(pattern, source, re.MULTILINE):
            name = m.group(1)
            params_str = m.group(2) or ""
            body_start = m.end()
            body = self._extract_def_body(source, body_start)
            pre_comments = self._get_preceding_comments(source, m.start())

            functions.append({
                "name": name.rstrip('!?'),
                "params": self._parse_params(params_str),
                "body": body,
                "line": source[:m.start()].count('\n') + 1,
                "comments": pre_comments,
                "has_bang": name.endswith('!'),
            })

        # Class methods
        class_pattern = r'class\s+(\w+)(?:\s*<\s*\w+)?\s*$'
        for cm in re.finditer(class_pattern, source, re.MULTILINE):
            class_name = cm.group(1)
            class_body = self._extract_class_body(source, cm.end())

            for mm in re.finditer(pattern, class_body, re.MULTILINE):
                method_name = mm.group(1)
                params_str = mm.group(2) or ""
                body_start = mm.end()
                body = self._extract_def_body(class_body, body_start)

                # Skip if already found as top-level
                full_name = f"{class_name}_{method_name.rstrip('!?')}"
                if any(f["name"] == full_name for f in functions):
                    continue

                functions.append({
                    "name": full_name,
                    "params": self._parse_params(params_str),
                    "body": body,
                    "line": source[:cm.start()].count('\n') + class_body[:mm.start()].count('\n') + 1,
                    "comments": "",
                    "class_name": class_name,
                    "has_bang": method_name.endswith('!'),
                })

        return functions

    def parse_classes(self, source: str) -> List[Dict[str, Any]]:
        """Extract class definitions."""
        classes: List[Dict[str, Any]] = []
        pattern = r'class\s+(\w+)(?:\s*<\s*(\w+))?\s*$'
        for m in re.finditer(pattern, source, re.MULTILINE):
            class_body = self._extract_class_body(source, m.end())
            fields = self._extract_attr_fields(class_body)
            classes.append({
                "name": m.group(1),
                "parent": m.group(2),
                "fields": fields,
                "line": source[:m.start()].count('\n') + 1,
            })
        return classes

    def parse_modules(self, source: str) -> List[Dict[str, Any]]:
        """Extract module definitions."""
        modules: List[Dict[str, Any]] = []
        pattern = r'module\s+(\w+)\s*$'
        for m in re.finditer(pattern, source, re.MULTILINE):
            modules.append({
                "name": m.group(1),
                "line": source[:m.start()].count('\n') + 1,
            })
        return modules

    def _parse_params(self, params_str: str) -> List[Dict[str, str]]:
        """Parse Ruby parameter list."""
        params = []
        if not params_str.strip():
            return params

        for p in params_str.split(','):
            p = p.strip()
            if not p:
                continue
            # Handle default values: name = default
            name = p.split('=')[0].strip().lstrip('*&')
            # Ruby doesn't have type annotations in params typically
            params.append({"name": name, "type": "any"})

        return params

    def _extract_def_body(self, source: str, start: int) -> str:
        """Extract body of a def...end block."""
        depth = 1
        lines = source[start:].split('\n')
        body_lines = []
        for line in lines:
            stripped = line.strip()
            # Count nested blocks
            if re.match(r'\b(def|class|module|do|if|unless|while|until|for|case|begin)\b', stripped):
                if not re.search(r'\bend\b', stripped):  # Not single-line
                    depth += 1
            if stripped == 'end' or re.match(r'end\b', stripped):
                depth -= 1
                if depth <= 0:
                    break
            body_lines.append(line)
        return '\n'.join(body_lines)

    def _extract_class_body(self, source: str, start: int) -> str:
        """Extract body of a class...end block."""
        return self._extract_def_body(source, start)

    def _extract_attr_fields(self, class_body: str) -> List[Dict[str, str]]:
        """Extract fields from attr_accessor, attr_reader, attr_writer."""
        fields = []
        for m in re.finditer(r'attr_(?:accessor|reader|writer)\s+(.+)$', class_body, re.MULTILINE):
            for sym in re.findall(r':(\w+)', m.group(1)):
                fields.append({"name": sym, "type": "any"})

        # Also find @instance_variable assignments in initialize
        for m in re.finditer(r'@(\w+)\s*=', class_body):
            name = m.group(1)
            if not any(f["name"] == name for f in fields):
                fields.append({"name": name, "type": "any"})

        return fields

    def _get_preceding_comments(self, source: str, pos: int) -> str:
        """Get comment lines immediately before a position."""
        lines = source[:pos].rstrip().split('\n')
        comments = []
        for line in reversed(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                comments.insert(0, stripped)
            else:
                break
        return '\n'.join(comments)


# ---------------------------------------------------------------------------
# Ruby Translator
# ---------------------------------------------------------------------------

class RubyTranslator(LanguageTranslator):
    """Translates Ruby source code to AEON AST for verification."""

    @property
    def language_name(self) -> str:
        return "Ruby"

    @property
    def file_extensions(self) -> List[str]:
        return [".rb"]

    @property
    def noise_patterns(self) -> List[str]:
        return _RUBY_NOISE_PATTERNS

    def __init__(self):
        super().__init__()
        self.declarations: List = []

    def translate(self, source: str) -> Program:
        """Parse Ruby source and translate to AEON Program."""
        self.declarations = []
        parser = _RegexRubyParser()

        # Extract and translate classes
        for cls_info in parser.parse_classes(source):
            self._translate_class(cls_info)

        # Extract and translate modules as DataDefs
        for mod_info in parser.parse_modules(source):
            loc = SourceLocation(line=mod_info.get("line", 0), column=0, file="<ruby>")
            self.declarations.append(DataDef(name=mod_info["name"], fields=[], location=loc))

        # Extract and translate functions
        for func_info in parser.parse_functions(source):
            func = self._translate_func(func_info)
            if func:
                self.declarations.append(func)

        return Program(declarations=self.declarations)

    def _translate_class(self, cls_info: Dict[str, Any]) -> None:
        """Translate a Ruby class to AEON DataDef."""
        loc = SourceLocation(line=cls_info.get("line", 0), column=0, file="<ruby>")
        fields = []
        for f in cls_info.get("fields", []):
            field_type = TypeAnnotation(name="Void")  # Ruby is dynamically typed
            fields.append(Parameter(name=f["name"], type_annotation=field_type, location=loc))

        self.declarations.append(DataDef(
            name=cls_info["name"],
            fields=fields,
            location=loc,
        ))

    def _translate_func(self, func_info: Dict[str, Any]) -> Optional[PureFunc | TaskFunc]:
        """Translate a Ruby method to AEON PureFunc or TaskFunc."""
        loc = SourceLocation(line=func_info.get("line", 0), column=0, file="<ruby>")

        # Parameters (Ruby is dynamically typed — all params are Void)
        params = []
        for p in func_info.get("params", []):
            params.append(Parameter(name=p["name"], type_annotation=TypeAnnotation(name="Void"), location=loc))

        return_type = TypeAnnotation(name="Void")

        # Extract contracts from comments
        requires, ensures = self._extract_contracts(func_info.get("comments", ""))

        # Translate body
        body = self._translate_body_str(func_info.get("body", ""))

        # Determine side effects
        body_str = func_info.get("body", "")
        has_bang = func_info.get("has_bang", False)
        has_side_effects = has_bang or self._body_has_side_effects(body_str)

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

    def _translate_body_str(self, body: str) -> List[Statement]:
        """Translate Ruby function body to AEON statements."""
        stmts: List[Statement] = []
        lines = body.strip().split('\n')

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            loc = SourceLocation(line=i + 1, column=0, file="<ruby>")

            # Explicit return
            ret_match = re.match(r'return\s+(.+?)$', stripped)
            if ret_match:
                expr = self._parse_simple_expr(ret_match.group(1), loc)
                stmts.append(ReturnStmt(value=expr, location=loc))
                continue

            # Local variable assignment
            var_match = re.match(r'(\w+)\s*=\s*(.+?)$', stripped)
            if var_match:
                name = var_match.group(1)
                if name not in ('if', 'unless', 'while', 'until', 'for', 'class', 'def', 'end'):
                    val_str = var_match.group(2)
                    value = self._parse_simple_expr(val_str, loc)
                    stmts.append(LetStmt(name=name, type_annotation=TypeAnnotation(name="Void"),
                                         value=value, location=loc))
                    continue

            # if statement
            if_match = re.match(r'if\s+(.+?)$', stripped)
            if if_match:
                condition = self._parse_simple_expr(if_match.group(1), loc)
                stmts.append(IfStmt(condition=condition, then_body=[], else_body=[], location=loc))
                continue

            # while loop
            while_match = re.match(r'while\s+(.+?)$', stripped)
            if while_match:
                condition = self._parse_simple_expr(while_match.group(1), loc)
                stmts.append(WhileStmt(condition=condition, body=[], location=loc))
                continue

            # Expression statement (last expression is implicit return in Ruby)
            if stripped and stripped != 'end':
                expr = self._parse_simple_expr(stripped, loc)
                # Last non-empty expression is implicit return
                remaining = [l.strip() for l in lines[i+1:] if l.strip() and l.strip() != 'end']
                if not remaining:
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
        if expr_str == "nil":
            return IntLiteral(value=0, location=loc)

        # String literal
        if (expr_str.startswith('"') and expr_str.endswith('"')) or \
           (expr_str.startswith("'") and expr_str.endswith("'")):
            return StringLiteral(value=expr_str[1:-1], location=loc)

        # Symbol
        if expr_str.startswith(':') and re.match(r'^:\w+$', expr_str):
            return StringLiteral(value=expr_str[1:], location=loc)

        # Numeric
        if re.match(r'^-?\d+$', expr_str):
            return IntLiteral(value=int(expr_str), location=loc)
        if re.match(r'^-?\d+\.\d+$', expr_str):
            return FloatLiteral(value=float(expr_str), location=loc)

        # Binary operations
        for op in ("!=", "==", ">=", "<=", "&&", "||", "and", "or", ">", "<", "+", "-", "*", "/", "%"):
            if f" {op} " in expr_str:
                parts = expr_str.split(f" {op} ", 1)
                if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                    left = self._parse_simple_expr(parts[0], loc)
                    right = self._parse_simple_expr(parts[1], loc)
                    aeon_op = {"and": "&&", "or": "||"}.get(op, op)
                    return BinaryOp(op=aeon_op, left=left, right=right, location=loc)

        # Also check without spaces for operators like +,-,*,/
        for op in ("!=", "==", ">=", "<=", ">", "<", "+", "-", "*", "/", "%"):
            if op in expr_str:
                parts = expr_str.split(op, 1)
                if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                    left = self._parse_simple_expr(parts[0], loc)
                    right = self._parse_simple_expr(parts[1], loc)
                    return BinaryOp(op=op, left=left, right=right, location=loc)

        # Method call: obj.method(args)
        method_match = re.match(r'(\w+)\.(\w+[!?]?)\(([^)]*)\)', expr_str)
        if method_match:
            obj_name, method_name, args_str = method_match.groups()
            args = [self._parse_simple_expr(a.strip(), loc) for a in args_str.split(',') if a.strip()] if args_str.strip() else []
            return MethodCall(
                obj=Identifier(name=obj_name, location=loc),
                method_name=method_name.rstrip('!?'),
                args=args,
                location=loc,
            )

        # Method call without parens: obj.method
        method_no_paren = re.match(r'(\w+)\.(\w+[!?]?)$', expr_str)
        if method_no_paren:
            return FieldAccess(
                obj=Identifier(name=method_no_paren.group(1), location=loc),
                field_name=method_no_paren.group(2).rstrip('!?'),
                location=loc,
            )

        # Function call: func(args) or func arg
        call_match = re.match(r'(\w+[!?]?)\(([^)]*)\)', expr_str)
        if call_match:
            func_name, args_str = call_match.groups()
            args = [self._parse_simple_expr(a.strip(), loc) for a in args_str.split(',') if a.strip()] if args_str.strip() else []
            return FunctionCall(
                callee=Identifier(name=func_name.rstrip('!?'), location=loc),
                args=args,
                location=loc,
            )

        # Ruby function call without parens: puts "hello"
        bare_call = re.match(r'(\w+[!?]?)\s+(.+)$', expr_str)
        if bare_call:
            func_name = bare_call.group(1)
            if func_name in ('puts', 'print', 'p', 'pp', 'raise', 'require', 'require_relative',
                             'include', 'extend', 'attr_accessor', 'attr_reader', 'attr_writer'):
                arg = self._parse_simple_expr(bare_call.group(2), loc)
                return FunctionCall(
                    callee=Identifier(name=func_name.rstrip('!?'), location=loc),
                    args=[arg],
                    location=loc,
                )

        # Instance variable
        if expr_str.startswith('@'):
            return Identifier(name=expr_str.lstrip('@'), location=loc)

        # Identifier
        if re.match(r'^[a-zA-Z_]\w*[!?]?$', expr_str):
            return Identifier(name=expr_str.rstrip('!?'), location=loc)

        return Identifier(name="__unknown__", location=loc)

    def _extract_contracts(self, comments: str) -> Tuple[List[ContractClause], List[ContractClause]]:
        """Extract contracts from Ruby comments."""
        requires: List[ContractClause] = []
        ensures: List[ContractClause] = []

        for line in comments.split('\n'):
            line = line.strip().lstrip('#').strip()

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
        """Heuristic: does a method body have side effects?"""
        for method in _RUBY_SIDE_EFFECT_METHODS:
            if method in body:
                return True
        for cls in _RUBY_SIDE_EFFECT_CLASSES:
            if cls in body:
                return True
        # Bang methods mutate
        if re.search(r'\.\w+!', body):
            return True
        return False

    def _infer_effects(self, body: str) -> List[str]:
        """Infer AEON effects from Ruby method body."""
        effects = set()
        if any(f in body for f in ("puts", "print", "p ", "pp ", "warn")):
            effects.add("Console.Write")
        if any(f in body for f in ("gets", "readline", "readlines")):
            effects.add("Console.Read")
        if any(f in body for f in ("File.", "Dir.", "IO.")):
            effects.add("File.Write")
        if any(f in body for f in ("Net::", "HTTP", "Socket", "TCPSocket")):
            effects.add("Network.Write")
        if any(f in body for f in ("Thread.", "Mutex")):
            effects.add("Sync.Lock")
        if any(f in body for f in ("system", "exec", "spawn", "`")):
            effects.add("Process.Exec")
        return sorted(effects)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_ruby(source: str, deep_verify: bool = True,
                analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify Ruby code using AEON's analysis engines."""
    return _verify(source, "ruby", deep_verify=deep_verify, analyses=analyses)
