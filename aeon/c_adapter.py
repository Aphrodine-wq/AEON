"""AEON C/C++ Adapter — Verify C/C++ Code Using AEON's Analysis Engines.

Translates C or C++ source code into AEON's internal representation and
runs the full verification suite. Uses regex-based parsing.

Usage:
    from aeon.c_adapter import verify_c, verify_cpp
    result = verify_c('''
        int divide(int a, int b) {
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


# ---------------------------------------------------------------------------
# Type maps
# ---------------------------------------------------------------------------

_C_TYPE_MAP: Dict[str, str] = {
    "int": "Int", "short": "Int", "long": "Int", "long long": "Int",
    "unsigned": "Int", "unsigned int": "Int", "unsigned long": "Int",
    "signed": "Int", "signed int": "Int",
    "int8_t": "Int", "int16_t": "Int", "int32_t": "Int", "int64_t": "Int",
    "uint8_t": "Int", "uint16_t": "Int", "uint32_t": "Int", "uint64_t": "Int",
    "size_t": "Int", "ssize_t": "Int", "ptrdiff_t": "Int",
    "float": "Float", "double": "Float", "long double": "Float",
    "char": "String", "char*": "String", "const char*": "String",
    "bool": "Bool", "_Bool": "Bool",
    "void": "Void",
    "FILE": "Void",
    "string": "String", "std::string": "String",
    "vector": "List", "std::vector": "List",
    "map": "Map", "std::map": "Map",
}

_C_NOISE_PATTERNS = [
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

_C_SIDE_EFFECT_FUNCS = {
    "printf", "fprintf", "sprintf", "snprintf",
    "scanf", "fscanf", "sscanf",
    "puts", "fputs", "putchar", "fputc",
    "gets", "fgets", "getchar", "fgetc",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "rewind",
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memmove", "memset",
    "open", "close", "read", "write",
    "socket", "bind", "listen", "accept", "connect", "send", "recv",
    "exit", "abort", "atexit",
    "system", "exec", "fork", "wait",
    "pthread_create", "pthread_join", "pthread_mutex_lock", "pthread_mutex_unlock",
    # C++ specific
    "cout", "cin", "cerr", "endl",
    "new", "delete",
    "std::cout", "std::cin", "std::cerr",
    "push_back", "pop_back", "insert", "erase", "clear",
}

_CPP_SIDE_EFFECT_METHODS = {
    "push_back", "pop_back", "insert", "erase", "clear", "resize",
    "open", "close", "read", "write", "flush",
    "lock", "unlock", "try_lock",
    "push", "pop", "front", "back",
    "send", "receive", "connect", "bind",
    "join", "detach",
}


# ---------------------------------------------------------------------------
# Regex-based C/C++ parser
# ---------------------------------------------------------------------------

class _RegexCParser:
    """Lightweight regex-based C/C++ parser."""

    def __init__(self, is_cpp: bool = False):
        self.is_cpp = is_cpp

    def parse_functions(self, source: str) -> List[Dict[str, Any]]:
        """Extract function definitions from C/C++ source."""
        functions: List[Dict[str, Any]] = []

        # Strip preprocessor directives for cleaner parsing
        clean_source = re.sub(r'#\s*(?:include|define|ifdef|ifndef|endif|pragma|if|else|elif|undef)\s*[^\n]*', '', source)

        # C functions: type name(params) {
        # Also matches: static type name, inline type name, etc.
        pattern = r'(?:(?:static|inline|extern|virtual|override|const)\s+)*(\w[\w\s\*&]*?)\s+(\w+)\s*\(([^)]*)\)\s*(?:const\s*)?(?:override\s*)?(?:noexcept\s*)?\{'
        for m in re.finditer(pattern, clean_source):
            return_type = m.group(1).strip()
            name = m.group(2)
            params_str = m.group(3)

            # Skip control flow keywords
            if name in ('if', 'while', 'for', 'switch', 'catch', 'do', 'else', 'try'):
                continue
            # Skip common macros
            if return_type in ('if', 'while', 'for', 'switch', 'return', 'else', 'case', 'default'):
                continue

            body = self._extract_brace_body(clean_source, m.end() - 1)
            pre_comments = self._get_preceding_comments(source, m.start())

            functions.append({
                "name": name,
                "params": self._parse_params(params_str),
                "return_type": return_type,
                "body": body,
                "line": source[:m.start()].count('\n') + 1,
                "comments": pre_comments,
            })

        # C++ class methods (inside class body)
        if self.is_cpp:
            class_pattern = r'class\s+(\w+)\s*(?::\s*(?:public|private|protected)\s+\w+\s*)?\{'
            for cm in re.finditer(class_pattern, clean_source):
                class_name = cm.group(1)
                class_body = self._extract_brace_body(clean_source, cm.end() - 1)

                method_pattern = r'(?:(?:static|virtual|inline|override|const)\s+)*(\w[\w\s\*&]*?)\s+(\w+)\s*\(([^)]*)\)\s*(?:const\s*)?(?:override\s*)?(?:noexcept\s*)?\{'
                for mm in re.finditer(method_pattern, class_body):
                    return_type = mm.group(1).strip()
                    method_name = mm.group(2)
                    params_str = mm.group(3)

                    if method_name in ('if', 'while', 'for', 'switch', 'catch', 'do'):
                        continue

                    body = self._extract_brace_body(class_body, mm.end() - 1)

                    functions.append({
                        "name": f"{class_name}_{method_name}",
                        "params": self._parse_params(params_str),
                        "return_type": return_type,
                        "body": body,
                        "line": source[:cm.start()].count('\n') + class_body[:mm.start()].count('\n') + 1,
                        "comments": "",
                        "class_name": class_name,
                    })

        return functions

    def parse_structs(self, source: str) -> List[Dict[str, Any]]:
        """Extract struct/class definitions."""
        structs: List[Dict[str, Any]] = []

        # struct Name { ... }
        pattern = r'(?:typedef\s+)?struct\s+(\w+)\s*\{'
        for m in re.finditer(pattern, source):
            struct_body = self._extract_brace_body(source, m.end() - 1)
            fields = self._parse_struct_fields(struct_body)
            structs.append({
                "name": m.group(1),
                "fields": fields,
                "line": source[:m.start()].count('\n') + 1,
            })

        # C++ classes
        if self.is_cpp:
            class_pattern = r'class\s+(\w+)\s*(?::\s*(?:public|private|protected)\s+\w+\s*)?\{'
            for m in re.finditer(class_pattern, source):
                class_body = self._extract_brace_body(source, m.end() - 1)
                fields = self._parse_class_fields(class_body)
                structs.append({
                    "name": m.group(1),
                    "fields": fields,
                    "line": source[:m.start()].count('\n') + 1,
                })

        return structs

    def _parse_params(self, params_str: str) -> List[Dict[str, str]]:
        """Parse C/C++ parameter list."""
        params = []
        if not params_str.strip() or params_str.strip() == 'void':
            return params

        for p in params_str.split(','):
            p = p.strip()
            if not p:
                continue
            # Type name or Type* name or const Type& name
            match = re.match(r'(.+?)\s+([*&]?\s*\w+)\s*$', p)
            if match:
                type_name = match.group(1).strip()
                name = match.group(2).strip().lstrip('*&').strip()
                params.append({"name": name, "type": type_name})
            else:
                # Just a type (unnamed param)
                params.append({"name": f"arg{len(params)}", "type": p.strip()})

        return params

    def _parse_struct_fields(self, body: str) -> List[Dict[str, str]]:
        """Parse struct field declarations."""
        fields = []
        for line in body.strip().split('\n'):
            line = line.strip().rstrip(';')
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
            match = re.match(r'(.+?)\s+(\w+)\s*$', line)
            if match:
                fields.append({
                    "name": match.group(2),
                    "type": match.group(1).strip(),
                })
        return fields

    def _parse_class_fields(self, body: str) -> List[Dict[str, str]]:
        """Parse C++ class field declarations (skip methods)."""
        fields = []
        for line in body.strip().split('\n'):
            line = line.strip().rstrip(';')
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
            if '(' in line or '{' in line:
                continue  # Skip methods
            # Skip access specifiers
            if line in ('public:', 'private:', 'protected:'):
                continue
            match = re.match(r'(.+?)\s+(\w+)\s*$', line)
            if match:
                fields.append({
                    "name": match.group(2),
                    "type": match.group(1).strip(),
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
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                comments.insert(0, stripped)
            else:
                break
        return '\n'.join(comments)


# ---------------------------------------------------------------------------
# C/C++ Translator base
# ---------------------------------------------------------------------------

class _BaseCTranslator(LanguageTranslator):
    """Shared translation logic for C and C++."""

    def __init__(self):
        super().__init__()
        self.declarations: List = []
        self._is_cpp = False

    @property
    def noise_patterns(self) -> List[str]:
        return _C_NOISE_PATTERNS

    def translate(self, source: str) -> Program:
        """Parse C/C++ source and translate to AEON Program."""
        self.declarations = []
        parser = _RegexCParser(is_cpp=self._is_cpp)

        # Extract and translate structs/classes
        for struct_info in parser.parse_structs(source):
            self._translate_struct(struct_info)

        # Extract and translate functions
        for func_info in parser.parse_functions(source):
            func = self._translate_func(func_info)
            if func:
                self.declarations.append(func)

        return Program(declarations=self.declarations)

    def _translate_struct(self, struct_info: Dict[str, Any]) -> None:
        """Translate a C struct / C++ class to AEON DataDef."""
        loc = SourceLocation(line=struct_info.get("line", 0), column=0,
                             file=f"<{'cpp' if self._is_cpp else 'c'}>")
        fields = []
        for f in struct_info.get("fields", []):
            field_type = self._map_type(f.get("type", "void"))
            fields.append(Parameter(name=f["name"], type_annotation=field_type, location=loc))

        self.declarations.append(DataDef(
            name=struct_info["name"],
            fields=fields,
            location=loc,
        ))

    def _translate_func(self, func_info: Dict[str, Any]) -> Optional[PureFunc | TaskFunc]:
        """Translate a C/C++ function to AEON PureFunc or TaskFunc."""
        loc = SourceLocation(line=func_info.get("line", 0), column=0,
                             file=f"<{'cpp' if self._is_cpp else 'c'}>")

        # Parameters
        params = []
        for p in func_info.get("params", []):
            param_type = self._map_type(p.get("type", "void"))
            params.append(Parameter(name=p["name"], type_annotation=param_type, location=loc))

        # Return type
        rt = func_info.get("return_type", "void")
        return_type = self._map_type(rt)

        # Contracts from comments
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
        """Map a C/C++ type to AEON TypeAnnotation."""
        if not type_str:
            return TypeAnnotation(name="Void")
        type_str = type_str.strip()

        # Strip const, volatile, pointer, reference markers
        clean = re.sub(r'\b(const|volatile|static|extern|inline|register|restrict)\b', '', type_str).strip()
        clean = clean.rstrip('*&').strip()

        # Handle C++ templates: vector<int>
        template_match = re.match(r'(\w+(?:::\w+)?)<(.+)>', clean)
        if template_match:
            base = template_match.group(1)
            inner = template_match.group(2)
            if base in ('vector', 'std::vector', 'list', 'std::list'):
                return TypeAnnotation(name="List", generic_args=[self._map_type(inner)])
            if base in ('map', 'std::map', 'unordered_map', 'std::unordered_map'):
                parts = inner.split(',', 1)
                if len(parts) == 2:
                    return TypeAnnotation(name="Map", generic_args=[
                        self._map_type(parts[0]),
                        self._map_type(parts[1]),
                    ])

        # Handle pointer types as the base type
        if '*' in type_str:
            base = type_str.replace('*', '').strip()
            return TypeAnnotation(name=_C_TYPE_MAP.get(base, base))

        return TypeAnnotation(name=_C_TYPE_MAP.get(clean, clean))

    def _translate_body_str(self, body: str) -> List[Statement]:
        """Translate function body to AEON statements."""
        stmts: List[Statement] = []
        lines = body.strip().split('\n')

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue

            loc = SourceLocation(line=i + 1, column=0,
                                 file=f"<{'cpp' if self._is_cpp else 'c'}>")

            # return
            ret_match = re.match(r'return\s+(.+?)\s*;\s*$', stripped)
            if ret_match:
                expr = self._parse_simple_expr(ret_match.group(1), loc)
                stmts.append(ReturnStmt(value=expr, location=loc))
                continue

            # Variable declaration: type name = expr;
            var_match = re.match(r'(?:(?:const|auto|static)\s+)?(\w[\w\s\*&]*?)\s+(\w+)\s*=\s*(.+?)\s*;\s*$', stripped)
            if var_match:
                type_name = var_match.group(1).strip()
                name = var_match.group(2)
                val_str = var_match.group(3)
                if type_name not in ('if', 'while', 'for', 'return', 'switch'):
                    value = self._parse_simple_expr(val_str, loc)
                    stmts.append(LetStmt(name=name, type_annotation=self._map_type(type_name),
                                         value=value, location=loc))
                    continue

            # if statement
            if_match = re.match(r'if\s*\((.+?)\)\s*\{?', stripped)
            if if_match:
                condition = self._parse_simple_expr(if_match.group(1), loc)
                stmts.append(IfStmt(condition=condition, then_body=[], else_body=[], location=loc))
                continue

            # while/for loop
            while_match = re.match(r'(?:while|for)\s*\((.+?)\)\s*\{?', stripped)
            if while_match:
                condition = self._parse_simple_expr(while_match.group(1).split(';')[0] if ';' in while_match.group(1) else while_match.group(1), loc)
                stmts.append(WhileStmt(condition=condition, body=[], location=loc))
                continue

            # Expression statement
            if stripped.endswith(';'):
                stripped = stripped[:-1]
            if stripped and not stripped.startswith('{') and not stripped.startswith('}'):
                expr = self._parse_simple_expr(stripped, loc)
                stmts.append(ExprStmt(expr=expr, location=loc))

        return stmts

    def _parse_simple_expr(self, expr_str: str, loc: SourceLocation) -> Expr:
        """Parse a simple expression to AEON Expr."""
        expr_str = expr_str.strip()

        if expr_str in ("true", "TRUE"):
            return BoolLiteral(value=True, location=loc)
        if expr_str in ("false", "FALSE"):
            return BoolLiteral(value=False, location=loc)
        if expr_str in ("NULL", "nullptr", "0"):
            return IntLiteral(value=0, location=loc)

        # String literal
        if (expr_str.startswith('"') and expr_str.endswith('"')):
            return StringLiteral(value=expr_str[1:-1], location=loc)

        # Char literal
        if expr_str.startswith("'") and expr_str.endswith("'"):
            return StringLiteral(value=expr_str[1:-1], location=loc)

        # Numeric literal
        if re.match(r'^-?\d+$', expr_str):
            return IntLiteral(value=int(expr_str), location=loc)
        if re.match(r'^-?\d+\.\d+[fF]?$', expr_str):
            return FloatLiteral(value=float(expr_str.rstrip('fF')), location=loc)
        if re.match(r'^0x[0-9a-fA-F]+$', expr_str):
            return IntLiteral(value=int(expr_str, 16), location=loc)

        # Binary operations
        for op in ("!=", "==", ">=", "<=", "&&", "||", ">", "<", "+", "-", "*", "/", "%"):
            if op in expr_str:
                parts = expr_str.split(op, 1)
                if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                    left = self._parse_simple_expr(parts[0], loc)
                    right = self._parse_simple_expr(parts[1], loc)
                    return BinaryOp(op=op, left=left, right=right, location=loc)

        # Function call
        call_match = re.match(r'(\w+(?:::\w+)?)\(([^)]*)\)', expr_str)
        if call_match:
            func_name, args_str = call_match.groups()
            args = [self._parse_simple_expr(a.strip(), loc) for a in args_str.split(',') if a.strip()] if args_str.strip() else []
            return FunctionCall(
                callee=Identifier(name=func_name, location=loc),
                args=args,
                location=loc,
            )

        # Member access: obj.member or obj->member or obj::member
        for sep in ('->', '::', '.'):
            if sep in expr_str:
                parts = expr_str.rsplit(sep, 1)
                if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                    return FieldAccess(
                        obj=Identifier(name=parts[0].strip(), location=loc),
                        field_name=parts[1].strip(),
                        location=loc,
                    )

        # Identifier
        if re.match(r'^[a-zA-Z_]\w*$', expr_str):
            return Identifier(name=expr_str, location=loc)

        return Identifier(name="__unknown__", location=loc)

    def _extract_contracts(self, comments: str) -> Tuple[List[ContractClause], List[ContractClause]]:
        """Extract contracts from C/C++ comments."""
        requires: List[ContractClause] = []
        ensures: List[ContractClause] = []

        for line in comments.split('\n'):
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
        for func in _C_SIDE_EFFECT_FUNCS:
            if func in body:
                return True
        if self._is_cpp:
            for method in _CPP_SIDE_EFFECT_METHODS:
                if f'.{method}(' in body:
                    return True
        # Pointer dereference writes
        if re.search(r'\*\w+\s*=', body):
            return True
        return False

    def _infer_effects(self, body: str) -> List[str]:
        """Infer AEON effects from C/C++ function body."""
        effects = set()
        if any(f in body for f in ("printf", "fprintf", "puts", "fputs", "cout", "cerr")):
            effects.add("Console.Write")
        if any(f in body for f in ("scanf", "fscanf", "gets", "fgets", "cin", "getchar")):
            effects.add("Console.Read")
        if any(f in body for f in ("fopen", "fclose", "fread", "fwrite", "open", "close")):
            effects.add("File.Write")
        if any(f in body for f in ("malloc", "calloc", "realloc", "free", "new", "delete")):
            effects.add("Memory.Alloc")
        if any(f in body for f in ("socket", "bind", "listen", "connect", "send", "recv")):
            effects.add("Network.Write")
        if any(f in body for f in ("pthread_", "mutex", "std::thread", "std::mutex")):
            effects.add("Sync.Lock")
        return sorted(effects)


# ---------------------------------------------------------------------------
# C Translator
# ---------------------------------------------------------------------------

class CTranslator(_BaseCTranslator):
    """Translates C source code to AEON AST."""

    @property
    def language_name(self) -> str:
        return "C"

    @property
    def file_extensions(self) -> List[str]:
        return [".c", ".h"]

    def __init__(self):
        super().__init__()
        self._is_cpp = False


# ---------------------------------------------------------------------------
# C++ Translator
# ---------------------------------------------------------------------------

class CppTranslator(_BaseCTranslator):
    """Translates C++ source code to AEON AST."""

    @property
    def language_name(self) -> str:
        return "C++"

    @property
    def file_extensions(self) -> List[str]:
        return [".cpp", ".hpp", ".cc", ".cxx", ".hxx"]

    def __init__(self):
        super().__init__()
        self._is_cpp = True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_c(source: str, deep_verify: bool = True,
             analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify C code using AEON's analysis engines."""
    return _verify(source, "c", deep_verify=deep_verify, analyses=analyses)


def verify_cpp(source: str, deep_verify: bool = True,
               analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify C++ code using AEON's analysis engines."""
    return _verify(source, "cpp", deep_verify=deep_verify, analyses=analyses)
