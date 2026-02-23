"""AEON Java Adapter — Verify Java Code Using AEON's Analysis Engines.

Translates Java source code into AEON's internal representation and
runs the full verification suite. Uses the `javalang` library for parsing.

Usage:
    from aeon.java_adapter import verify_java
    result = verify_java('''
        public int divide(int a, int b) {
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
    Statement, ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
)
from aeon.errors import SourceLocation
from aeon.language_adapter import LanguageTranslator, VerificationResult, verify as _verify

try:
    import javalang
    HAS_JAVALANG = True
except ImportError:
    HAS_JAVALANG = False


# ---------------------------------------------------------------------------
# Java -> AEON AST Translation
# ---------------------------------------------------------------------------

_JAVA_TYPE_MAP: Dict[str, str] = {
    "int": "Int", "Integer": "Int", "long": "Int", "Long": "Int",
    "short": "Int", "Short": "Int", "byte": "Int", "Byte": "Int",
    "double": "Float", "Double": "Float", "float": "Float", "Float": "Float",
    "boolean": "Bool", "Boolean": "Bool",
    "String": "String", "char": "String", "Character": "String",
    "void": "Void",
    "Object": "Void",
}

_JAVA_NOISE_PATTERNS = [
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

_JAVA_SIDE_EFFECT_METHODS = {
    "println", "print", "printf", "write", "flush", "close",
    "read", "readLine", "next", "nextInt", "nextLine",
    "executeQuery", "executeUpdate", "execute", "commit", "rollback",
    "send", "receive", "connect", "accept",
    "add", "remove", "put", "set", "clear", "push", "pop",
    "delete", "mkdir", "mkdirs", "createNewFile",
}

_JAVA_SIDE_EFFECT_CLASSES = {
    "System", "Scanner", "BufferedReader", "FileReader", "FileWriter",
    "PrintWriter", "Socket", "ServerSocket", "HttpURLConnection",
    "Connection", "Statement", "PreparedStatement", "ResultSet",
}


class JavaTranslator(LanguageTranslator):
    """Translates Java source code to AEON AST for verification."""

    @property
    def language_name(self) -> str:
        return "Java"

    @property
    def file_extensions(self) -> List[str]:
        return [".java"]

    @property
    def noise_patterns(self) -> List[str]:
        return _JAVA_NOISE_PATTERNS

    def __init__(self):
        super().__init__()
        self.declarations: List = []

    def translate(self, source: str) -> Program:
        """Parse Java source and translate to AEON Program."""
        if not HAS_JAVALANG:
            self.errors.append("javalang library not installed. Run: pip install javalang")
            return Program(declarations=[])

        # Wrap bare methods in a class if needed
        source = self._ensure_class_wrapper(source)

        try:
            tree = javalang.parse.parse(source)
        except javalang.parser.JavaSyntaxError as e:
            self.errors.append(f"Java syntax error: {e}")
            return Program(declarations=[])
        except Exception as e:
            self.errors.append(f"Java parse error: {e}")
            return Program(declarations=[])

        self.declarations = []

        for type_decl in (tree.types or []):
            if isinstance(type_decl, javalang.tree.ClassDeclaration):
                self._translate_class(type_decl)
            elif isinstance(type_decl, javalang.tree.InterfaceDeclaration):
                self._translate_interface(type_decl)

        return Program(declarations=self.declarations)

    def _ensure_class_wrapper(self, source: str) -> str:
        """If the source contains bare methods (no class), wrap them."""
        stripped = source.strip()
        # Quick check: if there's no class/interface declaration, wrap it
        if not re.search(r'\b(class|interface|enum)\s+\w+', stripped):
            return f"public class _AeonWrapper {{\n{source}\n}}"
        return source

    def _translate_class(self, node) -> None:
        """Translate a Java class to AEON DataDef + method PureFuncs."""
        pos = getattr(node, 'position', None)
        loc = SourceLocation(line=pos.line if pos else 0, column=pos.column if pos else 0, file="<java>")

        # Translate fields to DataDef
        fields = []
        for field_decl in (node.fields or []):
            field_type = self._translate_type(field_decl.type)
            for declarator in field_decl.declarators:
                fields.append(Parameter(
                    name=declarator.name,
                    type_annotation=field_type,
                    location=loc,
                ))

        if fields or node.name != "_AeonWrapper":
            self.declarations.append(DataDef(
                name=node.name,
                fields=fields,
                location=loc,
            ))

        # Translate methods
        for method in (node.methods or []):
            func = self._translate_method(method, class_name=node.name)
            if func:
                self.declarations.append(func)

        # Translate constructors as methods
        for constructor in (node.constructors or []):
            func = self._translate_constructor(constructor, class_name=node.name)
            if func:
                self.declarations.append(func)

    def _translate_interface(self, node) -> None:
        """Translate a Java interface to AEON DataDef."""
        pos = getattr(node, 'position', None)
        loc = SourceLocation(line=pos.line if pos else 0, column=pos.column if pos else 0, file="<java>")
        self.declarations.append(DataDef(
            name=node.name,
            fields=[],
            location=loc,
        ))

    def _translate_method(self, node, class_name: str = "") -> Optional[PureFunc | TaskFunc]:
        """Translate a Java method to AEON PureFunc or TaskFunc."""
        pos = getattr(node, 'position', None)
        loc = SourceLocation(line=pos.line if pos else 0, column=pos.column if pos else 0, file="<java>")

        # Parameters
        params = []
        for param in (node.parameters or []):
            param_type = self._translate_type(param.type)
            params.append(Parameter(
                name=param.name,
                type_annotation=param_type,
                location=loc,
            ))

        # Return type
        return_type = self._translate_type(node.return_type) if node.return_type else TypeAnnotation(name="Void")

        # Extract contracts from Javadoc
        requires, ensures = self._extract_javadoc_contracts(node)

        # Translate body
        body = self._translate_body(node.body) if node.body else []

        # Determine if pure or task
        has_side_effects = self._method_has_side_effects(node)

        name = node.name
        if class_name and class_name != "_AeonWrapper":
            name = f"{class_name}_{node.name}"

        if has_side_effects:
            effects = self._infer_effects(node)
            return TaskFunc(
                name=name,
                params=params,
                return_type=return_type,
                requires=requires,
                ensures=ensures,
                effects=effects,
                body=body,
                location=loc,
            )
        else:
            return PureFunc(
                name=name,
                params=params,
                return_type=return_type,
                requires=requires,
                ensures=ensures,
                body=body,
                location=loc,
            )

    def _translate_constructor(self, node, class_name: str) -> Optional[PureFunc]:
        """Translate a Java constructor to AEON PureFunc."""
        pos = getattr(node, 'position', None)
        loc = SourceLocation(line=pos.line if pos else 0, column=pos.column if pos else 0, file="<java>")

        params = []
        for param in (node.parameters or []):
            param_type = self._translate_type(param.type)
            params.append(Parameter(name=param.name, type_annotation=param_type, location=loc))

        body = self._translate_body(node.body) if node.body else []

        return PureFunc(
            name=f"{class_name}_init",
            params=params,
            return_type=TypeAnnotation(name=class_name),
            requires=[],
            ensures=[],
            body=body,
            location=loc,
        )

    def _translate_type(self, type_node) -> TypeAnnotation:
        """Translate a Java type to AEON TypeAnnotation."""
        if type_node is None:
            return TypeAnnotation(name="Void")

        if isinstance(type_node, javalang.tree.BasicType):
            return TypeAnnotation(name=_JAVA_TYPE_MAP.get(type_node.name, type_node.name))

        if isinstance(type_node, javalang.tree.ReferenceType):
            base_name = type_node.name
            mapped = _JAVA_TYPE_MAP.get(base_name, base_name)
            if type_node.arguments:
                # Generic type, e.g. List<String>
                generic_args = []
                for arg in type_node.arguments:
                    if arg.type:
                        generic_args.append(self._translate_type(arg.type))
                return TypeAnnotation(name=mapped, generic_args=generic_args)
            return TypeAnnotation(name=mapped)

        return TypeAnnotation(name="Void")

    def _translate_body(self, body_nodes) -> List[Statement]:
        """Translate a list of Java statements."""
        stmts = []
        if body_nodes is None:
            return stmts
        for node in body_nodes:
            translated = self._translate_statement(node)
            if translated:
                stmts.append(translated)
        return stmts

    def _translate_statement(self, node) -> Optional[Statement]:
        """Translate a Java statement to AEON Statement."""
        pos = getattr(node, 'position', None)
        loc = SourceLocation(line=pos.line if pos else 0, column=pos.column if pos else 0, file="<java>")

        if isinstance(node, javalang.tree.ReturnStatement):
            value = self._translate_expr(node.expression) if node.expression else None
            return ReturnStmt(value=value, location=loc)

        if isinstance(node, javalang.tree.LocalVariableDeclaration):
            var_type = self._translate_type(node.type)
            for declarator in node.declarators:
                value = self._translate_expr(declarator.initializer) if declarator.initializer else None
                return LetStmt(
                    name=declarator.name,
                    type_annotation=var_type,
                    value=value,
                    location=loc,
                )

        if isinstance(node, javalang.tree.IfStatement):
            condition = self._translate_expr(node.condition)
            then_body = []
            if node.then_statement:
                if isinstance(node.then_statement, javalang.tree.BlockStatement):
                    then_body = self._translate_body(node.then_statement.statements)
                else:
                    s = self._translate_statement(node.then_statement)
                    if s:
                        then_body = [s]
            else_body = []
            if node.else_statement:
                if isinstance(node.else_statement, javalang.tree.BlockStatement):
                    else_body = self._translate_body(node.else_statement.statements)
                else:
                    s = self._translate_statement(node.else_statement)
                    if s:
                        else_body = [s]
            return IfStmt(condition=condition, then_body=then_body, else_body=else_body, location=loc)

        if isinstance(node, javalang.tree.WhileStatement):
            condition = self._translate_expr(node.condition)
            body = []
            if node.body:
                if isinstance(node.body, javalang.tree.BlockStatement):
                    body = self._translate_body(node.body.statements)
                else:
                    s = self._translate_statement(node.body)
                    if s:
                        body = [s]
            return WhileStmt(condition=condition, body=body, location=loc)

        if isinstance(node, javalang.tree.ForStatement):
            # Translate for-loop as while with initialization
            body = []
            if node.body:
                if isinstance(node.body, javalang.tree.BlockStatement):
                    body = self._translate_body(node.body.statements)
                else:
                    s = self._translate_statement(node.body)
                    if s:
                        body = [s]
            condition = self._translate_expr(node.condition) if node.condition else BoolLiteral(value=True, location=loc)
            return WhileStmt(condition=condition, body=body, location=loc)

        if isinstance(node, javalang.tree.StatementExpression):
            expr = self._translate_expr(node.expression)
            return ExprStmt(expr=expr, location=loc)

        if isinstance(node, javalang.tree.BlockStatement):
            stmts = self._translate_body(node.statements)
            if stmts:
                return stmts[0]  # Flatten single-block

        if isinstance(node, javalang.tree.ThrowStatement):
            return ExprStmt(
                expr=FunctionCall(
                    callee=Identifier(name="throw", location=loc),
                    args=[self._translate_expr(node.expression)] if node.expression else [],
                    location=loc,
                ),
                location=loc,
            )

        return None

    def _translate_expr(self, node) -> Expr:
        """Translate a Java expression to AEON Expr."""
        if node is None:
            return IntLiteral(value=0)

        pos = getattr(node, 'position', None)
        loc = SourceLocation(line=pos.line if pos else 0, column=pos.column if pos else 0, file="<java>")

        if isinstance(node, javalang.tree.Literal):
            val = node.value
            if val in ("true", "false"):
                return BoolLiteral(value=(val == "true"), location=loc)
            if val.startswith('"') or val.startswith("'"):
                return StringLiteral(value=val.strip('"\''), location=loc)
            if '.' in val:
                try:
                    return FloatLiteral(value=float(val.rstrip('fFdD')), location=loc)
                except ValueError:
                    return FloatLiteral(value=0.0, location=loc)
            try:
                clean = val.rstrip('lL')
                if clean.startswith('0x') or clean.startswith('0X'):
                    return IntLiteral(value=int(clean, 16), location=loc)
                return IntLiteral(value=int(clean), location=loc)
            except ValueError:
                return IntLiteral(value=0, location=loc)

        if isinstance(node, javalang.tree.MemberReference):
            if node.qualifier:
                return FieldAccess(
                    obj=Identifier(name=node.qualifier, location=loc),
                    field_name=node.member,
                    location=loc,
                )
            return Identifier(name=node.member, location=loc)

        if isinstance(node, javalang.tree.BinaryOperation):
            left = self._translate_expr(node.operandl)
            right = self._translate_expr(node.operandr)
            op_map = {
                "+": "+", "-": "-", "*": "*", "/": "/", "%": "%",
                "==": "==", "!=": "!=", "<": "<", ">": ">",
                "<=": "<=", ">=": ">=",
                "&&": "&&", "||": "||",
                "&": "&&", "|": "||",
            }
            op = op_map.get(node.operator, node.operator)
            return BinaryOp(op=op, left=left, right=right, location=loc)

        if isinstance(node, javalang.tree.TernaryExpression):
            return FunctionCall(
                callee=Identifier(name="__ite__", location=loc),
                args=[
                    self._translate_expr(node.condition),
                    self._translate_expr(node.if_true),
                    self._translate_expr(node.if_false),
                ],
                location=loc,
            )

        if isinstance(node, (javalang.tree.MethodInvocation,)):
            args = [self._translate_expr(a) for a in (node.arguments or [])]
            if node.qualifier:
                return MethodCall(
                    obj=Identifier(name=node.qualifier, location=loc),
                    method_name=node.member,
                    args=args,
                    location=loc,
                )
            return FunctionCall(
                callee=Identifier(name=node.member, location=loc),
                args=args,
                location=loc,
            )

        if isinstance(node, javalang.tree.ClassCreator):
            type_name = node.type.name if node.type else "Unknown"
            args = [self._translate_expr(a) for a in (node.arguments or [])]
            return FunctionCall(
                callee=Identifier(name=f"new_{type_name}", location=loc),
                args=args,
                location=loc,
            )

        if isinstance(node, javalang.tree.Assignment):
            target = self._translate_expr(node.expressionl)
            value = self._translate_expr(node.value)
            return BinaryOp(op="=", left=target, right=value, location=loc)

        if isinstance(node, javalang.tree.Cast):
            return self._translate_expr(node.expression)

        if isinstance(node, javalang.tree.This):
            return Identifier(name="this", location=loc)

        return Identifier(name="__unknown__", location=loc)

    def _extract_javadoc_contracts(self, node) -> Tuple[List[ContractClause], List[ContractClause]]:
        """Extract contracts from Javadoc comments.

        Supports:
            /** @requires x > 0 */
            /** @ensures result >= 0 */
            /** Requires: x > 0 */
            /** Ensures: result >= 0 */
        """
        requires: List[ContractClause] = []
        ensures: List[ContractClause] = []

        doc = getattr(node, 'documentation', None) or ""
        if not doc:
            return requires, ensures

        for line in doc.split("\n"):
            line = line.strip().lstrip("*").strip()

            # Match @requires or Requires:
            req_match = re.match(r'(?:@requires|requires\s*:)\s*(.+)', line, re.IGNORECASE)
            if req_match:
                expr = self._parse_contract_expr(req_match.group(1).strip())
                if expr:
                    requires.append(ContractClause(kind="requires", expr=expr))

            # Match @ensures or Ensures:
            ens_match = re.match(r'(?:@ensures|ensures\s*:)\s*(.+)', line, re.IGNORECASE)
            if ens_match:
                expr = self._parse_contract_expr(ens_match.group(1).strip())
                if expr:
                    ensures.append(ContractClause(kind="ensures", expr=expr))

        return requires, ensures

    def _parse_contract_expr(self, expr_str: str) -> Optional[Expr]:
        """Parse a simple contract expression into an AEON Expr."""
        expr_str = expr_str.rstrip("*/").strip()

        # Handle comparison: x != 0, x > 0, x >= 0, etc.
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

    def _method_has_side_effects(self, node) -> bool:
        """Check if a Java method has side effects."""
        if not node.body:
            return False
        for _, child in node.filter(javalang.tree.MethodInvocation):
            if child.member in _JAVA_SIDE_EFFECT_METHODS:
                return True
            if child.qualifier and child.qualifier in _JAVA_SIDE_EFFECT_CLASSES:
                return True
        return False

    def _infer_effects(self, node) -> List[str]:
        """Infer AEON effects from Java method body."""
        effects = set()
        if not node.body:
            return []
        for _, child in node.filter(javalang.tree.MethodInvocation):
            member = child.member
            qualifier = child.qualifier or ""
            if member in ("println", "print", "printf"):
                effects.add("Console.Write")
            elif member in ("readLine", "next", "nextInt", "nextLine"):
                effects.add("Console.Read")
            elif "File" in qualifier or member in ("write", "read"):
                effects.add("File.Write" if member == "write" else "File.Read")
            elif member in ("executeQuery", "executeUpdate", "execute"):
                effects.add("Database.Write")
            elif "Socket" in qualifier or "Http" in qualifier:
                effects.add("Network.Write")
            elif member in ("send", "receive", "connect"):
                effects.add("Network.Write")
        return sorted(effects)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_java(source: str, deep_verify: bool = True,
                analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify Java code using AEON's analysis engines.

    Args:
        source: Java source code string
        deep_verify: Enable all 10 analysis passes
        analyses: Specific analyses to run (overrides deep_verify)

    Returns:
        VerificationResult with errors, warnings, and summary
    """
    return _verify(source, "java", deep_verify=deep_verify, analyses=analyses)
