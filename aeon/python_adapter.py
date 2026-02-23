"""AEON Python Adapter — Verify Python Code Using AEON's Analysis Engines.

Translates Python source code into AEON's internal representation and
runs the full verification suite. This lets developers verify Python code
without learning AEON's syntax.

Usage:
    from aeon.python_adapter import verify_python
    results = verify_python('''
        def divide(a: int, b: int) -> int:
            return a // b
    ''')
"""

from __future__ import annotations

import ast as python_ast
import textwrap
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Parameter, TypeAnnotation, ContractClause,
    Statement, ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
)
from aeon.errors import AeonError, SourceLocation
from aeon.language_adapter import LanguageTranslator, VerificationResult, verify as _verify


# ---------------------------------------------------------------------------
# Python -> AEON AST Translation
# ---------------------------------------------------------------------------

_PYTHON_NOISE_PATTERNS = [
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


class PythonTranslator(LanguageTranslator, python_ast.NodeVisitor):
    """Translates Python AST to AEON AST for verification."""

    @property
    def language_name(self) -> str:
        return "Python"

    @property
    def file_extensions(self) -> List[str]:
        return [".py"]

    @property
    def noise_patterns(self) -> List[str]:
        return _PYTHON_NOISE_PATTERNS

    def __init__(self, source: str = ""):
        LanguageTranslator.__init__(self)
        self.declarations: List = []
        self.source = source
        self._in_class: Optional[str] = None

    def translate(self, source: str) -> Program:
        """Parse Python source and translate to AEON Program."""
        self.source = source
        try:
            tree = python_ast.parse(textwrap.dedent(source))
        except SyntaxError as e:
            self.errors.append(f"Python syntax error: {e}")
            return Program(declarations=[])

        self.declarations = []
        for node in python_ast.iter_child_nodes(tree):
            self._translate_top_level(node)

        return Program(declarations=self.declarations)

    def _translate_top_level(self, node) -> None:
        """Translate a top-level Python node."""
        if isinstance(node, python_ast.FunctionDef):
            func = self._translate_function(node)
            if func:
                self.declarations.append(func)

        elif isinstance(node, python_ast.AsyncFunctionDef):
            func = self._translate_function(node, is_async=True)
            if func:
                self.declarations.append(func)

        elif isinstance(node, python_ast.ClassDef):
            data = self._translate_class(node)
            if data:
                self.declarations.append(data)
                # Also translate methods
                self._in_class = node.name
                for item in node.body:
                    if isinstance(item, python_ast.FunctionDef):
                        func = self._translate_function(item)
                        if func:
                            func.name = f"{node.name}_{func.name}"
                            self.declarations.append(func)
                self._in_class = None

    def _translate_function(self, node: python_ast.FunctionDef,
                           is_async: bool = False) -> Optional[PureFunc | TaskFunc]:
        """Translate a Python function to AEON PureFunc or TaskFunc."""
        loc = SourceLocation(file="<python>", line=node.lineno, column=node.col_offset)

        # Translate parameters
        params = []
        for arg in node.args.args:
            if arg.arg == "self":
                continue
            type_ann = self._translate_type_annotation(arg.annotation)
            params.append(Parameter(
                name=arg.arg,
                type_annotation=type_ann,
                location=loc,
            ))

        # Translate return type
        return_type = self._translate_type_annotation(node.returns)

        # Extract docstring contracts (requires/ensures from docstring)
        requires, ensures = self._extract_contracts(node)

        # Translate body
        body = []
        for stmt in node.body:
            translated = self._translate_statement(stmt)
            if translated:
                body.append(translated)

        # Determine if pure or task
        has_side_effects = is_async or self._has_side_effects(node)

        if has_side_effects:
            effects = self._infer_effects(node)
            func = TaskFunc(
                name=node.name,
                params=params,
                return_type=return_type,
                requires=requires,
                ensures=ensures,
                effects=effects,
                body=body,
                location=loc,
            )
        else:
            func = PureFunc(
                name=node.name,
                params=params,
                return_type=return_type,
                requires=requires,
                ensures=ensures,
                body=body,
                location=loc,
            )

        return func

    def _translate_class(self, node: python_ast.ClassDef) -> Optional[DataDef]:
        """Translate a Python class to AEON DataDef."""
        loc = SourceLocation(file="<python>", line=node.lineno, column=node.col_offset)
        fields = []

        # Look for __init__ to find fields
        for item in node.body:
            if isinstance(item, python_ast.FunctionDef) and item.name == "__init__":
                for stmt in item.body:
                    if isinstance(stmt, python_ast.AnnAssign):
                        if isinstance(stmt.target, python_ast.Attribute):
                            field_name = stmt.target.attr
                            field_type = self._translate_type_annotation(stmt.annotation)
                            fields.append(Parameter(
                                name=field_name,
                                type_annotation=field_type,
                                location=loc,
                            ))
                    elif isinstance(stmt, python_ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, python_ast.Attribute):
                                fields.append(Parameter(
                                    name=target.attr,
                                    type_annotation=TypeAnnotation(name="Void"),
                                    location=loc,
                                ))

            # Also check class-level annotations (dataclass style)
            elif isinstance(item, python_ast.AnnAssign):
                if isinstance(item.target, python_ast.Name):
                    field_type = self._translate_type_annotation(item.annotation)
                    fields.append(Parameter(
                        name=item.target.id,
                        type_annotation=field_type,
                        location=loc,
                    ))

        return DataDef(name=node.name, fields=fields, location=loc)

    def _translate_statement(self, node) -> Optional[Statement]:
        """Translate a Python statement to AEON Statement."""
        if isinstance(node, python_ast.Return):
            value = self._translate_expr(node.value) if node.value else None
            return ReturnStmt(
                value=value,
                location=SourceLocation("<python>", node.lineno, node.col_offset),
            )

        if isinstance(node, python_ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], python_ast.Name):
                value = self._translate_expr(node.value)
                return LetStmt(
                    name=node.targets[0].id,
                    type_annotation=TypeAnnotation(name="Void"),
                    value=value,
                    location=SourceLocation("<python>", node.lineno, node.col_offset),
                )

        if isinstance(node, python_ast.AnnAssign):
            if isinstance(node.target, python_ast.Name):
                type_ann = self._translate_type_annotation(node.annotation)
                value = self._translate_expr(node.value) if node.value else None
                return LetStmt(
                    name=node.target.id,
                    type_annotation=type_ann,
                    value=value,
                    location=SourceLocation("<python>", node.lineno, node.col_offset),
                )

        if isinstance(node, python_ast.If):
            condition = self._translate_expr(node.test)
            then_body = [self._translate_statement(s) for s in node.body]
            then_body = [s for s in then_body if s is not None]
            else_body = [self._translate_statement(s) for s in node.orelse]
            else_body = [s for s in else_body if s is not None]
            return IfStmt(
                condition=condition,
                then_body=then_body,
                else_body=else_body,
                location=SourceLocation("<python>", node.lineno, node.col_offset),
            )

        if isinstance(node, python_ast.While):
            condition = self._translate_expr(node.test)
            body = [self._translate_statement(s) for s in node.body]
            body = [s for s in body if s is not None]
            return WhileStmt(
                condition=condition,
                body=body,
                location=SourceLocation("<python>", node.lineno, node.col_offset),
            )

        if isinstance(node, python_ast.Expr):
            if isinstance(node.value, python_ast.Constant) and isinstance(node.value.value, str):
                return None  # Skip docstrings
            expr = self._translate_expr(node.value)
            return ExprStmt(
                expr=expr,
                location=SourceLocation("<python>", node.lineno, node.col_offset),
            )

        if isinstance(node, python_ast.Pass):
            return None

        return None

    def _translate_expr(self, node) -> Expr:
        """Translate a Python expression to AEON Expr."""
        if node is None:
            return IntLiteral(value=0)

        loc = SourceLocation("<python>", getattr(node, 'lineno', 0),
                            getattr(node, 'col_offset', 0))

        if isinstance(node, python_ast.Constant):
            if isinstance(node.value, bool):  # bool before int! (bool is subclass of int)
                return BoolLiteral(value=node.value, location=loc)
            if isinstance(node.value, int):
                return IntLiteral(value=node.value, location=loc)
            if isinstance(node.value, float):
                return FloatLiteral(value=node.value, location=loc)
            if isinstance(node.value, str):
                return StringLiteral(value=node.value, location=loc)
            return IntLiteral(value=0, location=loc)

        if isinstance(node, python_ast.Name):
            return Identifier(name=node.id, location=loc)

        if isinstance(node, python_ast.BinOp):
            left = self._translate_expr(node.left)
            right = self._translate_expr(node.right)
            op = self._translate_binop(node.op)
            return BinaryOp(op=op, left=left, right=right, location=loc)

        if isinstance(node, python_ast.BoolOp):
            op = "&&" if isinstance(node.op, python_ast.And) else "||"
            result = self._translate_expr(node.values[0])
            for val in node.values[1:]:
                right = self._translate_expr(val)
                result = BinaryOp(op=op, left=result, right=right, location=loc)
            return result

        if isinstance(node, python_ast.Compare):
            left = self._translate_expr(node.left)
            if len(node.ops) == 1:
                op = self._translate_cmpop(node.ops[0])
                right = self._translate_expr(node.comparators[0])
                return BinaryOp(op=op, left=left, right=right, location=loc)
            # Chain: a < b < c  =>  a < b && b < c
            result = None
            prev = left
            for op_node, comp in zip(node.ops, node.comparators):
                op = self._translate_cmpop(op_node)
                right = self._translate_expr(comp)
                cmp = BinaryOp(op=op, left=prev, right=right, location=loc)
                if result is None:
                    result = cmp
                else:
                    result = BinaryOp(op="&&", left=result, right=cmp, location=loc)
                prev = right
            return result or left

        if isinstance(node, python_ast.UnaryOp):
            operand = self._translate_expr(node.operand)
            if isinstance(node.op, python_ast.USub):
                return UnaryOp(op="-", operand=operand, location=loc)
            if isinstance(node.op, python_ast.Not):
                return UnaryOp(op="!", operand=operand, location=loc)
            return operand

        if isinstance(node, python_ast.Call):
            if isinstance(node.func, python_ast.Name):
                args = [self._translate_expr(a) for a in node.args]
                return FunctionCall(
                    callee=Identifier(name=node.func.id, location=loc),
                    args=args,
                    location=loc,
                )
            if isinstance(node.func, python_ast.Attribute):
                obj = self._translate_expr(node.func.value)
                args = [self._translate_expr(a) for a in node.args]
                return MethodCall(
                    obj=obj,
                    method_name=node.func.attr,
                    args=args,
                    location=loc,
                )
            return Identifier(name="__call__", location=loc)

        if isinstance(node, python_ast.Attribute):
            obj = self._translate_expr(node.value)
            return FieldAccess(obj=obj, field_name=node.attr, location=loc)

        if isinstance(node, python_ast.Subscript):
            obj = self._translate_expr(node.value)
            return FieldAccess(obj=obj, field_name="__getitem__", location=loc)

        if isinstance(node, python_ast.IfExp):
            # Ternary: x if cond else y
            cond = self._translate_expr(node.test)
            then_val = self._translate_expr(node.body)
            else_val = self._translate_expr(node.orelse)
            return FunctionCall(
                callee=Identifier(name="__ite__", location=loc),
                args=[cond, then_val, else_val],
                location=loc,
            )

        return Identifier(name="__unknown__", location=loc)

    def _translate_binop(self, op) -> str:
        ops = {
            python_ast.Add: "+", python_ast.Sub: "-",
            python_ast.Mult: "*", python_ast.Div: "/",
            python_ast.FloorDiv: "/", python_ast.Mod: "%",
        }
        return ops.get(type(op), "+")

    def _translate_cmpop(self, op) -> str:
        ops = {
            python_ast.Eq: "==", python_ast.NotEq: "!=",
            python_ast.Lt: "<", python_ast.LtE: "<=",
            python_ast.Gt: ">", python_ast.GtE: ">=",
        }
        return ops.get(type(op), "==")

    def _translate_type_annotation(self, node) -> TypeAnnotation:
        """Translate a Python type annotation to AEON TypeAnnotation."""
        if node is None:
            return TypeAnnotation(name="Void")
        if isinstance(node, python_ast.Constant):
            return TypeAnnotation(name=str(node.value))
        if isinstance(node, python_ast.Name):
            type_map = {
                "int": "Int", "float": "Float", "str": "String",
                "bool": "Bool", "None": "Void", "list": "List",
            }
            return TypeAnnotation(name=type_map.get(node.id, node.id))
        if isinstance(node, python_ast.Subscript):
            if isinstance(node.value, python_ast.Name):
                base = node.value.id
                if base == "Optional":
                    return TypeAnnotation(name="Void")
                return TypeAnnotation(name=base)
        if isinstance(node, python_ast.Attribute):
            return TypeAnnotation(name=node.attr)
        return TypeAnnotation(name="Void")

    def _extract_contracts(self, node: python_ast.FunctionDef) -> Tuple[List, List]:
        """Extract requires/ensures from Python docstrings.

        Supports format:
            def f(x: int) -> int:
                '''
                Requires: x > 0
                Ensures: result >= 0
                '''
        """
        requires = []
        ensures = []

        docstring = python_ast.get_docstring(node)
        if not docstring:
            return requires, ensures

        for line in docstring.split("\n"):
            line = line.strip()
            if line.lower().startswith("requires:"):
                expr_str = line[len("requires:"):].strip()
                expr = self._parse_contract_expr(expr_str, node)
                if expr:
                    requires.append(ContractClause(
                        kind="requires",
                        expr=expr,
                    ))
            elif line.lower().startswith("ensures:"):
                expr_str = line[len("ensures:"):].strip()
                expr = self._parse_contract_expr(expr_str, node)
                if expr:
                    ensures.append(ContractClause(
                        kind="ensures",
                        expr=expr,
                    ))

        return requires, ensures

    def _parse_contract_expr(self, expr_str: str, node) -> Optional[Expr]:
        """Parse a contract expression string into an AEON Expr."""
        try:
            tree = python_ast.parse(expr_str, mode='eval')
            return self._translate_expr(tree.body)
        except (SyntaxError, ValueError):
            return None

    def _has_side_effects(self, node: python_ast.FunctionDef) -> bool:
        """Heuristic: does a Python function have side effects?"""
        for child in python_ast.walk(node):
            if isinstance(child, python_ast.Call):
                if isinstance(child.func, python_ast.Name):
                    if child.func.id in ("print", "open", "input", "exit",
                                         "write", "exec", "eval"):
                        return True
                if isinstance(child.func, python_ast.Attribute):
                    if child.func.attr in ("write", "read", "send", "recv",
                                           "execute", "commit", "insert",
                                           "update", "delete", "post", "get",
                                           "put", "patch", "append", "extend",
                                           "pop", "remove", "clear"):
                        return True
            if isinstance(child, python_ast.Global):
                return True
            if isinstance(child, python_ast.Nonlocal):
                return True
        return False

    def _infer_effects(self, node: python_ast.FunctionDef) -> List[str]:
        """Infer AEON effects from Python function body."""
        effects = set()
        for child in python_ast.walk(node):
            if isinstance(child, python_ast.Call):
                if isinstance(child.func, python_ast.Name):
                    if child.func.id in ("print",):
                        effects.add("Console.Write")
                    if child.func.id in ("input",):
                        effects.add("Console.Read")
                    if child.func.id in ("open",):
                        effects.add("File.Read")
                if isinstance(child.func, python_ast.Attribute):
                    attr = child.func.attr
                    if attr in ("write", "writelines"):
                        effects.add("File.Write")
                    elif attr in ("read", "readline", "readlines"):
                        effects.add("File.Read")
                    elif attr in ("execute", "commit", "insert", "update", "delete"):
                        effects.add("Database.Write")
                    elif attr in ("query", "fetchone", "fetchall", "find"):
                        effects.add("Database.Read")
                    elif attr in ("get", "post", "put", "patch"):
                        effects.add("Network.Write")
                    elif attr in ("send", "recv"):
                        effects.add("Network.Write")
        return sorted(effects)


# ---------------------------------------------------------------------------
# Public API (delegates to language_adapter.verify)
# ---------------------------------------------------------------------------

def verify_python(source: str, deep_verify: bool = True,
                  analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify Python code using AEON's analysis engines.

    Args:
        source: Python source code string
        deep_verify: Enable all 10 analysis passes
        analyses: Specific analyses to run (overrides deep_verify)

    Returns:
        VerificationResult with errors, warnings, and summary

    Example:
        result = verify_python('''
            def divide(a: int, b: int) -> int:
                \"\"\"\n                Requires: b != 0
                Ensures: result == a // b
                \"\"\"\n                return a // b
        ''')
        print(result.summary)
    """
    return _verify(source, "python", deep_verify=deep_verify, analyses=analyses)
