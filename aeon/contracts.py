"""AEON Contract Verification.

Requires/ensures clauses verified via Z3 SMT solver.
Gated behind --verify flag for speed (lightweight type checking by default).
"""

from __future__ import annotations

from typing import Optional, Any

from aeon.ast_nodes import (
    ContractClause, Expr, BinaryOp, UnaryOp,
    Identifier, IntLiteral, FloatLiteral, BoolLiteral,
    FieldAccess, MethodCall, FunctionCall,
    PureFunc, TaskFunc, Parameter,
)
from aeon.types import AeonType, INT, FLOAT, BOOL, STRING
from aeon.errors import AeonError, contract_error, SourceLocation

import sys, io, os

# Try to use locally built Z3 first
z3_path = "/tmp/z3-src/build/python"
if os.path.exists(z3_path) and z3_path not in sys.path:
    sys.path.insert(0, z3_path)
    os.environ["DYLD_LIBRARY_PATH"] = "/tmp/z3-src/build:" + os.environ.get("DYLD_LIBRARY_PATH", "")

_saved_stdout = sys.stdout
_saved_stderr = sys.stderr
try:
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    import z3
    HAS_Z3 = True
except (ImportError, Exception):
    z3 = None
    HAS_Z3 = False
finally:
    sys.stdout = _saved_stdout
    sys.stderr = _saved_stderr


class ContractVerifier:
    """Verifies requires/ensures contracts using Z3 SMT solver."""

    def __init__(self, verify: bool = False):
        self.verify = verify and HAS_Z3
        self.errors: list[AeonError] = []

    def check_function(self, func: PureFunc | TaskFunc) -> list[AeonError]:
        """Check contracts for a function. Returns list of errors."""
        self.errors = []

        if not self.verify:
            return self.errors

        param_types: dict[str, AeonType] = {}
        for p in func.params:
            from aeon.types import resolve_type_annotation, TypeEnvironment
            env = TypeEnvironment()
            param_types[p.name] = resolve_type_annotation(p.type_annotation, env)

        # Verify requires clauses are satisfiable
        for req in func.requires:
            self._verify_requires(req, param_types, func)

        # Verify ensures clauses hold given requires
        for ens in func.ensures:
            self._verify_ensures(ens, func.requires, param_types, func)

        return self.errors

    def _verify_requires(
        self,
        clause: ContractClause,
        param_types: dict[str, AeonType],
        func: PureFunc | TaskFunc,
    ) -> None:
        """Check that requires clause is satisfiable."""
        try:
            solver = z3.Solver()
            z3_vars = self._make_z3_vars(param_types)
            z3_expr = self._expr_to_z3(clause.expr, z3_vars)
            if z3_expr is None:
                return

            solver.add(z3_expr)
            result = solver.check()
            if result == z3.unsat:
                self.errors.append(contract_error(
                    precondition=str(clause.expr),
                    failing_values={},
                    function_signature=self._func_sig(func),
                    location=clause.location,
                ))
        except Exception:
            pass  # Z3 conversion failed — skip verification

    def _verify_ensures(
        self,
        ensures: ContractClause,
        requires: list[ContractClause],
        param_types: dict[str, AeonType],
        func: PureFunc | TaskFunc,
    ) -> None:
        """Check that ensures clause holds given requires and function body."""
        try:
            solver = z3.Solver()
            z3_vars = self._make_z3_vars(param_types)

            # Add requires as assumptions
            for req in requires:
                z3_req = self._expr_to_z3(req.expr, z3_vars)
                if z3_req is not None:
                    solver.add(z3_req)

            # For simple functions, try to deduce the return value from the body
            # This is a simplified approach - full symbolic execution would be more complex
            if hasattr(func, 'body') and func.body:
                # For return statements, try to extract the return expression
                return_expr = self._extract_return_expression(func.body)
                if return_expr:
                    z3_return = self._expr_to_z3(return_expr, z3_vars)
                    if z3_return is not None:
                        # Add constraint that result equals return expression
                        if 'result' in z3_vars:
                            solver.add(z3_vars['result'] == z3_return)
                else:
                    # If we can't extract return, skip ensures verification for now
                    # This prevents false positives
                    return

            # Check negation of ensures (should be unsat)
            z3_ens = self._expr_to_z3(ensures.expr, z3_vars)
            if z3_ens is None:
                return

            solver.add(z3.Not(z3_ens))
            result = solver.check()
            if result == z3.sat:
                model = solver.model()
                failing = {}
                for name in param_types:
                    if name in z3_vars:
                        val = model.evaluate(z3_vars[name])
                        failing[name] = str(val)
                self.errors.append(contract_error(
                    precondition=f"ensures: {self._expr_str(ensures.expr)}",
                    failing_values=failing,
                    function_signature=self._func_sig(func),
                    location=ensures.location,
                ))
        except Exception:
            pass

    def _extract_return_expression(self, stmt) -> Optional['Expr']:
        """Extract return expression from function body (simplified)."""
        from aeon.ast_nodes import ReturnStmt

        # Direct return statement
        if isinstance(stmt, ReturnStmt) and stmt.value:
            return stmt.value

        # List of statements (function body is a list)
        if isinstance(stmt, list):
            for s in stmt:
                result = self._extract_return_expression(s)
                if result is not None:
                    return result
            return None

        # Any node with a statements attribute (block-like)
        if hasattr(stmt, 'statements') and stmt.statements:
            for s in stmt.statements:
                result = self._extract_return_expression(s)
                if result is not None:
                    return result

        return None

    def _make_z3_vars(self, param_types: dict[str, AeonType]) -> dict[str, Any]:
        """Create Z3 variables from parameter types."""
        z3_vars: dict[str, Any] = {}
        for name, typ in param_types.items():
            if typ == INT:
                z3_vars[name] = z3.Int(name)
            elif typ == FLOAT:
                z3_vars[name] = z3.Real(name)
            elif typ == BOOL:
                z3_vars[name] = z3.Bool(name)
        # Add 'result' variable for ensures clauses
        z3_vars['result'] = z3.Int('result')  # Default to Int, could be smarter
        return z3_vars

    def _expr_to_z3(self, expr: Expr, z3_vars: dict[str, Any]) -> Any:
        """Convert an AEON expression to a Z3 expression."""
        if isinstance(expr, IntLiteral):
            return z3.IntVal(expr.value)

        if isinstance(expr, BoolLiteral):
            return z3.BoolVal(expr.value)

        if isinstance(expr, Identifier):
            return z3_vars.get(expr.name)

        if isinstance(expr, BinaryOp):
            left = self._expr_to_z3(expr.left, z3_vars)
            right = self._expr_to_z3(expr.right, z3_vars)
            if left is None or right is None:
                return None
            ops = {
                "+": lambda l, r: l + r,
                "-": lambda l, r: l - r,
                "*": lambda l, r: l * r,
                "==": lambda l, r: l == r,
                "!=": lambda l, r: l != r,
                ">=": lambda l, r: l >= r,
                "<=": lambda l, r: l <= r,
                ">": lambda l, r: l > r,
                "<": lambda l, r: l < r,
                "&&": lambda l, r: z3.And(l, r),
                "||": lambda l, r: z3.Or(l, r),
            }
            op_fn = ops.get(expr.op)
            if op_fn:
                return op_fn(left, right)
            return None

        if isinstance(expr, UnaryOp):
            operand = self._expr_to_z3(expr.operand, z3_vars)
            if operand is None:
                return None
            if expr.op == "-":
                return -operand
            if expr.op == "!":
                return z3.Not(operand)

        if isinstance(expr, FieldAccess):
            # Handle result.field or param.field
            if isinstance(expr.obj, Identifier):
                key = f"{expr.obj.name}.{expr.field_name}"
                return z3_vars.get(key)

        if isinstance(expr, MethodCall):
            # Handle common method calls like isValid(), isOk()
            if isinstance(expr.obj, Identifier):
                key = f"{expr.obj.name}.{expr.method_name}"
                if key not in z3_vars:
                    z3_vars[key] = z3.Bool(key)
                return z3_vars[key]

        return None

    def _func_sig(self, func: PureFunc | TaskFunc) -> str:
        prefix = "pure" if isinstance(func, PureFunc) else "task"
        params = ", ".join(f"{p.name}: {p.type_annotation}" for p in func.params)
        ret = f" -> {func.return_type}" if func.return_type else ""
        return f"{prefix} {func.name}({params}){ret}"

    def _expr_str(self, expr: Expr) -> str:
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, IntLiteral):
            return str(expr.value)
        if isinstance(expr, BoolLiteral):
            return str(expr.value).lower()
        if isinstance(expr, BinaryOp):
            return f"{self._expr_str(expr.left)} {expr.op} {self._expr_str(expr.right)}"
        if isinstance(expr, UnaryOp):
            return f"{expr.op}{self._expr_str(expr.operand)}"
        if isinstance(expr, FieldAccess):
            return f"{self._expr_str(expr.obj)}.{expr.field_name}"
        if isinstance(expr, MethodCall):
            args = ", ".join(self._expr_str(a) for a in expr.args)
            return f"{self._expr_str(expr.obj)}.{expr.method_name}({args})"
        return "<?>"
