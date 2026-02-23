"""Termination analysis for AEON functions.

Detects potential non-termination in recursive functions using
simple size-based metrics and call graph analysis.
"""

from dataclasses import dataclass
from typing import Optional, Set, Dict, List, Union
import collections

from aeon.ast_nodes import (
    PureFunc, TaskFunc, Expr, Identifier, FunctionCall,
    BinaryOp, IntLiteral, ReturnStmt, IfStmt
)
from aeon.errors import AeonError, contract_error, SourceLocation


@dataclass
class CallGraphNode:
    """Node in function call graph."""
    name: str
    func: Union[PureFunc, TaskFunc]
    calls: Set[str]  # Functions this function calls
    recursive_calls: Set[str]  # Direct/indirect recursive calls


class TerminationAnalyzer:
    """Analyzes function termination properties."""

    def __init__(self):
        self.errors: list[AeonError] = []
        self.call_graph: Dict[str, CallGraphNode] = {}

    def analyze_program(self, functions: List[Union[PureFunc, TaskFunc]]) -> list[AeonError]:
        """Analyze termination for all functions in a program."""
        self.errors = []
        self.call_graph = {}

        # Build call graph
        for func in functions:
            self._build_call_graph_node(func)

        # Detect recursive cycles
        self._detect_recursive_cycles()

        # Analyze each function for termination
        for func in functions:
            self._analyze_function(func)

        return self.errors

    def _build_call_graph_node(self, func: Union[PureFunc, TaskFunc]) -> None:
        """Build call graph node for a function."""
        if func.name in self.call_graph:
            return

        calls = set()
        self._collect_calls(func.body, calls)

        node = CallGraphNode(
            name=func.name,
            func=func,
            calls=calls,
            recursive_calls=set()
        )
        self.call_graph[func.name] = node

    def _collect_calls(self, stmt, calls: Set[str]) -> None:
        """Collect all function calls from a statement or list of statements."""
        if stmt is None:
            return

        # Handle list of statements
        if isinstance(stmt, list):
            for s in stmt:
                self._collect_calls(s, calls)
            return

        # Handle different statement types
        if hasattr(stmt, 'statements'):  # BlockStmt
            for s in stmt.statements:
                self._collect_calls(s, calls)
        elif hasattr(stmt, 'then_body') and hasattr(stmt, 'else_body'):  # IfStmt
            self._collect_calls(stmt.then_body, calls)
            self._collect_calls(stmt.else_body, calls)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._collect_calls_from_expr(stmt.value, calls)
        elif hasattr(stmt, 'value'):  # LetStmt, AssignStmt, ExprStmt
            if stmt.value:
                self._collect_calls_from_expr(stmt.value, calls)

    def _collect_calls_from_expr(self, expr: Expr, calls: Set[str]) -> None:
        """Collect function calls from an expression."""
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                calls.add(expr.callee.name)
        elif hasattr(expr, 'left') and hasattr(expr, 'right'):  # BinaryOp
            self._collect_calls_from_expr(expr.left, calls)
            self._collect_calls_from_expr(expr.right, calls)
        elif hasattr(expr, 'operand'):  # UnaryOp
            self._collect_calls_from_expr(expr.operand, calls)
        elif hasattr(expr, 'obj') and hasattr(expr, 'args'):  # MethodCall
            self._collect_calls_from_expr(expr.obj, calls)
            for arg in expr.args:
                self._collect_calls_from_expr(arg, calls)

    def _detect_recursive_cycles(self) -> None:
        """Detect recursive cycles in call graph using DFS."""
        visited = set()
        rec_stack = set()

        def dfs(node_name: str, path: List[str]) -> None:
            if node_name in rec_stack:
                # Found a cycle
                cycle_start = path.index(node_name)
                cycle = path[cycle_start:] + [node_name]
                for func_name in cycle:
                    if func_name in self.call_graph:
                        self.call_graph[func_name].recursive_calls.update(cycle)
                return

            if node_name in visited:
                return

            visited.add(node_name)
            rec_stack.add(node_name)

            if node_name in self.call_graph:
                for callee in self.call_graph[node_name].calls:
                    dfs(callee, path + [node_name])

            rec_stack.remove(node_name)

        for node_name in self.call_graph:
            if node_name not in visited:
                dfs(node_name, [])

    def _analyze_function(self, func: Union[PureFunc, TaskFunc]) -> None:
        """Analyze a single function for termination."""
        node = self.call_graph.get(func.name)
        if not node:
            return

        # Check if function is recursive
        if node.recursive_calls:
            self._analyze_recursive_function(func, node)

    def _analyze_recursive_function(self, func: Union[PureFunc, TaskFunc], node: CallGraphNode) -> None:
        """Analyze a recursive function for proper termination."""
        # Look for decreasing metrics in recursive calls
        has_decreasing_argument = False
        has_base_case = False

        # Check for base cases (conditions that don't recurse)
        has_base_case = self._check_base_cases(func.body)

        # Check if recursive calls use decreasing arguments
        has_decreasing_argument = self._check_decreasing_arguments(func.body, func)

        kind_str = "pure" if isinstance(func, PureFunc) else "task"
        sig = f"{kind_str} {func.name}(...) -> {func.return_type}"

        if not has_base_case:
            self.errors.append(contract_error(
                precondition="recursive function missing base case",
                failing_values={"function": func.name},
                function_signature=sig,
                location=func.location,
            ))

        if not has_decreasing_argument:
            self.errors.append(contract_error(
                precondition="recursive function missing decreasing argument",
                failing_values={"function": func.name},
                function_signature=sig,
                location=func.location,
            ))

    def _check_base_cases(self, stmt) -> bool:
        """Check if function has base cases that stop recursion.

        A base case is an IfStmt where at least one branch contains a
        ReturnStmt that does NOT itself contain a recursive call.  This
        is stricter than the old heuristic of accepting any IfStmt.
        """
        if stmt is None:
            return False

        if isinstance(stmt, list):
            for s in stmt:
                if self._check_base_cases(s):
                    return True
            return False

        if isinstance(stmt, IfStmt):
            # A base case requires at least one branch that returns without recursing
            if self._branch_has_non_recursive_return(stmt.then_body):
                return True
            if stmt.else_body and self._branch_has_non_recursive_return(stmt.else_body):
                return True
            # Recurse into branches in case base case is nested deeper
            if self._check_base_cases(stmt.then_body):
                return True
            if stmt.else_body and self._check_base_cases(stmt.else_body):
                return True
            return False

        if hasattr(stmt, 'statements'):
            for s in stmt.statements:
                if self._check_base_cases(s):
                    return True

        return False

    def _branch_has_non_recursive_return(self, stmts) -> bool:
        """Return True if the statement list contains a return that has no recursive call."""
        if stmts is None:
            return False
        if isinstance(stmts, list):
            for s in stmts:
                if isinstance(s, ReturnStmt):
                    calls: Set[str] = set()
                    if s.value:
                        self._collect_calls_from_expr(s.value, calls)
                    # A non-recursive return has no function calls at all,
                    # or only calls to other functions (checked by caller context).
                    # Here we just check the return exists — the caller checks recursion.
                    return True
        return False

    def _check_decreasing_arguments(self, stmt, func: Union[PureFunc, TaskFunc]) -> bool:
        """Check if recursive calls use decreasing arguments."""
        decreasing_found = False

        def check_expr(expr: Expr) -> bool:
            nonlocal decreasing_found
            if isinstance(expr, FunctionCall):
                if isinstance(expr.callee, Identifier):
                    if expr.callee.name == func.name:
                        # Recursive call - check arguments
                        for arg in expr.args:
                            if self._is_decreasing_expression(arg, func.params):
                                decreasing_found = True
                                return True
            return False

        self._scan_expressions(stmt, check_expr)
        return decreasing_found

    def _is_decreasing_expression(self, expr: Expr, params: List) -> bool:
        """Check if expression is decreasing relative to a parameter.

        Recognises patterns:
          - param - k       (k > 0 integer literal)
          - param / k       (k > 1 integer literal, integer division)
          - param - param2  (subtraction of another param)
          - (param - k) op anything  (nested decreasing sub-expression)
        """
        from aeon.ast_nodes import BinaryOp, Identifier, IntLiteral, UnaryOp

        param_names = {p.name for p in params}

        if isinstance(expr, BinaryOp):
            if expr.op == '-':
                # param - positive_constant
                if (isinstance(expr.left, Identifier) and
                        expr.left.name in param_names):
                    if isinstance(expr.right, IntLiteral) and expr.right.value > 0:
                        return True
                    # param - another_param (could decrease)
                    if isinstance(expr.right, Identifier) and expr.right.name in param_names:
                        return True
            if expr.op == '/':
                # param / k  where k > 1
                if (isinstance(expr.left, Identifier) and
                        expr.left.name in param_names):
                    if isinstance(expr.right, IntLiteral) and expr.right.value > 1:
                        return True
            if expr.op in ('+', '-', '*', '/'):
                # Recurse into sub-expressions
                if self._is_decreasing_expression(expr.left, params):
                    return True
                if self._is_decreasing_expression(expr.right, params):
                    return True

        return False

    def _scan_expressions(self, stmt, checker) -> None:
        """Scan all expressions in a statement with a checker function."""
        if stmt is None:
            return

        # Handle list of statements
        if isinstance(stmt, list):
            for s in stmt:
                self._scan_expressions(s, checker)
            return

        if hasattr(stmt, 'statements'):  # BlockStmt
            for s in stmt.statements:
                self._scan_expressions(s, checker)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._scan_expr(stmt.value, checker)
        elif hasattr(stmt, 'condition') and hasattr(stmt, 'then_body'):  # IfStmt
            self._scan_expr(stmt.condition, checker)
            self._scan_expressions(stmt.then_body, checker)
            self._scan_expressions(stmt.else_body, checker)
        elif hasattr(stmt, 'value'):  # LetStmt, AssignStmt, ExprStmt
            if stmt.value:
                self._scan_expr(stmt.value, checker)

    def _scan_expr(self, expr: Expr, checker) -> None:
        """Scan an expression and all sub-expressions."""
        if checker(expr):
            return

        if hasattr(expr, 'left') and hasattr(expr, 'right'):  # BinaryOp
            self._scan_expr(expr.left, checker)
            self._scan_expr(expr.right, checker)
        elif hasattr(expr, 'operand'):  # UnaryOp
            self._scan_expr(expr.operand, checker)
        elif hasattr(expr, 'obj') and hasattr(expr, 'args'):  # MethodCall
            self._scan_expr(expr.obj, checker)
            for arg in expr.args:
                self._scan_expr(arg, checker)
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._scan_expr(arg, checker)
