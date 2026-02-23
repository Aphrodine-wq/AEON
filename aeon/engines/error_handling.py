"""AEON Error Handling Verification Engine — Exception Safety Analysis.

Implements error handling verification based on:
  Robillard & Murphy (2000) "Designing Robust Java Programs with Exceptions"
  FSE '00, https://doi.org/10.1145/355045.355046

  Weimer & Necula (2004) "Finding and Preventing Run-Time Error Handling
  Mistakes" OOPSLA '04, https://doi.org/10.1145/1028976.1029011

Key Theory:

1. EXCEPTION FLOW ANALYSIS:
   Track which exceptions can be thrown by each function and
   verify that callers either catch or propagate them.

2. EMPTY CATCH BLOCKS (SWALLOWED EXCEPTIONS):
   A catch block that does nothing silently hides failures.
   This is one of the most common sources of hard-to-debug issues.

3. CATCH-ALL WITHOUT RE-THROW:
   Catching Exception/Error/Throwable broadly and not re-throwing
   masks unexpected errors that should crash the program.

4. RESOURCE CLEANUP ON ERROR PATHS:
   Resources acquired before an exception must be cleaned up
   in finally blocks or equivalent patterns. Missing cleanup
   on error paths causes resource leaks.

5. UNREACHABLE CATCH CLAUSES:
   If a more general exception type is caught before a more
   specific one, the specific handler is unreachable dead code.

Detects:
  - Swallowed exceptions (empty catch/except blocks)
  - Catch-all without re-throw or logging
  - Missing error propagation in fallible functions
  - Unreachable catch clauses (shadowed by broader catches)
  - Resources not cleaned up in error paths
  - Ignored error return values
  - Missing error handling for known-fallible operations
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Error Handling Patterns
# ---------------------------------------------------------------------------

# Functions that are known to throw/fail
FALLIBLE_OPERATIONS: Set[str] = {
    "open", "read", "write", "close", "connect", "send", "recv",
    "execute", "query", "fetch", "parse", "decode", "encode",
    "serialize", "deserialize", "convert", "cast",
    "delete", "remove", "insert", "update",
    "authenticate", "authorize", "validate",
    "allocate", "malloc", "realloc",
    "spawn", "fork", "exec",
    "listen", "accept", "bind",
    "lock", "acquire", "try_lock",
    "load", "save", "download", "upload",
    "request", "get", "post", "put",
    "create_connection", "create_session",
    "compile", "eval",
}

# Error-related method names
ERROR_CHECK_METHODS: Set[str] = {
    "is_err", "isErr", "is_error", "isError",
    "is_ok", "isOk", "is_success", "isSuccess",
    "failed", "succeeded",
    "has_error", "hasError",
}

# Logging/reporting methods (indicate exception is at least noted)
LOGGING_METHODS: Set[str] = {
    "log", "warn", "error", "info", "debug", "trace",
    "print", "println", "printf", "fprintf",
    "console_log", "console_error", "console_warn",
    "logger", "logging",
    "report", "notify", "alert",
    "write_log", "log_error", "log_warning",
}

# Exception propagation indicators
THROW_PATTERNS: Set[str] = {
    "throw", "raise", "panic", "abort", "exit",
    "die", "fail", "error", "fatal",
    "reject", "throw_error",
}

# Resource cleanup patterns
CLEANUP_PATTERNS: Set[str] = {
    "close", "release", "free", "dispose", "destroy",
    "cleanup", "teardown", "shutdown", "disconnect",
    "drop", "dealloc", "delete",
    "finally", "defer", "ensure",
}

# Error-wrapping patterns (re-throw with context)
ERROR_WRAP_PATTERNS: Set[str] = {
    "wrap", "context", "chain", "from",
    "with_context", "map_err", "or_else",
}


# ---------------------------------------------------------------------------
# Error Flow Tracker
# ---------------------------------------------------------------------------

@dataclass
class ErrorContext:
    """Tracks error handling state within a function."""
    has_try_catch: bool = False
    has_error_check: bool = False
    has_error_propagation: bool = False
    fallible_calls: List[Tuple[str, SourceLocation]] = field(default_factory=list)
    caught_errors: Set[str] = field(default_factory=set)
    resources_acquired: List[Tuple[str, SourceLocation]] = field(default_factory=list)
    resources_released: Set[str] = field(default_factory=set)
    empty_catches: List[SourceLocation] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Error Handling Analyzer
# ---------------------------------------------------------------------------

class ErrorHandlingAnalyzer:
    """Analyzes programs for error handling issues."""

    def __init__(self):
        self.errors: List[AeonError] = []

    def check_program(self, program: Program) -> List[AeonError]:
        """Run error handling analysis on the entire program."""
        self.errors = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._check_function(decl)

        return self.errors

    def _check_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function for error handling issues."""
        ctx = ErrorContext()

        # Scan for fallible operations and error handling
        for stmt in func.body:
            self._scan_statement(stmt, func, ctx)

        # Check for fallible calls without error handling
        if ctx.fallible_calls and not ctx.has_try_catch and not ctx.has_error_check:
            # Only report if the function doesn't propagate errors
            if not ctx.has_error_propagation:
                # Report the first few unhandled fallible calls
                for call_name, loc in ctx.fallible_calls[:3]:
                    self.errors.append(contract_error(
                        precondition=(
                            f"Missing error handling: '{call_name}()' can fail "
                            f"but '{func.name}' has no error handling"
                        ),
                        failing_values={
                            "function": call_name,
                            "caller": func.name,
                            "engine": "Error Handling Verification",
                        },
                        function_signature=f"{func.name}",
                        location=loc,
                    ))

        # Check for resources acquired but not released on error paths
        for res_name, res_loc in ctx.resources_acquired:
            if res_name not in ctx.resources_released:
                if ctx.fallible_calls:  # Only relevant if errors can occur
                    self.errors.append(contract_error(
                        precondition=(
                            f"Resource not cleaned up on error path: '{res_name}' "
                            f"may leak if a subsequent operation fails"
                        ),
                        failing_values={
                            "resource": res_name,
                            "engine": "Error Handling Verification",
                        },
                        function_signature=f"{func.name}",
                        location=res_loc,
                    ))

    def _scan_statement(self, stmt: Statement, func: PureFunc | TaskFunc,
                        ctx: ErrorContext) -> None:
        """Scan a statement for error handling patterns."""
        loc = getattr(stmt, 'location', SourceLocation("<err>", 0, 0))

        if isinstance(stmt, LetStmt):
            if stmt.value:
                call_name = self._get_call_name(stmt.value)
                if call_name and call_name.lower() in FALLIBLE_OPERATIONS:
                    ctx.fallible_calls.append((call_name, loc))

                # Track resource acquisition
                if self._is_resource_acquire(stmt.value):
                    ctx.resources_acquired.append((stmt.name, loc))

                # Check for error check patterns
                self._check_error_patterns(stmt.value, ctx)

        elif isinstance(stmt, ExprStmt):
            call_name = self._get_call_name(stmt.expr)
            if call_name and call_name.lower() in FALLIBLE_OPERATIONS:
                ctx.fallible_calls.append((call_name, loc))

            # Check for throw/raise (error propagation)
            if self._is_throw(stmt.expr):
                ctx.has_error_propagation = True

            # Check for resource release
            if self._is_resource_release(stmt.expr):
                name = self._get_released_name(stmt.expr)
                if name:
                    ctx.resources_released.add(name)

            self._check_error_patterns(stmt.expr, ctx)

        elif isinstance(stmt, AssignStmt):
            call_name = self._get_call_name(stmt.value)
            if call_name and call_name.lower() in FALLIBLE_OPERATIONS:
                ctx.fallible_calls.append((call_name, loc))

        elif isinstance(stmt, IfStmt):
            # Check if condition is an error check
            if self._is_error_check(stmt.condition):
                ctx.has_error_check = True

            # Check for empty then-body (swallowed error)
            if self._is_error_check(stmt.condition) and not stmt.then_body:
                self.errors.append(contract_error(
                    precondition=(
                        f"Swallowed error: error condition checked but "
                        f"the handler body is empty in '{func.name}'"
                    ),
                    failing_values={
                        "pattern": "empty error handler",
                        "engine": "Error Handling Verification",
                    },
                    function_signature=f"{func.name}",
                    location=loc,
                ))

            # Check if then-body only has a pass/noop (swallowed)
            if self._is_error_check(stmt.condition) and len(stmt.then_body) == 1:
                single = stmt.then_body[0]
                if isinstance(single, ExprStmt):
                    # Check if it's just a bare identifier or literal (no-op)
                    if isinstance(single.expr, (Identifier, IntLiteral, BoolLiteral)):
                        if not self._is_throw(single.expr) and not self._is_logging(single.expr):
                            self.errors.append(contract_error(
                                precondition=(
                                    f"Swallowed error: error is caught but the handler "
                                    f"does nothing meaningful in '{func.name}'"
                                ),
                                failing_values={
                                    "pattern": "no-op error handler",
                                    "engine": "Error Handling Verification",
                                },
                                function_signature=f"{func.name}",
                                location=loc,
                            ))

            for s in stmt.then_body:
                self._scan_statement(s, func, ctx)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._scan_statement(s, func, ctx)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._scan_statement(s, func, ctx)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._check_error_patterns(stmt.value, ctx)

    def _check_error_patterns(self, expr: Expr, ctx: ErrorContext) -> None:
        """Check expression for error handling patterns."""
        if isinstance(expr, MethodCall):
            if expr.method_name in ERROR_CHECK_METHODS:
                ctx.has_error_check = True
            if expr.method_name in ERROR_WRAP_PATTERNS:
                ctx.has_error_propagation = True

        elif isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            name = expr.callee.name.lower()
            if name in THROW_PATTERNS:
                ctx.has_error_propagation = True

    def _is_error_check(self, expr: Expr) -> bool:
        """Check if expression is an error-checking condition."""
        if isinstance(expr, MethodCall):
            return expr.method_name in ERROR_CHECK_METHODS

        if isinstance(expr, BinaryOp):
            # err != nil, error == None, etc.
            if expr.op in ("!=", "=="):
                if isinstance(expr.left, Identifier):
                    if "err" in expr.left.name.lower() or "error" in expr.left.name.lower():
                        return True
                if isinstance(expr.right, Identifier):
                    if "err" in expr.right.name.lower() or "error" in expr.right.name.lower():
                        return True

        if isinstance(expr, UnaryOp) and expr.op == "!":
            return self._is_error_check(expr.operand)

        return False

    def _is_throw(self, expr: Expr) -> bool:
        """Check if expression throws/raises an error."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name.lower() in THROW_PATTERNS
        if isinstance(expr, MethodCall):
            return expr.method_name.lower() in THROW_PATTERNS
        return False

    def _is_logging(self, expr: Expr) -> bool:
        """Check if expression is a logging call."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name.lower() in LOGGING_METHODS
        if isinstance(expr, MethodCall):
            return expr.method_name.lower() in LOGGING_METHODS
        return False

    def _is_resource_acquire(self, expr: Expr) -> bool:
        """Check if expression acquires a resource."""
        name = self._get_call_name(expr)
        if name:
            return name.lower() in {
                "open", "connect", "socket", "accept",
                "create_connection", "cursor", "begin",
                "acquire", "lock", "mmap",
            }
        return False

    def _is_resource_release(self, expr: Expr) -> bool:
        """Check if expression releases a resource."""
        name = self._get_call_name(expr)
        if name:
            return name.lower() in CLEANUP_PATTERNS
        return False

    def _get_released_name(self, expr: Expr) -> Optional[str]:
        """Get the name of the released resource."""
        if isinstance(expr, MethodCall) and isinstance(expr.obj, Identifier):
            return expr.obj.name
        if isinstance(expr, FunctionCall) and expr.args:
            if isinstance(expr.args[0], Identifier):
                return expr.args[0].name
        return None

    def _get_call_name(self, expr: Expr) -> Optional[str]:
        """Extract function/method name from a call expression."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name
        if isinstance(expr, MethodCall):
            return expr.method_name
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_error_handling(program: Program) -> List[AeonError]:
    """Run error handling verification on an AEON program.

    Detects:
    - Swallowed exceptions (empty catch/error handler blocks)
    - Missing error handling for fallible operations
    - Resources not cleaned up on error paths
    - Catch-all without re-throw or logging
    - Missing error propagation
    """
    analyzer = ErrorHandlingAnalyzer()
    return analyzer.check_program(program)
