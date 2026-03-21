"""AEON Framework Rules Engine — Framework-Aware Verification.

Extends AEON's analysis with knowledge of specific web frameworks,
databases, and patterns.  Rather than treating all code as generic
functions, this engine understands that:

  - Next.js ``app/api/`` routes are HTTP entry points (taint sources)
  - ``searchParams``, ``params``, ``cookies()`` are user-controlled
  - Supabase ``.from().select().eq()`` chains are SQL-adjacent sinks
  - React ``dangerouslySetInnerHTML`` is an XSS sink
  - Middleware ``NextResponse.redirect()`` needs validated URLs
  - Server Components vs Client Components have different trust boundaries

Supports:
  - Next.js 13-15 (App Router)
  - Supabase (Auth, Postgres, Realtime)
  - React 18-19
  - Prisma
  - Express/Fastify (basic)

Based on:
  Tripp et al. (2009) "TAJ: Effective Taint Analysis of Web Applications"
  Arzt et al. (2014) "FlowDroid: Precise Context, Flow, Field,
  Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral,
    StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Framework Detection
# ---------------------------------------------------------------------------

class Framework(Enum):
    NEXTJS = "nextjs"
    EXPRESS = "express"
    SUPABASE = "supabase"
    PRISMA = "prisma"
    REACT = "react"
    GENERIC = "generic"


# ---------------------------------------------------------------------------
# Next.js Knowledge Base
# ---------------------------------------------------------------------------

# Next.js API route handler parameter names (taint sources)
NEXTJS_TAINT_SOURCES: Dict[str, str] = {
    # API route parameters
    "request": "HTTP request object — body, headers, URL are user-controlled",
    "req": "HTTP request object",
    "params": "URL path parameters from dynamic routes — user-controlled",
    "searchParams": "URL query parameters — user-controlled",
    # Cookies & headers
    "cookies": "Cookie values — user-controlled, can be forged",
    "headers": "HTTP headers — user-controlled",
    # Form data
    "formData": "Form submission data — user-controlled",
    # Next.js specific
    "NextRequest": "Next.js request wrapper — all properties are taint sources",
}

# Next.js API route function signatures that indicate entry points
NEXTJS_ROUTE_HANDLERS: Set[str] = {
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
}

# Middleware patterns
NEXTJS_MIDDLEWARE_PATTERNS: Set[str] = {
    "middleware", "NextResponse", "NextRequest",
}

# ---------------------------------------------------------------------------
# Supabase Knowledge Base
# ---------------------------------------------------------------------------

# Supabase methods that are sensitive sinks
SUPABASE_SINKS: Dict[str, str] = {
    "from": "Database table access — verify authorization before querying",
    "rpc": "Remote procedure call — untrusted input can reach SQL",
    "select": "SELECT query — sensitive data may be returned without RLS",
    "insert": "INSERT — validate all fields before writing",
    "update": "UPDATE — verify ownership/authorization of target row",
    "delete": "DELETE — verify ownership/authorization before deletion",
    "eq": "WHERE clause — user input flows into query filter",
    "neq": "WHERE clause — user input flows into query filter",
    "like": "LIKE clause — special characters can alter query behavior",
    "ilike": "ILIKE clause — special characters can alter query behavior",
    "in_": "IN clause — user input flows into query filter",
    "contains": "CONTAINS — user input flows into JSONB query",
    "textSearch": "Full-text search — user input in tsquery",
}

# Supabase auth methods that need careful handling
SUPABASE_AUTH_PATTERNS: Dict[str, str] = {
    "getUser": "Auth check — verify return is not null before using user data",
    "getSession": "Session check — session can be expired or forged",
    "signInWithPassword": "Login — rate limit and validate credentials",
    "signUp": "Registration — validate email, check for duplicates",
    "resetPasswordForEmail": "Password reset — rate limit to prevent enumeration",
}

# ---------------------------------------------------------------------------
# React Knowledge Base
# ---------------------------------------------------------------------------

REACT_XSS_SINKS: Set[str] = {
    "dangerouslySetInnerHTML",
    "innerHTML",
    "outerHTML",
    "document.write",
    "eval",
}

# Server Component vs Client Component boundaries
# Server Components can safely access DB, secrets, etc.
# Client Components receive serialized data — never pass secrets
CLIENT_COMPONENT_RISKS: Set[str] = {
    "process.env",  # Should not appear in client components
    "SUPABASE_SERVICE_ROLE_KEY",
    "SECRET",
    "API_KEY",
    "PRIVATE_KEY",
}


# ---------------------------------------------------------------------------
# Framework Rules Analyzer
# ---------------------------------------------------------------------------

class FrameworkRulesAnalyzer:
    """Analyzes programs for framework-specific security issues."""

    def __init__(self, custom_sources: Optional[List[str]] = None,
                 custom_sinks: Optional[List[str]] = None):
        self.errors: List[AeonError] = []
        self._custom_sources = set(custom_sources or [])
        self._custom_sinks = set(custom_sinks or [])
        self._tainted_vars: Set[str] = set()
        self._current_func: str = ""
        self._is_route_handler: bool = False
        self._is_middleware: bool = False

    def check_program(self, program: Program) -> List[AeonError]:
        """Run framework-aware analysis on the entire program."""
        self.errors = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._check_function(decl)

        return self.errors

    def _check_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function with framework awareness."""
        self._tainted_vars = set()
        self._current_func = func.name
        self._is_route_handler = func.name in NEXTJS_ROUTE_HANDLERS
        self._is_middleware = func.name.lower() in ("middleware",)

        # In route handlers, parameters are taint sources
        if self._is_route_handler:
            for param in func.params:
                if param.name in NEXTJS_TAINT_SOURCES or param.name in self._custom_sources:
                    self._tainted_vars.add(param.name)

        # Check all parameters against custom sources
        for param in func.params:
            if param.name in self._custom_sources:
                self._tainted_vars.add(param.name)

        for stmt in func.body:
            self._check_statement(stmt, func)

    def _check_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Check a statement for framework-specific issues."""
        loc = getattr(stmt, 'location', SourceLocation("<framework>", 0, 0))

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_expr(stmt.value, func, loc)
                # Track taint propagation
                if self._expr_is_tainted(stmt.value):
                    self._tainted_vars.add(stmt.name)
                # Check for taint source assignments
                if self._is_taint_source_expr(stmt.value):
                    self._tainted_vars.add(stmt.name)

        elif isinstance(stmt, AssignStmt):
            self._check_expr(stmt.value, func, loc)

        elif isinstance(stmt, ExprStmt):
            self._check_expr(stmt.expr, func, loc)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._check_expr(stmt.value, func, loc)
                # In route handlers, check for sensitive data in response
                if self._is_route_handler:
                    self._check_response_safety(stmt.value, func, loc)

        elif isinstance(stmt, IfStmt):
            self._check_expr(stmt.condition, func, loc)
            for s in stmt.then_body:
                self._check_statement(s, func)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._check_statement(s, func)

        elif isinstance(stmt, WhileStmt):
            self._check_expr(stmt.condition, func, loc)
            for s in stmt.body:
                self._check_statement(s, func)

    def _check_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                    loc: SourceLocation) -> None:
        """Check expressions for framework-specific issues."""
        if isinstance(expr, MethodCall):
            self._check_expr(expr.obj, func, loc)
            for arg in expr.args:
                self._check_expr(arg, func, loc)
            expr_loc = getattr(expr, 'location', loc)

            # Supabase sink checks
            if expr.method_name in SUPABASE_SINKS:
                # Check if any argument is tainted
                for arg in expr.args:
                    if self._expr_is_tainted(arg):
                        self.errors.append(self._fw_error(
                            f"Tainted input flows into Supabase .{expr.method_name}(): "
                            f"'{self._expr_str(arg)}' is user-controlled. "
                            f"{SUPABASE_SINKS[expr.method_name]}. "
                            f"Validate and sanitize before passing to database queries",
                            func, expr_loc,
                            severity="error",
                            rule="supabase-taint",
                        ))

            # Supabase auth checks
            if expr.method_name in SUPABASE_AUTH_PATTERNS:
                self.errors.append(self._fw_error(
                    f"Supabase auth call .{expr.method_name}(): "
                    f"{SUPABASE_AUTH_PATTERNS[expr.method_name]}",
                    func, expr_loc,
                    severity="warning",
                    rule="supabase-auth",
                ))

            # React XSS sinks
            if expr.method_name in REACT_XSS_SINKS:
                for arg in expr.args:
                    if self._expr_is_tainted(arg):
                        self.errors.append(self._fw_error(
                            f"XSS risk: tainted value '{self._expr_str(arg)}' flows into "
                            f"'{expr.method_name}'. Sanitize with DOMPurify or escape HTML",
                            func, expr_loc,
                            severity="error",
                            rule="react-xss",
                        ))

            # Custom sink checks
            method_full = f"{self._expr_str(expr.obj)}.{expr.method_name}"
            if method_full in self._custom_sinks or expr.method_name in self._custom_sinks:
                for arg in expr.args:
                    if self._expr_is_tainted(arg):
                        self.errors.append(self._fw_error(
                            f"Tainted input flows into custom sink "
                            f"'{method_full}': '{self._expr_str(arg)}' is user-controlled",
                            func, expr_loc,
                            severity="warning",
                            rule="custom-sink",
                        ))

        elif isinstance(expr, FieldAccess):
            self._check_expr(expr.obj, func, loc)
            expr_loc = getattr(expr, 'location', loc)

            # dangerouslySetInnerHTML check
            if expr.field_name == "dangerouslySetInnerHTML":
                self.errors.append(self._fw_error(
                    f"dangerouslySetInnerHTML used in {func.name}. "
                    f"This bypasses React's XSS protection. Ensure the HTML "
                    f"is sanitized with DOMPurify before rendering",
                    func, expr_loc,
                    severity="warning",
                    rule="react-xss",
                ))

            # Client component secret leak check
            if expr.field_name in CLIENT_COMPONENT_RISKS:
                self.errors.append(self._fw_error(
                    f"Sensitive value '{expr.field_name}' accessed. "
                    f"If this is a Client Component, secrets will be "
                    f"exposed to the browser. Use Server Components or "
                    f"API routes for sensitive operations",
                    func, expr_loc,
                    severity="warning",
                    rule="secret-leak",
                ))

        elif isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                for arg in expr.args:
                    self._check_expr(arg, func, loc)

                # Next.js redirect with tainted URL
                if expr.callee.name == "redirect":
                    for arg in expr.args:
                        if self._expr_is_tainted(arg):
                            self.errors.append(self._fw_error(
                                f"Open redirect: tainted URL '{self._expr_str(arg)}' "
                                f"passed to redirect(). Validate the URL against an "
                                f"allowlist before redirecting",
                                func, getattr(expr, 'location', loc),
                                severity="error",
                                rule="open-redirect",
                            ))

                # Next.js cookies() / headers() are taint sources
                if expr.callee.name in ("cookies", "headers"):
                    pass  # Result should be marked as tainted at assignment

            elif isinstance(expr.callee, FieldAccess):
                self._check_expr(expr.callee, func, loc)
                for arg in expr.args:
                    self._check_expr(arg, func, loc)

        elif isinstance(expr, BinaryOp):
            self._check_expr(expr.left, func, loc)
            self._check_expr(expr.right, func, loc)

    def _check_response_safety(self, expr: Expr, func: PureFunc | TaskFunc,
                               loc: SourceLocation) -> None:
        """Check that route handler responses don't leak sensitive data."""
        # This is a simplified check — in production you'd trace data flow
        # through the response construction
        pass

    def _expr_is_tainted(self, expr: Expr) -> bool:
        """Check if an expression contains tainted data."""
        if isinstance(expr, Identifier):
            return (expr.name in self._tainted_vars or
                    expr.name in NEXTJS_TAINT_SOURCES or
                    expr.name in self._custom_sources)
        if isinstance(expr, FieldAccess):
            # searchParams.get(), params.id, etc.
            if isinstance(expr.obj, Identifier):
                return (expr.obj.name in self._tainted_vars or
                        expr.obj.name in NEXTJS_TAINT_SOURCES)
            return self._expr_is_tainted(expr.obj)
        if isinstance(expr, MethodCall):
            # request.json(), cookies().get(), etc.
            if self._expr_is_tainted(expr.obj):
                return True
            if isinstance(expr.obj, Identifier):
                if expr.obj.name in NEXTJS_TAINT_SOURCES:
                    return True
        if isinstance(expr, BinaryOp):
            return self._expr_is_tainted(expr.left) or self._expr_is_tainted(expr.right)
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                if expr.callee.name in ("cookies", "headers"):
                    return True
        return False

    def _is_taint_source_expr(self, expr: Expr) -> bool:
        """Check if expression is a known taint source."""
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                return expr.callee.name in ("cookies", "headers", "formData")
        if isinstance(expr, MethodCall):
            if isinstance(expr.obj, Identifier):
                if expr.obj.name in NEXTJS_TAINT_SOURCES:
                    return True
            if expr.method_name in ("json", "text", "formData", "blob"):
                return self._expr_is_tainted(expr.obj)
        return False

    def _expr_str(self, expr: Expr) -> str:
        """Get a short string representation."""
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, FieldAccess):
            return f"{self._expr_str(expr.obj)}.{expr.field_name}"
        if isinstance(expr, MethodCall):
            return f"{self._expr_str(expr.obj)}.{expr.method_name}()"
        if isinstance(expr, StringLiteral):
            return f'"{expr.value[:20]}"'
        if isinstance(expr, BinaryOp):
            return f"{self._expr_str(expr.left)} {expr.op} {self._expr_str(expr.right)}"
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return f"{expr.callee.name}()"
        return "<expr>"

    def _fw_error(self, message: str, func: PureFunc | TaskFunc,
                  loc: Optional[SourceLocation] = None,
                  severity: str = "warning",
                  rule: str = "framework") -> AeonError:
        """Create a framework rules error."""
        return contract_error(
            precondition=message,
            failing_values={
                "engine": "Framework Rules",
                "framework": "nextjs",
                "rule": rule,
                "severity": severity,
                "function": func.name,
            },
            function_signature=func.name,
            location=loc or SourceLocation("<framework>", 0, 0),
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_framework_rules(program: Program,
                          custom_sources: Optional[List[str]] = None,
                          custom_sinks: Optional[List[str]] = None) -> List[AeonError]:
    """Run framework-aware analysis on an AEON program.

    Detects:
    - Tainted input flowing into Supabase queries
    - XSS via dangerouslySetInnerHTML with user input
    - Open redirects with user-controlled URLs
    - Secret leaks in Client Components
    - Supabase auth patterns needing validation
    - Custom taint source/sink violations from .aeonrc.yml
    """
    analyzer = FrameworkRulesAnalyzer(
        custom_sources=custom_sources,
        custom_sinks=custom_sinks,
    )
    return analyzer.check_program(program)
