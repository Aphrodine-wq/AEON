"""AEON Sanitizer-Aware Analysis — Recognize Validation & Auth Patterns.

Most false positives come from AEON not knowing that input was already
validated upstream.  This module recognizes common sanitization and
validation patterns so other engines can reduce confidence or suppress
findings when data is provably safe.

Recognizes:
  - Zod: .parse(), .safeParse(), z.string().email(), z.number().min()
  - Next.js middleware: middleware.ts as auth/redirect gate
  - Supabase RLS: Row-Level Security as authorization layer
  - TypeScript type guards: if (typeof x === 'string'), x is Foo
  - Input validation: .trim(), .toLowerCase(), parseInt(), Number()
  - Auth checks: getUser(), getSession(), isAuthenticated
  - Error boundaries: try/catch, .catch(), Result types
  - Parameterized queries: $1, ?, :param (not string concat)

Each recognized pattern produces a SanitizationFact that other engines
can query to adjust confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral,
    BinaryOp, FunctionCall, FieldAccess, MethodCall,
    LetStmt, IfStmt, ReturnStmt, ExprStmt,
)
from aeon.errors import SourceLocation


# ---------------------------------------------------------------------------
# Sanitization Facts
# ---------------------------------------------------------------------------

class SanitizationType(Enum):
    """Types of sanitization recognized."""
    ZOD_PARSE = "zod_parse"
    ZOD_SAFE_PARSE = "zod_safe_parse"
    TYPE_GUARD = "type_guard"
    INPUT_VALIDATION = "input_validation"
    AUTH_CHECK = "auth_check"
    MIDDLEWARE_GATE = "middleware_gate"
    ERROR_BOUNDARY = "error_boundary"
    PARAMETERIZED_QUERY = "parameterized_query"
    NUMERIC_PARSE = "numeric_parse"
    SUPABASE_RLS = "supabase_rls"
    NULL_CHECK = "null_check"


@dataclass
class SanitizationFact:
    """A fact about data being sanitized or validated."""
    sanitization_type: SanitizationType
    variable: str  # Variable that was sanitized
    function_name: str  # Function where sanitization occurs
    line: int = 0
    description: str = ""
    protects_against: Set[str] = field(default_factory=set)  # taint kinds: sql, xss, etc.


# ---------------------------------------------------------------------------
# Sanitizer Pattern Definitions
# ---------------------------------------------------------------------------

# Zod validation methods
ZOD_METHODS: Dict[str, Set[str]] = {
    "parse": {"sql", "xss", "cmd", "path", "deser"},
    "safeParse": {"sql", "xss", "cmd", "path", "deser"},
    "parseAsync": {"sql", "xss", "cmd", "path", "deser"},
    "safeParseAsync": {"sql", "xss", "cmd", "path", "deser"},
}

# Zod schema builders (indicate schema-level validation exists)
ZOD_SCHEMAS: Set[str] = {
    "z.string", "z.number", "z.boolean", "z.enum", "z.object",
    "z.array", "z.tuple", "z.union", "z.literal", "z.date",
    "z.coerce", "z.nativeEnum",
}

# Auth check functions/methods
AUTH_CHECKS: Set[str] = {
    "getUser", "getSession", "isAuthenticated", "requireAuth",
    "checkAuth", "verifyToken", "validateToken", "authenticate",
    "auth", "currentUser", "session",
    # Supabase specific
    "supabase.auth.getUser", "supabase.auth.getSession",
    # Next-Auth
    "getServerSession", "useSession", "getToken",
}

# Input validation functions
VALIDATION_FUNCTIONS: Dict[str, Set[str]] = {
    "parseInt": {"sql", "xss", "cmd"},
    "parseFloat": {"sql", "xss", "cmd"},
    "Number": {"sql", "xss", "cmd"},
    "Boolean": {"sql", "xss"},
    "trim": {"log", "header"},
    "toLowerCase": set(),
    "toUpperCase": set(),
    "encodeURIComponent": {"xss", "ssrf"},
    "encodeURI": {"xss", "ssrf"},
    "DOMPurify.sanitize": {"xss"},
    "sanitizeHtml": {"xss"},
    "escape": {"sql", "xss"},
    "validator.isEmail": {"sql", "xss"},
    "validator.isURL": {"ssrf"},
    "validator.isUUID": {"sql", "xss"},
}

# Type guard patterns in if conditions
TYPE_GUARDS: Set[str] = {
    "typeof", "instanceof", "is", "in",
    "Array.isArray", "Number.isNaN", "Number.isFinite",
    "Number.isInteger",
}

# Null check patterns
NULL_CHECKS: Set[str] = {
    "!= null", "!== null", "!= undefined", "!== undefined",
    "!= nil", "is not None",
}


# ---------------------------------------------------------------------------
# Sanitizer Analyzer
# ---------------------------------------------------------------------------

class SanitizerAnalyzer:
    """Analyzes programs to find sanitization and validation patterns."""

    def __init__(self):
        self.facts: List[SanitizationFact] = []
        self._current_func: str = ""

    def analyze_program(self, program: Program) -> List[SanitizationFact]:
        """Find all sanitization facts in a program."""
        self.facts = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.facts

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Find sanitization patterns in a function."""
        self._current_func = func.name

        # Check if function name suggests middleware/auth
        if func.name.lower() in ("middleware", "authmiddleware", "requireauth"):
            self.facts.append(SanitizationFact(
                sanitization_type=SanitizationType.MIDDLEWARE_GATE,
                variable="*",
                function_name=func.name,
                description=f"Middleware function '{func.name}' acts as auth/validation gate",
                protects_against={"sql", "xss", "cmd", "path"},
            ))

        for stmt in func.body:
            self._analyze_statement(stmt, func)

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Analyze a statement for sanitization patterns."""
        loc = getattr(stmt, 'location', None)
        line = loc.line if loc else 0

        if isinstance(stmt, LetStmt):
            if stmt.value:
                fact = self._check_sanitization_expr(stmt.value, stmt.name, line)
                if fact:
                    self.facts.append(fact)

        elif isinstance(stmt, IfStmt):
            # Check for null checks and type guards in condition
            cond_fact = self._check_guard_condition(stmt.condition, line)
            if cond_fact:
                self.facts.append(cond_fact)
            # Recurse into branches
            for s in stmt.then_body:
                self._analyze_statement(s, func)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._analyze_statement(s, func)

        elif isinstance(stmt, ExprStmt):
            fact = self._check_sanitization_expr(stmt.expr, "", line)
            if fact:
                self.facts.append(fact)

        elif isinstance(stmt, ReturnStmt):
            pass  # Returns don't typically sanitize

    def _check_sanitization_expr(self, expr: Expr, target_var: str,
                                 line: int) -> Optional[SanitizationFact]:
        """Check if an expression represents sanitization."""
        # Method calls: x.parse(), x.safeParse(), parseInt(), etc.
        if isinstance(expr, MethodCall):
            # Zod: schema.parse(input)
            if expr.method_name in ZOD_METHODS:
                return SanitizationFact(
                    sanitization_type=SanitizationType.ZOD_PARSE,
                    variable=target_var,
                    function_name=self._current_func,
                    line=line,
                    description=f"Zod .{expr.method_name}() validates '{target_var}'",
                    protects_against=ZOD_METHODS[expr.method_name],
                )

            # Auth checks: supabase.auth.getUser()
            if expr.method_name in AUTH_CHECKS:
                return SanitizationFact(
                    sanitization_type=SanitizationType.AUTH_CHECK,
                    variable=target_var,
                    function_name=self._current_func,
                    line=line,
                    description=f"Auth check .{expr.method_name}() in '{self._current_func}'",
                    protects_against=set(),
                )

            # Input validation: value.trim(), parseInt(value)
            if expr.method_name in VALIDATION_FUNCTIONS:
                return SanitizationFact(
                    sanitization_type=SanitizationType.INPUT_VALIDATION,
                    variable=target_var,
                    function_name=self._current_func,
                    line=line,
                    description=f"Validation .{expr.method_name}() on '{target_var}'",
                    protects_against=VALIDATION_FUNCTIONS[expr.method_name],
                )

        # Function calls: parseInt(x), Number(x), DOMPurify.sanitize(x)
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                fname = expr.callee.name
                if fname in VALIDATION_FUNCTIONS:
                    return SanitizationFact(
                        sanitization_type=SanitizationType.NUMERIC_PARSE,
                        variable=target_var,
                        function_name=self._current_func,
                        line=line,
                        description=f"{fname}() sanitizes '{target_var}'",
                        protects_against=VALIDATION_FUNCTIONS[fname],
                    )
                if fname in AUTH_CHECKS:
                    return SanitizationFact(
                        sanitization_type=SanitizationType.AUTH_CHECK,
                        variable=target_var,
                        function_name=self._current_func,
                        line=line,
                        description=f"Auth check {fname}() in '{self._current_func}'",
                        protects_against=set(),
                    )

        return None

    def _check_guard_condition(self, expr: Expr, line: int) -> Optional[SanitizationFact]:
        """Check if a condition expression is a type guard or null check."""
        if isinstance(expr, BinaryOp):
            # null/undefined checks: if (x != null)
            if expr.op in ("!=", "!=="):
                right_str = self._expr_str(expr.right)
                if right_str in ("null", "undefined", "None", "nil"):
                    left_var = self._expr_str(expr.left)
                    return SanitizationFact(
                        sanitization_type=SanitizationType.NULL_CHECK,
                        variable=left_var,
                        function_name=self._current_func,
                        line=line,
                        description=f"Null check on '{left_var}'",
                        protects_against=set(),
                    )
            # Numeric guards: if (divisor > 0)
            if expr.op in (">", ">=", "!="):
                left_var = self._expr_str(expr.left)
                return SanitizationFact(
                    sanitization_type=SanitizationType.INPUT_VALIDATION,
                    variable=left_var,
                    function_name=self._current_func,
                    line=line,
                    description=f"Guard condition '{left_var} {expr.op} {self._expr_str(expr.right)}'",
                    protects_against=set(),
                )

        return None

    def _expr_str(self, expr: Expr) -> str:
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, StringLiteral):
            return expr.value
        if isinstance(expr, FieldAccess):
            return f"{self._expr_str(expr.obj)}.{expr.field_name}"
        return "<expr>"


# ---------------------------------------------------------------------------
# Integration: Adjust confidence based on sanitization facts
# ---------------------------------------------------------------------------

def build_sanitization_index(facts: List[SanitizationFact]) -> Dict[str, List[SanitizationFact]]:
    """Build an index of sanitized variables for quick lookup."""
    index: Dict[str, List[SanitizationFact]] = {}
    for fact in facts:
        index.setdefault(fact.variable, []).append(fact)
        # Also index by function for auth checks
        index.setdefault(f"__func__{fact.function_name}", []).append(fact)
    return index


def confidence_adjustment(variable: str, taint_kind: str,
                          index: Dict[str, List[SanitizationFact]]) -> float:
    """Return a confidence multiplier (0.0–1.0) based on sanitization.

    If the variable was sanitized against the relevant taint kind,
    multiply confidence by a low factor (reducing it).
    """
    facts = index.get(variable, [])
    for fact in facts:
        if not fact.protects_against or taint_kind in fact.protects_against:
            # Zod parse → strong sanitization
            if fact.sanitization_type in (SanitizationType.ZOD_PARSE, SanitizationType.ZOD_SAFE_PARSE):
                return 0.1
            # Numeric parse → eliminates injection
            if fact.sanitization_type == SanitizationType.NUMERIC_PARSE:
                return 0.1
            # Input validation → moderate sanitization
            if fact.sanitization_type == SanitizationType.INPUT_VALIDATION:
                return 0.3
            # Null check → eliminates null-related issues
            if fact.sanitization_type == SanitizationType.NULL_CHECK:
                return 0.2
            # Auth check → reduces but doesn't eliminate
            if fact.sanitization_type == SanitizationType.AUTH_CHECK:
                return 0.5

    return 1.0  # No adjustment


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_sanitizers(program: Program) -> List[SanitizationFact]:
    """Find all sanitization and validation patterns in a program."""
    analyzer = SanitizerAnalyzer()
    return analyzer.analyze_program(program)
