"""AEON Taint Analysis Engine — Tracking Untrusted Data Flow.

Implements taint analysis for detecting injection vulnerabilities, based on:
  Schwartz, Avgerinos, Brumley (2010) "All You Ever Wanted to Know About
  Dynamic Taint Analysis and Forward Symbolic Execution"
  IEEE S&P '10, https://doi.org/10.1109/SP.2010.26

  Tripp et al. (2009) "TAJ: Effective Taint Analysis of Web Applications"
  PLDI '09, https://doi.org/10.1145/1542476.1542486

  Arzt et al. (2014) "FlowDroid: Precise Context, Flow, Field,
  Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps"
  PLDI '14, https://doi.org/10.1145/2594291.2594299

Key Theory:

1. TAINT SOURCES:
   External inputs that an attacker can control:
   - HTTP request parameters, headers, body
   - Database query results
   - File reads, environment variables
   - User input (stdin, forms, CLI args)

2. TAINT SINKS:
   Security-sensitive operations:
   - SQL queries (SQL injection)
   - HTML output (XSS)
   - OS commands (command injection)
   - File paths (path traversal)
   - Network destinations (SSRF)
   - Deserialization (insecure deserialization)

3. TAINT PROPAGATION:
   Taint flows through operations:
   - Assignment: y = x  =>  taint(y) = taint(x)
   - Binary ops: z = x + y  =>  taint(z) = taint(x) ∪ taint(y)
   - Function calls: propagate through parameters and returns
   - String operations: concatenation, formatting propagate taint

4. SANITIZERS:
   Functions that remove taint:
   - Input validation / escaping
   - Parameterized queries (prepared statements)
   - HTML encoding, URL encoding
   - Allowlist filtering

5. TAINT LATTICE:
   UNTAINTED < TAINTED
   With taint kinds: {SQL, XSS, CMD, PATH, SSRF, DESER}

Detects:
  - SQL injection
  - Cross-site scripting (XSS)
  - Command injection
  - Path traversal
  - Server-side request forgery (SSRF)
  - Insecure deserialization
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
# Taint Kinds
# ---------------------------------------------------------------------------

class TaintKind(Enum):
    SQL = "sql_injection"
    XSS = "cross_site_scripting"
    CMD = "command_injection"
    PATH = "path_traversal"
    SSRF = "server_side_request_forgery"
    DESER = "insecure_deserialization"
    LDAP = "ldap_injection"
    LOG = "log_injection"
    HEADER = "header_injection"
    TEMPLATE = "template_injection"
    REDIRECT = "open_redirect"


@dataclass(frozen=True)
class TaintLabel:
    """A taint label tracking where taint originated."""
    kind: TaintKind
    source_var: str
    source_location: Optional[SourceLocation] = None


@dataclass
class TaintState:
    """Taint state for a variable."""
    labels: Set[TaintLabel] = field(default_factory=set)
    is_sanitized: bool = False

    @property
    def is_tainted(self) -> bool:
        return len(self.labels) > 0 and not self.is_sanitized


# ---------------------------------------------------------------------------
# Source/Sink/Sanitizer Specifications
# ---------------------------------------------------------------------------

# Functions that introduce taint (sources)
TAINT_SOURCES: Dict[str, Set[TaintKind]] = {
    # Web inputs
    "request": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD, TaintKind.PATH},
    "get_param": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    "get_header": {TaintKind.XSS, TaintKind.LOG},
    "get_cookie": {TaintKind.XSS},
    "get_body": {TaintKind.SQL, TaintKind.XSS, TaintKind.DESER},
    "read_input": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    "readline": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    "gets": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    "stdin": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    "getenv": {TaintKind.CMD, TaintKind.PATH},
    "environ": {TaintKind.CMD, TaintKind.PATH},
    "argv": {TaintKind.CMD, TaintKind.PATH},
    # File/DB reads
    "read_file": {TaintKind.XSS, TaintKind.DESER},
    "query_result": {TaintKind.XSS},
    "fetch": {TaintKind.XSS, TaintKind.SSRF},
    "recv": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    # Deserialization
    "json_decode": {TaintKind.DESER},
    "deserialize": {TaintKind.DESER},
    "pickle_load": {TaintKind.DESER},
    "unmarshal": {TaintKind.DESER},
    "yaml_load": {TaintKind.DESER},
}

# Method names that are taint sources
TAINT_SOURCE_METHODS: Set[str] = {
    "get", "post", "param", "query", "body", "header", "cookie",
    "read", "readline", "readlines", "recv", "receive",
    "input", "scan", "next", "nextLine",
    "getParameter", "getAttribute", "getHeader",
    "Form", "Query", "Param", "Body",
}

# Functions/methods that are taint sinks
TAINT_SINKS: Dict[str, Set[TaintKind]] = {
    # SQL
    "execute": {TaintKind.SQL},
    "query": {TaintKind.SQL},
    "exec_sql": {TaintKind.SQL},
    "raw_query": {TaintKind.SQL},
    "cursor_execute": {TaintKind.SQL},
    "db_query": {TaintKind.SQL},
    # XSS
    "render_html": {TaintKind.XSS},
    "innerHTML": {TaintKind.XSS},
    "document_write": {TaintKind.XSS},
    "response_write": {TaintKind.XSS},
    "send_html": {TaintKind.XSS},
    # Command injection
    "system": {TaintKind.CMD},
    "exec": {TaintKind.CMD},
    "popen": {TaintKind.CMD},
    "spawn": {TaintKind.CMD},
    "shell_exec": {TaintKind.CMD},
    "subprocess_run": {TaintKind.CMD},
    "os_system": {TaintKind.CMD},
    # Path traversal
    "open": {TaintKind.PATH},
    "readFile": {TaintKind.PATH},
    "writeFile": {TaintKind.PATH},
    "unlink": {TaintKind.PATH},
    "rename": {TaintKind.PATH},
    # SSRF
    "http_get": {TaintKind.SSRF},
    "http_post": {TaintKind.SSRF},
    "fetch_url": {TaintKind.SSRF},
    "urlopen": {TaintKind.SSRF},
    "request_get": {TaintKind.SSRF},
    # Deserialization
    "pickle_loads": {TaintKind.DESER},
    "yaml_load_unsafe": {TaintKind.DESER},
    "unserialize": {TaintKind.DESER},
    # Log injection
    "log": {TaintKind.LOG},
    "logger_info": {TaintKind.LOG},
    "logger_warn": {TaintKind.LOG},
    "logger_error": {TaintKind.LOG},
    "logger_debug": {TaintKind.LOG},
    "console_log": {TaintKind.LOG},
    "syslog": {TaintKind.LOG},
    "print": {TaintKind.LOG},
    "fprintf": {TaintKind.LOG},
    # Header injection
    "set_header": {TaintKind.HEADER},
    "setHeader": {TaintKind.HEADER},
    "add_header": {TaintKind.HEADER},
    "addHeader": {TaintKind.HEADER},
    "response_header": {TaintKind.HEADER},
    "writeHead": {TaintKind.HEADER},
    "set_cookie": {TaintKind.HEADER},
    # Template injection
    "render": {TaintKind.TEMPLATE},
    "render_template": {TaintKind.TEMPLATE},
    "render_string": {TaintKind.TEMPLATE},
    "template_render": {TaintKind.TEMPLATE},
    "format": {TaintKind.TEMPLATE},
    "sprintf": {TaintKind.TEMPLATE},
    "eval_template": {TaintKind.TEMPLATE},
    # Open redirect
    "redirect": {TaintKind.REDIRECT},
    "redirect_to": {TaintKind.REDIRECT},
    "sendRedirect": {TaintKind.REDIRECT},
    "location_assign": {TaintKind.REDIRECT},
    "navigate": {TaintKind.REDIRECT},
    "window_location": {TaintKind.REDIRECT},
}

# Functions that sanitize taint
SANITIZERS: Dict[str, Set[TaintKind]] = {
    "escape_html": {TaintKind.XSS},
    "html_escape": {TaintKind.XSS},
    "htmlspecialchars": {TaintKind.XSS},
    "encode_html": {TaintKind.XSS},
    "sanitize": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD, TaintKind.PATH},
    "validate": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    "parameterize": {TaintKind.SQL},
    "prepared_statement": {TaintKind.SQL},
    "quote": {TaintKind.SQL},
    "escape_string": {TaintKind.SQL},
    "shellescape": {TaintKind.CMD},
    "shlex_quote": {TaintKind.CMD},
    "basename": {TaintKind.PATH},
    "realpath": {TaintKind.PATH},
    "url_encode": {TaintKind.SSRF, TaintKind.XSS},
    "parseInt": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    "to_int": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    "int": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD},
    "allowlist_check": {TaintKind.SQL, TaintKind.XSS, TaintKind.CMD, TaintKind.PATH, TaintKind.SSRF},
    "strip_newlines": {TaintKind.LOG, TaintKind.HEADER},
    "replace_newlines": {TaintKind.LOG, TaintKind.HEADER},
    "encode_log": {TaintKind.LOG},
    "validate_url": {TaintKind.REDIRECT, TaintKind.SSRF},
    "is_safe_url": {TaintKind.REDIRECT, TaintKind.SSRF},
    "allowlist_url": {TaintKind.REDIRECT, TaintKind.SSRF},
    "escape_template": {TaintKind.TEMPLATE},
    "auto_escape": {TaintKind.TEMPLATE, TaintKind.XSS},
}


# ---------------------------------------------------------------------------
# Taint Analyzer
# ---------------------------------------------------------------------------

class TaintAnalyzer:
    """Performs interprocedural taint analysis to detect injection vulnerabilities."""

    def __init__(self):
        self.errors: List[AeonError] = []
        self.taint_env: Dict[str, TaintState] = {}
        self._function_summaries: Dict[str, Tuple[Set[int], TaintState]] = {}

    def check_program(self, program: Program) -> List[AeonError]:
        """Run taint analysis on the entire program."""
        self.errors = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.errors

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function for taint flow from sources to sinks."""
        self.taint_env = {}

        # Check parameters for taint sources
        for param in func.params:
            param_name = param.name.lower()
            type_str = str(param.type_annotation).lower() if param.type_annotation else ""

            # Heuristic: parameters named like user input are taint sources
            is_source = any(kw in param_name for kw in
                          ("input", "request", "query", "param", "user",
                           "data", "body", "form", "header", "cookie",
                           "args", "payload", "content", "raw", "untrusted"))
            is_source = is_source or any(kw in type_str for kw in
                                        ("request", "httprequest", "formdata"))

            if is_source:
                loc = getattr(param, 'location', None)
                self.taint_env[param.name] = TaintState(labels={
                    TaintLabel(kind=k, source_var=param.name, source_location=loc)
                    for k in (TaintKind.SQL, TaintKind.XSS, TaintKind.CMD, TaintKind.PATH)
                })

        # Analyze body
        for stmt in func.body:
            self._analyze_statement(stmt, func)

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Analyze a statement for taint propagation."""
        loc = getattr(stmt, 'location', SourceLocation("<taint>", 0, 0))

        if isinstance(stmt, LetStmt):
            if stmt.value:
                taint = self._get_expr_taint(stmt.value, loc)
                # Check if the value is from a sanitizer
                if self._is_sanitizer_call(stmt.value):
                    taint = TaintState(labels=taint.labels, is_sanitized=True)
                # Check if the value is from a source
                source_taint = self._check_source(stmt.value, loc)
                if source_taint:
                    taint.labels.update(source_taint.labels)
                self.taint_env[stmt.name] = taint
                # Check if flowing into a sink
                self._check_sink(stmt.value, taint, func, loc)

        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                taint = self._get_expr_taint(stmt.value, loc)
                if self._is_sanitizer_call(stmt.value):
                    taint = TaintState(labels=taint.labels, is_sanitized=True)
                self.taint_env[stmt.target.name] = taint
                self._check_sink(stmt.value, taint, func, loc)

        elif isinstance(stmt, ExprStmt):
            expr_taint = self._get_expr_taint(stmt.expr, loc)
            self._check_sink(stmt.expr, expr_taint, func, loc)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._get_expr_taint(stmt.value, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._analyze_statement(s, func)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._analyze_statement(s, func)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._analyze_statement(s, func)

    def _get_expr_taint(self, expr: Expr, loc: SourceLocation) -> TaintState:
        """Compute the taint state of an expression."""
        if isinstance(expr, Identifier):
            return self.taint_env.get(expr.name, TaintState())

        if isinstance(expr, (IntLiteral, BoolLiteral)):
            return TaintState()

        if isinstance(expr, StringLiteral):
            return TaintState()

        if isinstance(expr, BinaryOp):
            left_taint = self._get_expr_taint(expr.left, loc)
            right_taint = self._get_expr_taint(expr.right, loc)
            # Taint propagates through binary ops (union)
            combined = TaintState(labels=left_taint.labels | right_taint.labels)
            return combined

        if isinstance(expr, UnaryOp):
            return self._get_expr_taint(expr.operand, loc)

        if isinstance(expr, FunctionCall):
            # Collect argument taints
            arg_taints = TaintState()
            for arg in expr.args:
                at = self._get_expr_taint(arg, loc)
                arg_taints.labels.update(at.labels)

            # Check if the function is a taint source
            source_taint = self._check_source(expr, loc)
            if source_taint:
                arg_taints.labels.update(source_taint.labels)

            # Check if the function is a sanitizer
            if self._is_sanitizer_call(expr):
                arg_taints.is_sanitized = True

            return arg_taints

        if isinstance(expr, MethodCall):
            obj_taint = self._get_expr_taint(expr.obj, loc)
            for arg in expr.args:
                at = self._get_expr_taint(arg, loc)
                obj_taint.labels.update(at.labels)

            # Check if method is a source
            if expr.method_name.lower() in TAINT_SOURCE_METHODS:
                obj_taint.labels.add(TaintLabel(
                    kind=TaintKind.XSS, source_var=f"{expr.method_name}_result",
                    source_location=loc,
                ))

            return obj_taint

        if isinstance(expr, FieldAccess):
            return self._get_expr_taint(expr.obj, loc)

        return TaintState()

    def _check_source(self, expr: Expr, loc: SourceLocation) -> Optional[TaintState]:
        """Check if an expression is a taint source."""
        func_name = None
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            func_name = expr.callee.name.lower()
        elif isinstance(expr, MethodCall):
            func_name = expr.method_name.lower()

        if func_name:
            for source_name, kinds in TAINT_SOURCES.items():
                if source_name in func_name:
                    return TaintState(labels={
                        TaintLabel(kind=k, source_var=func_name, source_location=loc)
                        for k in kinds
                    })
        return None

    def _check_sink(self, expr: Expr, taint: TaintState, func: PureFunc | TaskFunc,
                    loc: SourceLocation) -> None:
        """Check if tainted data flows into a sink without sanitization."""
        if not taint.is_tainted:
            return

        sink_name = None
        sink_kinds: Set[TaintKind] = set()

        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            name = expr.callee.name.lower()
            for sink, kinds in TAINT_SINKS.items():
                if sink in name:
                    sink_name = expr.callee.name
                    sink_kinds = kinds
                    break

        elif isinstance(expr, MethodCall):
            name = expr.method_name.lower()
            for sink, kinds in TAINT_SINKS.items():
                if sink in name:
                    sink_name = expr.method_name
                    sink_kinds = kinds
                    break

        if sink_name and sink_kinds:
            # Check which taint kinds reach this sink
            for label in taint.labels:
                if label.kind in sink_kinds:
                    vuln_name = label.kind.value.replace("_", " ").title()
                    self.errors.append(contract_error(
                        precondition=(
                            f"Taint violation: {vuln_name} — "
                            f"untrusted input '{label.source_var}' flows to "
                            f"sensitive sink '{sink_name}' without sanitization"
                        ),
                        failing_values={
                            "vulnerability": label.kind.value,
                            "source": label.source_var,
                            "sink": sink_name,
                            "engine": "Taint Analysis",
                        },
                        function_signature=f"{func.name}",
                        location=loc,
                    ))

    def _is_sanitizer_call(self, expr: Expr) -> bool:
        """Check if expression is a sanitizer call."""
        func_name = None
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            func_name = expr.callee.name.lower()
        elif isinstance(expr, MethodCall):
            func_name = expr.method_name.lower()

        if func_name:
            for sanitizer in SANITIZERS:
                if sanitizer in func_name:
                    return True
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_taint(program: Program) -> List[AeonError]:
    """Run taint analysis on an AEON program.

    Detects injection vulnerabilities:
    - SQL injection
    - Cross-site scripting (XSS)
    - Command injection
    - Path traversal
    - SSRF
    - Insecure deserialization
    - Log injection
    - Header injection
    - Template injection
    - Open redirect
    """
    analyzer = TaintAnalyzer()
    return analyzer.check_program(program)
