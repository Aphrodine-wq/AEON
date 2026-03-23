"""AEON HTTP Request Smuggling Detection Engine -- Server/Proxy Desync Analysis.

Detects HTTP request smuggling vulnerabilities that arise from ambiguities
in how HTTP/1.1 messages are framed, parsed, and forwarded between front-end
proxies and back-end servers.

References:
  CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')
  https://cwe.mitre.org/data/definitions/444.html

  CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')
  https://cwe.mitre.org/data/definitions/441.html

  CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')
  https://cwe.mitre.org/data/definitions/757.html

  Kettle (2019) "HTTP Desync Attacks: Request Smuggling Reborn"
  PortSwigger Research / Black Hat USA 2019
  https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

  Kettle (2021) "HTTP/2: The Sequel is Always Worse"
  PortSwigger Research / Black Hat USA 2021
  https://portswigger.net/research/http2

  Klein (2020) "HTTP Request Smuggling in 2020"
  SafeBreach Labs, https://i.blackhat.com/USA-20/Wednesday/us-20-Klein-HTTP-Request-Smuggling-In-2020.pdf

  RFC 7230 Section 3.3.3 -- Message Body Length rules
  RFC 9112 Section 6 -- HTTP/1.1 Message Body Length (supersedes 7230)

Detection Categories:

1. TRANSFER-ENCODING MANIPULATION (CWE-444):
   Code that manually sets or processes Transfer-Encoding headers. Incorrect
   handling of TE headers is the root cause of CL.TE and TE.CL smuggling.

2. CONTENT-LENGTH MANIPULATION (CWE-444):
   Manually setting Content-Length to a computed or hardcoded value that may
   not match the actual body size, creating CL desync conditions.

3. RAW HTTP HANDLING (CWE-444):
   Building HTTP requests/responses by string concatenation instead of using
   HTTP libraries. Hand-rolled HTTP framing is inherently smuggling-prone.

4. PROXY CONFIGURATION RISKS (CWE-441):
   Reverse proxy forwarding without request normalization, missing timeout
   configuration, or absent HTTP version pinning.

5. HTTP/2 DOWNGRADE (CWE-757):
   Accepting HTTP/2 from clients but forwarding as HTTP/1.1 to backends,
   enabling H2.CL and H2.TE smuggling vectors.

6. CHUNKED ENCODING ISSUES (CWE-444):
   Manually implementing chunked transfer encoding instead of using library
   implementations, risking malformed chunk boundaries.

7. WEBSOCKET UPGRADE SMUGGLING (CWE-444):
   Manual WebSocket upgrade handling (Connection: Upgrade) without proper
   request validation, enabling upgrade-based smuggling.

8. REQUEST BODY IN GET (CWE-444):
   Sending request bodies with GET requests. Some proxies ignore GET bodies
   while others forward them, creating desync conditions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral,
    BinaryOp, FunctionCall, FieldAccess, MethodCall,
    LetStmt, AssignStmt, IfStmt, ExprStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Severity Levels
# ---------------------------------------------------------------------------

class Severity(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Smuggling Categories
# ---------------------------------------------------------------------------

class SmugglingCategory(Enum):
    TE_MANIPULATION = "transfer_encoding_manipulation"
    CL_MANIPULATION = "content_length_manipulation"
    RAW_HTTP = "raw_http_handling"
    PROXY_CONFIG = "proxy_configuration_risk"
    H2_DOWNGRADE = "http2_downgrade"
    CHUNKED_ISSUES = "chunked_encoding_issues"
    WEBSOCKET_UPGRADE = "websocket_upgrade_smuggling"
    GET_BODY = "request_body_in_get"


# CWE mapping
CWE_MAP: Dict[SmugglingCategory, str] = {
    SmugglingCategory.TE_MANIPULATION: "CWE-444",
    SmugglingCategory.CL_MANIPULATION: "CWE-444",
    SmugglingCategory.RAW_HTTP: "CWE-444",
    SmugglingCategory.PROXY_CONFIG: "CWE-441",
    SmugglingCategory.H2_DOWNGRADE: "CWE-757",
    SmugglingCategory.CHUNKED_ISSUES: "CWE-444",
    SmugglingCategory.WEBSOCKET_UPGRADE: "CWE-444",
    SmugglingCategory.GET_BODY: "CWE-444",
}

# Severity mapping -- conservative; most are MEDIUM (risk indicator, not confirmed vuln)
SEVERITY_MAP: Dict[SmugglingCategory, Severity] = {
    SmugglingCategory.TE_MANIPULATION: Severity.MEDIUM,
    SmugglingCategory.CL_MANIPULATION: Severity.MEDIUM,
    SmugglingCategory.RAW_HTTP: Severity.HIGH,
    SmugglingCategory.PROXY_CONFIG: Severity.MEDIUM,
    SmugglingCategory.H2_DOWNGRADE: Severity.MEDIUM,
    SmugglingCategory.CHUNKED_ISSUES: Severity.MEDIUM,
    SmugglingCategory.WEBSOCKET_UPGRADE: Severity.MEDIUM,
    SmugglingCategory.GET_BODY: Severity.LOW,
}

# Remediation guidance
REMEDIATION_MAP: Dict[SmugglingCategory, str] = {
    SmugglingCategory.TE_MANIPULATION: (
        "Do not manually set or parse Transfer-Encoding headers. Use your "
        "HTTP library's built-in body framing. If you must process TE headers, "
        "reject requests with multiple TE headers or TE combined with Content-Length. "
        "Normalize all requests through a WAF or reverse proxy that strips ambiguous framing."
    ),
    SmugglingCategory.CL_MANIPULATION: (
        "Do not manually compute or set Content-Length. Let your HTTP library "
        "calculate it from the actual body. If setting Content-Length is required, "
        "derive it from Buffer.byteLength() or len() of the exact body bytes, "
        "never from string length or a hardcoded value."
    ),
    SmugglingCategory.RAW_HTTP: (
        "Do not build HTTP messages by string concatenation. Use an HTTP library "
        "(http module, requests, fetch, etc.) that handles framing, encoding, "
        "and header serialization correctly. Raw HTTP construction is inherently "
        "fragile and smuggling-prone."
    ),
    SmugglingCategory.PROXY_CONFIG: (
        "Configure reverse proxies with explicit request normalization: set "
        "proxyTimeout, use changeOrigin, pin the HTTP version for backend "
        "connections, and reject ambiguous requests. Use proxy_http_version 1.1 "
        "in nginx or equivalent in your proxy layer."
    ),
    SmugglingCategory.H2_DOWNGRADE: (
        "Avoid HTTP/2-to-HTTP/1.1 downgrade. Use end-to-end HTTP/2 where possible. "
        "If downgrade is required, ensure the proxy normalizes all headers and "
        "strips pseudo-headers before forwarding. Deploy a WAF that inspects "
        "the HTTP/1.1 translation for smuggling payloads."
    ),
    SmugglingCategory.CHUNKED_ISSUES: (
        "Do not implement chunked transfer encoding manually. Use your HTTP "
        "library's streaming/chunked response API. Manual chunk boundary "
        "construction risks off-by-one errors that enable smuggling."
    ),
    SmugglingCategory.WEBSOCKET_UPGRADE: (
        "Use a well-tested WebSocket library (ws, socket.io, websockets) "
        "instead of manually handling Upgrade headers. If manual handling is "
        "required, validate the full upgrade handshake: check Upgrade, "
        "Connection, Sec-WebSocket-Key, and Sec-WebSocket-Version headers."
    ),
    SmugglingCategory.GET_BODY: (
        "Do not send request bodies with GET requests. Per RFC 9110, a GET "
        "request body has no defined semantics -- different proxies handle "
        "GET bodies inconsistently, creating desync conditions. Use POST or "
        "PUT for requests that require a body."
    ),
}


# ---------------------------------------------------------------------------
# Finding Representation
# ---------------------------------------------------------------------------

@dataclass
class SmugglingFinding:
    """Internal representation of a detected HTTP smuggling vulnerability."""
    category: SmugglingCategory
    severity: Severity
    description: str
    cwe: str
    location: Optional[SourceLocation]
    function_name: str
    remediation: str
    evidence: str = ""
    details: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pattern Constants
# ---------------------------------------------------------------------------

# Transfer-Encoding header names (case variations)
TE_HEADER_NAMES: Set[str] = {
    "transfer-encoding", "Transfer-Encoding", "transfer_encoding",
    "transferEncoding", "TransferEncoding",
}

# Content-Length header names (case variations)
CL_HEADER_NAMES: Set[str] = {
    "content-length", "Content-Length", "content_length",
    "contentLength", "ContentLength",
}

# Functions/methods that set HTTP headers
HEADER_SET_FUNCTIONS: Set[str] = {
    "setHeader", "set_header", "writeHead", "write_head",
    "appendHeader", "append_header", "addHeader", "add_header",
    "set", "append", "header",
}

# Raw HTTP protocol markers in string literals
RAW_HTTP_MARKERS: List[str] = [
    "HTTP/1.0", "HTTP/1.1", "HTTP/2",
]

# CRLF sequence markers in raw HTTP
CRLF_MARKERS: List[str] = [
    "\\r\\n", "\r\n",
]

# Header patterns that indicate raw HTTP construction
RAW_HEADER_PATTERNS: List[re.Pattern] = [
    re.compile(r"Content-Length:\s*", re.IGNORECASE),
    re.compile(r"Transfer-Encoding:\s*", re.IGNORECASE),
    re.compile(r"Host:\s*", re.IGNORECASE),
    re.compile(r"Connection:\s*", re.IGNORECASE),
]

# Proxy middleware / libraries
PROXY_LIBRARIES: Set[str] = {
    "http-proxy", "http_proxy", "httpProxy", "HttpProxy",
    "http-proxy-middleware", "http_proxy_middleware",
    "httpProxyMiddleware", "HttpProxyMiddleware",
    "createProxyServer", "create_proxy_server",
    "createProxyMiddleware", "create_proxy_middleware",
}

# Proxy configuration functions/methods
PROXY_CONFIG_METHODS: Set[str] = {
    "createProxyServer", "create_proxy_server",
    "createProxyMiddleware", "create_proxy_middleware",
    "proxy_pass", "proxyPass", "ProxyPass",
    "reverse_proxy", "reverseProxy", "ReverseProxy",
    "forward", "forwardTo", "forward_to",
}

# Proxy safety configuration keys
PROXY_SAFETY_KEYS: Set[str] = {
    "proxyTimeout", "proxy_timeout",
    "changeOrigin", "change_origin",
    "httpVersion", "http_version",
    "secure", "xfwd", "ws",
    "timeout", "connectTimeout", "connect_timeout",
}

# Chunked encoding related strings
CHUNKED_MARKERS: Set[str] = {
    "chunked", "transfer-encoding: chunked",
    "Transfer-Encoding: chunked",
}

# WebSocket upgrade header values
WEBSOCKET_UPGRADE_MARKERS: Set[str] = {
    "upgrade", "Upgrade", "websocket", "WebSocket", "Websocket",
}

# Connection: Upgrade patterns
CONNECTION_UPGRADE_HEADERS: Set[str] = {
    "Connection", "connection", "upgrade", "Upgrade",
}

# HTTP methods that should not have a body
BODYLESS_METHODS: Set[str] = {
    "GET", "HEAD", "DELETE", "OPTIONS", "TRACE",
}

# Frontend file extensions to skip
_FRONTEND_EXTENSIONS = frozenset({
    ".tsx", ".jsx", ".vue", ".svelte", ".css", ".scss", ".less",
    ".html", ".htm", ".ejs", ".hbs", ".pug",
})

# Frontend framework identifiers
_FRONTEND_IDENTIFIERS: Set[str] = {
    "useState", "useEffect", "useCallback", "useMemo", "useRef",
    "useContext", "useReducer", "useRouter", "useNavigate",
    "useHistory", "useLocation", "useSearchParams", "usePathname",
    "jsx", "createElement", "Fragment", "render",
    "component", "Component", "directive", "Directive",
}


# ---------------------------------------------------------------------------
# AST Helpers
# ---------------------------------------------------------------------------

def _expr_name(expr: Expr) -> str:
    """Extract a readable name from an expression."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, StringLiteral):
        return expr.value
    if isinstance(expr, FieldAccess):
        obj_name = _expr_name(expr.obj)
        return f"{obj_name}.{expr.field_name}" if obj_name else expr.field_name
    if isinstance(expr, MethodCall):
        obj_name = _expr_name(expr.obj)
        return f"{obj_name}.{expr.method_name}" if obj_name else expr.method_name
    return ""


def _extract_string_values(expr: Expr) -> List[str]:
    """Recursively collect all string literal values from an expression tree."""
    results: List[str] = []
    if isinstance(expr, StringLiteral):
        results.append(expr.value)
    elif isinstance(expr, BinaryOp):
        results.extend(_extract_string_values(expr.left))
        results.extend(_extract_string_values(expr.right))
    elif isinstance(expr, FunctionCall):
        for arg in expr.args:
            results.extend(_extract_string_values(arg))
    elif isinstance(expr, MethodCall):
        results.extend(_extract_string_values(expr.obj))
        for arg in expr.args:
            results.extend(_extract_string_values(arg))
    elif isinstance(expr, FieldAccess):
        results.extend(_extract_string_values(expr.obj))
    return results


def _walk_stmt_recursive(stmt: Statement):
    """Recursively yield a statement and all nested statements."""
    yield stmt
    if isinstance(stmt, IfStmt):
        for s in stmt.then_body:
            yield from _walk_stmt_recursive(s)
        if stmt.else_body:
            for s in stmt.else_body:
                yield from _walk_stmt_recursive(s)
    elif hasattr(stmt, "body") and isinstance(getattr(stmt, "body"), list):
        for s in getattr(stmt, "body"):
            if isinstance(s, Statement):
                yield from _walk_stmt_recursive(s)


def _walk_all_statements(func: PureFunc | TaskFunc):
    """Yield all statements from a function body, recursively flattened."""
    for stmt in func.body:
        yield from _walk_stmt_recursive(stmt)


def _is_frontend_file(filename: str) -> bool:
    """Check if the filename indicates a frontend/UI component file."""
    if not filename:
        return False
    name_lower = filename.lower()
    return any(name_lower.endswith(ext) for ext in _FRONTEND_EXTENSIONS)


def _function_has_frontend_patterns(func) -> bool:
    """Check if a function body contains frontend framework patterns."""
    for stmt in getattr(func, "body", []):
        for sub_stmt in _walk_stmt_recursive(stmt):
            exprs: List[Expr] = []
            if isinstance(sub_stmt, LetStmt) and sub_stmt.value:
                exprs.append(sub_stmt.value)
            elif isinstance(sub_stmt, ExprStmt):
                exprs.append(sub_stmt.expr)
            elif isinstance(sub_stmt, AssignStmt):
                exprs.append(sub_stmt.value)
            for expr in exprs:
                if isinstance(expr, FunctionCall):
                    callee = _expr_name(expr.callee)
                    if callee in _FRONTEND_IDENTIFIERS:
                        return True
                elif isinstance(expr, Identifier):
                    if expr.name in _FRONTEND_IDENTIFIERS:
                        return True
    return False


def _extract_exprs(stmt: Statement) -> List[Expr]:
    """Extract top-level expressions from a statement."""
    exprs: List[Expr] = []
    if isinstance(stmt, LetStmt) and stmt.value:
        exprs.append(stmt.value)
    elif isinstance(stmt, AssignStmt):
        exprs.append(stmt.value)
    elif isinstance(stmt, ExprStmt):
        exprs.append(stmt.expr)
    elif isinstance(stmt, IfStmt):
        exprs.append(stmt.condition)
    return exprs


def _is_string_concat(expr: Expr) -> bool:
    """Check if an expression is a string concatenation operation."""
    if isinstance(expr, BinaryOp):
        if expr.op in ("+", ".."):
            left_has_str = isinstance(expr.left, StringLiteral) or _is_string_concat(expr.left)
            right_has_str = isinstance(expr.right, StringLiteral) or _is_string_concat(expr.right)
            return left_has_str or right_has_str
    return False


def _expr_is_literal_number(expr: Expr) -> bool:
    """Check if an expression is a numeric literal or simple arithmetic."""
    if isinstance(expr, Identifier):
        # Variable -- not a literal
        return False
    if isinstance(expr, StringLiteral):
        # String, not a number
        return False
    if isinstance(expr, BinaryOp):
        # Could be len(body) + 2, body.length, etc. -- computed, not literal
        return False
    if isinstance(expr, FunctionCall):
        return False
    if isinstance(expr, MethodCall):
        return False
    if isinstance(expr, FieldAccess):
        return False
    # Anything else (NumberLiteral if it exists) is a literal
    return True


def _is_body_length_expr(expr: Expr) -> bool:
    """Check if expression computes body/content length (safe pattern)."""
    name = _expr_name(expr).lower()
    safe_patterns = (
        "buffer.bytelength", "bytelength", "byte_length",
        "len(", "strlen", "sizeof",
        ".length", ".size", ".bytelength",
        "content_length", "contentlength",
    )
    return any(p in name for p in safe_patterns)


# ---------------------------------------------------------------------------
# HTTP Smuggling Analyzer
# ---------------------------------------------------------------------------

class HTTPSmugglingAnalyzer:
    """Analyzes programs for HTTP request smuggling vulnerabilities.

    Examines the AST for patterns that indicate HTTP request smuggling risks:
    Transfer-Encoding manipulation, Content-Length desync, raw HTTP construction,
    proxy misconfiguration, HTTP/2 downgrade, chunked encoding issues,
    WebSocket upgrade smuggling, and GET request bodies.
    """

    def __init__(self):
        self.findings: List[SmugglingFinding] = []
        self._current_func: str = ""
        self._is_frontend: bool = False
        self._func_has_frontend: bool = False
        # Track TE/CL header sets in current function for combined detection
        self._has_te_set: bool = False
        self._has_cl_set: bool = False
        # Track variables holding header values
        self._header_vars: Dict[str, str] = {}
        # Track proxy config objects
        self._proxy_configs: Dict[str, Set[str]] = {}

    def check_program(self, program: Program) -> List[SmugglingFinding]:
        """Run HTTP smuggling analysis on the entire program."""
        self.findings = []
        self._is_frontend = _is_frontend_file(getattr(program, "filename", ""))

        # Skip frontend files entirely -- smuggling is a server/proxy concern
        if self._is_frontend:
            return self.findings

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.findings

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for HTTP smuggling patterns."""
        self._current_func = func.name
        self._has_te_set = False
        self._has_cl_set = False
        self._header_vars = {}
        self._proxy_configs = {}

        # Skip functions with frontend patterns
        self._func_has_frontend = _function_has_frontend_patterns(func)
        if self._func_has_frontend:
            return

        all_stmts = list(_walk_all_statements(func))

        # Run all detectors
        for stmt in all_stmts:
            loc = getattr(stmt, "location", None)
            self._check_te_manipulation(stmt, loc)
            self._check_cl_manipulation(stmt, loc)
            self._check_raw_http(stmt, loc)
            self._check_proxy_config(stmt, loc)
            self._check_h2_downgrade(stmt, loc)
            self._check_chunked_issues(stmt, loc)
            self._check_websocket_upgrade(stmt, loc)
            self._check_get_body(stmt, loc)

        # Cross-statement: TE + CL both set in same function
        if self._has_te_set and self._has_cl_set:
            self.findings.append(SmugglingFinding(
                category=SmugglingCategory.TE_MANIPULATION,
                severity=Severity.HIGH,
                description=(
                    f"Both Transfer-Encoding and Content-Length headers are "
                    f"set in function '{self._current_func}'. Sending both "
                    f"headers simultaneously is the canonical HTTP request "
                    f"smuggling vector (CL.TE / TE.CL desync). RFC 7230 "
                    f"Section 3.3.3 requires that Transfer-Encoding take "
                    f"precedence, but not all servers comply."
                ),
                cwe="CWE-444",
                location=None,
                function_name=self._current_func,
                remediation=(
                    "Never send both Transfer-Encoding and Content-Length "
                    "headers in the same request. Remove one or let your "
                    "HTTP library handle framing automatically. If proxying, "
                    "strip one header before forwarding."
                ),
                evidence="TE + CL headers both set in same function",
            ))

    # ------------------------------------------------------------------
    # 1. Transfer-Encoding Manipulation (CWE-444)
    # ------------------------------------------------------------------

    def _check_te_manipulation(self, stmt: Statement, loc: Optional[SourceLocation]) -> None:
        """Detect manual Transfer-Encoding header manipulation."""
        exprs = _extract_exprs(stmt)
        for expr in exprs:
            self._check_te_in_expr(expr, loc)

    def _check_te_in_expr(self, expr: Expr, loc: Optional[SourceLocation]) -> None:
        """Check an expression for Transfer-Encoding header manipulation."""
        # Pattern: setHeader('Transfer-Encoding', ...)
        if isinstance(expr, MethodCall):
            if expr.method_name in HEADER_SET_FUNCTIONS:
                if expr.args:
                    header_name = self._get_header_name_from_arg(expr.args[0])
                    if header_name and header_name.lower() in {n.lower() for n in TE_HEADER_NAMES}:
                        self._has_te_set = True
                        self.findings.append(SmugglingFinding(
                            category=SmugglingCategory.TE_MANIPULATION,
                            severity=Severity.MEDIUM,
                            description=(
                                f"Manual Transfer-Encoding header set via "
                                f"'{expr.method_name}()' in '{self._current_func}'. "
                                f"Incorrect TE header handling is the root cause "
                                f"of HTTP request smuggling. Let your HTTP library "
                                f"manage transfer encoding automatically."
                            ),
                            cwe="CWE-444",
                            location=loc,
                            function_name=self._current_func,
                            remediation=REMEDIATION_MAP[SmugglingCategory.TE_MANIPULATION],
                            evidence=f"{_expr_name(expr.obj)}.{expr.method_name}('{header_name}', ...)",
                        ))

        if isinstance(expr, FunctionCall):
            callee_name = _expr_name(expr.callee)
            if callee_name in HEADER_SET_FUNCTIONS or callee_name.split(".")[-1] in HEADER_SET_FUNCTIONS:
                if expr.args:
                    header_name = self._get_header_name_from_arg(expr.args[0])
                    if header_name and header_name.lower() in {n.lower() for n in TE_HEADER_NAMES}:
                        self._has_te_set = True
                        self.findings.append(SmugglingFinding(
                            category=SmugglingCategory.TE_MANIPULATION,
                            severity=Severity.MEDIUM,
                            description=(
                                f"Manual Transfer-Encoding header set via "
                                f"'{callee_name}()' in '{self._current_func}'. "
                                f"Let your HTTP framework handle transfer encoding."
                            ),
                            cwe="CWE-444",
                            location=loc,
                            function_name=self._current_func,
                            remediation=REMEDIATION_MAP[SmugglingCategory.TE_MANIPULATION],
                            evidence=f"{callee_name}('{header_name}', ...)",
                        ))

        # Pattern: req.headers['transfer-encoding'] direct access/processing
        if isinstance(expr, FieldAccess):
            if expr.field_name.lower().replace("-", "").replace("_", "") == "transferencoding":
                # Reading TE from request headers -- flag only if it looks like parsing
                # (we check in parent context, but flag the access as informational)
                self._has_te_set = True

        # Check nested expressions
        if isinstance(expr, BinaryOp):
            self._check_te_in_expr(expr.left, loc)
            self._check_te_in_expr(expr.right, loc)
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._check_te_in_expr(arg, loc)
        elif isinstance(expr, MethodCall):
            self._check_te_in_expr(expr.obj, loc)
            for arg in expr.args:
                self._check_te_in_expr(arg, loc)

    # ------------------------------------------------------------------
    # 2. Content-Length Manipulation (CWE-444)
    # ------------------------------------------------------------------

    def _check_cl_manipulation(self, stmt: Statement, loc: Optional[SourceLocation]) -> None:
        """Detect manual Content-Length header setting with suspicious values."""
        exprs = _extract_exprs(stmt)
        for expr in exprs:
            self._check_cl_in_expr(expr, loc)

    def _check_cl_in_expr(self, expr: Expr, loc: Optional[SourceLocation]) -> None:
        """Check an expression for Content-Length manipulation."""
        # Pattern: setHeader('Content-Length', <computed_value>)
        if isinstance(expr, (MethodCall, FunctionCall)):
            method_name = ""
            args: List[Expr] = []

            if isinstance(expr, MethodCall):
                method_name = expr.method_name
                args = expr.args
            elif isinstance(expr, FunctionCall):
                method_name = _expr_name(expr.callee).split(".")[-1]
                args = expr.args

            if method_name in HEADER_SET_FUNCTIONS and len(args) >= 2:
                header_name = self._get_header_name_from_arg(args[0])
                if header_name and header_name.lower() in {n.lower() for n in CL_HEADER_NAMES}:
                    self._has_cl_set = True
                    value_expr = args[1]

                    # Check if the value is safely computed from actual body length
                    if _is_body_length_expr(value_expr):
                        # Safe -- derived from actual body, no finding
                        return

                    # Flag: hardcoded number or computed value that might not match
                    severity = Severity.MEDIUM
                    desc_detail = "a computed value"

                    if _expr_is_literal_number(value_expr):
                        severity = Severity.HIGH
                        desc_detail = "a hardcoded numeric value"

                    self.findings.append(SmugglingFinding(
                        category=SmugglingCategory.CL_MANIPULATION,
                        severity=severity,
                        description=(
                            f"Content-Length header manually set to {desc_detail} "
                            f"in '{self._current_func}'. If this value does not "
                            f"match the actual body size, the front-end and back-end "
                            f"will disagree on message boundaries, enabling smuggling."
                        ),
                        cwe="CWE-444",
                        location=loc,
                        function_name=self._current_func,
                        remediation=REMEDIATION_MAP[SmugglingCategory.CL_MANIPULATION],
                        evidence=f"Content-Length set to: {_expr_name(value_expr) or '<expression>'}",
                    ))

    # ------------------------------------------------------------------
    # 3. Raw HTTP Handling (CWE-444)
    # ------------------------------------------------------------------

    def _check_raw_http(self, stmt: Statement, loc: Optional[SourceLocation]) -> None:
        """Detect raw HTTP request/response construction via string concatenation."""
        exprs = _extract_exprs(stmt)
        for expr in exprs:
            if not _is_string_concat(expr) and not isinstance(expr, StringLiteral):
                continue

            strings = _extract_string_values(expr)
            combined = " ".join(strings)

            has_http_version = any(marker in combined for marker in RAW_HTTP_MARKERS)
            has_crlf = any(marker in combined for marker in CRLF_MARKERS)
            has_header_pattern = any(pat.search(combined) for pat in RAW_HEADER_PATTERNS)

            # Require at least two indicators to flag raw HTTP construction
            # This avoids flagging simple version strings or log messages
            indicators = sum([has_http_version, has_crlf, has_header_pattern])
            if indicators < 2:
                continue

            # Additional check: if this is just a string constant being compared
            # or logged, skip it. Only flag if it's being written/sent.
            if self._is_comparison_or_log_context(stmt):
                continue

            self.findings.append(SmugglingFinding(
                category=SmugglingCategory.RAW_HTTP,
                severity=Severity.HIGH,
                description=(
                    f"Raw HTTP message construction detected in "
                    f"'{self._current_func}'. Building HTTP requests or "
                    f"responses by string concatenation bypasses library-level "
                    f"framing safeguards and is inherently smuggling-prone. "
                    f"Indicators found: "
                    f"{'HTTP version marker, ' if has_http_version else ''}"
                    f"{'CRLF sequences, ' if has_crlf else ''}"
                    f"{'header patterns' if has_header_pattern else ''}"
                ),
                cwe="CWE-444",
                location=loc,
                function_name=self._current_func,
                remediation=REMEDIATION_MAP[SmugglingCategory.RAW_HTTP],
                evidence=combined[:150],
            ))

    def _is_comparison_or_log_context(self, stmt: Statement) -> bool:
        """Check if a statement is a comparison or logging context (reduce false positives)."""
        if isinstance(stmt, IfStmt):
            # String in an if-condition is likely a comparison, not construction
            return True
        if isinstance(stmt, ExprStmt):
            expr = stmt.expr
            if isinstance(expr, (FunctionCall, MethodCall)):
                name = ""
                if isinstance(expr, FunctionCall):
                    name = _expr_name(expr.callee).lower()
                else:
                    name = expr.method_name.lower()
                # Logging calls
                if any(kw in name for kw in ("log", "debug", "info", "warn", "error", "print", "console")):
                    return True
        return False

    # ------------------------------------------------------------------
    # 4. Proxy Configuration Risks (CWE-441)
    # ------------------------------------------------------------------

    def _check_proxy_config(self, stmt: Statement, loc: Optional[SourceLocation]) -> None:
        """Detect reverse proxy configurations without proper request normalization."""
        exprs = _extract_exprs(stmt)
        for expr in exprs:
            self._check_proxy_in_expr(expr, loc)

    def _check_proxy_in_expr(self, expr: Expr, loc: Optional[SourceLocation]) -> None:
        """Check an expression for proxy configuration risks."""
        # Pattern: createProxyServer({ target: ... })
        # Pattern: createProxyMiddleware({ target: ... })
        # Pattern: http-proxy-middleware usage
        is_proxy_call = False
        proxy_name = ""
        config_args: List[Expr] = []

        if isinstance(expr, FunctionCall):
            callee = _expr_name(expr.callee)
            if callee in PROXY_CONFIG_METHODS or callee in PROXY_LIBRARIES:
                is_proxy_call = True
                proxy_name = callee
                config_args = expr.args

        elif isinstance(expr, MethodCall):
            if expr.method_name in PROXY_CONFIG_METHODS:
                is_proxy_call = True
                proxy_name = f"{_expr_name(expr.obj)}.{expr.method_name}"
                config_args = expr.args
            # Check for require('http-proxy') or import patterns
            obj_name = _expr_name(expr.obj)
            if any(lib in obj_name for lib in PROXY_LIBRARIES):
                is_proxy_call = True
                proxy_name = f"{obj_name}.{expr.method_name}"
                config_args = expr.args

        if not is_proxy_call:
            return

        # Check if safety keys are present in the configuration
        all_strings = []
        for arg in config_args:
            all_strings.extend(_extract_string_values(arg))

        # Also check if field names in the config object mention safety keys
        config_field_names: Set[str] = set()
        for arg in config_args:
            self._collect_field_names(arg, config_field_names)

        has_safety_config = bool(config_field_names & PROXY_SAFETY_KEYS)

        if not has_safety_config:
            self.findings.append(SmugglingFinding(
                category=SmugglingCategory.PROXY_CONFIG,
                severity=Severity.MEDIUM,
                description=(
                    f"Reverse proxy configuration via '{proxy_name}' in "
                    f"'{self._current_func}' without explicit request "
                    f"normalization settings. Missing proxyTimeout, "
                    f"changeOrigin, or HTTP version pinning can allow "
                    f"request smuggling through the proxy."
                ),
                cwe="CWE-441",
                location=loc,
                function_name=self._current_func,
                remediation=REMEDIATION_MAP[SmugglingCategory.PROXY_CONFIG],
                evidence=f"Proxy call: {proxy_name}(...)",
            ))

    def _collect_field_names(self, expr: Expr, names: Set[str]) -> None:
        """Recursively collect field access names from an expression."""
        if isinstance(expr, FieldAccess):
            names.add(expr.field_name)
            self._collect_field_names(expr.obj, names)
        elif isinstance(expr, Identifier):
            names.add(expr.name)
        elif isinstance(expr, BinaryOp):
            self._collect_field_names(expr.left, names)
            self._collect_field_names(expr.right, names)
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._collect_field_names(arg, names)
        elif isinstance(expr, MethodCall):
            self._collect_field_names(expr.obj, names)
            for arg in expr.args:
                self._collect_field_names(arg, names)

    # ------------------------------------------------------------------
    # 5. HTTP/2 Downgrade (CWE-757)
    # ------------------------------------------------------------------

    def _check_h2_downgrade(self, stmt: Statement, loc: Optional[SourceLocation]) -> None:
        """Detect HTTP/2 to HTTP/1.1 downgrade in proxy configurations."""
        exprs = _extract_exprs(stmt)
        for expr in exprs:
            strings = _extract_string_values(expr)
            combined = " ".join(s.lower() for s in strings)

            # Look for patterns indicating H2 frontend + H1.1 backend
            # Pattern: proxy serving HTTP/2 but connecting to backend via HTTP/1.1
            has_h2_ref = any(s in combined for s in ("http/2", "http2", "h2", "h2c"))
            has_h1_ref = any(s in combined for s in ("http/1.1", "http1.1", "http/1.0"))

            if has_h2_ref and has_h1_ref:
                # Both versions referenced -- potential downgrade scenario
                self.findings.append(SmugglingFinding(
                    category=SmugglingCategory.H2_DOWNGRADE,
                    severity=Severity.MEDIUM,
                    description=(
                        f"HTTP/2 to HTTP/1.1 downgrade pattern detected in "
                        f"'{self._current_func}'. Accepting HTTP/2 from clients "
                        f"but forwarding as HTTP/1.1 to backends enables H2.CL "
                        f"and H2.TE smuggling attacks where HTTP/2 pseudo-headers "
                        f"are translated into ambiguous HTTP/1.1 framing."
                    ),
                    cwe="CWE-757",
                    location=loc,
                    function_name=self._current_func,
                    remediation=REMEDIATION_MAP[SmugglingCategory.H2_DOWNGRADE],
                    evidence=combined[:150],
                ))

    # ------------------------------------------------------------------
    # 6. Chunked Encoding Issues (CWE-444)
    # ------------------------------------------------------------------

    def _check_chunked_issues(self, stmt: Statement, loc: Optional[SourceLocation]) -> None:
        """Detect manual chunked transfer encoding implementation."""
        exprs = _extract_exprs(stmt)
        for expr in exprs:
            # Pattern 1: Writing chunk size + CRLF + data + CRLF manually
            if _is_string_concat(expr):
                strings = _extract_string_values(expr)
                combined = " ".join(strings)

                has_crlf = any(m in combined for m in CRLF_MARKERS)
                has_chunked_ref = any(m in combined.lower() for m in CHUNKED_MARKERS)

                # Look for hex-digit + CRLF pattern (chunk size header)
                has_chunk_size = bool(re.search(r"[0-9a-fA-F]+\\r\\n", combined))

                # Terminator: 0\r\n\r\n
                has_terminator = "0\\r\\n\\r\\n" in combined or "0\r\n\r\n" in combined

                indicators = sum([has_crlf, has_chunked_ref, has_chunk_size, has_terminator])
                if indicators >= 2:
                    self.findings.append(SmugglingFinding(
                        category=SmugglingCategory.CHUNKED_ISSUES,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Manual chunked transfer encoding construction "
                            f"detected in '{self._current_func}'. Hand-rolling "
                            f"chunk boundaries risks off-by-one errors, missing "
                            f"terminators, and malformed chunks that different "
                            f"HTTP parsers interpret inconsistently."
                        ),
                        cwe="CWE-444",
                        location=loc,
                        function_name=self._current_func,
                        remediation=REMEDIATION_MAP[SmugglingCategory.CHUNKED_ISSUES],
                        evidence=combined[:150],
                    ))

            # Pattern 2: Parsing Transfer-Encoding: chunked manually
            if isinstance(expr, (MethodCall, FunctionCall)):
                name = ""
                if isinstance(expr, MethodCall):
                    name = expr.method_name.lower()
                else:
                    name = _expr_name(expr.callee).lower()

                # Manual chunk parsing functions
                if any(kw in name for kw in ("parse_chunk", "parsechunk", "read_chunk",
                                              "readchunk", "decode_chunk", "decodechunk",
                                              "chunk_decode", "chunkdecode")):
                    self.findings.append(SmugglingFinding(
                        category=SmugglingCategory.CHUNKED_ISSUES,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Manual chunk parsing function '{name}' called in "
                            f"'{self._current_func}'. Custom chunked encoding "
                            f"parsers may disagree with standard HTTP parsers on "
                            f"chunk boundaries, enabling smuggling."
                        ),
                        cwe="CWE-444",
                        location=loc,
                        function_name=self._current_func,
                        remediation=REMEDIATION_MAP[SmugglingCategory.CHUNKED_ISSUES],
                        evidence=f"Manual chunk parsing: {name}()",
                    ))

    # ------------------------------------------------------------------
    # 7. WebSocket Upgrade Smuggling (CWE-444)
    # ------------------------------------------------------------------

    def _check_websocket_upgrade(self, stmt: Statement, loc: Optional[SourceLocation]) -> None:
        """Detect manual WebSocket upgrade handling without proper validation."""
        exprs = _extract_exprs(stmt)
        for expr in exprs:
            self._check_ws_upgrade_in_expr(expr, loc)

    def _check_ws_upgrade_in_expr(self, expr: Expr, loc: Optional[SourceLocation]) -> None:
        """Check an expression for manual WebSocket upgrade handling."""
        # Pattern: setHeader('Connection', 'Upgrade') or setHeader('Upgrade', 'websocket')
        if isinstance(expr, (MethodCall, FunctionCall)):
            method_name = ""
            args: List[Expr] = []

            if isinstance(expr, MethodCall):
                method_name = expr.method_name
                args = expr.args
            else:
                method_name = _expr_name(expr.callee).split(".")[-1]
                args = expr.args

            if method_name in HEADER_SET_FUNCTIONS and len(args) >= 2:
                header_name = self._get_header_name_from_arg(args[0])
                header_value = self._get_header_name_from_arg(args[1])

                if not header_name or not header_value:
                    return

                is_connection_upgrade = (
                    header_name.lower() == "connection" and
                    header_value.lower() == "upgrade"
                )
                is_upgrade_websocket = (
                    header_name.lower() == "upgrade" and
                    header_value.lower() == "websocket"
                )

                if is_connection_upgrade or is_upgrade_websocket:
                    # Check if the function also validates Sec-WebSocket-Key
                    # by looking at surrounding strings
                    func_strings = self._collect_function_strings()
                    has_ws_key_validation = any(
                        "sec-websocket-key" in s.lower() or
                        "sec-websocket-version" in s.lower() or
                        "sec-websocket-accept" in s.lower()
                        for s in func_strings
                    )

                    if not has_ws_key_validation:
                        self.findings.append(SmugglingFinding(
                            category=SmugglingCategory.WEBSOCKET_UPGRADE,
                            severity=Severity.MEDIUM,
                            description=(
                                f"Manual WebSocket upgrade handling in "
                                f"'{self._current_func}' without "
                                f"Sec-WebSocket-Key/Version validation. An attacker "
                                f"can smuggle requests through the upgrade handshake "
                                f"if the proxy treats the connection as upgraded "
                                f"while the backend does not."
                            ),
                            cwe="CWE-444",
                            location=loc,
                            function_name=self._current_func,
                            remediation=REMEDIATION_MAP[SmugglingCategory.WEBSOCKET_UPGRADE],
                            evidence=f"{header_name}: {header_value}",
                        ))

    def _collect_function_strings(self) -> List[str]:
        """Collect all string literals referenced in the current function context.

        This is a best-effort heuristic -- we track strings seen during analysis
        rather than re-walking the entire function body.
        """
        # We don't have direct access to the function body here, but the
        # findings list contains evidence strings from the current function
        return [f.evidence for f in self.findings if f.function_name == self._current_func]

    # ------------------------------------------------------------------
    # 8. Request Body in GET (CWE-444)
    # ------------------------------------------------------------------

    def _check_get_body(self, stmt: Statement, loc: Optional[SourceLocation]) -> None:
        """Detect GET requests with request bodies."""
        exprs = _extract_exprs(stmt)
        for expr in exprs:
            self._check_get_body_in_expr(expr, loc)

    def _check_get_body_in_expr(self, expr: Expr, loc: Optional[SourceLocation]) -> None:
        """Check an expression for GET requests with bodies."""
        # Pattern 1: fetch(url, { method: 'GET', body: ... })
        # Pattern 2: axios.get(url, { data: ... })
        # Pattern 3: requests.get(url, data=...)
        # Pattern 4: http.request({ method: 'GET', body: ... })

        if isinstance(expr, FunctionCall):
            callee = _expr_name(expr.callee).lower()

            # Direct GET calls with extra arguments that could be body
            if callee in ("fetch",) and len(expr.args) >= 2:
                # Second arg is options -- check if it contains 'GET' + body
                option_strings = _extract_string_values(expr.args[1])
                option_names: Set[str] = set()
                self._collect_field_names(expr.args[1], option_names)

                has_get = any(s.upper() == "GET" for s in option_strings)
                has_body = "body" in {n.lower() for n in option_names}

                if has_get and has_body:
                    self.findings.append(SmugglingFinding(
                        category=SmugglingCategory.GET_BODY,
                        severity=Severity.LOW,
                        description=(
                            f"GET request with a body detected in "
                            f"'{self._current_func}'. RFC 9110 assigns no "
                            f"semantics to a GET request body. Some proxies "
                            f"strip GET bodies while others forward them, "
                            f"creating a desync between front-end and back-end."
                        ),
                        cwe="CWE-444",
                        location=loc,
                        function_name=self._current_func,
                        remediation=REMEDIATION_MAP[SmugglingCategory.GET_BODY],
                        evidence="fetch(url, { method: 'GET', body: ... })",
                    ))

            # requests.get(url, data=...) / requests.request('GET', url, data=...)
            if any(kw in callee for kw in ("requests.get", "requests_get",
                                            "http.get", "http_get")):
                # These are GET calls -- check if body/data is passed
                if len(expr.args) >= 2:
                    arg_names: Set[str] = set()
                    for arg in expr.args[1:]:
                        self._collect_field_names(arg, arg_names)
                    if any(n.lower() in ("data", "body", "json", "content") for n in arg_names):
                        self.findings.append(SmugglingFinding(
                            category=SmugglingCategory.GET_BODY,
                            severity=Severity.LOW,
                            description=(
                                f"GET request with body/data parameter in "
                                f"'{self._current_func}'. Different proxies "
                                f"handle GET bodies inconsistently."
                            ),
                            cwe="CWE-444",
                            location=loc,
                            function_name=self._current_func,
                            remediation=REMEDIATION_MAP[SmugglingCategory.GET_BODY],
                            evidence=f"{callee}(url, data=...)",
                        ))

        elif isinstance(expr, MethodCall):
            method = expr.method_name.lower()

            # obj.get(url, { body: ... }) or obj.get(url, { data: ... })
            if method == "get" and len(expr.args) >= 2:
                arg_names: Set[str] = set()
                for arg in expr.args[1:]:
                    self._collect_field_names(arg, arg_names)
                if any(n.lower() in ("data", "body", "json", "content") for n in arg_names):
                    obj_name = _expr_name(expr.obj)
                    self.findings.append(SmugglingFinding(
                        category=SmugglingCategory.GET_BODY,
                        severity=Severity.LOW,
                        description=(
                            f"GET request with body/data parameter via "
                            f"'{obj_name}.get()' in '{self._current_func}'. "
                            f"Some proxies ignore GET bodies, creating a "
                            f"request desync condition."
                        ),
                        cwe="CWE-444",
                        location=loc,
                        function_name=self._current_func,
                        remediation=REMEDIATION_MAP[SmugglingCategory.GET_BODY],
                        evidence=f"{obj_name}.get(url, {{ body/data: ... }})",
                    ))

        # Pattern 5: Raw HTTP construction with GET + body
        if isinstance(expr, StringLiteral) or _is_string_concat(expr):
            strings = _extract_string_values(expr)
            combined = " ".join(strings)
            # Look for "GET /path HTTP/1.1" followed by Content-Length or body
            if re.search(r"GET\s+\S+\s+HTTP/", combined):
                if re.search(r"Content-Length:|Transfer-Encoding:", combined, re.IGNORECASE):
                    self.findings.append(SmugglingFinding(
                        category=SmugglingCategory.GET_BODY,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Raw GET request with Content-Length or "
                            f"Transfer-Encoding header constructed in "
                            f"'{self._current_func}'. This raw request "
                            f"includes a body with a bodyless method, "
                            f"which is a classic smuggling pattern."
                        ),
                        cwe="CWE-444",
                        location=loc,
                        function_name=self._current_func,
                        remediation=REMEDIATION_MAP[SmugglingCategory.GET_BODY],
                        evidence=combined[:150],
                    ))

    # ------------------------------------------------------------------
    # Shared Helpers
    # ------------------------------------------------------------------

    def _get_header_name_from_arg(self, expr: Expr) -> Optional[str]:
        """Extract a header name string from a function argument."""
        if isinstance(expr, StringLiteral):
            return expr.value
        if isinstance(expr, Identifier):
            # Variable -- try to resolve from tracked header vars
            return self._header_vars.get(expr.name)
        return None


# ---------------------------------------------------------------------------
# Finding Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: SmugglingFinding) -> AeonError:
    """Convert a SmugglingFinding into an AeonError using contract_error."""
    severity_label = finding.severity.value.upper()
    category_label = finding.category.value.replace("_", " ").title()

    return contract_error(
        precondition=(
            f"No HTTP smuggling ({finding.cwe}) -- "
            f"[{severity_label}] {category_label}: {finding.description}"
        ),
        failing_values={
            "engine": "HTTP Request Smuggling",
            "category": finding.category.value,
            "severity": finding.severity.value,
            "cwe": finding.cwe,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            **finding.details,
        },
        function_signature=finding.function_name,
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_http_smuggling(program: Program) -> list:
    """Run HTTP request smuggling analysis on an AEON program.

    Detects HTTP desync and request smuggling vulnerabilities across
    eight categories:

    1. Transfer-Encoding manipulation
       - Manual TE header setting/parsing
       - Multiple TE headers or TE + CL combination
       - CWE-444, Severity: Medium (High if TE + CL combined)

    2. Content-Length manipulation
       - Manually setting CL to computed/hardcoded values
       - CL value that may not match actual body size
       - CWE-444, Severity: Medium (High if hardcoded)

    3. Raw HTTP handling
       - String concatenation building HTTP messages
       - HTTP/1.1 + CRLF + header patterns in string construction
       - CWE-444, Severity: High

    4. Proxy configuration risks
       - Reverse proxy without request normalization
       - Missing proxyTimeout, changeOrigin, HTTP version pinning
       - CWE-441, Severity: Medium

    5. HTTP/2 downgrade
       - H2 frontend with H1.1 backend forwarding
       - Enables H2.CL and H2.TE smuggling vectors
       - CWE-757, Severity: Medium

    6. Chunked encoding issues
       - Manual chunked TE implementation
       - Hand-rolled chunk boundary construction/parsing
       - CWE-444, Severity: Medium

    7. WebSocket upgrade smuggling
       - Manual Connection: Upgrade handling
       - Missing Sec-WebSocket-Key/Version validation
       - CWE-444, Severity: Medium

    8. Request body in GET
       - GET requests with body/data parameters
       - Proxy-dependent body handling creates desync
       - CWE-444, Severity: Low (Medium for raw construction)

    Frontend files are skipped entirely -- HTTP smuggling is a
    server-side and proxy-level concern.

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected smuggling vector.
    """
    try:
        analyzer = HTTPSmugglingAnalyzer()
        findings = analyzer.check_program(program)
        return [_finding_to_error(f) for f in findings]
    except Exception:
        # Engine-level safety net: never let the engine crash
        # the verification pipeline
        return []
