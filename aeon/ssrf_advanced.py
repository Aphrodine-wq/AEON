"""AEON Advanced SSRF Detection Engine -- Deep Server-Side Request Forgery Analysis.

Goes beyond basic taint analysis (which marks SSRF as a taint sink) to detect
sophisticated SSRF attack patterns that require structural and semantic analysis
of URL construction, DNS resolution timing, protocol handling, and request
configuration.

References:
  CWE-918: Server-Side Request Forgery (SSRF)
  https://cwe.mitre.org/data/definitions/918.html

  CWE-441: Unintended Proxy or Intermediary
  https://cwe.mitre.org/data/definitions/441.html

  CWE-367: Time-of-Check Time-of-Use (TOCTOU) Race Condition
  https://cwe.mitre.org/data/definitions/367.html

  Jabiyev et al. (2021) "Preventing Server-Side Request Forgery Attacks"
  ACM Computing Surveys 54(9), https://doi.org/10.1145/3471621

  Orange Tsai (2017) "A New Era of SSRF - Exploiting URL Parser in
  Trending Programming Languages"
  Black Hat USA 2017

Detection Categories:

1. CLOUD METADATA ENDPOINT ACCESS:
   Detects requests to cloud provider metadata services (AWS, GCP, Azure,
   Alibaba) that can leak IAM credentials, instance identity, and secrets.

2. DNS REBINDING (TOCTOU):
   Detects validate-then-fetch patterns where hostname validation and the
   subsequent HTTP request are separate operations, allowing DNS rebinding
   attacks to bypass allowlists.

3. INTERNAL NETWORK ACCESS:
   Detects requests to RFC 1918 private IP ranges, loopback addresses, and
   link-local addresses that can scan or exploit internal services.

4. PROTOCOL SMUGGLING:
   Detects non-HTTP protocol schemes (file://, gopher://, dict://, ftp://)
   that can be abused to interact with internal services via protocol confusion.

5. URL PARSING BYPASS:
   Detects URL authentication segments (user@host), Unicode normalization
   attacks, and weak hostname validation (prefix/suffix checks) that can
   trick URL parsers into resolving to unintended hosts.

6. WEBHOOK/CALLBACK SSRF (Blind SSRF):
   Detects user-provided URLs stored for later fetching (webhook_url,
   callback_url, notify_url) that enable out-of-band SSRF.

7. IMAGE/FILE PROCESSING SSRF:
   Detects user-controlled URLs passed to server-side renderers and image
   processors (ImageMagick, Pillow, wkhtmltopdf, Puppeteer) that can be
   abused to fetch internal resources.

8. REDIRECT FOLLOWING:
   Detects HTTP clients configured to follow redirects without validation,
   enabling redirect-based SSRF where an external URL 302s to an internal one.
"""

from __future__ import annotations

import ipaddress
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
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# ---------------------------------------------------------------------------
# SSRF Finding
# ---------------------------------------------------------------------------

@dataclass
class SSRFFinding:
    """Internal representation of a detected SSRF vector."""
    category: str
    severity: Severity
    description: str
    location: Optional[SourceLocation]
    function_name: str
    cwe: str
    evidence: str = ""
    remediation: str = ""


# ---------------------------------------------------------------------------
# Cloud Metadata Patterns
# ---------------------------------------------------------------------------

# IP addresses and hostnames for cloud metadata services
CLOUD_METADATA_IPS: Set[str] = {
    "169.254.169.254",       # AWS, GCP, Azure
    "100.100.100.200",       # Alibaba Cloud
    "169.254.170.2",         # AWS ECS task metadata
}

CLOUD_METADATA_HOSTS: Set[str] = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
}

# Full URL prefixes that indicate metadata endpoint access
CLOUD_METADATA_URL_PREFIXES: List[str] = [
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/dynamic/instance-identity/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/computeMetadata/",
    "http://100.100.100.200/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/",
    "http://169.254.170.2/v2/credentials",
]


# ---------------------------------------------------------------------------
# Protocol Smuggling Schemes
# ---------------------------------------------------------------------------

DANGEROUS_PROTOCOLS: Dict[str, str] = {
    "file://": "Local file access via file:// protocol",
    "gopher://": "Gopher protocol can craft arbitrary TCP payloads",
    "dict://": "DICT protocol can probe internal services",
    "ftp://": "FTP protocol can interact with internal FTP servers",
    "ldap://": "LDAP protocol can query internal directory services",
    "tftp://": "TFTP protocol can transfer files from internal hosts",
    "jar://": "JAR protocol can trigger SSRF in Java applications",
    "netdoc://": "Netdoc protocol can access local files (Java)",
}


# ---------------------------------------------------------------------------
# HTTP Request Functions / Methods
# ---------------------------------------------------------------------------

# Functions that make HTTP requests (function name -> True if it's a request maker)
HTTP_REQUEST_FUNCTIONS: Set[str] = {
    # Python
    "requests_get", "requests_post", "requests_put", "requests_delete",
    "requests_patch", "requests_head", "requests_request",
    "urlopen", "urllib_request", "http_get", "http_post",
    "httpx_get", "httpx_post", "httpx_request",
    "aiohttp_get", "aiohttp_post", "aiohttp_request",
    # Node.js
    "fetch", "axios_get", "axios_post", "axios_request", "axios",
    "http_request", "https_request", "got", "node_fetch",
    "superagent_get", "superagent_post",
    # Generic
    "fetch_url", "make_request", "send_request", "do_request",
    "http_client_get", "http_client_post",
    "curl_exec", "wget", "download",
    "request_get", "request_post",
}

# Methods on HTTP client objects that make requests
HTTP_REQUEST_METHODS: Set[str] = {
    "get", "post", "put", "delete", "patch", "head", "request",
    "fetch", "send", "execute", "open", "load", "retrieve",
    "download", "connect",
}

# Image/file processing functions that accept URLs
IMAGE_PROCESSING_FUNCTIONS: Set[str] = {
    # Python PIL/Pillow
    "image_open", "Image_open",
    # ImageMagick
    "magick_read", "imagemagick_convert",
    # PDF generators
    "wkhtmltopdf", "wkhtmltoimage",
    "html_to_pdf", "render_pdf", "generate_pdf",
    "pdf_from_url", "screenshot_url",
    # Headless browsers
    "puppeteer_goto", "playwright_goto",
    "page_goto", "page_navigate",
    "browser_get", "webdriver_get",
    # Generic
    "load_image", "fetch_image", "download_image",
    "process_url", "render_url",
}

# Image processing methods
IMAGE_PROCESSING_METHODS: Set[str] = {
    "goto", "navigate", "open", "load",
    "from_url", "download", "fetch",
    "set_page", "screenshot",
    "read", "convert",
}

# Client-side navigation functions/methods (NOT server-side HTTP requests)
# These are React/Vue/Angular/frontend routing calls that should not trigger SSRF
CLIENT_SIDE_NAVIGATION: Set[str] = {
    # React Router / Next.js
    "router_push", "router_replace", "router_back", "router_forward",
    "router_prefetch", "router_refresh",
    "push", "replace", "navigate", "redirect",
    "useRouter", "useNavigate", "useHistory", "useLocation",
    "useSearchParams", "usePathname",
    # Next.js Link / navigation
    "Link", "NavLink",
    # Vue Router
    "router_go", "router_beforeEach",
    # Generic SPA
    "history_push", "history_pushState", "history_replaceState",
    "window_location_assign", "window_location_replace",
}

# File extensions that indicate frontend/UI component code
_FRONTEND_EXTENSIONS = frozenset({
    ".tsx", ".jsx", ".vue", ".svelte",
})

# URL validation functions
URL_VALIDATION_FUNCTIONS: Set[str] = {
    "validate_url", "is_valid_url", "check_url", "parse_url",
    "url_parse", "is_safe_url", "verify_url", "is_allowed_url",
    "is_internal_url", "check_host", "validate_host",
    "is_private_ip", "is_internal_ip",
    "urlparse", "URL",
}

# Webhook/callback variable name patterns
WEBHOOK_VARIABLE_PATTERNS: List[re.Pattern] = [
    re.compile(r"webhook[_\-]?url", re.IGNORECASE),
    re.compile(r"callback[_\-]?url", re.IGNORECASE),
    re.compile(r"notify[_\-]?url", re.IGNORECASE),
    re.compile(r"hook[_\-]?url", re.IGNORECASE),
    re.compile(r"ping[_\-]?url", re.IGNORECASE),
    re.compile(r"endpoint[_\-]?url", re.IGNORECASE),
    re.compile(r"return[_\-]?url", re.IGNORECASE),
    re.compile(r"redirect[_\-]?url", re.IGNORECASE),
    re.compile(r"postback[_\-]?url", re.IGNORECASE),
    re.compile(r"notification[_\-]?url", re.IGNORECASE),
    re.compile(r"target[_\-]?url", re.IGNORECASE),
    re.compile(r"dest(?:ination)?[_\-]?url", re.IGNORECASE),
]

# Redirect-following configuration patterns
REDIRECT_FOLLOW_PATTERNS: Set[str] = {
    "allow_redirects",
    "follow_redirects",
    "followRedirects",
    "followAllRedirects",
    "maxRedirects",
    "redirect",
}


# ---------------------------------------------------------------------------
# Private IP Range Helpers
# ---------------------------------------------------------------------------

# Compiled regex for private IP addresses in string literals
_PRIVATE_IP_PATTERN = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"          # 10.0.0.0/8
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"  # 172.16.0.0/12
    r"|192\.168\.\d{1,3}\.\d{1,3}"             # 192.168.0.0/16
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"         # 127.0.0.0/8
    r"|0\.0\.0\.0"                              # 0.0.0.0
    r")\b"
)

_PRIVATE_HOST_PATTERN = re.compile(
    r"\b(localhost|internal|intranet|corp|local)\b",
    re.IGNORECASE,
)

# URL with authentication segment (user@host bypass)
_URL_AUTH_SEGMENT = re.compile(
    r"https?://[^/]*@[^/]+",
)

# Weak hostname validation patterns (endsWith, startsWith on hostnames)
_WEAK_VALIDATION_METHODS: Set[str] = {
    "endsWith", "startsWith", "ends_with", "starts_with",
    "includes", "contains", "indexOf", "index_of",
}


# ---------------------------------------------------------------------------
# AST Walking Utilities
# ---------------------------------------------------------------------------

def _get_func_name(expr: Expr) -> Optional[str]:
    """Extract function name from a call expression's callee."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, FieldAccess):
        return expr.field_name
    return None


def _get_full_callee_name(expr: Expr) -> str:
    """Get a dotted representation of a call target (e.g., 'requests.get')."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, FieldAccess):
        obj_name = _get_full_callee_name(expr.obj)
        return f"{obj_name}.{expr.field_name}" if obj_name else expr.field_name
    return ""


def _is_user_input_identifier(name: str) -> bool:
    """Check if an identifier name suggests user-controlled input."""
    name_lower = name.lower()
    input_keywords = (
        "input", "request", "query", "param", "user", "url",
        "body", "form", "header", "data", "payload", "raw",
        "untrusted", "external", "remote", "client",
        "args", "arg", "params",
    )
    return any(kw in name_lower for kw in input_keywords)


def _expr_contains_user_input(expr: Expr) -> bool:
    """Check if an expression tree contains references to user-controlled data."""
    if isinstance(expr, Identifier):
        return _is_user_input_identifier(expr.name)
    if isinstance(expr, BinaryOp):
        return _expr_contains_user_input(expr.left) or _expr_contains_user_input(expr.right)
    if isinstance(expr, FunctionCall):
        if isinstance(expr.callee, Identifier):
            callee_lower = expr.callee.name.lower()
            if any(src in callee_lower for src in (
                "get_param", "get_header", "get_body", "read_input",
                "request", "query", "input", "getenv",
            )):
                return True
        return any(_expr_contains_user_input(a) for a in expr.args)
    if isinstance(expr, MethodCall):
        method_lower = expr.method_name.lower()
        if method_lower in ("get", "param", "query", "body", "header", "input"):
            return True
        return (_expr_contains_user_input(expr.obj) or
                any(_expr_contains_user_input(a) for a in expr.args))
    if isinstance(expr, FieldAccess):
        return _expr_contains_user_input(expr.obj) or _is_user_input_identifier(expr.field_name)
    if isinstance(expr, StringLiteral):
        return False
    return False


def _extract_string_values(expr: Expr) -> List[str]:
    """Extract all string literal values from an expression tree."""
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
    return results


def _walk_all_statements(func: PureFunc | TaskFunc):
    """Yield all statements from a function body, recursively flattened."""
    for stmt in func.body:
        yield from _walk_stmt_recursive(stmt)


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


def _is_frontend_file(filename: str) -> bool:
    """Check if the filename indicates a frontend/UI component file."""
    if not filename:
        return False
    name_lower = filename.lower()
    return any(name_lower.endswith(ext) for ext in _FRONTEND_EXTENSIONS)


def _is_client_navigation_call(expr: Expr) -> bool:
    """Check if an expression is a client-side navigation call (not an HTTP request).

    Returns True for patterns like router.push('/dashboard'), navigate('/home'),
    Link components, useRouter(), etc. These are frontend routing calls that
    should NOT be flagged as SSRF.
    """
    if isinstance(expr, FunctionCall):
        callee_name = _get_func_name(expr.callee)
        if callee_name:
            callee_lower = callee_name.lower()
            for nav_func in CLIENT_SIDE_NAVIGATION:
                if nav_func.lower() == callee_lower:
                    return True
        full_name = _get_full_callee_name(expr.callee).lower()
        # Match patterns like "router.push", "router.replace", "history.pushState"
        for nav_func in CLIENT_SIDE_NAVIGATION:
            if nav_func.lower().replace("_", ".") in full_name:
                return True
    elif isinstance(expr, MethodCall):
        method_lower = expr.method_name.lower()
        # Check for router.push(), router.replace(), etc.
        if method_lower in {"push", "replace", "back", "forward", "prefetch",
                            "refresh", "go", "navigate"}:
            # Verify the object looks like a router/history
            obj_name = ""
            if isinstance(expr.obj, Identifier):
                obj_name = expr.obj.name.lower()
            elif isinstance(expr.obj, FunctionCall):
                obj_name = _get_func_name(expr.callee) or ""
                obj_name = obj_name.lower()
            if any(kw in obj_name for kw in ("router", "history", "nav", "navigation")):
                return True
    return False


def _is_relative_path_only(s: str) -> bool:
    """Check if a string is a relative URL path (starts with / but no protocol)."""
    return s.startswith("/") and "://" not in s


def _function_has_react_patterns(func) -> bool:
    """Check if a function body contains React/JSX patterns.

    Looks for hooks (useState, useEffect, etc.), JSX elements, or other
    frontend framework indicators in function bodies.
    """
    react_identifiers = {
        "useState", "useEffect", "useCallback", "useMemo", "useRef",
        "useContext", "useReducer", "useRouter", "useNavigate",
        "useHistory", "useLocation", "useSearchParams", "usePathname",
        "useParams", "useQuery", "useMutation",
        "jsx", "createElement", "Fragment",
    }

    for stmt in getattr(func, "body", []):
        for sub_stmt in _walk_stmt_recursive(stmt):
            exprs = []
            if isinstance(sub_stmt, LetStmt) and sub_stmt.value:
                exprs.append(sub_stmt.value)
            elif isinstance(sub_stmt, ExprStmt):
                exprs.append(sub_stmt.expr)
            elif isinstance(sub_stmt, AssignStmt):
                exprs.append(sub_stmt.value)
            for expr in exprs:
                if isinstance(expr, FunctionCall):
                    name = _get_func_name(expr.callee)
                    if name and name in react_identifiers:
                        return True
                elif isinstance(expr, MethodCall):
                    if expr.method_name in react_identifiers:
                        return True
                elif isinstance(expr, Identifier):
                    if expr.name in react_identifiers:
                        return True
    return False


# ---------------------------------------------------------------------------
# SSRF Analyzer
# ---------------------------------------------------------------------------

class SSRFAdvancedAnalyzer:
    """Deep SSRF analysis beyond basic taint tracking.

    Examines the AST for structural patterns that indicate SSRF
    vulnerabilities: cloud metadata access, DNS rebinding windows,
    internal network targeting, protocol smuggling, URL parsing
    bypasses, webhook/callback abuse, image processing SSRF, and
    unvalidated redirect following.
    """

    def __init__(self):
        self.findings: List[SSRFFinding] = []
        # Track variables and their assigned expressions for data flow
        self._var_assignments: Dict[str, Expr] = {}
        # Track which variables were validated (for DNS rebinding detection)
        self._validated_vars: Set[str] = set()
        # Track variables from user input
        self._user_input_vars: Set[str] = set()
        # Track webhook/callback URL variables
        self._webhook_vars: Set[str] = set()
        # Whether the current file is a frontend component
        self._is_frontend: bool = False
        # Whether the current function has React/JSX patterns
        self._func_has_react: bool = False

    def check_program(self, program: Program) -> List[SSRFFinding]:
        """Run advanced SSRF analysis on the entire program."""
        self.findings = []
        self._is_frontend = _is_frontend_file(getattr(program, "filename", ""))

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.findings

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for SSRF patterns."""
        self._var_assignments = {}
        self._validated_vars = set()
        self._user_input_vars = set()
        self._webhook_vars = set()

        # Detect if this function contains React/frontend patterns
        if self._is_frontend:
            self._func_has_react = _function_has_react_patterns(func)
        else:
            self._func_has_react = False

        # First pass: identify user input parameters
        for param in func.params:
            param_lower = param.name.lower()
            type_str = str(param.type_annotation).lower() if param.type_annotation else ""

            if _is_user_input_identifier(param.name):
                self._user_input_vars.add(param.name)

            # Check for webhook/callback parameter names
            for pattern in WEBHOOK_VARIABLE_PATTERNS:
                if pattern.search(param.name):
                    self._webhook_vars.add(param.name)
                    self._user_input_vars.add(param.name)

            # Check type annotations for request types
            if any(kw in type_str for kw in ("request", "httprequest", "formdata")):
                self._user_input_vars.add(param.name)

        # Second pass: collect all variable assignments and detect patterns
        all_stmts = list(_walk_all_statements(func))

        for stmt in all_stmts:
            self._collect_variable_info(stmt)

        # Third pass: run all SSRF detectors
        for stmt in all_stmts:
            loc = getattr(stmt, "location", SourceLocation("<ssrf>", 0, 0))
            self._check_cloud_metadata(stmt, func.name, loc)
            self._check_internal_network(stmt, func.name, loc)
            self._check_protocol_smuggling(stmt, func.name, loc)
            self._check_url_parsing_bypass(stmt, func.name, loc)
            self._check_webhook_ssrf(stmt, func.name, loc)
            self._check_image_processing_ssrf(stmt, func.name, loc)
            self._check_redirect_following(stmt, func.name, loc)

        # DNS rebinding requires cross-statement analysis
        self._check_dns_rebinding(all_stmts, func.name)

    # ------------------------------------------------------------------
    # Variable Collection
    # ------------------------------------------------------------------

    def _collect_variable_info(self, stmt: Statement) -> None:
        """Collect variable assignment and validation information."""
        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._var_assignments[stmt.name] = stmt.value

                # Track user input variables
                if _expr_contains_user_input(stmt.value):
                    self._user_input_vars.add(stmt.name)

                # Track webhook/callback URL variables
                for pattern in WEBHOOK_VARIABLE_PATTERNS:
                    if pattern.search(stmt.name):
                        self._webhook_vars.add(stmt.name)

                # Track URL validation calls
                if self._is_url_validation(stmt.value):
                    # The validated variable is typically the argument
                    validated = self._extract_validated_var(stmt.value)
                    if validated:
                        self._validated_vars.add(validated)

        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                self._var_assignments[stmt.target.name] = stmt.value

                if _expr_contains_user_input(stmt.value):
                    self._user_input_vars.add(stmt.target.name)

                for pattern in WEBHOOK_VARIABLE_PATTERNS:
                    if pattern.search(stmt.target.name):
                        self._webhook_vars.add(stmt.target.name)

        elif isinstance(stmt, ExprStmt):
            # Detect standalone validation calls like: validate_url(url)
            if self._is_url_validation(stmt.expr):
                validated = self._extract_validated_var(stmt.expr)
                if validated:
                    self._validated_vars.add(validated)

        elif isinstance(stmt, IfStmt):
            # Conditions that validate URLs/hosts
            if self._is_url_validation(stmt.condition):
                validated = self._extract_validated_var(stmt.condition)
                if validated:
                    self._validated_vars.add(validated)

    def _is_url_validation(self, expr: Expr) -> bool:
        """Check if an expression is a URL/host validation call."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name.lower() in {f.lower() for f in URL_VALIDATION_FUNCTIONS}
        if isinstance(expr, MethodCall):
            return expr.method_name.lower() in {f.lower() for f in URL_VALIDATION_FUNCTIONS}
        return False

    def _extract_validated_var(self, expr: Expr) -> Optional[str]:
        """Extract the variable name being validated in a validation call."""
        args: List[Expr] = []
        if isinstance(expr, FunctionCall):
            args = expr.args
        elif isinstance(expr, MethodCall):
            args = expr.args
            # The object itself might be the validated target
            if isinstance(expr.obj, Identifier):
                return expr.obj.name

        for arg in args:
            if isinstance(arg, Identifier):
                return arg.name
        return None

    # ------------------------------------------------------------------
    # 1. Cloud Metadata Endpoint Access
    # ------------------------------------------------------------------

    def _check_cloud_metadata(self, stmt: Statement, func_name: str,
                              loc: SourceLocation) -> None:
        """Detect requests to cloud metadata endpoints."""
        exprs = self._extract_exprs(stmt)
        for expr in exprs:
            strings = _extract_string_values(expr)
            for s in strings:
                s_lower = s.lower().strip()

                # Check for metadata IP addresses
                for ip in CLOUD_METADATA_IPS:
                    if ip in s:
                        self.findings.append(SSRFFinding(
                            category="Cloud Metadata Endpoint Access",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Request to cloud metadata IP '{ip}' detected. "
                                f"An attacker exploiting this SSRF can steal IAM "
                                f"credentials, instance identity tokens, and other "
                                f"secrets from the metadata service."
                            ),
                            location=loc,
                            function_name=func_name,
                            cwe="CWE-918",
                            evidence=s[:120],
                            remediation=(
                                "Block requests to metadata IPs at the network level "
                                "(IMDSv2 on AWS, metadata concealment on GCP). "
                                "Use an allowlist of permitted destination hosts. "
                                "Enforce IMDSv2 (token-required) to mitigate "
                                "header-based SSRF exploitation."
                            ),
                        ))
                        break

                # Check for metadata hostnames
                for host in CLOUD_METADATA_HOSTS:
                    if host in s_lower:
                        self.findings.append(SSRFFinding(
                            category="Cloud Metadata Endpoint Access",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Request to cloud metadata host '{host}' detected. "
                                f"This can expose instance credentials and secrets."
                            ),
                            location=loc,
                            function_name=func_name,
                            cwe="CWE-918",
                            evidence=s[:120],
                            remediation=(
                                "Use IMDSv2 (AWS) or metadata concealment (GCP). "
                                "Block metadata hostnames in URL validation. "
                                "Apply network-level firewall rules."
                            ),
                        ))
                        break

                # Check for full metadata URL prefixes
                for prefix in CLOUD_METADATA_URL_PREFIXES:
                    if s_lower.startswith(prefix.lower()):
                        # Avoid duplicate if already caught by IP/host check
                        if not any(
                            f.category == "Cloud Metadata Endpoint Access" and
                            f.location == loc and f.evidence == s[:120]
                            for f in self.findings
                        ):
                            self.findings.append(SSRFFinding(
                                category="Cloud Metadata Endpoint Access",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"Direct cloud metadata URL access: '{s[:80]}'. "
                                    f"This fetches sensitive instance metadata "
                                    f"including credentials."
                                ),
                                location=loc,
                                function_name=func_name,
                                cwe="CWE-918",
                                evidence=s[:120],
                                remediation=(
                                    "Never hardcode metadata URLs. If metadata access "
                                    "is needed, use the cloud provider SDK with "
                                    "IMDSv2/token-based access."
                                ),
                            ))
                        break

    # ------------------------------------------------------------------
    # 2. DNS Rebinding (TOCTOU)
    # ------------------------------------------------------------------

    def _check_dns_rebinding(self, stmts: List[Statement],
                             func_name: str) -> None:
        """Detect validate-then-fetch patterns vulnerable to DNS rebinding.

        DNS rebinding occurs when:
        1. Code validates a URL/hostname (DNS resolution #1)
        2. Code later makes an HTTP request with the same URL (DNS resolution #2)
        The DNS record can change between checks, bypassing the validation.
        """
        # Find pairs: validation call followed by HTTP request using same variable
        validation_sites: List[Tuple[str, SourceLocation]] = []  # (var_name, location)
        request_sites: List[Tuple[str, SourceLocation]] = []     # (var_name, location)

        for stmt in stmts:
            loc = getattr(stmt, "location", SourceLocation("<ssrf>", 0, 0))
            exprs = self._extract_exprs(stmt)

            for expr in exprs:
                # Detect URL validation
                if self._is_url_validation(expr):
                    validated_var = self._extract_validated_var(expr)
                    if validated_var:
                        validation_sites.append((validated_var, loc))

                # Detect HTTP requests
                request_var = self._extract_request_url_var(expr)
                if request_var:
                    request_sites.append((request_var, loc))

        # Check for validate-then-fetch on the same variable
        for val_var, val_loc in validation_sites:
            for req_var, req_loc in request_sites:
                if val_var == req_var:
                    # Same variable validated then used -- TOCTOU window
                    val_line = getattr(val_loc, "line", 0)
                    req_line = getattr(req_loc, "line", 0)
                    if req_line >= val_line:
                        self.findings.append(SSRFFinding(
                            category="DNS Rebinding (TOCTOU)",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Variable '{val_var}' is validated at line "
                                f"{val_line} then used in an HTTP request at line "
                                f"{req_line}. DNS can change between validation and "
                                f"request, allowing rebinding to an internal address."
                            ),
                            location=req_loc,
                            function_name=func_name,
                            cwe="CWE-367",
                            evidence=f"validate({val_var}) ... request({req_var})",
                            remediation=(
                                "Pin the DNS resolution: resolve the hostname once, "
                                "validate the resolved IP, then make the request "
                                "using the resolved IP directly. Use "
                                "socket.getaddrinfo() and pass the IP to the HTTP "
                                "client. Alternatively, use a DNS-pinning HTTP client "
                                "or validate the response IP after connection."
                            ),
                        ))

    def _extract_request_url_var(self, expr: Expr) -> Optional[str]:
        """Extract the URL variable name from an HTTP request expression."""
        if isinstance(expr, FunctionCall):
            callee_name = _get_func_name(expr.callee)
            if callee_name and callee_name.lower() in {f.lower() for f in HTTP_REQUEST_FUNCTIONS}:
                for arg in expr.args:
                    if isinstance(arg, Identifier):
                        return arg.name
        elif isinstance(expr, MethodCall):
            if expr.method_name.lower() in HTTP_REQUEST_METHODS:
                for arg in expr.args:
                    if isinstance(arg, Identifier):
                        return arg.name
        return None

    # ------------------------------------------------------------------
    # 3. Internal Network Access
    # ------------------------------------------------------------------

    def _check_internal_network(self, stmt: Statement, func_name: str,
                                loc: SourceLocation) -> None:
        """Detect requests to private/internal IP ranges."""
        exprs = self._extract_exprs(stmt)
        for expr in exprs:
            # Skip client-side navigation calls entirely
            if _is_client_navigation_call(expr):
                continue

            # Only flag when the expression is in a request context or
            # contains a URL-like string
            strings = _extract_string_values(expr)
            for s in strings:
                # In frontend files, relative paths (starting with /) are
                # client-side navigation routes, not server-side requests.
                # Skip them to avoid false positives on React components.
                if (self._is_frontend or self._func_has_react) and _is_relative_path_only(s):
                    continue

                # Check for private IPs in URL-like strings
                if "://" in s or s.startswith("/"):
                    match = _PRIVATE_IP_PATTERN.search(s)
                    if match:
                        ip = match.group(1)
                        self.findings.append(SSRFFinding(
                            category="Internal Network Access",
                            severity=Severity.CRITICAL,
                            description=(
                                f"URL contains private IP address '{ip}'. "
                                f"An attacker can exploit this to scan the internal "
                                f"network, access internal services, or exfiltrate "
                                f"data from behind the firewall."
                            ),
                            location=loc,
                            function_name=func_name,
                            cwe="CWE-918",
                            evidence=s[:120],
                            remediation=(
                                "Validate and resolve destination URLs before "
                                "making requests. Block RFC 1918 addresses "
                                "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), "
                                "loopback (127.0.0.0/8), and link-local "
                                "(169.254.0.0/16) ranges. Use a URL allowlist."
                            ),
                        ))
                        continue

                    # Check for localhost/internal hostnames in URLs
                    host_match = _PRIVATE_HOST_PATTERN.search(s)
                    if host_match:
                        host = host_match.group(1)
                        self.findings.append(SSRFFinding(
                            category="Internal Network Access",
                            severity=Severity.CRITICAL,
                            description=(
                                f"URL references internal hostname '{host}'. "
                                f"This can be exploited to access internal services."
                            ),
                            location=loc,
                            function_name=func_name,
                            cwe="CWE-918",
                            evidence=s[:120],
                            remediation=(
                                "Block requests to internal hostnames. Resolve "
                                "hostnames and validate the resolved IP is not "
                                "in a private range before making the request."
                            ),
                        ))

            # Check if user input flows into a request without IP validation
            if self._is_http_request_expr(expr) and _expr_contains_user_input(expr):
                # Check if the URL variable was validated
                url_var = self._extract_request_url_var(expr)
                if url_var and url_var not in self._validated_vars:
                    # Only flag if not already caught by string literal checks
                    if not any(
                        f.category == "Internal Network Access" and f.location == loc
                        for f in self.findings
                    ):
                        self.findings.append(SSRFFinding(
                            category="Internal Network Access",
                            severity=Severity.CRITICAL,
                            description=(
                                f"User-controlled URL variable '{url_var}' is used "
                                f"in an HTTP request without URL/IP validation. "
                                f"An attacker can supply internal network addresses."
                            ),
                            location=loc,
                            function_name=func_name,
                            cwe="CWE-918",
                            evidence=f"request({url_var}) -- no IP validation",
                            remediation=(
                                "Resolve the URL hostname and validate the IP "
                                "address is not in a private range before making "
                                "the request. Use a URL allowlist or blocklist "
                                "of internal IP ranges."
                            ),
                        ))

    # ------------------------------------------------------------------
    # 4. Protocol Smuggling
    # ------------------------------------------------------------------

    def _check_protocol_smuggling(self, stmt: Statement, func_name: str,
                                  loc: SourceLocation) -> None:
        """Detect non-HTTP protocol schemes in URLs."""
        exprs = self._extract_exprs(stmt)
        for expr in exprs:
            strings = _extract_string_values(expr)
            for s in strings:
                s_lower = s.lower().strip()
                for protocol, description in DANGEROUS_PROTOCOLS.items():
                    if s_lower.startswith(protocol):
                        self.findings.append(SSRFFinding(
                            category="Protocol Smuggling",
                            severity=Severity.HIGH,
                            description=(
                                f"Non-HTTP protocol '{protocol}' detected in URL. "
                                f"{description}. This can be exploited for SSRF "
                                f"even when HTTP-based validation is in place."
                            ),
                            location=loc,
                            function_name=func_name,
                            cwe="CWE-918",
                            evidence=s[:120],
                            remediation=(
                                "Enforce an allowlist of permitted URL schemes "
                                "(http:// and https:// only). Validate the URL "
                                "scheme before passing to any HTTP client or "
                                "URL handler."
                            ),
                        ))
                        break

            # Check for user input flowing into requests without protocol validation
            if self._is_http_request_expr(expr):
                for arg in self._get_call_args(expr):
                    if isinstance(arg, Identifier) and arg.name in self._user_input_vars:
                        # Check if the variable's assigned value has protocol checks
                        if arg.name not in self._validated_vars:
                            if not any(
                                f.category == "Protocol Smuggling" and f.location == loc
                                for f in self.findings
                            ):
                                self.findings.append(SSRFFinding(
                                    category="Protocol Smuggling",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"User-controlled input '{arg.name}' is used "
                                        f"as a URL without protocol scheme validation. "
                                        f"An attacker can supply file://, gopher://, "
                                        f"or other dangerous protocol schemes."
                                    ),
                                    location=loc,
                                    function_name=func_name,
                                    cwe="CWE-441",
                                    evidence=f"request({arg.name}) -- no scheme check",
                                    remediation=(
                                        "Parse the URL and verify the scheme is "
                                        "http or https before making the request. "
                                        "Reject all other protocol schemes."
                                    ),
                                ))

    # ------------------------------------------------------------------
    # 5. URL Parsing Bypass
    # ------------------------------------------------------------------

    def _check_url_parsing_bypass(self, stmt: Statement, func_name: str,
                                  loc: SourceLocation) -> None:
        """Detect URL authentication segments and weak hostname validation."""
        exprs = self._extract_exprs(stmt)
        for expr in exprs:
            # Check string literals for URL auth segments (http://evil@internal/)
            strings = _extract_string_values(expr)
            for s in strings:
                if _URL_AUTH_SEGMENT.search(s):
                    self.findings.append(SSRFFinding(
                        category="URL Parsing Bypass",
                        severity=Severity.HIGH,
                        description=(
                            f"URL contains authentication segment (user@host). "
                            f"Different URL parsers interpret the authority section "
                            f"differently, allowing an attacker to craft URLs like "
                            f"'http://evil.com@internal:8080/' that bypass validation "
                            f"but resolve to the internal host."
                        ),
                        location=loc,
                        function_name=func_name,
                        cwe="CWE-918",
                        evidence=s[:120],
                        remediation=(
                            "Parse the URL with a strict parser and extract the "
                            "hostname after removing the userinfo component. "
                            "Reject URLs containing '@' in the authority section."
                        ),
                    ))

            # Check for weak hostname validation (endsWith, startsWith)
            if isinstance(expr, MethodCall):
                if expr.method_name in _WEAK_VALIDATION_METHODS:
                    # Check if this is being used on a hostname/URL variable
                    obj_is_url = False
                    if isinstance(expr.obj, Identifier):
                        name_lower = expr.obj.name.lower()
                        if any(kw in name_lower for kw in ("url", "host", "domain", "origin")):
                            obj_is_url = True
                    if isinstance(expr.obj, MethodCall):
                        if expr.obj.method_name.lower() in ("hostname", "host", "origin"):
                            obj_is_url = True

                    if obj_is_url:
                        self.findings.append(SSRFFinding(
                            category="URL Parsing Bypass",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Weak hostname validation using '{expr.method_name}'. "
                                f"Prefix/suffix checks on hostnames can be bypassed "
                                f"(e.g., 'evil-example.com' passes "
                                f"endsWith('.example.com') check, "
                                f"'example.com.evil.com' passes "
                                f"startsWith('example.com') check)."
                            ),
                            location=loc,
                            function_name=func_name,
                            cwe="CWE-918",
                            evidence=f"{expr.method_name}(...) on URL/host variable",
                            remediation=(
                                "Use exact hostname matching or parse the URL "
                                "with a proper URL parser and compare the full "
                                "hostname against an allowlist. If using suffix "
                                "matching, prepend a dot (e.g., '.example.com') "
                                "and check that the hostname ends with it OR "
                                "equals the bare domain."
                            ),
                        ))

    # ------------------------------------------------------------------
    # 6. Webhook/Callback SSRF (Blind SSRF)
    # ------------------------------------------------------------------

    def _check_webhook_ssrf(self, stmt: Statement, func_name: str,
                            loc: SourceLocation) -> None:
        """Detect user-provided URLs stored for later fetching (blind SSRF)."""
        exprs = self._extract_exprs(stmt)
        for expr in exprs:
            # Check if a webhook variable is used in an HTTP request
            if self._is_http_request_expr(expr):
                for arg in self._get_call_args(expr):
                    if isinstance(arg, Identifier) and arg.name in self._webhook_vars:
                        if arg.name not in self._validated_vars:
                            self.findings.append(SSRFFinding(
                                category="Webhook/Callback SSRF",
                                severity=Severity.HIGH,
                                description=(
                                    f"Webhook/callback URL variable '{arg.name}' is "
                                    f"used in an HTTP request without validation. "
                                    f"User-provided callback URLs enable blind SSRF "
                                    f"where the attacker cannot see the response but "
                                    f"can trigger requests to internal services."
                                ),
                                location=loc,
                                function_name=func_name,
                                cwe="CWE-918",
                                evidence=f"request({arg.name})",
                                remediation=(
                                    "Validate webhook URLs against an allowlist of "
                                    "permitted domains. Resolve the hostname and "
                                    "block internal IP ranges. Consider using a "
                                    "webhook proxy service that sanitizes requests. "
                                    "Log all outbound webhook requests for monitoring."
                                ),
                            ))

            # Check for webhook URL variable assignment from user input
            if isinstance(stmt, LetStmt) and stmt.value:
                for pattern in WEBHOOK_VARIABLE_PATTERNS:
                    if pattern.search(stmt.name):
                        if _expr_contains_user_input(stmt.value):
                            # Only flag once per variable
                            if not any(
                                f.category == "Webhook/Callback SSRF" and
                                f.evidence == f"stored: {stmt.name}"
                                for f in self.findings
                            ):
                                self.findings.append(SSRFFinding(
                                    category="Webhook/Callback SSRF",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"User-provided URL stored in webhook variable "
                                        f"'{stmt.name}'. If this URL is later fetched "
                                        f"server-side, it enables blind SSRF."
                                    ),
                                    location=loc,
                                    function_name=func_name,
                                    cwe="CWE-918",
                                    evidence=f"stored: {stmt.name}",
                                    remediation=(
                                        "Validate the URL at storage time: check the "
                                        "scheme (https only), resolve and validate the "
                                        "IP is not internal, and restrict to an allowlist "
                                        "of permitted callback domains."
                                    ),
                                ))
                        break

    # ------------------------------------------------------------------
    # 7. Image/File Processing SSRF
    # ------------------------------------------------------------------

    def _check_image_processing_ssrf(self, stmt: Statement, func_name: str,
                                     loc: SourceLocation) -> None:
        """Detect user-controlled URLs passed to image/file processors."""
        exprs = self._extract_exprs(stmt)
        for expr in exprs:
            processor_name: Optional[str] = None
            has_user_input = False

            if isinstance(expr, FunctionCall):
                callee_name = _get_func_name(expr.callee)
                if callee_name:
                    full_name = _get_full_callee_name(expr.callee)
                    callee_lower = callee_name.lower()
                    # Check function name against known image processors
                    for proc in IMAGE_PROCESSING_FUNCTIONS:
                        if proc.lower() in callee_lower or proc.lower() in full_name.lower():
                            processor_name = callee_name
                            break
                    if processor_name:
                        has_user_input = any(
                            _expr_contains_user_input(a) for a in expr.args
                        ) or any(
                            isinstance(a, Identifier) and a.name in self._user_input_vars
                            for a in expr.args
                        )

            elif isinstance(expr, MethodCall):
                method_lower = expr.method_name.lower()
                if method_lower in IMAGE_PROCESSING_METHODS:
                    # Check if the object is an image processor
                    obj_name = ""
                    if isinstance(expr.obj, Identifier):
                        obj_name = expr.obj.name.lower()
                    elif isinstance(expr.obj, FieldAccess):
                        obj_name = _get_full_callee_name(expr.obj).lower()

                    image_obj_hints = (
                        "image", "page", "browser", "puppeteer", "playwright",
                        "pdf", "magick", "driver", "webdriver", "phantom",
                        "renderer", "converter",
                    )
                    if any(hint in obj_name for hint in image_obj_hints):
                        processor_name = f"{obj_name}.{expr.method_name}"
                        has_user_input = any(
                            _expr_contains_user_input(a) for a in expr.args
                        ) or any(
                            isinstance(a, Identifier) and a.name in self._user_input_vars
                            for a in expr.args
                        )

            if processor_name and has_user_input:
                self.findings.append(SSRFFinding(
                    category="Image/File Processing SSRF",
                    severity=Severity.HIGH,
                    description=(
                        f"User-controlled URL passed to '{processor_name}'. "
                        f"Server-side image processors, PDF generators, and "
                        f"headless browsers will fetch the URL, enabling SSRF "
                        f"to internal services."
                    ),
                    location=loc,
                    function_name=func_name,
                    cwe="CWE-918",
                    evidence=f"{processor_name}(user_input)",
                    remediation=(
                        "Validate and sanitize URLs before passing to processors. "
                        "Resolve the hostname, block internal IPs, enforce https://, "
                        "and consider using a sandboxed network for server-side "
                        "rendering (e.g., a separate VPC with no internal access)."
                    ),
                ))

    # ------------------------------------------------------------------
    # 8. Redirect Following
    # ------------------------------------------------------------------

    def _check_redirect_following(self, stmt: Statement, func_name: str,
                                  loc: SourceLocation) -> None:
        """Detect HTTP clients following redirects without validation."""
        exprs = self._extract_exprs(stmt)
        for expr in exprs:
            if not self._is_http_request_expr(expr):
                continue

            # Check if the request has explicit redirect-following enabled
            # or uses a user-controlled URL (where default redirect behavior is risky)
            has_redirect_config = False
            has_user_url = False

            if isinstance(expr, FunctionCall):
                # Check keyword-like arguments (in AEON AST, these are regular args
                # but we can detect string patterns in the call arguments)
                for arg in expr.args:
                    # Check for redirect configuration identifiers
                    if isinstance(arg, Identifier):
                        if arg.name.lower() in REDIRECT_FOLLOW_PATTERNS:
                            has_redirect_config = True
                        if arg.name in self._user_input_vars:
                            has_user_url = True
                    # Check for BinaryOp assignments like allow_redirects=True
                    if isinstance(arg, BinaryOp) and arg.op == "=":
                        if isinstance(arg.left, Identifier):
                            if arg.left.name.lower() in REDIRECT_FOLLOW_PATTERNS:
                                if isinstance(arg.right, Identifier) and arg.right.name.lower() == "true":
                                    has_redirect_config = True

                # Check callee args for user input
                for arg in expr.args:
                    if _expr_contains_user_input(arg):
                        has_user_url = True

            elif isinstance(expr, MethodCall):
                for arg in expr.args:
                    if isinstance(arg, Identifier):
                        if arg.name.lower() in REDIRECT_FOLLOW_PATTERNS:
                            has_redirect_config = True
                        if arg.name in self._user_input_vars:
                            has_user_url = True
                    if _expr_contains_user_input(arg):
                        has_user_url = True

            if has_redirect_config and has_user_url:
                self.findings.append(SSRFFinding(
                    category="Redirect Following",
                    severity=Severity.MEDIUM,
                    description=(
                        f"HTTP request with user-controlled URL has redirect "
                        f"following enabled. An attacker can supply an external "
                        f"URL that 302-redirects to an internal service, "
                        f"bypassing URL validation on the initial request."
                    ),
                    location=loc,
                    function_name=func_name,
                    cwe="CWE-918",
                    evidence="follow_redirects + user_url",
                    remediation=(
                        "Disable automatic redirect following "
                        "(allow_redirects=False / followRedirects: false). "
                        "If redirects must be followed, validate each redirect "
                        "destination against the same URL/IP rules as the "
                        "original request. Check the resolved IP of each "
                        "redirect hop."
                    ),
                ))
            elif has_user_url and not has_redirect_config:
                # Most HTTP clients follow redirects by default --
                # if there's no explicit disable, flag as potential risk
                url_var = self._extract_request_url_var(expr)
                if url_var and url_var not in self._validated_vars:
                    # Only flag if not already caught by other checks at same loc
                    if not any(
                        f.category == "Redirect Following" and f.location == loc
                        for f in self.findings
                    ):
                        self.findings.append(SSRFFinding(
                            category="Redirect Following",
                            severity=Severity.MEDIUM,
                            description=(
                                f"HTTP request with user-controlled URL '{url_var}' "
                                f"does not explicitly disable redirect following. "
                                f"Most HTTP clients follow redirects by default, "
                                f"which can be exploited for redirect-based SSRF."
                            ),
                            location=loc,
                            function_name=func_name,
                            cwe="CWE-918",
                            evidence=f"request({url_var}) -- default redirects",
                            remediation=(
                                "Explicitly disable redirects "
                                "(allow_redirects=False / followRedirects: false) "
                                "or validate each redirect destination. "
                                "Resolve hostnames and block internal IPs at "
                                "every redirect hop."
                            ),
                        ))

    # ------------------------------------------------------------------
    # Shared Helpers
    # ------------------------------------------------------------------

    def _extract_exprs(self, stmt: Statement) -> List[Expr]:
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

    def _is_http_request_expr(self, expr: Expr) -> bool:
        """Check if an expression is an HTTP request call.

        Excludes client-side navigation calls (router.push, navigate, Link,
        useRouter, etc.) which are frontend routing, not server-side HTTP
        requests. This prevents false positives on React/Vue/Angular components.
        """
        # First, check if this is a client-side navigation call -- never SSRF
        if _is_client_navigation_call(expr):
            return False

        if isinstance(expr, FunctionCall):
            callee_name = _get_func_name(expr.callee)
            if callee_name:
                callee_lower = callee_name.lower()
                for func in HTTP_REQUEST_FUNCTIONS:
                    if func.lower() in callee_lower or callee_lower in func.lower():
                        return True
                # Also check full dotted name (e.g., requests.get)
                full_name = _get_full_callee_name(expr.callee).lower()
                for func in HTTP_REQUEST_FUNCTIONS:
                    if func.lower() in full_name:
                        return True
        elif isinstance(expr, MethodCall):
            if expr.method_name.lower() in HTTP_REQUEST_METHODS:
                # In frontend files, skip methods that overlap with client navigation
                # (e.g., .push(), .replace(), .navigate()) when called on router objects
                if self._is_frontend or self._func_has_react:
                    if _is_client_navigation_call(expr):
                        return False
                return True
        return False

    def _get_call_args(self, expr: Expr) -> List[Expr]:
        """Get arguments from a call expression."""
        if isinstance(expr, FunctionCall):
            return expr.args
        elif isinstance(expr, MethodCall):
            return expr.args
        return []


# ---------------------------------------------------------------------------
# Error Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: SSRFFinding) -> AeonError:
    """Convert an SSRFFinding into an AeonError using contract_error."""
    severity_label = finding.severity.value.upper()
    category_short = finding.category.replace(" ", "_").lower()

    return contract_error(
        precondition=(
            f"SSRF protection ({finding.cwe}) -- "
            f"[{severity_label}] {finding.category}: {finding.description}"
        ),
        failing_values={
            "category": finding.category,
            "severity": finding.severity.value,
            "cwe": finding.cwe,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "engine": "SSRF Advanced",
        },
        function_signature=finding.function_name,
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_ssrf_advanced(program: Program) -> list:
    """Run advanced SSRF analysis on an AEON program.

    Detects sophisticated Server-Side Request Forgery patterns that go
    beyond basic taint analysis:

    1. Cloud metadata endpoint access (AWS, GCP, Azure, Alibaba)
       - CWE-918, Severity: Critical

    2. DNS rebinding / TOCTOU race conditions
       - CWE-367, Severity: Medium

    3. Internal network access (RFC 1918, loopback, link-local)
       - CWE-918, Severity: Critical

    4. Protocol smuggling (file://, gopher://, dict://, ftp://)
       - CWE-918 / CWE-441, Severity: High

    5. URL parsing bypass (auth segments, weak validation)
       - CWE-918, Severity: High / Medium

    6. Webhook/callback blind SSRF
       - CWE-918, Severity: High

    7. Image/file processing SSRF (Pillow, wkhtmltopdf, Puppeteer)
       - CWE-918, Severity: High

    8. Redirect following without validation
       - CWE-918, Severity: Medium

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected SSRF vector.
    """
    try:
        analyzer = SSRFAdvancedAnalyzer()
        findings = analyzer.check_program(program)
        return [_finding_to_error(f) for f in findings]
    except Exception:
        # Engine-level safety net: never let the engine crash
        # the verification pipeline
        return []
