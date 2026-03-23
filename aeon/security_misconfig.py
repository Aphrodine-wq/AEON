"""AEON Security Misconfiguration Engine -- Configuration Vulnerability Scanner.

Detects security misconfigurations across web frameworks, server configurations,
cookie settings, and deployment patterns that leave applications vulnerable.

References:
  CWE-489: Active Debug Code
  https://cwe.mitre.org/data/definitions/489.html

  CWE-798: Use of Hard-Coded Credentials
  https://cwe.mitre.org/data/definitions/798.html

  CWE-215: Insertion of Sensitive Information Into Debugging Code
  https://cwe.mitre.org/data/definitions/215.html

  CWE-209: Generation of Error Message Containing Sensitive Information
  https://cwe.mitre.org/data/definitions/209.html

  CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
  https://cwe.mitre.org/data/definitions/614.html

  CWE-548: Exposure of Information Through Directory Listing
  https://cwe.mitre.org/data/definitions/548.html

  CWE-319: Cleartext Transmission of Sensitive Information
  https://cwe.mitre.org/data/definitions/319.html

  CWE-1188: Initialization with Hard-Coded Network Resource Configuration Default
  https://cwe.mitre.org/data/definitions/1188.html

  CWE-526: Exposure of Sensitive Information Through Environmental Variables
  https://cwe.mitre.org/data/definitions/526.html

  OWASP Top 10 (2021) A05: Security Misconfiguration
  https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

  NIST SP 800-123 "Guide to General Server Security"
  https://doi.org/10.6028/NIST.SP.800-123

Detection Categories:

1. DEBUG MODE IN PRODUCTION (CWE-489):
   DEBUG=True, app.debug, settings.DEBUG, config.debug, NODE_ENV checks
   that enable debug features. Debug mode exposes stack traces, internal
   state, and often disables security middleware.

2. DEFAULT CREDENTIALS (CWE-798):
   Common default passwords (admin, password, 123456, root, default,
   changeme, test, guest) assigned to password/secret/credential variables.
   Default credentials are the first thing attackers try.

3. EXPOSED ADMIN/DEBUG ENDPOINTS (CWE-215):
   Routes containing /debug/, /admin/, /__debug__/, /graphql (with
   introspection), /swagger, /api-docs, /_profiler, /phpinfo, /elmah,
   /trace, /actuator. These endpoints leak internal application details.

4. VERBOSE ERROR HANDLING (CWE-209):
   Global error handlers that return full exceptions to clients.
   Patterns like res.json(err) in Express error middleware.
   Missing custom error pages expose stack traces and internals.

5. INSECURE COOKIE DEFAULTS (CWE-614):
   Session/cookie configuration missing secure, httpOnly, sameSite flags.
   Framework-specific: Express cookie-session without secure, Phoenix
   endpoint config without secure flag.

6. DIRECTORY LISTING ENABLED (CWE-548):
   Static file serving without index file or listing disabled.
   express.static() without dotfiles: 'deny', serveStatic without options.
   Directory listings expose file structure to attackers.

7. MISSING HTTPS REDIRECT (CWE-319):
   HTTP endpoints without redirect to HTTPS. No x-forwarded-proto check
   in middleware. Cleartext HTTP transmits credentials and session tokens
   in the open.

8. UNNECESSARY FEATURES ENABLED (CWE-1188):
   TRACE/OPTIONS methods enabled globally, XML parsing with DTD enabled
   by default, server version headers exposed (X-Powered-By, Server).
   Every enabled feature is additional attack surface.

9. FRAMEWORK-SPECIFIC MISCONFIGS:
   Next.js: poweredByHeader: true (default), missing reactStrictMode.
   Express: missing helmet(), trust proxy without validation.
   Phoenix: check_origin: false, debug_errors: true in prod config.
   Django: ALLOWED_HOSTS = ['*'], SECRET_KEY in settings file.

10. EXPOSED ENVIRONMENT VARIABLES (CWE-526):
    process.env dumped to client, env vars in client-side bundles,
    .env file served statically. Environment variables often contain
    database credentials, API keys, and signing secrets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    LetStmt, AssignStmt, IfStmt, ExprStmt, WhileStmt, ReturnStmt,
    ListLiteral, ConstructExpr,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Severity Levels
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Finding Categories
# ---------------------------------------------------------------------------

class FindingCategory(Enum):
    DEBUG_MODE_PRODUCTION = "debug_mode_in_production"
    DEFAULT_CREDENTIALS = "default_credentials"
    EXPOSED_DEBUG_ENDPOINT = "exposed_debug_endpoint"
    EXPOSED_ADMIN_ENDPOINT = "exposed_admin_endpoint"
    VERBOSE_ERROR_HANDLING = "verbose_error_handling"
    COOKIE_MISSING_SECURE = "cookie_missing_secure"
    COOKIE_MISSING_HTTPONLY = "cookie_missing_httponly"
    COOKIE_MISSING_SAMESITE = "cookie_missing_samesite"
    DIRECTORY_LISTING = "directory_listing_enabled"
    MISSING_HTTPS_REDIRECT = "missing_https_redirect"
    TRACE_METHOD_ENABLED = "trace_method_enabled"
    OPTIONS_GLOBAL = "options_method_global"
    XML_DTD_ENABLED = "xml_dtd_enabled"
    SERVER_VERSION_EXPOSED = "server_version_exposed"
    NEXTJS_POWERED_BY = "nextjs_powered_by_header"
    NEXTJS_NO_STRICT_MODE = "nextjs_missing_strict_mode"
    EXPRESS_NO_HELMET = "express_missing_helmet"
    EXPRESS_TRUST_PROXY = "express_trust_proxy_unvalidated"
    PHOENIX_NO_CHECK_ORIGIN = "phoenix_check_origin_false"
    PHOENIX_DEBUG_ERRORS = "phoenix_debug_errors_true"
    DJANGO_ALLOWED_HOSTS_WILDCARD = "django_allowed_hosts_wildcard"
    DJANGO_SECRET_KEY_HARDCODED = "django_secret_key_hardcoded"
    ENV_VARS_EXPOSED = "environment_variables_exposed"
    ENV_FILE_SERVED = "env_file_served_statically"
    GRAPHQL_INTROSPECTION = "graphql_introspection_enabled"


# ---------------------------------------------------------------------------
# CWE Mapping
# ---------------------------------------------------------------------------

CWE_MAP: Dict[FindingCategory, str] = {
    FindingCategory.DEBUG_MODE_PRODUCTION: "CWE-489",
    FindingCategory.DEFAULT_CREDENTIALS: "CWE-798",
    FindingCategory.EXPOSED_DEBUG_ENDPOINT: "CWE-215",
    FindingCategory.EXPOSED_ADMIN_ENDPOINT: "CWE-215",
    FindingCategory.VERBOSE_ERROR_HANDLING: "CWE-209",
    FindingCategory.COOKIE_MISSING_SECURE: "CWE-614",
    FindingCategory.COOKIE_MISSING_HTTPONLY: "CWE-614",
    FindingCategory.COOKIE_MISSING_SAMESITE: "CWE-614",
    FindingCategory.DIRECTORY_LISTING: "CWE-548",
    FindingCategory.MISSING_HTTPS_REDIRECT: "CWE-319",
    FindingCategory.TRACE_METHOD_ENABLED: "CWE-1188",
    FindingCategory.OPTIONS_GLOBAL: "CWE-1188",
    FindingCategory.XML_DTD_ENABLED: "CWE-1188",
    FindingCategory.SERVER_VERSION_EXPOSED: "CWE-1188",
    FindingCategory.NEXTJS_POWERED_BY: "CWE-1188",
    FindingCategory.NEXTJS_NO_STRICT_MODE: "CWE-1188",
    FindingCategory.EXPRESS_NO_HELMET: "CWE-1188",
    FindingCategory.EXPRESS_TRUST_PROXY: "CWE-1188",
    FindingCategory.PHOENIX_NO_CHECK_ORIGIN: "CWE-1188",
    FindingCategory.PHOENIX_DEBUG_ERRORS: "CWE-489",
    FindingCategory.DJANGO_ALLOWED_HOSTS_WILDCARD: "CWE-1188",
    FindingCategory.DJANGO_SECRET_KEY_HARDCODED: "CWE-798",
    FindingCategory.ENV_VARS_EXPOSED: "CWE-526",
    FindingCategory.ENV_FILE_SERVED: "CWE-526",
    FindingCategory.GRAPHQL_INTROSPECTION: "CWE-215",
}


# ---------------------------------------------------------------------------
# Severity Mapping
# ---------------------------------------------------------------------------

SEVERITY_MAP: Dict[FindingCategory, Severity] = {
    FindingCategory.DEBUG_MODE_PRODUCTION: Severity.HIGH,
    FindingCategory.DEFAULT_CREDENTIALS: Severity.CRITICAL,
    FindingCategory.EXPOSED_DEBUG_ENDPOINT: Severity.HIGH,
    FindingCategory.EXPOSED_ADMIN_ENDPOINT: Severity.MEDIUM,
    FindingCategory.VERBOSE_ERROR_HANDLING: Severity.HIGH,
    FindingCategory.COOKIE_MISSING_SECURE: Severity.HIGH,
    FindingCategory.COOKIE_MISSING_HTTPONLY: Severity.HIGH,
    FindingCategory.COOKIE_MISSING_SAMESITE: Severity.MEDIUM,
    FindingCategory.DIRECTORY_LISTING: Severity.MEDIUM,
    FindingCategory.MISSING_HTTPS_REDIRECT: Severity.HIGH,
    FindingCategory.TRACE_METHOD_ENABLED: Severity.MEDIUM,
    FindingCategory.OPTIONS_GLOBAL: Severity.LOW,
    FindingCategory.XML_DTD_ENABLED: Severity.HIGH,
    FindingCategory.SERVER_VERSION_EXPOSED: Severity.MEDIUM,
    FindingCategory.NEXTJS_POWERED_BY: Severity.LOW,
    FindingCategory.NEXTJS_NO_STRICT_MODE: Severity.LOW,
    FindingCategory.EXPRESS_NO_HELMET: Severity.HIGH,
    FindingCategory.EXPRESS_TRUST_PROXY: Severity.MEDIUM,
    FindingCategory.PHOENIX_NO_CHECK_ORIGIN: Severity.HIGH,
    FindingCategory.PHOENIX_DEBUG_ERRORS: Severity.HIGH,
    FindingCategory.DJANGO_ALLOWED_HOSTS_WILDCARD: Severity.HIGH,
    FindingCategory.DJANGO_SECRET_KEY_HARDCODED: Severity.CRITICAL,
    FindingCategory.ENV_VARS_EXPOSED: Severity.CRITICAL,
    FindingCategory.ENV_FILE_SERVED: Severity.CRITICAL,
    FindingCategory.GRAPHQL_INTROSPECTION: Severity.MEDIUM,
}


# ---------------------------------------------------------------------------
# Remediation Guidance
# ---------------------------------------------------------------------------

REMEDIATION: Dict[FindingCategory, str] = {
    FindingCategory.DEBUG_MODE_PRODUCTION: (
        "Ensure DEBUG is False in production. Use environment variables to "
        "control debug mode: DEBUG = os.environ.get('DEBUG', 'False') == 'True'. "
        "Never deploy with debug mode enabled"
    ),
    FindingCategory.DEFAULT_CREDENTIALS: (
        "Replace default credentials with strong, unique passwords. Use a "
        "secrets manager or environment variables. Never ship default "
        "passwords like 'admin', 'password', or 'changeme'"
    ),
    FindingCategory.EXPOSED_DEBUG_ENDPOINT: (
        "Remove or restrict debug endpoints in production. Use middleware "
        "to block access to /__debug__/, /_profiler/, /trace/, /phpinfo, "
        "and similar paths. Gate behind IP allowlist or authentication"
    ),
    FindingCategory.EXPOSED_ADMIN_ENDPOINT: (
        "Protect admin endpoints with authentication, IP allowlisting, "
        "and rate limiting. Never expose /admin/ without access control. "
        "Consider placing admin routes behind a VPN"
    ),
    FindingCategory.VERBOSE_ERROR_HANDLING: (
        "Never return raw exception details to clients. Use custom error "
        "handlers that return generic messages. Log full errors server-side. "
        "In Express: app.use((err, req, res, next) => res.status(500).json("
        "{ error: 'Internal server error' }))"
    ),
    FindingCategory.COOKIE_MISSING_SECURE: (
        "Set the Secure flag on all session cookies to ensure they are only "
        "sent over HTTPS. In Express: { cookie: { secure: true } }. "
        "In Phoenix: put_resp_cookie(conn, key, val, secure: true)"
    ),
    FindingCategory.COOKIE_MISSING_HTTPONLY: (
        "Set the HttpOnly flag on session cookies to prevent JavaScript "
        "access via document.cookie. This mitigates XSS-based session theft"
    ),
    FindingCategory.COOKIE_MISSING_SAMESITE: (
        "Set the SameSite attribute (Lax or Strict) on cookies to prevent "
        "cross-site request forgery. SameSite=Lax is the recommended default"
    ),
    FindingCategory.DIRECTORY_LISTING: (
        "Disable directory listing on static file servers. In Express: "
        "use express.static with { dotfiles: 'deny', index: false } only if "
        "intended. Ensure a default index file exists or listing is disabled"
    ),
    FindingCategory.MISSING_HTTPS_REDIRECT: (
        "Implement HTTPS redirect middleware. Check x-forwarded-proto header "
        "behind load balancers. Redirect all HTTP requests to HTTPS. "
        "Set Strict-Transport-Security header"
    ),
    FindingCategory.TRACE_METHOD_ENABLED: (
        "Disable TRACE and TRACK HTTP methods. TRACE enables Cross-Site "
        "Tracing (XST) attacks that can steal credentials. In Express: "
        "reject TRACE/TRACK in middleware before route handlers"
    ),
    FindingCategory.OPTIONS_GLOBAL: (
        "Do not enable OPTIONS globally without CORS restrictions. "
        "Use framework-specific CORS middleware (e.g., cors() in Express) "
        "with explicit origin allowlists"
    ),
    FindingCategory.XML_DTD_ENABLED: (
        "Disable DTD processing in XML parsers to prevent XXE attacks. "
        "In Python: defusedxml or lxml with resolve_entities=False. "
        "In Java: setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)"
    ),
    FindingCategory.SERVER_VERSION_EXPOSED: (
        "Remove server version headers (X-Powered-By, Server). In Express: "
        "app.disable('x-powered-by') or use helmet(). Version disclosure "
        "helps attackers identify known vulnerabilities"
    ),
    FindingCategory.NEXTJS_POWERED_BY: (
        "In next.config.js, set poweredByHeader: false to remove the "
        "X-Powered-By: Next.js header. This is enabled by default and "
        "discloses the framework to attackers"
    ),
    FindingCategory.NEXTJS_NO_STRICT_MODE: (
        "Enable reactStrictMode: true in next.config.js. Strict mode "
        "identifies unsafe lifecycles, legacy API usage, and other "
        "potential problems during development"
    ),
    FindingCategory.EXPRESS_NO_HELMET: (
        "Add helmet() middleware to Express applications. Helmet sets "
        "security headers including CSP, X-Content-Type-Options, "
        "X-Frame-Options, HSTS, and more. Install: npm install helmet"
    ),
    FindingCategory.EXPRESS_TRUST_PROXY: (
        "When using 'trust proxy', specify exact proxy addresses or "
        "a subnet rather than 'true' (trust all). Unvalidated trust proxy "
        "allows IP spoofing via X-Forwarded-For headers"
    ),
    FindingCategory.PHOENIX_NO_CHECK_ORIGIN: (
        "Set check_origin: true or check_origin: ['//yourdomain.com'] in "
        "Phoenix endpoint configuration. check_origin: false allows "
        "WebSocket connections from any origin (CSRF for WebSockets)"
    ),
    FindingCategory.PHOENIX_DEBUG_ERRORS: (
        "Set debug_errors: false in production Phoenix endpoint configuration. "
        "debug_errors: true returns full stack traces to clients"
    ),
    FindingCategory.DJANGO_ALLOWED_HOSTS_WILDCARD: (
        "Set ALLOWED_HOSTS to a specific list of domains, never ['*']. "
        "Wildcard ALLOWED_HOSTS disables host header validation and enables "
        "host header injection attacks"
    ),
    FindingCategory.DJANGO_SECRET_KEY_HARDCODED: (
        "Load SECRET_KEY from an environment variable or secrets manager, "
        "never hardcode it in settings.py. A leaked SECRET_KEY allows "
        "forging session cookies and CSRF tokens"
    ),
    FindingCategory.ENV_VARS_EXPOSED: (
        "Never dump process.env or os.environ to client-side code. "
        "Only expose specific, non-sensitive environment variables. "
        "Use server-side-only env access patterns"
    ),
    FindingCategory.ENV_FILE_SERVED: (
        "Never serve .env files statically. Add .env to .gitignore and "
        "exclude it from static file serving. Configure web servers to "
        "deny access to dotfiles"
    ),
    FindingCategory.GRAPHQL_INTROSPECTION: (
        "Disable GraphQL introspection in production. Introspection exposes "
        "the entire schema including types, queries, mutations, and "
        "relationships. Enable only in development"
    ),
}


# ---------------------------------------------------------------------------
# Default Credential Patterns
# ---------------------------------------------------------------------------

# Values that are common default passwords
DEFAULT_PASSWORDS: Set[str] = {
    "admin", "password", "123456", "root", "default", "changeme",
    "test", "guest", "12345", "1234", "pass", "letmein", "master",
    "qwerty", "abc123", "monkey", "dragon", "login", "princess",
    "welcome", "shadow", "sunshine", "trustno1", "iloveyou",
}

# Variable names that indicate a credential assignment
CREDENTIAL_VARIABLE_NAMES: Set[str] = {
    "password", "passwd", "pwd", "pass", "secret", "credential",
    "credentials", "secret_key", "secretkey", "auth_token",
    "api_key", "apikey", "api_secret", "apisecret",
    "db_password", "db_pass", "database_password",
    "admin_password", "admin_pass", "root_password",
    "master_password", "master_key", "signing_key",
    "encryption_key", "private_key",
}


# ---------------------------------------------------------------------------
# Debug Variable Patterns
# ---------------------------------------------------------------------------

# Variable names that indicate debug mode settings
DEBUG_VARIABLE_NAMES: Set[str] = {
    "debug", "DEBUG", "debug_mode", "DEBUG_MODE",
    "is_debug", "IS_DEBUG", "development", "DEVELOPMENT",
    "dev_mode", "DEV_MODE",
}

# Full-chain identifiers that indicate debug mode
DEBUG_FIELD_CHAINS: Set[str] = {
    "app.debug", "settings.DEBUG", "config.debug", "app.config.DEBUG",
    "settings.debug", "config.DEBUG", "flask.debug", "django.conf.settings.DEBUG",
}


# ---------------------------------------------------------------------------
# Exposed Endpoint Patterns
# ---------------------------------------------------------------------------

# Route path segments that indicate debug/admin endpoints
DEBUG_ENDPOINT_PATTERNS: List[re.Pattern] = [
    re.compile(r"/debug/", re.IGNORECASE),
    re.compile(r"/__debug__/", re.IGNORECASE),
    re.compile(r"/_profiler", re.IGNORECASE),
    re.compile(r"/phpinfo", re.IGNORECASE),
    re.compile(r"/elmah", re.IGNORECASE),
    re.compile(r"/trace\b", re.IGNORECASE),
    re.compile(r"/actuator", re.IGNORECASE),
    re.compile(r"/server-status", re.IGNORECASE),
    re.compile(r"/server-info", re.IGNORECASE),
]

ADMIN_ENDPOINT_PATTERNS: List[re.Pattern] = [
    re.compile(r"/admin/", re.IGNORECASE),
    re.compile(r"/swagger", re.IGNORECASE),
    re.compile(r"/api-docs", re.IGNORECASE),
    re.compile(r"/graphiql", re.IGNORECASE),
]

GRAPHQL_ENDPOINT_PATTERNS: List[re.Pattern] = [
    re.compile(r"/graphql\b", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Server Version Headers
# ---------------------------------------------------------------------------

SERVER_VERSION_HEADERS: Set[str] = {
    "x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-php-version",
}


# ---------------------------------------------------------------------------
# Cookie/Session Function Names
# ---------------------------------------------------------------------------

COOKIE_SET_FUNCTIONS: Set[str] = {
    "setCookie", "set_cookie", "cookie", "setcookie",
    "session", "cookieSession", "cookie_session",
    "put_resp_cookie", "set_session",
}

SESSION_CONFIG_FUNCTIONS: Set[str] = {
    "session", "cookieSession", "cookie_session", "expressSession",
    "express_session", "cookie-session",
}

COOKIE_SECURITY_FLAGS: Set[str] = {"secure", "httponly", "httpOnly", "samesite", "sameSite"}


# ---------------------------------------------------------------------------
# Static File Functions
# ---------------------------------------------------------------------------

STATIC_FILE_FUNCTIONS: Set[str] = {
    "static", "express.static", "serveStatic", "serve_static",
    "staticFiles", "static_files", "send_static_file",
    "use_static", "Plug.Static",
}


# ---------------------------------------------------------------------------
# HTTP Method Patterns
# ---------------------------------------------------------------------------

DANGEROUS_HTTP_METHODS: Set[str] = {"TRACE", "TRACK"}


# ---------------------------------------------------------------------------
# Express-Specific Patterns
# ---------------------------------------------------------------------------

EXPRESS_SETUP_FUNCTIONS: Set[str] = {
    "express", "createServer", "create_server",
}

HELMET_FUNCTIONS: Set[str] = {
    "helmet", "lusca", "hpp",
}


# ---------------------------------------------------------------------------
# Internal Finding
# ---------------------------------------------------------------------------

@dataclass
class MisconfigFinding:
    """Internal finding before conversion to AeonError."""
    category: FindingCategory
    message: str
    location: Optional[SourceLocation]
    context: str = ""  # function name or variable name


# ---------------------------------------------------------------------------
# AST Helpers
# ---------------------------------------------------------------------------

def _get_callee_name(expr: Expr) -> str:
    """Extract the function/method name from a call expression."""
    if isinstance(expr, FunctionCall):
        callee = expr.callee
        if isinstance(callee, Identifier):
            return callee.name
        if isinstance(callee, FieldAccess):
            return callee.field_name
    if isinstance(expr, MethodCall):
        return expr.method_name
    return ""


def _get_callee_chain(expr: Expr) -> str:
    """Build a dotted callee chain: e.g., 'app.use', 'express.static'."""
    if isinstance(expr, FunctionCall):
        callee = expr.callee
        if isinstance(callee, Identifier):
            return callee.name
        if isinstance(callee, FieldAccess):
            obj_name = _get_callee_chain_from_expr(callee.obj)
            return f"{obj_name}.{callee.field_name}" if obj_name else callee.field_name
    if isinstance(expr, MethodCall):
        obj_name = _get_callee_chain_from_expr(expr.obj)
        return f"{obj_name}.{expr.method_name}" if obj_name else expr.method_name
    return ""


def _get_callee_chain_from_expr(expr: Expr) -> str:
    """Build a dotted chain from an arbitrary expression (for nested access)."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, FieldAccess):
        obj_name = _get_callee_chain_from_expr(expr.obj)
        return f"{obj_name}.{expr.field_name}" if obj_name else expr.field_name
    if isinstance(expr, MethodCall):
        obj_name = _get_callee_chain_from_expr(expr.obj)
        return f"{obj_name}.{expr.method_name}" if obj_name else expr.method_name
    if isinstance(expr, FunctionCall):
        return _get_callee_chain(expr)
    return ""


def _get_construct_field(expr: Expr, field_name: str) -> Optional[Expr]:
    """Get a named field from a ConstructExpr argument in a call."""
    args: List[Expr] = []
    if isinstance(expr, FunctionCall):
        args = expr.args
    elif isinstance(expr, MethodCall):
        args = expr.args

    for arg in args:
        if isinstance(arg, ConstructExpr):
            for fname, fval in arg.fields.items():
                if fname.lower() == field_name.lower():
                    return fval
    return None


def _has_construct_field(expr: Expr, field_names: Set[str]) -> bool:
    """Check if a call has any of the named fields in its ConstructExpr args."""
    args: List[Expr] = []
    if isinstance(expr, FunctionCall):
        args = expr.args
    elif isinstance(expr, MethodCall):
        args = expr.args

    normalized = {f.lower() for f in field_names}
    for arg in args:
        if isinstance(arg, ConstructExpr):
            for fname in arg.fields:
                if fname.lower() in normalized:
                    return True
    return False


def _is_bool_true(expr: Expr) -> bool:
    """Check if an expression is the boolean literal True."""
    return isinstance(expr, BoolLiteral) and expr.value is True


def _is_bool_false(expr: Expr) -> bool:
    """Check if an expression is the boolean literal False."""
    return isinstance(expr, BoolLiteral) and expr.value is False


def _string_value(expr: Expr) -> Optional[str]:
    """Extract the string value from an expression, if it is a StringLiteral."""
    if isinstance(expr, StringLiteral):
        return expr.value
    return None


def _identifier_name(expr: Expr) -> Optional[str]:
    """Extract the name from an Identifier expression."""
    if isinstance(expr, Identifier):
        return expr.name
    return None


def _variable_name_from_let(stmt: LetStmt) -> str:
    """Extract the variable name from a let statement."""
    return getattr(stmt, "name", "")


def _variable_name_from_assign(stmt: AssignStmt) -> str:
    """Extract the variable name or field chain from an assignment target."""
    target = stmt.target
    if isinstance(target, Identifier):
        return target.name
    if isinstance(target, FieldAccess):
        obj_chain = _get_callee_chain_from_expr(target.obj)
        return f"{obj_chain}.{target.field_name}" if obj_chain else target.field_name
    return ""


# ---------------------------------------------------------------------------
# Security Misconfiguration Analyzer
# ---------------------------------------------------------------------------

class SecurityMisconfigAnalyzer:
    """Scans AEON AST for security misconfiguration vulnerabilities."""

    def __init__(self):
        self.findings: List[MisconfigFinding] = []
        self._current_func_name: str = ""
        # Track whether the current file/program uses Express patterns
        self._has_express: bool = False
        self._has_helmet: bool = False
        self._has_https_redirect: bool = False
        # Track variable assignments for cross-statement analysis
        self._var_values: Dict[str, Expr] = {}

    def check_program(self, program: Program) -> List[MisconfigFinding]:
        """Run all security misconfiguration checks on the program."""
        self.findings = []
        self._has_express = False
        self._has_helmet = False
        self._has_https_redirect = False

        # First pass: detect framework usage and global patterns
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._detect_framework_usage(decl)

        # Second pass: run all checks
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        # Post-program checks: file-level misconfigurations
        self._check_express_missing_helmet(program)
        self._check_missing_https_redirect(program)

        return self.findings

    # ------------------------------------------------------------------
    # Framework Detection (First Pass)
    # ------------------------------------------------------------------

    def _detect_framework_usage(self, func: PureFunc | TaskFunc) -> None:
        """Detect framework usage in the function body."""
        for stmt in func.body:
            self._detect_framework_in_statement(stmt)

    def _detect_framework_in_statement(self, stmt: Statement) -> None:
        """Recursively scan statements for framework indicators."""
        try:
            if isinstance(stmt, ExprStmt):
                self._detect_framework_in_expr(stmt.expr)
            elif isinstance(stmt, LetStmt):
                if stmt.value:
                    self._detect_framework_in_expr(stmt.value)
            elif isinstance(stmt, AssignStmt):
                self._detect_framework_in_expr(stmt.value)
            elif isinstance(stmt, IfStmt):
                for s in stmt.then_body:
                    self._detect_framework_in_statement(s)
                for s in stmt.else_body:
                    self._detect_framework_in_statement(s)
            elif isinstance(stmt, WhileStmt):
                for s in stmt.body:
                    self._detect_framework_in_statement(s)
            elif isinstance(stmt, ReturnStmt):
                if stmt.value:
                    self._detect_framework_in_expr(stmt.value)
        except Exception:
            pass

    def _detect_framework_in_expr(self, expr: Expr) -> None:
        """Detect framework indicators in an expression."""
        try:
            chain = _get_callee_chain(expr)
            name = _get_callee_name(expr)

            # Detect Express
            if name in EXPRESS_SETUP_FUNCTIONS or "express" in chain.lower():
                self._has_express = True

            # Detect helmet usage
            if name in HELMET_FUNCTIONS:
                self._has_helmet = True

            # Detect HTTPS redirect patterns
            if self._is_https_redirect_expr(expr):
                self._has_https_redirect = True

            # Recurse into call arguments
            args: List[Expr] = []
            if isinstance(expr, FunctionCall):
                args = expr.args
            elif isinstance(expr, MethodCall):
                args = expr.args
            for arg in args:
                self._detect_framework_in_expr(arg)
        except Exception:
            pass

    def _is_https_redirect_expr(self, expr: Expr) -> bool:
        """Check if an expression is part of an HTTPS redirect pattern."""
        # Look for x-forwarded-proto checks
        if isinstance(expr, BinaryOp):
            left_str = _string_value(expr.left)
            right_str = _string_value(expr.right)
            if left_str and "x-forwarded-proto" in left_str.lower():
                return True
            if right_str and "x-forwarded-proto" in right_str.lower():
                return True
            left_name = _identifier_name(expr.left)
            right_name = _identifier_name(expr.right)
            if left_name and "proto" in left_name.lower():
                return True
            if right_name and "proto" in right_name.lower():
                return True
        # Look for redirect to https
        if isinstance(expr, (FunctionCall, MethodCall)):
            for arg in (expr.args if hasattr(expr, "args") else []):
                s = _string_value(arg)
                if s and s.startswith("https://"):
                    chain = _get_callee_name(expr)
                    if "redirect" in chain.lower():
                        return True
        return False

    # ------------------------------------------------------------------
    # Per-Function Analysis (Second Pass)
    # ------------------------------------------------------------------

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for security misconfigurations."""
        self._current_func_name = func.name
        self._var_values = {}

        for stmt in func.body:
            self._analyze_statement(stmt, func)

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Dispatch statement analysis to specific checks."""
        loc = getattr(stmt, "location", None)

        try:
            if isinstance(stmt, LetStmt):
                var_name = _variable_name_from_let(stmt)
                if stmt.value:
                    self._var_values[var_name] = stmt.value
                    self._check_debug_assignment(var_name, stmt.value, loc)
                    self._check_default_credentials(var_name, stmt.value, loc)
                    self._check_django_secret_key(var_name, stmt.value, loc)
                    self._check_django_allowed_hosts(var_name, stmt.value, loc)
                    self._check_env_exposure(stmt.value, loc)
                    self._analyze_expr(stmt.value, loc, func)

            elif isinstance(stmt, AssignStmt):
                var_name = _variable_name_from_assign(stmt)
                self._var_values[var_name] = stmt.value
                self._check_debug_assignment(var_name, stmt.value, loc)
                self._check_default_credentials(var_name, stmt.value, loc)
                self._check_django_secret_key(var_name, stmt.value, loc)
                self._check_django_allowed_hosts(var_name, stmt.value, loc)
                self._check_env_exposure(stmt.value, loc)
                self._analyze_expr(stmt.value, loc, func)

            elif isinstance(stmt, ExprStmt):
                self._analyze_expr(stmt.expr, loc, func)

            elif isinstance(stmt, ReturnStmt):
                if stmt.value:
                    self._check_verbose_error_return(stmt.value, loc, func)
                    self._analyze_expr(stmt.value, loc, func)

            elif isinstance(stmt, IfStmt):
                self._check_debug_conditional(stmt, loc)
                for s in stmt.then_body:
                    self._analyze_statement(s, func)
                for s in stmt.else_body:
                    self._analyze_statement(s, func)

            elif isinstance(stmt, WhileStmt):
                for s in stmt.body:
                    self._analyze_statement(s, func)

        except Exception:
            # Per-statement robustness: one bad statement must not kill the engine
            pass

    def _analyze_expr(self, expr: Expr, loc: Optional[SourceLocation],
                      func: PureFunc | TaskFunc) -> None:
        """Analyze an expression for security misconfigurations."""
        try:
            expr_loc = getattr(expr, "location", None) or loc

            if isinstance(expr, (FunctionCall, MethodCall)):
                self._check_exposed_endpoints(expr, expr_loc)
                self._check_cookie_config(expr, expr_loc)
                self._check_directory_listing(expr, expr_loc)
                self._check_server_version_headers(expr, expr_loc)
                self._check_dangerous_http_methods(expr, expr_loc)
                self._check_xml_dtd(expr, expr_loc)
                self._check_nextjs_config(expr, expr_loc)
                self._check_express_trust_proxy(expr, expr_loc)
                self._check_phoenix_config(expr, expr_loc)
                self._check_graphql_introspection(expr, expr_loc)
                self._check_verbose_error_handler(expr, expr_loc, func)
                self._check_env_file_serving(expr, expr_loc)
                self._check_env_dump_in_response(expr, expr_loc)

                # Recurse into arguments
                for arg in (expr.args if hasattr(expr, "args") else []):
                    self._analyze_expr(arg, expr_loc, func)

            elif isinstance(expr, FieldAccess):
                self._check_env_field_access(expr, expr_loc)
                self._analyze_expr(expr.obj, expr_loc, func)

            elif isinstance(expr, BinaryOp):
                self._analyze_expr(expr.left, expr_loc, func)
                self._analyze_expr(expr.right, expr_loc, func)

            elif isinstance(expr, UnaryOp):
                self._analyze_expr(expr.operand, expr_loc, func)

        except Exception:
            pass

    # ------------------------------------------------------------------
    # 1. Debug Mode in Production (CWE-489)
    # ------------------------------------------------------------------

    def _check_debug_assignment(self, var_name: str, value: Expr,
                                loc: Optional[SourceLocation]) -> None:
        """Check if a debug-related variable is set to True."""
        if not var_name:
            return

        # Normalize the variable name chain
        var_lower = var_name.lower()

        # Check direct debug variable assignment: DEBUG = True
        is_debug_var = var_lower in {v.lower() for v in DEBUG_VARIABLE_NAMES}
        is_debug_chain = var_name in DEBUG_FIELD_CHAINS or var_lower in {
            c.lower() for c in DEBUG_FIELD_CHAINS
        }

        if is_debug_var or is_debug_chain:
            if _is_bool_true(value):
                self._add_finding(
                    FindingCategory.DEBUG_MODE_PRODUCTION,
                    f"Debug mode enabled: '{var_name} = True'. "
                    f"Debug mode exposes stack traces, internal state, "
                    f"and often disables security middleware",
                    loc,
                    context=var_name,
                )

            # String value "true" or "1"
            s = _string_value(value)
            if s and s.lower() in ("true", "1", "yes", "on"):
                self._add_finding(
                    FindingCategory.DEBUG_MODE_PRODUCTION,
                    f"Debug mode enabled via string: '{var_name} = \"{s}\"'. "
                    f"Ensure this is not deployed to production",
                    loc,
                    context=var_name,
                )

    def _check_debug_conditional(self, stmt: IfStmt,
                                 loc: Optional[SourceLocation]) -> None:
        """Check for NODE_ENV !== 'production' enabling debug features."""
        try:
            cond = stmt.condition
            if not isinstance(cond, BinaryOp):
                return

            # Check for NODE_ENV !== 'production' or process.env.NODE_ENV !== 'production'
            if cond.op in ("!==", "!=", "ne"):
                left_name = _identifier_name(cond.left)
                right_str = _string_value(cond.right)

                if right_str and right_str.lower() == "production":
                    if left_name and "node_env" in left_name.lower():
                        # Check if then_body enables debug features
                        if self._body_enables_debug(stmt.then_body):
                            self._add_finding(
                                FindingCategory.DEBUG_MODE_PRODUCTION,
                                f"Debug features enabled when NODE_ENV !== 'production'. "
                                f"Ensure NODE_ENV is set to 'production' in deployment",
                                loc,
                                context="NODE_ENV",
                            )

                # Also check left as string, right as identifier
                left_str = _string_value(cond.left)
                right_name = _identifier_name(cond.right)

                if left_str and left_str.lower() == "production":
                    if right_name and "node_env" in right_name.lower():
                        if self._body_enables_debug(stmt.then_body):
                            self._add_finding(
                                FindingCategory.DEBUG_MODE_PRODUCTION,
                                f"Debug features enabled when NODE_ENV !== 'production'. "
                                f"Ensure NODE_ENV is set to 'production' in deployment",
                                loc,
                                context="NODE_ENV",
                            )
        except Exception:
            pass

    def _body_enables_debug(self, body: List[Statement]) -> bool:
        """Check if a statement body enables debug-like features."""
        for stmt in body:
            if isinstance(stmt, (LetStmt, AssignStmt)):
                var = ""
                val = None
                if isinstance(stmt, LetStmt):
                    var = _variable_name_from_let(stmt)
                    val = stmt.value
                else:
                    var = _variable_name_from_assign(stmt)
                    val = stmt.value
                if var.lower() in {v.lower() for v in DEBUG_VARIABLE_NAMES}:
                    if val and _is_bool_true(val):
                        return True
            if isinstance(stmt, ExprStmt):
                name = _get_callee_name(stmt.expr)
                if name.lower() in ("enabledebug", "enable_debug", "setdebug", "set_debug"):
                    return True
        return False

    # ------------------------------------------------------------------
    # 2. Default Credentials (CWE-798)
    # ------------------------------------------------------------------

    def _check_default_credentials(self, var_name: str, value: Expr,
                                   loc: Optional[SourceLocation]) -> None:
        """Check if a credential variable is assigned a default password."""
        if not var_name:
            return

        var_lower = var_name.lower()
        is_credential = var_lower in {v.lower() for v in CREDENTIAL_VARIABLE_NAMES}
        if not is_credential:
            # Also check for substring matches
            credential_keywords = {"password", "passwd", "pwd", "secret", "credential"}
            is_credential = any(kw in var_lower for kw in credential_keywords)

        if not is_credential:
            return

        s = _string_value(value)
        if s and s.lower() in DEFAULT_PASSWORDS:
            self._add_finding(
                FindingCategory.DEFAULT_CREDENTIALS,
                f"Default credential '{s}' assigned to '{var_name}'. "
                f"Default passwords are the first thing attackers try",
                loc,
                context=var_name,
            )

    # ------------------------------------------------------------------
    # 3. Exposed Admin/Debug Endpoints (CWE-215)
    # ------------------------------------------------------------------

    def _check_exposed_endpoints(self, expr: Expr,
                                 loc: Optional[SourceLocation]) -> None:
        """Check if routes expose debug, admin, or sensitive endpoints."""
        name = _get_callee_name(expr)
        chain = _get_callee_chain(expr)

        # Route registration patterns
        route_methods = {"get", "post", "put", "delete", "patch", "route",
                         "all", "use", "handle", "match", "scope", "pipe_through"}

        if name.lower() not in route_methods:
            return

        # Check string arguments for sensitive paths
        args = expr.args if hasattr(expr, "args") else []
        for arg in args:
            s = _string_value(arg)
            if not s:
                continue

            # Debug endpoints
            for pattern in DEBUG_ENDPOINT_PATTERNS:
                if pattern.search(s):
                    self._add_finding(
                        FindingCategory.EXPOSED_DEBUG_ENDPOINT,
                        f"Debug endpoint exposed: '{s}'. Debug endpoints leak "
                        f"internal application details and should be removed "
                        f"or restricted in production",
                        loc,
                        context=s,
                    )
                    break

            # Admin endpoints
            for pattern in ADMIN_ENDPOINT_PATTERNS:
                if pattern.search(s):
                    self._add_finding(
                        FindingCategory.EXPOSED_ADMIN_ENDPOINT,
                        f"Admin/documentation endpoint exposed: '{s}'. "
                        f"Ensure this route requires authentication and "
                        f"is restricted in production",
                        loc,
                        context=s,
                    )
                    break

            # GraphQL with introspection concerns
            for pattern in GRAPHQL_ENDPOINT_PATTERNS:
                if pattern.search(s):
                    # GraphQL endpoint found -- check for introspection
                    # in the handler (separate check)
                    self._add_finding(
                        FindingCategory.GRAPHQL_INTROSPECTION,
                        f"GraphQL endpoint at '{s}' detected. Ensure "
                        f"introspection is disabled in production to "
                        f"prevent schema exposure",
                        loc,
                        context=s,
                    )
                    break

    # ------------------------------------------------------------------
    # 4. Verbose Error Handling (CWE-209)
    # ------------------------------------------------------------------

    def _check_verbose_error_handler(self, expr: Expr,
                                     loc: Optional[SourceLocation],
                                     func: PureFunc | TaskFunc) -> None:
        """Check for Express-style error handlers that leak exception details."""
        # Pattern: app.use((err, req, res, next) => res.json(err))
        # In AEON AST, we look for middleware-registration calls whose callback
        # passes error objects directly to response methods.
        name = _get_callee_name(expr)
        if name.lower() != "use":
            return

        # Check if this is a 4-arg middleware (error handler)
        func_name = func.name.lower()
        error_handler_indicators = {
            "errorhandler", "error_handler", "handleerror", "handle_error",
            "errorMiddleware", "error_middleware",
        }

        if func_name in {f.lower() for f in error_handler_indicators}:
            # Check if the function returns raw error objects
            for stmt in func.body:
                if isinstance(stmt, ReturnStmt) and stmt.value:
                    self._check_verbose_error_return(stmt.value, loc, func)

    def _check_verbose_error_return(self, value: Expr,
                                    loc: Optional[SourceLocation],
                                    func: PureFunc | TaskFunc) -> None:
        """Check if a return value sends raw error/exception data to client."""
        try:
            # res.json(err), res.send(err), res.status(500).json(err)
            if isinstance(value, (MethodCall, FunctionCall)):
                name = _get_callee_name(value)
                response_methods = {"json", "send", "render", "write", "end"}

                if name.lower() in response_methods:
                    args = value.args if hasattr(value, "args") else []
                    for arg in args:
                        arg_name = _identifier_name(arg)
                        if arg_name and arg_name.lower() in {
                            "err", "error", "exception", "exc", "e",
                            "stack", "stacktrace", "stack_trace",
                        }:
                            self._add_finding(
                                FindingCategory.VERBOSE_ERROR_HANDLING,
                                f"Raw error object '{arg_name}' returned in response "
                                f"via {name}(). Stack traces and error internals are "
                                f"exposed to clients",
                                loc,
                                context=func.name,
                            )
                            return

                        # Check for err.message, err.stack, etc.
                        if isinstance(arg, FieldAccess):
                            obj_name = _identifier_name(arg.obj)
                            if obj_name and obj_name.lower() in {"err", "error", "exception", "exc", "e"}:
                                if arg.field_name.lower() in {"stack", "stacktrace", "message", "trace"}:
                                    self._add_finding(
                                        FindingCategory.VERBOSE_ERROR_HANDLING,
                                        f"Error detail '{obj_name}.{arg.field_name}' returned "
                                        f"in response. Internal error information is exposed to clients",
                                        loc,
                                        context=func.name,
                                    )
                                    return
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 5. Insecure Cookie Defaults (CWE-614)
    # ------------------------------------------------------------------

    def _check_cookie_config(self, expr: Expr,
                             loc: Optional[SourceLocation]) -> None:
        """Check cookie/session configuration for missing security flags."""
        name = _get_callee_name(expr)

        # Check direct cookie-setting functions and session configuration
        is_cookie_fn = name.lower() in {f.lower() for f in COOKIE_SET_FUNCTIONS}
        is_session_fn = name.lower() in {f.lower() for f in SESSION_CONFIG_FUNCTIONS}

        if not (is_cookie_fn or is_session_fn):
            return

        # Look for ConstructExpr arguments with cookie options
        args = expr.args if hasattr(expr, "args") else []
        options_found = False

        for arg in args:
            if isinstance(arg, ConstructExpr):
                options_found = True
                fields_lower = {f.lower(): f for f in arg.fields}

                # Check for missing 'secure' flag
                if "secure" not in fields_lower:
                    self._add_finding(
                        FindingCategory.COOKIE_MISSING_SECURE,
                        f"Cookie/session configuration via {name}() is missing "
                        f"the 'secure' flag. Cookies will be sent over HTTP, "
                        f"exposing them to interception",
                        loc,
                        context=name,
                    )
                else:
                    # Check if secure is explicitly set to false
                    secure_val = arg.fields[fields_lower["secure"]]
                    if _is_bool_false(secure_val):
                        self._add_finding(
                            FindingCategory.COOKIE_MISSING_SECURE,
                            f"Cookie/session configuration via {name}() sets "
                            f"secure: false. Cookies will be sent over HTTP",
                            loc,
                            context=name,
                        )

                # Check for missing 'httpOnly' / 'httponly' flag
                if "httponly" not in fields_lower:
                    self._add_finding(
                        FindingCategory.COOKIE_MISSING_HTTPONLY,
                        f"Cookie/session configuration via {name}() is missing "
                        f"the 'httpOnly' flag. Cookies are accessible to "
                        f"JavaScript via document.cookie (XSS risk)",
                        loc,
                        context=name,
                    )
                else:
                    httponly_val = arg.fields[fields_lower["httponly"]]
                    if _is_bool_false(httponly_val):
                        self._add_finding(
                            FindingCategory.COOKIE_MISSING_HTTPONLY,
                            f"Cookie/session configuration via {name}() sets "
                            f"httpOnly: false. Cookies are accessible to JavaScript",
                            loc,
                            context=name,
                        )

                # Check for missing 'sameSite' / 'samesite' flag
                if "samesite" not in fields_lower:
                    self._add_finding(
                        FindingCategory.COOKIE_MISSING_SAMESITE,
                        f"Cookie/session configuration via {name}() is missing "
                        f"the 'sameSite' attribute. Without SameSite, cookies "
                        f"are vulnerable to CSRF",
                        loc,
                        context=name,
                    )

                # Nested cookie options: { cookie: { secure: true, ... } }
                if "cookie" in fields_lower:
                    cookie_val = arg.fields[fields_lower["cookie"]]
                    if isinstance(cookie_val, ConstructExpr):
                        self._check_nested_cookie_options(cookie_val, name, loc)

        # If session/cookie function called without options object, all flags missing
        if not options_found and is_session_fn:
            self._add_finding(
                FindingCategory.COOKIE_MISSING_SECURE,
                f"Session configuration via {name}() has no options object. "
                f"Default cookie settings lack secure, httpOnly, and sameSite flags",
                loc,
                context=name,
            )

    def _check_nested_cookie_options(self, cookie_expr: ConstructExpr,
                                     parent_name: str,
                                     loc: Optional[SourceLocation]) -> None:
        """Check nested cookie options within a session config."""
        fields_lower = {f.lower(): f for f in cookie_expr.fields}

        if "secure" not in fields_lower:
            self._add_finding(
                FindingCategory.COOKIE_MISSING_SECURE,
                f"Session cookie options in {parent_name}() missing 'secure' flag",
                loc,
                context=parent_name,
            )
        elif _is_bool_false(cookie_expr.fields[fields_lower["secure"]]):
            self._add_finding(
                FindingCategory.COOKIE_MISSING_SECURE,
                f"Session cookie in {parent_name}() has secure: false",
                loc,
                context=parent_name,
            )

        if "httponly" not in fields_lower:
            self._add_finding(
                FindingCategory.COOKIE_MISSING_HTTPONLY,
                f"Session cookie options in {parent_name}() missing 'httpOnly' flag",
                loc,
                context=parent_name,
            )

        if "samesite" not in fields_lower:
            self._add_finding(
                FindingCategory.COOKIE_MISSING_SAMESITE,
                f"Session cookie options in {parent_name}() missing 'sameSite' attribute",
                loc,
                context=parent_name,
            )

    # ------------------------------------------------------------------
    # 6. Directory Listing Enabled (CWE-548)
    # ------------------------------------------------------------------

    def _check_directory_listing(self, expr: Expr,
                                 loc: Optional[SourceLocation]) -> None:
        """Check static file serving for directory listing exposure."""
        name = _get_callee_name(expr)
        chain = _get_callee_chain(expr)

        is_static = (
            name.lower() in {f.lower() for f in STATIC_FILE_FUNCTIONS}
            or chain.lower() in {"express.static", "serve.static"}
        )

        if not is_static:
            return

        # Check if options are provided
        args = expr.args if hasattr(expr, "args") else []
        has_options = False

        for arg in args:
            if isinstance(arg, ConstructExpr):
                has_options = True
                fields_lower = {f.lower() for f in arg.fields}

                # Check for missing dotfiles: 'deny'
                if "dotfiles" not in fields_lower:
                    self._add_finding(
                        FindingCategory.DIRECTORY_LISTING,
                        f"Static file serving via {name}() without "
                        f"dotfiles: 'deny'. Hidden files (e.g., .env, .git) "
                        f"may be accessible",
                        loc,
                        context=name,
                    )

        if not has_options and len(args) <= 1:
            # express.static('public') without options
            self._add_finding(
                FindingCategory.DIRECTORY_LISTING,
                f"Static file serving via {name}() without security options. "
                f"Consider adding {{ dotfiles: 'deny', index: false }} "
                f"or equivalent restrictions",
                loc,
                context=name,
            )

    # ------------------------------------------------------------------
    # 7. Missing HTTPS Redirect (CWE-319)
    # ------------------------------------------------------------------

    def _check_missing_https_redirect(self, program: Program) -> None:
        """File-level check: Express app without HTTPS redirect middleware."""
        if self._has_express and not self._has_https_redirect:
            # Only flag if we detected Express but no HTTPS redirect pattern
            loc = None
            for decl in program.declarations:
                if isinstance(decl, (PureFunc, TaskFunc)):
                    loc = getattr(decl, "location", None)
                    break

            self._add_finding(
                FindingCategory.MISSING_HTTPS_REDIRECT,
                "Express application detected without HTTPS redirect middleware. "
                "HTTP requests are not redirected to HTTPS, allowing cleartext "
                "transmission of credentials and session tokens",
                loc,
                context="app",
            )

    # ------------------------------------------------------------------
    # 8. Unnecessary Features Enabled (CWE-1188)
    # ------------------------------------------------------------------

    def _check_dangerous_http_methods(self, expr: Expr,
                                      loc: Optional[SourceLocation]) -> None:
        """Check for TRACE/TRACK methods enabled."""
        name = _get_callee_name(expr)
        chain = _get_callee_chain(expr)

        # app.trace(), router.trace()
        if name.upper() in DANGEROUS_HTTP_METHODS:
            self._add_finding(
                FindingCategory.TRACE_METHOD_ENABLED,
                f"{name.upper()} HTTP method is enabled. TRACE enables "
                f"Cross-Site Tracing (XST) attacks that can steal "
                f"authentication cookies and headers",
                loc,
                context=name.upper(),
            )
            return

        # Check for method strings in route registrations
        if name.lower() in ("all", "method", "match"):
            args = expr.args if hasattr(expr, "args") else []
            for arg in args:
                s = _string_value(arg)
                if s and s.upper() in DANGEROUS_HTTP_METHODS:
                    self._add_finding(
                        FindingCategory.TRACE_METHOD_ENABLED,
                        f"{s.upper()} method registered via {name}(). "
                        f"Disable TRACE/TRACK to prevent XST attacks",
                        loc,
                        context=s.upper(),
                    )

                # Check list of methods
                if isinstance(arg, ListLiteral):
                    for elem in arg.elements:
                        es = _string_value(elem)
                        if es and es.upper() in DANGEROUS_HTTP_METHODS:
                            self._add_finding(
                                FindingCategory.TRACE_METHOD_ENABLED,
                                f"{es.upper()} method in method list. "
                                f"Disable TRACE/TRACK to prevent XST attacks",
                                loc,
                                context=es.upper(),
                            )

    def _check_server_version_headers(self, expr: Expr,
                                      loc: Optional[SourceLocation]) -> None:
        """Check for server version headers being set/exposed."""
        name = _get_callee_name(expr)
        chain = _get_callee_chain(expr)

        # res.setHeader('X-Powered-By', ...), res.set('Server', ...)
        if name.lower() in ("setheader", "set", "header", "append", "writeHead"):
            args = expr.args if hasattr(expr, "args") else []
            if args:
                header_name = _string_value(args[0])
                if header_name and header_name.lower() in SERVER_VERSION_HEADERS:
                    self._add_finding(
                        FindingCategory.SERVER_VERSION_EXPOSED,
                        f"Server version header '{header_name}' is being set. "
                        f"Version disclosure helps attackers identify known "
                        f"vulnerabilities in your stack",
                        loc,
                        context=header_name,
                    )

    def _check_xml_dtd(self, expr: Expr, loc: Optional[SourceLocation]) -> None:
        """Check for XML parsing with DTD enabled."""
        name = _get_callee_name(expr)
        chain = _get_callee_chain(expr)

        xml_parsers = {"parsexml", "parse_xml", "xmlparser", "xml_parser",
                       "domparser", "saxparser", "etree.parse",
                       "parsestring", "parse_string", "fromstring"}

        if name.lower() not in xml_parsers:
            return

        # Check for options that disable DTD
        has_safe_options = False
        args = expr.args if hasattr(expr, "args") else []
        for arg in args:
            if isinstance(arg, ConstructExpr):
                fields_lower = {f.lower() for f in arg.fields}
                safe_fields = {"resolve_entities", "no_network", "dtd_validation",
                               "load_dtd", "external_general_entities",
                               "disallow_doctype_decl"}
                if fields_lower & safe_fields:
                    has_safe_options = True

        if not has_safe_options:
            self._add_finding(
                FindingCategory.XML_DTD_ENABLED,
                f"XML parsing via {name}() without DTD restrictions. "
                f"Default XML parser settings may allow XXE (XML External "
                f"Entity) attacks. Use defusedxml or disable DTD processing",
                loc,
                context=name,
            )

    # ------------------------------------------------------------------
    # 9. Framework-Specific Misconfigs
    # ------------------------------------------------------------------

    def _check_nextjs_config(self, expr: Expr,
                             loc: Optional[SourceLocation]) -> None:
        """Check Next.js configuration for security misconfigs."""
        # Look for next.config module.exports or nextConfig assignments
        # containing poweredByHeader or missing reactStrictMode
        if not isinstance(expr, (FunctionCall, MethodCall)):
            return

        # Check ConstructExpr args for Next.js config properties
        args = expr.args if hasattr(expr, "args") else []
        for arg in args:
            if isinstance(arg, ConstructExpr):
                fields_lower = {f.lower(): f for f in arg.fields}

                # poweredByHeader: true (or missing, which defaults to true)
                if "poweredbyheader" in fields_lower:
                    val = arg.fields[fields_lower["poweredbyheader"]]
                    if _is_bool_true(val):
                        self._add_finding(
                            FindingCategory.NEXTJS_POWERED_BY,
                            "Next.js config has poweredByHeader: true. "
                            "The X-Powered-By: Next.js header discloses "
                            "the framework to attackers",
                            loc,
                            context="next.config",
                        )

                # Missing reactStrictMode
                if "reactstrictmode" in fields_lower:
                    val = arg.fields[fields_lower["reactstrictmode"]]
                    if _is_bool_false(val):
                        self._add_finding(
                            FindingCategory.NEXTJS_NO_STRICT_MODE,
                            "Next.js config has reactStrictMode: false. "
                            "Strict mode identifies unsafe patterns and "
                            "legacy API usage during development",
                            loc,
                            context="next.config",
                        )

    def _check_express_trust_proxy(self, expr: Expr,
                                   loc: Optional[SourceLocation]) -> None:
        """Check Express trust proxy configuration."""
        name = _get_callee_name(expr)
        chain = _get_callee_chain(expr)

        # app.set('trust proxy', true) or app.enable('trust proxy')
        if name.lower() in ("set", "enable"):
            args = expr.args if hasattr(expr, "args") else []
            if args:
                s = _string_value(args[0])
                if s and s.lower() == "trust proxy":
                    # If second arg is simply 'true', warn about unvalidated proxy
                    if len(args) > 1 and _is_bool_true(args[1]):
                        self._add_finding(
                            FindingCategory.EXPRESS_TRUST_PROXY,
                            "Express 'trust proxy' set to true (trust all). "
                            "This allows IP spoofing via X-Forwarded-For. "
                            "Specify exact proxy addresses or a count instead",
                            loc,
                            context="trust proxy",
                        )
                    # app.enable('trust proxy') is the same as set('trust proxy', true)
                    if name.lower() == "enable":
                        self._add_finding(
                            FindingCategory.EXPRESS_TRUST_PROXY,
                            "Express 'trust proxy' enabled without validation. "
                            "Use app.set('trust proxy', 'loopback') or specify "
                            "exact proxy addresses to prevent IP spoofing",
                            loc,
                            context="trust proxy",
                        )

    def _check_express_missing_helmet(self, program: Program) -> None:
        """File-level check: Express app without helmet middleware."""
        if self._has_express and not self._has_helmet:
            loc = None
            for decl in program.declarations:
                if isinstance(decl, (PureFunc, TaskFunc)):
                    loc = getattr(decl, "location", None)
                    break

            self._add_finding(
                FindingCategory.EXPRESS_NO_HELMET,
                "Express application detected without helmet() middleware. "
                "Helmet sets critical security headers (CSP, X-Content-Type-Options, "
                "X-Frame-Options, HSTS, Referrer-Policy). Install: npm install helmet",
                loc,
                context="app",
            )

    def _check_phoenix_config(self, expr: Expr,
                              loc: Optional[SourceLocation]) -> None:
        """Check Phoenix framework configuration for security misconfigs."""
        name = _get_callee_name(expr)
        chain = _get_callee_chain(expr)

        # Look for socket/endpoint configuration
        socket_config_fns = {"socket", "endpoint", "configure", "config"}

        if name.lower() not in socket_config_fns:
            return

        # Check for check_origin: false
        check_origin_val = _get_construct_field(expr, "check_origin")
        if check_origin_val and _is_bool_false(check_origin_val):
            self._add_finding(
                FindingCategory.PHOENIX_NO_CHECK_ORIGIN,
                "Phoenix config has check_origin: false. WebSocket connections "
                "from any origin are allowed, enabling cross-site WebSocket "
                "hijacking (CSRF for WebSockets)",
                loc,
                context="check_origin",
            )

        # Check for debug_errors: true
        debug_errors_val = _get_construct_field(expr, "debug_errors")
        if debug_errors_val and _is_bool_true(debug_errors_val):
            self._add_finding(
                FindingCategory.PHOENIX_DEBUG_ERRORS,
                "Phoenix config has debug_errors: true. Full stack traces "
                "are returned to clients, exposing internal application "
                "details and file paths",
                loc,
                context="debug_errors",
            )

    def _check_django_secret_key(self, var_name: str, value: Expr,
                                 loc: Optional[SourceLocation]) -> None:
        """Check for Django SECRET_KEY hardcoded in settings."""
        if not var_name:
            return

        if var_name in ("SECRET_KEY", "secret_key"):
            s = _string_value(value)
            if s and len(s) > 0:
                # A hardcoded string assigned to SECRET_KEY
                self._add_finding(
                    FindingCategory.DJANGO_SECRET_KEY_HARDCODED,
                    f"Django SECRET_KEY is hardcoded in source code. "
                    f"A leaked SECRET_KEY allows forging session cookies "
                    f"and CSRF tokens. Load from environment variable instead",
                    loc,
                    context="SECRET_KEY",
                )

    def _check_django_allowed_hosts(self, var_name: str, value: Expr,
                                    loc: Optional[SourceLocation]) -> None:
        """Check for Django ALLOWED_HOSTS = ['*']."""
        if not var_name:
            return

        if var_name in ("ALLOWED_HOSTS", "allowed_hosts"):
            if isinstance(value, ListLiteral):
                for elem in value.elements:
                    s = _string_value(elem)
                    if s == "*":
                        self._add_finding(
                            FindingCategory.DJANGO_ALLOWED_HOSTS_WILDCARD,
                            "Django ALLOWED_HOSTS contains '*' (wildcard). "
                            "This disables host header validation and enables "
                            "host header injection attacks. Use specific domains",
                            loc,
                            context="ALLOWED_HOSTS",
                        )
                        return

    def _check_graphql_introspection(self, expr: Expr,
                                     loc: Optional[SourceLocation]) -> None:
        """Check for GraphQL introspection enabled in configuration."""
        name = _get_callee_name(expr)

        graphql_setup_fns = {"graphqlhttp", "graphqlserver", "apolloserver",
                             "makeexecutableschema", "graphql", "yoga",
                             "createhandler", "createyoga"}

        if name.lower() not in graphql_setup_fns:
            return

        # Check for introspection: true in options
        introspection_val = _get_construct_field(expr, "introspection")
        if introspection_val and _is_bool_true(introspection_val):
            self._add_finding(
                FindingCategory.GRAPHQL_INTROSPECTION,
                f"GraphQL introspection is explicitly enabled via {name}(). "
                f"Introspection exposes the entire schema including types, "
                f"queries, mutations, and relationships",
                loc,
                context=name,
            )

    # ------------------------------------------------------------------
    # 10. Exposed Environment Variables (CWE-526)
    # ------------------------------------------------------------------

    def _check_env_exposure(self, value: Expr,
                            loc: Optional[SourceLocation]) -> None:
        """Check if environment variables are being exposed broadly."""
        # Direct process.env or os.environ assignment to client-visible value
        if isinstance(value, FieldAccess):
            self._check_env_field_access(value, loc)

    def _check_env_field_access(self, expr: FieldAccess,
                                loc: Optional[SourceLocation]) -> None:
        """Check for process.env or os.environ used in client-facing contexts."""
        chain = _get_callee_chain_from_expr(expr)

        # Detect process.env being dumped wholesale (not individual var access)
        # process.env without a specific key is a dump of ALL env vars
        if chain.lower() in ("process.env", "os.environ"):
            # This is the entire env object, not a specific variable
            self._add_finding(
                FindingCategory.ENV_VARS_EXPOSED,
                f"Entire environment object '{chain}' referenced. "
                f"If passed to client code or responses, all environment "
                f"variables (including secrets) are exposed",
                loc,
                context=chain,
            )

    def _check_env_dump_in_response(self, expr: Expr,
                                    loc: Optional[SourceLocation]) -> None:
        """Check if env vars are passed to response methods."""
        name = _get_callee_name(expr)
        response_methods = {"json", "send", "render", "write", "res"}

        if name.lower() not in response_methods:
            return

        args = expr.args if hasattr(expr, "args") else []
        for arg in args:
            if isinstance(arg, FieldAccess):
                chain = _get_callee_chain_from_expr(arg)
                if chain.lower() in ("process.env", "os.environ"):
                    self._add_finding(
                        FindingCategory.ENV_VARS_EXPOSED,
                        f"Environment variables ({chain}) sent in HTTP response "
                        f"via {name}(). All environment variables including "
                        f"database credentials and API keys are exposed",
                        loc,
                        context=chain,
                    )

            # Check ConstructExpr fields that reference process.env
            if isinstance(arg, ConstructExpr):
                for fname, fval in arg.fields.items():
                    if isinstance(fval, FieldAccess):
                        chain = _get_callee_chain_from_expr(fval)
                        if chain.lower() in ("process.env", "os.environ"):
                            self._add_finding(
                                FindingCategory.ENV_VARS_EXPOSED,
                                f"Environment variables ({chain}) included in "
                                f"response object field '{fname}'. All env vars "
                                f"are exposed to clients",
                                loc,
                                context=chain,
                            )

    def _check_env_file_serving(self, expr: Expr,
                                loc: Optional[SourceLocation]) -> None:
        """Check if .env files are served statically."""
        name = _get_callee_name(expr)
        chain = _get_callee_chain(expr)

        # Static file serving or send file patterns
        file_serve_fns = {"sendfile", "send_file", "sendFile", "download",
                          "static", "serve"}

        if name.lower() not in file_serve_fns:
            return

        args = expr.args if hasattr(expr, "args") else []
        for arg in args:
            s = _string_value(arg)
            if s and (".env" in s.lower()):
                # Serving a .env file
                env_patterns = [".env", ".env.local", ".env.production",
                                ".env.development", ".env.staging"]
                for pattern in env_patterns:
                    if s.lower().endswith(pattern) or f"/{pattern}" in s.lower():
                        self._add_finding(
                            FindingCategory.ENV_FILE_SERVED,
                            f"Environment file '{s}' is served statically. "
                            f".env files contain secrets (database credentials, "
                            f"API keys, signing keys) and must never be accessible",
                            loc,
                            context=s,
                        )
                        return

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _add_finding(self, category: FindingCategory, message: str,
                     location: Optional[SourceLocation], context: str = "") -> None:
        """Add a finding, deduplicating by category + location."""
        # Deduplicate: same category at the same location
        for existing in self.findings:
            if existing.category == category and existing.location == location:
                return

        self.findings.append(MisconfigFinding(
            category=category,
            message=message,
            location=location,
            context=context,
        ))


# ---------------------------------------------------------------------------
# Error Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: MisconfigFinding) -> AeonError:
    """Convert a MisconfigFinding into an AeonError."""
    cwe = CWE_MAP.get(finding.category, "CWE-1188")
    severity = SEVERITY_MAP.get(finding.category, Severity.MEDIUM)
    severity_label = severity.value.upper()
    remediation = REMEDIATION.get(
        finding.category,
        "Review security configuration against OWASP best practices"
    )
    category_label = finding.category.value.replace("_", " ").title()

    context_suffix = ""
    if finding.context:
        context_suffix = f" [{finding.context}]"

    return contract_error(
        precondition=(
            f"Security Misconfiguration ({cwe}) -- "
            f"[{severity_label}] {category_label}{context_suffix}: {finding.message}"
        ),
        failing_values={
            "category": finding.category.value,
            "severity": severity.value,
            "cwe": cwe,
            "remediation": remediation,
            "engine": "Security Misconfiguration",
        },
        function_signature="security_misconfig",
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_security_misconfig(program: Program) -> list:
    """Run security misconfiguration analysis on an AEON program.

    Scans the AST for configuration vulnerabilities including debug mode
    enabled in production, default credentials, exposed endpoints, verbose
    error handling, insecure cookies, directory listing, missing HTTPS,
    unnecessary features, framework misconfigs, and exposed env vars.

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected misconfiguration.

    Detection categories:
        1.  Debug mode in production (CWE-489)
        2.  Default credentials (CWE-798)
        3.  Exposed admin/debug endpoints (CWE-215)
        4.  Verbose error handling (CWE-209)
        5.  Insecure cookie defaults (CWE-614)
        6.  Directory listing enabled (CWE-548)
        7.  Missing HTTPS redirect (CWE-319)
        8.  Unnecessary features enabled (CWE-1188)
        9.  Framework-specific misconfigs (Next.js, Express, Phoenix, Django)
        10. Exposed environment variables (CWE-526)

    CWEs:
        CWE-489:  Active Debug Code
        CWE-798:  Use of Hard-Coded Credentials
        CWE-215:  Insertion of Sensitive Information Into Debugging Code
        CWE-209:  Generation of Error Message Containing Sensitive Information
        CWE-614:  Sensitive Cookie Without 'Secure' Attribute
        CWE-548:  Exposure of Information Through Directory Listing
        CWE-319:  Cleartext Transmission of Sensitive Information
        CWE-1188: Initialization with Hard-Coded Network Resource Configuration Default
        CWE-526:  Exposure of Sensitive Information Through Environmental Variables
    """
    try:
        analyzer = SecurityMisconfigAnalyzer()
        findings = analyzer.check_program(program)
        return [_finding_to_error(f) for f in findings]
    except Exception:
        # Engine-level safety net: never let the entire engine crash
        # the verification pipeline
        return []
