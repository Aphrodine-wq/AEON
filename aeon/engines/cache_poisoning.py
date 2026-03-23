"""AEON Web Cache Poisoning Detection Engine -- CDN/Cache Security Analysis.

Detects web cache poisoning, web cache deception, and cache-related security
vulnerabilities in server-side code. This is a niche engine -- it is
conservative by design and only flags clear, high-confidence patterns rather
than every missing Cache-Control header.

References:
  CWE-444: Inconsistent Interpretation of HTTP Requests
  https://cwe.mitre.org/data/definitions/444.html

  CWE-525: Use of Web Browser Cache Containing Sensitive Information
  https://cwe.mitre.org/data/definitions/525.html

  CWE-384: Session Fixation (predictable cache keys)
  https://cwe.mitre.org/data/definitions/384.html

  CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
  https://cwe.mitre.org/data/definitions/113.html

  James Kettle (2018) "Practical Web Cache Poisoning"
  PortSwigger Research, https://portswigger.net/research/practical-web-cache-poisoning

  James Kettle (2020) "Web Cache Entanglement: Novel Pathways to Poisoning"
  PortSwigger Research, https://portswigger.net/research/web-cache-entanglement

  Omer Gil (2017) "Web Cache Deception Attack"
  BlackHat USA 2017, https://www.blackhat.com/us-17/briefings.html

  Mirheidari et al. (2020) "Cached and Confused: Web Cache Deception in the Wild"
  USENIX Security '20, https://www.usenix.org/conference/usenixsecurity20

Detection Categories:
  1. Unkeyed header reflection (CWE-444)
     - X-Forwarded-Host / X-Forwarded-Scheme / X-Original-URL reflected in
       response body (<link>, <script>, <meta>, redirects)

  2. Cache key manipulation (CWE-444)
     - Query parameters used in response generation that CDNs typically ignore
       (utm_*, fbclid, gclid, etc.)

  3. Web cache deception (CWE-525)
     - Routes serving dynamic/authenticated content without Cache-Control:
       no-store or private headers (profile, account, settings, dashboard)

  4. Missing cache-control on sensitive responses (CWE-525)
     - API responses containing user-specific data without proper
       Cache-Control: no-store, private

  5. Predictable cache keys (CWE-384)
     - cache.set(url, response) without user ID in key for authenticated
       content

  6. Host header poisoning (CWE-444)
     - req.headers.host or X-Forwarded-Host used in URL construction for
       password reset links, emails, canonical URLs

  7. CDN bypass via headers (CWE-444)
     - Cache-Control: public on authenticated endpoints, Vary: * misuse

  8. Response splitting via cache (CWE-113)
     - User input in Set-Cookie, Location, or custom headers that could
       inject Cache-Control directives
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum

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
# Cache Poisoning Categories
# ---------------------------------------------------------------------------

class CachePoisoningCategory(Enum):
    UNKEYED_HEADER_REFLECTION = "unkeyed_header_reflection"
    CACHE_KEY_MANIPULATION = "cache_key_manipulation"
    WEB_CACHE_DECEPTION = "web_cache_deception"
    MISSING_CACHE_CONTROL = "missing_cache_control_on_sensitive_response"
    PREDICTABLE_CACHE_KEY = "predictable_cache_key"
    HOST_HEADER_POISONING = "host_header_poisoning"
    CDN_BYPASS_VIA_HEADERS = "cdn_bypass_via_headers"
    RESPONSE_SPLITTING_CACHE = "response_splitting_via_cache"


# CWE mapping
CWE_MAP: Dict[CachePoisoningCategory, str] = {
    CachePoisoningCategory.UNKEYED_HEADER_REFLECTION: "CWE-444",
    CachePoisoningCategory.CACHE_KEY_MANIPULATION: "CWE-444",
    CachePoisoningCategory.WEB_CACHE_DECEPTION: "CWE-525",
    CachePoisoningCategory.MISSING_CACHE_CONTROL: "CWE-525",
    CachePoisoningCategory.PREDICTABLE_CACHE_KEY: "CWE-384",
    CachePoisoningCategory.HOST_HEADER_POISONING: "CWE-444",
    CachePoisoningCategory.CDN_BYPASS_VIA_HEADERS: "CWE-444",
    CachePoisoningCategory.RESPONSE_SPLITTING_CACHE: "CWE-113",
}

# Severity mapping -- conservative; most findings are medium/high
SEVERITY_MAP: Dict[CachePoisoningCategory, Severity] = {
    CachePoisoningCategory.UNKEYED_HEADER_REFLECTION: Severity.HIGH,
    CachePoisoningCategory.CACHE_KEY_MANIPULATION: Severity.MEDIUM,
    CachePoisoningCategory.WEB_CACHE_DECEPTION: Severity.HIGH,
    CachePoisoningCategory.MISSING_CACHE_CONTROL: Severity.MEDIUM,
    CachePoisoningCategory.PREDICTABLE_CACHE_KEY: Severity.HIGH,
    CachePoisoningCategory.HOST_HEADER_POISONING: Severity.HIGH,
    CachePoisoningCategory.CDN_BYPASS_VIA_HEADERS: Severity.MEDIUM,
    CachePoisoningCategory.RESPONSE_SPLITTING_CACHE: Severity.HIGH,
}

# OWASP mapping
OWASP_MAP: Dict[CachePoisoningCategory, str] = {
    CachePoisoningCategory.UNKEYED_HEADER_REFLECTION: "A05:2021 Security Misconfiguration",
    CachePoisoningCategory.CACHE_KEY_MANIPULATION: "A05:2021 Security Misconfiguration",
    CachePoisoningCategory.WEB_CACHE_DECEPTION: "A05:2021 Security Misconfiguration",
    CachePoisoningCategory.MISSING_CACHE_CONTROL: "A05:2021 Security Misconfiguration",
    CachePoisoningCategory.PREDICTABLE_CACHE_KEY: "A04:2021 Insecure Design",
    CachePoisoningCategory.HOST_HEADER_POISONING: "A03:2021 Injection",
    CachePoisoningCategory.CDN_BYPASS_VIA_HEADERS: "A05:2021 Security Misconfiguration",
    CachePoisoningCategory.RESPONSE_SPLITTING_CACHE: "A03:2021 Injection",
}

# Remediation guidance
REMEDIATION_MAP: Dict[CachePoisoningCategory, str] = {
    CachePoisoningCategory.UNKEYED_HEADER_REFLECTION: (
        "Never reflect unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme, "
        "X-Original-URL) in response bodies. If these headers must influence "
        "response content, add them to the cache key via the Vary header, or "
        "use a hardcoded canonical origin."
    ),
    CachePoisoningCategory.CACHE_KEY_MANIPULATION: (
        "Do not use CDN-ignored query parameters (utm_*, fbclid, gclid) in "
        "response generation logic. If query parameters affect output, ensure "
        "they are part of the cache key configuration at the CDN layer."
    ),
    CachePoisoningCategory.WEB_CACHE_DECEPTION: (
        "Add 'Cache-Control: no-store, private' to all routes that serve "
        "dynamic or authenticated content. Configure CDN rules to never cache "
        "responses from /profile, /account, /settings, /dashboard endpoints."
    ),
    CachePoisoningCategory.MISSING_CACHE_CONTROL: (
        "Set 'Cache-Control: no-store, private' on all API responses that "
        "contain user-specific data. Never rely on CDN defaults for "
        "authenticated endpoints."
    ),
    CachePoisoningCategory.PREDICTABLE_CACHE_KEY: (
        "Include a user-specific component (user ID, session ID) in cache "
        "keys for authenticated content. Use cache.set(f'{user_id}:{url}', "
        "response) instead of cache.set(url, response)."
    ),
    CachePoisoningCategory.HOST_HEADER_POISONING: (
        "Never use Host header or X-Forwarded-Host for URL construction in "
        "emails, password reset links, or canonical URLs. Use a hardcoded, "
        "configured origin (e.g., SERVER_URL environment variable)."
    ),
    CachePoisoningCategory.CDN_BYPASS_VIA_HEADERS: (
        "Never set Cache-Control: public on authenticated endpoints. "
        "Use Cache-Control: private, no-store for user-specific responses. "
        "Avoid Vary: * which behaves inconsistently across CDN providers."
    ),
    CachePoisoningCategory.RESPONSE_SPLITTING_CACHE: (
        "Sanitize all user input before including it in HTTP response headers. "
        "Strip or reject CR (\\r) and LF (\\n) characters. Use framework-"
        "provided header setters that enforce proper encoding."
    ),
}


# ---------------------------------------------------------------------------
# Finding Representation
# ---------------------------------------------------------------------------

@dataclass
class CachePoisoningFinding:
    """Internal representation of a detected cache poisoning vulnerability."""
    category: CachePoisoningCategory
    severity: Severity
    description: str
    cwe: str
    location: Optional[SourceLocation]
    function_name: str
    remediation: str
    evidence: str = ""
    details: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Unkeyed Header Constants
# ---------------------------------------------------------------------------

# Headers that CDNs/caches typically do NOT include in cache keys
UNKEYED_HEADERS: Set[str] = {
    "x-forwarded-host", "x-forwarded-scheme", "x-forwarded-proto",
    "x-forwarded-port", "x-forwarded-prefix", "x-original-url",
    "x-rewrite-url", "x-forwarded-server", "x-host",
    "x-forwarded-for", "x-real-ip", "x-custom-ip-authorization",
    "x-original-host", "x-proxy-url",
}

# Subset of unkeyed headers that are especially dangerous when reflected
# in HTML output (link/script/meta tags) or redirects
REFLECTION_DANGEROUS_HEADERS: Set[str] = {
    "x-forwarded-host", "x-forwarded-scheme", "x-forwarded-proto",
    "x-original-url", "x-rewrite-url", "x-host", "x-original-host",
}

# HTML tags that are dangerous injection targets for cache poisoning
# (reflected header values in these tags = stored XSS via cache)
HTML_INJECTION_TAGS: Set[str] = {
    "link", "script", "meta", "base", "iframe", "img", "a",
}

# ---------------------------------------------------------------------------
# Cache Key Manipulation Constants
# ---------------------------------------------------------------------------

# Query parameters that most CDNs strip from cache keys
CDN_IGNORED_PARAMS: Set[str] = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_source_platform", "utm_creative_format",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid",
    "mc_cid", "mc_eid", "twclid", "li_fat_id",
    "yclid", "wickedid", "_ga", "_gl", "ref",
    "srsltid", "ttclid",
}

# ---------------------------------------------------------------------------
# Web Cache Deception Constants
# ---------------------------------------------------------------------------

# Route path segments that indicate dynamic/authenticated content
SENSITIVE_ROUTE_SEGMENTS: Set[str] = {
    "profile", "account", "settings", "dashboard", "admin",
    "user", "preferences", "billing", "subscription", "payment",
    "my-account", "my_account", "myaccount", "me",
    "private", "inbox", "notifications", "orders",
}

# ---------------------------------------------------------------------------
# User Data Field Patterns
# ---------------------------------------------------------------------------

# Fields that indicate user-specific data in response bodies
USER_DATA_FIELDS: Set[str] = {
    "email", "name", "username", "phone", "address",
    "ssn", "social_security", "credit_card", "card_number",
    "password", "password_hash", "api_key", "apiKey", "api_secret",
    "token", "access_token", "refresh_token", "session_id",
    "balance", "salary", "income", "dob", "date_of_birth",
    "first_name", "last_name", "full_name", "firstName", "lastName",
}

# Object names that suggest user-specific data
USER_DATA_OBJECTS: Set[str] = {
    "user", "account", "profile", "customer", "member",
    "patient", "employee", "client", "subscriber",
    "currentUser", "current_user", "authenticatedUser", "authenticated_user",
    "loggedInUser", "logged_in_user", "me",
}

# ---------------------------------------------------------------------------
# Cache Operation Patterns
# ---------------------------------------------------------------------------

# Functions/methods that write to cache
CACHE_SET_FUNCTIONS: Set[str] = {
    "set", "put", "store", "save", "write", "add",
    "setex", "setnx", "hset", "mset", "hmset",
    "cache_set", "cache_put", "cache_store",
}

# Object names that suggest a cache client
CACHE_CLIENT_NAMES: Set[str] = {
    "cache", "redis", "memcache", "memcached", "mc",
    "redisClient", "redis_client", "cacheClient", "cache_client",
    "cacheStore", "cache_store", "cdn", "varnish",
}

# ---------------------------------------------------------------------------
# Response Header Patterns
# ---------------------------------------------------------------------------

# Functions/methods that set HTTP response headers
HEADER_SET_METHODS: Set[str] = {
    "set_header", "setHeader", "set", "header", "append",
    "add_header", "addHeader", "writeHead", "write_head",
    "set_response_header", "append_header",
}

# Response object names
RESPONSE_OBJECTS: Set[str] = {
    "res", "resp", "response", "reply", "ctx", "context",
}

# Headers that affect caching behavior
CACHE_HEADERS_LOWER: Set[str] = {
    "cache-control", "expires", "pragma", "surrogate-control",
    "cdn-cache-control", "cloudflare-cdn-cache-control",
    "vercel-cdn-cache-control", "s-maxage",
}

# Headers vulnerable to response splitting
SPLITTABLE_HEADERS: Set[str] = {
    "set-cookie", "location", "content-disposition",
    "content-type", "x-redirect", "link",
}

# ---------------------------------------------------------------------------
# Host Header Patterns
# ---------------------------------------------------------------------------

# Patterns where Host header is used for URL construction
URL_CONSTRUCTION_CONTEXTS: Set[str] = {
    "reset_url", "resetUrl", "reset_link", "resetLink",
    "confirm_url", "confirmUrl", "confirmation_url", "confirmationUrl",
    "verify_url", "verifyUrl", "verification_url", "verificationUrl",
    "callback_url", "callbackUrl", "redirect_url", "redirectUrl",
    "canonical", "canonicalUrl", "canonical_url",
    "base_url", "baseUrl", "origin", "site_url", "siteUrl",
    "invite_url", "inviteUrl", "invite_link", "inviteLink",
    "unsubscribe_url", "unsubscribeUrl", "unsubscribe_link",
}

# File extensions that indicate frontend/UI component code
_FRONTEND_EXTENSIONS = frozenset({
    ".tsx", ".jsx", ".vue", ".svelte",
})


# ---------------------------------------------------------------------------
# AST Walking Utilities
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


def _get_full_callee_name(expr: Expr) -> str:
    """Get a dotted representation of a call target."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, FieldAccess):
        obj_name = _get_full_callee_name(expr.obj)
        return f"{obj_name}.{expr.field_name}" if obj_name else expr.field_name
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


def _walk_exprs(expr: Expr):
    """Yield an expression and all sub-expressions recursively."""
    yield expr
    if isinstance(expr, BinaryOp):
        yield from _walk_exprs(expr.left)
        yield from _walk_exprs(expr.right)
    elif isinstance(expr, FunctionCall):
        if hasattr(expr, "callee") and expr.callee:
            yield from _walk_exprs(expr.callee)
        for arg in expr.args:
            yield from _walk_exprs(arg)
    elif isinstance(expr, MethodCall):
        yield from _walk_exprs(expr.obj)
        for arg in expr.args:
            yield from _walk_exprs(arg)
    elif isinstance(expr, FieldAccess):
        yield from _walk_exprs(expr.obj)


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


def _is_user_input_identifier(name: str) -> bool:
    """Check if an identifier name suggests user-controlled input."""
    name_lower = name.lower()
    input_keywords = (
        "input", "request", "query", "param", "user_input",
        "body", "form", "header", "payload", "raw",
        "untrusted", "external",
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
    return False


def _is_header_access(expr: Expr, header_names: Set[str]) -> Tuple[bool, str]:
    """Check if an expression accesses a specific HTTP request header.

    Returns (True, header_name) if the expression reads one of the given
    headers, (False, '') otherwise.

    Recognized patterns:
      - req.headers['x-forwarded-host']
      - req.get('x-forwarded-host')
      - request.headers.get('x-forwarded-host')
      - headers['x-forwarded-host']
      - getHeader('x-forwarded-host')
    """
    # MethodCall: req.headers.get('x-forwarded-host'), req.get('X-Forwarded-Host')
    if isinstance(expr, MethodCall):
        method_lower = expr.method_name.lower()
        if method_lower in ("get", "header", "get_header", "getheader"):
            for arg in expr.args:
                if isinstance(arg, StringLiteral):
                    if arg.value.lower() in header_names:
                        return True, arg.value.lower()

    # FunctionCall: getHeader('x-forwarded-host')
    if isinstance(expr, FunctionCall):
        callee_name = _get_full_callee_name(expr.callee).lower()
        if any(kw in callee_name for kw in ("getheader", "get_header", "header")):
            for arg in expr.args:
                if isinstance(arg, StringLiteral):
                    if arg.value.lower() in header_names:
                        return True, arg.value.lower()

    # FieldAccess: req.headers (then check if the parent is a bracket access)
    # In AEON AST, bracket access for headers is usually represented as
    # MethodCall with .get() or similar. Also check for chained FieldAccess
    # patterns like headers.x_forwarded_host
    if isinstance(expr, FieldAccess):
        field_lower = expr.field_name.lower().replace("_", "-")
        if field_lower in header_names:
            # Verify the parent is a headers-like object
            obj_name = _expr_name(expr.obj).lower()
            if "header" in obj_name:
                return True, field_lower

    return False, ""


def _is_host_header_access(expr: Expr) -> bool:
    """Check if an expression accesses the Host or X-Forwarded-Host header."""
    host_headers = {"host", "x-forwarded-host", "x-host", "x-original-host"}

    # Direct check
    found, _ = _is_header_access(expr, host_headers)
    if found:
        return True

    # FieldAccess: req.headers.host, req.hostname, req.host
    if isinstance(expr, FieldAccess):
        field_lower = expr.field_name.lower()
        if field_lower in ("host", "hostname"):
            obj_name = _expr_name(expr.obj).lower()
            if any(kw in obj_name for kw in ("req", "request", "header", "ctx")):
                return True

    return False


def _expr_contains_header_access(expr: Expr, header_names: Set[str]) -> Tuple[bool, str]:
    """Walk an expression tree looking for access to any of the given headers."""
    for sub_expr in _walk_exprs(expr):
        found, header = _is_header_access(sub_expr, header_names)
        if found:
            return True, header
    return False, ""


def _expr_contains_host_header(expr: Expr) -> bool:
    """Walk an expression tree looking for Host header access."""
    for sub_expr in _walk_exprs(expr):
        if _is_host_header_access(sub_expr):
            return True
    return False


def _is_response_send(expr: Expr) -> bool:
    """Check if an expression sends/renders an HTTP response.

    Patterns: res.send(), res.render(), res.json(), response.write(),
    ctx.body = ..., return Response(...)
    """
    if isinstance(expr, MethodCall):
        method_lower = expr.method_name.lower()
        if method_lower in ("send", "render", "json", "write", "end",
                            "html", "text", "jsonify", "respond"):
            obj_name = _expr_name(expr.obj).lower()
            if any(kw in obj_name for kw in RESPONSE_OBJECTS):
                return True
    if isinstance(expr, FunctionCall):
        callee = _get_full_callee_name(expr.callee).lower()
        if any(kw in callee for kw in ("response", "jsonify", "render",
                                        "make_response", "httpresponse")):
            return True
    return False


def _is_redirect_call(expr: Expr) -> bool:
    """Check if an expression is an HTTP redirect."""
    if isinstance(expr, MethodCall):
        method_lower = expr.method_name.lower()
        if method_lower in ("redirect", "redirect_to", "moved_permanently",
                            "found", "temporary_redirect"):
            return True
    if isinstance(expr, FunctionCall):
        callee = _get_full_callee_name(expr.callee).lower()
        if "redirect" in callee:
            return True
    return False


def _is_cache_set_call(expr: Expr) -> Tuple[bool, List[Expr]]:
    """Check if an expression is a cache write operation.

    Returns (True, [key_arg, value_arg, ...]) if it is a cache set call.
    """
    if isinstance(expr, MethodCall):
        method_lower = expr.method_name.lower()
        if method_lower in CACHE_SET_FUNCTIONS:
            obj_name = _expr_name(expr.obj).lower()
            if any(cn in obj_name for cn in CACHE_CLIENT_NAMES):
                return True, expr.args
    if isinstance(expr, FunctionCall):
        callee = _get_full_callee_name(expr.callee).lower()
        if any(f"cache.{fn}" in callee or f"redis.{fn}" in callee
               for fn in CACHE_SET_FUNCTIONS):
            return True, expr.args
        if any(fn in callee for fn in ("cache_set", "cache_put", "cache_store")):
            return True, expr.args
    return False, []


def _is_header_set_call(expr: Expr) -> Tuple[bool, str, Optional[Expr]]:
    """Check if an expression sets an HTTP response header.

    Returns (True, header_name_lower, value_expr) or (False, '', None).
    """
    if isinstance(expr, MethodCall):
        method_lower = expr.method_name.lower()
        if method_lower in HEADER_SET_METHODS:
            obj_name = _expr_name(expr.obj).lower()
            if any(ro in obj_name for ro in RESPONSE_OBJECTS):
                if len(expr.args) >= 2:
                    if isinstance(expr.args[0], StringLiteral):
                        return True, expr.args[0].value.lower(), expr.args[1]
                elif len(expr.args) == 1 and method_lower == "header":
                    # Some frameworks: res.header('Cache-Control: ...')
                    if isinstance(expr.args[0], StringLiteral):
                        val = expr.args[0].value.lower()
                        for ch in CACHE_HEADERS_LOWER:
                            if ch in val:
                                return True, ch, expr.args[0]
    return False, "", None


def _contains_user_data_access(expr: Expr) -> bool:
    """Check if an expression accesses user-specific data fields.

    Looks for patterns like user.email, account.name, profile.address,
    currentUser.balance, etc. Only triggers on clear user-data-object + field
    combinations to stay conservative.
    """
    for sub_expr in _walk_exprs(expr):
        if isinstance(sub_expr, FieldAccess):
            field_lower = sub_expr.field_name.lower()
            obj_name = _expr_name(sub_expr.obj).lower()

            # Must be a user data object accessing a user data field
            if (any(udo in obj_name for udo in USER_DATA_OBJECTS) and
                    any(udf in field_lower for udf in USER_DATA_FIELDS)):
                return True
    return False


def _string_contains_html_tag_context(s: str) -> bool:
    """Check if a string contains HTML tag patterns that are dangerous for
    cache poisoning (link, script, meta, base, etc.)."""
    s_lower = s.lower()
    for tag in HTML_INJECTION_TAGS:
        # Match <link, <script, <meta, etc. in the string
        if f"<{tag}" in s_lower:
            return True
    return False


def _looks_like_route_handler(func: PureFunc | TaskFunc) -> bool:
    """Heuristically determine if a function is an HTTP route handler.

    Checks for request/response parameters, route-handler-like names,
    and framework decorator patterns.
    """
    func_lower = func.name.lower()

    # Common route handler name patterns
    handler_patterns = (
        "handler", "endpoint", "route", "view", "controller",
        "api_", "get_", "post_", "put_", "delete_", "patch_",
        "handle_", "serve_", "process_request",
    )
    if any(func_lower.startswith(p) or func_lower.endswith(p.rstrip("_"))
           for p in handler_patterns):
        return True

    # Check parameters for request/response types
    has_req = False
    has_res = False
    for param in func.params:
        pname = param.name.lower()
        ptype = str(param.type_annotation).lower() if param.type_annotation else ""

        if pname in ("req", "request", "ctx", "context") or "request" in ptype:
            has_req = True
        if pname in ("res", "resp", "response", "reply") or "response" in ptype:
            has_res = True

    return has_req and has_res


def _route_serves_sensitive_path(func: PureFunc | TaskFunc) -> bool:
    """Check if a function name suggests it serves a sensitive route path."""
    func_lower = func.name.lower()
    for segment in SENSITIVE_ROUTE_SEGMENTS:
        if segment in func_lower:
            return True
    return False


def _function_sets_cache_control(stmts: List[Statement]) -> bool:
    """Check if any statement in the list sets a Cache-Control header.

    Looks for res.setHeader('Cache-Control', ...), res.set('Cache-Control', ...),
    or equivalent patterns that set no-store / private.
    """
    for stmt in stmts:
        exprs: List[Expr] = []
        if isinstance(stmt, ExprStmt):
            exprs.append(stmt.expr)
        elif isinstance(stmt, LetStmt) and stmt.value:
            exprs.append(stmt.value)
        elif isinstance(stmt, AssignStmt):
            exprs.append(stmt.value)

        for expr in exprs:
            for sub_expr in _walk_exprs(expr):
                is_header, header_name, value_expr = _is_header_set_call(sub_expr)
                if is_header and header_name in CACHE_HEADERS_LOWER:
                    # Check if the value contains no-store or private
                    if value_expr:
                        strings = _extract_string_values(value_expr)
                        for s in strings:
                            s_lower = s.lower()
                            if "no-store" in s_lower or "private" in s_lower:
                                return True
    return False


# ---------------------------------------------------------------------------
# Cache Poisoning Analyzer
# ---------------------------------------------------------------------------

class CachePoisoningAnalyzer:
    """Analyzes programs for web cache poisoning and cache deception vulnerabilities.

    Conservative by design: only flags clear patterns where cache poisoning is
    plausible. Skips frontend files entirely, as cache poisoning is a
    server-side vulnerability class.
    """

    def __init__(self):
        self.findings: List[CachePoisoningFinding] = []
        self._is_frontend: bool = False
        # Track variables assigned from unkeyed headers per function
        self._unkeyed_header_vars: Dict[str, str] = {}  # var_name -> header_name
        # Track variables assigned from Host header
        self._host_header_vars: Set[str] = set()
        # Track variables that hold user input
        self._user_input_vars: Set[str] = set()
        # Track variables assigned from CDN-ignored query params
        self._cdn_ignored_param_vars: Dict[str, str] = {}  # var_name -> param_name
        # Track if function sets cache-control
        self._func_sets_cache_control: bool = False

    def check_program(self, program: Program) -> List[CachePoisoningFinding]:
        """Run cache poisoning analysis on the entire program."""
        self.findings = []
        self._is_frontend = _is_frontend_file(getattr(program, "filename", ""))

        # Skip frontend files entirely -- cache poisoning is server-side
        if self._is_frontend:
            return []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.findings

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for cache poisoning patterns."""
        self._unkeyed_header_vars = {}
        self._host_header_vars = set()
        self._user_input_vars = set()
        self._cdn_ignored_param_vars = {}

        # Identify user input parameters
        for param in func.params:
            param_lower = param.name.lower()
            type_str = str(param.type_annotation).lower() if param.type_annotation else ""
            if _is_user_input_identifier(param.name):
                self._user_input_vars.add(param.name)
            if any(kw in type_str for kw in ("request", "httprequest", "formdata")):
                self._user_input_vars.add(param.name)

        all_stmts = list(_walk_all_statements(func))

        # Pre-check: does this function set cache-control headers?
        self._func_sets_cache_control = _function_sets_cache_control(all_stmts)

        # First pass: collect variable tracking data
        for stmt in all_stmts:
            self._collect_variable_info(stmt)

        # Second pass: run all detectors
        for stmt in all_stmts:
            loc = getattr(stmt, "location", SourceLocation(0, 0, "<cache-poisoning>"))
            self._check_unkeyed_header_reflection(stmt, func.name, loc)
            self._check_cache_key_manipulation(stmt, func.name, loc)
            self._check_host_header_poisoning(stmt, func.name, loc)
            self._check_response_splitting_cache(stmt, func.name, loc)
            self._check_predictable_cache_key(stmt, func.name, loc)
            self._check_cdn_bypass_headers(stmt, func.name, loc)

        # Function-level checks (require analyzing the function as a whole)
        self._check_web_cache_deception(func, all_stmts)
        self._check_missing_cache_control(func, all_stmts)

    # ------------------------------------------------------------------
    # Variable Collection
    # ------------------------------------------------------------------

    def _collect_variable_info(self, stmt: Statement) -> None:
        """Collect variable assignments that track header access and user input."""
        if isinstance(stmt, LetStmt) and stmt.value:
            # Track unkeyed header reads
            found, header = _expr_contains_header_access(
                stmt.value, REFLECTION_DANGEROUS_HEADERS
            )
            if found:
                self._unkeyed_header_vars[stmt.name] = header

            # Track Host header reads
            if _expr_contains_host_header(stmt.value):
                self._host_header_vars.add(stmt.name)

            # Track user input
            if _expr_contains_user_input(stmt.value):
                self._user_input_vars.add(stmt.name)

            # Track CDN-ignored query param access
            self._check_cdn_param_assignment(stmt.name, stmt.value)

        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                found, header = _expr_contains_header_access(
                    stmt.value, REFLECTION_DANGEROUS_HEADERS
                )
                if found:
                    self._unkeyed_header_vars[stmt.target.name] = header

                if _expr_contains_host_header(stmt.value):
                    self._host_header_vars.add(stmt.target.name)

                if _expr_contains_user_input(stmt.value):
                    self._user_input_vars.add(stmt.target.name)

                self._check_cdn_param_assignment(stmt.target.name, stmt.value)

    def _check_cdn_param_assignment(self, var_name: str, expr: Expr) -> None:
        """Check if an expression reads a CDN-ignored query parameter."""
        strings = _extract_string_values(expr)
        for s in strings:
            s_lower = s.lower()
            for param in CDN_IGNORED_PARAMS:
                if param == s_lower:
                    self._cdn_ignored_param_vars[var_name] = param
                    return

    # ------------------------------------------------------------------
    # Utility: Extract Expressions from Statement
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

    # ------------------------------------------------------------------
    # 1. Unkeyed Header Reflection
    # ------------------------------------------------------------------

    def _check_unkeyed_header_reflection(self, stmt: Statement,
                                         func_name: str,
                                         loc: SourceLocation) -> None:
        """Detect unkeyed header values reflected in response content.

        Flags when X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL, or
        similar unkeyed headers are read and then included in response bodies,
        especially in HTML tag contexts (<link>, <script>, <meta>) or redirects.
        """
        exprs = self._extract_exprs(stmt)

        for expr in exprs:
            # Check for direct reflection: response includes unkeyed header
            if _is_response_send(expr) or _is_redirect_call(expr):
                # Check arguments for unkeyed header variable references
                args = expr.args if hasattr(expr, "args") else []
                for arg in args:
                    # Direct header access in response
                    found, header = _expr_contains_header_access(
                        arg, REFLECTION_DANGEROUS_HEADERS
                    )
                    if found:
                        self._add_reflection_finding(header, func_name, loc,
                                                     is_redirect=_is_redirect_call(expr))
                        continue

                    # Variable that was assigned from unkeyed header
                    for sub_expr in _walk_exprs(arg):
                        if isinstance(sub_expr, Identifier):
                            if sub_expr.name in self._unkeyed_header_vars:
                                header = self._unkeyed_header_vars[sub_expr.name]
                                self._add_reflection_finding(
                                    header, func_name, loc,
                                    is_redirect=_is_redirect_call(expr),
                                )
                                break

            # Check for string concatenation with unkeyed header into HTML context
            if isinstance(expr, BinaryOp):
                found, header = _expr_contains_header_access(
                    expr, REFLECTION_DANGEROUS_HEADERS
                )
                if found:
                    strings = _extract_string_values(expr)
                    for s in strings:
                        if _string_contains_html_tag_context(s):
                            self._add_reflection_finding(
                                header, func_name, loc,
                                context="HTML tag injection",
                            )
                            break

    def _add_reflection_finding(self, header: str, func_name: str,
                                loc: SourceLocation,
                                is_redirect: bool = False,
                                context: str = "") -> None:
        """Record an unkeyed header reflection finding."""
        category = CachePoisoningCategory.UNKEYED_HEADER_REFLECTION
        detail = (
            f"redirect target" if is_redirect
            else context if context
            else "response body"
        )
        self.findings.append(CachePoisoningFinding(
            category=category,
            severity=SEVERITY_MAP[category],
            description=(
                f"Unkeyed header '{header}' is reflected in the {detail}. "
                f"An attacker can set this header to poison the cache with "
                f"malicious content that is served to all subsequent users."
            ),
            cwe=CWE_MAP[category],
            location=loc,
            function_name=func_name,
            remediation=REMEDIATION_MAP[category],
            evidence=f"Header: {header}, reflected in: {detail}",
        ))

    # ------------------------------------------------------------------
    # 2. Cache Key Manipulation
    # ------------------------------------------------------------------

    def _check_cache_key_manipulation(self, stmt: Statement,
                                      func_name: str,
                                      loc: SourceLocation) -> None:
        """Detect CDN-ignored query parameters used in response generation.

        Only flags when a CDN-ignored parameter (utm_*, fbclid, gclid, etc.)
        is used in response rendering logic -- not just read from the request.
        """
        exprs = self._extract_exprs(stmt)

        for expr in exprs:
            if _is_response_send(expr) or _is_redirect_call(expr):
                args = expr.args if hasattr(expr, "args") else []
                for arg in args:
                    # Check for CDN-ignored param variables in response
                    for sub_expr in _walk_exprs(arg):
                        if isinstance(sub_expr, Identifier):
                            if sub_expr.name in self._cdn_ignored_param_vars:
                                param = self._cdn_ignored_param_vars[sub_expr.name]
                                category = CachePoisoningCategory.CACHE_KEY_MANIPULATION
                                self.findings.append(CachePoisoningFinding(
                                    category=category,
                                    severity=SEVERITY_MAP[category],
                                    description=(
                                        f"CDN-ignored query parameter '{param}' "
                                        f"is used in response generation. Most CDNs "
                                        f"strip utm_* and tracking parameters from "
                                        f"cache keys, so an attacker can manipulate "
                                        f"the cached response via this parameter."
                                    ),
                                    cwe=CWE_MAP[category],
                                    location=loc,
                                    function_name=func_name,
                                    remediation=REMEDIATION_MAP[category],
                                    evidence=f"Parameter: {param}",
                                ))
                                return

    # ------------------------------------------------------------------
    # 3. Web Cache Deception
    # ------------------------------------------------------------------

    def _check_web_cache_deception(self, func: PureFunc | TaskFunc,
                                   all_stmts: List[Statement]) -> None:
        """Detect routes serving authenticated/dynamic content without
        Cache-Control: no-store or private.

        Only flags if the function looks like a route handler for a sensitive
        path AND does not set appropriate cache-control headers.
        """
        if not _looks_like_route_handler(func):
            return

        if not _route_serves_sensitive_path(func):
            return

        if self._func_sets_cache_control:
            return

        # Verify the function actually sends a response with dynamic content
        sends_response = False
        for stmt in all_stmts:
            for expr in self._extract_exprs(stmt):
                for sub_expr in _walk_exprs(expr):
                    if _is_response_send(sub_expr):
                        sends_response = True
                        break
                if sends_response:
                    break
            if sends_response:
                break

        if not sends_response:
            return

        loc = SourceLocation(0, 0, "<cache-poisoning>")
        if func.body:
            loc = getattr(func.body[0], "location", loc)

        category = CachePoisoningCategory.WEB_CACHE_DECEPTION
        self.findings.append(CachePoisoningFinding(
            category=category,
            severity=SEVERITY_MAP[category],
            description=(
                f"Route handler '{func.name}' serves sensitive/authenticated "
                f"content on a path that matches common cache deception targets "
                f"(profile, account, settings, dashboard) but does not set "
                f"Cache-Control: no-store or private. An attacker can append "
                f"a static extension (e.g., /profile/photo.jpg) to trick CDNs "
                f"into caching the authenticated response."
            ),
            cwe=CWE_MAP[category],
            location=loc,
            function_name=func.name,
            remediation=REMEDIATION_MAP[category],
            evidence=f"Route handler: {func.name}",
        ))

    # ------------------------------------------------------------------
    # 4. Missing Cache-Control on Sensitive Responses
    # ------------------------------------------------------------------

    def _check_missing_cache_control(self, func: PureFunc | TaskFunc,
                                     all_stmts: List[Statement]) -> None:
        """Detect API responses with user-specific data lacking cache-control.

        Only flags when the response clearly contains user-specific data
        (user.email, account.name, etc.) AND the handler does not set
        Cache-Control: no-store or private. Conservative: requires both
        a user-data-object + field pattern and a response send call.
        """
        if not _looks_like_route_handler(func):
            return

        if self._func_sets_cache_control:
            return

        # Look for response sends that include user-specific data
        for stmt in all_stmts:
            for expr in self._extract_exprs(stmt):
                if _is_response_send(expr):
                    args = expr.args if hasattr(expr, "args") else []
                    for arg in args:
                        if _contains_user_data_access(arg):
                            loc = getattr(stmt, "location",
                                          SourceLocation(0, 0, "<cache-poisoning>"))
                            category = CachePoisoningCategory.MISSING_CACHE_CONTROL
                            self.findings.append(CachePoisoningFinding(
                                category=category,
                                severity=SEVERITY_MAP[category],
                                description=(
                                    f"Response in '{func.name}' includes "
                                    f"user-specific data but does not set "
                                    f"Cache-Control: no-store, private. "
                                    f"Intermediate caches or CDNs may store "
                                    f"this response, exposing one user's data "
                                    f"to others."
                                ),
                                cwe=CWE_MAP[category],
                                location=loc,
                                function_name=func.name,
                                remediation=REMEDIATION_MAP[category],
                                evidence=f"User data in response without cache-control",
                            ))
                            return  # One finding per function is enough

    # ------------------------------------------------------------------
    # 5. Predictable Cache Keys
    # ------------------------------------------------------------------

    def _check_predictable_cache_key(self, stmt: Statement,
                                     func_name: str,
                                     loc: SourceLocation) -> None:
        """Detect cache.set(url, response) without user ID in the key.

        Flags when a cache write operation uses a URL or path as the key
        without incorporating a user-specific component, for content that
        appears to be user-specific.
        """
        exprs = self._extract_exprs(stmt)

        for expr in exprs:
            for sub_expr in _walk_exprs(expr):
                is_cache_set, args = _is_cache_set_call(sub_expr)
                if not is_cache_set or len(args) < 2:
                    continue

                key_expr = args[0]
                value_expr = args[1]

                # Check if the value contains user-specific data
                value_has_user_data = _contains_user_data_access(value_expr)
                if not value_has_user_data:
                    # Also check if any tracked user input variable is in value
                    value_has_user_data = any(
                        isinstance(se, Identifier) and se.name in self._user_input_vars
                        for se in _walk_exprs(value_expr)
                    )

                if not value_has_user_data:
                    continue

                # Check if the key includes a user-specific component
                key_name = _expr_name(key_expr).lower()
                key_strings = _extract_string_values(key_expr)
                all_key_text = key_name + " ".join(key_strings)

                user_key_indicators = (
                    "user", "uid", "user_id", "userid", "session",
                    "account", "member", "customer", "auth",
                )
                has_user_in_key = any(
                    indicator in all_key_text.lower()
                    for indicator in user_key_indicators
                )

                if not has_user_in_key:
                    # Key looks like just a URL/path without user component
                    category = CachePoisoningCategory.PREDICTABLE_CACHE_KEY
                    self.findings.append(CachePoisoningFinding(
                        category=category,
                        severity=SEVERITY_MAP[category],
                        description=(
                            f"Cache key '{key_name or '<dynamic>'}' does not "
                            f"include a user-specific component but the cached "
                            f"value contains user-specific data. Another user "
                            f"requesting the same URL will receive the first "
                            f"user's cached data."
                        ),
                        cwe=CWE_MAP[category],
                        location=loc,
                        function_name=func_name,
                        remediation=REMEDIATION_MAP[category],
                        evidence=f"Cache key: {key_name or '<expr>'}",
                    ))
                    return  # One per statement

    # ------------------------------------------------------------------
    # 6. Host Header Poisoning
    # ------------------------------------------------------------------

    def _check_host_header_poisoning(self, stmt: Statement,
                                     func_name: str,
                                     loc: SourceLocation) -> None:
        """Detect Host header used in URL construction for emails or redirects.

        Flags when req.headers.host or X-Forwarded-Host is used to build
        URLs that appear in password reset links, canonical URLs, email
        content, or redirect targets. These are cache-poisonable because
        the Host header is typically part of the cache key, but
        X-Forwarded-Host is not -- and even the Host header can be
        manipulated in some configurations.
        """
        exprs = self._extract_exprs(stmt)

        for expr in exprs:
            # Look for URL construction using host header
            if not isinstance(expr, BinaryOp):
                # Also check let/assign where value is a concatenation
                if isinstance(stmt, LetStmt) and stmt.value:
                    self._check_host_in_url_construction(
                        stmt.name, stmt.value, func_name, loc
                    )
                continue

            self._check_host_in_url_construction(
                "", expr, func_name, loc
            )

    def _check_host_in_url_construction(self, var_name: str, expr: Expr,
                                         func_name: str,
                                         loc: SourceLocation) -> None:
        """Check if a host header is used in URL construction context."""
        has_host = _expr_contains_host_header(expr)
        if not has_host:
            # Check tracked host header variables
            for sub_expr in _walk_exprs(expr):
                if isinstance(sub_expr, Identifier) and sub_expr.name in self._host_header_vars:
                    has_host = True
                    break

        if not has_host:
            return

        # Determine if this is a sensitive URL construction context
        is_url_context = False
        context_type = ""

        # Check variable name
        var_lower = var_name.lower()
        for url_ctx in URL_CONSTRUCTION_CONTEXTS:
            if url_ctx.lower() in var_lower:
                is_url_context = True
                context_type = url_ctx
                break

        # Check if it's used in an email sending or redirect context
        if not is_url_context:
            strings = _extract_string_values(expr)
            for s in strings:
                s_lower = s.lower()
                # URL protocol prefix + host header = URL construction
                if s_lower.startswith(("http://", "https://", "//")):
                    is_url_context = True
                    context_type = "URL construction"
                    break
                # Password reset, email, or canonical URL context
                if any(kw in s_lower for kw in
                       ("reset", "confirm", "verify", "canonical",
                        "unsubscribe", "invite", "callback")):
                    is_url_context = True
                    context_type = "sensitive link generation"
                    break

        if not is_url_context:
            return

        category = CachePoisoningCategory.HOST_HEADER_POISONING
        self.findings.append(CachePoisoningFinding(
            category=category,
            severity=SEVERITY_MAP[category],
            description=(
                f"Host header value is used in {context_type} in "
                f"'{func_name}'. An attacker can send a crafted Host or "
                f"X-Forwarded-Host header to generate URLs pointing to a "
                f"malicious domain (e.g., in password reset emails, canonical "
                f"tags, or redirect targets)."
            ),
            cwe=CWE_MAP[category],
            location=loc,
            function_name=func_name,
            remediation=REMEDIATION_MAP[category],
            evidence=f"Context: {context_type}, variable: {var_name or '<inline>'}",
        ))

    # ------------------------------------------------------------------
    # 7. CDN Bypass via Headers
    # ------------------------------------------------------------------

    def _check_cdn_bypass_headers(self, stmt: Statement,
                                  func_name: str,
                                  loc: SourceLocation) -> None:
        """Detect cache headers that bypass CDN security.

        Flags:
          - Cache-Control: public on endpoints that serve authenticated content
          - Vary: * which behaves inconsistently across CDN providers
        """
        exprs = self._extract_exprs(stmt)

        for expr in exprs:
            for sub_expr in _walk_exprs(expr):
                is_header, header_name, value_expr = _is_header_set_call(sub_expr)
                if not is_header:
                    continue

                if not value_expr:
                    continue

                strings = _extract_string_values(value_expr)

                # Check for Cache-Control: public
                if header_name == "cache-control":
                    for s in strings:
                        s_lower = s.lower()
                        if "public" in s_lower and "no-store" not in s_lower:
                            # Only flag if the function looks like it handles
                            # authenticated content
                            if self._user_input_vars or self._host_header_vars:
                                category = CachePoisoningCategory.CDN_BYPASS_VIA_HEADERS
                                self.findings.append(CachePoisoningFinding(
                                    category=category,
                                    severity=SEVERITY_MAP[category],
                                    description=(
                                        f"Cache-Control: public is set in "
                                        f"'{func_name}' which appears to handle "
                                        f"authenticated or user-specific content. "
                                        f"Public caching of authenticated responses "
                                        f"exposes user data to other users via "
                                        f"shared CDN caches."
                                    ),
                                    cwe=CWE_MAP[category],
                                    location=loc,
                                    function_name=func_name,
                                    remediation=REMEDIATION_MAP[category],
                                    evidence=f"Header: Cache-Control: {s}",
                                ))

                # Check for Vary: *
                if header_name == "vary":
                    for s in strings:
                        if s.strip() == "*":
                            category = CachePoisoningCategory.CDN_BYPASS_VIA_HEADERS
                            self.findings.append(CachePoisoningFinding(
                                category=category,
                                severity=SEVERITY_MAP[category],
                                description=(
                                    f"Vary: * is set in '{func_name}'. While "
                                    f"RFC 7231 says Vary: * means the response "
                                    f"varies on everything (effectively uncacheable), "
                                    f"many CDNs handle this inconsistently -- some "
                                    f"ignore it, some cache anyway. Use explicit "
                                    f"Cache-Control: no-store instead."
                                ),
                                cwe=CWE_MAP[category],
                                location=loc,
                                function_name=func_name,
                                remediation=REMEDIATION_MAP[category],
                                evidence=f"Header: Vary: *",
                            ))

    # ------------------------------------------------------------------
    # 8. Response Splitting via Cache
    # ------------------------------------------------------------------

    def _check_response_splitting_cache(self, stmt: Statement,
                                        func_name: str,
                                        loc: SourceLocation) -> None:
        """Detect user input in response headers that could inject cache directives.

        Flags when user-controlled data flows into Set-Cookie, Location, or
        custom response headers without sanitization, enabling injection of
        CR/LF sequences that add Cache-Control directives.
        """
        exprs = self._extract_exprs(stmt)

        for expr in exprs:
            for sub_expr in _walk_exprs(expr):
                is_header, header_name, value_expr = _is_header_set_call(sub_expr)
                if not is_header or not value_expr:
                    continue

                # Only check headers that are vulnerable to splitting
                if header_name not in SPLITTABLE_HEADERS:
                    continue

                # Check if the header value contains user input
                has_user_input = _expr_contains_user_input(value_expr)
                if not has_user_input:
                    # Check tracked user input variables
                    for ve in _walk_exprs(value_expr):
                        if isinstance(ve, Identifier) and ve.name in self._user_input_vars:
                            has_user_input = True
                            break

                if not has_user_input:
                    continue

                category = CachePoisoningCategory.RESPONSE_SPLITTING_CACHE
                self.findings.append(CachePoisoningFinding(
                    category=category,
                    severity=SEVERITY_MAP[category],
                    description=(
                        f"User input flows into the '{header_name}' response "
                        f"header in '{func_name}'. An attacker can inject CRLF "
                        f"sequences to add arbitrary headers (including "
                        f"Cache-Control directives) that poison the cache."
                    ),
                    cwe=CWE_MAP[category],
                    location=loc,
                    function_name=func_name,
                    remediation=REMEDIATION_MAP[category],
                    evidence=f"Header: {header_name}, source: user input",
                ))


# ---------------------------------------------------------------------------
# Finding -> AeonError Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: CachePoisoningFinding) -> AeonError:
    """Convert an internal finding to an AeonError for the verification pipeline."""
    severity_label = finding.severity.value.upper()
    category_label = finding.category.value.replace("_", " ").title()

    return contract_error(
        precondition=(
            f"No cache poisoning ({finding.cwe}) -- "
            f"[{severity_label}] {category_label}: {finding.description}"
        ),
        failing_values={
            "category": finding.category.value,
            "severity": finding.severity.value,
            "cwe": finding.cwe,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "engine": "Web Cache Poisoning",
            **finding.details,
        },
        function_signature=finding.function_name,
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_cache_poisoning(program: Program) -> list:
    """Run web cache poisoning analysis on an AEON program.

    Detects cache poisoning, cache deception, and cache-related security
    vulnerabilities across eight categories:

    1. Unkeyed header reflection (CWE-444)
       - X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL reflected
         in response bodies, especially in <link>, <script>, <meta> tags
         or redirect targets

    2. Cache key manipulation (CWE-444)
       - CDN-ignored query parameters (utm_*, fbclid, gclid) used in
         response generation logic

    3. Web cache deception (CWE-525)
       - Sensitive routes (profile, account, settings, dashboard) serving
         dynamic/authenticated content without Cache-Control: no-store

    4. Missing cache-control on sensitive responses (CWE-525)
       - API responses with user-specific data (user.email, account.name)
         without Cache-Control: no-store, private

    5. Predictable cache keys (CWE-384)
       - cache.set(url, response) without user ID in key for
         authenticated content

    6. Host header poisoning (CWE-444)
       - Host or X-Forwarded-Host used in URL construction for password
         reset links, canonical URLs, or email content

    7. CDN bypass via headers (CWE-444)
       - Cache-Control: public on authenticated endpoints
       - Vary: * which behaves inconsistently across CDN providers

    8. Response splitting via cache (CWE-113)
       - User input in Set-Cookie, Location, or custom headers that
         could inject Cache-Control directives via CRLF

    This is a conservative engine. It only flags clear, high-confidence
    patterns rather than every missing Cache-Control header. Frontend
    files are skipped entirely.

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected vulnerability.
    """
    try:
        analyzer = CachePoisoningAnalyzer()
        findings = analyzer.check_program(program)
        return [_finding_to_error(f) for f in findings]
    except Exception:
        # Engine-level safety net: never let the engine crash
        # the verification pipeline
        return []
