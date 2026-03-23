"""AEON OAuth & OIDC Security Engine -- OAuth 2.0/2.1 and OpenID Connect Vulnerability Scanner.

Detects OAuth and OpenID Connect security vulnerabilities across web application
codebases, with special attention to Supabase auth patterns common in modern
JavaScript/TypeScript applications.

References:
  CWE-345: Insufficient Verification of Data Authenticity
  https://cwe.mitre.org/data/definitions/345.html

  CWE-346: Origin Validation Error
  https://cwe.mitre.org/data/definitions/346.html

  CWE-352: Cross-Site Request Forgery (CSRF)
  https://cwe.mitre.org/data/definitions/352.html

  CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
  https://cwe.mitre.org/data/definitions/601.html

  CWE-269: Improper Privilege Management
  https://cwe.mitre.org/data/definitions/269.html

  CWE-922: Insecure Storage of Sensitive Information
  https://cwe.mitre.org/data/definitions/922.html

  RFC 7636 — Proof Key for Code Exchange (PKCE)
  https://datatracker.ietf.org/doc/html/rfc7636

  RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification
  https://datatracker.ietf.org/doc/html/rfc9207

  OAuth 2.1 Draft — Deprecation of Implicit Grant
  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-11

  Lodderstedt, T. et al. (2020) "OAuth 2.0 Security Best Current Practice"
  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics

  OWASP OAuth Security Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html

Detection Categories:

1. MISSING PKCE (CWE-346):
   OAuth authorization code flow without code_challenge/code_verifier.
   PKCE (RFC 7636) is REQUIRED for all OAuth clients in OAuth 2.1,
   not just public clients. Without PKCE, authorization codes are
   interceptable.

2. MISSING STATE PARAMETER (CWE-352):
   OAuth authorization redirects without the state parameter allow
   CSRF attacks. An attacker can initiate an OAuth flow and trick the
   victim into completing it, binding the attacker's account.

3. TOKEN LEAKAGE IN REDIRECTS (CWE-601):
   Access tokens in URL fragments (response_type=token) leak via
   Referer headers, browser history, and proxy logs. Implicit flow
   exposes tokens directly in the URL.

4. OPEN REDIRECT IN OAUTH FLOW (CWE-601):
   redirect_uri values taken from user input without domain validation
   enable authorization code/token theft. The redirect_uri MUST be
   validated against a pre-registered allowlist on the server side.

5. AUTHORIZATION CODE INJECTION (CWE-345):
   Authorization codes used without binding to the client session
   (via PKCE or state) enable code injection attacks where an attacker
   substitutes their authorization code into the victim's session.

6. INSECURE TOKEN STORAGE (CWE-922):
   OAuth tokens stored in localStorage are accessible to any JavaScript
   on the page via XSS. Tokens should be stored in HttpOnly cookies
   or in-memory with refresh token rotation.

7. MISSING TOKEN VALIDATION (CWE-345):
   ID tokens accepted without verifying signature, audience (aud),
   issuer (iss), expiration (exp), or nonce allow token forgery and
   replay attacks.

8. OVERLY BROAD SCOPES (CWE-269):
   Requesting more permissions than needed violates the principle of
   least privilege. Broad scopes like admin, write:all, or * increase
   the blast radius of token compromise.

9. IMPLICIT FLOW USAGE (CWE-346):
   response_type=token (implicit grant) is deprecated in OAuth 2.1.
   Tokens are exposed in the URL fragment, vulnerable to interception,
   and cannot be refreshed. Use authorization code + PKCE instead.

10. SUPABASE-SPECIFIC ISSUES:
    supabase.auth.signInWithOAuth without PKCE, missing redirectTo
    validation, and getSession() on server without getUser() — the
    session JWT can be spoofed from the client; only getUser() makes
    an authenticated call to Supabase Auth to verify the token.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral, IntLiteral, BoolLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    LetStmt, AssignStmt, IfStmt, ExprStmt, WhileStmt, ForStmt,
    ReturnStmt, ListLiteral, ConstructExpr,
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
    MISSING_PKCE = "missing_pkce"
    MISSING_STATE = "missing_state_parameter"
    TOKEN_IN_URL = "token_leakage_in_redirect"
    OPEN_REDIRECT = "open_redirect_oauth"
    CODE_INJECTION = "authorization_code_injection"
    INSECURE_TOKEN_STORAGE = "insecure_token_storage"
    MISSING_TOKEN_SIGNATURE = "missing_token_signature_verification"
    MISSING_AUD_CHECK = "missing_audience_check"
    MISSING_ISS_CHECK = "missing_issuer_check"
    MISSING_EXP_CHECK = "missing_expiration_check"
    MISSING_NONCE = "missing_nonce_validation"
    OVERLY_BROAD_SCOPES = "overly_broad_scopes"
    IMPLICIT_FLOW = "implicit_flow_usage"
    SUPABASE_NO_PKCE = "supabase_oauth_without_pkce"
    SUPABASE_REDIRECT_UNVALIDATED = "supabase_redirect_unvalidated"
    SUPABASE_SESSION_NOT_VERIFIED = "supabase_session_without_getuser"


# ---------------------------------------------------------------------------
# CWE Mapping
# ---------------------------------------------------------------------------

CWE_MAP: Dict[FindingCategory, str] = {
    FindingCategory.MISSING_PKCE: "CWE-346",
    FindingCategory.MISSING_STATE: "CWE-352",
    FindingCategory.TOKEN_IN_URL: "CWE-601",
    FindingCategory.OPEN_REDIRECT: "CWE-601",
    FindingCategory.CODE_INJECTION: "CWE-345",
    FindingCategory.INSECURE_TOKEN_STORAGE: "CWE-922",
    FindingCategory.MISSING_TOKEN_SIGNATURE: "CWE-345",
    FindingCategory.MISSING_AUD_CHECK: "CWE-345",
    FindingCategory.MISSING_ISS_CHECK: "CWE-345",
    FindingCategory.MISSING_EXP_CHECK: "CWE-345",
    FindingCategory.MISSING_NONCE: "CWE-345",
    FindingCategory.OVERLY_BROAD_SCOPES: "CWE-269",
    FindingCategory.IMPLICIT_FLOW: "CWE-346",
    FindingCategory.SUPABASE_NO_PKCE: "CWE-346",
    FindingCategory.SUPABASE_REDIRECT_UNVALIDATED: "CWE-601",
    FindingCategory.SUPABASE_SESSION_NOT_VERIFIED: "CWE-345",
}

# ---------------------------------------------------------------------------
# Severity Mapping
# ---------------------------------------------------------------------------

SEVERITY_MAP: Dict[FindingCategory, Severity] = {
    FindingCategory.MISSING_PKCE: Severity.HIGH,
    FindingCategory.MISSING_STATE: Severity.HIGH,
    FindingCategory.TOKEN_IN_URL: Severity.HIGH,
    FindingCategory.OPEN_REDIRECT: Severity.CRITICAL,
    FindingCategory.CODE_INJECTION: Severity.HIGH,
    FindingCategory.INSECURE_TOKEN_STORAGE: Severity.HIGH,
    FindingCategory.MISSING_TOKEN_SIGNATURE: Severity.CRITICAL,
    FindingCategory.MISSING_AUD_CHECK: Severity.HIGH,
    FindingCategory.MISSING_ISS_CHECK: Severity.MEDIUM,
    FindingCategory.MISSING_EXP_CHECK: Severity.HIGH,
    FindingCategory.MISSING_NONCE: Severity.MEDIUM,
    FindingCategory.OVERLY_BROAD_SCOPES: Severity.MEDIUM,
    FindingCategory.IMPLICIT_FLOW: Severity.HIGH,
    FindingCategory.SUPABASE_NO_PKCE: Severity.HIGH,
    FindingCategory.SUPABASE_REDIRECT_UNVALIDATED: Severity.HIGH,
    FindingCategory.SUPABASE_SESSION_NOT_VERIFIED: Severity.HIGH,
}

# ---------------------------------------------------------------------------
# Remediation Guidance
# ---------------------------------------------------------------------------

REMEDIATION: Dict[FindingCategory, str] = {
    FindingCategory.MISSING_PKCE: (
        "Always use PKCE (RFC 7636) for the authorization code flow. "
        "Generate a code_verifier with crypto.randomBytes(32), derive "
        "code_challenge via S256 hash, and send both in the auth request "
        "and token exchange. PKCE is mandatory in OAuth 2.1 for all clients."
    ),
    FindingCategory.MISSING_STATE: (
        "Include a cryptographically random 'state' parameter in every "
        "OAuth authorization request. Validate it on the callback to prevent "
        "CSRF. The state should be bound to the user's browser session."
    ),
    FindingCategory.TOKEN_IN_URL: (
        "Never use response_type=token (implicit flow). Tokens in URL "
        "fragments leak via Referer headers, browser history, and proxy logs. "
        "Use authorization code flow with PKCE instead."
    ),
    FindingCategory.OPEN_REDIRECT: (
        "Validate redirect_uri against a server-side allowlist of pre-registered "
        "URIs. Never construct redirect_uri from user-supplied input (query params, "
        "headers, request body). Use exact string matching, not pattern matching."
    ),
    FindingCategory.CODE_INJECTION: (
        "Bind authorization codes to the client session using PKCE or a validated "
        "state parameter. Without this binding, an attacker can inject their "
        "authorization code into a victim's session."
    ),
    FindingCategory.INSECURE_TOKEN_STORAGE: (
        "Do not store OAuth tokens (access_token, id_token, refresh_token) in "
        "localStorage or sessionStorage — both are accessible to any JavaScript "
        "on the page via XSS. Use HttpOnly cookies or in-memory storage with "
        "refresh token rotation."
    ),
    FindingCategory.MISSING_TOKEN_SIGNATURE: (
        "Always verify ID token signatures using the provider's public keys "
        "(JWKS endpoint). Never skip signature verification or use alg:none. "
        "Libraries like jose, jsonwebtoken, and python-jose handle this correctly "
        "when configured with the expected algorithm."
    ),
    FindingCategory.MISSING_AUD_CHECK: (
        "Validate the 'aud' (audience) claim in ID tokens and access tokens. "
        "The audience must match your application's client_id. Without this check, "
        "tokens issued for a different application can be replayed."
    ),
    FindingCategory.MISSING_ISS_CHECK: (
        "Validate the 'iss' (issuer) claim in ID tokens. The issuer must match "
        "your OAuth provider's expected issuer URL. This prevents tokens from "
        "a different provider from being accepted."
    ),
    FindingCategory.MISSING_EXP_CHECK: (
        "Always check the 'exp' (expiration) claim in tokens. Expired tokens "
        "must be rejected. Most JWT libraries check expiration by default, "
        "but verify that this check is not disabled."
    ),
    FindingCategory.MISSING_NONCE: (
        "Include a nonce in OIDC authentication requests and validate it in "
        "the returned ID token. The nonce binds the token to the specific "
        "authentication session, preventing replay attacks."
    ),
    FindingCategory.OVERLY_BROAD_SCOPES: (
        "Request only the minimum scopes necessary for your application. "
        "Avoid admin, write:all, or wildcard (*) scopes. Broad scopes increase "
        "the damage from token compromise. Review scopes periodically."
    ),
    FindingCategory.IMPLICIT_FLOW: (
        "Replace implicit flow (response_type=token) with authorization code "
        "flow + PKCE. Implicit flow is deprecated in OAuth 2.1 because tokens "
        "are exposed in the URL fragment. Authorization code + PKCE is secure "
        "for both public and confidential clients."
    ),
    FindingCategory.SUPABASE_NO_PKCE: (
        "Pass options: { flowType: 'pkce' } to supabase.auth.signInWithOAuth(). "
        "Without PKCE, the authorization code can be intercepted. Supabase "
        "supports PKCE natively since supabase-js v2.39.0."
    ),
    FindingCategory.SUPABASE_REDIRECT_UNVALIDATED: (
        "Do not construct the redirectTo URL from user input (query parameters, "
        "headers, or request body). Use a hardcoded redirectTo or validate it "
        "against a known allowlist of your own domains."
    ),
    FindingCategory.SUPABASE_SESSION_NOT_VERIFIED: (
        "On the server side, use supabase.auth.getUser() instead of "
        "supabase.auth.getSession(). getSession() reads the JWT without "
        "verifying it with Supabase Auth — a client can forge the session JWT. "
        "getUser() makes an authenticated API call to verify the token."
    ),
}


# ---------------------------------------------------------------------------
# Internal Finding
# ---------------------------------------------------------------------------

@dataclass
class OAuthFinding:
    """Internal finding before conversion to AeonError."""
    category: FindingCategory
    message: str
    location: Optional[SourceLocation]
    context: str = ""  # function name or variable for context


# ---------------------------------------------------------------------------
# Pattern Databases
# ---------------------------------------------------------------------------

# OAuth authorization endpoint patterns (URLs or function names)
OAUTH_AUTH_FUNCTIONS: Set[str] = {
    "authorize", "authorization", "authorizationurl", "authorization_url",
    "getauthorizationurl", "get_authorization_url", "buildauthurl",
    "build_auth_url", "createauthorizationurl", "create_authorization_url",
    "initiateauth", "initiate_auth", "startauth", "start_auth",
    "oauth2login", "oauth2_login", "oauthlogin", "oauth_login",
    "signinwithoauth", "sign_in_with_oauth", "signInWithOAuth",
    "signinwithoidc", "sign_in_with_oidc", "signInWithOIDC",
    "signinwithredirect", "sign_in_with_redirect", "signInWithRedirect",
}

# Authorization endpoint URL patterns
AUTH_ENDPOINT_URL_PATTERNS: Set[str] = {
    "/authorize", "/oauth/authorize", "/oauth2/authorize",
    "/auth/authorize", "/connect/authorize", "/openid-connect/auth",
    "/oauth2/auth", "/v1/authorize", "/v2/authorize",
}

# Token exchange functions
TOKEN_EXCHANGE_FUNCTIONS: Set[str] = {
    "gettoken", "get_token", "exchangecode", "exchange_code",
    "exchangeauthorizationcode", "exchange_authorization_code",
    "requesttoken", "request_token", "fetchtoken", "fetch_token",
    "getaccesstoken", "get_access_token", "handlecallback",
    "handle_callback", "oauthcallback", "oauth_callback",
    "exchangecodefortoken", "exchange_code_for_token",
}

# PKCE parameter names
PKCE_PARAMS: Set[str] = {
    "code_challenge", "codechallenge", "code_verifier", "codeverifier",
    "pkce", "flowtype", "flow_type",
}

# State parameter names
STATE_PARAMS: Set[str] = {
    "state",
}

# OAuth token variable patterns
TOKEN_VARIABLE_PATTERNS: Set[str] = {
    "access_token", "accesstoken", "id_token", "idtoken",
    "refresh_token", "refreshtoken", "oauth_token", "oauthtoken",
    "bearer_token", "bearertoken", "auth_token", "authtoken",
}

# Token verification/validation function names
TOKEN_VERIFY_FUNCTIONS: Set[str] = {
    "verify", "decode", "verifyidtoken", "verify_id_token",
    "verifyjwt", "verify_jwt", "validatetoken", "validate_token",
    "validateidtoken", "validate_id_token", "jwtverify", "jwt_verify",
    "verifytoken", "verify_token",
}

# Token claim validation indicators
CLAIM_AUD_CHECKS: Set[str] = {
    "aud", "audience", "client_id", "clientid",
}

CLAIM_ISS_CHECKS: Set[str] = {
    "iss", "issuer",
}

CLAIM_EXP_CHECKS: Set[str] = {
    "exp", "expiration", "expiresIn", "expires_in", "maxage", "max_age",
}

CLAIM_NONCE_CHECKS: Set[str] = {
    "nonce",
}

# Overly broad scope patterns
BROAD_SCOPE_PATTERNS: Set[str] = {
    "admin", "write:all", "read:all", "*", ".*",
    "root", "superadmin", "super_admin", "full_access",
    "all", "manage:all", "scope:all",
}

# Redirect URI variable patterns
REDIRECT_URI_PATTERNS: Set[str] = {
    "redirect_uri", "redirecturi", "redirect_url", "redirecturl",
    "callback_url", "callbackurl", "callback_uri", "callbackuri",
    "redirectto", "redirect_to",
}

# User input source patterns (indicates redirect_uri from user input)
USER_INPUT_SOURCES: Set[str] = {
    "req.query", "req.params", "req.body", "request.query",
    "request.params", "request.body", "request.args",
    "request.form", "request.get", "params",
    "searchparams", "searchParams", "urlsearchparams",
    "query.get", "getquerystring", "get_query_string",
    "useSearchParams", "event.queryStringParameters",
    "ctx.query", "context.query",
    "headers", "req.headers", "request.headers",
}

# Supabase-specific patterns
SUPABASE_OAUTH_METHODS: Set[str] = {
    "signinwithoauth", "signInWithOAuth",
    "signinwithoidc", "signInWithOIDC",
}

SUPABASE_SESSION_METHODS: Set[str] = {
    "getsession", "getSession", "get_session",
}

SUPABASE_VERIFY_METHODS: Set[str] = {
    "getuser", "getUser", "get_user",
}

# localStorage/sessionStorage patterns for token storage
STORAGE_SET_METHODS: Set[str] = {
    "setitem", "setItem",
}

STORAGE_OBJECTS: Set[str] = {
    "localstorage", "localStorage",
    "sessionstorage", "sessionStorage",
}


# ---------------------------------------------------------------------------
# AST Walking Helpers
# ---------------------------------------------------------------------------

def _get_line(node) -> int:
    """Extract line number from an AST node."""
    loc = getattr(node, "location", None)
    if loc is not None:
        return getattr(loc, "line", 0)
    return 0


def _get_column(node) -> int:
    """Extract column number from an AST node."""
    loc = getattr(node, "location", None)
    if loc is not None:
        return getattr(loc, "column", 0)
    return 0


def _get_location(node) -> Optional[SourceLocation]:
    """Extract SourceLocation from an AST node."""
    return getattr(node, "location", None)


def _callee_name(expr: Expr) -> str:
    """Extract the function/method name from a call expression."""
    if isinstance(expr, FunctionCall):
        if isinstance(expr.callee, Identifier):
            return expr.callee.name
        if isinstance(expr.callee, FieldAccess):
            return expr.callee.field_name
    if isinstance(expr, MethodCall):
        return expr.method_name
    return ""


def _full_callee_chain(expr: Expr) -> str:
    """Extract dotted callee chain like 'supabase.auth.signInWithOAuth'."""
    if isinstance(expr, FunctionCall):
        if isinstance(expr.callee, FieldAccess):
            obj_str = _expr_to_string(expr.callee.obj)
            return f"{obj_str}.{expr.callee.field_name}"
        if isinstance(expr.callee, Identifier):
            return expr.callee.name
    if isinstance(expr, MethodCall):
        obj_str = _expr_to_string(expr.obj)
        return f"{obj_str}.{expr.method_name}"
    return ""


def _expr_to_string(expr: Expr) -> str:
    """Rough string representation of an expression for pattern matching."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, StringLiteral):
        return expr.value
    if isinstance(expr, FieldAccess):
        return f"{_expr_to_string(expr.obj)}.{expr.field_name}"
    if isinstance(expr, IntLiteral):
        return str(expr.value)
    if isinstance(expr, BoolLiteral):
        return str(expr.value).lower()
    if isinstance(expr, MethodCall):
        return f"{_expr_to_string(expr.obj)}.{expr.method_name}"
    return ""


def _collect_string_values(expr: Expr) -> List[str]:
    """Collect all string literal values reachable from an expression."""
    results: List[str] = []
    if isinstance(expr, StringLiteral):
        results.append(expr.value)
    elif isinstance(expr, ListLiteral):
        for elem in expr.elements:
            results.extend(_collect_string_values(elem))
    elif isinstance(expr, FunctionCall):
        for arg in expr.args:
            results.extend(_collect_string_values(arg))
    elif isinstance(expr, MethodCall):
        results.extend(_collect_string_values(expr.obj))
        for arg in expr.args:
            results.extend(_collect_string_values(arg))
    elif isinstance(expr, BinaryOp):
        results.extend(_collect_string_values(expr.left))
        results.extend(_collect_string_values(expr.right))
    elif isinstance(expr, ConstructExpr):
        for _fname, fval in expr.fields.items():
            results.extend(_collect_string_values(fval))
    return results


def _collect_identifiers(expr: Expr) -> List[str]:
    """Collect all identifier names reachable from an expression."""
    results: List[str] = []
    if isinstance(expr, Identifier):
        results.append(expr.name)
    elif isinstance(expr, FunctionCall):
        results.extend(_collect_identifiers(expr.callee))
        for arg in expr.args:
            results.extend(_collect_identifiers(arg))
    elif isinstance(expr, MethodCall):
        results.extend(_collect_identifiers(expr.obj))
        for arg in expr.args:
            results.extend(_collect_identifiers(arg))
    elif isinstance(expr, FieldAccess):
        results.extend(_collect_identifiers(expr.obj))
    elif isinstance(expr, BinaryOp):
        results.extend(_collect_identifiers(expr.left))
        results.extend(_collect_identifiers(expr.right))
    elif isinstance(expr, ListLiteral):
        for elem in expr.elements:
            results.extend(_collect_identifiers(elem))
    elif isinstance(expr, ConstructExpr):
        for _fname, fval in expr.fields.items():
            results.extend(_collect_identifiers(fval))
    elif isinstance(expr, UnaryOp):
        results.extend(_collect_identifiers(expr.operand))
    return results


def _get_target_name(stmt: Statement) -> str:
    """Get the variable name being assigned to in a LetStmt or AssignStmt."""
    if isinstance(stmt, LetStmt):
        return stmt.name
    if isinstance(stmt, AssignStmt):
        if isinstance(stmt.target, Identifier):
            return stmt.target.name
        if isinstance(stmt.target, FieldAccess):
            return stmt.target.field_name
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


def _has_construct_key(expr: Expr, key_names: Set[str]) -> bool:
    """Check if a function/method call has a ConstructExpr arg with a matching key."""
    args: List[Expr] = []
    if isinstance(expr, FunctionCall):
        args = expr.args
    elif isinstance(expr, MethodCall):
        args = expr.args

    for arg in args:
        if isinstance(arg, ConstructExpr):
            for fname in arg.fields:
                if fname.lower() in {k.lower() for k in key_names}:
                    return True
        # Also check nested ConstructExpr in ConstructExpr fields
        if isinstance(arg, ConstructExpr):
            for _fname, fval in arg.fields.items():
                if isinstance(fval, ConstructExpr):
                    for inner_name in fval.fields:
                        if inner_name.lower() in {k.lower() for k in key_names}:
                            return True
    return False


def _has_string_arg_containing(args: List[Expr], patterns: Set[str]) -> Optional[str]:
    """Check if any string argument contains any of the patterns (case-insensitive)."""
    for arg in args:
        if isinstance(arg, StringLiteral):
            val_lower = arg.value.lower()
            for pattern in patterns:
                if pattern.lower() in val_lower:
                    return arg.value
    return None


def _collect_all_exprs(stmts: List[Statement]) -> List[Tuple[Expr, Statement]]:
    """Recursively collect all expressions from a statement list with parent statement."""
    results: List[Tuple[Expr, Statement]] = []

    def _walk_expr(expr: Expr, parent: Statement) -> None:
        results.append((expr, parent))
        if isinstance(expr, BinaryOp):
            _walk_expr(expr.left, parent)
            _walk_expr(expr.right, parent)
        elif isinstance(expr, UnaryOp):
            _walk_expr(expr.operand, parent)
        elif isinstance(expr, FunctionCall):
            _walk_expr(expr.callee, parent)
            for arg in expr.args:
                _walk_expr(arg, parent)
        elif isinstance(expr, MethodCall):
            _walk_expr(expr.obj, parent)
            for arg in expr.args:
                _walk_expr(arg, parent)
        elif isinstance(expr, FieldAccess):
            _walk_expr(expr.obj, parent)
        elif isinstance(expr, ListLiteral):
            for elem in expr.elements:
                _walk_expr(elem, parent)
        elif isinstance(expr, ConstructExpr):
            for _fname, fval in expr.fields.items():
                _walk_expr(fval, parent)

    for stmt in stmts:
        if isinstance(stmt, LetStmt) and stmt.value:
            _walk_expr(stmt.value, stmt)
        elif isinstance(stmt, AssignStmt):
            _walk_expr(stmt.target, stmt)
            _walk_expr(stmt.value, stmt)
        elif isinstance(stmt, ExprStmt):
            _walk_expr(stmt.expr, stmt)
        elif isinstance(stmt, ReturnStmt) and stmt.value:
            _walk_expr(stmt.value, stmt)
        elif isinstance(stmt, IfStmt):
            _walk_expr(stmt.condition, stmt)
            results.extend(_collect_all_exprs(stmt.then_body))
            if stmt.else_body:
                results.extend(_collect_all_exprs(stmt.else_body))
        elif isinstance(stmt, WhileStmt):
            _walk_expr(stmt.condition, stmt)
            results.extend(_collect_all_exprs(stmt.body))
        elif isinstance(stmt, ForStmt):
            _walk_expr(stmt.iterable, stmt)
            results.extend(_collect_all_exprs(stmt.body))

    return results


def _name_matches(name: str, patterns: Set[str]) -> bool:
    """Check if a name matches any pattern (case-insensitive substring)."""
    name_lower = name.lower()
    return any(p.lower() in name_lower for p in patterns)


def _is_oauth_context(chain: str) -> bool:
    """Check if a callee chain involves OAuth/OIDC operations."""
    lower = chain.lower()
    return any(kw in lower for kw in (
        "oauth", "oidc", "openid", "authorize", "authorization",
        "auth.signin", "auth.login", "auth.signinwith",
    ))


def _function_body_contains_call(body: List[Statement], names: Set[str]) -> bool:
    """Check if a function body contains any call to the named functions."""
    exprs = _collect_all_exprs(body)
    for expr, _ in exprs:
        if isinstance(expr, (FunctionCall, MethodCall)):
            cname = _callee_name(expr).lower()
            if any(n.lower() in cname for n in names):
                return True
            chain = _full_callee_chain(expr).lower()
            if any(n.lower() in chain for n in names):
                return True
    return False


def _function_body_contains_string(body: List[Statement], patterns: Set[str]) -> bool:
    """Check if a function body contains any string literal matching patterns."""
    exprs = _collect_all_exprs(body)
    for expr, _ in exprs:
        if isinstance(expr, StringLiteral):
            val_lower = expr.value.lower()
            for pattern in patterns:
                if pattern.lower() in val_lower:
                    return True
    return False


# ---------------------------------------------------------------------------
# OAuth/OIDC Analyzer
# ---------------------------------------------------------------------------

class OAuthOidcAnalyzer:
    """Scans AEON AST for OAuth 2.0/2.1 and OpenID Connect security vulnerabilities."""

    def __init__(self):
        self.findings: List[OAuthFinding] = []
        self._current_func_name: str = ""
        # Track variable assignments for cross-statement analysis
        self._var_values: Dict[str, Expr] = {}
        # Track whether the current function has certain patterns
        self._func_has_pkce: bool = False
        self._func_has_state: bool = False
        self._func_has_getuser: bool = False
        self._func_has_getsession: bool = False

    def check_program(self, program: Program) -> List[OAuthFinding]:
        """Run all OAuth/OIDC checks on the program."""
        self.findings = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.findings

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for OAuth/OIDC issues."""
        self._current_func_name = func.name
        self._var_values = {}
        self._func_has_pkce = False
        self._func_has_state = False
        self._func_has_getuser = False
        self._func_has_getsession = False

        # Pre-scan: detect PKCE, state, and Supabase patterns in the function
        self._prescan_function(func.body)

        # Main analysis pass
        for stmt in func.body:
            self._analyze_statement(stmt, func)

        # Post-function checks
        self._post_function_checks(func)

    def _prescan_function(self, body: List[Statement]) -> None:
        """Pre-scan the function body for PKCE, state, and Supabase verification."""
        exprs = _collect_all_exprs(body)
        for expr, stmt in exprs:
            # Check for PKCE parameters in any call or construct
            if isinstance(expr, ConstructExpr):
                for fname in expr.fields:
                    if fname.lower() in {p.lower() for p in PKCE_PARAMS}:
                        self._func_has_pkce = True
                    if fname.lower() == "state":
                        self._func_has_state = True

            # Check for PKCE or state in string values
            if isinstance(expr, StringLiteral):
                val_lower = expr.value.lower()
                if "code_challenge" in val_lower or "code_verifier" in val_lower:
                    self._func_has_pkce = True
                if "state=" in val_lower:
                    self._func_has_state = True
                # flowType: 'pkce' in Supabase
                if val_lower == "pkce":
                    self._func_has_pkce = True

            # Check for Supabase getUser / getSession
            if isinstance(expr, (FunctionCall, MethodCall)):
                cname = _callee_name(expr).lower()
                chain = _full_callee_chain(expr).lower()
                if any(m.lower() in cname or m.lower() in chain
                       for m in SUPABASE_VERIFY_METHODS):
                    self._func_has_getuser = True
                if any(m.lower() in cname or m.lower() in chain
                       for m in SUPABASE_SESSION_METHODS):
                    self._func_has_getsession = True

            # Check for identifiers referencing PKCE/state
            if isinstance(expr, Identifier):
                name_lower = expr.name.lower()
                if any(p.lower() in name_lower for p in PKCE_PARAMS):
                    self._func_has_pkce = True
                if name_lower == "state" or "csrfstate" in name_lower:
                    self._func_has_state = True

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Analyze a statement for OAuth/OIDC issues."""
        loc = _get_location(stmt)

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._var_values[stmt.name] = stmt.value
                self._check_expr(stmt.value, loc, var_name=stmt.name)

        elif isinstance(stmt, AssignStmt):
            target_name = _get_target_name(stmt)
            if target_name:
                self._var_values[target_name] = stmt.value
            self._check_expr(stmt.value, loc, var_name=target_name)

        elif isinstance(stmt, ExprStmt):
            self._check_expr(stmt.expr, loc)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._check_expr(stmt.value, loc)

        elif isinstance(stmt, IfStmt):
            self._check_expr(stmt.condition, loc)
            for s in stmt.then_body:
                self._analyze_statement(s, func)
            for s in stmt.else_body:
                self._analyze_statement(s, func)

        elif isinstance(stmt, WhileStmt):
            self._check_expr(stmt.condition, loc)
            for s in stmt.body:
                self._analyze_statement(s, func)

        elif isinstance(stmt, ForStmt):
            self._check_expr(stmt.iterable, loc)
            for s in stmt.body:
                self._analyze_statement(s, func)

    def _check_expr(self, expr: Expr, loc: Optional[SourceLocation],
                    var_name: str = "") -> None:
        """Run all OAuth/OIDC checks on an expression."""
        expr_loc = _get_location(expr) or loc

        if isinstance(expr, (FunctionCall, MethodCall)):
            callee = _callee_name(expr)
            chain = _full_callee_chain(expr)
            callee_lower = callee.lower()
            chain_lower = chain.lower()

            # --- Category 1: Missing PKCE ---
            self._check_missing_pkce(expr, callee_lower, chain_lower, expr_loc)

            # --- Category 2: Missing state parameter ---
            self._check_missing_state(expr, callee_lower, chain_lower, expr_loc)

            # --- Category 3: Token leakage in redirects ---
            self._check_token_in_url(expr, callee_lower, chain_lower, expr_loc)

            # --- Category 4: Open redirect ---
            self._check_open_redirect(expr, callee_lower, chain_lower, expr_loc)

            # --- Category 6: Insecure token storage ---
            self._check_insecure_storage(expr, callee_lower, chain_lower, expr_loc)

            # --- Category 7: Missing token validation ---
            self._check_token_validation(expr, callee_lower, chain_lower, expr_loc)

            # --- Category 8: Overly broad scopes ---
            self._check_broad_scopes(expr, callee_lower, chain_lower, expr_loc)

            # --- Category 9: Implicit flow ---
            self._check_implicit_flow(expr, callee_lower, chain_lower, expr_loc)

            # --- Category 10: Supabase-specific ---
            self._check_supabase_oauth(expr, callee_lower, chain_lower, expr_loc)

            # Recurse into arguments
            args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
            for arg in args:
                self._check_expr(arg, expr_loc, var_name=var_name)

        elif isinstance(expr, BinaryOp):
            self._check_expr(expr.left, expr_loc, var_name=var_name)
            self._check_expr(expr.right, expr_loc, var_name=var_name)

        # Check string literals that build authorization URLs
        elif isinstance(expr, StringLiteral):
            self._check_string_for_oauth_issues(expr, loc, var_name)

    # -----------------------------------------------------------------------
    # Category 1: Missing PKCE
    # -----------------------------------------------------------------------

    def _check_missing_pkce(self, expr: Expr, callee_lower: str,
                            chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect OAuth authorization code flow without PKCE."""
        # Check if this is an OAuth authorization call
        is_oauth_auth = any(f.lower() in callee_lower or f.lower() in chain_lower
                           for f in OAUTH_AUTH_FUNCTIONS)
        if not is_oauth_auth:
            return

        # Skip if PKCE is already present in the function
        if self._func_has_pkce:
            return

        # Check if the call itself has PKCE params
        if _has_construct_key(expr, PKCE_PARAMS):
            return

        # Check string arguments for code_challenge
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
        for arg in args:
            strings = _collect_string_values(arg)
            for s in strings:
                if "code_challenge" in s.lower() or "code_verifier" in s.lower():
                    return

        # Check for flowType: 'pkce' in nested options
        flow_type = _get_construct_field(expr, "flowType")
        if flow_type and isinstance(flow_type, StringLiteral) and flow_type.value.lower() == "pkce":
            return

        # Also check options.flowType nested in the call
        options = _get_construct_field(expr, "options")
        if options and isinstance(options, ConstructExpr):
            ft = options.fields.get("flowType") or options.fields.get("flow_type")
            if ft and isinstance(ft, StringLiteral) and ft.value.lower() == "pkce":
                return

        self._add_finding(
            FindingCategory.MISSING_PKCE,
            (
                f"OAuth authorization call '{_full_callee_chain(expr) or callee_lower}' "
                f"does not include PKCE parameters (code_challenge / code_verifier). "
                f"Without PKCE, authorization codes are vulnerable to interception "
                f"(RFC 7636). PKCE is mandatory in OAuth 2.1."
            ),
            loc,
            context=self._current_func_name,
        )

    # -----------------------------------------------------------------------
    # Category 2: Missing state parameter
    # -----------------------------------------------------------------------

    def _check_missing_state(self, expr: Expr, callee_lower: str,
                             chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect OAuth redirects without state parameter."""
        is_oauth_auth = any(f.lower() in callee_lower or f.lower() in chain_lower
                           for f in OAUTH_AUTH_FUNCTIONS)
        if not is_oauth_auth:
            return

        if self._func_has_state:
            return

        # Check call arguments for state
        if _has_construct_key(expr, STATE_PARAMS):
            return

        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
        for arg in args:
            strings = _collect_string_values(arg)
            for s in strings:
                if "state=" in s.lower():
                    return
            idents = _collect_identifiers(arg)
            for ident in idents:
                if ident.lower() == "state":
                    return

        self._add_finding(
            FindingCategory.MISSING_STATE,
            (
                f"OAuth authorization call '{_full_callee_chain(expr) or callee_lower}' "
                f"does not include a 'state' parameter for CSRF protection. "
                f"An attacker can initiate an OAuth flow and trick the victim "
                f"into completing it, binding the attacker's account."
            ),
            loc,
            context=self._current_func_name,
        )

    # -----------------------------------------------------------------------
    # Category 3: Token leakage in redirects
    # -----------------------------------------------------------------------

    def _check_token_in_url(self, expr: Expr, callee_lower: str,
                            chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect access tokens in URL fragments (response_type=token)."""
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []

        # Check for response_type=token in arguments
        for arg in args:
            strings = _collect_string_values(arg)
            for s in strings:
                s_lower = s.lower()
                if "response_type=token" in s_lower or "response_type=id_token" in s_lower:
                    self._add_finding(
                        FindingCategory.TOKEN_IN_URL,
                        (
                            f"Authorization request uses response_type containing 'token', "
                            f"which returns tokens in the URL fragment. Tokens in URLs leak "
                            f"via Referer headers, browser history, and proxy logs."
                        ),
                        loc,
                        context=self._current_func_name,
                    )
                    return

        # Check ConstructExpr fields for response_type
        response_type = _get_construct_field(expr, "response_type")
        if response_type and isinstance(response_type, StringLiteral):
            val_lower = response_type.value.lower()
            if "token" in val_lower and "code" not in val_lower:
                self._add_finding(
                    FindingCategory.TOKEN_IN_URL,
                    (
                        f"response_type='{response_type.value}' returns tokens in the "
                        f"URL fragment. Tokens in URLs leak via Referer headers, "
                        f"browser history, and proxy logs. Use 'code' with PKCE instead."
                    ),
                    loc,
                    context=self._current_func_name,
                )

    # -----------------------------------------------------------------------
    # Category 4: Open redirect in OAuth flow
    # -----------------------------------------------------------------------

    def _check_open_redirect(self, expr: Expr, callee_lower: str,
                             chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect redirect_uri constructed from user input without validation."""
        # Check if this is an OAuth-related call
        is_oauth = _is_oauth_context(chain_lower) or any(
            f.lower() in callee_lower for f in OAUTH_AUTH_FUNCTIONS
        ) or any(
            f.lower() in callee_lower for f in TOKEN_EXCHANGE_FUNCTIONS
        )
        if not is_oauth:
            return

        # Look for redirect_uri fields in the call
        for field_name in REDIRECT_URI_PATTERNS:
            redirect_val = _get_construct_field(expr, field_name)
            if redirect_val is None:
                continue

            # Check if redirect_uri comes from user input
            idents = _collect_identifiers(redirect_val)
            redirect_str = _expr_to_string(redirect_val).lower()

            for source in USER_INPUT_SOURCES:
                if source.lower() in redirect_str:
                    self._add_finding(
                        FindingCategory.OPEN_REDIRECT,
                        (
                            f"redirect_uri is derived from user input ({source}). "
                            f"An attacker can manipulate the redirect_uri to steal "
                            f"authorization codes or tokens. Validate redirect_uri "
                            f"against a pre-registered server-side allowlist."
                        ),
                        loc,
                        context=self._current_func_name,
                    )
                    return

            for ident in idents:
                ident_lower = ident.lower()
                # Check if the identifier references user input
                if ident in self._var_values:
                    val_str = _expr_to_string(self._var_values[ident]).lower()
                    for source in USER_INPUT_SOURCES:
                        if source.lower() in val_str:
                            self._add_finding(
                                FindingCategory.OPEN_REDIRECT,
                                (
                                    f"redirect_uri uses variable '{ident}' which "
                                    f"is derived from user input. An attacker can "
                                    f"manipulate the redirect_uri to steal authorization "
                                    f"codes or tokens."
                                ),
                                loc,
                                context=self._current_func_name,
                            )
                            return

    # -----------------------------------------------------------------------
    # Category 5: Authorization code injection (post-function check)
    # -----------------------------------------------------------------------

    def _check_code_injection_in_callback(self, func: PureFunc | TaskFunc) -> None:
        """Detect authorization code usage without PKCE or state validation."""
        func_name_lower = func.name.lower()

        # Only check functions that look like OAuth callbacks
        is_callback = any(kw in func_name_lower for kw in (
            "callback", "redirect", "oauth", "oidc", "handleauth",
            "handle_auth", "authcallback", "auth_callback",
        ))
        if not is_callback:
            return

        # Check if the function uses an authorization code
        has_code_usage = False
        exprs = _collect_all_exprs(func.body)
        for expr, stmt in exprs:
            if isinstance(expr, Identifier) and expr.name.lower() == "code":
                has_code_usage = True
                break
            if isinstance(expr, FieldAccess) and expr.field_name.lower() == "code":
                has_code_usage = True
                break
            if isinstance(expr, StringLiteral) and "code" in expr.value.lower():
                # Check for query param extraction: req.query.code, searchParams.get('code')
                pass

        if not has_code_usage:
            return

        # Check if PKCE or state validation is present
        if self._func_has_pkce or self._func_has_state:
            return

        self._add_finding(
            FindingCategory.CODE_INJECTION,
            (
                f"OAuth callback function '{func.name}' processes an authorization "
                f"code without PKCE (code_verifier) or state parameter validation. "
                f"An attacker can inject their authorization code into a victim's "
                f"session."
            ),
            _get_location(func),
            context=func.name,
        )

    # -----------------------------------------------------------------------
    # Category 6: Insecure token storage
    # -----------------------------------------------------------------------

    def _check_insecure_storage(self, expr: Expr, callee_lower: str,
                                chain_lower: str,
                                loc: Optional[SourceLocation]) -> None:
        """Detect OAuth tokens stored in localStorage/sessionStorage."""
        # Pattern: localStorage.setItem('access_token', ...)
        # Pattern: sessionStorage.setItem('id_token', ...)
        is_storage_set = any(m.lower() in callee_lower for m in STORAGE_SET_METHODS)
        if not is_storage_set:
            return

        # Check if the object is localStorage or sessionStorage
        is_local_storage = False
        storage_name = ""
        if isinstance(expr, MethodCall):
            obj_str = _expr_to_string(expr.obj).lower()
            for storage in STORAGE_OBJECTS:
                if storage.lower() in obj_str:
                    is_local_storage = True
                    storage_name = storage
                    break
        elif isinstance(expr, FunctionCall) and isinstance(expr.callee, FieldAccess):
            obj_str = _expr_to_string(expr.callee.obj).lower()
            for storage in STORAGE_OBJECTS:
                if storage.lower() in obj_str:
                    is_local_storage = True
                    storage_name = storage
                    break

        if not is_local_storage:
            return

        # Check if the key being stored is a token
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
        if not args:
            return

        first_arg = args[0]
        if isinstance(first_arg, StringLiteral):
            key_lower = first_arg.value.lower()
            for pattern in TOKEN_VARIABLE_PATTERNS:
                if pattern.lower() in key_lower:
                    self._add_finding(
                        FindingCategory.INSECURE_TOKEN_STORAGE,
                        (
                            f"{storage_name}.setItem('{first_arg.value}', ...) stores "
                            f"an OAuth token in browser storage. {storage_name} is "
                            f"accessible to any JavaScript on the page via XSS, "
                            f"allowing token theft."
                        ),
                        loc,
                        context=self._current_func_name,
                    )
                    return

    # -----------------------------------------------------------------------
    # Category 7: Missing token validation
    # -----------------------------------------------------------------------

    def _check_token_validation(self, expr: Expr, callee_lower: str,
                                chain_lower: str,
                                loc: Optional[SourceLocation]) -> None:
        """Detect ID tokens accepted without proper verification."""
        # Check if this is a token decode/verify call
        is_token_verify = any(f.lower() in callee_lower or f.lower() in chain_lower
                             for f in TOKEN_VERIFY_FUNCTIONS)
        if not is_token_verify:
            return

        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []

        # Check for verify=False or similar disablement
        for arg in args:
            if isinstance(arg, ConstructExpr):
                for fname, fval in arg.fields.items():
                    fname_lower = fname.lower()
                    # verify: false — disables signature verification
                    if fname_lower in ("verify", "verifysignature", "verify_signature",
                                       "checksignature", "check_signature"):
                        if isinstance(fval, BoolLiteral) and not fval.value:
                            self._add_finding(
                                FindingCategory.MISSING_TOKEN_SIGNATURE,
                                (
                                    f"Token verification call '{callee_lower}' has "
                                    f"signature verification disabled ({fname}=false). "
                                    f"Tokens without signature verification can be "
                                    f"forged by anyone."
                                ),
                                loc,
                                context=self._current_func_name,
                            )
                            return

                    # algorithms: ['none'] — disables signature entirely
                    if fname_lower in ("algorithms", "algorithm"):
                        alg_strings = _collect_string_values(fval)
                        for alg in alg_strings:
                            if alg.lower() == "none":
                                self._add_finding(
                                    FindingCategory.MISSING_TOKEN_SIGNATURE,
                                    (
                                        f"Token verification allows algorithm 'none', "
                                        f"which disables signature verification entirely. "
                                        f"Specify explicit algorithms (e.g., RS256, ES256)."
                                    ),
                                    loc,
                                    context=self._current_func_name,
                                )
                                return

            # Check for BoolLiteral false as standalone arg (some APIs: jwt.decode(token, false))
            if isinstance(arg, BoolLiteral) and not arg.value:
                # Could be verify=False positional
                self._add_finding(
                    FindingCategory.MISSING_TOKEN_SIGNATURE,
                    (
                        f"Token verification call '{callee_lower}' may have "
                        f"signature verification disabled (false argument). "
                        f"Always verify token signatures."
                    ),
                    loc,
                    context=self._current_func_name,
                )
                return

        # Check for missing audience validation
        has_aud = _has_construct_key(expr, CLAIM_AUD_CHECKS)
        if not has_aud:
            # Check if any string arg contains 'aud' or 'audience'
            for arg in args:
                strings = _collect_string_values(arg)
                for s in strings:
                    if s.lower() in ("aud", "audience"):
                        has_aud = True
                        break
                if has_aud:
                    break

        if not has_aud:
            self._add_finding(
                FindingCategory.MISSING_AUD_CHECK,
                (
                    f"Token verification call '{callee_lower}' does not validate "
                    f"the 'aud' (audience) claim. Without audience validation, "
                    f"tokens issued for a different application can be replayed."
                ),
                loc,
                context=self._current_func_name,
            )

        # Check for missing issuer validation
        has_iss = _has_construct_key(expr, CLAIM_ISS_CHECKS)
        if not has_iss:
            for arg in args:
                strings = _collect_string_values(arg)
                for s in strings:
                    if s.lower() in ("iss", "issuer"):
                        has_iss = True
                        break
                if has_iss:
                    break

        if not has_iss:
            self._add_finding(
                FindingCategory.MISSING_ISS_CHECK,
                (
                    f"Token verification call '{callee_lower}' does not validate "
                    f"the 'iss' (issuer) claim. Without issuer validation, tokens "
                    f"from an untrusted provider could be accepted."
                ),
                loc,
                context=self._current_func_name,
            )

        # Check for missing expiration validation
        has_exp = _has_construct_key(expr, CLAIM_EXP_CHECKS)
        if not has_exp:
            for arg in args:
                if isinstance(arg, ConstructExpr):
                    for fname in arg.fields:
                        fname_lower = fname.lower()
                        if fname_lower in ("ignoreexpiration", "ignore_expiration",
                                           "clocktolerance", "clock_tolerance"):
                            has_exp = True
                            break
                            # These imply expiration is being considered
                        if fname_lower in ("maxage", "max_age", "exp"):
                            has_exp = True
                            break

        # Most JWT libraries check exp by default — only flag if explicitly disabled
        for arg in args:
            if isinstance(arg, ConstructExpr):
                ignore_exp = arg.fields.get("ignoreExpiration") or arg.fields.get("ignore_expiration")
                if ignore_exp and isinstance(ignore_exp, BoolLiteral) and ignore_exp.value:
                    self._add_finding(
                        FindingCategory.MISSING_EXP_CHECK,
                        (
                            f"Token verification call '{callee_lower}' has expiration "
                            f"checking disabled (ignoreExpiration=true). Expired tokens "
                            f"will be accepted, enabling replay attacks."
                        ),
                        loc,
                        context=self._current_func_name,
                    )

        # Check for missing nonce validation (OIDC-specific)
        # Only flag in an OIDC context (chain contains oidc/openid)
        if any(kw in chain_lower for kw in ("oidc", "openid", "id_token", "idtoken")):
            has_nonce = _has_construct_key(expr, CLAIM_NONCE_CHECKS)
            if not has_nonce:
                for arg in args:
                    strings = _collect_string_values(arg)
                    for s in strings:
                        if s.lower() == "nonce":
                            has_nonce = True
                            break
                    if has_nonce:
                        break

            if not has_nonce:
                self._add_finding(
                    FindingCategory.MISSING_NONCE,
                    (
                        f"OIDC token verification call '{callee_lower}' does not "
                        f"validate the nonce. Without nonce validation, ID tokens "
                        f"can be replayed from a different authentication session."
                    ),
                    loc,
                    context=self._current_func_name,
                )

    # -----------------------------------------------------------------------
    # Category 8: Overly broad scopes
    # -----------------------------------------------------------------------

    def _check_broad_scopes(self, expr: Expr, callee_lower: str,
                            chain_lower: str,
                            loc: Optional[SourceLocation]) -> None:
        """Detect overly broad OAuth scope requests."""
        # Check if this is an OAuth-related call
        is_oauth = _is_oauth_context(chain_lower) or any(
            f.lower() in callee_lower for f in OAUTH_AUTH_FUNCTIONS
        )
        if not is_oauth:
            return

        # Look for scope field in ConstructExpr arguments
        scope_val = _get_construct_field(expr, "scope")
        if scope_val is None:
            scope_val = _get_construct_field(expr, "scopes")

        # Also check options.scopes nested pattern
        if scope_val is None:
            options = _get_construct_field(expr, "options")
            if options and isinstance(options, ConstructExpr):
                scope_val = options.fields.get("scopes") or options.fields.get("scope")

        if scope_val is None:
            return

        # Collect all scope strings
        scope_strings: List[str] = []
        if isinstance(scope_val, StringLiteral):
            # Space-separated scope string: "openid profile admin write:all"
            scope_strings = scope_val.value.split()
        elif isinstance(scope_val, ListLiteral):
            for elem in scope_val.elements:
                if isinstance(elem, StringLiteral):
                    scope_strings.append(elem.value)

        # Check each scope against broad patterns
        for scope in scope_strings:
            scope_lower = scope.lower().strip()
            for broad in BROAD_SCOPE_PATTERNS:
                if broad.lower() == scope_lower or (
                    broad.lower() in scope_lower and scope_lower != "readonly"
                ):
                    self._add_finding(
                        FindingCategory.OVERLY_BROAD_SCOPES,
                        (
                            f"OAuth scope '{scope}' is overly broad. Requesting "
                            f"more permissions than needed increases the blast radius "
                            f"of token compromise. Apply the principle of least privilege."
                        ),
                        loc,
                        context=self._current_func_name,
                    )
                    return  # One finding per call is enough

    # -----------------------------------------------------------------------
    # Category 9: Implicit flow usage
    # -----------------------------------------------------------------------

    def _check_implicit_flow(self, expr: Expr, callee_lower: str,
                             chain_lower: str,
                             loc: Optional[SourceLocation]) -> None:
        """Detect use of response_type=token (implicit grant, deprecated in OAuth 2.1)."""
        # Check ConstructExpr fields for response_type
        response_type = _get_construct_field(expr, "response_type")
        if response_type and isinstance(response_type, StringLiteral):
            val_lower = response_type.value.lower().strip()
            if val_lower == "token" or val_lower == "id_token token":
                self._add_finding(
                    FindingCategory.IMPLICIT_FLOW,
                    (
                        f"Using response_type='{response_type.value}' (implicit flow), "
                        f"which is deprecated in OAuth 2.1. Tokens are exposed in the "
                        f"URL fragment, vulnerable to interception, and cannot be "
                        f"refreshed. Use authorization code flow with PKCE instead."
                    ),
                    loc,
                    context=self._current_func_name,
                )
                return

        # Check string arguments for implicit flow
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
        for arg in args:
            strings = _collect_string_values(arg)
            for s in strings:
                s_lower = s.lower()
                # Match response_type=token in URL strings
                if re.search(r'response_type\s*=\s*token(?:\s|&|$)', s_lower):
                    self._add_finding(
                        FindingCategory.IMPLICIT_FLOW,
                        (
                            f"Authorization URL uses implicit flow (response_type=token), "
                            f"which is deprecated in OAuth 2.1. Tokens are exposed in "
                            f"the URL fragment. Use authorization code + PKCE instead."
                        ),
                        loc,
                        context=self._current_func_name,
                    )
                    return

    # -----------------------------------------------------------------------
    # Category 10: Supabase-specific
    # -----------------------------------------------------------------------

    def _check_supabase_oauth(self, expr: Expr, callee_lower: str,
                              chain_lower: str,
                              loc: Optional[SourceLocation]) -> None:
        """Detect Supabase-specific OAuth/auth issues."""
        # Check for supabase.auth.signInWithOAuth without PKCE
        is_supabase_oauth = any(
            m.lower() in callee_lower or m.lower() in chain_lower
            for m in SUPABASE_OAUTH_METHODS
        )

        if is_supabase_oauth:
            # Check for flowType: 'pkce' in options
            has_pkce = False

            # Direct options argument
            options = _get_construct_field(expr, "options")
            if options and isinstance(options, ConstructExpr):
                ft = options.fields.get("flowType") or options.fields.get("flow_type")
                if ft and isinstance(ft, StringLiteral) and ft.value.lower() == "pkce":
                    has_pkce = True

            # Top-level flowType in arguments
            if not has_pkce:
                ft = _get_construct_field(expr, "flowType")
                if ft and isinstance(ft, StringLiteral) and ft.value.lower() == "pkce":
                    has_pkce = True

            # Also check if PKCE is set elsewhere in the function
            if not has_pkce and self._func_has_pkce:
                has_pkce = True

            if not has_pkce:
                self._add_finding(
                    FindingCategory.SUPABASE_NO_PKCE,
                    (
                        f"supabase.auth.signInWithOAuth() called without "
                        f"flowType: 'pkce' in options. Without PKCE, the "
                        f"authorization code can be intercepted. Add "
                        f"{{ options: {{ flowType: 'pkce' }} }} to the call."
                    ),
                    loc,
                    context=self._current_func_name,
                )

            # Check for redirectTo from user input
            redirect_to = _get_construct_field(expr, "redirectTo")
            if redirect_to is None and options and isinstance(options, ConstructExpr):
                redirect_to = options.fields.get("redirectTo") or options.fields.get("redirect_to")

            if redirect_to:
                redirect_str = _expr_to_string(redirect_to).lower()
                idents = _collect_identifiers(redirect_to)
                for source in USER_INPUT_SOURCES:
                    if source.lower() in redirect_str:
                        self._add_finding(
                            FindingCategory.SUPABASE_REDIRECT_UNVALIDATED,
                            (
                                f"supabase.auth.signInWithOAuth() redirectTo is derived "
                                f"from user input ({source}). An attacker can manipulate "
                                f"the redirect URL to steal the authorization code."
                            ),
                            loc,
                            context=self._current_func_name,
                        )
                        break
                else:
                    # Check variables that hold user input
                    for ident in idents:
                        if ident in self._var_values:
                            val_str = _expr_to_string(self._var_values[ident]).lower()
                            for source in USER_INPUT_SOURCES:
                                if source.lower() in val_str:
                                    self._add_finding(
                                        FindingCategory.SUPABASE_REDIRECT_UNVALIDATED,
                                        (
                                            f"supabase.auth.signInWithOAuth() redirectTo "
                                            f"uses variable '{ident}' which is derived "
                                            f"from user input."
                                        ),
                                        loc,
                                        context=self._current_func_name,
                                    )
                                    break

        # Check for getSession() without getUser() on server-side patterns
        is_get_session = any(
            m.lower() in callee_lower or m.lower() in chain_lower
            for m in SUPABASE_SESSION_METHODS
        )
        if is_get_session and "supabase" in chain_lower and "auth" in chain_lower:
            # This is supabase.auth.getSession() — flag it in the prescan,
            # the post-function check will handle the finding
            pass

    # -----------------------------------------------------------------------
    # String literal checks
    # -----------------------------------------------------------------------

    def _check_string_for_oauth_issues(self, expr: StringLiteral,
                                       loc: Optional[SourceLocation],
                                       var_name: str) -> None:
        """Check string literals for OAuth URL patterns with issues."""
        val = expr.value
        val_lower = val.lower()

        # Check for authorization endpoint URLs with issues
        has_auth_endpoint = any(ep in val_lower for ep in AUTH_ENDPOINT_URL_PATTERNS)
        if not has_auth_endpoint:
            return

        # Check for implicit flow in URL
        if re.search(r'response_type\s*=\s*token(?:\s|&|$|#)', val_lower):
            self._add_finding(
                FindingCategory.IMPLICIT_FLOW,
                (
                    f"Authorization URL string uses response_type=token (implicit flow), "
                    f"which is deprecated in OAuth 2.1. Use authorization code + PKCE."
                ),
                _get_location(expr) or loc,
                context=self._current_func_name,
            )

        # Check for missing state in URL
        if "state=" not in val_lower and not self._func_has_state:
            # Only flag if the URL contains other query params (it's being built inline)
            if "?" in val and ("client_id" in val_lower or "redirect_uri" in val_lower):
                self._add_finding(
                    FindingCategory.MISSING_STATE,
                    (
                        f"Authorization URL is constructed without a 'state' parameter. "
                        f"Add a cryptographically random state parameter bound to the "
                        f"user's session to prevent CSRF attacks."
                    ),
                    _get_location(expr) or loc,
                    context=self._current_func_name,
                )

        # Check for missing PKCE in URL
        if "code_challenge=" not in val_lower and not self._func_has_pkce:
            if "?" in val and "response_type=code" in val_lower:
                self._add_finding(
                    FindingCategory.MISSING_PKCE,
                    (
                        f"Authorization URL uses response_type=code without "
                        f"code_challenge (PKCE). Add code_challenge and "
                        f"code_challenge_method=S256 to the URL."
                    ),
                    _get_location(expr) or loc,
                    context=self._current_func_name,
                )

    # -----------------------------------------------------------------------
    # Post-function checks
    # -----------------------------------------------------------------------

    def _post_function_checks(self, func: PureFunc | TaskFunc) -> None:
        """Run checks that require whole-function context."""
        # Category 5: Authorization code injection in callbacks
        self._check_code_injection_in_callback(func)

        # Category 10: Supabase getSession without getUser
        if self._func_has_getsession and not self._func_has_getuser:
            # Check if this looks like a server-side function
            func_name_lower = func.name.lower()
            is_server_context = any(kw in func_name_lower for kw in (
                "server", "api", "handler", "middleware", "route",
                "endpoint", "loader", "action", "getserversideprops",
                "get_server_side_props", "getstaticprops",
            ))

            # Also check for server-side patterns in function body
            if not is_server_context:
                server_indicators = {
                    "NextResponse", "res.json", "res.status", "res.send",
                    "cookies", "headers", "redirect", "json(",
                }
                exprs = _collect_all_exprs(func.body)
                for expr, _ in exprs:
                    if isinstance(expr, Identifier) and expr.name in server_indicators:
                        is_server_context = True
                        break
                    if isinstance(expr, (FunctionCall, MethodCall)):
                        chain = _full_callee_chain(expr)
                        if any(si in chain for si in server_indicators):
                            is_server_context = True
                            break

            if is_server_context:
                self._add_finding(
                    FindingCategory.SUPABASE_SESSION_NOT_VERIFIED,
                    (
                        f"Server-side function '{func.name}' uses "
                        f"supabase.auth.getSession() without supabase.auth.getUser(). "
                        f"getSession() reads the JWT without server-side verification "
                        f"— the session can be spoofed from the client. Use getUser() "
                        f"which makes an authenticated call to Supabase Auth."
                    ),
                    _get_location(func),
                    context=func.name,
                )

    # -----------------------------------------------------------------------
    # Finding management
    # -----------------------------------------------------------------------

    def _add_finding(self, category: FindingCategory, message: str,
                     location: Optional[SourceLocation], context: str = "") -> None:
        """Add a finding, deduplicating by category + location."""
        for existing in self.findings:
            if existing.category == category and existing.location == location:
                return

        self.findings.append(OAuthFinding(
            category=category,
            message=message,
            location=location,
            context=context,
        ))


# ---------------------------------------------------------------------------
# Finding to AeonError Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: OAuthFinding) -> AeonError:
    """Convert an OAuthFinding into an AeonError."""
    cwe = CWE_MAP.get(finding.category, "CWE-346")
    severity = SEVERITY_MAP.get(finding.category, Severity.MEDIUM)
    severity_label = severity.value.upper()
    remediation = REMEDIATION.get(finding.category, "Review OAuth/OIDC security configuration")
    category_label = finding.category.value.replace("_", " ").title()

    context_suffix = ""
    if finding.context:
        context_suffix = f" [{finding.context}]"

    return contract_error(
        precondition=(
            f"OAuth & OIDC Security ({cwe}) -- "
            f"[{severity_label}] {category_label}{context_suffix}: {finding.message}"
        ),
        failing_values={
            "category": finding.category.value,
            "severity": severity.value,
            "cwe": cwe,
            "remediation": remediation,
            "engine": "OAuth & OIDC Security",
        },
        function_signature="oauth_oidc",
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_oauth_oidc(program: Program) -> list:
    """Run OAuth 2.0/2.1 and OpenID Connect security analysis on an AEON program.

    Scans the AST for OAuth/OIDC vulnerabilities including missing PKCE, CSRF
    via missing state, implicit flow usage, token leakage, open redirects,
    insecure token storage, missing token validation, overly broad scopes,
    and Supabase-specific auth issues.

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected vulnerability.

    Detection categories:
        1. Missing PKCE (CWE-346)
        2. Missing state parameter (CWE-352)
        3. Token leakage in redirects (CWE-601)
        4. Open redirect in OAuth flow (CWE-601)
        5. Authorization code injection (CWE-345)
        6. Insecure token storage (CWE-922)
        7. Missing token validation (CWE-345)
        8. Overly broad scopes (CWE-269)
        9. Implicit flow usage (CWE-346)
        10. Supabase-specific issues (CWE-345, CWE-346, CWE-601)

    CWEs:
        CWE-345: Insufficient Verification of Data Authenticity
        CWE-346: Origin Validation Error
        CWE-352: Cross-Site Request Forgery (CSRF)
        CWE-601: URL Redirection to Untrusted Site
        CWE-269: Improper Privilege Management
        CWE-922: Insecure Storage of Sensitive Information
    """
    try:
        analyzer = OAuthOidcAnalyzer()
        findings = analyzer.check_program(program)
        return [_finding_to_error(f) for f in findings]
    except Exception:
        # Engine-level safety net: never let the engine crash
        # the verification pipeline
        return []
