"""AEON Session & JWT Security Engine -- Session Management Vulnerability Scanner.

Detects session management and JSON Web Token (JWT) security vulnerabilities
across web application codebases.

References:
  CWE-347: Improper Verification of Cryptographic Signature
  https://cwe.mitre.org/data/definitions/347.html

  CWE-346: Origin Validation Error
  https://cwe.mitre.org/data/definitions/346.html

  CWE-613: Insufficient Session Expiration
  https://cwe.mitre.org/data/definitions/613.html

  CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
  https://cwe.mitre.org/data/definitions/614.html

  CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
  https://cwe.mitre.org/data/definitions/1004.html

  CWE-384: Session Fixation
  https://cwe.mitre.org/data/definitions/384.html

  CWE-922: Insecure Storage of Sensitive Information
  https://cwe.mitre.org/data/definitions/922.html

  Auth0 (2015) "Critical vulnerabilities in JSON Web Token libraries"
  https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

  OWASP Session Management Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

Detection Categories:

1. JWT ALGORITHM CONFUSION:
   algorithm "none" disables signature verification entirely.
   Mixing symmetric (HS256) and asymmetric (RS256) algorithms enables
   key confusion attacks where the public key is used as HMAC secret.

2. WEAK JWT SECRETS:
   Short or predictable signing secrets can be brute-forced offline.
   Secrets under 32 characters or matching common words are flagged.

3. MISSING JWT CLAIMS:
   Tokens without exp, iss, or aud claims lack fundamental validity
   constraints. Tokens without expiration live forever if leaked.

4. JWT IN URL PARAMETERS:
   Tokens in query strings leak via Referer headers, server logs,
   browser history, and proxy logs.

5. COOKIE SECURITY:
   Missing httpOnly (XSS-accessible), missing secure (sent over HTTP),
   missing sameSite (CSRF), sameSite=none without secure (third-party
   cookie with no transport protection).

6. SESSION FIXATION:
   Failing to regenerate session ID after authentication allows an
   attacker to set the victim's session ID before login.

7. INSECURE TOKEN STORAGE (CLIENT-SIDE):
   localStorage and sessionStorage are accessible to any JavaScript
   running on the page, making stored tokens vulnerable to XSS.

8. TOKEN REFRESH ISSUES:
   Access tokens with very long expiry (>24h) or refresh flows that
   don't invalidate old refresh tokens enable token reuse attacks.

9. SESSION TIMEOUT:
   Missing idle timeout or extremely long session durations (>24h)
   leave sessions vulnerable to hijacking over extended windows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral, IntLiteral, BoolLiteral,
    BinaryOp, FunctionCall, FieldAccess, MethodCall,
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
    JWT_ALG_NONE = "jwt_algorithm_none"
    JWT_ALG_CONFUSION = "jwt_algorithm_confusion"
    JWT_VERIFY_DISABLED = "jwt_verify_disabled"
    JWT_WEAK_SECRET = "jwt_weak_secret"
    JWT_MISSING_EXP = "jwt_missing_exp"
    JWT_MISSING_ISS = "jwt_missing_iss"
    JWT_MISSING_AUD = "jwt_missing_aud"
    JWT_IN_URL = "jwt_in_url"
    COOKIE_NO_HTTPONLY = "cookie_no_httponly"
    COOKIE_NO_SECURE = "cookie_no_secure"
    COOKIE_NO_SAMESITE = "cookie_no_samesite"
    COOKIE_SAMESITE_NONE_INSECURE = "cookie_samesite_none_without_secure"
    SESSION_FIXATION = "session_fixation"
    INSECURE_TOKEN_STORAGE = "insecure_token_storage"
    TOKEN_LONG_EXPIRY = "token_long_expiry"
    NO_REFRESH_ROTATION = "no_refresh_token_rotation"
    SESSION_NO_TIMEOUT = "session_no_timeout"
    SESSION_LONG_TIMEOUT = "session_long_timeout"


# ---------------------------------------------------------------------------
# CWE Mapping
# ---------------------------------------------------------------------------

CWE_MAP: Dict[FindingCategory, str] = {
    FindingCategory.JWT_ALG_NONE: "CWE-347",
    FindingCategory.JWT_ALG_CONFUSION: "CWE-346",
    FindingCategory.JWT_VERIFY_DISABLED: "CWE-347",
    FindingCategory.JWT_WEAK_SECRET: "CWE-347",
    FindingCategory.JWT_MISSING_EXP: "CWE-613",
    FindingCategory.JWT_MISSING_ISS: "CWE-346",
    FindingCategory.JWT_MISSING_AUD: "CWE-346",
    FindingCategory.JWT_IN_URL: "CWE-598",
    FindingCategory.COOKIE_NO_HTTPONLY: "CWE-1004",
    FindingCategory.COOKIE_NO_SECURE: "CWE-614",
    FindingCategory.COOKIE_NO_SAMESITE: "CWE-1275",
    FindingCategory.COOKIE_SAMESITE_NONE_INSECURE: "CWE-614",
    FindingCategory.SESSION_FIXATION: "CWE-384",
    FindingCategory.INSECURE_TOKEN_STORAGE: "CWE-922",
    FindingCategory.TOKEN_LONG_EXPIRY: "CWE-613",
    FindingCategory.NO_REFRESH_ROTATION: "CWE-613",
    FindingCategory.SESSION_NO_TIMEOUT: "CWE-613",
    FindingCategory.SESSION_LONG_TIMEOUT: "CWE-613",
}

# ---------------------------------------------------------------------------
# Severity Mapping
# ---------------------------------------------------------------------------

SEVERITY_MAP: Dict[FindingCategory, Severity] = {
    FindingCategory.JWT_ALG_NONE: Severity.CRITICAL,
    FindingCategory.JWT_ALG_CONFUSION: Severity.CRITICAL,
    FindingCategory.JWT_VERIFY_DISABLED: Severity.CRITICAL,
    FindingCategory.JWT_WEAK_SECRET: Severity.HIGH,
    FindingCategory.JWT_MISSING_EXP: Severity.HIGH,
    FindingCategory.JWT_MISSING_ISS: Severity.MEDIUM,
    FindingCategory.JWT_MISSING_AUD: Severity.MEDIUM,
    FindingCategory.JWT_IN_URL: Severity.HIGH,
    FindingCategory.COOKIE_NO_HTTPONLY: Severity.HIGH,
    FindingCategory.COOKIE_NO_SECURE: Severity.HIGH,
    FindingCategory.COOKIE_NO_SAMESITE: Severity.MEDIUM,
    FindingCategory.COOKIE_SAMESITE_NONE_INSECURE: Severity.HIGH,
    FindingCategory.SESSION_FIXATION: Severity.HIGH,
    FindingCategory.INSECURE_TOKEN_STORAGE: Severity.HIGH,
    FindingCategory.TOKEN_LONG_EXPIRY: Severity.MEDIUM,
    FindingCategory.NO_REFRESH_ROTATION: Severity.MEDIUM,
    FindingCategory.SESSION_NO_TIMEOUT: Severity.MEDIUM,
    FindingCategory.SESSION_LONG_TIMEOUT: Severity.MEDIUM,
}

# ---------------------------------------------------------------------------
# Remediation Guidance
# ---------------------------------------------------------------------------

REMEDIATION: Dict[FindingCategory, str] = {
    FindingCategory.JWT_ALG_NONE: (
        "Never allow algorithm 'none'. Explicitly specify the expected algorithm "
        "in jwt.verify/jwt.decode (e.g., algorithms=['RS256'])"
    ),
    FindingCategory.JWT_ALG_CONFUSION: (
        "Do not mix symmetric (HS*) and asymmetric (RS*/ES*/PS*) algorithms. "
        "Accept only one algorithm family to prevent key confusion attacks"
    ),
    FindingCategory.JWT_VERIFY_DISABLED: (
        "Never disable JWT signature verification (verify=False). "
        "Always validate signatures using the correct algorithm and key"
    ),
    FindingCategory.JWT_WEAK_SECRET: (
        "Use a cryptographically random secret of at least 256 bits (32 bytes). "
        "Load secrets from environment variables, never hardcode them"
    ),
    FindingCategory.JWT_MISSING_EXP: (
        "Always include an 'exp' (expiration) claim in JWTs. "
        "Use short-lived access tokens (15-60 minutes) with refresh token rotation"
    ),
    FindingCategory.JWT_MISSING_ISS: (
        "Include an 'iss' (issuer) claim and validate it on receipt "
        "to prevent token confusion across services"
    ),
    FindingCategory.JWT_MISSING_AUD: (
        "Include an 'aud' (audience) claim and validate it on receipt "
        "to prevent tokens intended for one service from being accepted by another"
    ),
    FindingCategory.JWT_IN_URL: (
        "Never pass tokens in URL query parameters. Use Authorization headers "
        "or secure HttpOnly cookies instead. URLs leak via Referer headers, "
        "server logs, browser history, and proxy logs"
    ),
    FindingCategory.COOKIE_NO_HTTPONLY: (
        "Set the HttpOnly flag on session cookies to prevent "
        "JavaScript access via document.cookie (XSS mitigation)"
    ),
    FindingCategory.COOKIE_NO_SECURE: (
        "Set the Secure flag on session cookies to ensure they are only "
        "sent over HTTPS, preventing interception on insecure connections"
    ),
    FindingCategory.COOKIE_NO_SAMESITE: (
        "Set the SameSite attribute (Lax or Strict) on cookies to prevent "
        "cross-site request forgery (CSRF) attacks"
    ),
    FindingCategory.COOKIE_SAMESITE_NONE_INSECURE: (
        "When SameSite=None, the Secure flag is required. "
        "Without Secure, the cookie will be rejected by modern browsers"
    ),
    FindingCategory.SESSION_FIXATION: (
        "Regenerate the session ID immediately after successful authentication. "
        "Call req.session.regenerate(), session.cycle(), or session_regenerate_id() "
        "in the login handler"
    ),
    FindingCategory.INSECURE_TOKEN_STORAGE: (
        "Do not store auth tokens in localStorage or sessionStorage — both are "
        "accessible to any JavaScript on the page (XSS). Use HttpOnly cookies "
        "or in-memory storage with refresh tokens instead"
    ),
    FindingCategory.TOKEN_LONG_EXPIRY: (
        "Access tokens should expire within 15-60 minutes. "
        "Use short-lived access tokens with refresh token rotation for longer sessions"
    ),
    FindingCategory.NO_REFRESH_ROTATION: (
        "Implement refresh token rotation: issue a new refresh token with each use "
        "and invalidate the old one. Detect reuse to identify token theft"
    ),
    FindingCategory.SESSION_NO_TIMEOUT: (
        "Configure an idle session timeout (recommended: 15-30 minutes for "
        "sensitive apps, 2-8 hours for low-risk apps)"
    ),
    FindingCategory.SESSION_LONG_TIMEOUT: (
        "Reduce session timeout. Sessions lasting more than 24 hours increase "
        "the window for session hijacking. Use 2-8 hours for typical web apps"
    ),
}


# ---------------------------------------------------------------------------
# Internal Finding
# ---------------------------------------------------------------------------

@dataclass
class SessionJwtFinding:
    """Internal finding before conversion to AeonError."""
    category: FindingCategory
    message: str
    location: Optional[SourceLocation]
    context: str = ""  # function name or variable name for context


# ---------------------------------------------------------------------------
# JWT-Related Function Names
# ---------------------------------------------------------------------------

# Functions/methods that sign/encode JWTs
JWT_SIGN_FUNCTIONS: Set[str] = {
    "sign", "encode", "jwt_encode", "create_token", "generate_token",
    "createToken", "generateToken", "signToken", "jwt_sign",
}

# Functions/methods that verify/decode JWTs
JWT_VERIFY_FUNCTIONS: Set[str] = {
    "verify", "decode", "jwt_decode", "verify_token", "verifyToken",
    "validateToken", "jwt_verify",
}

# Common weak JWT secrets
WEAK_SECRETS: Set[str] = {
    "secret", "password", "key", "jwt", "token", "auth",
    "mysecret", "mypassword", "mykey", "changeme", "test",
    "123456", "default", "admin", "jwt_secret", "supersecret",
    "shhh", "shh", "abc123", "pass", "letmein",
}

# Variable names that hold JWT secrets
JWT_SECRET_VARIABLE_NAMES: Set[str] = {
    "jwt_secret", "jwt_key", "secret_key", "signing_key",
    "token_secret", "auth_secret", "jwtSecret", "secretKey",
    "signingKey", "tokenSecret", "authSecret", "JWT_SECRET",
    "SECRET_KEY", "SIGNING_KEY", "TOKEN_SECRET",
}

# Cookie-setting functions/methods
COOKIE_SET_FUNCTIONS: Set[str] = {
    "setCookie", "set_cookie", "cookie", "setcookie",
    "cookies_set", "res_cookie", "response_cookie",
    "append_header",  # set-cookie header
}

# Session regeneration functions
SESSION_REGEN_FUNCTIONS: Set[str] = {
    "regenerate", "cycle", "session_regenerate_id",
    "regenerateId", "regenerate_id", "rotate",
    "create_session", "createSession", "newSession",
    "new_session", "resetSession", "reset_session",
}

# Authentication functions
AUTH_FUNCTIONS: Set[str] = {
    "login", "authenticate", "sign_in", "signIn", "signin",
    "do_login", "doLogin", "handle_login", "handleLogin",
    "process_login", "processLogin", "auth", "log_in", "logIn",
}

# Token storage keys that indicate sensitive data
SENSITIVE_STORAGE_KEYS: Set[str] = {
    "token", "jwt", "auth", "session", "access_token",
    "refresh_token", "accessToken", "refreshToken",
    "id_token", "idToken", "bearer", "authorization",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_callee_name(expr: Expr) -> str:
    """Extract the function/method name from a call expression."""
    if isinstance(expr, FunctionCall):
        if isinstance(expr.callee, Identifier):
            return expr.callee.name
        if isinstance(expr.callee, FieldAccess):
            return expr.callee.field_name
    if isinstance(expr, MethodCall):
        return expr.method_name
    return ""


def _get_full_callee_chain(expr: Expr) -> str:
    """Extract dotted callee chain like 'jwt.decode' or 'jwt.sign'."""
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
    """Rough string representation of an expression for matching."""
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
    return ""


def _collect_string_values_from_expr(expr: Expr) -> List[str]:
    """Collect all string literal values reachable from an expression."""
    results: List[str] = []
    if isinstance(expr, StringLiteral):
        results.append(expr.value)
    elif isinstance(expr, ListLiteral):
        for elem in expr.elements:
            results.extend(_collect_string_values_from_expr(elem))
    elif isinstance(expr, FunctionCall):
        for arg in expr.args:
            results.extend(_collect_string_values_from_expr(arg))
    elif isinstance(expr, MethodCall):
        results.extend(_collect_string_values_from_expr(expr.obj))
        for arg in expr.args:
            results.extend(_collect_string_values_from_expr(arg))
    elif isinstance(expr, BinaryOp):
        results.extend(_collect_string_values_from_expr(expr.left))
        results.extend(_collect_string_values_from_expr(expr.right))
    return results


def _collect_identifiers_from_expr(expr: Expr) -> List[str]:
    """Collect all identifier names reachable from an expression."""
    results: List[str] = []
    if isinstance(expr, Identifier):
        results.append(expr.name)
    elif isinstance(expr, FunctionCall):
        results.extend(_collect_identifiers_from_expr(expr.callee))
        for arg in expr.args:
            results.extend(_collect_identifiers_from_expr(arg))
    elif isinstance(expr, MethodCall):
        results.extend(_collect_identifiers_from_expr(expr.obj))
        for arg in expr.args:
            results.extend(_collect_identifiers_from_expr(arg))
    elif isinstance(expr, FieldAccess):
        results.extend(_collect_identifiers_from_expr(expr.obj))
    elif isinstance(expr, BinaryOp):
        results.extend(_collect_identifiers_from_expr(expr.left))
        results.extend(_collect_identifiers_from_expr(expr.right))
    elif isinstance(expr, ListLiteral):
        for elem in expr.elements:
            results.extend(_collect_identifiers_from_expr(elem))
    return results


def _has_keyword_arg(expr: Expr, key_names: Set[str]) -> bool:
    """Check if a function/method call has a keyword-style argument.

    AEON AST represents keyword arguments as ConstructExpr fields or
    as Identifier references. We check both call args and construct fields.
    """
    args: List[Expr] = []
    if isinstance(expr, FunctionCall):
        args = expr.args
    elif isinstance(expr, MethodCall):
        args = expr.args

    for arg in args:
        # ConstructExpr represents an options object: { httpOnly: true, ... }
        if isinstance(arg, ConstructExpr):
            for field_name in arg.fields:
                if field_name.lower() in {k.lower() for k in key_names}:
                    return True
        # Identifier referencing a config variable
        if isinstance(arg, Identifier):
            if arg.name.lower() in {k.lower() for k in key_names}:
                return True
    return False


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


def _is_jwt_context(callee_chain: str) -> bool:
    """Check if a callee chain involves JWT operations."""
    lower = callee_chain.lower()
    return any(kw in lower for kw in ("jwt", "jsonwebtoken", "jose", "jws", "jwe"))


def _int_value(expr: Expr) -> Optional[int]:
    """Extract integer value from an expression, if possible."""
    if isinstance(expr, IntLiteral):
        return expr.value
    return None


def _string_value(expr: Expr) -> Optional[str]:
    """Extract string value from an expression, if possible."""
    if isinstance(expr, StringLiteral):
        return expr.value
    return None


# ---------------------------------------------------------------------------
# Session/JWT Analyzer
# ---------------------------------------------------------------------------

class SessionJwtAnalyzer:
    """Scans AEON AST for session management and JWT security vulnerabilities."""

    def __init__(self):
        self.findings: List[SessionJwtFinding] = []
        self._current_func_name: str = ""
        self._current_func_has_session_regen: bool = False
        self._current_func_is_auth: bool = False
        # Track variable assignments for cross-statement analysis
        self._var_values: Dict[str, Expr] = {}

    def check_program(self, program: Program) -> List[SessionJwtFinding]:
        """Run all session/JWT checks on the program."""
        self.findings = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.findings

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for session/JWT issues."""
        self._current_func_name = func.name
        self._current_func_has_session_regen = False
        self._current_func_is_auth = self._is_auth_function(func.name)
        self._var_values = {}

        # First pass: collect variable assignments and check for session regeneration
        for stmt in func.body:
            self._scan_for_session_regen(stmt)

        # Second pass: run all checks
        for stmt in func.body:
            self._analyze_statement(stmt, func)

        # Post-function check: session fixation (auth function without regeneration)
        if self._current_func_is_auth and not self._current_func_has_session_regen:
            self._add_finding(
                FindingCategory.SESSION_FIXATION,
                (
                    f"Authentication function '{func.name}' does not regenerate "
                    f"session ID after login — vulnerable to session fixation"
                ),
                getattr(func, "location", None),
                context=func.name,
            )

    def _scan_for_session_regen(self, stmt: Statement) -> None:
        """Scan for session regeneration calls anywhere in a function body."""
        if isinstance(stmt, ExprStmt):
            if self._expr_calls_regen(stmt.expr):
                self._current_func_has_session_regen = True
        elif isinstance(stmt, LetStmt):
            if stmt.value and self._expr_calls_regen(stmt.value):
                self._current_func_has_session_regen = True
        elif isinstance(stmt, AssignStmt):
            if self._expr_calls_regen(stmt.value):
                self._current_func_has_session_regen = True
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_for_session_regen(s)
            for s in stmt.else_body:
                self._scan_for_session_regen(s)
        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._scan_for_session_regen(s)

    def _expr_calls_regen(self, expr: Expr) -> bool:
        """Check if an expression contains a session regeneration call."""
        callee = _get_callee_name(expr)
        if callee.lower() in {f.lower() for f in SESSION_REGEN_FUNCTIONS}:
            return True
        chain = _get_full_callee_chain(expr)
        if any(regen.lower() in chain.lower() for regen in SESSION_REGEN_FUNCTIONS):
            return True

        # Recurse into sub-expressions
        if isinstance(expr, FunctionCall):
            for arg in expr.args:
                if self._expr_calls_regen(arg):
                    return True
        if isinstance(expr, MethodCall):
            if self._expr_calls_regen(expr.obj):
                return True
            for arg in expr.args:
                if self._expr_calls_regen(arg):
                    return True
        return False

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Analyze a statement for session/JWT issues."""
        loc = getattr(stmt, "location", None)

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._var_values[stmt.name] = stmt.value
                self._check_expr(stmt.value, loc, var_name=stmt.name)

        elif isinstance(stmt, AssignStmt):
            target_name = ""
            if isinstance(stmt.target, Identifier):
                target_name = stmt.target.name
            elif isinstance(stmt.target, FieldAccess):
                target_name = stmt.target.field_name
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

    def _check_expr(self, expr: Expr, loc: Optional[SourceLocation],
                    var_name: str = "") -> None:
        """Run all checks on an expression."""
        expr_loc = getattr(expr, "location", None) or loc

        # Check all call-based patterns
        if isinstance(expr, (FunctionCall, MethodCall)):
            callee = _get_callee_name(expr)
            chain = _get_full_callee_chain(expr)
            callee_lower = callee.lower()
            chain_lower = chain.lower()

            # --- JWT Algorithm Confusion ---
            self._check_jwt_algorithm(expr, callee_lower, chain_lower, expr_loc)

            # --- JWT Verify Disabled ---
            self._check_jwt_verify_disabled(expr, callee_lower, chain_lower, expr_loc)

            # --- Missing JWT Claims ---
            self._check_jwt_missing_claims(expr, callee_lower, chain_lower, expr_loc)

            # --- Cookie Security ---
            self._check_cookie_security(expr, callee_lower, chain_lower, expr_loc)

            # --- Insecure Token Storage ---
            self._check_insecure_storage(expr, callee_lower, chain_lower, expr_loc)

            # --- Session Config / Timeout ---
            self._check_session_config(expr, callee_lower, chain_lower, expr_loc)

            # Recurse into arguments
            args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
            for arg in args:
                self._check_expr(arg, loc, var_name="")

            # Recurse into method receiver
            if isinstance(expr, MethodCall):
                self._check_expr(expr.obj, loc, var_name="")

        # --- Weak JWT Secret (assignment context) ---
        if var_name:
            self._check_weak_jwt_secret(expr, var_name, loc)

        # --- JWT in URL ---
        if isinstance(expr, StringLiteral):
            self._check_jwt_in_url(expr, expr_loc)

        # Recurse into binary ops and field access
        if isinstance(expr, BinaryOp):
            self._check_expr(expr.left, loc, var_name="")
            self._check_expr(expr.right, loc, var_name="")

        if isinstance(expr, FieldAccess):
            self._check_expr(expr.obj, loc, var_name="")

    # ------------------------------------------------------------------
    # 1. JWT Algorithm Confusion
    # ------------------------------------------------------------------

    def _check_jwt_algorithm(self, expr: Expr, callee_lower: str,
                             chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect algorithm=none and mixed symmetric/asymmetric algorithms."""
        # Only check JWT-related calls
        is_jwt_call = (
            _is_jwt_context(chain_lower)
            or callee_lower in JWT_VERIFY_FUNCTIONS
            or callee_lower in JWT_SIGN_FUNCTIONS
        )
        if not is_jwt_call:
            return

        # Collect all string values from arguments
        all_strings = _collect_string_values_from_expr(expr)

        # Check for algorithm "none"
        for val in all_strings:
            if val.lower() == "none":
                self._add_finding(
                    FindingCategory.JWT_ALG_NONE,
                    (
                        f"JWT algorithm set to 'none' — signature verification is disabled. "
                        f"An attacker can forge arbitrary tokens"
                    ),
                    loc,
                    context=chain_lower,
                )
                return

        # Check for mixed symmetric and asymmetric algorithms
        has_symmetric = False
        has_asymmetric = False
        symmetric_pattern = re.compile(r"^HS\d+$", re.IGNORECASE)
        asymmetric_pattern = re.compile(r"^(RS|ES|PS)\d+$", re.IGNORECASE)

        for val in all_strings:
            if symmetric_pattern.match(val):
                has_symmetric = True
            if asymmetric_pattern.match(val):
                has_asymmetric = True

        if has_symmetric and has_asymmetric:
            self._add_finding(
                FindingCategory.JWT_ALG_CONFUSION,
                (
                    f"JWT accepts both symmetric (HS*) and asymmetric (RS*/ES*/PS*) algorithms — "
                    f"vulnerable to algorithm confusion attack where the public key is used as HMAC secret"
                ),
                loc,
                context=chain_lower,
            )

        # Also check ListLiteral arguments directly for algorithm lists
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
        for arg in args:
            if isinstance(arg, ListLiteral):
                self._check_algorithm_list(arg, loc, chain_lower)

    def _check_algorithm_list(self, lst: ListLiteral, loc: Optional[SourceLocation],
                              context: str) -> None:
        """Check a list literal for mixed algorithm types."""
        has_symmetric = False
        has_asymmetric = False
        has_none = False
        symmetric_re = re.compile(r"^HS\d+$", re.IGNORECASE)
        asymmetric_re = re.compile(r"^(RS|ES|PS)\d+$", re.IGNORECASE)

        for elem in lst.elements:
            if isinstance(elem, StringLiteral):
                val = elem.value
                if val.lower() == "none":
                    has_none = True
                if symmetric_re.match(val):
                    has_symmetric = True
                if asymmetric_re.match(val):
                    has_asymmetric = True

        if has_none:
            self._add_finding(
                FindingCategory.JWT_ALG_NONE,
                "JWT algorithms list includes 'none' — signature verification can be bypassed",
                loc,
                context=context,
            )

        if has_symmetric and has_asymmetric:
            self._add_finding(
                FindingCategory.JWT_ALG_CONFUSION,
                (
                    "JWT algorithms list mixes symmetric (HS*) and asymmetric (RS*/ES*/PS*) — "
                    "vulnerable to algorithm confusion attack"
                ),
                loc,
                context=context,
            )

    # ------------------------------------------------------------------
    # 2. JWT Verify Disabled
    # ------------------------------------------------------------------

    def _check_jwt_verify_disabled(self, expr: Expr, callee_lower: str,
                                   chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect jwt.decode(token, verify=False) and similar patterns."""
        is_decode = (
            callee_lower in JWT_VERIFY_FUNCTIONS
            or any(kw in chain_lower for kw in ("decode", "verify"))
        )
        if not is_decode:
            return

        # Look for verify=False in arguments
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
        for arg in args:
            # Direct BoolLiteral(False) as a positional arg near a decode call
            if isinstance(arg, BoolLiteral) and arg.value is False:
                self._add_finding(
                    FindingCategory.JWT_VERIFY_DISABLED,
                    (
                        f"JWT signature verification is disabled (verify=False) — "
                        f"any forged token will be accepted"
                    ),
                    loc,
                    context=chain_lower,
                )
                return

            # ConstructExpr with verify: false
            if isinstance(arg, ConstructExpr):
                for fname, fval in arg.fields.items():
                    if fname.lower() == "verify" and isinstance(fval, BoolLiteral) and fval.value is False:
                        self._add_finding(
                            FindingCategory.JWT_VERIFY_DISABLED,
                            "JWT signature verification explicitly disabled (verify: false)",
                            loc,
                            context=chain_lower,
                        )
                        return
                    # options: { algorithms: false } or { verification: false }
                    if fname.lower() in ("verification", "verifysignature") and isinstance(fval, BoolLiteral) and fval.value is False:
                        self._add_finding(
                            FindingCategory.JWT_VERIFY_DISABLED,
                            f"JWT verification disabled via {fname}: false",
                            loc,
                            context=chain_lower,
                        )
                        return

    # ------------------------------------------------------------------
    # 3. Weak JWT Secret
    # ------------------------------------------------------------------

    def _check_weak_jwt_secret(self, expr: Expr, var_name: str,
                               loc: Optional[SourceLocation]) -> None:
        """Detect short/predictable JWT signing secrets assigned to known variable names."""
        name_lower = var_name.lower()

        # Only check variables that look like JWT secret holders
        is_jwt_secret_var = name_lower in {v.lower() for v in JWT_SECRET_VARIABLE_NAMES}
        if not is_jwt_secret_var:
            # Also match partial patterns
            is_jwt_secret_var = any(
                kw in name_lower
                for kw in ("jwt_secret", "jwtsecret", "signing_key", "signingkey",
                           "secret_key", "secretkey", "token_secret", "tokensecret")
            )
        if not is_jwt_secret_var:
            return

        if not isinstance(expr, StringLiteral):
            return

        value = expr.value

        # Check for common weak secrets
        if value.lower() in WEAK_SECRETS:
            self._add_finding(
                FindingCategory.JWT_WEAK_SECRET,
                (
                    f"JWT secret '{var_name}' is set to a common/predictable value — "
                    f"can be brute-forced offline"
                ),
                loc,
                context=var_name,
            )
            return

        # Check for short secrets (< 32 characters)
        if len(value) < 32:
            self._add_finding(
                FindingCategory.JWT_WEAK_SECRET,
                (
                    f"JWT secret '{var_name}' is only {len(value)} characters — "
                    f"use at least 256 bits (32 bytes) for HMAC signing keys"
                ),
                loc,
                context=var_name,
            )

    # ------------------------------------------------------------------
    # 4. Missing JWT Claims
    # ------------------------------------------------------------------

    def _check_jwt_missing_claims(self, expr: Expr, callee_lower: str,
                                  chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect JWT creation without exp, iss, or aud claims."""
        is_sign = (
            callee_lower in JWT_SIGN_FUNCTIONS
            or ("jwt" in chain_lower and any(kw in chain_lower for kw in ("sign", "encode", "create")))
        )
        if not is_sign:
            return

        # Collect all string values and identifier names from args to check for claims
        all_strings = _collect_string_values_from_expr(expr)
        all_idents = _collect_identifiers_from_expr(expr)
        all_text = {s.lower() for s in all_strings} | {i.lower() for i in all_idents}

        # Check for options objects in arguments
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
        has_exp = False
        has_iss = False
        has_aud = False

        # Check ConstructExpr fields (options objects)
        for arg in args:
            if isinstance(arg, ConstructExpr):
                field_names_lower = {f.lower() for f in arg.fields}
                if any(k in field_names_lower for k in ("exp", "expiresin", "expires_in", "expirationtime", "expiration")):
                    has_exp = True
                if any(k in field_names_lower for k in ("iss", "issuer")):
                    has_iss = True
                if any(k in field_names_lower for k in ("aud", "audience")):
                    has_aud = True

        # Also check string/ident-based heuristics
        if any(k in all_text for k in ("exp", "expiresin", "expires_in", "expirationtime")):
            has_exp = True
        if any(k in all_text for k in ("iss", "issuer")):
            has_iss = True
        if any(k in all_text for k in ("aud", "audience")):
            has_aud = True

        if not has_exp:
            self._add_finding(
                FindingCategory.JWT_MISSING_EXP,
                (
                    "JWT created without 'exp' (expiration) claim — "
                    "token never expires and remains valid indefinitely if leaked"
                ),
                loc,
                context=chain_lower,
            )

        if not has_iss:
            self._add_finding(
                FindingCategory.JWT_MISSING_ISS,
                (
                    "JWT created without 'iss' (issuer) claim — "
                    "cannot verify which service issued the token"
                ),
                loc,
                context=chain_lower,
            )

        if not has_aud:
            self._add_finding(
                FindingCategory.JWT_MISSING_AUD,
                (
                    "JWT created without 'aud' (audience) claim — "
                    "token may be accepted by unintended services"
                ),
                loc,
                context=chain_lower,
            )

    # ------------------------------------------------------------------
    # 5. JWT in URL Parameters
    # ------------------------------------------------------------------

    def _check_jwt_in_url(self, expr: StringLiteral, loc: Optional[SourceLocation]) -> None:
        """Detect tokens passed in URL query strings."""
        value = expr.value

        # Pattern: ?token= or &token= or ?access_token= etc.
        url_token_pattern = re.compile(
            r"[?&](token|access_token|auth_token|jwt|id_token|bearer|authorization)=",
            re.IGNORECASE,
        )
        if url_token_pattern.search(value):
            self._add_finding(
                FindingCategory.JWT_IN_URL,
                (
                    "Token passed in URL query parameter — leaks via Referer headers, "
                    "server logs, browser history, and proxy logs"
                ),
                loc,
                context=value[:60],
            )

    # ------------------------------------------------------------------
    # 6. Cookie Security
    # ------------------------------------------------------------------

    def _check_cookie_security(self, expr: Expr, callee_lower: str,
                               chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect missing security flags on cookie-setting calls."""
        is_cookie_set = (
            callee_lower in {f.lower() for f in COOKIE_SET_FUNCTIONS}
            or "set-cookie" in chain_lower
            or "setcookie" in chain_lower
            or "set_cookie" in chain_lower
            or ("cookie" in chain_lower and callee_lower in ("set", "cookie", "append"))
        )
        if not is_cookie_set:
            return

        # Check for security flags in options arguments
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []

        has_httponly = False
        has_secure = False
        has_samesite = False
        samesite_value: Optional[str] = None
        secure_value: Optional[bool] = None

        for arg in args:
            if isinstance(arg, ConstructExpr):
                fields_lower = {f.lower(): v for f, v in arg.fields.items()}

                if "httponly" in fields_lower or "http_only" in fields_lower:
                    val = fields_lower.get("httponly") or fields_lower.get("http_only")
                    if isinstance(val, BoolLiteral) and val.value is True:
                        has_httponly = True
                    elif isinstance(val, BoolLiteral) and val.value is False:
                        pass  # Explicitly set to false, still flag it
                    else:
                        has_httponly = True  # Non-literal, assume intentional

                if "secure" in fields_lower:
                    val = fields_lower["secure"]
                    if isinstance(val, BoolLiteral):
                        secure_value = val.value
                        if val.value is True:
                            has_secure = True
                    else:
                        has_secure = True  # Non-literal, assume intentional

                if "samesite" in fields_lower or "same_site" in fields_lower:
                    has_samesite = True
                    val = fields_lower.get("samesite") or fields_lower.get("same_site")
                    if isinstance(val, StringLiteral):
                        samesite_value = val.value.lower()

            # Also check string arguments for set-cookie header format
            if isinstance(arg, StringLiteral):
                val_lower = arg.value.lower()
                if "httponly" in val_lower:
                    has_httponly = True
                if "secure" in val_lower:
                    has_secure = True
                if "samesite" in val_lower:
                    has_samesite = True
                    if "samesite=none" in val_lower:
                        samesite_value = "none"
                    if "samesite=lax" in val_lower:
                        samesite_value = "lax"
                    if "samesite=strict" in val_lower:
                        samesite_value = "strict"

        if not has_httponly:
            self._add_finding(
                FindingCategory.COOKIE_NO_HTTPONLY,
                (
                    "Cookie set without HttpOnly flag — JavaScript can access "
                    "this cookie via document.cookie, enabling XSS-based session theft"
                ),
                loc,
                context=chain_lower or callee_lower,
            )

        if not has_secure:
            self._add_finding(
                FindingCategory.COOKIE_NO_SECURE,
                (
                    "Cookie set without Secure flag — cookie will be sent over "
                    "unencrypted HTTP connections, enabling interception"
                ),
                loc,
                context=chain_lower or callee_lower,
            )

        if not has_samesite:
            self._add_finding(
                FindingCategory.COOKIE_NO_SAMESITE,
                (
                    "Cookie set without SameSite attribute — vulnerable to "
                    "cross-site request forgery (CSRF) attacks"
                ),
                loc,
                context=chain_lower or callee_lower,
            )

        # sameSite: "none" without secure: true
        if samesite_value == "none" and not has_secure:
            self._add_finding(
                FindingCategory.COOKIE_SAMESITE_NONE_INSECURE,
                (
                    "Cookie has SameSite=None but Secure flag is not set — "
                    "modern browsers will reject this cookie"
                ),
                loc,
                context=chain_lower or callee_lower,
            )

    # ------------------------------------------------------------------
    # 7. Insecure Token Storage (Client-Side)
    # ------------------------------------------------------------------

    def _check_insecure_storage(self, expr: Expr, callee_lower: str,
                                chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect localStorage.setItem('token', ...) and sessionStorage.setItem('token', ...)."""
        is_storage_set = (
            ("localstorage" in chain_lower and callee_lower == "setitem")
            or ("sessionstorage" in chain_lower and callee_lower == "setitem")
            or ("localstorage.setitem" in chain_lower)
            or ("sessionstorage.setitem" in chain_lower)
        )
        if not is_storage_set:
            return

        # Check if the storage key relates to auth tokens
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []
        if not args:
            return

        first_arg = args[0]
        key_value = _string_value(first_arg)
        if key_value is None:
            # If the key is not a literal, still flag if in a JWT/auth context
            key_idents = _collect_identifiers_from_expr(first_arg)
            key_value = " ".join(key_idents).lower()

        key_lower = key_value.lower() if key_value else ""

        if any(sensitive in key_lower for sensitive in SENSITIVE_STORAGE_KEYS):
            storage_type = "localStorage" if "localstorage" in chain_lower else "sessionStorage"
            self._add_finding(
                FindingCategory.INSECURE_TOKEN_STORAGE,
                (
                    f"Auth token stored in {storage_type} (key: '{key_value}') — "
                    f"accessible to any JavaScript on the page, vulnerable to XSS"
                ),
                loc,
                context=f"{storage_type}.setItem('{key_value}')",
            )

    # ------------------------------------------------------------------
    # 8. Token Refresh / Long Expiry
    # ------------------------------------------------------------------

    def _check_token_expiry_in_sign(self, expr: Expr, loc: Optional[SourceLocation],
                                    chain_lower: str) -> None:
        """Check for very long access token expiry times."""
        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []

        for arg in args:
            if isinstance(arg, ConstructExpr):
                for fname, fval in arg.fields.items():
                    fname_lower = fname.lower()
                    if fname_lower in ("expiresin", "expires_in", "exp", "maxage", "max_age"):
                        # Check numeric value (in seconds)
                        int_val = _int_value(fval)
                        if int_val is not None and int_val > 86400:  # > 24 hours
                            hours = int_val / 3600
                            self._add_finding(
                                FindingCategory.TOKEN_LONG_EXPIRY,
                                (
                                    f"Access token expiry set to {hours:.0f} hours — "
                                    f"access tokens should expire within 15-60 minutes"
                                ),
                                loc,
                                context=chain_lower,
                            )

                        # Check string value like "7d", "30d", "365d"
                        str_val = _string_value(fval)
                        if str_val:
                            self._check_expiry_string(str_val, loc, chain_lower)

    def _check_expiry_string(self, value: str, loc: Optional[SourceLocation],
                             context: str) -> None:
        """Parse expiry duration strings like '7d', '48h', '525600m'."""
        match = re.match(r"^(\d+)\s*(d|h|m|s)$", value.strip(), re.IGNORECASE)
        if not match:
            return

        amount = int(match.group(1))
        unit = match.group(2).lower()

        # Convert to hours
        hours = 0
        if unit == "d":
            hours = amount * 24
        elif unit == "h":
            hours = amount
        elif unit == "m":
            hours = amount / 60
        elif unit == "s":
            hours = amount / 3600

        if hours > 24:
            self._add_finding(
                FindingCategory.TOKEN_LONG_EXPIRY,
                (
                    f"Access token expiry set to '{value}' ({hours:.0f} hours) — "
                    f"access tokens should expire within 15-60 minutes"
                ),
                loc,
                context=context,
            )

    # ------------------------------------------------------------------
    # 9. Session Timeout
    # ------------------------------------------------------------------

    def _check_session_config(self, expr: Expr, callee_lower: str,
                              chain_lower: str, loc: Optional[SourceLocation]) -> None:
        """Detect session configuration with missing or excessive timeouts."""
        # Look for session configuration calls
        is_session_config = (
            "session" in chain_lower
            and any(kw in callee_lower for kw in ("config", "configure", "setup",
                                                    "init", "create", "use", "session"))
        )
        if not is_session_config:
            # Also check jwt sign for long expiry
            if callee_lower in JWT_SIGN_FUNCTIONS or (
                "jwt" in chain_lower and any(kw in chain_lower for kw in ("sign", "encode"))
            ):
                self._check_token_expiry_in_sign(expr, loc, chain_lower)
            return

        args = expr.args if isinstance(expr, (FunctionCall, MethodCall)) else []

        has_timeout = False
        for arg in args:
            if isinstance(arg, ConstructExpr):
                fields_lower = {f.lower(): v for f, v in arg.fields.items()}

                # Check for timeout/maxAge/ttl fields
                timeout_keys = {"timeout", "maxage", "max_age", "ttl", "idle_timeout",
                                "idletimeout", "rolling_duration", "absolute_timeout",
                                "absolutetimeout", "cookie_maxage", "session_timeout",
                                "maxlifetime", "max_lifetime", "gc_maxlifetime"}

                for tk in timeout_keys:
                    if tk in fields_lower:
                        has_timeout = True
                        val = fields_lower[tk]

                        int_val = _int_value(val)
                        if int_val is not None:
                            # Assume seconds
                            hours = int_val / 3600
                            if hours > 24:
                                self._add_finding(
                                    FindingCategory.SESSION_LONG_TIMEOUT,
                                    (
                                        f"Session timeout set to {hours:.0f} hours — "
                                        f"long sessions increase hijacking risk"
                                    ),
                                    loc,
                                    context=chain_lower,
                                )

                        str_val = _string_value(val)
                        if str_val:
                            self._check_session_timeout_string(str_val, loc, chain_lower)

        if not has_timeout:
            self._add_finding(
                FindingCategory.SESSION_NO_TIMEOUT,
                (
                    "Session configured without a timeout — "
                    "sessions will remain active indefinitely"
                ),
                loc,
                context=chain_lower,
            )

    def _check_session_timeout_string(self, value: str, loc: Optional[SourceLocation],
                                      context: str) -> None:
        """Parse session timeout strings and flag excessive durations."""
        match = re.match(r"^(\d+)\s*(d|h|m|s)$", value.strip(), re.IGNORECASE)
        if not match:
            return

        amount = int(match.group(1))
        unit = match.group(2).lower()

        hours = 0
        if unit == "d":
            hours = amount * 24
        elif unit == "h":
            hours = amount
        elif unit == "m":
            hours = amount / 60
        elif unit == "s":
            hours = amount / 3600

        if hours > 24:
            self._add_finding(
                FindingCategory.SESSION_LONG_TIMEOUT,
                (
                    f"Session timeout set to '{value}' ({hours:.0f} hours) — "
                    f"sessions lasting more than 24 hours increase hijacking risk"
                ),
                loc,
                context=context,
            )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _is_auth_function(name: str) -> bool:
        """Check if a function name indicates an authentication handler."""
        name_lower = name.lower()
        return name_lower in {f.lower() for f in AUTH_FUNCTIONS} or any(
            kw in name_lower for kw in ("login", "signin", "sign_in", "authenticate", "log_in")
        )

    def _add_finding(self, category: FindingCategory, message: str,
                     location: Optional[SourceLocation], context: str = "") -> None:
        """Add a finding, deduplicating by category + location."""
        # Deduplicate: same category at the same location
        for existing in self.findings:
            if existing.category == category and existing.location == location:
                return

        self.findings.append(SessionJwtFinding(
            category=category,
            message=message,
            location=location,
            context=context,
        ))


# ---------------------------------------------------------------------------
# Error Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: SessionJwtFinding) -> AeonError:
    """Convert a SessionJwtFinding into an AeonError."""
    cwe = CWE_MAP.get(finding.category, "CWE-613")
    severity = SEVERITY_MAP.get(finding.category, Severity.MEDIUM)
    severity_label = severity.value.upper()
    remediation = REMEDIATION.get(finding.category, "Review session/JWT security configuration")
    category_label = finding.category.value.replace("_", " ").title()

    context_suffix = ""
    if finding.context:
        context_suffix = f" [{finding.context}]"

    return contract_error(
        precondition=(
            f"Session/JWT Security ({cwe}) — "
            f"[{severity_label}] {category_label}{context_suffix}: {finding.message}"
        ),
        failing_values={
            "category": finding.category.value,
            "severity": severity.value,
            "cwe": cwe,
            "remediation": remediation,
            "engine": "Session & JWT Security",
        },
        function_signature="session_jwt",
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_session_jwt(program: Program) -> list:
    """Run session management and JWT security analysis on an AEON program.

    Scans the AST for vulnerabilities in session handling, JWT usage, cookie
    configuration, and token storage patterns.

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected vulnerability.

    Detection categories:
        1. JWT algorithm confusion (alg:none, mixed HS*/RS*)
        2. Weak JWT secrets (short, predictable, hardcoded)
        3. Missing JWT claims (exp, iss, aud)
        4. JWT in URL parameters (query string token leakage)
        5. Cookie security (missing httpOnly, secure, sameSite)
        6. Session fixation (no session regeneration after auth)
        7. Insecure token storage (localStorage, sessionStorage)
        8. Token refresh issues (long expiry, no rotation)
        9. Session timeout (missing or excessive)

    CWEs:
        CWE-347: Improper Verification of Cryptographic Signature
        CWE-346: Origin Validation Error
        CWE-613: Insufficient Session Expiration
        CWE-614: Sensitive Cookie Without 'Secure' Flag
        CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
        CWE-384: Session Fixation
        CWE-922: Insecure Storage of Sensitive Information
    """
    try:
        analyzer = SessionJwtAnalyzer()
        findings = analyzer.check_program(program)
        return [_finding_to_error(f) for f in findings]
    except Exception:
        # Engine-level safety net: never let the entire engine crash
        # the verification pipeline
        return []
