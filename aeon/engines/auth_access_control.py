"""AEON Auth & Access Control Engine — Broken Authentication and Authorization Detection.

Implements detection for OWASP Top 10 categories:
  A01:2021 Broken Access Control
  A07:2021 Identification and Authentication Failures

Based on:
  OWASP Foundation (2021) "OWASP Top 10:2021"
  https://owasp.org/Top10/

  CWE/SANS Top 25 Most Dangerous Software Weaknesses
  https://cwe.mitre.org/top25/

  Li & Xue (2014) "Access Control Policy Verification and Troubleshooting"
  IEEE TDSC, https://doi.org/10.1109/TDSC.2013.23

  De Capitani di Vimercati et al. (2003) "Access Control: Policies,
  Models, and Mechanisms" FOSAD '00, https://doi.org/10.1007/3-540-45608-2_3

Key Theory:

1. AUTHENTICATION vs AUTHORIZATION:
   Authentication (authn) verifies identity: "Who are you?"
   Authorization (authz) verifies permission: "What can you do?"
   A common vulnerability is performing authn without authz, or skipping both.
   Every route handler / API endpoint that accesses protected resources
   MUST perform both checks.

2. BROKEN ACCESS CONTROL (CWE-862, CWE-863):
   When access control checks are missing or incorrectly implemented:
   - Route handlers without auth middleware
   - Functions accessing user data without identity verification
   - Admin operations without role guards
   - Horizontal privilege escalation (user A accesses user B's data)

3. INSECURE DIRECT OBJECT REFERENCES — IDOR (CWE-639):
   When user-controlled identifiers are used directly to access resources
   without verifying the requesting user owns or has access to that resource:
     id = request.params.id
     record = db.find(id)        // Missing: WHERE owner = current_user
   The fix is always to scope data access by the authenticated user's identity.

4. PRIVILEGE ESCALATION (CWE-863):
   When role checks use weak patterns:
   - String comparison: if role == "admin" (bypassable, no framework guard)
   - Client-derived roles: isAdmin from request body or JWT claim without
     server-side validation against an authoritative source
   - Missing re-authentication for privilege changes

5. BROKEN AUTHENTICATION (CWE-307):
   - Password comparison with == instead of constant-time compare
     (timing side-channel leaks password length/content)
   - No rate limiting on login endpoints (brute force)
   - No account lockout after failed attempts
   - Passwords stored or logged in plaintext
   - Auth tokens without expiry (stolen tokens valid forever)

6. SESSION MANAGEMENT (CWE-613):
   - Session ID in URL parameters (leaked via Referer header, logs)
   - Missing session invalidation on logout (session remains valid)
   - Session fixation (accepting pre-auth session IDs post-auth)

7. CSRF PROTECTION (CWE-352):
   State-changing operations (POST, PUT, DELETE) must validate a CSRF
   token to prevent cross-site request forgery. Forms without CSRF tokens
   and handlers without CSRF validation are vulnerable.

Detects:
  - Missing authentication on route handlers / API endpoints
  - Insecure direct object references (IDOR)
  - Privilege escalation via string-based role comparison
  - Password comparison with == instead of constant-time compare
  - Missing rate limiting on login endpoints
  - Session management weaknesses
  - Missing CSRF protection on state-changing endpoints
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral,
    BinaryOp, FunctionCall, FieldAccess, MethodCall,
    LetStmt, AssignStmt, IfStmt, ReturnStmt, ExprStmt,
    WhileStmt, ForStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Severity Classification
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# ---------------------------------------------------------------------------
# Pattern Specifications
# ---------------------------------------------------------------------------

# Function name patterns that indicate a route handler / API endpoint.
# These are the functions we expect to contain authentication checks.
ROUTE_HANDLER_PREFIXES: Tuple[str, ...] = (
    "api_", "route_", "endpoint_",
    "post_", "put_", "patch_", "delete_",
    "serve_",
    "view_", "action_", "controller_",
)

ROUTE_HANDLER_SUFFIXES: Tuple[str, ...] = (
    "_handler", "_endpoint", "_route", "_view",
    "_action", "_controller", "_api",
    "Handler", "Endpoint", "Route", "View",
    "Action", "Controller",
)

# Exact function names for Next.js/Remix-style API route exports.
EXACT_ROUTE_HANDLER_NAMES: Set[str] = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
}

# Parameter names that indicate a server-side HTTP handler.
HTTP_HANDLER_PARAMS: Set[str] = {
    "req", "request", "res", "response", "conn", "ctx", "context",
    "next", "reply",
}

# Function body patterns that indicate server-side HTTP handling.
HTTP_RESPONSE_PATTERNS: Set[str] = {
    "NextResponse", "res.json", "res.status", "res.send", "res.end",
    "res.redirect", "response.json", "response.status", "send_resp",
    "json(", "jsonify", "HttpResponse", "JsonResponse",
    "render_template", "send_file",
}

# React / client-side UI patterns — presence in a function body means
# the function is almost certainly a UI event handler, not a server endpoint.
REACT_UI_PATTERNS: Set[str] = {
    # React hooks
    "useState", "useEffect", "useCallback", "useMemo", "useRef",
    "useContext", "useReducer", "useNavigate", "useRouter", "useParams",
    "useSearchParams", "useForm", "useQuery", "useMutation",
    # State setters (set + capital letter is the convention)
    "setState", "dispatch",
    # Navigation
    "navigate", "router.push", "router.replace", "router.back",
    # UI feedback
    "toast", "toast.success", "toast.error", "alert",
    "setOpen", "setLoading", "setError", "setVisible", "setShow",
    "setSelected", "setActive", "setDisabled", "setEditing",
    # JSX / DOM
    "onClick", "onChange", "onSubmit", "onBlur", "onFocus",
    "onKeyDown", "onKeyUp", "onMouseEnter", "onMouseLeave",
    "className", "preventDefault", "stopPropagation",
    "e.target", "event.target", "ref.current",
    # Common React patterns
    "console.log", "console.error",
}

# Function/method names that indicate an authentication or authorization check.
AUTH_CHECK_FUNCTIONS: Set[str] = {
    # Authentication
    "authenticate", "verify_token", "check_token", "validate_token",
    "get_session", "getUser", "get_user", "getCurrentUser",
    "get_current_user", "requireAuth", "require_auth",
    "requireLogin", "require_login", "ensureAuthenticated",
    "ensure_authenticated", "isAuthenticated", "is_authenticated",
    "verifySession", "verify_session", "checkSession", "check_session",
    "verifyAuth", "verify_auth", "checkAuth", "check_auth",
    "jwt_required", "login_required", "auth_required",
    "token_required", "session_required",
    "passport_authenticate", "validateJWT", "validate_jwt",
    "decode_token", "decodeToken", "verify_credentials",
    "check_credentials", "getAuthUser", "get_auth_user",
    # Authorization
    "check_permission", "checkPermission", "has_permission",
    "hasPermission", "authorize", "require_role", "requireRole",
    "check_role", "checkRole", "has_role", "hasRole",
    "can_access", "canAccess", "is_allowed", "isAllowed",
    "verify_access", "verifyAccess", "require_permission",
    "requirePermission", "enforce_policy", "enforcePolicy",
    "check_access", "checkAccess", "guard", "protect",
    "require_admin", "requireAdmin", "is_admin", "isAdmin",
    "check_ownership", "checkOwnership", "verify_ownership",
    "verifyOwnership", "belongs_to", "belongsTo",
}

# Subset: functions that specifically check authorization (not just authn).
AUTHZ_CHECK_FUNCTIONS: Set[str] = {
    "check_permission", "checkPermission", "has_permission",
    "hasPermission", "authorize", "require_role", "requireRole",
    "check_role", "checkRole", "has_role", "hasRole",
    "can_access", "canAccess", "is_allowed", "isAllowed",
    "verify_access", "verifyAccess", "require_permission",
    "requirePermission", "enforce_policy", "enforcePolicy",
    "check_access", "checkAccess", "require_admin", "requireAdmin",
    "check_ownership", "checkOwnership", "verify_ownership",
    "verifyOwnership", "belongs_to", "belongsTo",
}

# Database access methods that should be scoped by authenticated user.
DATA_ACCESS_METHODS: Set[str] = {
    "find", "findOne", "find_one", "findById", "find_by_id",
    "get", "getOne", "get_one", "getById", "get_by_id",
    "query", "select", "fetch", "fetchOne", "fetch_one",
    "load", "lookup", "retrieve", "read",
    "findAll", "find_all", "getAll", "get_all",
    "where", "filter", "search",
    "delete", "remove", "destroy", "update", "save", "insert",
    "create", "put", "patch", "upsert",
}

# Parameters that indicate user-controlled IDs (IDOR risk).
ID_PARAM_PATTERNS: Set[str] = {
    "id", "user_id", "userId", "account_id", "accountId",
    "profile_id", "profileId", "record_id", "recordId",
    "document_id", "documentId", "resource_id", "resourceId",
    "order_id", "orderId", "item_id", "itemId",
    "project_id", "projectId", "org_id", "orgId",
    "file_id", "fileId", "message_id", "messageId",
    "comment_id", "commentId", "post_id", "postId",
    "invoice_id", "invoiceId", "payment_id", "paymentId",
}

# Ownership verification patterns — presence of these in data access
# indicates the developer IS checking ownership (good).
OWNERSHIP_CHECK_PATTERNS: Set[str] = {
    "current_user", "currentUser", "auth_user", "authUser",
    "session_user", "sessionUser", "logged_in_user", "loggedInUser",
    "req_user", "reqUser", "request_user", "requestUser",
    "owner", "owner_id", "ownerId", "created_by", "createdBy",
    "user_id", "userId",  # when used as a WHERE clause, not as input
    "belongs_to", "belongsTo",
}

# Password and credential variable name patterns.
PASSWORD_VAR_PATTERNS: Set[str] = {
    "password", "passwd", "pass", "pwd", "secret",
    "credential", "credentials", "auth_token", "authToken",
    "access_token", "accessToken", "api_key", "apiKey",
    "private_key", "privateKey", "secret_key", "secretKey",
}

# Constant-time comparison functions (safe password comparison).
CONSTANT_TIME_COMPARE: Set[str] = {
    "hmac_compare", "constant_time_compare", "constantTimeCompare",
    "secure_compare", "secureCompare", "timingSafeEqual",
    "timing_safe_equal", "crypto_compare", "cryptoCompare",
    "bcrypt_compare", "bcryptCompare", "bcrypt_verify",
    "verify_password", "verifyPassword", "check_password",
    "checkPassword", "password_verify", "passwordVerify",
    "argon2_verify", "scrypt_verify", "pbkdf2_verify",
    "compare_digest", "compareDigest",
    "hmac_equal", "hmacEqual",
}

# Rate limiting functions/decorators.
RATE_LIMIT_PATTERNS: Set[str] = {
    "rate_limit", "rateLimit", "throttle", "limit",
    "rate_limiter", "rateLimiter", "throttler",
    "check_rate_limit", "checkRateLimit",
    "apply_rate_limit", "applyRateLimit",
    "limiter", "slowDown", "slow_down",
    "brute_force_check", "bruteForceCheck",
    "login_attempt_check", "loginAttemptCheck",
    "account_lockout", "accountLockout",
    "max_attempts", "maxAttempts",
}

# CSRF protection patterns.
CSRF_CHECK_PATTERNS: Set[str] = {
    "csrf_token", "csrfToken", "csrf_verify", "csrfVerify",
    "verify_csrf", "verifyCsrf", "check_csrf", "checkCsrf",
    "csrf_protect", "csrfProtect", "csrf_middleware",
    "csrfMiddleware", "validate_csrf", "validateCsrf",
    "anti_forgery", "antiForgery", "xsrf_token", "xsrfToken",
    "csurf", "csrf_exempt",  # presence of exempt is also notable
}

# Session invalidation patterns.
SESSION_INVALIDATION_PATTERNS: Set[str] = {
    "destroy_session", "destroySession", "invalidate_session",
    "invalidateSession", "session_destroy", "sessionDestroy",
    "logout", "logOut", "log_out", "signOut", "sign_out",
    "clear_session", "clearSession", "end_session", "endSession",
    "remove_session", "removeSession", "expire_session", "expireSession",
    "revoke_token", "revokeToken", "revoke_session", "revokeSession",
    "delete_session", "deleteSession",
}

# State-changing HTTP methods that require CSRF protection.
STATE_CHANGING_PREFIXES: Tuple[str, ...] = (
    "post_", "put_", "patch_", "delete_",
    "create_", "update_", "remove_", "destroy_",
    "submit_", "save_", "modify_", "edit_",
)

# Role string literals that suggest string-based RBAC (weak pattern).
ROLE_STRING_LITERALS: Set[str] = {
    "admin", "administrator", "superadmin", "super_admin",
    "root", "moderator", "mod", "editor", "manager",
    "owner", "staff", "operator", "superuser", "super_user",
    "user", "guest", "viewer", "readonly", "read_only",
}

# Variable names that hold role information.
ROLE_VAR_PATTERNS: Set[str] = {
    "role", "roles", "user_role", "userRole",
    "is_admin", "isAdmin", "is_moderator", "isModerator",
    "permission", "permissions", "access_level", "accessLevel",
    "privilege", "privileges", "auth_level", "authLevel",
}


# ---------------------------------------------------------------------------
# Auth Access Control Analyzer
# ---------------------------------------------------------------------------

class AuthAccessControlAnalyzer:
    """Detects broken authentication and access control vulnerabilities.

    Covers OWASP A01:2021 (Broken Access Control) and A07:2021
    (Identification and Authentication Failures).

    Walks the AEON AST looking for:
    1. Route handlers without authentication checks
    2. Insecure direct object references (IDOR)
    3. Privilege escalation via weak role comparison
    4. Broken authentication patterns (timing attacks, missing rate limits)
    5. Session management issues
    6. Missing CSRF protection on state-changing endpoints
    """

    def __init__(self):
        self.errors: List[AeonError] = []
        # Track which variables hold user-supplied IDs
        self._id_vars: Set[str] = set()
        # Track which variables hold passwords/secrets
        self._secret_vars: Set[str] = set()
        # Track auth calls found in current function
        self._auth_calls_found: Set[str] = set()
        # Track authz calls found in current function
        self._authz_calls_found: Set[str] = set()
        # Track ownership checks found in current function
        self._ownership_checks_found: bool = False
        # Track data access calls with user-supplied IDs
        self._unscoped_data_access: List[Tuple[str, SourceLocation]] = []

    def check_program(self, program: Program) -> List[AeonError]:
        """Run authentication and access control analysis on the entire program."""
        self.errors = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.errors

    # ------------------------------------------------------------------
    # Function-level analysis
    # ------------------------------------------------------------------

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for auth/access control vulnerabilities."""
        # Reset per-function tracking state
        self._id_vars = set()
        self._secret_vars = set()
        self._auth_calls_found = set()
        self._authz_calls_found = set()
        self._ownership_checks_found = False
        self._unscoped_data_access = []

        func_name = func.name
        loc = func.location or SourceLocation(line=0, column=0)

        # Identify ID parameters and secret parameters
        for param in func.params:
            pname = param.name
            pname_lower = pname.lower()
            if pname_lower in ID_PARAM_PATTERNS or pname_lower.endswith("_id"):
                self._id_vars.add(pname)
            if any(pat in pname_lower for pat in PASSWORD_VAR_PATTERNS):
                self._secret_vars.add(pname)

        # Walk the body to collect auth calls, data access, and patterns
        for stmt in func.body:
            self._analyze_statement(stmt, func)

        # Post-analysis checks
        is_handler = self._is_route_handler(func_name, func)

        # 1. Missing authentication on route handlers
        if is_handler and not self._auth_calls_found:
            self._report(
                severity=Severity.CRITICAL,
                cwe="CWE-862",
                message=(
                    f"Missing authentication: route handler '{func_name}' "
                    f"has no authentication check. All API endpoints must verify "
                    f"the caller's identity before processing requests."
                ),
                details={
                    "vulnerability": "missing_authentication",
                    "function": func_name,
                    "owasp": "A01:2021 Broken Access Control",
                    "cwe": "CWE-862: Missing Authorization",
                    "engine": "Auth & Access Control",
                },
                suggestion=(
                    f"Add an authentication guard at the start of '{func_name}', "
                    f"e.g., call authenticate(), verify_token(), or requireAuth() "
                    f"before accessing any resources."
                ),
                location=loc,
            )

        # 2. Authentication without authorization (authn != authz)
        if is_handler and self._auth_calls_found and not self._authz_calls_found:
            # Only flag if the handler accesses data or modifies state
            if self._unscoped_data_access:
                self._report(
                    severity=Severity.MEDIUM,
                    cwe="CWE-863",
                    message=(
                        f"Missing authorization: '{func_name}' authenticates "
                        f"the user but never checks permissions or roles. "
                        f"Authentication alone does not verify what a user "
                        f"is allowed to do."
                    ),
                    details={
                        "vulnerability": "authentication_without_authorization",
                        "function": func_name,
                        "owasp": "A01:2021 Broken Access Control",
                        "cwe": "CWE-863: Incorrect Authorization",
                        "engine": "Auth & Access Control",
                    },
                    suggestion=(
                        f"Add an authorization check (e.g., check_permission(), "
                        f"require_role(), or has_role()) after authentication "
                        f"in '{func_name}'."
                    ),
                    location=loc,
                )

        # 3. IDOR — user-supplied IDs used in data access without ownership check
        if self._id_vars and self._unscoped_data_access and not self._ownership_checks_found:
            for access_name, access_loc in self._unscoped_data_access:
                self._report(
                    severity=Severity.CRITICAL,
                    cwe="CWE-639",
                    message=(
                        f"Insecure Direct Object Reference (IDOR): "
                        f"'{func_name}' passes user-controlled ID parameter(s) "
                        f"{sorted(self._id_vars)} directly to data access "
                        f"method '{access_name}' without verifying ownership. "
                        f"An attacker can manipulate the ID to access other "
                        f"users' data."
                    ),
                    details={
                        "vulnerability": "idor",
                        "function": func_name,
                        "id_params": sorted(self._id_vars),
                        "data_access": access_name,
                        "owasp": "A01:2021 Broken Access Control",
                        "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key",
                        "engine": "Auth & Access Control",
                    },
                    suggestion=(
                        f"Scope the data access by the authenticated user's identity. "
                        f"For example, add a WHERE clause: "
                        f"'db.find(id, where: owner_id == current_user.id)' "
                        f"or call check_ownership() before returning the resource."
                    ),
                    location=access_loc,
                )

        # 4. Missing CSRF on state-changing handlers
        is_state_changing = self._is_state_changing_handler(func_name)
        has_csrf = any(
            self._matches_pattern_set(call, CSRF_CHECK_PATTERNS)
            for call in self._auth_calls_found | self._authz_calls_found
        )
        if is_handler and is_state_changing and not has_csrf:
            self._report(
                severity=Severity.HIGH,
                cwe="CWE-352",
                message=(
                    f"Missing CSRF protection: state-changing handler "
                    f"'{func_name}' does not validate a CSRF token. "
                    f"An attacker can forge cross-site requests to perform "
                    f"actions on behalf of authenticated users."
                ),
                details={
                    "vulnerability": "missing_csrf",
                    "function": func_name,
                    "owasp": "A01:2021 Broken Access Control",
                    "cwe": "CWE-352: Cross-Site Request Forgery",
                    "engine": "Auth & Access Control",
                },
                suggestion=(
                    f"Add CSRF token validation to '{func_name}'. "
                    f"Verify the token with csrf_verify() or equivalent "
                    f"middleware before processing the request."
                ),
                location=loc,
            )

        # 5. Login handler without rate limiting
        if self._is_login_handler(func_name) and not self._has_rate_limiting(func):
            self._report(
                severity=Severity.MEDIUM,
                cwe="CWE-307",
                message=(
                    f"Missing rate limiting: login handler '{func_name}' "
                    f"has no rate limiting or account lockout mechanism. "
                    f"An attacker can perform brute-force attacks to guess "
                    f"user credentials."
                ),
                details={
                    "vulnerability": "missing_rate_limiting",
                    "function": func_name,
                    "owasp": "A07:2021 Identification and Authentication Failures",
                    "cwe": "CWE-307: Improper Restriction of Excessive Authentication Attempts",
                    "engine": "Auth & Access Control",
                },
                suggestion=(
                    f"Add rate limiting to '{func_name}' using rate_limit(), "
                    f"throttle(), or an account lockout check after N failed attempts."
                ),
                location=loc,
            )

        # 6. Logout handler without session invalidation
        if self._is_logout_handler(func_name):
            has_invalidation = any(
                self._matches_pattern_set(call, SESSION_INVALIDATION_PATTERNS)
                for call in self._auth_calls_found | self._authz_calls_found
            )
            if not has_invalidation:
                self._report(
                    severity=Severity.HIGH,
                    cwe="CWE-613",
                    message=(
                        f"Missing session invalidation: logout handler "
                        f"'{func_name}' does not destroy or invalidate the "
                        f"session. The session token remains valid after logout, "
                        f"allowing session hijacking."
                    ),
                    details={
                        "vulnerability": "missing_session_invalidation",
                        "function": func_name,
                        "owasp": "A07:2021 Identification and Authentication Failures",
                        "cwe": "CWE-613: Insufficient Session Expiration",
                        "engine": "Auth & Access Control",
                    },
                    suggestion=(
                        f"Invalidate the session in '{func_name}' by calling "
                        f"destroy_session(), invalidate_session(), or equivalent "
                        f"before responding to the logout request."
                    ),
                    location=loc,
                )

    # ------------------------------------------------------------------
    # Statement analysis (recursive walk)
    # ------------------------------------------------------------------

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Walk a statement, collecting auth patterns and detecting vulnerabilities."""
        loc = getattr(stmt, 'location', None) or SourceLocation(line=0, column=0)

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_expr_patterns(stmt.value, func, loc)
                # Track variables that receive ID-like values
                if self._expr_references_id(stmt.value):
                    self._id_vars.add(stmt.name)
                # Track variables that receive secret-like values
                if self._expr_references_secret(stmt.value):
                    self._secret_vars.add(stmt.name)
                # Track variables with role names from user input
                self._check_role_from_input(stmt.name, stmt.value, func, loc)

        elif isinstance(stmt, AssignStmt):
            self._check_expr_patterns(stmt.value, func, loc)
            if isinstance(stmt.target, Identifier):
                if self._expr_references_id(stmt.value):
                    self._id_vars.add(stmt.target.name)
                if self._expr_references_secret(stmt.value):
                    self._secret_vars.add(stmt.target.name)

        elif isinstance(stmt, ExprStmt):
            self._check_expr_patterns(stmt.expr, func, loc)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._check_expr_patterns(stmt.value, func, loc)

        elif isinstance(stmt, IfStmt):
            # Check the condition for weak role comparison patterns
            self._check_condition_patterns(stmt.condition, func, loc)
            self._check_expr_patterns(stmt.condition, func, loc)
            for s in stmt.then_body:
                self._analyze_statement(s, func)
            for s in stmt.else_body:
                self._analyze_statement(s, func)

        elif isinstance(stmt, WhileStmt):
            self._check_expr_patterns(stmt.condition, func, loc)
            for s in stmt.body:
                self._analyze_statement(s, func)

        elif isinstance(stmt, ForStmt):
            self._check_expr_patterns(stmt.iterable, func, loc)
            for s in stmt.body:
                self._analyze_statement(s, func)

    # ------------------------------------------------------------------
    # Expression pattern detection
    # ------------------------------------------------------------------

    def _check_expr_patterns(self, expr: Expr, func: PureFunc | TaskFunc,
                             loc: SourceLocation) -> None:
        """Check an expression for auth/access control patterns."""
        expr_loc = getattr(expr, 'location', None) or loc

        if isinstance(expr, FunctionCall):
            call_name = self._get_call_name(expr)
            if call_name:
                call_lower = call_name.lower()

                # Track auth/authz calls
                if call_name in AUTH_CHECK_FUNCTIONS or call_lower in {
                    f.lower() for f in AUTH_CHECK_FUNCTIONS
                }:
                    self._auth_calls_found.add(call_name)
                if call_name in AUTHZ_CHECK_FUNCTIONS or call_lower in {
                    f.lower() for f in AUTHZ_CHECK_FUNCTIONS
                }:
                    self._authz_calls_found.add(call_name)

                # Track CSRF checks
                if self._matches_pattern_set(call_name, CSRF_CHECK_PATTERNS):
                    self._auth_calls_found.add(call_name)

                # Track rate limiting
                if self._matches_pattern_set(call_name, RATE_LIMIT_PATTERNS):
                    self._auth_calls_found.add(call_name)

                # Track session invalidation
                if self._matches_pattern_set(call_name, SESSION_INVALIDATION_PATTERNS):
                    self._auth_calls_found.add(call_name)

                # Track ownership checks
                if self._matches_pattern_set(call_name, OWNERSHIP_CHECK_PATTERNS):
                    self._ownership_checks_found = True

                # Check for password comparison via ==
                # (handled in _check_condition_patterns for BinaryOp)

                # Check for constant-time comparison (safe)
                if call_name in CONSTANT_TIME_COMPARE or call_lower in {
                    f.lower() for f in CONSTANT_TIME_COMPARE
                }:
                    # Safe pattern — mark secrets as properly compared
                    pass

            # Recurse into arguments
            for arg in expr.args:
                self._check_expr_patterns(arg, func, loc)

        elif isinstance(expr, MethodCall):
            method = expr.method_name
            method_lower = method.lower()

            # Track auth method calls
            if method in AUTH_CHECK_FUNCTIONS or method_lower in {
                f.lower() for f in AUTH_CHECK_FUNCTIONS
            }:
                self._auth_calls_found.add(method)
            if method in AUTHZ_CHECK_FUNCTIONS or method_lower in {
                f.lower() for f in AUTHZ_CHECK_FUNCTIONS
            }:
                self._authz_calls_found.add(method)

            # Track ownership checks from method calls
            if self._matches_pattern_set(method, OWNERSHIP_CHECK_PATTERNS):
                self._ownership_checks_found = True

            # Detect data access with user-supplied IDs
            if method_lower in {m.lower() for m in DATA_ACCESS_METHODS}:
                has_id_arg = any(
                    self._expr_is_id_var(arg) for arg in expr.args
                )
                if has_id_arg:
                    self._unscoped_data_access.append((method, expr_loc))

                # Check if the method call includes an ownership scope
                if self._method_call_has_ownership_scope(expr):
                    self._ownership_checks_found = True

            # Check for session ID in URL
            self._check_session_in_url(expr, func, expr_loc)

            # Recurse into object and arguments
            self._check_expr_patterns(expr.obj, func, loc)
            for arg in expr.args:
                self._check_expr_patterns(arg, func, loc)

        elif isinstance(expr, FunctionCall):
            call_name = self._get_call_name(expr)
            if call_name:
                call_lower = call_name.lower()
                # Detect data access with user-supplied IDs (function calls)
                if call_lower in {m.lower() for m in DATA_ACCESS_METHODS}:
                    has_id_arg = any(
                        self._expr_is_id_var(arg) for arg in expr.args
                    )
                    if has_id_arg:
                        self._unscoped_data_access.append((call_name, expr_loc))

        elif isinstance(expr, BinaryOp):
            self._check_expr_patterns(expr.left, func, loc)
            self._check_expr_patterns(expr.right, func, loc)

        elif isinstance(expr, FieldAccess):
            self._check_expr_patterns(expr.obj, func, loc)
            # Track ownership references in field access chains
            if expr.field_name.lower() in {p.lower() for p in OWNERSHIP_CHECK_PATTERNS}:
                self._ownership_checks_found = True

    def _check_condition_patterns(self, expr: Expr, func: PureFunc | TaskFunc,
                                  loc: SourceLocation) -> None:
        """Check conditional expressions for weak auth patterns."""
        expr_loc = getattr(expr, 'location', None) or loc

        if isinstance(expr, BinaryOp):
            # Detect: password == some_value (timing-unsafe comparison)
            if expr.op == "==":
                left_is_secret = self._expr_is_secret_var(expr.left)
                right_is_secret = self._expr_is_secret_var(expr.right)

                if left_is_secret or right_is_secret:
                    secret_name = self._get_identifier_name(
                        expr.left if left_is_secret else expr.right
                    )
                    self._report(
                        severity=Severity.CRITICAL,
                        cwe="CWE-208",
                        message=(
                            f"Timing-unsafe credential comparison: "
                            f"'{func.name}' compares secret variable "
                            f"'{secret_name}' using '==' operator. This is "
                            f"vulnerable to timing side-channel attacks that "
                            f"can leak the secret value byte-by-byte."
                        ),
                        details={
                            "vulnerability": "timing_unsafe_comparison",
                            "function": func.name,
                            "variable": secret_name,
                            "owasp": "A07:2021 Identification and Authentication Failures",
                            "cwe": "CWE-208: Observable Timing Discrepancy",
                            "engine": "Auth & Access Control",
                        },
                        suggestion=(
                            f"Use a constant-time comparison function instead of '=='. "
                            f"For example: constant_time_compare({secret_name}, expected) "
                            f"or hmac.compare_digest({secret_name}, expected)."
                        ),
                        location=expr_loc,
                    )

                # Detect: role == "admin" (weak string-based role check)
                left_is_role = self._expr_is_role_var(expr.left)
                right_is_role = self._expr_is_role_var(expr.right)
                left_is_role_string = self._expr_is_role_string(expr.left)
                right_is_role_string = self._expr_is_role_string(expr.right)

                if (left_is_role and right_is_role_string) or \
                   (right_is_role and left_is_role_string):
                    role_var = self._get_identifier_name(
                        expr.left if left_is_role else expr.right
                    )
                    role_lit = self._get_string_value(
                        expr.right if right_is_role_string else expr.left
                    )
                    self._report(
                        severity=Severity.MEDIUM,
                        cwe="CWE-863",
                        message=(
                            f"String-based role comparison: '{func.name}' "
                            f"checks role with '{role_var} == \"{role_lit}\"'. "
                            f"String comparison is fragile and bypassable. "
                            f"Use a framework-level RBAC guard or enum-based "
                            f"role system instead."
                        ),
                        details={
                            "vulnerability": "string_role_comparison",
                            "function": func.name,
                            "role_variable": role_var,
                            "role_value": role_lit,
                            "owasp": "A01:2021 Broken Access Control",
                            "cwe": "CWE-863: Incorrect Authorization",
                            "engine": "Auth & Access Control",
                        },
                        suggestion=(
                            f"Replace 'if {role_var} == \"{role_lit}\"' with a "
                            f"framework-level guard: require_role(Role.{role_lit.upper()}) "
                            f"or has_role(user, Role.{role_lit.upper()})."
                        ),
                        location=expr_loc,
                    )

            # Recurse into nested conditions (&&, ||)
            if expr.op in ("&&", "||", "and", "or"):
                self._check_condition_patterns(expr.left, func, loc)
                self._check_condition_patterns(expr.right, func, loc)

    # ------------------------------------------------------------------
    # Special-case detectors
    # ------------------------------------------------------------------

    def _check_role_from_input(self, var_name: str, value: Expr,
                               func: PureFunc | TaskFunc,
                               loc: SourceLocation) -> None:
        """Detect role/admin variables derived from user input rather than
        server-side session data."""
        var_lower = var_name.lower()
        is_role_var = var_lower in {p.lower() for p in ROLE_VAR_PATTERNS}

        if not is_role_var:
            return

        # Check if the value comes from request/user input
        if self._expr_from_request_input(value):
            self._report(
                severity=Severity.CRITICAL,
                cwe="CWE-863",
                message=(
                    f"Client-controlled privilege: '{func.name}' derives "
                    f"role variable '{var_name}' from user input. "
                    f"An attacker can set their own role to escalate privileges. "
                    f"Roles must come from server-side session data, not "
                    f"from request parameters."
                ),
                details={
                    "vulnerability": "client_controlled_role",
                    "function": func.name,
                    "variable": var_name,
                    "owasp": "A01:2021 Broken Access Control",
                    "cwe": "CWE-863: Incorrect Authorization",
                    "engine": "Auth & Access Control",
                },
                suggestion=(
                    f"Derive '{var_name}' from the server-side session or "
                    f"a trusted token claim, not from request.body or "
                    f"request.params. For example: "
                    f"let {var_name} = session.user.role"
                ),
                location=loc,
            )

    def _check_session_in_url(self, expr: MethodCall,
                              func: PureFunc | TaskFunc,
                              loc: SourceLocation) -> None:
        """Detect session IDs being placed in URL parameters."""
        method_lower = expr.method_name.lower()

        # Check if building a URL with session data
        url_methods = {"redirect", "redirect_to", "url_for", "build_url",
                       "set_param", "append_param", "add_query"}
        if method_lower not in url_methods:
            return

        for arg in expr.args:
            if self._expr_references_session_id(arg):
                self._report(
                    severity=Severity.HIGH,
                    cwe="CWE-613",
                    message=(
                        f"Session ID in URL: '{func.name}' passes a session "
                        f"identifier as a URL parameter via '{expr.method_name}'. "
                        f"Session IDs in URLs are leaked through browser history, "
                        f"Referer headers, and server logs."
                    ),
                    details={
                        "vulnerability": "session_id_in_url",
                        "function": func.name,
                        "method": expr.method_name,
                        "owasp": "A07:2021 Identification and Authentication Failures",
                        "cwe": "CWE-613: Insufficient Session Expiration",
                        "engine": "Auth & Access Control",
                    },
                    suggestion=(
                        "Pass session identifiers via HTTP-only cookies or "
                        "Authorization headers, never as URL parameters."
                    ),
                    location=loc,
                )

    # ------------------------------------------------------------------
    # Helper: classification predicates
    # ------------------------------------------------------------------

    def _is_route_handler(self, name: str,
                          func: PureFunc | TaskFunc | None = None) -> bool:
        """Determine if a function name looks like a route handler.

        Uses a multi-signal heuristic:
        1. Exact HTTP method names (GET, POST, etc.) are always handlers.
        2. Functions with server-side HTTP params (req, res, etc.) are handlers.
        3. Functions matching route prefixes/suffixes are candidate handlers,
           BUT functions named ``handle*`` are only flagged if they show
           server-side HTTP patterns and do NOT show React/UI patterns.
        4. Functions whose body contains React/UI patterns (useState, onClick,
           setState, toast, etc.) are excluded — they are client-side event
           handlers, not API endpoints.
        """
        # 1. Exact HTTP method exports (Next.js API routes, etc.)
        if name in EXACT_ROUTE_HANDLER_NAMES:
            return True

        # 2. Gather body signals when we have the function AST
        has_http_params = False
        has_http_body_signals = False
        has_ui_body_signals = False

        if func is not None:
            # Check parameter names for HTTP handler indicators
            param_names = {p.name.lower() for p in func.params}
            has_http_params = bool(param_names & HTTP_HANDLER_PARAMS)

            # Collect all identifiers/names from function body for pattern matching
            body_names = self._collect_body_names(func.body)
            body_text_lower = " ".join(body_names).lower()

            has_http_body_signals = any(
                pat.lower() in body_text_lower for pat in HTTP_RESPONSE_PATTERNS
            )
            has_ui_body_signals = any(
                pat.lower() in body_text_lower for pat in REACT_UI_PATTERNS
            )

        name_lower = name.lower()

        # 3. handle* functions: require positive HTTP signals AND no UI signals
        if name_lower.startswith("handle"):
            # If the body has UI patterns (React hooks, state setters, JSX
            # events, etc.) this is a client-side event handler — skip it.
            if has_ui_body_signals and not has_http_body_signals:
                return False
            # If it has explicit HTTP params or HTTP response patterns, flag it.
            if has_http_params or has_http_body_signals:
                return True
            # Bare handle* with no body context — be conservative, skip it.
            # This avoids false positives when we cannot inspect the body.
            return False

        # 4. on_*, do_*, process_*, get_* — only flag with HTTP evidence
        ambiguous_prefixes = ("on_", "do_", "process_", "get_")
        if any(name_lower.startswith(p) for p in ambiguous_prefixes):
            if has_ui_body_signals and not has_http_body_signals:
                return False
            if has_http_params or has_http_body_signals:
                return True
            # Check suffixes as a fallback (e.g., get_users_handler)
            for suffix in ROUTE_HANDLER_SUFFIXES:
                if name_lower.endswith(suffix.lower()):
                    return True
            return False

        # 5. Standard route prefixes (api_, route_, endpoint_, etc.)
        for prefix in ROUTE_HANDLER_PREFIXES:
            if name_lower.startswith(prefix.lower()):
                # Even standard prefixes: skip if body is clearly client-side
                if has_ui_body_signals and not has_http_body_signals and not has_http_params:
                    return False
                return True

        # 6. Standard route suffixes
        for suffix in ROUTE_HANDLER_SUFFIXES:
            if name_lower.endswith(suffix.lower()):
                if has_ui_body_signals and not has_http_body_signals and not has_http_params:
                    return False
                return True

        # 7. Functions with HTTP params even without naming conventions
        if has_http_params and has_http_body_signals:
            return True

        return False

    def _collect_body_names(self, body: List[Statement]) -> List[str]:
        """Recursively collect all identifier and method names from a body.

        Returns a flat list of name strings used for pattern matching against
        HTTP and UI signal sets.
        """
        names: List[str] = []
        for stmt in body:
            if isinstance(stmt, ExprStmt):
                self._collect_expr_names(stmt.expr, names)
            elif isinstance(stmt, LetStmt):
                names.append(stmt.name)
                if stmt.value:
                    self._collect_expr_names(stmt.value, names)
            elif isinstance(stmt, AssignStmt):
                self._collect_expr_names(stmt.target, names)
                self._collect_expr_names(stmt.value, names)
            elif isinstance(stmt, ReturnStmt):
                if stmt.value:
                    self._collect_expr_names(stmt.value, names)
            elif isinstance(stmt, IfStmt):
                self._collect_expr_names(stmt.condition, names)
                names.extend(self._collect_body_names(stmt.then_body))
                names.extend(self._collect_body_names(stmt.else_body))
            elif isinstance(stmt, WhileStmt):
                self._collect_expr_names(stmt.condition, names)
                names.extend(self._collect_body_names(stmt.body))
            elif isinstance(stmt, ForStmt):
                self._collect_expr_names(stmt.iterable, names)
                names.extend(self._collect_body_names(stmt.body))
        return names

    def _collect_expr_names(self, expr: Expr, names: List[str]) -> None:
        """Recursively collect identifier and method names from an expression."""
        if isinstance(expr, Identifier):
            names.append(expr.name)
        elif isinstance(expr, StringLiteral):
            names.append(expr.value)
        elif isinstance(expr, FieldAccess):
            full = self._get_identifier_name(expr)
            names.append(full)
            self._collect_expr_names(expr.obj, names)
        elif isinstance(expr, FunctionCall):
            call_name = self._get_call_name(expr)
            if call_name:
                names.append(call_name)
            for arg in expr.args:
                self._collect_expr_names(arg, names)
        elif isinstance(expr, MethodCall):
            names.append(expr.method_name)
            self._collect_expr_names(expr.obj, names)
            for arg in expr.args:
                self._collect_expr_names(arg, names)
        elif isinstance(expr, BinaryOp):
            self._collect_expr_names(expr.left, names)
            self._collect_expr_names(expr.right, names)

    def _is_state_changing_handler(self, name: str) -> bool:
        """Determine if a handler performs state-changing operations."""
        name_lower = name.lower()
        for prefix in STATE_CHANGING_PREFIXES:
            if name_lower.startswith(prefix) or f"_{prefix}" in name_lower:
                return True
        return False

    def _is_login_handler(self, name: str) -> bool:
        """Determine if a function is a login/authentication handler."""
        login_patterns = {
            "login", "log_in", "signin", "sign_in", "authenticate",
            "handle_login", "handleLogin", "api_login", "apiLogin",
            "post_login", "postLogin", "do_login", "doLogin",
            "process_login", "processLogin", "submit_login", "submitLogin",
        }
        name_lower = name.lower()
        return name_lower in login_patterns or any(
            pat in name_lower for pat in ("login", "signin", "sign_in", "log_in")
        )

    def _is_logout_handler(self, name: str) -> bool:
        """Determine if a function is a logout handler."""
        name_lower = name.lower()
        return any(
            pat in name_lower for pat in ("logout", "log_out", "signout", "sign_out")
        )

    def _has_rate_limiting(self, func: PureFunc | TaskFunc) -> bool:
        """Check if a function contains rate limiting patterns (in its body)."""
        return self._body_contains_pattern(func.body, RATE_LIMIT_PATTERNS)

    def _body_contains_pattern(self, body: List[Statement],
                               patterns: Set[str]) -> bool:
        """Recursively check if any statement in a body matches patterns."""
        for stmt in body:
            if isinstance(stmt, ExprStmt):
                if self._expr_matches_patterns(stmt.expr, patterns):
                    return True
            elif isinstance(stmt, LetStmt) and stmt.value:
                if self._expr_matches_patterns(stmt.value, patterns):
                    return True
            elif isinstance(stmt, AssignStmt):
                if self._expr_matches_patterns(stmt.value, patterns):
                    return True
            elif isinstance(stmt, IfStmt):
                if self._expr_matches_patterns(stmt.condition, patterns):
                    return True
                if self._body_contains_pattern(stmt.then_body, patterns):
                    return True
                if self._body_contains_pattern(stmt.else_body, patterns):
                    return True
            elif isinstance(stmt, WhileStmt):
                if self._body_contains_pattern(stmt.body, patterns):
                    return True
            elif isinstance(stmt, ForStmt):
                if self._body_contains_pattern(stmt.body, patterns):
                    return True
        return False

    def _expr_matches_patterns(self, expr: Expr, patterns: Set[str]) -> bool:
        """Check if an expression contains a call matching any pattern."""
        if isinstance(expr, FunctionCall):
            call_name = self._get_call_name(expr)
            if call_name and self._matches_pattern_set(call_name, patterns):
                return True
            return any(self._expr_matches_patterns(a, patterns) for a in expr.args)
        if isinstance(expr, MethodCall):
            if self._matches_pattern_set(expr.method_name, patterns):
                return True
            if self._expr_matches_patterns(expr.obj, patterns):
                return True
            return any(self._expr_matches_patterns(a, patterns) for a in expr.args)
        if isinstance(expr, BinaryOp):
            return (self._expr_matches_patterns(expr.left, patterns) or
                    self._expr_matches_patterns(expr.right, patterns))
        if isinstance(expr, FieldAccess):
            return self._expr_matches_patterns(expr.obj, patterns)
        return False

    # ------------------------------------------------------------------
    # Helper: expression interrogation
    # ------------------------------------------------------------------

    def _get_call_name(self, expr: FunctionCall) -> str:
        """Extract the function name from a FunctionCall."""
        if isinstance(expr.callee, Identifier):
            return expr.callee.name
        return getattr(expr.callee, 'name', '')

    def _get_identifier_name(self, expr: Expr) -> str:
        """Extract the name from an Identifier or FieldAccess."""
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, FieldAccess):
            obj_name = self._get_identifier_name(expr.obj)
            return f"{obj_name}.{expr.field_name}" if obj_name else expr.field_name
        return ""

    def _get_string_value(self, expr: Expr) -> str:
        """Extract the string value from a StringLiteral."""
        if isinstance(expr, StringLiteral):
            return expr.value
        return ""

    def _expr_is_id_var(self, expr: Expr) -> bool:
        """Check if an expression references a user-supplied ID variable."""
        if isinstance(expr, Identifier):
            return expr.name in self._id_vars
        if isinstance(expr, FieldAccess):
            # request.params.id, etc.
            full_name = self._get_identifier_name(expr)
            return any(pat in full_name.lower() for pat in ID_PARAM_PATTERNS)
        return False

    def _expr_references_id(self, expr: Expr) -> bool:
        """Check if an expression derives from an ID parameter."""
        if isinstance(expr, Identifier):
            return expr.name in self._id_vars
        if isinstance(expr, FieldAccess):
            field_lower = expr.field_name.lower()
            if field_lower in ID_PARAM_PATTERNS or field_lower.endswith("_id"):
                return True
            return self._expr_references_id(expr.obj)
        if isinstance(expr, MethodCall):
            return any(self._expr_references_id(a) for a in expr.args)
        if isinstance(expr, FunctionCall):
            return any(self._expr_references_id(a) for a in expr.args)
        return False

    def _expr_is_secret_var(self, expr: Expr) -> bool:
        """Check if an expression references a secret/password variable."""
        if isinstance(expr, Identifier):
            if expr.name in self._secret_vars:
                return True
            return any(pat in expr.name.lower() for pat in PASSWORD_VAR_PATTERNS)
        if isinstance(expr, FieldAccess):
            return any(
                pat in expr.field_name.lower() for pat in PASSWORD_VAR_PATTERNS
            )
        return False

    def _expr_references_secret(self, expr: Expr) -> bool:
        """Check if an expression derives from a secret variable."""
        if isinstance(expr, Identifier):
            return expr.name in self._secret_vars
        if isinstance(expr, FieldAccess):
            return any(
                pat in expr.field_name.lower() for pat in PASSWORD_VAR_PATTERNS
            ) or self._expr_references_secret(expr.obj)
        return False

    def _expr_is_role_var(self, expr: Expr) -> bool:
        """Check if an expression is a role variable."""
        if isinstance(expr, Identifier):
            return expr.name.lower() in {p.lower() for p in ROLE_VAR_PATTERNS}
        if isinstance(expr, FieldAccess):
            return expr.field_name.lower() in {p.lower() for p in ROLE_VAR_PATTERNS}
        return False

    def _expr_is_role_string(self, expr: Expr) -> bool:
        """Check if an expression is a string literal with a role name."""
        if isinstance(expr, StringLiteral):
            return expr.value.lower() in ROLE_STRING_LITERALS
        return False

    def _expr_from_request_input(self, expr: Expr) -> bool:
        """Check if an expression derives from request/user input."""
        if isinstance(expr, FieldAccess):
            full = self._get_identifier_name(expr)
            full_lower = full.lower()
            request_patterns = (
                "request.body", "request.params", "request.query",
                "req.body", "req.params", "req.query",
                "request.form", "request.data", "request.json",
                "req.form", "req.data", "req.json",
                "body.", "params.", "query.",
            )
            return any(pat in full_lower for pat in request_patterns)
        if isinstance(expr, MethodCall):
            method_lower = expr.method_name.lower()
            input_methods = {
                "get_param", "getparam", "get_body", "getbody",
                "get_query", "getquery", "get_input", "getinput",
                "param", "query", "body", "form",
            }
            return method_lower in input_methods
        if isinstance(expr, FunctionCall):
            call_name = self._get_call_name(expr)
            if call_name:
                input_funcs = {
                    "get_param", "get_body", "get_query", "get_input",
                    "read_input", "parse_body", "parse_params",
                }
                return call_name.lower() in input_funcs
        return False

    def _expr_references_session_id(self, expr: Expr) -> bool:
        """Check if an expression references a session ID."""
        if isinstance(expr, Identifier):
            name_lower = expr.name.lower()
            return any(pat in name_lower for pat in
                      ("session_id", "sessionid", "sid", "session_token",
                       "sessiontoken", "jsessionid", "phpsessid"))
        if isinstance(expr, FieldAccess):
            field_lower = expr.field_name.lower()
            return any(pat in field_lower for pat in
                      ("session_id", "sessionid", "sid", "session_token",
                       "sessiontoken", "jsessionid", "phpsessid"))
        return False

    def _method_call_has_ownership_scope(self, expr: MethodCall) -> bool:
        """Check if a data access method call includes an ownership scope."""
        # Look for ownership patterns in arguments
        for arg in expr.args:
            if self._expr_contains_ownership_ref(arg):
                return True
        return False

    def _expr_contains_ownership_ref(self, expr: Expr) -> bool:
        """Check if an expression references the current user (ownership)."""
        if isinstance(expr, Identifier):
            return expr.name.lower() in {p.lower() for p in OWNERSHIP_CHECK_PATTERNS}
        if isinstance(expr, FieldAccess):
            full = self._get_identifier_name(expr)
            full_lower = full.lower()
            return any(pat in full_lower for pat in
                      ("current_user", "currentuser", "auth_user", "authuser",
                       "session.user", "req.user", "request.user"))
        if isinstance(expr, BinaryOp):
            return (self._expr_contains_ownership_ref(expr.left) or
                    self._expr_contains_ownership_ref(expr.right))
        if isinstance(expr, FunctionCall):
            call_name = self._get_call_name(expr)
            if call_name and call_name.lower() in {
                p.lower() for p in OWNERSHIP_CHECK_PATTERNS
            }:
                return True
            return any(self._expr_contains_ownership_ref(a) for a in expr.args)
        if isinstance(expr, MethodCall):
            return (self._expr_contains_ownership_ref(expr.obj) or
                    any(self._expr_contains_ownership_ref(a) for a in expr.args))
        return False

    @staticmethod
    def _matches_pattern_set(name: str, patterns: Set[str]) -> bool:
        """Check if a name matches any pattern in the set (case-insensitive)."""
        name_lower = name.lower()
        return any(pat.lower() in name_lower for pat in patterns)

    # ------------------------------------------------------------------
    # Error reporting
    # ------------------------------------------------------------------

    def _report(self, severity: Severity, cwe: str, message: str,
                details: Dict, suggestion: str,
                location: SourceLocation) -> None:
        """Emit a structured finding as an AeonError."""
        details["severity"] = severity.value
        self.errors.append(contract_error(
            precondition=f"[{severity.value.upper()}] [{cwe}] {message}",
            failing_values=details,
            function_signature="auth_access_control",
            location=location,
        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_auth_access(program: Program) -> list:
    """Run authentication and access control analysis on an AEON program.

    Detects broken authentication and access control vulnerabilities
    covering OWASP A01:2021 and A07:2021:

    1. Missing authentication on route handlers / API endpoints (CWE-862)
    2. Missing authorization after authentication (CWE-863)
    3. Insecure Direct Object References — IDOR (CWE-639)
    4. Privilege escalation via string-based role comparison (CWE-863)
    5. Client-controlled role/privilege variables (CWE-863)
    6. Timing-unsafe credential comparison (CWE-208)
    7. Missing rate limiting on login endpoints (CWE-307)
    8. Missing session invalidation on logout (CWE-613)
    9. Session ID in URL parameters (CWE-613)
    10. Missing CSRF protection on state-changing endpoints (CWE-352)

    Severity levels:
      Critical — Missing auth on data-modifying endpoints, IDOR,
                 timing-unsafe password comparison, client-controlled roles
      High     — Missing CSRF, broken session management
      Medium   — String-based role comparison, missing rate limiting,
                 authentication without authorization
    """
    analyzer = AuthAccessControlAnalyzer()
    return analyzer.check_program(program)
