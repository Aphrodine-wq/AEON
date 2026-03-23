"""AEON API Security Engine -- Detecting API Security Vulnerabilities.

Implements API security analysis based on:
  OWASP API Security Top 10 (2023)
  https://owasp.org/API-Security/editions/2023/en/0x11-t10/

  Bau et al. (2010) "State of the Art: Automated Black-Box Web Application
  Vulnerability Testing"
  IEEE S&P '10, https://doi.org/10.1109/SP.2010.27

  Pellegrino et al. (2017) "Deemon: Detecting CSRF with Dynamic Analysis
  and Property Graphs"
  CCS '17, https://doi.org/10.1145/3133956.3133959

Key Theory:

1. SECURITY HEADERS:
   HTTP response headers that mitigate entire classes of attacks:
   - Content-Security-Policy prevents XSS via script injection
   - X-Content-Type-Options prevents MIME-sniffing attacks
   - X-Frame-Options / frame-ancestors prevents clickjacking
   - Strict-Transport-Security enforces HTTPS
   - Referrer-Policy controls information leakage
   - Permissions-Policy restricts browser features
   Middleware like helmet() in Express sets all of these.

2. CORS POLICY:
   Cross-Origin Resource Sharing controls which origins can access
   an API. Wildcard origin (*) is permissive and dangerous with
   credentials. Reflecting the Origin header without validation
   is equivalent to wildcard.

3. MASS ASSIGNMENT:
   Accepting the entire request body and passing it directly to
   database create/update operations allows attackers to set fields
   they should not control (e.g., isAdmin, role, balance).

4. EXCESSIVE DATA EXPOSURE:
   Returning entire database objects without field selection leaks
   sensitive data (password hashes, tokens, internal IDs).

5. RATE LIMITING:
   Authentication endpoints without rate limiting enable credential
   stuffing. Any public endpoint without rate limiting enables DoS.

6. HTTP METHOD SECURITY:
   TRACE/TRACK enable XST attacks. DELETE/PUT/PATCH without
   authorization checks enable unauthorized mutations.

7. GRAPHQL SECURITY:
   Introspection in production leaks the schema. Unbounded query
   depth and complexity enable denial-of-service via nested queries.

8. REQUEST VALIDATION:
   Accepting unvalidated input enables injection, type confusion,
   and business logic bypass.

9. VERBOSE ERROR MESSAGES:
   Returning stack traces, database errors, or internal paths in
   API responses leaks implementation details to attackers.

10. INSECURE DIRECT API:
    Exposing debug, admin, or internal endpoints without IP
    restriction or authentication enables unauthorized access.

CWE References:
  - CWE-16:  Configuration (security headers)
  - CWE-200: Exposure of Sensitive Information
  - CWE-209: Information Exposure Through Error Message
  - CWE-770: Missing Rate Limiting
  - CWE-915: Mass Assignment
  - CWE-942: Permissive CORS Policy

Detects:
  - Missing security headers on route-handling files
  - Wildcard CORS or reflected origin without validation
  - Request body passed directly to ORM create/update
  - Entire database objects returned without field selection
  - Authentication endpoints without rate limiting
  - TRACE/TRACK methods enabled, DELETE without auth
  - GraphQL introspection/depth/complexity misconfig
  - Unvalidated request body/params access
  - Stack traces or DB errors returned to client
  - Debug/admin endpoints without access control
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
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Vulnerability Categories
# ---------------------------------------------------------------------------

class VulnCategory(Enum):
    MISSING_SECURITY_HEADERS = "missing_security_headers"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    MASS_ASSIGNMENT = "mass_assignment"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    MISSING_RATE_LIMITING = "missing_rate_limiting"
    INSECURE_HTTP_METHODS = "insecure_http_methods"
    GRAPHQL_SECURITY = "graphql_security"
    MISSING_REQUEST_VALIDATION = "missing_request_validation"
    VERBOSE_ERROR_MESSAGES = "verbose_error_messages"
    INSECURE_DIRECT_API = "insecure_direct_api"


CWE_MAP: Dict[VulnCategory, str] = {
    VulnCategory.MISSING_SECURITY_HEADERS: "CWE-16",
    VulnCategory.CORS_MISCONFIGURATION: "CWE-942",
    VulnCategory.MASS_ASSIGNMENT: "CWE-915",
    VulnCategory.EXCESSIVE_DATA_EXPOSURE: "CWE-200",
    VulnCategory.MISSING_RATE_LIMITING: "CWE-770",
    VulnCategory.INSECURE_HTTP_METHODS: "CWE-16",
    VulnCategory.GRAPHQL_SECURITY: "CWE-16",
    VulnCategory.MISSING_REQUEST_VALIDATION: "CWE-20",
    VulnCategory.VERBOSE_ERROR_MESSAGES: "CWE-209",
    VulnCategory.INSECURE_DIRECT_API: "CWE-200",
}


# ---------------------------------------------------------------------------
# Detection Patterns -- Security Headers
# ---------------------------------------------------------------------------

# Middleware functions that set all security headers
SECURITY_HEADER_MIDDLEWARE: Set[str] = {
    "helmet", "secure_headers", "secureHeaders",
    "SecurityMiddleware", "security_middleware",
    "django_security_middleware", "talisman",
    "secure", "koa_helmet", "fastify_helmet",
}

# Individual header names that must be present
REQUIRED_SECURITY_HEADERS: Set[str] = {
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
}

# Route-defining function/method names
ROUTE_HANDLERS: Set[str] = {
    "get", "post", "put", "patch", "delete", "head", "options",
    "route", "router", "handle", "handler",
    "app_get", "app_post", "app_put", "app_patch", "app_delete",
    "api_view", "api_route", "endpoint",
    "createHandler", "defineRoute", "addRoute",
    "RequestMapping", "GetMapping", "PostMapping",
    "PutMapping", "DeleteMapping", "PatchMapping",
}

# Middleware-registration patterns
MIDDLEWARE_REGISTRATION: Set[str] = {
    "use", "middleware", "add_middleware", "addMiddleware",
    "register_middleware", "registerMiddleware",
    "before_request", "beforeRequest", "beforeAll",
    "pipe", "useGlobalPipes", "useGlobalGuards",
}


# ---------------------------------------------------------------------------
# Detection Patterns -- CORS
# ---------------------------------------------------------------------------

CORS_CONFIG_FUNCTIONS: Set[str] = {
    "cors", "enable_cors", "enableCors",
    "add_cors", "addCors", "cors_middleware",
    "CorsMiddleware", "cors_config",
    "set_cors", "setCors", "allowCors",
}

CORS_HEADER_NAMES: Set[str] = {
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
}


# ---------------------------------------------------------------------------
# Detection Patterns -- Mass Assignment
# ---------------------------------------------------------------------------

# ORM create/update methods that accept objects
ORM_WRITE_METHODS: Set[str] = {
    "create", "update", "save", "insert",
    "bulkCreate", "bulk_create", "insertMany", "insert_many",
    "updateMany", "update_many", "upsert",
    "findAndUpdate", "findOneAndUpdate",
    "find_and_update", "find_one_and_update",
    "updateOne", "update_one", "replaceOne", "replace_one",
    "set", "assign", "merge",
    "objects_create", "objects_update",
    "from_dict", "from_json",
}

# Request body access patterns
REQUEST_BODY_PATTERNS: Set[str] = {
    "body", "data", "payload", "json",
    "request_data", "request_body", "requestBody",
    "parsed_body", "parsedBody",
}

# Field allowlist/selection methods
FIELD_ALLOWLIST_METHODS: Set[str] = {
    "pick", "only", "permit", "allowlist",
    "whitelist", "select_fields", "selectFields",
    "allowed_fields", "allowedFields",
    "pluck", "slice", "filter_keys", "filterKeys",
    "schema_validate", "validate_fields",
}


# ---------------------------------------------------------------------------
# Detection Patterns -- Excessive Data Exposure
# ---------------------------------------------------------------------------

# Response methods that send data
RESPONSE_METHODS: Set[str] = {
    "json", "send", "write", "render",
    "respond", "response", "reply",
    "res_json", "res_send",
    "jsonify", "to_json", "toJSON",
    "ok", "success", "data",
    "JsonResponse", "json_response",
    "Response", "make_response",
}

# Sensitive field names that should never be in responses
SENSITIVE_FIELDS: Set[str] = {
    "password", "password_hash", "passwordHash", "hashed_password",
    "secret", "secret_key", "secretKey", "api_key", "apiKey",
    "token", "access_token", "accessToken", "refresh_token", "refreshToken",
    "private_key", "privateKey", "signing_key", "signingKey",
    "ssn", "social_security", "socialSecurity",
    "credit_card", "creditCard", "card_number", "cardNumber",
    "cvv", "cvc", "pin",
    "internal_id", "internalId", "_id",
    "salt", "pepper", "encryption_key", "encryptionKey",
    "mfa_secret", "mfaSecret", "otp_secret", "otpSecret",
    "recovery_codes", "recoveryCodes",
}

# Field selection methods (evidence of proper filtering)
FIELD_SELECTION_METHODS: Set[str] = {
    "select", "only", "fields", "pick",
    "exclude", "omit", "without",
    "project", "projection",
    "values", "values_list",
    "to_dict", "toDict", "serialize",
    "as_dict", "asDict",
}

# Serializer patterns (evidence of controlled output)
SERIALIZER_PATTERNS: Set[str] = {
    "serializer", "Serializer", "serialize",
    "schema", "Schema", "DTO", "dto",
    "presenter", "Presenter",
    "transformer", "Transformer",
    "resource", "Resource",
    "view_model", "ViewModel",
    "response_model", "ResponseModel",
}


# ---------------------------------------------------------------------------
# Detection Patterns -- Rate Limiting
# ---------------------------------------------------------------------------

RATE_LIMIT_MIDDLEWARE: Set[str] = {
    "rateLimit", "rate_limit", "rateLimiter", "rate_limiter",
    "throttle", "Throttle", "throttler", "Throttler",
    "limiter", "Limiter", "slowDown", "slow_down",
    "RateLimitGuard", "rate_limit_guard",
    "express_rate_limit", "expressRateLimit",
    "django_ratelimit", "flask_limiter",
}

# Sensitive endpoints that especially need rate limiting
SENSITIVE_ENDPOINTS: Set[str] = {
    "login", "signin", "sign_in", "signIn",
    "register", "signup", "sign_up", "signUp",
    "password_reset", "passwordReset", "reset_password", "resetPassword",
    "forgot_password", "forgotPassword",
    "verify_otp", "verifyOtp", "verify_code", "verifyCode",
    "verify_email", "verifyEmail", "confirm_email", "confirmEmail",
    "two_factor", "twoFactor", "mfa", "2fa",
    "token", "refresh_token", "refreshToken",
    "authenticate", "authorize",
}


# ---------------------------------------------------------------------------
# Detection Patterns -- Insecure HTTP Methods
# ---------------------------------------------------------------------------

DANGEROUS_METHODS: Set[str] = {
    "trace", "track", "TRACE", "TRACK",
}

MUTATION_METHODS: Set[str] = {
    "delete", "put", "patch",
    "DELETE", "PUT", "PATCH",
}

AUTH_CHECK_PATTERNS: Set[str] = {
    "authenticate", "authorize", "isAuthenticated", "is_authenticated",
    "requireAuth", "require_auth", "requireLogin", "require_login",
    "authGuard", "auth_guard", "AuthGuard",
    "isAuthorized", "is_authorized", "checkAuth", "check_auth",
    "verifyToken", "verify_token", "ensureAuth", "ensure_auth",
    "protect", "protected", "requirePermission", "require_permission",
    "checkOwnership", "check_ownership", "isOwner", "is_owner",
    "getUser", "get_user", "getCurrentUser", "get_current_user",
    "passport", "jwt_required", "jwtRequired",
    "login_required", "loginRequired",
}


# ---------------------------------------------------------------------------
# Detection Patterns -- GraphQL Security
# ---------------------------------------------------------------------------

GRAPHQL_SETUP_FUNCTIONS: Set[str] = {
    "GraphQLServer", "ApolloServer", "graphqlHTTP",
    "graphql_server", "apollo_server", "graphql_http",
    "createServer", "create_server",
    "GraphQLModule", "graphql_module",
    "makeExecutableSchema", "make_executable_schema",
    "buildSchema", "build_schema",
    "Strawberry", "strawberry",
    "Ariadne", "ariadne",
    "graphene",
}

GRAPHQL_DEPTH_LIMITERS: Set[str] = {
    "depthLimit", "depth_limit", "depthLimiting",
    "maxDepth", "max_depth", "queryDepth", "query_depth",
    "DepthLimitRule", "depth_limit_rule",
    "GraphQLDepthLimit", "graphql_depth_limit",
}

GRAPHQL_COMPLEXITY_LIMITERS: Set[str] = {
    "costAnalysis", "cost_analysis", "queryCost", "query_cost",
    "complexityLimit", "complexity_limit",
    "queryComplexity", "query_complexity",
    "maxComplexity", "max_complexity",
    "ComplexityLimitRule", "complexity_limit_rule",
    "GraphQLComplexity", "graphql_complexity",
}


# ---------------------------------------------------------------------------
# Detection Patterns -- Request Validation
# ---------------------------------------------------------------------------

VALIDATION_LIBRARIES: Set[str] = {
    # JavaScript/TypeScript
    "validate", "Validate", "validator", "Validator",
    "parse", "safeParse", "safe_parse",
    "zod", "Zod", "z_string", "z_number", "z_object",
    "joi", "Joi", "celebrate",
    "yup", "Yup",
    "class_validator", "classValidator",
    "io_ts", "superstruct", "valibot",
    # Python
    "pydantic", "Pydantic", "BaseModel",
    "marshmallow", "Marshmallow",
    "cerberus", "Cerberus",
    "wtforms", "WTForms",
    "django_forms", "DjangoForms",
    # General
    "schema", "Schema",
    "validateBody", "validate_body",
    "validateParams", "validate_params",
    "validateQuery", "validate_query",
    "checkSchema", "check_schema",
}

# Raw access without validation
RAW_BODY_ACCESS: Set[str] = {
    "body", "params", "query",
    "request_body", "request_data",
    "json", "form",
}

RAW_PARSE_FUNCTIONS: Set[str] = {
    "JSON_parse", "json_parse", "JSON.parse",
    "json_loads", "json_decode",
    "yaml_load", "yaml_safe_load",
    "parse", "loads",
}


# ---------------------------------------------------------------------------
# Detection Patterns -- Verbose Error Messages
# ---------------------------------------------------------------------------

ERROR_EXPOSURE_PATTERNS: Set[str] = {
    "message", "stack", "stackTrace", "stack_trace",
    "traceback", "trace",
    "detail", "details",
    "error", "err",
    "cause",
}

DEBUG_ENDPOINTS: Set[str] = {
    "debug", "__debug__", "_debug",
    "admin_sql", "admin/sql",
    "phpinfo", "server_info", "serverInfo",
    "health_debug", "healthDebug",
    "test", "_test", "__test__",
    "internal", "_internal",
    "metrics", "prometheus",
    "graphiql", "playground",
    "swagger", "api_docs", "apiDocs",
}


# ---------------------------------------------------------------------------
# File-Level Context Tracker
# ---------------------------------------------------------------------------

@dataclass
class FileContext:
    """Tracks file-level security context across all functions."""
    has_route_handlers: bool = False
    has_security_header_middleware: bool = False
    has_cors_config: bool = False
    has_rate_limit_middleware: bool = False
    has_graphql_setup: bool = False
    has_graphql_depth_limit: bool = False
    has_graphql_complexity_limit: bool = False
    has_graphql_introspection_disabled: bool = False
    has_validation_middleware: bool = False
    route_handler_locations: List[SourceLocation] = field(default_factory=list)
    sensitive_endpoint_locations: List[Tuple[str, SourceLocation]] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# API Security Analyzer
# ---------------------------------------------------------------------------

class APISecurityAnalyzer:
    """Analyzes programs for API security vulnerabilities.

    Performs a two-pass analysis:
      Pass 1: Collect file-level context (middleware, route handlers, config).
      Pass 2: Per-function analysis for each vulnerability category.
    """

    def __init__(self):
        self.errors: List[AeonError] = []
        self._file_ctx = FileContext()
        self._program_filename: str = "<stdin>"

    def check_program(self, program: Program) -> List[AeonError]:
        """Run API security analysis on the entire program."""
        self.errors = []
        self._file_ctx = FileContext()
        self._program_filename = program.filename

        # --- Pass 1: Collect file-level context ---
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._collect_file_context(decl)

        # --- Pass 2: Per-function vulnerability analysis ---
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._check_cors_misconfig(decl)
                self._check_mass_assignment(decl)
                self._check_excessive_data_exposure(decl)
                self._check_insecure_http_methods(decl)
                self._check_graphql_security(decl)
                self._check_missing_request_validation(decl)
                self._check_verbose_error_messages(decl)
                self._check_insecure_direct_api(decl)

        # --- File-level checks (after all functions scanned) ---
        self._check_missing_security_headers()
        self._check_missing_rate_limiting()

        return self.errors

    # ------------------------------------------------------------------
    # Pass 1 helpers: collect file-level context
    # ------------------------------------------------------------------

    def _collect_file_context(self, func: PureFunc | TaskFunc) -> None:
        """Scan a function to collect file-level facts."""
        func_name_lower = func.name.lower()
        func_loc = getattr(func, 'location', SourceLocation(self._program_filename, 0, 0))

        # Check if the function name itself is a route handler pattern
        if func_name_lower in ROUTE_HANDLERS:
            self._file_ctx.has_route_handlers = True
            self._file_ctx.route_handler_locations.append(func_loc)

        # Check if the function name matches a sensitive endpoint
        for endpoint in SENSITIVE_ENDPOINTS:
            if endpoint in func_name_lower:
                self._file_ctx.sensitive_endpoint_locations.append(
                    (func.name, func_loc)
                )
                break

        for stmt in func.body:
            self._collect_context_from_statement(stmt)

    def _collect_context_from_statement(self, stmt: Statement) -> None:
        """Recursively scan a statement for file-level context signals."""
        if isinstance(stmt, ExprStmt):
            self._collect_context_from_expr(stmt.expr)
        elif isinstance(stmt, LetStmt) and stmt.value:
            self._collect_context_from_expr(stmt.value)
        elif isinstance(stmt, AssignStmt):
            self._collect_context_from_expr(stmt.value)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._collect_context_from_statement(s)
            for s in stmt.else_body:
                self._collect_context_from_statement(s)
        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._collect_context_from_expr(stmt.value)

    def _collect_context_from_expr(self, expr: Expr) -> None:
        """Extract file-level signals from an expression."""
        loc = getattr(expr, 'location', SourceLocation(self._program_filename, 0, 0))

        if isinstance(expr, FunctionCall):
            callee_name = self._get_callee_name(expr)
            if callee_name:
                cn_lower = callee_name.lower()
                # Security header middleware
                if callee_name in SECURITY_HEADER_MIDDLEWARE:
                    self._file_ctx.has_security_header_middleware = True
                # CORS config
                if callee_name in CORS_CONFIG_FUNCTIONS:
                    self._file_ctx.has_cors_config = True
                # Rate limiting
                if callee_name in RATE_LIMIT_MIDDLEWARE:
                    self._file_ctx.has_rate_limit_middleware = True
                # GraphQL setup
                if callee_name in GRAPHQL_SETUP_FUNCTIONS:
                    self._file_ctx.has_graphql_setup = True
                    self._scan_graphql_config(expr)
                # GraphQL depth/complexity limiters
                if callee_name in GRAPHQL_DEPTH_LIMITERS:
                    self._file_ctx.has_graphql_depth_limit = True
                if callee_name in GRAPHQL_COMPLEXITY_LIMITERS:
                    self._file_ctx.has_graphql_complexity_limit = True
                # Route handlers
                if callee_name in ROUTE_HANDLERS:
                    self._file_ctx.has_route_handlers = True
                    self._file_ctx.route_handler_locations.append(loc)
                    # Check if it is a sensitive endpoint
                    self._check_route_is_sensitive(expr, loc)
                # Middleware registration
                if callee_name in MIDDLEWARE_REGISTRATION:
                    self._scan_middleware_args(expr)
                # Validation middleware
                if callee_name in VALIDATION_LIBRARIES:
                    self._file_ctx.has_validation_middleware = True

            # Recurse into arguments
            for arg in expr.args:
                self._collect_context_from_expr(arg)

        elif isinstance(expr, MethodCall):
            method_lower = expr.method_name.lower()
            # Route handler methods: app.get(), router.post(), etc.
            if expr.method_name in ROUTE_HANDLERS:
                self._file_ctx.has_route_handlers = True
                self._file_ctx.route_handler_locations.append(loc)
                self._check_route_is_sensitive(expr, loc)
            # Middleware: app.use(helmet())
            if expr.method_name in MIDDLEWARE_REGISTRATION:
                self._scan_middleware_args_method(expr)
            # Rate limiting as method
            if expr.method_name in RATE_LIMIT_MIDDLEWARE:
                self._file_ctx.has_rate_limit_middleware = True
            # Validation
            if expr.method_name in VALIDATION_LIBRARIES:
                self._file_ctx.has_validation_middleware = True

            self._collect_context_from_expr(expr.obj)
            for arg in expr.args:
                self._collect_context_from_expr(arg)

        elif isinstance(expr, FieldAccess):
            self._collect_context_from_expr(expr.obj)

        elif isinstance(expr, BinaryOp):
            self._collect_context_from_expr(expr.left)
            self._collect_context_from_expr(expr.right)

    def _check_route_is_sensitive(self, expr: Expr, loc: SourceLocation) -> None:
        """Check if a route-defining call targets a sensitive endpoint."""
        # Look for string literal route paths in arguments
        args: List[Expr] = []
        if isinstance(expr, FunctionCall):
            args = expr.args
        elif isinstance(expr, MethodCall):
            args = expr.args

        for arg in args:
            if isinstance(arg, StringLiteral):
                path_lower = arg.value.lower()
                for endpoint in SENSITIVE_ENDPOINTS:
                    if endpoint in path_lower:
                        self._file_ctx.sensitive_endpoint_locations.append(
                            (arg.value, loc)
                        )
                        return

    def _scan_middleware_args(self, expr: FunctionCall) -> None:
        """Check middleware registration arguments for security middleware."""
        for arg in expr.args:
            callee = self._get_callee_name(arg) if isinstance(arg, FunctionCall) else None
            if callee:
                if callee in SECURITY_HEADER_MIDDLEWARE:
                    self._file_ctx.has_security_header_middleware = True
                if callee in RATE_LIMIT_MIDDLEWARE:
                    self._file_ctx.has_rate_limit_middleware = True
                if callee in CORS_CONFIG_FUNCTIONS:
                    self._file_ctx.has_cors_config = True
                if callee in VALIDATION_LIBRARIES:
                    self._file_ctx.has_validation_middleware = True

    def _scan_middleware_args_method(self, expr: MethodCall) -> None:
        """Check method-style middleware registration args."""
        for arg in expr.args:
            callee = self._get_callee_name(arg) if isinstance(arg, FunctionCall) else None
            if callee:
                if callee in SECURITY_HEADER_MIDDLEWARE:
                    self._file_ctx.has_security_header_middleware = True
                if callee in RATE_LIMIT_MIDDLEWARE:
                    self._file_ctx.has_rate_limit_middleware = True
                if callee in CORS_CONFIG_FUNCTIONS:
                    self._file_ctx.has_cors_config = True
                if callee in VALIDATION_LIBRARIES:
                    self._file_ctx.has_validation_middleware = True

    def _scan_graphql_config(self, expr: FunctionCall) -> None:
        """Scan GraphQL server/setup arguments for security config."""
        for arg in expr.args:
            # Look for introspection: false
            if isinstance(arg, FunctionCall):
                name = self._get_callee_name(arg)
                if name and "introspection" in name.lower():
                    # If introspection config is referenced, check for false
                    for inner in arg.args:
                        if isinstance(inner, Identifier) and inner.name.lower() == "false":
                            self._file_ctx.has_graphql_introspection_disabled = True
            # Look for nested FieldAccess or Identifier referencing introspection
            self._scan_graphql_arg_for_introspection(arg)

    def _scan_graphql_arg_for_introspection(self, expr: Expr) -> None:
        """Recursively check for introspection: false in GraphQL config."""
        if isinstance(expr, FieldAccess):
            if expr.field_name.lower() == "introspection":
                # Cannot determine value from AST alone -- presence suggests config
                pass
            self._scan_graphql_arg_for_introspection(expr.obj)
        elif isinstance(expr, BinaryOp):
            # introspection == false
            if isinstance(expr.left, Identifier) and expr.left.name.lower() == "introspection":
                if isinstance(expr.right, Identifier) and expr.right.name.lower() == "false":
                    self._file_ctx.has_graphql_introspection_disabled = True
            self._scan_graphql_arg_for_introspection(expr.left)
            self._scan_graphql_arg_for_introspection(expr.right)

    # ------------------------------------------------------------------
    # Check 1: Missing Security Headers
    # ------------------------------------------------------------------

    def _check_missing_security_headers(self) -> None:
        """File-level check: route handlers present but no security header middleware."""
        if not self._file_ctx.has_route_handlers:
            return
        if self._file_ctx.has_security_header_middleware:
            return

        # There are route handlers but no security header middleware
        loc = (
            self._file_ctx.route_handler_locations[0]
            if self._file_ctx.route_handler_locations
            else SourceLocation(self._program_filename, 0, 0)
        )
        self._emit(
            VulnCategory.MISSING_SECURITY_HEADERS,
            "Missing security headers: this file defines route handlers but does "
            "not use security header middleware (e.g., helmet(), secure_headers). "
            "Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, "
            "Strict-Transport-Security, Referrer-Policy, and Permissions-Policy "
            "should all be set.",
            location=loc,
            details={
                "missing_headers": sorted(REQUIRED_SECURITY_HEADERS),
                "suggestion": (
                    "Add security header middleware: app.use(helmet()) for Express, "
                    "Talisman for Flask, SecurityMiddleware for Django"
                ),
            },
            func_name=self._program_filename,
        )

    # ------------------------------------------------------------------
    # Check 2: CORS Misconfiguration
    # ------------------------------------------------------------------

    def _check_cors_misconfig(self, func: PureFunc | TaskFunc) -> None:
        """Per-function check for permissive CORS configuration."""
        for stmt in func.body:
            self._scan_cors_statement(stmt, func)

    def _scan_cors_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Recursively scan statements for CORS issues."""
        loc = getattr(stmt, 'location', SourceLocation(self._program_filename, 0, 0))

        if isinstance(stmt, ExprStmt):
            self._scan_cors_expr(stmt.expr, func, loc)
        elif isinstance(stmt, LetStmt) and stmt.value:
            self._scan_cors_expr(stmt.value, func, loc)
        elif isinstance(stmt, AssignStmt):
            self._scan_cors_expr(stmt.value, func, loc)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_cors_statement(s, func)
            for s in stmt.else_body:
                self._scan_cors_statement(s, func)
        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._scan_cors_expr(stmt.value, func, loc)

    def _scan_cors_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                        loc: SourceLocation) -> None:
        """Check an expression for CORS misconfigurations."""
        if isinstance(expr, FunctionCall):
            callee_name = self._get_callee_name(expr)

            # Check cors() call with wildcard origin arg
            if callee_name and callee_name in CORS_CONFIG_FUNCTIONS:
                for arg in expr.args:
                    if self._is_wildcard_origin(arg):
                        self._emit(
                            VulnCategory.CORS_MISCONFIGURATION,
                            "Permissive CORS: Access-Control-Allow-Origin set to "
                            "wildcard '*'. This allows any origin to make cross-origin "
                            "requests to this API.",
                            location=loc,
                            details={
                                "suggestion": (
                                    "Restrict to specific trusted origins: "
                                    "cors({ origin: ['https://yourdomain.com'] })"
                                ),
                            },
                            func_name=func.name,
                        )
                    if self._has_credentials_with_wildcard(arg, expr.args):
                        self._emit(
                            VulnCategory.CORS_MISCONFIGURATION,
                            "CORS credentials with wildcard origin: "
                            "Access-Control-Allow-Credentials is true while "
                            "Access-Control-Allow-Origin is '*'. Browsers will "
                            "reject this, but misconfig indicates intent to allow "
                            "credentialed cross-origin requests from anywhere.",
                            location=loc,
                            details={
                                "suggestion": (
                                    "Set specific origin when credentials are enabled"
                                ),
                            },
                            func_name=func.name,
                        )

            # Recurse into args
            for arg in expr.args:
                self._scan_cors_expr(arg, func, loc)

        elif isinstance(expr, MethodCall):
            method_lower = expr.method_name.lower()

            # setHeader('Access-Control-Allow-Origin', '*')
            if method_lower in ("setheader", "set_header", "header", "set",
                                "addheader", "add_header", "writehead"):
                if len(expr.args) >= 2:
                    header_arg = expr.args[0]
                    value_arg = expr.args[1]
                    if isinstance(header_arg, StringLiteral):
                        header_lower = header_arg.value.lower()
                        if header_lower == "access-control-allow-origin":
                            if isinstance(value_arg, StringLiteral) and value_arg.value == "*":
                                self._emit(
                                    VulnCategory.CORS_MISCONFIGURATION,
                                    "Permissive CORS: Access-Control-Allow-Origin "
                                    "header set to wildcard '*'.",
                                    location=loc,
                                    details={
                                        "suggestion": (
                                            "Set to specific trusted origin(s)"
                                        ),
                                    },
                                    func_name=func.name,
                                )
                            # Reflected origin: value comes from request
                            if self._is_reflected_origin(value_arg):
                                self._emit(
                                    VulnCategory.CORS_MISCONFIGURATION,
                                    "Reflected CORS origin: the Origin header from "
                                    "the request is reflected back without validation. "
                                    "This is equivalent to wildcard '*'.",
                                    location=loc,
                                    details={
                                        "suggestion": (
                                            "Validate Origin against an allowlist "
                                            "before reflecting"
                                        ),
                                    },
                                    func_name=func.name,
                                )

            # CORS function called as method
            if expr.method_name in CORS_CONFIG_FUNCTIONS:
                for arg in expr.args:
                    if self._is_wildcard_origin(arg):
                        self._emit(
                            VulnCategory.CORS_MISCONFIGURATION,
                            "Permissive CORS: wildcard origin '*' in CORS "
                            "configuration.",
                            location=loc,
                            details={
                                "suggestion": (
                                    "Restrict to specific trusted origins"
                                ),
                            },
                            func_name=func.name,
                        )

            self._scan_cors_expr(expr.obj, func, loc)
            for arg in expr.args:
                self._scan_cors_expr(arg, func, loc)

        elif isinstance(expr, BinaryOp):
            self._scan_cors_expr(expr.left, func, loc)
            self._scan_cors_expr(expr.right, func, loc)

        elif isinstance(expr, FieldAccess):
            self._scan_cors_expr(expr.obj, func, loc)

    def _is_wildcard_origin(self, expr: Expr) -> bool:
        """Check if an expression is the wildcard origin string '*'."""
        if isinstance(expr, StringLiteral) and expr.value == "*":
            return True
        return False

    def _has_credentials_with_wildcard(self, arg: Expr, all_args: List[Expr]) -> bool:
        """Check if credentials: true co-occurs with wildcard origin."""
        has_wildcard = any(
            isinstance(a, StringLiteral) and a.value == "*" for a in all_args
        )
        if not has_wildcard:
            return False
        # Look for credentials-related identifier or string in args
        for a in all_args:
            if isinstance(a, Identifier) and "credentials" in a.name.lower():
                return True
            if isinstance(a, StringLiteral) and "credentials" in a.value.lower():
                return True
        return False

    def _is_reflected_origin(self, expr: Expr) -> bool:
        """Check if an expression reflects the request Origin header."""
        # Pattern: req.headers.origin, request.header('origin'), getHeader('origin')
        if isinstance(expr, FieldAccess):
            if expr.field_name.lower() == "origin":
                return True
            return self._is_reflected_origin(expr.obj)

        if isinstance(expr, MethodCall):
            if expr.method_name.lower() in ("header", "get_header", "getheader", "get"):
                for arg in expr.args:
                    if isinstance(arg, StringLiteral) and arg.value.lower() == "origin":
                        return True

        if isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee.lower() in ("get_header", "getheader"):
                for arg in expr.args:
                    if isinstance(arg, StringLiteral) and arg.value.lower() == "origin":
                        return True

        return False

    # ------------------------------------------------------------------
    # Check 3: Mass Assignment / Over-posting
    # ------------------------------------------------------------------

    def _check_mass_assignment(self, func: PureFunc | TaskFunc) -> None:
        """Per-function check for mass assignment vulnerabilities."""
        # Track which variables hold raw request body data
        body_vars: Set[str] = set()

        # Check parameters for request body patterns
        for param in func.params:
            pname_lower = param.name.lower()
            if any(pat in pname_lower for pat in REQUEST_BODY_PATTERNS):
                body_vars.add(param.name)

        for stmt in func.body:
            self._scan_mass_assignment_stmt(stmt, func, body_vars)

    def _scan_mass_assignment_stmt(self, stmt: Statement, func: PureFunc | TaskFunc,
                                   body_vars: Set[str]) -> None:
        """Scan a statement for mass assignment patterns."""
        loc = getattr(stmt, 'location', SourceLocation(self._program_filename, 0, 0))

        if isinstance(stmt, LetStmt) and stmt.value:
            # Track: let data = req.body / request.data
            if self._is_request_body_access(stmt.value):
                body_vars.add(stmt.name)
            # Track: let filtered = pick(body, [...])  -- safe
            if self._is_field_allowlist(stmt.value):
                # The result is filtered, so remove from body_vars if assigned
                body_vars.discard(stmt.name)
            # Check: Model.create(req.body)
            self._check_orm_write_with_body(stmt.value, func, body_vars, loc)

        elif isinstance(stmt, ExprStmt):
            self._check_orm_write_with_body(stmt.expr, func, body_vars, loc)

        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                if self._is_request_body_access(stmt.value):
                    body_vars.add(stmt.target.name)
                if self._is_field_allowlist(stmt.value):
                    body_vars.discard(stmt.target.name)
            self._check_orm_write_with_body(stmt.value, func, body_vars, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_mass_assignment_stmt(s, func, body_vars)
            for s in stmt.else_body:
                self._scan_mass_assignment_stmt(s, func, body_vars)

        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._check_orm_write_with_body(stmt.value, func, body_vars, loc)

    def _is_request_body_access(self, expr: Expr) -> bool:
        """Check if expression accesses the request body."""
        if isinstance(expr, FieldAccess):
            if expr.field_name.lower() in REQUEST_BODY_PATTERNS:
                return True
            return self._is_request_body_access(expr.obj)

        if isinstance(expr, MethodCall):
            if expr.method_name.lower() in ("json", "body", "data", "form",
                                             "get_json", "get_data"):
                return True

        if isinstance(expr, Identifier):
            return expr.name.lower() in REQUEST_BODY_PATTERNS

        return False

    def _is_field_allowlist(self, expr: Expr) -> bool:
        """Check if expression applies field allowlisting."""
        if isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee in FIELD_ALLOWLIST_METHODS:
                return True

        if isinstance(expr, MethodCall):
            if expr.method_name in FIELD_ALLOWLIST_METHODS:
                return True

        return False

    def _check_orm_write_with_body(self, expr: Expr, func: PureFunc | TaskFunc,
                                   body_vars: Set[str],
                                   loc: SourceLocation) -> None:
        """Check if ORM write methods receive raw request body."""
        if isinstance(expr, MethodCall):
            if expr.method_name in ORM_WRITE_METHODS:
                for arg in expr.args:
                    if self._expr_references_body(arg, body_vars):
                        self._emit(
                            VulnCategory.MASS_ASSIGNMENT,
                            f"Mass assignment: request body passed directly to "
                            f"'{expr.method_name}()' without field allowlisting. "
                            f"Attackers can set unintended fields (e.g., role, "
                            f"isAdmin, balance).",
                            location=loc,
                            details={
                                "orm_method": expr.method_name,
                                "suggestion": (
                                    "Use explicit field selection: "
                                    "Model.create({ name: body.name, email: body.email })"
                                ),
                            },
                            func_name=func.name,
                        )
                        return

        elif isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee in ORM_WRITE_METHODS:
                for arg in expr.args:
                    if self._expr_references_body(arg, body_vars):
                        self._emit(
                            VulnCategory.MASS_ASSIGNMENT,
                            f"Mass assignment: request body passed directly to "
                            f"'{callee}()' without field allowlisting.",
                            location=loc,
                            details={
                                "orm_method": callee,
                                "suggestion": (
                                    "Use explicit field selection or a DTO"
                                ),
                            },
                            func_name=func.name,
                        )
                        return

            # Recurse into args of non-ORM calls
            for arg in expr.args:
                self._check_orm_write_with_body(arg, func, body_vars, loc)

    def _expr_references_body(self, expr: Expr, body_vars: Set[str]) -> bool:
        """Check if expression references raw request body data."""
        if isinstance(expr, Identifier):
            return expr.name in body_vars

        if isinstance(expr, FieldAccess):
            # req.body, request.data
            if expr.field_name.lower() in REQUEST_BODY_PATTERNS:
                return True
            return self._expr_references_body(expr.obj, body_vars)

        if isinstance(expr, MethodCall):
            if expr.method_name.lower() in ("json", "body", "data", "form"):
                return True

        return False

    # ------------------------------------------------------------------
    # Check 4: Excessive Data Exposure
    # ------------------------------------------------------------------

    def _check_excessive_data_exposure(self, func: PureFunc | TaskFunc) -> None:
        """Per-function check for returning entire objects without filtering."""
        # Track variables that hold raw DB objects (no .select() or serializer)
        raw_db_vars: Set[str] = set()
        # Track variables that have been filtered
        filtered_vars: Set[str] = set()

        for stmt in func.body:
            self._scan_data_exposure_stmt(stmt, func, raw_db_vars, filtered_vars)

    def _scan_data_exposure_stmt(self, stmt: Statement, func: PureFunc | TaskFunc,
                                 raw_db_vars: Set[str],
                                 filtered_vars: Set[str]) -> None:
        """Scan for excessive data exposure patterns."""
        loc = getattr(stmt, 'location', SourceLocation(self._program_filename, 0, 0))

        if isinstance(stmt, LetStmt) and stmt.value:
            # Track DB query results
            if self._is_db_query_result(stmt.value):
                if self._has_field_selection(stmt.value):
                    filtered_vars.add(stmt.name)
                else:
                    raw_db_vars.add(stmt.name)
            # Track serializer/DTO usage
            if self._is_serializer_call(stmt.value):
                filtered_vars.add(stmt.name)

        elif isinstance(stmt, ExprStmt):
            self._check_response_sends_raw(stmt.expr, func, raw_db_vars,
                                           filtered_vars, loc)

        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._check_response_sends_raw(stmt.value, func, raw_db_vars,
                                           filtered_vars, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_data_exposure_stmt(s, func, raw_db_vars, filtered_vars)
            for s in stmt.else_body:
                self._scan_data_exposure_stmt(s, func, raw_db_vars, filtered_vars)

    def _is_db_query_result(self, expr: Expr) -> bool:
        """Check if expression is a database query result."""
        db_methods = {
            "find", "findOne", "find_one", "findById", "find_by_id",
            "findAll", "find_all", "first", "last", "get",
            "query", "execute", "fetch", "fetchOne", "fetch_one",
            "fetchAll", "fetch_all", "all", "filter",
            "objects_get", "objects_filter", "objects_all",
            "from", "select", "where",
        }
        if isinstance(expr, MethodCall):
            return expr.method_name in db_methods
        if isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee:
                return callee in db_methods
        return False

    def _has_field_selection(self, expr: Expr) -> bool:
        """Check if a query expression includes field selection."""
        if isinstance(expr, MethodCall):
            if expr.method_name in FIELD_SELECTION_METHODS:
                return True
            # Check chained methods: Model.find().select('name email')
            return self._has_field_selection(expr.obj)
        return False

    def _is_serializer_call(self, expr: Expr) -> bool:
        """Check if expression uses a serializer/DTO pattern."""
        if isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee:
                for pat in SERIALIZER_PATTERNS:
                    if pat.lower() in callee.lower():
                        return True
        if isinstance(expr, MethodCall):
            for pat in SERIALIZER_PATTERNS:
                if pat.lower() in expr.method_name.lower():
                    return True
        return False

    def _check_response_sends_raw(self, expr: Expr, func: PureFunc | TaskFunc,
                                  raw_db_vars: Set[str], filtered_vars: Set[str],
                                  loc: SourceLocation) -> None:
        """Check if a response method sends raw DB objects."""
        if isinstance(expr, MethodCall):
            if expr.method_name in RESPONSE_METHODS:
                for arg in expr.args:
                    if isinstance(arg, Identifier):
                        name_lower = arg.name.lower()
                        # Direct raw DB var
                        if arg.name in raw_db_vars and arg.name not in filtered_vars:
                            self._emit(
                                VulnCategory.EXCESSIVE_DATA_EXPOSURE,
                                f"Excessive data exposure: raw database object "
                                f"'{arg.name}' sent in API response without field "
                                f"selection. May leak sensitive fields (password "
                                f"hashes, tokens, internal IDs).",
                                location=loc,
                                details={
                                    "variable": arg.name,
                                    "suggestion": (
                                        "Use .select() to pick specific fields, or "
                                        "use a serializer/DTO to control output shape"
                                    ),
                                },
                                func_name=func.name,
                            )
                        # Heuristic: variable named 'user', 'account', etc.
                        # sent without filtering
                        elif name_lower in ("user", "account", "profile",
                                            "admin", "customer", "member"):
                            if arg.name not in filtered_vars:
                                self._emit(
                                    VulnCategory.EXCESSIVE_DATA_EXPOSURE,
                                    f"Potential excessive data exposure: variable "
                                    f"'{arg.name}' sent in response. If this is a "
                                    f"database model, it may contain sensitive fields.",
                                    location=loc,
                                    details={
                                        "variable": arg.name,
                                        "suggestion": (
                                            "Ensure only necessary fields are included "
                                            "in the response (use a serializer or "
                                            "explicit field selection)"
                                        ),
                                    },
                                    func_name=func.name,
                                )

                    # Check for sensitive field names in FieldAccess
                    if isinstance(arg, FieldAccess):
                        if arg.field_name.lower() in SENSITIVE_FIELDS:
                            self._emit(
                                VulnCategory.EXCESSIVE_DATA_EXPOSURE,
                                f"Sensitive field in API response: "
                                f"'{arg.field_name}' is being sent to the client. "
                                f"This field should never appear in API responses.",
                                location=loc,
                                details={
                                    "field": arg.field_name,
                                    "suggestion": (
                                        "Remove this field from the response"
                                    ),
                                },
                                func_name=func.name,
                            )

        elif isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee in RESPONSE_METHODS:
                for arg in expr.args:
                    if isinstance(arg, Identifier) and arg.name in raw_db_vars:
                        if arg.name not in filtered_vars:
                            self._emit(
                                VulnCategory.EXCESSIVE_DATA_EXPOSURE,
                                f"Excessive data exposure: raw database object "
                                f"'{arg.name}' sent via '{callee}()' without "
                                f"field selection.",
                                location=loc,
                                details={
                                    "variable": arg.name,
                                    "suggestion": (
                                        "Select specific fields before responding"
                                    ),
                                },
                                func_name=func.name,
                            )

    # ------------------------------------------------------------------
    # Check 5: Missing Rate Limiting
    # ------------------------------------------------------------------

    def _check_missing_rate_limiting(self) -> None:
        """File-level check: sensitive endpoints without rate limiting."""
        if self._file_ctx.has_rate_limit_middleware:
            return

        if not self._file_ctx.sensitive_endpoint_locations:
            return

        for endpoint_name, loc in self._file_ctx.sensitive_endpoint_locations:
            self._emit(
                VulnCategory.MISSING_RATE_LIMITING,
                f"Missing rate limiting: sensitive endpoint '{endpoint_name}' "
                f"has no rate limiting middleware. Authentication and "
                f"verification endpoints are high-value targets for "
                f"credential stuffing and brute-force attacks.",
                location=loc,
                details={
                    "endpoint": endpoint_name,
                    "suggestion": (
                        "Add rate limiting middleware: "
                        "rateLimit({ windowMs: 15*60*1000, max: 5 }) for Express, "
                        "@Throttle for NestJS, flask-limiter for Flask"
                    ),
                },
                func_name=endpoint_name,
            )

    # ------------------------------------------------------------------
    # Check 6: Insecure HTTP Methods
    # ------------------------------------------------------------------

    def _check_insecure_http_methods(self, func: PureFunc | TaskFunc) -> None:
        """Per-function check for dangerous HTTP method exposure."""
        for stmt in func.body:
            self._scan_http_methods_stmt(stmt, func)

    def _scan_http_methods_stmt(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Scan for insecure HTTP method patterns."""
        loc = getattr(stmt, 'location', SourceLocation(self._program_filename, 0, 0))

        if isinstance(stmt, ExprStmt):
            self._scan_http_methods_expr(stmt.expr, func, loc)
        elif isinstance(stmt, LetStmt) and stmt.value:
            self._scan_http_methods_expr(stmt.value, func, loc)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_http_methods_stmt(s, func)
            for s in stmt.else_body:
                self._scan_http_methods_stmt(s, func)

    def _scan_http_methods_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                                loc: SourceLocation) -> None:
        """Check for dangerous HTTP method patterns in an expression."""
        # TRACE/TRACK method registration
        if isinstance(expr, MethodCall):
            if expr.method_name.lower() in ("trace", "track"):
                self._emit(
                    VulnCategory.INSECURE_HTTP_METHODS,
                    f"Insecure HTTP method: TRACE/TRACK is enabled. These methods "
                    f"can be exploited for Cross-Site Tracing (XST) attacks to "
                    f"steal credentials.",
                    location=loc,
                    details={
                        "method": expr.method_name.upper(),
                        "suggestion": "Disable TRACE and TRACK methods entirely",
                    },
                    func_name=func.name,
                )

            # DELETE without auth check in the same function
            if expr.method_name.lower() == "delete":
                if not self._function_has_auth_check(func):
                    self._emit(
                        VulnCategory.INSECURE_HTTP_METHODS,
                        f"DELETE endpoint without authorization: "
                        f"'{func.name}' handles DELETE requests but has no "
                        f"visible authorization or ownership check.",
                        location=loc,
                        details={
                            "suggestion": (
                                "Add authorization middleware or ownership "
                                "verification before destructive operations"
                            ),
                        },
                        func_name=func.name,
                    )

        elif isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee.lower() in ("trace", "track"):
                self._emit(
                    VulnCategory.INSECURE_HTTP_METHODS,
                    f"Insecure HTTP method: TRACE/TRACK enabled via "
                    f"'{callee}()' registration.",
                    location=loc,
                    details={
                        "method": callee.upper(),
                        "suggestion": "Disable TRACE and TRACK methods entirely",
                    },
                    func_name=func.name,
                )

            # Recurse
            for arg in expr.args:
                self._scan_http_methods_expr(arg, func, loc)

    def _function_has_auth_check(self, func: PureFunc | TaskFunc) -> bool:
        """Check if a function contains any authorization/authentication check."""
        for stmt in func.body:
            if self._stmt_has_auth_check(stmt):
                return True
        return False

    def _stmt_has_auth_check(self, stmt: Statement) -> bool:
        """Recursively check if a statement contains an auth check."""
        if isinstance(stmt, ExprStmt):
            return self._expr_has_auth_check(stmt.expr)
        elif isinstance(stmt, LetStmt) and stmt.value:
            return self._expr_has_auth_check(stmt.value)
        elif isinstance(stmt, IfStmt):
            if self._expr_has_auth_check(stmt.condition):
                return True
            for s in stmt.then_body:
                if self._stmt_has_auth_check(s):
                    return True
            for s in stmt.else_body:
                if self._stmt_has_auth_check(s):
                    return True
        return False

    def _expr_has_auth_check(self, expr: Expr) -> bool:
        """Check if an expression is or contains an auth check."""
        if isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee in AUTH_CHECK_PATTERNS:
                return True
            for arg in expr.args:
                if self._expr_has_auth_check(arg):
                    return True

        elif isinstance(expr, MethodCall):
            if expr.method_name in AUTH_CHECK_PATTERNS:
                return True
            if self._expr_has_auth_check(expr.obj):
                return True
            for arg in expr.args:
                if self._expr_has_auth_check(arg):
                    return True

        elif isinstance(expr, Identifier):
            return expr.name in AUTH_CHECK_PATTERNS

        elif isinstance(expr, BinaryOp):
            return (self._expr_has_auth_check(expr.left) or
                    self._expr_has_auth_check(expr.right))

        elif isinstance(expr, FieldAccess):
            if expr.field_name in AUTH_CHECK_PATTERNS:
                return True
            return self._expr_has_auth_check(expr.obj)

        return False

    # ------------------------------------------------------------------
    # Check 7: GraphQL Security
    # ------------------------------------------------------------------

    def _check_graphql_security(self, func: PureFunc | TaskFunc) -> None:
        """Per-function check for GraphQL security misconfigurations."""
        if not self._file_ctx.has_graphql_setup:
            return

        for stmt in func.body:
            self._scan_graphql_stmt(stmt, func)

    def _scan_graphql_stmt(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Scan for GraphQL security issues in a statement."""
        loc = getattr(stmt, 'location', SourceLocation(self._program_filename, 0, 0))

        if isinstance(stmt, ExprStmt):
            self._scan_graphql_expr(stmt.expr, func, loc)
        elif isinstance(stmt, LetStmt) and stmt.value:
            self._scan_graphql_expr(stmt.value, func, loc)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_graphql_stmt(s, func)
            for s in stmt.else_body:
                self._scan_graphql_stmt(s, func)

    def _scan_graphql_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                           loc: SourceLocation) -> None:
        """Check for GraphQL misconfig in an expression."""
        if isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee in GRAPHQL_SETUP_FUNCTIONS:
                # Check if introspection is disabled
                if not self._file_ctx.has_graphql_introspection_disabled:
                    self._emit(
                        VulnCategory.GRAPHQL_SECURITY,
                        f"GraphQL introspection enabled: the GraphQL server "
                        f"created by '{callee}()' does not disable "
                        f"introspection. In production, introspection exposes "
                        f"the entire schema to attackers.",
                        location=loc,
                        details={
                            "suggestion": (
                                "Set introspection: false in production, or "
                                "use a plugin to disable it conditionally"
                            ),
                        },
                        func_name=func.name,
                    )

                # Check for depth limiting
                if not self._file_ctx.has_graphql_depth_limit:
                    self._emit(
                        VulnCategory.GRAPHQL_SECURITY,
                        f"No GraphQL query depth limiting: the server "
                        f"allows arbitrarily nested queries, enabling "
                        f"denial-of-service via deeply nested requests.",
                        location=loc,
                        details={
                            "suggestion": (
                                "Add depthLimit() validation rule: "
                                "validationRules: [depthLimit(10)]"
                            ),
                        },
                        func_name=func.name,
                    )

                # Check for complexity limiting
                if not self._file_ctx.has_graphql_complexity_limit:
                    self._emit(
                        VulnCategory.GRAPHQL_SECURITY,
                        f"No GraphQL query complexity limiting: the server "
                        f"allows unbounded query cost, enabling "
                        f"denial-of-service via expensive queries.",
                        location=loc,
                        details={
                            "suggestion": (
                                "Add cost analysis: "
                                "validationRules: [costAnalysis({ maximumCost: 1000 })]"
                            ),
                        },
                        func_name=func.name,
                    )

    # ------------------------------------------------------------------
    # Check 8: Missing Request Validation
    # ------------------------------------------------------------------

    def _check_missing_request_validation(self, func: PureFunc | TaskFunc) -> None:
        """Per-function check for unvalidated request input access."""
        # Track whether validation has been observed before body access
        validation_seen = False
        # Track variables that hold validated data
        validated_vars: Set[str] = set()

        for stmt in func.body:
            self._scan_request_validation_stmt(
                stmt, func, validation_seen, validated_vars
            )

    def _scan_request_validation_stmt(self, stmt: Statement,
                                      func: PureFunc | TaskFunc,
                                      validation_seen: bool,
                                      validated_vars: Set[str]) -> None:
        """Scan a statement for unvalidated request body access."""
        loc = getattr(stmt, 'location', SourceLocation(self._program_filename, 0, 0))

        if isinstance(stmt, LetStmt) and stmt.value:
            # Check if this is a validation call
            if self._is_validation_call(stmt.value):
                validated_vars.add(stmt.name)
                return

            # Check if this is a raw JSON.parse without schema validation
            if self._is_raw_parse(stmt.value):
                if stmt.name not in validated_vars:
                    self._emit(
                        VulnCategory.MISSING_REQUEST_VALIDATION,
                        f"Raw JSON/data parsing without schema validation: "
                        f"'{stmt.name}' is assigned from a parse call without "
                        f"subsequent schema validation (Zod, Joi, Pydantic, etc.).",
                        location=loc,
                        details={
                            "variable": stmt.name,
                            "suggestion": (
                                "Parse with schema validation: "
                                "const data = schema.parse(JSON.parse(raw))"
                            ),
                        },
                        func_name=func.name,
                    )

            # Check for direct body field access without prior validation
            if self._accesses_request_field(stmt.value):
                if not self._file_ctx.has_validation_middleware:
                    if stmt.name not in validated_vars:
                        self._emit(
                            VulnCategory.MISSING_REQUEST_VALIDATION,
                            f"Unvalidated request input: accessing request "
                            f"body/params without prior validation in "
                            f"'{func.name}'. No validation middleware or "
                            f"schema validation detected.",
                            location=loc,
                            details={
                                "suggestion": (
                                    "Add input validation before accessing request "
                                    "data: use Zod, Joi, class-validator, Pydantic, etc."
                                ),
                            },
                            func_name=func.name,
                        )

        elif isinstance(stmt, ExprStmt):
            if self._is_validation_call(stmt.expr):
                return

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_request_validation_stmt(s, func, validation_seen,
                                                   validated_vars)
            for s in stmt.else_body:
                self._scan_request_validation_stmt(s, func, validation_seen,
                                                   validated_vars)

    def _is_validation_call(self, expr: Expr) -> bool:
        """Check if an expression is a validation/parsing call."""
        if isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee in VALIDATION_LIBRARIES:
                return True

        if isinstance(expr, MethodCall):
            if expr.method_name in VALIDATION_LIBRARIES:
                return True
            # Chained: schema.parse(), schema.safeParse()
            if expr.method_name in ("parse", "safeParse", "safe_parse",
                                    "validate", "validateSync",
                                    "validate_sync", "check"):
                return True

        return False

    def _is_raw_parse(self, expr: Expr) -> bool:
        """Check if an expression is raw JSON/data parsing."""
        if isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee in RAW_PARSE_FUNCTIONS:
                return True

        if isinstance(expr, MethodCall):
            if expr.method_name in RAW_PARSE_FUNCTIONS:
                return True

        return False

    def _accesses_request_field(self, expr: Expr) -> bool:
        """Check if expression directly accesses request body/params fields."""
        if isinstance(expr, FieldAccess):
            # req.body.field, request.params.id
            if isinstance(expr.obj, FieldAccess):
                parent_field = expr.obj.field_name.lower()
                if parent_field in RAW_BODY_ACCESS:
                    return True
            if expr.field_name.lower() in RAW_BODY_ACCESS:
                return True
            return self._accesses_request_field(expr.obj)

        if isinstance(expr, MethodCall):
            # req.body.get('field')
            if isinstance(expr.obj, FieldAccess):
                if expr.obj.field_name.lower() in RAW_BODY_ACCESS:
                    return True

        return False

    # ------------------------------------------------------------------
    # Check 9: Verbose Error Messages
    # ------------------------------------------------------------------

    def _check_verbose_error_messages(self, func: PureFunc | TaskFunc) -> None:
        """Per-function check for error details leaked to clients."""
        for stmt in func.body:
            self._scan_verbose_errors_stmt(stmt, func)

    def _scan_verbose_errors_stmt(self, stmt: Statement,
                                  func: PureFunc | TaskFunc) -> None:
        """Scan for verbose error message patterns."""
        loc = getattr(stmt, 'location', SourceLocation(self._program_filename, 0, 0))

        if isinstance(stmt, ExprStmt):
            self._scan_verbose_errors_expr(stmt.expr, func, loc)
        elif isinstance(stmt, LetStmt) and stmt.value:
            self._scan_verbose_errors_expr(stmt.value, func, loc)
        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._scan_verbose_errors_expr(stmt.value, func, loc)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_verbose_errors_stmt(s, func)
            for s in stmt.else_body:
                self._scan_verbose_errors_stmt(s, func)

    def _scan_verbose_errors_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                                  loc: SourceLocation) -> None:
        """Check for error detail leakage in response calls."""
        # Pattern: res.json({ error: err.message }), res.send(err.stack)
        if isinstance(expr, MethodCall):
            if expr.method_name in RESPONSE_METHODS:
                for arg in expr.args:
                    if self._is_error_detail_leak(arg):
                        self._emit(
                            VulnCategory.VERBOSE_ERROR_MESSAGES,
                            f"Verbose error message in API response: error "
                            f"details (stack trace, message, or internal info) "
                            f"sent to client via '{expr.method_name}()'. "
                            f"This leaks implementation details to attackers.",
                            location=loc,
                            details={
                                "suggestion": (
                                    "Return a generic error message to the client. "
                                    "Log the full error server-side instead: "
                                    "res.status(500).json({ error: 'Internal server error' })"
                                ),
                            },
                            func_name=func.name,
                        )
                        return

        elif isinstance(expr, FunctionCall):
            callee = self._get_callee_name(expr)
            if callee and callee in RESPONSE_METHODS:
                for arg in expr.args:
                    if self._is_error_detail_leak(arg):
                        self._emit(
                            VulnCategory.VERBOSE_ERROR_MESSAGES,
                            f"Verbose error message: error details sent to "
                            f"client via '{callee}()'.",
                            location=loc,
                            details={
                                "suggestion": (
                                    "Return generic error, log details server-side"
                                ),
                            },
                            func_name=func.name,
                        )
                        return

    def _is_error_detail_leak(self, expr: Expr) -> bool:
        """Check if an expression leaks error internals."""
        # err.message, err.stack, err.stackTrace
        if isinstance(expr, FieldAccess):
            if expr.field_name.lower() in ERROR_EXPOSURE_PATTERNS:
                # Check if the object is error-like
                if isinstance(expr.obj, Identifier):
                    name_lower = expr.obj.name.lower()
                    if any(kw in name_lower for kw in ("err", "error", "ex",
                                                        "exception", "e")):
                        return True
            return self._is_error_detail_leak(expr.obj)

        # err.toString(), err.getMessage()
        if isinstance(expr, MethodCall):
            if expr.method_name.lower() in ("tostring", "getmessage",
                                             "get_message", "getstack",
                                             "get_stack", "to_string",
                                             "format_exc", "format_exception"):
                if isinstance(expr.obj, Identifier):
                    name_lower = expr.obj.name.lower()
                    if any(kw in name_lower for kw in ("err", "error", "ex",
                                                        "exception", "e")):
                        return True

        # Direct error identifier in response args
        if isinstance(expr, Identifier):
            name_lower = expr.name.lower()
            if name_lower in ("stack", "stacktrace", "stack_trace", "traceback"):
                return True

        return False

    # ------------------------------------------------------------------
    # Check 10: Insecure Direct API (debug/admin endpoints)
    # ------------------------------------------------------------------

    def _check_insecure_direct_api(self, func: PureFunc | TaskFunc) -> None:
        """Per-function check for exposed debug/admin endpoints."""
        func_loc = getattr(func, 'location',
                           SourceLocation(self._program_filename, 0, 0))
        func_name_lower = func.name.lower()

        # Check if the function name looks like a debug/admin endpoint
        for debug_pattern in DEBUG_ENDPOINTS:
            if debug_pattern in func_name_lower:
                if not self._function_has_auth_check(func):
                    self._emit(
                        VulnCategory.INSECURE_DIRECT_API,
                        f"Insecure debug/admin endpoint: '{func.name}' "
                        f"appears to be a debug or administrative endpoint "
                        f"with no authentication or IP restriction.",
                        location=func_loc,
                        details={
                            "pattern": debug_pattern,
                            "suggestion": (
                                "Add authentication, IP allowlisting, or remove "
                                "debug endpoints from production builds"
                            ),
                        },
                        func_name=func.name,
                    )
                break

        # Scan for route definitions pointing to debug paths
        for stmt in func.body:
            self._scan_debug_routes_stmt(stmt, func)

    def _scan_debug_routes_stmt(self, stmt: Statement,
                                func: PureFunc | TaskFunc) -> None:
        """Scan for debug/admin route path literals."""
        loc = getattr(stmt, 'location', SourceLocation(self._program_filename, 0, 0))

        if isinstance(stmt, ExprStmt):
            self._scan_debug_routes_expr(stmt.expr, func, loc)
        elif isinstance(stmt, LetStmt) and stmt.value:
            self._scan_debug_routes_expr(stmt.value, func, loc)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_debug_routes_stmt(s, func)
            for s in stmt.else_body:
                self._scan_debug_routes_stmt(s, func)

    def _scan_debug_routes_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                                loc: SourceLocation) -> None:
        """Check for debug path strings in route registrations."""
        if isinstance(expr, (FunctionCall, MethodCall)):
            # Get call name
            call_name = None
            args: List[Expr] = []
            if isinstance(expr, FunctionCall):
                call_name = self._get_callee_name(expr)
                args = expr.args
            else:
                call_name = expr.method_name
                args = expr.args

            if call_name and call_name in ROUTE_HANDLERS:
                for arg in args:
                    if isinstance(arg, StringLiteral):
                        path_lower = arg.value.lower()
                        for debug_pat in DEBUG_ENDPOINTS:
                            if debug_pat in path_lower:
                                if not self._function_has_auth_check(func):
                                    self._emit(
                                        VulnCategory.INSECURE_DIRECT_API,
                                        f"Debug/admin route exposed: "
                                        f"'{arg.value}' is registered as a "
                                        f"route without authentication or IP "
                                        f"restriction.",
                                        location=loc,
                                        details={
                                            "path": arg.value,
                                            "pattern": debug_pat,
                                            "suggestion": (
                                                "Remove in production or add "
                                                "authentication/IP restriction"
                                            ),
                                        },
                                        func_name=func.name,
                                    )
                                break

            # Recurse
            for arg in args:
                self._scan_debug_routes_expr(arg, func, loc)

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _get_callee_name(self, expr: Expr) -> Optional[str]:
        """Extract the callee name from a FunctionCall."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name
        return None

    def _emit(self, category: VulnCategory, message: str,
              location: SourceLocation, details: Dict,
              func_name: str) -> None:
        """Emit a finding with CWE reference and category metadata."""
        cwe = CWE_MAP.get(category, "CWE-16")
        full_details = {
            "category": category.value,
            "cwe": cwe,
            "engine": "API Security",
            **details,
        }
        self.errors.append(contract_error(
            precondition=f"[{cwe}] {message}",
            failing_values=full_details,
            function_signature=func_name,
            location=location,
        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_api_security(program: Program) -> list:
    """Run API security analysis on an AEON program.

    Detects 10 categories of API security vulnerabilities:

    1.  Missing Security Headers (CWE-16)
        No CSP, HSTS, X-Frame-Options, etc. on route-handling files.

    2.  CORS Misconfiguration (CWE-942)
        Wildcard origin, reflected origin, credentials with wildcard.

    3.  Mass Assignment (CWE-915)
        Request body passed directly to ORM create/update.

    4.  Excessive Data Exposure (CWE-200)
        Raw DB objects returned without field selection.

    5.  Missing Rate Limiting (CWE-770)
        Auth/verification endpoints without rate limiting.

    6.  Insecure HTTP Methods (CWE-16)
        TRACE/TRACK enabled, DELETE without authorization.

    7.  GraphQL Security (CWE-16)
        Introspection enabled, no depth/complexity limiting.

    8.  Missing Request Validation (CWE-20)
        Raw body/param access without schema validation.

    9.  Verbose Error Messages (CWE-209)
        Stack traces or DB errors sent to client.

    10. Insecure Direct API (CWE-200)
        Debug/admin endpoints without access control.

    Returns a list of AeonError findings, each with CWE reference,
    category, and actionable fix suggestion.
    """
    analyzer = APISecurityAnalyzer()
    return analyzer.check_program(program)
