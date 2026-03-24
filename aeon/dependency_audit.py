"""AEON Dependency Audit Engine -- Vulnerability Pattern Detection from Source Code.

Detects dependency and version vulnerabilities by analyzing source code patterns
in the AST. This engine cannot read package.json or lockfiles directly, but it
CAN detect risky dependency usage patterns that indicate vulnerable library
versions, deprecated APIs, insecure defaults, and missing security packages.

References:
  CWE-1035: Using Components with Known Vulnerabilities
  https://cwe.mitre.org/data/definitions/1035.html

  CWE-1104: Use of Unmaintained Third-Party Components
  https://cwe.mitre.org/data/definitions/1104.html

  CWE-829: Inclusion of Functionality from Untrusted Control Sphere
  https://cwe.mitre.org/data/definitions/829.html

  CWE-1188: Insecure Default Initialization of Resource
  https://cwe.mitre.org/data/definitions/1188.html

  CWE-693: Protection Mechanism Failure
  https://cwe.mitre.org/data/definitions/693.html

  OWASP Top 10 (2021) A06: Vulnerable and Outdated Components
  https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/

  Pashchenko, I. et al. (2018) "Vulnerable Open Source Dependencies:
  Counting Those That Matter"
  ESEM '18, https://doi.org/10.1145/3239235.3268920

  Decan, A. et al. (2018) "On the Impact of Security Vulnerabilities
  in the npm Package Dependency Network"
  MSR '18, https://doi.org/10.1145/3196398.3196401

Key Theory:

1. KNOWN VULNERABLE API PATTERNS (CWE-1035):
   Code patterns that indicate use of vulnerable library versions or APIs.
   Express without x-powered-by disable, jwt.verify without algorithms,
   yaml.load without SafeLoader, requests with verify=False, lodash.merge
   (prototype pollution pre-4.17.21), moment() (deprecated), deprecated
   Node crypto APIs, deprecated Buffer constructor, unparameterized mysql.

2. DEPRECATED/EOL RUNTIME INDICATORS (CWE-1104):
   Code patterns suggesting old runtime or deprecated lifecycle methods.
   var declarations (pre-ES6), Python 2 patterns (print statement,
   raw_input, xrange), deprecated React lifecycle methods.

3. WILDCARD/UNPINNED IMPORTS (CWE-829):
   Dynamic version loading patterns. importlib.import_module with
   version-unchecked package names.

4. KNOWN INSECURE DEFAULT CONFIGURATIONS (CWE-1188):
   Using libraries with insecure defaults without explicit secure config.
   axios without maxRedirects, cors() without options, helmet imported but
   unused, bcrypt with cost factor < 10, express-session without secure
   options.

5. VENDORED/BUNDLED DEPENDENCIES (CWE-1104):
   Copying library code directly instead of using package manager.
   Large utility functions that match signatures of popular libraries.

6. MISSING SECURITY-CRITICAL PACKAGES (CWE-693):
   Code patterns that should use security packages but don't.
   Route handlers without helmet/CORS, auth code without bcrypt/argon2,
   SQL without prepared statement library.

7. PROTOTYPE POLLUTION-VULNERABLE PATTERNS (cross-reference):
   Object.assign, _.merge, $.extend with deep merge on user input
   indicating potential need for newer library version.

Detects patterns visible in source code AST -- NOT lockfile scanning.
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
# Language Detection — avoid cross-language false positives
# ---------------------------------------------------------------------------

_ELIXIR_EXTENSIONS = frozenset({'.ex', '.exs'})


def _is_elixir_file(program) -> bool:
    """Check if the program's source file is an Elixir file."""
    fn = getattr(program, 'filename', '') or ''
    return any(fn.lower().endswith(ext) for ext in _ELIXIR_EXTENSIONS)


# ---------------------------------------------------------------------------
# Severity Levels
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# CWE References
# ---------------------------------------------------------------------------

CWE_1035 = "CWE-1035: Using Components with Known Vulnerabilities"
CWE_1104 = "CWE-1104: Use of Unmaintained Third-Party Components"
CWE_829 = "CWE-829: Inclusion of Functionality from Untrusted Control Sphere"
CWE_1188 = "CWE-1188: Insecure Default Initialization of Resource"
CWE_693 = "CWE-693: Protection Mechanism Failure"
CWE_1321 = "CWE-1321: Improperly Controlled Modification of Object Prototype Attributes"


# ---------------------------------------------------------------------------
# Finding Categories
# ---------------------------------------------------------------------------

class FindingCategory(Enum):
    VULNERABLE_API = "known_vulnerable_api_pattern"
    DEPRECATED_RUNTIME = "deprecated_eol_runtime_indicator"
    WILDCARD_IMPORT = "wildcard_unpinned_import"
    INSECURE_DEFAULT = "insecure_default_configuration"
    VENDORED_DEPENDENCY = "vendored_bundled_dependency"
    MISSING_SECURITY_PKG = "missing_security_critical_package"
    PROTOTYPE_POLLUTION_PATTERN = "prototype_pollution_vulnerable_pattern"


CATEGORY_CWE: Dict[FindingCategory, str] = {
    FindingCategory.VULNERABLE_API: CWE_1035,
    FindingCategory.DEPRECATED_RUNTIME: CWE_1104,
    FindingCategory.WILDCARD_IMPORT: CWE_829,
    FindingCategory.INSECURE_DEFAULT: CWE_1188,
    FindingCategory.VENDORED_DEPENDENCY: CWE_1104,
    FindingCategory.MISSING_SECURITY_PKG: CWE_693,
    FindingCategory.PROTOTYPE_POLLUTION_PATTERN: CWE_1321,
}

CATEGORY_SEVERITY: Dict[FindingCategory, Severity] = {
    FindingCategory.VULNERABLE_API: Severity.HIGH,
    FindingCategory.DEPRECATED_RUNTIME: Severity.MEDIUM,
    FindingCategory.WILDCARD_IMPORT: Severity.MEDIUM,
    FindingCategory.INSECURE_DEFAULT: Severity.HIGH,
    FindingCategory.VENDORED_DEPENDENCY: Severity.LOW,
    FindingCategory.MISSING_SECURITY_PKG: Severity.HIGH,
    FindingCategory.PROTOTYPE_POLLUTION_PATTERN: Severity.HIGH,
}


# ---------------------------------------------------------------------------
# 1. Known Vulnerable API Patterns (CWE-1035)
# ---------------------------------------------------------------------------

# Functions/methods that are deprecated or known-vulnerable
DEPRECATED_CRYPTO_FUNCTIONS: Set[str] = {
    "createcipher",       # Node crypto.createCipher — deprecated, use createCipheriv
    "createdecipher",     # Node crypto.createDecipher — deprecated, use createDecipheriv
}

DEPRECATED_BUFFER_CONSTRUCTORS: Set[str] = {
    "buffer",             # new Buffer() — deprecated, use Buffer.from() / Buffer.alloc()
}

# moment() usage — deprecated library
DEPRECATED_LIBRARIES: Dict[str, str] = {
    "moment": "moment.js is deprecated and unmaintained. Use dayjs, date-fns, or Temporal API",
}

# lodash functions vulnerable to prototype pollution pre-4.17.21
LODASH_VULNERABLE_METHODS: Set[str] = {
    "merge", "defaultsdeep", "defaultsDeep",
    "mergewith", "mergeWith",
}

LODASH_OBJECT_NAMES: Set[str] = {
    "_", "lodash", "lo",
}

# yaml.load without SafeLoader — PyYAML <6.0 default is unsafe
UNSAFE_YAML_FUNCTIONS: Set[str] = {
    "load",  # yaml.load — needs Loader=SafeLoader
}

YAML_OBJECT_NAMES: Set[str] = {
    "yaml", "pyyaml", "YAML",
}

SAFE_YAML_ARGS: Set[str] = {
    "safeloader", "csafeloader", "baseloader",
    "loader=safeloader", "loader=yaml.safeloader",
    "loader=yaml.csafeloader",
}

# jwt.verify without algorithms parameter — allows alg confusion pre-9.0
JWT_VERIFY_METHODS: Set[str] = {
    "verify",
}

JWT_OBJECT_NAMES: Set[str] = {
    "jwt", "jsonwebtoken", "njwt",
}

# requests.get(url, verify=False) — disabling TLS
TLS_DISABLE_KWARGS: Set[str] = {
    "verify",
}

# mysql.query(sql) without parameterized queries
MYSQL_QUERY_METHODS: Set[str] = {
    "query", "execute",
}

MYSQL_OBJECT_NAMES: Set[str] = {
    "mysql", "connection", "conn", "db", "pool",
}


# ---------------------------------------------------------------------------
# 2. Deprecated/EOL Runtime Indicators (CWE-1104)
# ---------------------------------------------------------------------------

# Python 2 built-in functions
PYTHON2_FUNCTIONS: Set[str] = {
    "raw_input",        # Python 2 only — use input() in Python 3
    "xrange",           # Python 2 only — use range() in Python 3
    "execfile",         # Python 2 only — use exec(open(...).read())
    "unicode",          # Python 2 only — str is unicode in Python 3
    "long",             # Python 2 only — int handles large numbers in Python 3
    "basestring",       # Python 2 only — use str in Python 3
    "reduce",           # Moved to functools.reduce in Python 3
}

# Deprecated React lifecycle methods
DEPRECATED_REACT_METHODS: Set[str] = {
    "componentwillmount",
    "componentwillreceiveprops",
    "componentwillupdate",
}

# Python 2 print statement detection: print "..." pattern
# (In AST terms, this would be a FunctionCall to 'print' with a StringLiteral
#  that starts with a quote — but more reliably, we detect print without parens
#  by looking for ExprStmt containing a FunctionCall to 'print')
# We rely on the adapter to detect this. For AST, we flag other patterns.


# ---------------------------------------------------------------------------
# 3. Insecure Default Configuration Patterns (CWE-1188)
# ---------------------------------------------------------------------------

# bcrypt minimum cost factor
BCRYPT_MIN_COST: int = 10

# Functions that need specific secure arguments
BCRYPT_HASH_FUNCTIONS: Set[str] = {
    "hash", "hashsync", "hashSync",
}

BCRYPT_OBJECT_NAMES: Set[str] = {
    "bcrypt", "bcryptjs",
}

# express-session required secure options
SESSION_REQUIRED_OPTIONS: Set[str] = {
    "resave", "saveuninitialized", "saveUninitialized",
}

# cors() without options — allows all origins
CORS_FUNCTION_NAMES: Set[str] = {
    "cors",
}

# axios without maxRedirects
AXIOS_NAMES: Set[str] = {
    "axios",
}

# helmet() — good if called, bad if imported but never called
HELMET_NAMES: Set[str] = {
    "helmet",
}


# ---------------------------------------------------------------------------
# 4. Vendored Dependency Signatures (CWE-1104)
# ---------------------------------------------------------------------------

# Function names that match well-known library internals when defined locally
VENDORED_SIGNATURES: Dict[str, str] = {
    "clonedeep": "lodash _.cloneDeep",
    "cloneDeep": "lodash _.cloneDeep",
    "debounce": "lodash _.debounce",
    "throttle": "lodash _.throttle",
    "deepmerge": "deepmerge library",
    "deepMerge": "deepmerge library",
    "deepclone": "structured clone / lodash",
    "deepClone": "structured clone / lodash",
    "flattendeep": "lodash _.flattenDeep",
    "flattenDeep": "lodash _.flattenDeep",
    "isequal": "lodash _.isEqual",
    "isEqual": "lodash _.isEqual",
    "camelcase": "lodash _.camelCase / camelcase package",
    "camelCase": "lodash _.camelCase / camelcase package",
    "snakecase": "lodash _.snakeCase",
    "snakeCase": "lodash _.snakeCase",
    "leftpad": "left-pad package",
    "leftPad": "left-pad package",
}

# Minimum body size (number of statements) to flag as vendored
VENDORED_MIN_BODY_SIZE: int = 8


# ---------------------------------------------------------------------------
# 5. Missing Security Package Indicators (CWE-693)
# ---------------------------------------------------------------------------

# Route handler indicators — functions that define HTTP routes
ROUTE_HANDLER_METHODS: Set[str] = {
    "get", "post", "put", "delete", "patch", "use",
    "all", "route", "options", "head",
}

ROUTE_HANDLER_OBJECTS: Set[str] = {
    "app", "router", "server", "express",
}

# Security middleware names
SECURITY_MIDDLEWARE: Set[str] = {
    "helmet", "cors", "csurf", "csrf",
    "ratelimit", "rateLimit", "rate_limit",
    "hpp",  # HTTP parameter pollution
}

# Auth-related function names
AUTH_FUNCTION_PATTERNS: Set[str] = {
    "login", "authenticate", "signin", "signup",
    "register", "resetpassword", "changepassword",
    "verifypassword", "checkpassword", "validatepassword",
}

# Secure password hashing libraries
SECURE_HASH_IMPORTS: Set[str] = {
    "bcrypt", "bcryptjs", "argon2", "scrypt",
    "pbkdf2", "passlib",
}

# SQL-related patterns that need parameterization
SQL_KEYWORDS: Set[str] = {
    "select", "insert", "update", "delete", "drop",
    "create", "alter", "exec", "execute",
}


# ---------------------------------------------------------------------------
# 6. Prototype Pollution Cross-Reference Patterns (CWE-1321)
# ---------------------------------------------------------------------------

# Deep merge functions that are vulnerable when receiving user input
DEEP_MERGE_FUNCTIONS: Set[str] = {
    "assign",          # Object.assign
    "merge",           # _.merge
    "extend",          # $.extend or _.extend
    "defaults",        # _.defaults
    "defaultsdeep",    # _.defaultsDeep
    "defaultsDeep",
}

DEEP_MERGE_OBJECTS: Set[str] = {
    "object", "Object", "_", "lodash", "$", "jQuery", "jquery",
}

# User input indicators — variable names suggesting user-controlled data
USER_INPUT_PATTERNS: Set[str] = {
    "req", "request", "body", "query", "params",
    "input", "data", "payload", "args", "options",
    "user_input", "userinput", "userdata", "user_data",
    "form", "formdata", "form_data",
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


def _callee_name(expr) -> str:
    """Get the string name of a FunctionCall's callee, handling dotted access."""
    if isinstance(expr, FunctionCall):
        if isinstance(expr.callee, Identifier):
            return expr.callee.name
        if isinstance(expr.callee, FieldAccess):
            obj_name = ""
            if isinstance(expr.callee.obj, Identifier):
                obj_name = expr.callee.obj.name
            return f"{obj_name}.{expr.callee.field_name}" if obj_name else expr.callee.field_name
    if isinstance(expr, MethodCall):
        return expr.method_name
    return ""


def _callee_object_name(expr) -> str:
    """Get the object name from a MethodCall or dotted FunctionCall."""
    if isinstance(expr, MethodCall) and isinstance(expr.obj, Identifier):
        return expr.obj.name
    if isinstance(expr, FunctionCall) and isinstance(expr.callee, FieldAccess):
        if isinstance(expr.callee.obj, Identifier):
            return expr.callee.obj.name
    return ""


def _name_matches_any(name: str, patterns: Set[str]) -> bool:
    """Check if a variable name matches any of the given patterns (case-insensitive substring)."""
    name_lower = name.lower()
    return any(p.lower() in name_lower for p in patterns)


def _get_args(expr) -> List[Expr]:
    """Get the argument list from a call expression."""
    if isinstance(expr, FunctionCall):
        return expr.args
    if isinstance(expr, MethodCall):
        return expr.args
    return []


def _has_keyword_arg(args: List[Expr], keyword: str) -> bool:
    """Check if args contain a keyword-style argument matching the given name.

    In AEON AST, keyword arguments appear as BinaryOp with '=' operator
    or as Identifier names that match. This is a heuristic check.
    """
    for arg in args:
        if isinstance(arg, BinaryOp) and arg.op == "=":
            if isinstance(arg.left, Identifier) and arg.left.name.lower() == keyword.lower():
                return True
        # Check for named parameter identifiers
        if isinstance(arg, Identifier) and arg.name.lower() == keyword.lower():
            return True
    return False


def _has_string_arg_matching(args: List[Expr], patterns: Set[str]) -> Optional[StringLiteral]:
    """Check if any argument is a StringLiteral whose value matches any pattern."""
    for arg in args:
        if isinstance(arg, StringLiteral) and arg.value.lower() in {p.lower() for p in patterns}:
            return arg
    return None


def _has_false_kwarg(args: List[Expr], keyword: str) -> bool:
    """Check if args contain keyword=False pattern."""
    for arg in args:
        if isinstance(arg, BinaryOp) and arg.op == "=":
            if isinstance(arg.left, Identifier) and arg.left.name.lower() == keyword.lower():
                if isinstance(arg.right, BoolLiteral) and arg.right.value is False:
                    return True
    return False


def _has_int_arg_below(args: List[Expr], threshold: int) -> Optional[IntLiteral]:
    """Check if any argument is an IntLiteral below the threshold and > 0."""
    for arg in args:
        if isinstance(arg, IntLiteral) and 0 < arg.value < threshold:
            return arg
    return False


def _expr_str(expr: Expr) -> str:
    """Convert an expression to a human-readable string."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, StringLiteral):
        return f'"{expr.value}"'
    if isinstance(expr, IntLiteral):
        return str(expr.value)
    if isinstance(expr, BoolLiteral):
        return str(expr.value)
    if isinstance(expr, FieldAccess):
        return f"{_expr_str(expr.obj)}.{expr.field_name}"
    if isinstance(expr, MethodCall):
        return f"{_expr_str(expr.obj)}.{expr.method_name}()"
    if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
        return f"{expr.callee.name}()"
    return "<expr>"


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

    return results


def _get_target_name(stmt: Statement) -> str:
    """Get the variable name being assigned to in a LetStmt or AssignStmt."""
    if isinstance(stmt, LetStmt):
        return stmt.name
    if isinstance(stmt, AssignStmt) and isinstance(stmt.target, Identifier):
        return stmt.target.name
    return ""


def _function_contains_call(body: List[Statement], names: Set[str]) -> bool:
    """Check if a function body contains a call to any of the named functions/methods."""
    exprs = _collect_all_exprs(body)
    for expr, _ in exprs:
        if isinstance(expr, FunctionCall):
            cname = _callee_name(expr).lower()
            if any(n.lower() in cname for n in names):
                return True
        elif isinstance(expr, MethodCall):
            if expr.method_name.lower() in {n.lower() for n in names}:
                return True
    return False


def _function_contains_import(body: List[Statement], names: Set[str]) -> bool:
    """Check if a function body references any identifier matching the given names."""
    exprs = _collect_all_exprs(body)
    for expr, _ in exprs:
        if isinstance(expr, Identifier) and expr.name.lower() in {n.lower() for n in names}:
            return True
    return False


def _count_var_declarations(stmts: List[Statement]) -> int:
    """Count LetStmt declarations that use 'var' keyword (mutable without const/let)."""
    count = 0
    for stmt in stmts:
        if isinstance(stmt, LetStmt) and stmt.mutable:
            count += 1
        elif isinstance(stmt, IfStmt):
            count += _count_var_declarations(stmt.then_body)
            if stmt.else_body:
                count += _count_var_declarations(stmt.else_body)
        elif isinstance(stmt, WhileStmt):
            count += _count_var_declarations(stmt.body)
    return count


# ---------------------------------------------------------------------------
# Dependency Audit Analyzer
# ---------------------------------------------------------------------------

class DependencyAuditAnalyzer:
    """Analyzes programs for dependency and version vulnerability patterns.

    Scans source-level AST for patterns indicating use of vulnerable library
    versions, deprecated APIs, insecure defaults, and missing security packages.
    """

    def __init__(self):
        self.errors: List[AeonError] = []
        self._function_names: Set[str] = set()
        self._all_identifiers: Set[str] = set()
        self._has_route_handlers: bool = False
        self._has_auth_functions: bool = False
        self._has_sql_patterns: bool = False
        self._has_helmet_import: bool = False
        self._has_helmet_call: bool = False
        self._has_cors_import: bool = False
        self._has_cors_call: bool = False
        self._has_secure_hash_import: bool = False
        self._is_elixir: bool = False

    def check_program(self, program: Program) -> List[AeonError]:
        """Run dependency audit analysis on the entire program."""
        self.errors = []
        self._is_elixir = _is_elixir_file(program)

        # First pass: collect metadata about the program
        self._collect_program_metadata(program)

        # Second pass: analyze each function
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl, program)

        # Third pass: cross-function checks (missing security packages)
        self._check_missing_security_packages(program)

        return self.errors

    # ------------------------------------------------------------------
    # Metadata Collection
    # ------------------------------------------------------------------

    def _collect_program_metadata(self, program: Program) -> None:
        """Collect program-wide metadata for cross-function analysis."""
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._function_names.add(decl.name)
                func_name_lower = decl.name.lower()

                # Check if this function name looks like an auth handler
                if any(p in func_name_lower for p in AUTH_FUNCTION_PATTERNS):
                    self._has_auth_functions = True

                # Scan body for identifiers and patterns
                exprs = _collect_all_exprs(decl.body)
                for expr, stmt in exprs:
                    if isinstance(expr, Identifier):
                        self._all_identifiers.add(expr.name.lower())

                    # Check for route handlers
                    if isinstance(expr, MethodCall):
                        obj_name = ""
                        if isinstance(expr.obj, Identifier):
                            obj_name = expr.obj.name.lower()
                        if (obj_name in ROUTE_HANDLER_OBJECTS and
                                expr.method_name.lower() in ROUTE_HANDLER_METHODS):
                            self._has_route_handlers = True

                    # Check for SQL patterns in string literals
                    if isinstance(expr, StringLiteral):
                        val_lower = expr.value.lower().strip()
                        if any(val_lower.startswith(kw) for kw in SQL_KEYWORDS):
                            self._has_sql_patterns = True

                    # Track helmet/cors imports and calls
                    if isinstance(expr, Identifier):
                        if expr.name.lower() in HELMET_NAMES:
                            self._has_helmet_import = True
                        if expr.name.lower() == "cors":
                            self._has_cors_import = True

                    if isinstance(expr, FunctionCall):
                        cn = _callee_name(expr).lower()
                        if cn in HELMET_NAMES:
                            self._has_helmet_call = True
                        if cn == "cors":
                            self._has_cors_call = True

                    # Track secure hash imports
                    if isinstance(expr, Identifier):
                        if expr.name.lower() in SECURE_HASH_IMPORTS:
                            self._has_secure_hash_import = True

    # ------------------------------------------------------------------
    # Function-level analysis
    # ------------------------------------------------------------------

    def _analyze_function(self, func: PureFunc | TaskFunc,
                          program: Program) -> None:
        """Analyze a function body for dependency vulnerability patterns."""
        for stmt in func.body:
            self._analyze_statement(stmt, func)

        # Check for vendored dependency patterns
        self._check_vendored_dependency(func)

        # Check for deprecated runtime patterns (var declarations)
        self._check_deprecated_runtime_function(func)

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Walk a statement tree, dispatching to category-specific checks."""
        loc = getattr(stmt, 'location', SourceLocation("<dependency-audit>", 0, 0))

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_expr(stmt.value, func, loc, stmt)

        elif isinstance(stmt, AssignStmt):
            self._check_expr(stmt.value, func, loc, stmt)

        elif isinstance(stmt, ExprStmt):
            self._check_expr(stmt.expr, func, loc, stmt)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._check_expr(stmt.value, func, loc, stmt)

        elif isinstance(stmt, IfStmt):
            self._check_expr(stmt.condition, func, loc, stmt)
            for s in stmt.then_body:
                self._analyze_statement(s, func)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._analyze_statement(s, func)

        elif isinstance(stmt, WhileStmt):
            self._check_expr(stmt.condition, func, loc, stmt)
            for s in stmt.body:
                self._analyze_statement(s, func)

    # ------------------------------------------------------------------
    # Expression dispatcher
    # ------------------------------------------------------------------

    def _check_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                    loc: SourceLocation, stmt: Statement) -> None:
        """Run all dependency audit checks against an expression."""
        # Category 1: Known Vulnerable API Patterns
        self._check_vulnerable_api(expr, func, loc, stmt)
        # Category 2: Deprecated/EOL Runtime Indicators
        self._check_deprecated_runtime(expr, func, loc)
        # Category 3: Wildcard/Unpinned Imports
        self._check_wildcard_import(expr, func, loc)
        # Category 4: Insecure Default Configurations
        self._check_insecure_defaults(expr, func, loc, stmt)
        # Category 7: Prototype Pollution-Vulnerable Patterns
        self._check_prototype_pollution_pattern(expr, func, loc, stmt)

        # Recurse into subexpressions
        if isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._check_expr(arg, func, loc, stmt)
        elif isinstance(expr, MethodCall):
            self._check_expr(expr.obj, func, loc, stmt)
            for arg in expr.args:
                self._check_expr(arg, func, loc, stmt)
        elif isinstance(expr, BinaryOp):
            self._check_expr(expr.left, func, loc, stmt)
            self._check_expr(expr.right, func, loc, stmt)
        elif isinstance(expr, FieldAccess):
            self._check_expr(expr.obj, func, loc, stmt)

    # ------------------------------------------------------------------
    # 1. Known Vulnerable API Patterns (CWE-1035)
    # ------------------------------------------------------------------

    def _check_vulnerable_api(self, expr: Expr, func: PureFunc | TaskFunc,
                              loc: SourceLocation, stmt: Statement) -> None:
        """Detect patterns indicating use of vulnerable library versions."""
        cname = _callee_name(expr)
        if not cname:
            return
        cname_lower = cname.lower()
        obj_name = _callee_object_name(expr)
        obj_name_lower = obj_name.lower()
        args = _get_args(expr)

        # --- Express without x-powered-by disable ---
        # Pattern: express() call without subsequent app.disable('x-powered-by')
        if cname_lower == "express" and not args:
            # Check if the same function body contains app.disable('x-powered-by')
            if not _function_contains_call(func.body, {"disable"}):
                self._emit(
                    category=FindingCategory.VULNERABLE_API,
                    message=(
                        "express() called without app.disable('x-powered-by') -- "
                        "Express <4.x leaks server identity via X-Powered-By header, "
                        "aiding targeted attacks"
                    ),
                    func=func,
                    loc=loc,
                    details={
                        "library": "express",
                        "pattern": "missing x-powered-by disable",
                        "fix": "Add app.disable('x-powered-by') or use helmet()",
                    },
                )

        # --- jwt.verify without algorithms parameter ---
        # Pattern: jwt.verify(token, secret) with only 2 args (no options/algorithms)
        if (cname_lower in JWT_VERIFY_METHODS and
                obj_name_lower in JWT_OBJECT_NAMES):
            if len(args) <= 2:
                # Only token and secret, no options object with algorithms
                self._emit(
                    category=FindingCategory.VULNERABLE_API,
                    message=(
                        "jwt.verify() called without 'algorithms' parameter -- "
                        "pre-jsonwebtoken-9.0 allows algorithm confusion attacks "
                        "(CVE-2022-23529). Attacker can switch RS256 to HS256 and "
                        "sign with the public key"
                    ),
                    func=func,
                    loc=loc,
                    severity_override=Severity.CRITICAL,
                    details={
                        "library": "jsonwebtoken",
                        "pattern": "missing algorithms restriction",
                        "fix": "jwt.verify(token, secret, { algorithms: ['RS256'] })",
                    },
                )

        # --- yaml.load without SafeLoader ---
        if (cname_lower in UNSAFE_YAML_FUNCTIONS and
                obj_name_lower in YAML_OBJECT_NAMES):
            has_safe_loader = False
            for arg in args:
                if isinstance(arg, Identifier) and arg.name.lower() in SAFE_YAML_ARGS:
                    has_safe_loader = True
                if isinstance(arg, FieldAccess):
                    full = f"{_expr_str(arg)}".lower()
                    if any(s in full for s in SAFE_YAML_ARGS):
                        has_safe_loader = True
                if isinstance(arg, BinaryOp) and arg.op == "=":
                    if isinstance(arg.left, Identifier) and arg.left.name.lower() == "loader":
                        if isinstance(arg.right, Identifier) and arg.right.name.lower() in {
                            "safeloader", "csafeloader", "baseloader"
                        }:
                            has_safe_loader = True
                        if isinstance(arg.right, FieldAccess):
                            rname = _expr_str(arg.right).lower()
                            if any(s in rname for s in {"safeloader", "csafeloader"}):
                                has_safe_loader = True
            if not has_safe_loader:
                self._emit(
                    category=FindingCategory.VULNERABLE_API,
                    message=(
                        "yaml.load() called without Loader=SafeLoader -- "
                        "PyYAML <6.0 defaults to yaml.FullLoader which allows "
                        "arbitrary Python object instantiation (CVE-2020-1747). "
                        "Attacker-controlled YAML achieves RCE"
                    ),
                    func=func,
                    loc=loc,
                    severity_override=Severity.CRITICAL,
                    details={
                        "library": "PyYAML",
                        "pattern": "unsafe yaml.load default",
                        "fix": "yaml.load(data, Loader=yaml.SafeLoader) or yaml.safe_load(data)",
                    },
                )

        # --- requests.get(url, verify=False) ---
        if (isinstance(expr, (FunctionCall, MethodCall)) and
                cname_lower in {"get", "post", "put", "delete", "patch", "request", "head"}):
            if obj_name_lower in {"requests", "httpx", "urllib3", "session", "sess"}:
                if _has_false_kwarg(args, "verify"):
                    self._emit(
                        category=FindingCategory.VULNERABLE_API,
                        message=(
                            f"{obj_name}.{cname}() called with verify=False -- "
                            "disables TLS certificate validation, enabling "
                            "man-in-the-middle attacks on all data in transit"
                        ),
                        func=func,
                        loc=loc,
                        severity_override=Severity.CRITICAL,
                        details={
                            "library": obj_name,
                            "pattern": "TLS verification disabled",
                            "fix": f"Remove verify=False or set verify='/path/to/ca-bundle.crt'",
                        },
                    )

        # --- lodash.merge / lodash.defaultsDeep (prototype pollution) ---
        if (isinstance(expr, MethodCall) and
                obj_name_lower in LODASH_OBJECT_NAMES and
                cname_lower in {m.lower() for m in LODASH_VULNERABLE_METHODS}):
            self._emit(
                category=FindingCategory.VULNERABLE_API,
                message=(
                    f"{obj_name}.{cname}() -- lodash merge/defaultsDeep is vulnerable "
                    "to prototype pollution in versions prior to 4.17.21 "
                    "(CVE-2020-8203, CVE-2021-23337). Attacker-controlled input "
                    "can modify Object.prototype"
                ),
                func=func,
                loc=loc,
                details={
                    "library": "lodash",
                    "pattern": "prototype pollution-vulnerable method",
                    "fix": "Update lodash >= 4.17.21 or use structuredClone()",
                },
            )

        # --- moment() (deprecated library) ---
        if cname_lower in DEPRECATED_LIBRARIES and not obj_name:
            self._emit(
                category=FindingCategory.VULNERABLE_API,
                message=(
                    f"{cname}() -- {DEPRECATED_LIBRARIES[cname_lower]}. "
                    "Moment.js is in maintenance mode with known ReDoS "
                    "vulnerabilities (CVE-2022-31129) and adds ~300KB to bundles"
                ),
                func=func,
                loc=loc,
                severity_override=Severity.MEDIUM,
                details={
                    "library": cname,
                    "pattern": "deprecated library usage",
                    "fix": "Migrate to dayjs (2KB), date-fns, or Temporal API",
                },
            )

        # --- crypto.createCipher (deprecated) ---
        if cname_lower in DEPRECATED_CRYPTO_FUNCTIONS:
            self._emit(
                category=FindingCategory.VULNERABLE_API,
                message=(
                    f"crypto.{cname}() is deprecated -- uses a weak key derivation "
                    "(MD5 single-pass) and static IV. Replaced by createCipheriv() "
                    "in Node.js 10+. DEP0106"
                ),
                func=func,
                loc=loc,
                details={
                    "library": "node:crypto",
                    "pattern": "deprecated crypto API",
                    "fix": "Use crypto.createCipheriv(algorithm, key, iv) with a random IV",
                },
            )

        # --- new Buffer() (deprecated) ---
        if (cname_lower in DEPRECATED_BUFFER_CONSTRUCTORS and
                isinstance(expr, FunctionCall)):
            # Heuristic: Buffer() as a function call (new Buffer() becomes FunctionCall)
            self._emit(
                category=FindingCategory.VULNERABLE_API,
                message=(
                    "new Buffer() is deprecated (DEP0005) -- subject to "
                    "uninitialized memory exposure when called with a number. "
                    "Attackers can read heap contents"
                ),
                func=func,
                loc=loc,
                details={
                    "library": "node:buffer",
                    "pattern": "deprecated Buffer constructor",
                    "fix": "Use Buffer.from(), Buffer.alloc(), or Buffer.allocUnsafe()",
                },
            )

        # --- mysql.query(sql) without parameterized queries ---
        if (isinstance(expr, MethodCall) and
                cname_lower in MYSQL_QUERY_METHODS and
                obj_name_lower in MYSQL_OBJECT_NAMES):
            # If the first arg is a string literal containing SQL keywords
            # and there's no second arg (parameterized values), flag it
            if args and isinstance(args[0], StringLiteral):
                val_lower = args[0].value.lower().strip()
                if any(val_lower.startswith(kw) for kw in SQL_KEYWORDS):
                    if len(args) < 2:
                        self._emit(
                            category=FindingCategory.VULNERABLE_API,
                            message=(
                                f"{obj_name}.{cname}() with SQL string literal and no "
                                "parameterized values -- pre-mysql2 pattern vulnerable "
                                "to SQL injection. Always use parameterized queries"
                            ),
                            func=func,
                            loc=loc,
                            severity_override=Severity.CRITICAL,
                            details={
                                "library": "mysql",
                                "pattern": "unparameterized SQL query",
                                "fix": f"{obj_name}.{cname}('SELECT ... WHERE id = ?', [id])",
                            },
                        )
            # Also flag string concatenation in SQL (BinaryOp with + containing SQL)
            if args and isinstance(args[0], BinaryOp) and args[0].op == "+":
                if self._expr_contains_sql_keyword(args[0]):
                    self._emit(
                        category=FindingCategory.VULNERABLE_API,
                        message=(
                            f"{obj_name}.{cname}() with string concatenation in SQL -- "
                            "classic SQL injection vector. String building SQL queries "
                            "bypasses all parameterization"
                        ),
                        func=func,
                        loc=loc,
                        severity_override=Severity.CRITICAL,
                        details={
                            "library": "mysql",
                            "pattern": "SQL string concatenation",
                            "fix": "Use parameterized queries with placeholder values",
                        },
                    )

    def _expr_contains_sql_keyword(self, expr: Expr) -> bool:
        """Check if a BinaryOp expression tree contains SQL keywords in string literals."""
        if isinstance(expr, StringLiteral):
            val_lower = expr.value.lower().strip()
            return any(kw in val_lower for kw in SQL_KEYWORDS)
        if isinstance(expr, BinaryOp):
            return (self._expr_contains_sql_keyword(expr.left) or
                    self._expr_contains_sql_keyword(expr.right))
        return False

    # ------------------------------------------------------------------
    # 2. Deprecated/EOL Runtime Indicators (CWE-1104)
    # ------------------------------------------------------------------

    def _check_deprecated_runtime(self, expr: Expr, func: PureFunc | TaskFunc,
                                  loc: SourceLocation) -> None:
        """Detect patterns indicating deprecated or EOL runtimes."""
        cname = _callee_name(expr)
        if not cname:
            return
        cname_lower = cname.lower()

        # --- Python 2 functions ---
        # Skip Python 2 detection entirely for Elixir files (.ex/.exs)
        if not self._is_elixir and cname_lower in PYTHON2_FUNCTIONS:
            # For 'reduce', only flag bare FunctionCalls (e.g., reduce(fn, seq)),
            # NOT method calls like Enum.reduce() or List.reduce() which are
            # valid in other languages.
            if cname_lower == "reduce" and isinstance(expr, MethodCall):
                pass  # Skip — this is a method call, not a bare Python 2 reduce()
            else:
                self._emit(
                    category=FindingCategory.DEPRECATED_RUNTIME,
                    message=(
                        f"{cname}() is a Python 2 built-in -- Python 2 reached "
                        "end-of-life on January 1, 2020. No security patches are "
                        "released. Migrate to Python 3.10+"
                    ),
                    func=func,
                    loc=loc,
                    details={
                        "runtime": "Python 2",
                        "pattern": f"{cname} function",
                        "fix": self._python2_fix(cname_lower),
                    },
                )

        # --- Deprecated React lifecycle methods ---
        if isinstance(expr, MethodCall):
            method_lower = expr.method_name.lower()
            if method_lower in DEPRECATED_REACT_METHODS:
                safe_name = {
                    "componentwillmount": "componentDidMount or useEffect",
                    "componentwillreceiveprops": "getDerivedStateFromProps or useEffect",
                    "componentwillupdate": "getSnapshotBeforeUpdate or useEffect",
                }
                replacement = safe_name.get(method_lower, "modern React hooks")
                self._emit(
                    category=FindingCategory.DEPRECATED_RUNTIME,
                    message=(
                        f"{expr.method_name}() is deprecated since React 16.3 and "
                        f"removed in React 18 (UNSAFE_ prefix required in 16.x). "
                        f"Contains known issues with async rendering"
                    ),
                    func=func,
                    loc=loc,
                    details={
                        "runtime": "React <16.3",
                        "pattern": f"deprecated lifecycle method",
                        "fix": f"Replace with {replacement}",
                    },
                )

    def _check_deprecated_runtime_function(self, func: PureFunc | TaskFunc) -> None:
        """Check function-level deprecated runtime patterns."""
        # --- var declarations (pre-ES6, indicates old Node.js/browser target) ---
        # In AEON AST, LetStmt with mutable=True maps to 'var' in JS/TS.
        # We only flag if the ratio is very high (suggesting ES5 codebase)
        var_count = _count_var_declarations(func.body)
        total_lets = self._count_all_lets(func.body)
        if var_count > 5 and total_lets > 0 and (var_count / total_lets) > 0.8:
            loc = getattr(func, 'location', SourceLocation("<dependency-audit>", 0, 0))
            self._emit(
                category=FindingCategory.DEPRECATED_RUNTIME,
                message=(
                    f"Function '{func.name}' uses {var_count} mutable 'var' declarations "
                    f"out of {total_lets} total -- heavy var usage indicates pre-ES6 "
                    f"codebase targeting Node.js <4.x or IE11. Modern runtimes use "
                    f"const/let exclusively"
                ),
                func=func,
                loc=loc,
                severity_override=Severity.LOW,
                details={
                    "runtime": "pre-ES6 / Node <4",
                    "pattern": "var-heavy declarations",
                    "var_count": str(var_count),
                    "total_declarations": str(total_lets),
                    "fix": "Replace var with const (preferred) or let",
                },
            )

    def _count_all_lets(self, stmts: List[Statement]) -> int:
        """Count all LetStmt declarations recursively."""
        count = 0
        for stmt in stmts:
            if isinstance(stmt, LetStmt):
                count += 1
            elif isinstance(stmt, IfStmt):
                count += self._count_all_lets(stmt.then_body)
                if stmt.else_body:
                    count += self._count_all_lets(stmt.else_body)
            elif isinstance(stmt, WhileStmt):
                count += self._count_all_lets(stmt.body)
        return count

    @staticmethod
    def _python2_fix(func_name: str) -> str:
        """Return the Python 3 equivalent for a Python 2 function."""
        fixes = {
            "raw_input": "Use input() (Python 3 input = Python 2 raw_input)",
            "xrange": "Use range() (Python 3 range is lazy like Python 2 xrange)",
            "execfile": "Use exec(open(file).read())",
            "unicode": "Use str (all strings are unicode in Python 3)",
            "long": "Use int (Python 3 int handles arbitrary precision)",
            "basestring": "Use str",
            "reduce": "Use functools.reduce()",
        }
        return fixes.get(func_name, "Migrate to Python 3.10+")

    # ------------------------------------------------------------------
    # 3. Wildcard/Unpinned Imports (CWE-829)
    # ------------------------------------------------------------------

    def _check_wildcard_import(self, expr: Expr, func: PureFunc | TaskFunc,
                               loc: SourceLocation) -> None:
        """Detect dynamic imports without version checking."""
        cname = _callee_name(expr)
        if not cname:
            return
        cname_lower = cname.lower()
        obj_name = _callee_object_name(expr)
        obj_name_lower = obj_name.lower()
        args = _get_args(expr)

        # importlib.import_module with variable argument
        if (cname_lower == "import_module" and
                obj_name_lower in {"importlib", ""}):
            # Only flag if argument is not a string literal (dynamic)
            if args and not isinstance(args[0], StringLiteral):
                self._emit(
                    category=FindingCategory.WILDCARD_IMPORT,
                    message=(
                        f"importlib.import_module() called with dynamic argument "
                        f"'{_expr_str(args[0])}' -- module resolved at runtime with "
                        f"no version pinning or integrity check. Attacker-controlled "
                        f"module names enable arbitrary code execution"
                    ),
                    func=func,
                    loc=loc,
                    severity_override=Severity.HIGH,
                    details={
                        "pattern": "dynamic module loading without version check",
                        "argument": _expr_str(args[0]),
                        "fix": "Pin to known module names via allowlist, verify version at import time",
                    },
                )

        # __import__ with variable argument
        if cname_lower == "__import__":
            if args and not isinstance(args[0], StringLiteral):
                self._emit(
                    category=FindingCategory.WILDCARD_IMPORT,
                    message=(
                        f"__import__() called with dynamic argument "
                        f"'{_expr_str(args[0])}' -- bypasses static analysis and "
                        f"allows loading arbitrary modules without version control"
                    ),
                    func=func,
                    loc=loc,
                    severity_override=Severity.HIGH,
                    details={
                        "pattern": "dynamic __import__ without version check",
                        "argument": _expr_str(args[0]),
                        "fix": "Use explicit imports or maintain an allowlist of permitted module names",
                    },
                )

        # require() with variable argument (Node.js)
        if cname_lower == "require":
            if args and not isinstance(args[0], StringLiteral):
                self._emit(
                    category=FindingCategory.WILDCARD_IMPORT,
                    message=(
                        f"require() called with dynamic argument "
                        f"'{_expr_str(args[0])}' -- module path resolved at runtime "
                        f"with no version pinning. Enables directory traversal and "
                        f"dependency confusion attacks"
                    ),
                    func=func,
                    loc=loc,
                    details={
                        "pattern": "dynamic require without version check",
                        "argument": _expr_str(args[0]),
                        "fix": "Use static require() with literal strings or dynamic import() with validation",
                    },
                )

    # ------------------------------------------------------------------
    # 4. Insecure Default Configurations (CWE-1188)
    # ------------------------------------------------------------------

    def _check_insecure_defaults(self, expr: Expr, func: PureFunc | TaskFunc,
                                 loc: SourceLocation, stmt: Statement) -> None:
        """Detect libraries used with insecure default configurations."""
        cname = _callee_name(expr)
        if not cname:
            return
        cname_lower = cname.lower()
        obj_name = _callee_object_name(expr)
        obj_name_lower = obj_name.lower()
        args = _get_args(expr)

        # --- cors() without options ---
        if cname_lower in CORS_FUNCTION_NAMES and not args:
            self._emit(
                category=FindingCategory.INSECURE_DEFAULT,
                message=(
                    "cors() called without options -- in some versions this "
                    "defaults to Access-Control-Allow-Origin: * which allows "
                    "any domain to make cross-origin requests, including reading "
                    "authenticated responses"
                ),
                func=func,
                loc=loc,
                details={
                    "library": "cors",
                    "pattern": "permissive CORS default",
                    "fix": "cors({ origin: ['https://yourdomain.com'], credentials: true })",
                },
            )

        # --- bcrypt.hash with low cost factor ---
        if (cname_lower in BCRYPT_HASH_FUNCTIONS and
                obj_name_lower in BCRYPT_OBJECT_NAMES):
            low_cost = _has_int_arg_below(args, BCRYPT_MIN_COST)
            if low_cost:
                self._emit(
                    category=FindingCategory.INSECURE_DEFAULT,
                    message=(
                        f"bcrypt.hash() with cost factor {low_cost.value} -- "
                        f"minimum recommended cost factor is {BCRYPT_MIN_COST}. "
                        f"Low cost factors allow GPU-accelerated brute force at "
                        f"millions of hashes per second"
                    ),
                    func=func,
                    loc=loc,
                    severity_override=Severity.HIGH,
                    details={
                        "library": "bcrypt",
                        "pattern": "low cost factor",
                        "cost_factor": str(low_cost.value),
                        "minimum": str(BCRYPT_MIN_COST),
                        "fix": f"bcrypt.hash(password, {BCRYPT_MIN_COST}) -- use 12+ for high-value targets",
                    },
                )

        # --- express-session without secure options ---
        if cname_lower == "session" or (cname_lower == "session" and
                                         obj_name_lower == "express"):
            # If session is called, check for resave and saveUninitialized
            if args:
                has_resave = False
                has_save_uninit = False
                for arg in args:
                    if isinstance(arg, BinaryOp) and arg.op == "=":
                        if isinstance(arg.left, Identifier):
                            kname = arg.left.name.lower()
                            if kname == "resave":
                                has_resave = True
                            if kname in {"saveuninitialized", "saveuninitialised"}:
                                has_save_uninit = True

                if not has_resave or not has_save_uninit:
                    missing = []
                    if not has_resave:
                        missing.append("resave: false")
                    if not has_save_uninit:
                        missing.append("saveUninitialized: false")
                    self._emit(
                        category=FindingCategory.INSECURE_DEFAULT,
                        message=(
                            f"express-session missing secure options: "
                            f"{', '.join(missing)} -- default values create "
                            f"unnecessary session writes and storage leaks"
                        ),
                        func=func,
                        loc=loc,
                        severity_override=Severity.MEDIUM,
                        details={
                            "library": "express-session",
                            "pattern": "missing session security options",
                            "missing_options": ", ".join(missing),
                            "fix": "session({ resave: false, saveUninitialized: false, "
                                   "secret: process.env.SESSION_SECRET })",
                        },
                    )

        # --- axios without maxRedirects ---
        if (isinstance(expr, MethodCall) and
                obj_name_lower in AXIOS_NAMES and
                cname_lower in {"get", "post", "put", "delete", "patch", "request"}):
            # Check if any argument contains maxRedirects
            has_max_redirects = False
            for arg in args:
                if isinstance(arg, BinaryOp) and arg.op == "=":
                    if isinstance(arg.left, Identifier) and arg.left.name.lower() == "maxredirects":
                        has_max_redirects = True
            if not has_max_redirects and len(args) >= 1:
                # Only flag if there's a config object (2nd arg) without maxRedirects
                # or if making requests without config at all
                self._emit(
                    category=FindingCategory.INSECURE_DEFAULT,
                    message=(
                        f"axios.{cname}() without maxRedirects -- axios follows "
                        f"redirects infinitely by default, enabling redirect loops "
                        f"and SSRF via open redirect chains"
                    ),
                    func=func,
                    loc=loc,
                    severity_override=Severity.MEDIUM,
                    details={
                        "library": "axios",
                        "pattern": "infinite redirect default",
                        "fix": f"axios.{cname}(url, {{ maxRedirects: 5 }})",
                    },
                )

        # --- helmet imported but not called ---
        # (This is checked at program level in _check_missing_security_packages)

    # ------------------------------------------------------------------
    # 5. Vendored/Bundled Dependencies (CWE-1104)
    # ------------------------------------------------------------------

    def _check_vendored_dependency(self, func: PureFunc | TaskFunc) -> None:
        """Detect functions that appear to be vendored copies of library code."""
        func_name_lower = func.name.lower()
        body_size = self._count_statements(func.body)

        if (func_name_lower in {k.lower() for k in VENDORED_SIGNATURES} and
                body_size >= VENDORED_MIN_BODY_SIZE):
            # Find the matching library name
            lib_name = ""
            for sig_name, lib in VENDORED_SIGNATURES.items():
                if sig_name.lower() == func_name_lower:
                    lib_name = lib
                    break

            loc = getattr(func, 'location', SourceLocation("<dependency-audit>", 0, 0))
            self._emit(
                category=FindingCategory.VENDORED_DEPENDENCY,
                message=(
                    f"Function '{func.name}' ({body_size} statements) matches the "
                    f"signature of {lib_name} -- vendored/copied library code misses "
                    f"upstream security patches and bug fixes. Use the package "
                    f"manager version instead"
                ),
                func=func,
                loc=loc,
                severity_override=Severity.LOW,
                details={
                    "function": func.name,
                    "likely_library": lib_name,
                    "body_size": str(body_size),
                    "fix": f"Install {lib_name} via package manager and import it",
                },
            )

    def _count_statements(self, stmts: List[Statement]) -> int:
        """Count total statements recursively."""
        count = len(stmts)
        for stmt in stmts:
            if isinstance(stmt, IfStmt):
                count += self._count_statements(stmt.then_body)
                if stmt.else_body:
                    count += self._count_statements(stmt.else_body)
            elif isinstance(stmt, WhileStmt):
                count += self._count_statements(stmt.body)
        return count

    # ------------------------------------------------------------------
    # 6. Missing Security-Critical Packages (CWE-693)
    # ------------------------------------------------------------------

    def _check_missing_security_packages(self, program: Program) -> None:
        """Detect missing security packages at the program level."""
        # Use a synthetic location for program-level findings
        prog_loc = SourceLocation("<dependency-audit>", 0, 0)

        # Create a dummy func for emission (program-level finding)
        dummy_func = None
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                dummy_func = decl
                break

        if dummy_func is None:
            return

        # --- Route handlers without helmet ---
        if self._has_route_handlers and not self._has_helmet_call:
            if self._has_helmet_import and not self._has_helmet_call:
                self._emit(
                    category=FindingCategory.MISSING_SECURITY_PKG,
                    message=(
                        "helmet is imported but never called -- helmet() must be "
                        "invoked as middleware to set security headers "
                        "(X-Content-Type-Options, X-Frame-Options, CSP, HSTS, etc.)"
                    ),
                    func=dummy_func,
                    loc=prog_loc,
                    severity_override=Severity.HIGH,
                    details={
                        "pattern": "helmet imported but unused",
                        "fix": "app.use(helmet()) -- must be called, not just imported",
                    },
                )
            elif not self._has_helmet_import:
                self._emit(
                    category=FindingCategory.MISSING_SECURITY_PKG,
                    message=(
                        "HTTP route handlers detected without helmet -- responses "
                        "lack critical security headers: X-Content-Type-Options "
                        "(MIME sniffing), X-Frame-Options (clickjacking), "
                        "Strict-Transport-Security (downgrade attacks), CSP (XSS)"
                    ),
                    func=dummy_func,
                    loc=prog_loc,
                    severity_override=Severity.MEDIUM,
                    details={
                        "pattern": "missing helmet middleware",
                        "fix": "npm install helmet && app.use(helmet())",
                    },
                )

        # --- Auth functions without secure hashing ---
        if self._has_auth_functions and not self._has_secure_hash_import:
            self._emit(
                category=FindingCategory.MISSING_SECURITY_PKG,
                message=(
                    "Authentication functions detected without bcrypt/argon2 -- "
                    "password handling code must use a memory-hard hashing function. "
                    "SHA-256/MD5 hashing is brute-forceable at billions/sec on GPUs"
                ),
                func=dummy_func,
                loc=prog_loc,
                details={
                    "pattern": "auth code without secure password hashing",
                    "fix": "npm install bcrypt / pip install bcrypt -- use bcrypt.hash(password, 12)",
                },
            )

        # --- SQL patterns without parameterization library ---
        # (This is a softer signal -- SQL in string literals)
        if self._has_sql_patterns and not self._has_route_handlers:
            # If we see SQL but no web framework, it's likely a script or backend
            # that might not use an ORM. This is informational.
            pass

    # ------------------------------------------------------------------
    # 7. Prototype Pollution-Vulnerable Patterns (CWE-1321)
    # ------------------------------------------------------------------

    def _check_prototype_pollution_pattern(self, expr: Expr,
                                           func: PureFunc | TaskFunc,
                                           loc: SourceLocation,
                                           stmt: Statement) -> None:
        """Detect Object.assign/_.merge/$.extend with user input patterns."""
        cname = _callee_name(expr)
        if not cname:
            return
        cname_lower = cname.lower()
        obj_name = _callee_object_name(expr)
        obj_name_lower = obj_name.lower()
        args = _get_args(expr)

        # Check for deep merge functions on known objects
        if not (cname_lower in {m.lower() for m in DEEP_MERGE_FUNCTIONS} and
                obj_name_lower in {o.lower() for o in DEEP_MERGE_OBJECTS}):
            return

        # Check if any argument looks like user input
        for arg in args:
            arg_name = ""
            if isinstance(arg, Identifier):
                arg_name = arg.name
            elif isinstance(arg, FieldAccess):
                arg_name = _expr_str(arg)
            elif isinstance(arg, MethodCall):
                arg_name = _expr_str(arg)

            if arg_name and _name_matches_any(arg_name, USER_INPUT_PATTERNS):
                self._emit(
                    category=FindingCategory.PROTOTYPE_POLLUTION_PATTERN,
                    message=(
                        f"{obj_name}.{cname}() called with user-controlled argument "
                        f"'{arg_name}' -- deep merge of attacker-controlled objects "
                        f"enables prototype pollution. Polluting Object.prototype can "
                        f"lead to RCE, auth bypass, or DoS"
                    ),
                    func=func,
                    loc=loc,
                    severity_override=Severity.HIGH,
                    details={
                        "function": f"{obj_name}.{cname}",
                        "user_input_arg": arg_name,
                        "pattern": "deep merge with user input",
                        "fix": (
                            "Sanitize input by removing __proto__, constructor, and "
                            "prototype keys before merging, or use Map instead of plain objects"
                        ),
                    },
                )
                break  # One finding per call is sufficient

    # ------------------------------------------------------------------
    # Emission
    # ------------------------------------------------------------------

    def _emit(self, category: FindingCategory, message: str,
              func: PureFunc | TaskFunc, loc: SourceLocation,
              details: Optional[Dict] = None,
              severity_override: Optional[Severity] = None) -> None:
        """Emit a dependency audit finding as an AeonError."""
        severity = severity_override or CATEGORY_SEVERITY[category]
        cwe = CATEGORY_CWE[category]

        finding_details = {
            "category": category.value,
            "severity": severity.value,
            "cwe": cwe,
            "engine": "Dependency Audit",
        }
        if details:
            finding_details.update(details)

        self.errors.append(contract_error(
            precondition=f"Dependency audit ({severity.value}): {message}",
            failing_values=finding_details,
            function_signature=func.name,
            location=loc,
        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_dependency_audit(program: Program) -> list:
    """Run dependency audit analysis on an AEON program.

    Detects source-level patterns that indicate dependency vulnerabilities:
    - Known vulnerable API patterns (CWE-1035): Express, JWT, YAML, lodash,
      moment, deprecated crypto/Buffer, unparameterized SQL
    - Deprecated/EOL runtime indicators (CWE-1104): Python 2 patterns,
      pre-ES6 var usage, deprecated React lifecycles
    - Wildcard/unpinned imports (CWE-829): Dynamic module loading without
      version checking via importlib, __import__, or require
    - Insecure default configurations (CWE-1188): cors(), bcrypt cost,
      express-session options, axios redirects
    - Vendored/bundled dependencies (CWE-1104): Copied library code that
      misses upstream patches
    - Missing security-critical packages (CWE-693): Route handlers without
      helmet/CORS, auth without bcrypt/argon2
    - Prototype pollution patterns (CWE-1321): Object.assign/_.merge with
      user input indicating need for newer library versions

    Args:
        program: An AEON Program AST node.

    Returns:
        A list of AeonError objects, one per finding.

    Note: This engine analyzes AST patterns in source code. It does NOT
    scan lockfiles, package.json, or dependency manifests -- that is a
    separate tool. Focuses on risky dependency usage patterns.
    """
    analyzer = DependencyAuditAnalyzer()
    return analyzer.check_program(program)
