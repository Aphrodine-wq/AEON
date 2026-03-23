"""AEON Race Condition Security Engine -- Security-Relevant Race Condition Detection.

Detects race conditions that have direct security implications: authorization
bypasses, financial double-spends, session hijacking, and data integrity
violations. This is distinct from concurrency.py, which performs generic race
and deadlock detection using lockset analysis. This engine focuses on the
SECURITY IMPACT of race conditions in web applications, APIs, and payment
systems.

Based on:
  Bishop & Dilger (1996) "Checking for Race Conditions in File Accesses"
  Computing Systems 9(2) -- foundational TOCTOU analysis

  Tsyrklevich & Yee (2003) "Dynamic Detection and Prevention of Race
  Conditions in File Accesses"
  USENIX Security '03, https://www.usenix.org/legacy/events/sec03/tech/tsyrklevich.html

  MITRE CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
  https://cwe.mitre.org/data/definitions/367.html

  MITRE CWE-362: Concurrent Execution Using Shared Resource with
  Improper Synchronization ('Race Condition')
  https://cwe.mitre.org/data/definitions/362.html

  Paleari et al. (2008) "A Fistful of Red-Pills: How to Automatically
  Generate Procedures to Detect CPU Emulators"
  WOOT '08 -- race-based detection evasion techniques

  OWASP Race Condition Vulnerability
  https://owasp.org/www-community/vulnerabilities/Race_Condition

Key Theory:

1. TOCTOU IN AUTHORIZATION (CWE-367):
   A check-then-use pattern on authorization state. The permission is
   verified at time T1, but the privileged action occurs at time T2.
   Between T1 and T2, the authorization state can change (role revoked,
   session invalidated, resource ownership transferred). The gap between
   check and use is the exploitation window.

2. DOUBLE-SUBMIT ON PAYMENT (CWE-362):
   Payment endpoints that lack idempotency keys are vulnerable to rapid
   double-submission. If a client sends two identical requests before the
   first completes, both may pass validation and execute. Requires
   idempotency keys, database unique constraints, or optimistic locking.

3. RACE IN BALANCE CHECK (CWE-362):
   Read-check-write patterns on financial state: "if balance >= amount"
   followed by "balance -= amount" without atomicity. Two concurrent
   requests can both read the same balance, both pass the check, and
   both deduct -- resulting in a negative balance (double-spend).

4. CONCURRENT SESSION MANIPULATION (CWE-362):
   Session state modified in API endpoint handlers without session-level
   locking. Concurrent requests from the same user can interleave
   session reads and writes, corrupting session state or bypassing
   step-based workflows (e.g., payment confirmation steps).

5. FILE OPERATION TOCTOU (CWE-367):
   Checking file existence or permissions, then operating on the file
   in a separate system call. An attacker can replace the file (symlink
   attack) between the check and the operation.

6. REGISTRATION RACE (CWE-362):
   User registration that checks for existing email in one query, then
   inserts in another. Two concurrent registrations with the same email
   can both pass the uniqueness check, creating duplicate accounts.
   Requires a database unique constraint or INSERT ... ON CONFLICT.

7. TOKEN/NONCE REUSE (CWE-362):
   One-time tokens (email verification, password reset, OTP) that are
   validated and invalidated in separate database operations. Two
   concurrent requests can both read the token as valid before either
   invalidates it, allowing the token to be used twice.

8. INVENTORY/STOCK RACE (CWE-362):
   Read-check-decrement on quantity fields without atomic operations.
   Two concurrent purchases can both see stock > 0, both pass, and
   both decrement, resulting in negative inventory (overselling).

Detects:
  - TOCTOU in authorization (check permission, then act)
  - Double-submit on payment/bid/order endpoints without idempotency
  - Race in balance check-then-deduct without atomicity
  - Concurrent session manipulation without locking
  - File existence check followed by file operation (TOCTOU)
  - Registration uniqueness check-then-insert without unique constraint
  - Token check-then-invalidate without atomic operation
  - Inventory check-then-decrement without atomic decrement
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
    ForStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Frontend Detection — skip client-side UI components
# ---------------------------------------------------------------------------

_FRONTEND_EXTENSIONS = frozenset({'.tsx', '.jsx', '.vue', '.svelte'})
_REACT_PATTERNS = frozenset({
    'useState', 'useEffect', 'useCallback', 'useMemo', 'useRef', 'useContext',
    'useRouter', 'useNavigate', 'onClick', 'onChange', 'onSubmit',
    'setState', 'setOpen', 'setLoading', 'dispatch', 'toast',
    'className', 'children', 'props', 'createElement',
})


def _is_frontend_file(program):
    """Check if the program's source file is a frontend file."""
    fn = getattr(program, 'filename', '') or ''
    return any(fn.lower().endswith(ext) for ext in _FRONTEND_EXTENSIONS)


def _function_has_react_patterns(func):
    """Check if function body contains React patterns."""
    names: set = set()
    for stmt in getattr(func, 'body', []):
        _collect_names_for_react(stmt, names)
    return bool(names & _REACT_PATTERNS)


def _collect_names_for_react(node, names: set) -> None:
    """Recursively collect all identifier and method names from AST nodes."""
    if isinstance(node, Identifier):
        names.add(node.name)
    elif isinstance(node, MethodCall):
        names.add(node.method_name)
        _collect_names_for_react(node.obj, names)
        for arg in node.args:
            _collect_names_for_react(arg, names)
    elif isinstance(node, FunctionCall):
        _collect_names_for_react(node.callee, names)
        for arg in node.args:
            _collect_names_for_react(arg, names)
    elif isinstance(node, FieldAccess):
        names.add(node.field_name)
        _collect_names_for_react(node.obj, names)
    elif isinstance(node, BinaryOp):
        _collect_names_for_react(node.left, names)
        _collect_names_for_react(node.right, names)
    elif isinstance(node, UnaryOp):
        _collect_names_for_react(node.operand, names)
    elif isinstance(node, ExprStmt):
        _collect_names_for_react(node.expr, names)
    elif isinstance(node, LetStmt):
        if node.value:
            _collect_names_for_react(node.value, names)
    elif isinstance(node, AssignStmt):
        _collect_names_for_react(node.value, names)
    elif isinstance(node, ReturnStmt):
        if node.value:
            _collect_names_for_react(node.value, names)
    elif isinstance(node, IfStmt):
        _collect_names_for_react(node.condition, names)
        for s in node.then_body:
            _collect_names_for_react(s, names)
        for s in getattr(node, 'else_body', []) or []:
            _collect_names_for_react(s, names)
    elif isinstance(node, WhileStmt):
        _collect_names_for_react(node.condition, names)
        for s in node.body:
            _collect_names_for_react(s, names)
    elif isinstance(node, ForStmt):
        _collect_names_for_react(node.iterable, names)
        for s in node.body:
            _collect_names_for_react(s, names)


# ---------------------------------------------------------------------------
# Severity Levels
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# ---------------------------------------------------------------------------
# Finding Data
# ---------------------------------------------------------------------------

@dataclass
class RaceSecurityFinding:
    """A single security-relevant race condition finding."""
    category: str
    cwe: str
    severity: Severity
    message: str
    remediation: str
    function: str
    line: int
    column: int = 0
    file: str = "<unknown>"

    def to_aeon_error(self) -> AeonError:
        return contract_error(
            precondition=(
                f"[{self.severity.value.upper()}] [{self.cwe}] {self.message}"
            ),
            failing_values={
                "engine": "Race Condition Security",
                "category": self.category,
                "cwe": self.cwe,
                "severity": self.severity.value,
                "remediation": self.remediation,
                "function": self.function,
            },
            function_signature=self.function,
            location=SourceLocation(self.file, self.line, self.column),
        )


# ---------------------------------------------------------------------------
# Pattern Constants
# ---------------------------------------------------------------------------

# Authorization check function names (check at time T1).
AUTHZ_CHECK_NAMES: Set[str] = {
    "check_permission", "checkpermission", "has_permission", "haspermission",
    "authorize", "is_authorized", "isauthorized",
    "check_role", "checkrole", "has_role", "hasrole",
    "can_access", "canaccess", "is_allowed", "isallowed",
    "verify_access", "verifyaccess", "require_permission", "requirepermission",
    "check_access", "checkaccess", "is_admin", "isadmin",
    "require_role", "requirerole", "check_ownership", "checkownership",
    "verify_ownership", "verifyownership",
}

# Condition-level authorization keywords (appears in if-condition text).
AUTHZ_CONDITION_KEYWORDS: Set[str] = {
    "authorized", "is_authorized", "isauthorized",
    "has_permission", "haspermission",
    "has_role", "hasrole",
    "is_admin", "isadmin",
    "can_access", "canaccess",
    "is_allowed", "isallowed",
    "permitted", "is_permitted", "ispermitted",
}

# Action function/method names that perform privileged operations (use at T2).
PRIVILEGED_ACTION_NAMES: Set[str] = {
    "delete", "remove", "destroy", "drop",
    "update", "save", "patch", "put",
    "create", "insert", "add",
    "transfer", "send", "execute", "run",
    "grant", "revoke", "assign", "promote",
    "publish", "approve", "reject",
    "write", "modify", "alter",
}

# Payment/financial function patterns (for double-submit detection).
PAYMENT_FUNCTION_PATTERNS: Set[str] = {
    "pay", "charge", "submit_bid", "submitbid",
    "place_order", "placeorder", "process_payment", "processpayment",
    "create_charge", "createcharge", "capture_payment", "capturepayment",
    "execute_payment", "executepayment", "refund",
    "transfer_funds", "transferfunds", "debit", "credit",
    "withdraw", "deposit", "purchase", "checkout",
    "create_transaction", "createtransaction",
    "submit_order", "submitorder",
    "finalize_order", "finalizeorder",
    "complete_purchase", "completepurchase",
}

# Idempotency protection indicators.
IDEMPOTENCY_INDICATORS: Set[str] = {
    "idempotency_key", "idempotencykey", "idempotent_key", "idempotentkey",
    "request_id", "requestid", "transaction_id", "transactionid",
    "unique_constraint", "uniqueconstraint",
    "on_conflict", "onconflict", "on conflict",
    "optimistic_lock", "optimisticlock",
    "version", "etag", "if_match", "ifmatch",
    "lock_version", "lockversion",
    "for_update", "forupdate", "for update",
    "select_for_update", "selectforupdate",
    "compare_and_swap", "compareandswap", "cas",
    "atomic", "serializable",
}

# Financial variable names (for balance race detection).
FINANCIAL_VAR_PATTERNS: Set[str] = {
    "balance", "credit", "credits", "funds", "wallet",
    "account_balance", "accountbalance",
    "available", "available_balance", "availablebalance",
    "amount", "total", "budget", "allowance",
}

# Atomicity protection keywords (wrapping a check-then-modify).
ATOMICITY_KEYWORDS: Set[str] = {
    "transaction", "atomic", "serializable",
    "for_update", "forupdate", "for update",
    "lock", "mutex", "semaphore", "synchronized",
    "with_lock", "withlock", "acquire",
    "begin_transaction", "begintransaction",
    "start_transaction", "starttransaction",
    "compare_and_swap", "compareandswap",
    "atomic_update", "atomicupdate",
}

# Session write patterns.
SESSION_WRITE_PATTERNS: Set[str] = {
    "session.set", "session.put", "session.save",
    "session.update", "session.delete", "session.destroy",
    "session.clear", "session.regenerate",
}

# Session field assignment patterns (object parts).
SESSION_OBJECT_NAMES: Set[str] = {
    "session", "req.session", "request.session",
    "ctx.session", "context.session",
}

# Session locking indicators.
SESSION_LOCK_INDICATORS: Set[str] = {
    "session_lock", "sessionlock",
    "lock_session", "locksession",
    "session.lock", "session.acquire",
    "serialize_session", "serializesession",
    "session_mutex", "sessionmutex",
}

# File existence check functions.
FILE_EXISTS_FUNCTIONS: Set[str] = {
    "file_exists", "fileexists", "exists", "path.exists",
    "os.path.exists", "os.path.isfile", "os.path.isdir",
    "path.isfile", "path.isdir",
    "fs.existssync", "fs.exists", "fs.access",
    "file.exists", "files.exists",
    "stat", "lstat", "access",
    "isfile", "isdir", "is_file", "is_dir",
}

# File operation functions (the "use" after the "check").
FILE_OPERATION_FUNCTIONS: Set[str] = {
    "open", "read", "write", "readfile", "writefile",
    "read_file", "write_file", "readfilesync", "writefilesync",
    "unlink", "remove", "delete", "rename", "move",
    "chmod", "chown", "chgrp",
    "copy", "copyfile", "copy_file",
    "fs.readfile", "fs.writefile", "fs.unlink", "fs.rename",
    "fs.readfilesync", "fs.writefilesync",
    "os.remove", "os.unlink", "os.rename",
    "shutil.copy", "shutil.move",
    "fopen", "fread", "fwrite",
    "create_read_stream", "createreadstream",
    "create_write_stream", "createwritestream",
}

# Atomic file creation patterns (safe alternatives).
ATOMIC_FILE_OPERATIONS: Set[str] = {
    "o_creat", "o_excl", "wx", "ax",
    "open_exclusive", "openexclusive",
    "atomic_write", "atomicwrite",
    "safe_open", "safeopen",
    "tempfile", "mkstemp", "namedtemporaryfile",
    "createwritestream",  # with exclusive flag
}

# Database uniqueness-check patterns (for registration race).
DB_SELECT_FUNCTIONS: Set[str] = {
    "find", "findone", "find_one", "findby", "find_by",
    "select", "query", "get", "getone", "get_one",
    "where", "filter", "count", "exists",
    "find_by_email", "findbyemail",
    "find_by_username", "findbyusername",
    "get_user_by_email", "getuserbyemail",
    "get_user_by_username", "getuserbyusername",
    "lookup", "fetch", "fetchone", "fetch_one",
}

# Database insert functions (the "use" in select-then-insert).
DB_INSERT_FUNCTIONS: Set[str] = {
    "insert", "create", "save", "add",
    "insert_one", "insertone",
    "insert_many", "insertmany",
    "create_user", "createuser",
    "register", "register_user", "registeruser",
    "signup", "sign_up",
}

# Unique constraint indicators (safe alternatives to select-then-insert).
UNIQUE_CONSTRAINT_INDICATORS: Set[str] = {
    "unique", "unique_constraint", "uniqueconstraint",
    "unique_index", "uniqueindex",
    "on_conflict", "onconflict", "on conflict",
    "insert_or_ignore", "insertorignore",
    "insert_or_update", "insertorupdate",
    "upsert", "merge",
    "if_not_exists", "ifnotexists", "if not exists",
    "create_unique", "createunique",
    "add_unique_constraint", "adduniqueconstraint",
}

# Token retrieval patterns (for token reuse race).
TOKEN_GET_PATTERNS: Set[str] = {
    "get_token", "gettoken", "find_token", "findtoken",
    "lookup_token", "lookuptoken", "verify_token", "verifytoken",
    "validate_token", "validatetoken", "check_token", "checktoken",
    "get_otp", "getotp", "verify_otp", "verifyotp",
    "get_nonce", "getnonce", "verify_nonce", "verifynonce",
    "get_reset_token", "getresettoken",
    "find_verification_token", "findverificationtoken",
}

# Token invalidation patterns.
TOKEN_INVALIDATE_PATTERNS: Set[str] = {
    "invalidate_token", "invalidatetoken",
    "delete_token", "deletetoken",
    "revoke_token", "revoketoken",
    "mark_used", "markused",
    "consume_token", "consumetoken",
    "expire_token", "expiretoken",
    "remove_token", "removetoken",
    "invalidate_otp", "invalidateotp",
    "use_token", "usetoken",
    "burn_token", "burntoken",
}

# Atomic token check-and-invalidate patterns (safe alternatives).
ATOMIC_TOKEN_PATTERNS: Set[str] = {
    "find_and_delete", "findanddelete",
    "find_one_and_delete", "findoneanddelete",
    "find_and_modify", "findandmodify",
    "find_one_and_update", "findoneandupdate",
    "update_and_return", "updateandreturn",
    "delete_returning", "deletereturning",
    "compare_and_delete", "compareanddelete",
    "atomic_check_and_invalidate", "atomicheckandinvalidate",
    "claim_token", "claimtoken",
    "atomic_consume", "atomicconsume",
}

# Inventory/stock variable names.
INVENTORY_VAR_PATTERNS: Set[str] = {
    "stock", "inventory", "quantity", "qty",
    "available_stock", "availablestock",
    "stock_count", "stockcount",
    "remaining", "in_stock", "instock",
    "available_quantity", "availablequantity",
    "units", "supply", "capacity",
    "seats", "tickets", "slots",
}

# API endpoint indicators (functions likely to run concurrently).
ENDPOINT_INDICATORS: Tuple[str, ...] = (
    "api_", "route_", "endpoint_",
    "post_", "put_", "patch_", "delete_", "get_",
    "handle_", "serve_", "view_", "action_",
    "_handler", "_endpoint", "_route", "_view",
    "_action", "_controller", "_api",
    "Handler", "Endpoint", "Route", "Controller",
)

ENDPOINT_EXACT_NAMES: Set[str] = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
}

# Registration-related function name patterns.
REGISTRATION_FUNC_PATTERNS: Set[str] = {
    "register", "signup", "sign_up", "create_user", "createuser",
    "create_account", "createaccount", "onboard", "enroll",
}


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _get_loc(node) -> SourceLocation:
    """Extract SourceLocation from an AST node, with fallback."""
    loc = getattr(node, "location", None)
    if loc is not None:
        return loc
    return SourceLocation("<race>", 0, 0)


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


def _callee_name(expr: FunctionCall) -> str:
    """Get the string name of a FunctionCall's callee, handling dotted access."""
    if isinstance(expr.callee, Identifier):
        return expr.callee.name
    if isinstance(expr.callee, FieldAccess):
        obj_name = ""
        if isinstance(expr.callee.obj, Identifier):
            obj_name = expr.callee.obj.name
        return f"{obj_name}.{expr.callee.field_name}" if obj_name else expr.callee.field_name
    return ""


def _call_name(expr: Expr) -> str:
    """Get the callable name from a FunctionCall or MethodCall."""
    if isinstance(expr, FunctionCall):
        return _callee_name(expr)
    if isinstance(expr, MethodCall):
        obj_name = ""
        if isinstance(expr.obj, Identifier):
            obj_name = expr.obj.name
        return f"{obj_name}.{expr.method_name}" if obj_name else expr.method_name
    return ""


def _name_matches_any(name: str, patterns: Set[str]) -> bool:
    """Check if a name matches any pattern (case-insensitive substring)."""
    name_lower = name.lower()
    return any(p in name_lower for p in patterns)


def _name_matches_exact(name: str, patterns: Set[str]) -> bool:
    """Check if a name matches any pattern exactly (case-insensitive)."""
    name_lower = name.lower()
    return name_lower in patterns


def _is_endpoint_function(func: PureFunc | TaskFunc) -> bool:
    """Determine if a function is likely an API endpoint handler."""
    name = func.name
    if name in ENDPOINT_EXACT_NAMES:
        return True
    name_lower = name.lower()
    for indicator in ENDPOINT_INDICATORS:
        if name_lower.startswith(indicator.lower()) or name_lower.endswith(indicator.lower()):
            return True
    # Check parameter names for HTTP handler signatures
    for param in func.params:
        param_name = param.name if hasattr(param, "name") else str(param)
        if param_name.lower() in {"req", "request", "res", "response", "ctx", "context", "conn"}:
            return True
    return False


def _collect_call_names_in_stmts(stmts: List[Statement]) -> Set[str]:
    """Collect all function/method call names from a statement list (non-recursive for block scope)."""
    names: Set[str] = set()
    for stmt in stmts:
        _collect_call_names_stmt(stmt, names)
    return names


def _collect_call_names_stmt(stmt: Statement, names: Set[str]) -> None:
    """Collect call names from a single statement, recursing into blocks."""
    if isinstance(stmt, ExprStmt):
        _collect_call_names_expr(stmt.expr, names)
    elif isinstance(stmt, LetStmt) and stmt.value:
        _collect_call_names_expr(stmt.value, names)
    elif isinstance(stmt, AssignStmt):
        _collect_call_names_expr(stmt.value, names)
    elif isinstance(stmt, ReturnStmt) and stmt.value:
        _collect_call_names_expr(stmt.value, names)
    elif isinstance(stmt, IfStmt):
        _collect_call_names_expr(stmt.condition, names)
        for s in stmt.then_body:
            _collect_call_names_stmt(s, names)
        if stmt.else_body:
            for s in stmt.else_body:
                _collect_call_names_stmt(s, names)
    elif isinstance(stmt, WhileStmt):
        _collect_call_names_expr(stmt.condition, names)
        for s in stmt.body:
            _collect_call_names_stmt(s, names)
    elif isinstance(stmt, ForStmt):
        _collect_call_names_expr(stmt.iterable, names)
        for s in stmt.body:
            _collect_call_names_stmt(s, names)


def _collect_call_names_expr(expr: Expr, names: Set[str]) -> None:
    """Collect all callable names from an expression tree."""
    if isinstance(expr, FunctionCall):
        cname = _callee_name(expr)
        if cname:
            names.add(cname)
        for arg in expr.args:
            _collect_call_names_expr(arg, names)
    elif isinstance(expr, MethodCall):
        mname = _call_name(expr)
        if mname:
            names.add(mname)
        _collect_call_names_expr(expr.obj, names)
        for arg in expr.args:
            _collect_call_names_expr(arg, names)
    elif isinstance(expr, BinaryOp):
        _collect_call_names_expr(expr.left, names)
        _collect_call_names_expr(expr.right, names)
    elif isinstance(expr, UnaryOp):
        _collect_call_names_expr(expr.operand, names)
    elif isinstance(expr, FieldAccess):
        _collect_call_names_expr(expr.obj, names)


def _collect_identifiers_expr(expr: Expr) -> Set[str]:
    """Collect all identifier names referenced in an expression."""
    result: Set[str] = set()
    if isinstance(expr, Identifier):
        result.add(expr.name)
    elif isinstance(expr, BinaryOp):
        result.update(_collect_identifiers_expr(expr.left))
        result.update(_collect_identifiers_expr(expr.right))
    elif isinstance(expr, UnaryOp):
        result.update(_collect_identifiers_expr(expr.operand))
    elif isinstance(expr, FieldAccess):
        result.update(_collect_identifiers_expr(expr.obj))
        result.add(expr.field_name)
    elif isinstance(expr, MethodCall):
        result.update(_collect_identifiers_expr(expr.obj))
        for arg in expr.args:
            result.update(_collect_identifiers_expr(arg))
    elif isinstance(expr, FunctionCall):
        for arg in expr.args:
            result.update(_collect_identifiers_expr(arg))
    return result


def _stmts_contain_atomicity_keyword(stmts: List[Statement]) -> bool:
    """Check if any statement in a block references atomicity constructs."""
    all_names = _collect_call_names_in_stmts(stmts)
    all_names_lower = {n.lower() for n in all_names}
    for keyword in ATOMICITY_KEYWORDS:
        if any(keyword in name for name in all_names_lower):
            return True
    return False


def _function_body_contains(func: PureFunc | TaskFunc, patterns: Set[str]) -> bool:
    """Check if a function's body contains any calls matching the given patterns."""
    all_names = _collect_call_names_in_stmts(func.body)
    for name in all_names:
        if _name_matches_any(name, patterns):
            return True
    return False


def _expr_contains_call_matching(expr: Expr, patterns: Set[str]) -> bool:
    """Check if an expression tree contains any call matching the patterns."""
    names: Set[str] = set()
    _collect_call_names_expr(expr, names)
    for name in names:
        if _name_matches_any(name, patterns):
            return True
    return False


# ---------------------------------------------------------------------------
# Detector: TOCTOU in Authorization
# ---------------------------------------------------------------------------

class AuthzTOCTOUDetector:
    """Detect check-permission-then-act patterns without atomic binding.

    CWE-367: Time-of-check Time-of-use in authorization decisions.
    Pattern: if check_permission(user, resource) then do_action(resource)
    in separate statements where the authorization state can change between
    the check and the use.
    """

    def analyze(self, func: PureFunc | TaskFunc, file: str) -> List[RaceSecurityFinding]:
        findings: List[RaceSecurityFinding] = []
        if not _is_endpoint_function(func):
            return findings
        self._scan_body(func.body, func, file, findings)
        return findings

    def _scan_body(
        self,
        stmts: List[Statement],
        func: PureFunc | TaskFunc,
        file: str,
        findings: List[RaceSecurityFinding],
    ) -> None:
        for stmt in stmts:
            if isinstance(stmt, IfStmt):
                self._check_if_stmt(stmt, func, file, findings)
                # Recurse into nested blocks
                self._scan_body(stmt.then_body, func, file, findings)
                if stmt.else_body:
                    self._scan_body(stmt.else_body, func, file, findings)
            elif isinstance(stmt, WhileStmt):
                self._scan_body(stmt.body, func, file, findings)
            elif isinstance(stmt, ForStmt):
                self._scan_body(stmt.body, func, file, findings)

    def _check_if_stmt(
        self,
        stmt: IfStmt,
        func: PureFunc | TaskFunc,
        file: str,
        findings: List[RaceSecurityFinding],
    ) -> None:
        # Check if the condition involves an authorization call or keyword
        cond_names: Set[str] = set()
        _collect_call_names_expr(stmt.condition, cond_names)
        cond_idents = _collect_identifiers_expr(stmt.condition)

        has_authz_check = False
        for name in cond_names:
            if _name_matches_exact(name, AUTHZ_CHECK_NAMES):
                has_authz_check = True
                break
        if not has_authz_check:
            for ident in cond_idents:
                if ident.lower() in AUTHZ_CONDITION_KEYWORDS:
                    has_authz_check = True
                    break

        if not has_authz_check:
            return

        # Check if the then-body performs a privileged action
        body_names = _collect_call_names_in_stmts(stmt.then_body)
        has_privileged_action = False
        for name in body_names:
            if _name_matches_any(name, PRIVILEGED_ACTION_NAMES):
                has_privileged_action = True
                break

        if not has_privileged_action:
            return

        # Check if the block is wrapped in atomicity (transaction, lock, etc.)
        if _stmts_contain_atomicity_keyword(stmt.then_body):
            return

        loc = _get_loc(stmt)
        findings.append(RaceSecurityFinding(
            category="toctou_authorization",
            cwe="CWE-367",
            severity=Severity.HIGH,
            message=(
                f"TOCTOU in authorization: permission is checked in the condition "
                f"but the privileged action in the body executes in a separate step. "
                f"Between the check and the action, the authorization state could change "
                f"(role revoked, session invalidated, resource ownership transferred)"
            ),
            remediation=(
                "Bind the authorization check and the privileged action atomically. "
                "Use database-level row locks (SELECT ... FOR UPDATE), perform the "
                "permission check inside the same transaction as the action, or use "
                "optimistic concurrency control with version checks at write time."
            ),
            function=func.name,
            line=loc.line,
            column=loc.column,
            file=file,
        ))


# ---------------------------------------------------------------------------
# Detector: Double-Submit on Payment
# ---------------------------------------------------------------------------

class DoubleSubmitDetector:
    """Detect payment/bid/order endpoints without idempotency protection.

    CWE-362: Payment endpoints vulnerable to rapid double-submission.
    """

    def analyze(self, func: PureFunc | TaskFunc, file: str) -> List[RaceSecurityFinding]:
        findings: List[RaceSecurityFinding] = []

        # Check if this function is a payment-related endpoint
        func_name_lower = func.name.lower()
        is_payment_func = _name_matches_any(func.name, PAYMENT_FUNCTION_PATTERNS)

        if not is_payment_func:
            return findings

        # Check if the function uses idempotency protection
        all_names = _collect_call_names_in_stmts(func.body)
        all_text = {n.lower() for n in all_names}
        # Also check variable names in let/assign statements
        var_names = self._collect_var_names(func.body)
        all_text.update(v.lower() for v in var_names)

        has_idempotency = False
        for indicator in IDEMPOTENCY_INDICATORS:
            if any(indicator in text for text in all_text):
                has_idempotency = True
                break

        # Also check for string literals that reference idempotency
        if not has_idempotency:
            has_idempotency = self._has_idempotency_string_literal(func.body)

        if has_idempotency:
            return findings

        loc = _get_loc(func)
        findings.append(RaceSecurityFinding(
            category="double_submit_payment",
            cwe="CWE-362",
            severity=Severity.CRITICAL,
            message=(
                f"Payment/financial endpoint '{func.name}' has no idempotency protection. "
                f"Rapid double-submission (network retry, user double-click, attacker replay) "
                f"can cause duplicate charges, duplicate bids, or duplicate orders"
            ),
            remediation=(
                "Accept an idempotency key from the client and enforce uniqueness in the "
                "database (UNIQUE constraint on idempotency_key). Alternatively, use "
                "optimistic locking with version fields, or database-level unique constraints "
                "on transaction identifiers. For Stripe-like APIs, pass the Idempotency-Key header."
            ),
            function=func.name,
            line=loc.line,
            column=loc.column,
            file=file,
        ))
        return findings

    def _collect_var_names(self, stmts: List[Statement]) -> Set[str]:
        """Collect all variable names from let/assign statements."""
        names: Set[str] = set()
        for stmt in stmts:
            if isinstance(stmt, LetStmt):
                names.add(stmt.name)
            elif isinstance(stmt, AssignStmt) and isinstance(stmt.target, Identifier):
                names.add(stmt.target.name)
            elif isinstance(stmt, IfStmt):
                names.update(self._collect_var_names(stmt.then_body))
                if stmt.else_body:
                    names.update(self._collect_var_names(stmt.else_body))
            elif isinstance(stmt, WhileStmt):
                names.update(self._collect_var_names(stmt.body))
            elif isinstance(stmt, ForStmt):
                names.update(self._collect_var_names(stmt.body))
        return names

    def _has_idempotency_string_literal(self, stmts: List[Statement]) -> bool:
        """Check if any string literal in the body references idempotency."""
        for stmt in stmts:
            if self._stmt_has_idempotency_literal(stmt):
                return True
        return False

    def _stmt_has_idempotency_literal(self, stmt: Statement) -> bool:
        if isinstance(stmt, LetStmt) and stmt.value:
            return self._expr_has_idempotency_literal(stmt.value)
        elif isinstance(stmt, AssignStmt):
            return self._expr_has_idempotency_literal(stmt.value)
        elif isinstance(stmt, ExprStmt):
            return self._expr_has_idempotency_literal(stmt.expr)
        elif isinstance(stmt, ReturnStmt) and stmt.value:
            return self._expr_has_idempotency_literal(stmt.value)
        elif isinstance(stmt, IfStmt):
            if self._expr_has_idempotency_literal(stmt.condition):
                return True
            return (self._has_idempotency_string_literal(stmt.then_body) or
                    (stmt.else_body and self._has_idempotency_string_literal(stmt.else_body)))
        elif isinstance(stmt, WhileStmt):
            return self._has_idempotency_string_literal(stmt.body)
        elif isinstance(stmt, ForStmt):
            return self._has_idempotency_string_literal(stmt.body)
        return False

    def _expr_has_idempotency_literal(self, expr: Expr) -> bool:
        if isinstance(expr, StringLiteral):
            val = expr.value.lower()
            for indicator in IDEMPOTENCY_INDICATORS:
                if indicator in val:
                    return True
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                if self._expr_has_idempotency_literal(arg):
                    return True
        elif isinstance(expr, MethodCall):
            for arg in expr.args:
                if self._expr_has_idempotency_literal(arg):
                    return True
        elif isinstance(expr, BinaryOp):
            return (self._expr_has_idempotency_literal(expr.left) or
                    self._expr_has_idempotency_literal(expr.right))
        return False


# ---------------------------------------------------------------------------
# Detector: Race in Balance Check
# ---------------------------------------------------------------------------

class BalanceRaceDetector:
    """Detect read-check-write on financial variables without atomicity.

    CWE-362: if balance >= amount then balance -= amount without transaction.
    """

    def analyze(self, func: PureFunc | TaskFunc, file: str) -> List[RaceSecurityFinding]:
        findings: List[RaceSecurityFinding] = []
        self._scan_body(func.body, func, file, findings, in_atomic=False)
        return findings

    def _scan_body(
        self,
        stmts: List[Statement],
        func: PureFunc | TaskFunc,
        file: str,
        findings: List[RaceSecurityFinding],
        in_atomic: bool,
    ) -> None:
        # Check if this block is inside an atomicity wrapper
        if not in_atomic:
            in_atomic = _stmts_contain_atomicity_keyword(stmts)

        for stmt in stmts:
            if isinstance(stmt, IfStmt):
                self._check_if_stmt(stmt, func, file, findings, in_atomic)
                self._scan_body(stmt.then_body, func, file, findings, in_atomic)
                if stmt.else_body:
                    self._scan_body(stmt.else_body, func, file, findings, in_atomic)
            elif isinstance(stmt, WhileStmt):
                self._scan_body(stmt.body, func, file, findings, in_atomic)
            elif isinstance(stmt, ForStmt):
                self._scan_body(stmt.body, func, file, findings, in_atomic)

    def _check_if_stmt(
        self,
        stmt: IfStmt,
        func: PureFunc | TaskFunc,
        file: str,
        findings: List[RaceSecurityFinding],
        in_atomic: bool,
    ) -> None:
        if in_atomic:
            return

        # Check if condition reads a financial variable in a comparison
        cond_idents = _collect_identifiers_expr(stmt.condition)
        financial_in_cond: Set[str] = set()
        for ident in cond_idents:
            if _name_matches_any(ident, FINANCIAL_VAR_PATTERNS):
                financial_in_cond.add(ident)

        if not financial_in_cond:
            return

        # Check if the condition is a comparison (>=, >, <=, <, ==)
        if not isinstance(stmt.condition, BinaryOp):
            return
        if stmt.condition.op not in (">=", ">", "<=", "<", "==", "!="):
            return

        # Check if the then-body modifies the same financial variable
        body_writes = self._collect_write_targets(stmt.then_body)
        overlap = financial_in_cond & body_writes

        if not overlap:
            return

        # Already checked in_atomic above; also check then-body specifically
        if _stmts_contain_atomicity_keyword(stmt.then_body):
            return

        for var in overlap:
            loc = _get_loc(stmt)
            findings.append(RaceSecurityFinding(
                category="balance_race",
                cwe="CWE-362",
                severity=Severity.CRITICAL,
                message=(
                    f"Race condition on financial variable '{var}': balance is checked "
                    f"in the condition and modified in the body without atomicity. "
                    f"Two concurrent requests can both read the same balance, both pass "
                    f"the check, and both deduct -- resulting in a double-spend"
                ),
                remediation=(
                    "Wrap the check-and-deduct in a database transaction with row-level "
                    "locking (SELECT ... FOR UPDATE) or use an atomic decrement operation "
                    "(UPDATE ... SET balance = balance - amount WHERE balance >= amount). "
                    "The single UPDATE statement is both the check and the modification, "
                    "eliminating the race window entirely."
                ),
                function=func.name,
                line=loc.line,
                column=loc.column,
                file=file,
            ))

    def _collect_write_targets(self, stmts: List[Statement]) -> Set[str]:
        """Collect variable names that are written to in a statement list."""
        targets: Set[str] = set()
        for stmt in stmts:
            if isinstance(stmt, AssignStmt) and isinstance(stmt.target, Identifier):
                targets.add(stmt.target.name)
            elif isinstance(stmt, ExprStmt):
                # Check for method calls that modify (obj.method(...))
                if isinstance(stmt.expr, MethodCall) and isinstance(stmt.expr.obj, Identifier):
                    if stmt.expr.method_name.lower() in {
                        "set", "update", "save", "subtract", "deduct", "decrement",
                        "add", "increment", "modify",
                    }:
                        targets.add(stmt.expr.obj.name)
            elif isinstance(stmt, IfStmt):
                targets.update(self._collect_write_targets(stmt.then_body))
                if stmt.else_body:
                    targets.update(self._collect_write_targets(stmt.else_body))
            elif isinstance(stmt, WhileStmt):
                targets.update(self._collect_write_targets(stmt.body))
            elif isinstance(stmt, ForStmt):
                targets.update(self._collect_write_targets(stmt.body))
        return targets


# ---------------------------------------------------------------------------
# Detector: Concurrent Session Manipulation
# ---------------------------------------------------------------------------

class SessionRaceDetector:
    """Detect session state modification without synchronization in endpoints.

    CWE-362: Session state modified in concurrent API handlers without locking.
    """

    def analyze(self, func: PureFunc | TaskFunc, file: str) -> List[RaceSecurityFinding]:
        findings: List[RaceSecurityFinding] = []

        if not _is_endpoint_function(func):
            return findings

        # Check if this function modifies session state
        session_writes = self._find_session_writes(func.body)
        if not session_writes:
            return findings

        # Check if there is session locking
        all_names = _collect_call_names_in_stmts(func.body)
        all_names_lower = {n.lower() for n in all_names}
        has_session_lock = False
        for indicator in SESSION_LOCK_INDICATORS:
            if any(indicator in name for name in all_names_lower):
                has_session_lock = True
                break
        # Also check for generic locking around session code
        if not has_session_lock:
            has_session_lock = _stmts_contain_atomicity_keyword(func.body)

        if has_session_lock:
            return findings

        first_write = session_writes[0]
        loc = _get_loc(first_write)
        findings.append(RaceSecurityFinding(
            category="concurrent_session_manipulation",
            cwe="CWE-362",
            severity=Severity.MEDIUM,
            message=(
                f"Session state is modified in endpoint '{func.name}' without session "
                f"locking. Concurrent requests from the same user can interleave session "
                f"reads and writes, corrupting session state or bypassing step-based "
                f"workflows (e.g., multi-step checkout, CSRF token rotation)"
            ),
            remediation=(
                "Use session-level locking (e.g., connect-redis with advisory locks, "
                "database-backed sessions with row locks). Alternatively, design session "
                "mutations to be idempotent or use atomic compare-and-set operations "
                "on session fields."
            ),
            function=func.name,
            line=loc.line,
            column=loc.column,
            file=file,
        ))
        return findings

    def _find_session_writes(self, stmts: List[Statement]) -> List[Statement]:
        """Find statements that write to session state."""
        writes: List[Statement] = []
        for stmt in stmts:
            if self._is_session_write(stmt):
                writes.append(stmt)
            # Recurse into nested blocks
            if isinstance(stmt, IfStmt):
                writes.extend(self._find_session_writes(stmt.then_body))
                if stmt.else_body:
                    writes.extend(self._find_session_writes(stmt.else_body))
            elif isinstance(stmt, WhileStmt):
                writes.extend(self._find_session_writes(stmt.body))
            elif isinstance(stmt, ForStmt):
                writes.extend(self._find_session_writes(stmt.body))
        return writes

    def _is_session_write(self, stmt: Statement) -> bool:
        """Check if a statement writes to session state."""
        # Pattern: session.set(...), session.put(...), etc.
        if isinstance(stmt, ExprStmt):
            name = _call_name(stmt.expr)
            if name and _name_matches_any(name, SESSION_WRITE_PATTERNS):
                return True
            # Pattern: req.session.field = ...
            if isinstance(stmt.expr, MethodCall) and isinstance(stmt.expr.obj, Identifier):
                if stmt.expr.obj.name.lower() in {"session"}:
                    return True

        # Pattern: req.session.field = value
        if isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, FieldAccess):
                obj_name = ""
                if isinstance(stmt.target.obj, Identifier):
                    obj_name = stmt.target.obj.name
                elif isinstance(stmt.target.obj, FieldAccess):
                    # req.session.field -- obj is req.session, field is the target field
                    if isinstance(stmt.target.obj.obj, Identifier):
                        obj_name = f"{stmt.target.obj.obj.name}.{stmt.target.obj.field_name}"
                    else:
                        obj_name = stmt.target.obj.field_name
                if _name_matches_any(obj_name, SESSION_OBJECT_NAMES):
                    return True
                # Also catch: session.xyz = ...
                if obj_name.lower() == "session":
                    return True

        return False


# ---------------------------------------------------------------------------
# Detector: File Operation TOCTOU
# ---------------------------------------------------------------------------

class FileTOCTOUDetector:
    """Detect file existence check followed by file operation.

    CWE-367: if file_exists(path) then read(path) or
             if not exists(path) then write(path).
    """

    def analyze(self, func: PureFunc | TaskFunc, file: str) -> List[RaceSecurityFinding]:
        findings: List[RaceSecurityFinding] = []
        self._scan_body(func.body, func, file, findings)
        return findings

    def _scan_body(
        self,
        stmts: List[Statement],
        func: PureFunc | TaskFunc,
        file: str,
        findings: List[RaceSecurityFinding],
    ) -> None:
        for stmt in stmts:
            if isinstance(stmt, IfStmt):
                self._check_if_stmt(stmt, func, file, findings)
                self._scan_body(stmt.then_body, func, file, findings)
                if stmt.else_body:
                    self._scan_body(stmt.else_body, func, file, findings)
            elif isinstance(stmt, WhileStmt):
                self._scan_body(stmt.body, func, file, findings)
            elif isinstance(stmt, ForStmt):
                self._scan_body(stmt.body, func, file, findings)

    def _check_if_stmt(
        self,
        stmt: IfStmt,
        func: PureFunc | TaskFunc,
        file: str,
        findings: List[RaceSecurityFinding],
    ) -> None:
        # Check if the condition calls a file-exists function
        cond_names: Set[str] = set()
        _collect_call_names_expr(stmt.condition, cond_names)

        has_file_check = False
        for name in cond_names:
            if _name_matches_any(name, FILE_EXISTS_FUNCTIONS):
                has_file_check = True
                break

        if not has_file_check:
            return

        # Check both then and else branches for file operations
        branches = [stmt.then_body]
        if stmt.else_body:
            branches.append(stmt.else_body)

        for branch in branches:
            branch_names = _collect_call_names_in_stmts(branch)
            has_file_op = False
            for name in branch_names:
                if _name_matches_any(name, FILE_OPERATION_FUNCTIONS):
                    has_file_op = True
                    break

            if not has_file_op:
                continue

            # Check for atomic file operations (safe pattern)
            has_atomic = False
            for name in branch_names:
                if _name_matches_any(name, ATOMIC_FILE_OPERATIONS):
                    has_atomic = True
                    break

            if has_atomic:
                continue

            loc = _get_loc(stmt)
            findings.append(RaceSecurityFinding(
                category="file_toctou",
                cwe="CWE-367",
                severity=Severity.MEDIUM,
                message=(
                    f"File TOCTOU: existence check in condition followed by file "
                    f"operation in body. Between the check and the operation, an attacker "
                    f"can replace the file with a symlink (symlink attack) or another "
                    f"process can modify/delete the file"
                ),
                remediation=(
                    "Use atomic file operations instead of check-then-act: "
                    "open(path, 'x') for exclusive create (fails if exists), "
                    "O_CREAT|O_EXCL flags in C, 'wx' flag in Node.js fs. "
                    "For reads, open the file and use the file descriptor/handle -- "
                    "do not re-reference the path after checking."
                ),
                function=func.name,
                line=loc.line,
                column=loc.column,
                file=file,
            ))


# ---------------------------------------------------------------------------
# Detector: Registration Race
# ---------------------------------------------------------------------------

class RegistrationRaceDetector:
    """Detect select-then-insert without unique constraint in registration flows.

    CWE-362: Check email not in DB then INSERT without unique index.
    """

    def analyze(self, func: PureFunc | TaskFunc, file: str) -> List[RaceSecurityFinding]:
        findings: List[RaceSecurityFinding] = []

        # Only check registration-related functions
        func_name_lower = func.name.lower()
        is_registration = _name_matches_any(func.name, REGISTRATION_FUNC_PATTERNS)
        if not is_registration:
            return findings

        # Collect all call names in the function
        all_names = _collect_call_names_in_stmts(func.body)

        has_select = False
        has_insert = False
        for name in all_names:
            if _name_matches_any(name, DB_SELECT_FUNCTIONS):
                has_select = True
            if _name_matches_any(name, DB_INSERT_FUNCTIONS):
                has_insert = True

        if not (has_select and has_insert):
            return findings

        # Check for unique constraint indicators
        all_names_lower = {n.lower() for n in all_names}
        has_unique = False
        for indicator in UNIQUE_CONSTRAINT_INDICATORS:
            if any(indicator in name for name in all_names_lower):
                has_unique = True
                break

        if has_unique:
            return findings

        # Also check string literals for ON CONFLICT, UNIQUE, etc.
        if self._has_unique_constraint_literal(func.body):
            return findings

        loc = _get_loc(func)
        findings.append(RaceSecurityFinding(
            category="registration_race",
            cwe="CWE-362",
            severity=Severity.HIGH,
            message=(
                f"Registration race in '{func.name}': checks if email/username exists "
                f"(SELECT) then inserts (INSERT) without a database unique constraint. "
                f"Two concurrent registrations with the same email can both pass the "
                f"uniqueness check, creating duplicate accounts"
            ),
            remediation=(
                "Add a UNIQUE constraint or UNIQUE INDEX on the email/username column. "
                "Use INSERT ... ON CONFLICT DO NOTHING (PostgreSQL), "
                "INSERT IGNORE (MySQL), or handle the unique violation exception. "
                "The database constraint is the source of truth -- the application-level "
                "check is a convenience, not a guarantee."
            ),
            function=func.name,
            line=loc.line,
            column=loc.column,
            file=file,
        ))
        return findings

    def _has_unique_constraint_literal(self, stmts: List[Statement]) -> bool:
        """Check for string literals referencing unique constraints."""
        for stmt in stmts:
            if isinstance(stmt, LetStmt) and stmt.value:
                if self._expr_has_unique_literal(stmt.value):
                    return True
            elif isinstance(stmt, AssignStmt):
                if self._expr_has_unique_literal(stmt.value):
                    return True
            elif isinstance(stmt, ExprStmt):
                if self._expr_has_unique_literal(stmt.expr):
                    return True
            elif isinstance(stmt, ReturnStmt) and stmt.value:
                if self._expr_has_unique_literal(stmt.value):
                    return True
            elif isinstance(stmt, IfStmt):
                if self._has_unique_constraint_literal(stmt.then_body):
                    return True
                if stmt.else_body and self._has_unique_constraint_literal(stmt.else_body):
                    return True
            elif isinstance(stmt, WhileStmt):
                if self._has_unique_constraint_literal(stmt.body):
                    return True
            elif isinstance(stmt, ForStmt):
                if self._has_unique_constraint_literal(stmt.body):
                    return True
        return False

    def _expr_has_unique_literal(self, expr: Expr) -> bool:
        if isinstance(expr, StringLiteral):
            val = expr.value.lower()
            for indicator in UNIQUE_CONSTRAINT_INDICATORS:
                if indicator in val:
                    return True
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                if self._expr_has_unique_literal(arg):
                    return True
        elif isinstance(expr, MethodCall):
            for arg in expr.args:
                if self._expr_has_unique_literal(arg):
                    return True
        elif isinstance(expr, BinaryOp):
            return (self._expr_has_unique_literal(expr.left) or
                    self._expr_has_unique_literal(expr.right))
        return False


# ---------------------------------------------------------------------------
# Detector: Token/Nonce Reuse
# ---------------------------------------------------------------------------

class TokenReuseDetector:
    """Detect check-then-invalidate on one-time tokens without atomicity.

    CWE-362: get_token -> if valid -> use_token -> invalidate_token
    as separate operations.
    """

    def analyze(self, func: PureFunc | TaskFunc, file: str) -> List[RaceSecurityFinding]:
        findings: List[RaceSecurityFinding] = []

        all_names = _collect_call_names_in_stmts(func.body)

        has_token_get = False
        has_token_invalidate = False
        for name in all_names:
            if _name_matches_any(name, TOKEN_GET_PATTERNS):
                has_token_get = True
            if _name_matches_any(name, TOKEN_INVALIDATE_PATTERNS):
                has_token_invalidate = True

        if not (has_token_get and has_token_invalidate):
            return findings

        # Check for atomic token operations
        has_atomic_token = False
        for name in all_names:
            if _name_matches_any(name, ATOMIC_TOKEN_PATTERNS):
                has_atomic_token = True
                break

        if has_atomic_token:
            return findings

        # Check for general atomicity wrappers
        if _stmts_contain_atomicity_keyword(func.body):
            return findings

        loc = _get_loc(func)
        findings.append(RaceSecurityFinding(
            category="token_nonce_reuse",
            cwe="CWE-362",
            severity=Severity.HIGH,
            message=(
                f"Token reuse race in '{func.name}': one-time token is retrieved and "
                f"invalidated in separate operations. Two concurrent requests can both "
                f"read the token as valid before either invalidates it, allowing the "
                f"token to be used twice (password reset replay, email verification bypass, "
                f"OTP reuse)"
            ),
            remediation=(
                "Use an atomic check-and-invalidate operation: "
                "DELETE ... RETURNING (PostgreSQL), findOneAndDelete (MongoDB), "
                "or UPDATE ... SET used=true WHERE used=false RETURNING. "
                "The single query atomically checks validity and marks the token as used. "
                "If the UPDATE affects 0 rows, the token was already consumed."
            ),
            function=func.name,
            line=loc.line,
            column=loc.column,
            file=file,
        ))
        return findings


# ---------------------------------------------------------------------------
# Detector: Inventory/Stock Race
# ---------------------------------------------------------------------------

class InventoryRaceDetector:
    """Detect read-check-decrement on inventory without atomic operations.

    CWE-362: if stock > 0 then stock -= 1 without atomicity.
    """

    def analyze(self, func: PureFunc | TaskFunc, file: str) -> List[RaceSecurityFinding]:
        findings: List[RaceSecurityFinding] = []
        self._scan_body(func.body, func, file, findings, in_atomic=False)
        return findings

    def _scan_body(
        self,
        stmts: List[Statement],
        func: PureFunc | TaskFunc,
        file: str,
        findings: List[RaceSecurityFinding],
        in_atomic: bool,
    ) -> None:
        if not in_atomic:
            in_atomic = _stmts_contain_atomicity_keyword(stmts)

        for stmt in stmts:
            if isinstance(stmt, IfStmt):
                self._check_if_stmt(stmt, func, file, findings, in_atomic)
                self._scan_body(stmt.then_body, func, file, findings, in_atomic)
                if stmt.else_body:
                    self._scan_body(stmt.else_body, func, file, findings, in_atomic)
            elif isinstance(stmt, WhileStmt):
                self._scan_body(stmt.body, func, file, findings, in_atomic)
            elif isinstance(stmt, ForStmt):
                self._scan_body(stmt.body, func, file, findings, in_atomic)

    def _check_if_stmt(
        self,
        stmt: IfStmt,
        func: PureFunc | TaskFunc,
        file: str,
        findings: List[RaceSecurityFinding],
        in_atomic: bool,
    ) -> None:
        if in_atomic:
            return

        # Check if condition reads an inventory variable in a comparison
        cond_idents = _collect_identifiers_expr(stmt.condition)
        inventory_in_cond: Set[str] = set()
        for ident in cond_idents:
            if _name_matches_any(ident, INVENTORY_VAR_PATTERNS):
                inventory_in_cond.add(ident)

        if not inventory_in_cond:
            return

        # Check for comparison operator
        if not isinstance(stmt.condition, BinaryOp):
            return
        if stmt.condition.op not in (">", ">=", "<", "<=", "==", "!="):
            return

        # Check if the then-body modifies the same variable
        body_writes = self._collect_write_targets(stmt.then_body)
        overlap = inventory_in_cond & body_writes

        if not overlap:
            return

        if _stmts_contain_atomicity_keyword(stmt.then_body):
            return

        for var in overlap:
            loc = _get_loc(stmt)
            findings.append(RaceSecurityFinding(
                category="inventory_race",
                cwe="CWE-362",
                severity=Severity.HIGH,
                message=(
                    f"Inventory race on '{var}': stock/quantity is checked in the condition "
                    f"and decremented in the body without atomicity. Two concurrent purchases "
                    f"can both see stock > 0, both pass, and both decrement -- resulting in "
                    f"overselling (negative inventory)"
                ),
                remediation=(
                    "Use an atomic decrement: "
                    "UPDATE products SET stock = stock - 1 WHERE id = ? AND stock > 0. "
                    "Check the affected row count -- if 0, the item is out of stock. "
                    "This single statement is both the check and the decrement. "
                    "Alternatively, use SELECT ... FOR UPDATE with a transaction."
                ),
                function=func.name,
                line=loc.line,
                column=loc.column,
                file=file,
            ))

    def _collect_write_targets(self, stmts: List[Statement]) -> Set[str]:
        """Collect variable names written to in a statement list."""
        targets: Set[str] = set()
        for stmt in stmts:
            if isinstance(stmt, AssignStmt) and isinstance(stmt.target, Identifier):
                targets.add(stmt.target.name)
            elif isinstance(stmt, ExprStmt):
                if isinstance(stmt.expr, MethodCall) and isinstance(stmt.expr.obj, Identifier):
                    if stmt.expr.method_name.lower() in {
                        "set", "update", "save", "subtract", "decrement",
                        "dec", "deduct", "modify",
                    }:
                        targets.add(stmt.expr.obj.name)
            elif isinstance(stmt, IfStmt):
                targets.update(self._collect_write_targets(stmt.then_body))
                if stmt.else_body:
                    targets.update(self._collect_write_targets(stmt.else_body))
            elif isinstance(stmt, WhileStmt):
                targets.update(self._collect_write_targets(stmt.body))
            elif isinstance(stmt, ForStmt):
                targets.update(self._collect_write_targets(stmt.body))
        return targets


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class RaceConditionSecurityEngine:
    """Full race condition security detection engine.

    Walks the AEON AST and runs all detectors on every function.
    """

    def __init__(self) -> None:
        self.authz_toctou = AuthzTOCTOUDetector()
        self.double_submit = DoubleSubmitDetector()
        self.balance_race = BalanceRaceDetector()
        self.session_race = SessionRaceDetector()
        self.file_toctou = FileTOCTOUDetector()
        self.registration_race = RegistrationRaceDetector()
        self.token_reuse = TokenReuseDetector()
        self.inventory_race = InventoryRaceDetector()

    def analyze(self, program: Program) -> List[RaceSecurityFinding]:
        """Run all race condition security detectors on the program."""
        all_findings: List[RaceSecurityFinding] = []
        file = program.filename

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                all_findings.extend(self._analyze_function(decl, file))

        return all_findings

    def _analyze_function(
        self,
        func: PureFunc | TaskFunc,
        file: str,
    ) -> List[RaceSecurityFinding]:
        """Run all detectors on a single function."""
        findings: List[RaceSecurityFinding] = []

        findings.extend(self.authz_toctou.analyze(func, file))
        findings.extend(self.double_submit.analyze(func, file))
        findings.extend(self.balance_race.analyze(func, file))
        findings.extend(self.session_race.analyze(func, file))
        findings.extend(self.file_toctou.analyze(func, file))
        findings.extend(self.registration_race.analyze(func, file))
        findings.extend(self.token_reuse.analyze(func, file))
        findings.extend(self.inventory_race.analyze(func, file))

        return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_race_conditions(program: Program) -> list:
    """Run security-focused race condition detection on an AEON program.

    Detects race conditions with direct security implications:

    1. TOCTOU in authorization (CWE-367):
       Permission checked then action performed in separate steps.

    2. Double-submit on payment (CWE-362):
       Payment/bid/order endpoints without idempotency keys.

    3. Race in balance check (CWE-362):
       Read-check-write on financial variables without atomicity.

    4. Concurrent session manipulation (CWE-362):
       Session state modified without synchronization in API endpoints.

    5. File operation TOCTOU (CWE-367):
       File existence check followed by file operation.

    6. Registration race (CWE-362):
       Select-then-insert without unique constraint.

    7. Token/nonce reuse (CWE-362):
       One-time tokens checked and invalidated in separate operations.

    8. Inventory/stock race (CWE-362):
       Read-check-decrement without atomic operations.

    Severity levels:
      Critical -- Double-submit payment, balance race (financial impact)
      High     -- TOCTOU authorization, registration race, token reuse,
                  inventory race
      Medium   -- Session manipulation, file TOCTOU

    This is distinct from concurrency.py, which detects generic data races,
    deadlocks, and atomicity violations using lockset analysis. This engine
    focuses on the SECURITY IMPACT of race conditions.

    Args:
        program: An AEON Program AST node.

    Returns:
        A list of AeonError objects, one per finding.
    """
    engine = RaceConditionSecurityEngine()
    findings = engine.analyze(program)

    errors: List[AeonError] = []
    for finding in findings:
        errors.append(finding.to_aeon_error())

    return errors
