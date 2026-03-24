"""AEON Business Logic Security Engine — Detects Business Logic Vulnerabilities.

Catches flaws in application-level logic that bypass traditional input validation
and access control checks. Business logic vulnerabilities are among the hardest
to detect automatically because they depend on the intended behavior of the
application rather than on syntactic patterns alone. This engine uses heuristic
pattern matching on function names, parameter names, control flow structure, and
call sequences to identify likely violations.

Based on:
  OWASP (2021) "Business Logic Vulnerabilities"
  https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability

  OWASP Testing Guide v4.2 — Testing for Business Logic
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/

  Grossman (2007) "Seven Business Logic Flaws That Put Your Website at Risk"
  WhiteHat Security Technical Paper

  Anderson (2020) "Security Engineering" 3rd ed., Chapter 10: Banking and Bookkeeping
  https://www.cl.cam.ac.uk/~rja14/book.html

  Seacord (2013) "Secure Coding in C and C++", 2nd ed. — Integer Overflow
  Addison-Wesley, ISBN 978-0321822130

Detects:
  1. Race conditions in financial operations (CWE-362)
  2. Double-spend / double-submit without idempotency (CWE-837)
  3. Negative quantity/amount attacks (CWE-20)
  4. Price manipulation via client-provided values (CWE-472)
  5. Insufficient workflow / state transition validation (CWE-841)
  6. Mass discount / coupon abuse without limits (CWE-799)
  7. Integer overflow in financial calculations (CWE-190)
  8. Unbounded resource allocation (CWE-770)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral,
    StringLiteral,
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
        _collect_names(stmt, names)
    return bool(names & _REACT_PATTERNS)


def _collect_names(node, names: set) -> None:
    """Recursively collect all identifier and method names from AST nodes."""
    if isinstance(node, Identifier):
        names.add(node.name)
    elif isinstance(node, MethodCall):
        names.add(node.method_name)
        _collect_names(node.obj, names)
        for arg in node.args:
            _collect_names(arg, names)
    elif isinstance(node, FunctionCall):
        _collect_names(node.callee, names)
        for arg in node.args:
            _collect_names(arg, names)
    elif isinstance(node, FieldAccess):
        names.add(node.field_name)
        _collect_names(node.obj, names)
    elif isinstance(node, BinaryOp):
        _collect_names(node.left, names)
        _collect_names(node.right, names)
    elif isinstance(node, UnaryOp):
        _collect_names(node.operand, names)
    elif isinstance(node, ExprStmt):
        _collect_names(node.expr, names)
    elif isinstance(node, LetStmt):
        if node.value:
            _collect_names(node.value, names)
    elif isinstance(node, AssignStmt):
        _collect_names(node.value, names)
    elif isinstance(node, ReturnStmt):
        if node.value:
            _collect_names(node.value, names)
    elif isinstance(node, IfStmt):
        _collect_names(node.condition, names)
        for s in node.then_body:
            _collect_names(s, names)
        for s in node.else_body:
            _collect_names(s, names)
    elif isinstance(node, WhileStmt):
        _collect_names(node.condition, names)
        for s in node.body:
            _collect_names(s, names)
    elif isinstance(node, ForStmt):
        _collect_names(node.iterable, names)
        for s in node.body:
            _collect_names(s, names)


# ---------------------------------------------------------------------------
# Severity Classification
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# ---------------------------------------------------------------------------
# CWE / Category Mapping
# ---------------------------------------------------------------------------

class BizLogicCategory(Enum):
    RACE_CONDITION = "race_condition_financial"
    DOUBLE_SPEND = "double_spend"
    NEGATIVE_AMOUNT = "negative_amount"
    PRICE_MANIPULATION = "price_manipulation"
    WORKFLOW_BYPASS = "workflow_bypass"
    COUPON_ABUSE = "coupon_abuse"
    INTEGER_OVERFLOW = "integer_overflow_financial"
    UNBOUNDED_ALLOCATION = "unbounded_allocation"


CWE_MAP: Dict[BizLogicCategory, str] = {
    BizLogicCategory.RACE_CONDITION: "CWE-362",
    BizLogicCategory.DOUBLE_SPEND: "CWE-837",
    BizLogicCategory.NEGATIVE_AMOUNT: "CWE-20",
    BizLogicCategory.PRICE_MANIPULATION: "CWE-472",
    BizLogicCategory.WORKFLOW_BYPASS: "CWE-841",
    BizLogicCategory.COUPON_ABUSE: "CWE-799",
    BizLogicCategory.INTEGER_OVERFLOW: "CWE-190",
    BizLogicCategory.UNBOUNDED_ALLOCATION: "CWE-770",
}

SEVERITY_MAP: Dict[BizLogicCategory, Severity] = {
    BizLogicCategory.RACE_CONDITION: Severity.CRITICAL,
    BizLogicCategory.DOUBLE_SPEND: Severity.CRITICAL,
    BizLogicCategory.NEGATIVE_AMOUNT: Severity.HIGH,
    BizLogicCategory.PRICE_MANIPULATION: Severity.CRITICAL,
    BizLogicCategory.WORKFLOW_BYPASS: Severity.HIGH,
    BizLogicCategory.COUPON_ABUSE: Severity.MEDIUM,
    BizLogicCategory.INTEGER_OVERFLOW: Severity.HIGH,
    BizLogicCategory.UNBOUNDED_ALLOCATION: Severity.MEDIUM,
}

DESCRIPTION_MAP: Dict[BizLogicCategory, str] = {
    BizLogicCategory.RACE_CONDITION: "Race Condition in Financial Operation",
    BizLogicCategory.DOUBLE_SPEND: "Double-Spend / Double-Submit",
    BizLogicCategory.NEGATIVE_AMOUNT: "Negative Quantity/Amount Attack",
    BizLogicCategory.PRICE_MANIPULATION: "Client-Side Price Manipulation",
    BizLogicCategory.WORKFLOW_BYPASS: "Insufficient Workflow Validation",
    BizLogicCategory.COUPON_ABUSE: "Mass Discount / Coupon Abuse",
    BizLogicCategory.INTEGER_OVERFLOW: "Integer Overflow in Financial Calculation",
    BizLogicCategory.UNBOUNDED_ALLOCATION: "Unbounded Resource Allocation",
}


# ---------------------------------------------------------------------------
# Pattern Specifications — Financial Operations
# ---------------------------------------------------------------------------

# Function name fragments that indicate financial / transactional operations.
# If a function's name contains any of these, it handles money movement.
FINANCIAL_FUNC_PATTERNS: Set[str] = {
    "payment", "transfer", "withdraw", "charge", "refund",
    "deposit", "payout", "purchase", "checkout", "invoice",
    "bill", "settle", "disburse", "credit", "debit",
}

# Function name fragments for bid/order operations (double-submit risk).
ORDER_FUNC_PATTERNS: Set[str] = {
    "payment", "order", "bid", "purchase", "checkout",
    "subscribe", "book", "reserve", "confirm", "submit_order",
    "place_order", "create_order", "create_bid", "submit_bid",
    "place_bid", "make_payment", "process_payment",
}

# Read-then-write patterns: functions that read a balance/value.
BALANCE_READ_PATTERNS: Set[str] = {
    "get_balance", "getBalance", "fetch_balance", "fetchBalance",
    "read_balance", "readBalance", "check_balance", "checkBalance",
    "get_credits", "getCredits", "get_inventory", "getInventory",
    "get_stock", "getStock", "get_quantity", "getQuantity",
    "get_available", "getAvailable", "get_amount", "getAmount",
    "get_funds", "getFunds", "get_wallet", "getWallet",
    "get_account", "getAccount", "load_balance", "loadBalance",
}

# Write-back patterns: functions that update a balance/value.
BALANCE_WRITE_PATTERNS: Set[str] = {
    "update_balance", "updateBalance", "set_balance", "setBalance",
    "save_balance", "saveBalance", "write_balance", "writeBalance",
    "update_credits", "updateCredits", "set_credits", "setCredits",
    "update_inventory", "updateInventory", "set_inventory", "setInventory",
    "update_stock", "updateStock", "set_stock", "setStock",
    "decrement_stock", "decrementStock", "increment_stock", "incrementStock",
    "deduct_balance", "deductBalance", "add_balance", "addBalance",
    "update_quantity", "updateQuantity", "set_quantity", "setQuantity",
    "update_funds", "updateFunds", "set_funds", "setFunds",
    "update_wallet", "updateWallet", "save_wallet", "saveWallet",
    "update_account", "updateAccount",
}

# Transaction / locking patterns that protect against race conditions.
TRANSACTION_PATTERNS: Set[str] = {
    "transaction", "begin_transaction", "beginTransaction",
    "start_transaction", "startTransaction",
    "commit", "rollback", "atomic", "with_lock", "withLock",
    "acquire_lock", "acquireLock", "lock", "mutex",
    "serializable", "for_update", "forUpdate", "select_for_update",
    "selectForUpdate", "advisory_lock", "advisoryLock",
    "compare_and_swap", "compareAndSwap", "cas",
    "optimistic_lock", "optimisticLock", "version_check", "versionCheck",
    "db_transaction", "dbTransaction", "prisma_transaction",
    "prismaTransaction", "sequelize_transaction", "knex_transaction",
    "with_transaction", "withTransaction", "run_in_transaction",
    "runInTransaction",
}

# Idempotency patterns that protect against double-submit.
IDEMPOTENCY_PATTERNS: Set[str] = {
    "idempotency_key", "idempotencyKey", "idempotent",
    "dedup", "deduplicate", "deduplication",
    "request_id", "requestId", "unique_key", "uniqueKey",
    "nonce", "transaction_id", "transactionId",
    "already_processed", "alreadyProcessed",
    "check_duplicate", "checkDuplicate", "is_duplicate", "isDuplicate",
    "unique_constraint", "uniqueConstraint",
    "on_conflict", "onConflict", "upsert",
    "if_not_exists", "ifNotExists",
    "prevent_duplicate", "preventDuplicate",
    "submission_token", "submissionToken",
}

# Parameter names that represent monetary amounts or quantities.
AMOUNT_PARAM_PATTERNS: Set[str] = {
    "amount", "price", "quantity", "discount", "total",
    "cost", "qty", "count", "units", "credit",
    "charge", "fee", "rate", "payment_amount", "paymentAmount",
    "order_total", "orderTotal", "line_total", "lineTotal",
    "subtotal", "sub_total", "tax", "tip", "gratuity",
    "bid_amount", "bidAmount", "deposit_amount", "depositAmount",
    "refund_amount", "refundAmount", "transfer_amount", "transferAmount",
    "withdraw_amount", "withdrawAmount",
}

# Validation patterns that guard against negative values.
POSITIVE_GUARD_PATTERNS: Set[str] = {
    "> 0", ">= 0", ">= 1", "is_positive", "isPositive",
    "validate_amount", "validateAmount", "check_amount", "checkAmount",
    "assert_positive", "assertPositive", "must_be_positive",
    "min_value", "minValue", "minimum",
    "Math.abs", "abs(", "Math.max",
}

# Client-side price source patterns (request.body.price, params.price, etc.).
CLIENT_PRICE_FIELD_NAMES: Set[str] = {
    "price", "unit_price", "unitPrice", "item_price", "itemPrice",
    "total", "subtotal", "amount", "cost", "rate",
    "fee", "charge",
}

CLIENT_SOURCE_OBJECTS: Set[str] = {
    "request", "req", "body", "params", "query",
    "payload", "input", "data", "args", "form",
}

# Server-side price lookup patterns (fetching canonical price from DB).
PRICE_LOOKUP_PATTERNS: Set[str] = {
    "get_price", "getPrice", "fetch_price", "fetchPrice",
    "lookup_price", "lookupPrice", "load_price", "loadPrice",
    "find_price", "findPrice", "product_price", "productPrice",
    "catalog_price", "catalogPrice", "db_price", "dbPrice",
    "server_price", "serverPrice", "canonical_price", "canonicalPrice",
    "get_product", "getProduct", "find_product", "findProduct",
    "fetch_product", "fetchProduct", "load_product", "loadProduct",
    "get_item", "getItem", "find_item", "findItem",
    "price_from_db", "priceFromDb", "price_from_catalog", "priceFromCatalog",
}

# Status/workflow patterns.
STATUS_UPDATE_PATTERNS: Set[str] = {
    "update_status", "updateStatus", "set_status", "setStatus",
    "change_status", "changeStatus", "transition_status", "transitionStatus",
    "advance_status", "advanceStatus", "move_to", "moveTo",
    "transition_to", "transitionTo", "update_state", "updateState",
    "set_state", "setState", "change_state", "changeState",
}

STATUS_CHECK_PATTERNS: Set[str] = {
    "check_status", "checkStatus", "get_status", "getStatus",
    "current_status", "currentStatus", "validate_transition",
    "validateTransition", "can_transition", "canTransition",
    "is_valid_transition", "isValidTransition",
    "allowed_transitions", "allowedTransitions",
    "status_machine", "statusMachine", "state_machine", "stateMachine",
    "verify_status", "verifyStatus", "assert_status", "assertStatus",
    "require_status", "requireStatus",
}

# Status field assignment patterns (status = "...", order.status = "...").
STATUS_FIELD_NAMES: Set[str] = {
    "status", "state", "order_status", "orderStatus",
    "payment_status", "paymentStatus", "job_status", "jobStatus",
    "bid_status", "bidStatus", "workflow_status", "workflowStatus",
    "step", "phase", "stage",
}

# Status literals that represent workflow steps.
STATUS_LITERALS: Set[str] = {
    "pending", "processing", "paid", "shipped", "delivered",
    "cancelled", "refunded", "completed", "approved", "rejected",
    "active", "inactive", "draft", "published", "archived",
    "open", "closed", "in_progress", "review", "verified",
    "submitted", "accepted", "declined", "expired", "failed",
    "awaiting_payment", "awaiting_shipment", "in_transit",
}

# Discount / coupon patterns.
DISCOUNT_FUNC_PATTERNS: Set[str] = {
    "apply_discount", "applyDiscount", "apply_coupon", "applyCoupon",
    "redeem", "redeem_code", "redeemCode", "use_coupon", "useCoupon",
    "apply_promo", "applyPromo", "apply_code", "applyCode",
    "validate_coupon", "validateCoupon", "process_discount", "processDiscount",
    "add_discount", "addDiscount",
}

# Patterns that indicate proper coupon/discount limiting.
DISCOUNT_LIMIT_PATTERNS: Set[str] = {
    "used_count", "usedCount", "max_uses", "maxUses",
    "already_applied", "alreadyApplied", "already_used", "alreadyUsed",
    "is_expired", "isExpired", "check_expiry", "checkExpiry",
    "usage_limit", "usageLimit", "redemption_limit", "redemptionLimit",
    "single_use", "singleUse", "one_time", "oneTime",
    "per_user_limit", "perUserLimit", "check_usage", "checkUsage",
    "times_used", "timesUsed", "remaining_uses", "remainingUses",
    "max_redemptions", "maxRedemptions", "is_redeemable", "isRedeemable",
    "can_apply", "canApply", "is_valid_coupon", "isValidCoupon",
}

# Resource creation patterns (unbounded allocation risk).
RESOURCE_CREATE_PATTERNS: Set[str] = {
    "create_account", "createAccount", "register", "signup", "sign_up",
    "create_order", "createOrder", "create_key", "createKey",
    "generate_key", "generateKey", "create_api_key", "createApiKey",
    "generate_api_key", "generateApiKey", "create_token", "createToken",
    "generate_token", "generateToken", "create_session", "createSession",
    "create_invite", "createInvite", "create_webhook", "createWebhook",
    "create_project", "createProject", "create_workspace", "createWorkspace",
    "create_team", "createTeam", "create_org", "createOrg",
    "create_resource", "createResource", "provision", "allocate",
    "spawn", "instantiate", "new_instance", "newInstance",
    "create_subscription", "createSubscription",
    "create_job", "createJob", "create_bid", "createBid",
}

# Per-user / rate limit patterns that protect against unbounded allocation.
ALLOCATION_LIMIT_PATTERNS: Set[str] = {
    "rate_limit", "rateLimit", "throttle", "per_user_limit", "perUserLimit",
    "max_accounts", "maxAccounts", "max_keys", "maxKeys",
    "max_tokens", "maxTokens", "max_sessions", "maxSessions",
    "max_orders", "maxOrders", "max_resources", "maxResources",
    "check_limit", "checkLimit", "enforce_limit", "enforceLimit",
    "quota", "check_quota", "checkQuota", "within_quota", "withinQuota",
    "usage_limit", "usageLimit", "daily_limit", "dailyLimit",
    "hourly_limit", "hourlyLimit", "count_existing", "countExisting",
    "count_by_user", "countByUser", "user_count", "userCount",
    "max_allowed", "maxAllowed", "limit_reached", "limitReached",
    "is_over_limit", "isOverLimit", "captcha", "verify_captcha",
    "verifyCaptcha", "recaptcha",
}

# Money-related parameter/variable names for overflow detection.
MONEY_CALC_NAMES: Set[str] = {
    "price", "cost", "amount", "total", "subtotal",
    "quantity", "qty", "units", "count",
    "rate", "fee", "charge", "tax", "markup",
    "wage", "salary", "hours", "labor",
    "material", "materials", "overhead",
    "unit_price", "unitPrice", "line_total", "lineTotal",
}


# ---------------------------------------------------------------------------
# Helper: Expression Utilities
# ---------------------------------------------------------------------------

def _expr_name(expr: Expr) -> str:
    """Extract a simple name from an expression, or empty string."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, FieldAccess):
        return expr.field_name
    if isinstance(expr, MethodCall):
        return expr.method_name
    if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
        return expr.callee.name
    return ""


def _expr_str(expr: Expr) -> str:
    """Get a short human-readable representation of an expression."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, IntLiteral):
        return str(expr.value)
    if isinstance(expr, FloatLiteral):
        return str(expr.value)
    if isinstance(expr, StringLiteral):
        return f'"{expr.value}"'
    if isinstance(expr, BoolLiteral):
        return str(expr.value).lower()
    if isinstance(expr, FieldAccess):
        return f"{_expr_str(expr.obj)}.{expr.field_name}"
    if isinstance(expr, BinaryOp):
        return f"{_expr_str(expr.left)} {expr.op} {_expr_str(expr.right)}"
    if isinstance(expr, MethodCall):
        args = ", ".join(_expr_str(a) for a in expr.args)
        return f"{_expr_str(expr.obj)}.{expr.method_name}({args})"
    if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
        args = ", ".join(_expr_str(a) for a in expr.args)
        return f"{expr.callee.name}({args})"
    if isinstance(expr, UnaryOp):
        return f"{expr.op}{_expr_str(expr.operand)}"
    return "<expr>"


def _matches_any(name: str, patterns: Set[str]) -> bool:
    """Check if a name contains any of the given pattern fragments (case-insensitive)."""
    lower = name.lower()
    for pat in patterns:
        if pat.lower() in lower:
            return True
    return False


def _matches_exact(name: str, patterns: Set[str]) -> bool:
    """Check if a name exactly matches any pattern (case-sensitive)."""
    return name in patterns


def _collect_call_names(stmts: List[Statement]) -> Set[str]:
    """Collect all function/method call names from a statement list (shallow + recursive)."""
    names: Set[str] = set()
    for stmt in stmts:
        _collect_call_names_stmt(stmt, names)
    return names


def _collect_call_names_stmt(stmt: Statement, names: Set[str]) -> None:
    """Recursively collect call names from a single statement."""
    if isinstance(stmt, ExprStmt):
        _collect_call_names_expr(stmt.expr, names)
    elif isinstance(stmt, LetStmt):
        if stmt.value:
            _collect_call_names_expr(stmt.value, names)
    elif isinstance(stmt, AssignStmt):
        _collect_call_names_expr(stmt.value, names)
    elif isinstance(stmt, ReturnStmt):
        if stmt.value:
            _collect_call_names_expr(stmt.value, names)
    elif isinstance(stmt, IfStmt):
        _collect_call_names_expr(stmt.condition, names)
        for s in stmt.then_body:
            _collect_call_names_stmt(s, names)
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
    """Recursively collect call names from an expression."""
    if isinstance(expr, FunctionCall):
        n = _expr_name(expr.callee) if hasattr(expr, 'callee') else ""
        if n:
            names.add(n)
        for arg in expr.args:
            _collect_call_names_expr(arg, names)
    elif isinstance(expr, MethodCall):
        if expr.method_name:
            names.add(expr.method_name)
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


def _collect_identifiers(expr: Expr) -> Set[str]:
    """Collect all Identifier names referenced in an expression."""
    ids: Set[str] = set()
    _collect_ids_recursive(expr, ids)
    return ids


def _collect_ids_recursive(expr: Expr, ids: Set[str]) -> None:
    """Recursively collect identifiers from an expression."""
    if isinstance(expr, Identifier):
        ids.add(expr.name)
    elif isinstance(expr, BinaryOp):
        _collect_ids_recursive(expr.left, ids)
        _collect_ids_recursive(expr.right, ids)
    elif isinstance(expr, UnaryOp):
        _collect_ids_recursive(expr.operand, ids)
    elif isinstance(expr, FunctionCall):
        _collect_ids_recursive(expr.callee, ids)
        for arg in expr.args:
            _collect_ids_recursive(arg, ids)
    elif isinstance(expr, MethodCall):
        _collect_ids_recursive(expr.obj, ids)
        for arg in expr.args:
            _collect_ids_recursive(arg, ids)
    elif isinstance(expr, FieldAccess):
        _collect_ids_recursive(expr.obj, ids)


def _collect_string_literals(stmts: List[Statement]) -> Set[str]:
    """Collect all string literal values from a statement list."""
    strings: Set[str] = set()
    for stmt in stmts:
        _collect_strings_stmt(stmt, strings)
    return strings


def _collect_strings_stmt(stmt: Statement, strings: Set[str]) -> None:
    """Recursively collect string literals from a statement."""
    if isinstance(stmt, ExprStmt):
        _collect_strings_expr(stmt.expr, strings)
    elif isinstance(stmt, LetStmt):
        if stmt.value:
            _collect_strings_expr(stmt.value, strings)
    elif isinstance(stmt, AssignStmt):
        _collect_strings_expr(stmt.value, strings)
    elif isinstance(stmt, ReturnStmt):
        if stmt.value:
            _collect_strings_expr(stmt.value, strings)
    elif isinstance(stmt, IfStmt):
        _collect_strings_expr(stmt.condition, strings)
        for s in stmt.then_body:
            _collect_strings_stmt(s, strings)
        for s in stmt.else_body:
            _collect_strings_stmt(s, strings)
    elif isinstance(stmt, WhileStmt):
        for s in stmt.body:
            _collect_strings_stmt(s, strings)
    elif isinstance(stmt, ForStmt):
        for s in stmt.body:
            _collect_strings_stmt(s, strings)


def _collect_strings_expr(expr: Expr, strings: Set[str]) -> None:
    """Recursively collect string literals from an expression."""
    if isinstance(expr, StringLiteral):
        strings.add(expr.value)
    elif isinstance(expr, BinaryOp):
        _collect_strings_expr(expr.left, strings)
        _collect_strings_expr(expr.right, strings)
    elif isinstance(expr, UnaryOp):
        _collect_strings_expr(expr.operand, strings)
    elif isinstance(expr, FunctionCall):
        for arg in expr.args:
            _collect_strings_expr(arg, strings)
    elif isinstance(expr, MethodCall):
        _collect_strings_expr(expr.obj, strings)
        for arg in expr.args:
            _collect_strings_expr(arg, strings)
    elif isinstance(expr, FieldAccess):
        _collect_strings_expr(expr.obj, strings)


def _has_comparison_guard(stmts: List[Statement], param_name: str, ops: Set[str]) -> bool:
    """Check if any statement contains a comparison guard on the given parameter.

    For example, if param_name is 'amount' and ops is {'>', '>='}, returns True
    if any if-condition or expression contains 'amount > 0' or 'amount >= 0'.
    """
    for stmt in stmts:
        if _stmt_has_guard(stmt, param_name, ops):
            return True
    return False


def _stmt_has_guard(stmt: Statement, param_name: str, ops: Set[str]) -> bool:
    """Check a single statement for a comparison guard."""
    if isinstance(stmt, IfStmt):
        if _expr_has_guard(stmt.condition, param_name, ops):
            return True
        for s in stmt.then_body:
            if _stmt_has_guard(s, param_name, ops):
                return True
        for s in stmt.else_body:
            if _stmt_has_guard(s, param_name, ops):
                return True
    elif isinstance(stmt, ExprStmt):
        if _expr_has_guard(stmt.expr, param_name, ops):
            return True
    elif isinstance(stmt, LetStmt):
        if stmt.value and _expr_has_guard(stmt.value, param_name, ops):
            return True
    elif isinstance(stmt, WhileStmt):
        if _expr_has_guard(stmt.condition, param_name, ops):
            return True
        for s in stmt.body:
            if _stmt_has_guard(s, param_name, ops):
                return True
    elif isinstance(stmt, ForStmt):
        for s in stmt.body:
            if _stmt_has_guard(s, param_name, ops):
                return True
    elif isinstance(stmt, ReturnStmt):
        if stmt.value and _expr_has_guard(stmt.value, param_name, ops):
            return True
    return False


def _expr_has_guard(expr: Expr, param_name: str, ops: Set[str]) -> bool:
    """Check if an expression contains a comparison of param_name with the given operators."""
    if isinstance(expr, BinaryOp):
        if expr.op in ops:
            # Check both sides: param > 0 or 0 < param
            left_name = _expr_name(expr.left)
            right_name = _expr_name(expr.right)
            if left_name == param_name or right_name == param_name:
                return True
        # Also check sub-expressions (e.g., amount > 0 && quantity > 0)
        if _expr_has_guard(expr.left, param_name, ops):
            return True
        if _expr_has_guard(expr.right, param_name, ops):
            return True
    elif isinstance(expr, UnaryOp):
        return _expr_has_guard(expr.operand, param_name, ops)
    elif isinstance(expr, FunctionCall):
        # Check for validation function calls: validateAmount(amount)
        callee_name = _expr_name(expr.callee) if hasattr(expr, 'callee') else ""
        if callee_name and _matches_any(callee_name, {"validate", "assert", "check", "ensure"}):
            for arg in expr.args:
                if isinstance(arg, Identifier) and arg.name == param_name:
                    return True
        for arg in expr.args:
            if _expr_has_guard(arg, param_name, ops):
                return True
    elif isinstance(expr, MethodCall):
        if _matches_any(expr.method_name, {"validate", "assert", "check", "ensure"}):
            for arg in expr.args:
                if isinstance(arg, Identifier) and arg.name == param_name:
                    return True
        for arg in expr.args:
            if _expr_has_guard(arg, param_name, ops):
                return True
    return False


def _is_client_source_expr(expr: Expr) -> bool:
    """Check if an expression accesses a client-provided request field.

    Looks for patterns like request.body.price, req.params.amount, body.price, etc.
    """
    if isinstance(expr, FieldAccess):
        field_lower = expr.field_name.lower()
        # Check if the field name is a price-like field
        is_price_field = any(p in field_lower for p in CLIENT_PRICE_FIELD_NAMES)
        if is_price_field:
            # Check if the object chain references a client source
            obj_name = _get_root_name(expr.obj)
            if obj_name and obj_name.lower() in CLIENT_SOURCE_OBJECTS:
                return True
            # Also check intermediate field (request.body.price)
            if isinstance(expr.obj, FieldAccess):
                mid_name = expr.obj.field_name.lower()
                root_name = _get_root_name(expr.obj.obj)
                if mid_name in CLIENT_SOURCE_OBJECTS or (
                    root_name and root_name.lower() in CLIENT_SOURCE_OBJECTS
                ):
                    return True
    return False


def _get_root_name(expr: Expr) -> str:
    """Get the root identifier name from a chain of field accesses."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, FieldAccess):
        return _get_root_name(expr.obj)
    return ""


def _find_status_assignments(stmts: List[Statement]) -> List[Tuple[str, str, SourceLocation]]:
    """Find all status field assignments in a statement list.

    Returns list of (field_name, assigned_value, location) tuples.
    """
    results: List[Tuple[str, str, SourceLocation]] = []
    for stmt in stmts:
        _find_status_assign_stmt(stmt, results)
    return results


def _find_status_assign_stmt(
    stmt: Statement,
    results: List[Tuple[str, str, SourceLocation]],
) -> None:
    """Recursively find status assignments in a statement."""
    loc = getattr(stmt, 'location', None) or SourceLocation(line=0, column=0)

    if isinstance(stmt, AssignStmt):
        # Check if target is a status field: obj.status = "shipped"
        target_name = ""
        if isinstance(stmt.target, FieldAccess):
            target_name = stmt.target.field_name
        elif isinstance(stmt.target, Identifier):
            target_name = stmt.target.name

        if target_name.lower() in STATUS_FIELD_NAMES:
            value_str = ""
            if isinstance(stmt.value, StringLiteral):
                value_str = stmt.value.value
            elif isinstance(stmt.value, Identifier):
                value_str = stmt.value.name
            results.append((target_name, value_str, loc))

    elif isinstance(stmt, ExprStmt):
        # Check for set_status("shipped") or update_status("shipped") calls
        if isinstance(stmt.expr, FunctionCall):
            callee_name = _expr_name(stmt.expr.callee) if hasattr(stmt.expr, 'callee') else ""
            if _matches_any(callee_name, STATUS_UPDATE_PATTERNS):
                for arg in stmt.expr.args:
                    if isinstance(arg, StringLiteral):
                        results.append((callee_name, arg.value, loc))
        elif isinstance(stmt.expr, MethodCall):
            if _matches_any(stmt.expr.method_name, STATUS_UPDATE_PATTERNS):
                for arg in stmt.expr.args:
                    if isinstance(arg, StringLiteral):
                        results.append((stmt.expr.method_name, arg.value, loc))

    elif isinstance(stmt, IfStmt):
        for s in stmt.then_body:
            _find_status_assign_stmt(s, results)
        for s in stmt.else_body:
            _find_status_assign_stmt(s, results)
    elif isinstance(stmt, WhileStmt):
        for s in stmt.body:
            _find_status_assign_stmt(s, results)
    elif isinstance(stmt, ForStmt):
        for s in stmt.body:
            _find_status_assign_stmt(s, results)


def _find_multiplications(stmts: List[Statement]) -> List[Tuple[BinaryOp, SourceLocation]]:
    """Find all BinaryOp multiplication nodes in a statement list."""
    results: List[Tuple[BinaryOp, SourceLocation]] = []
    for stmt in stmts:
        _find_mult_stmt(stmt, results)
    return results


def _find_mult_stmt(
    stmt: Statement,
    results: List[Tuple[BinaryOp, SourceLocation]],
) -> None:
    """Recursively find multiplications in a statement."""
    loc = getattr(stmt, 'location', None) or SourceLocation(line=0, column=0)

    if isinstance(stmt, ExprStmt):
        _find_mult_expr(stmt.expr, loc, results)
    elif isinstance(stmt, LetStmt):
        if stmt.value:
            _find_mult_expr(stmt.value, loc, results)
    elif isinstance(stmt, AssignStmt):
        _find_mult_expr(stmt.value, loc, results)
    elif isinstance(stmt, ReturnStmt):
        if stmt.value:
            _find_mult_expr(stmt.value, loc, results)
    elif isinstance(stmt, IfStmt):
        _find_mult_expr(stmt.condition, loc, results)
        for s in stmt.then_body:
            _find_mult_stmt(s, results)
        for s in stmt.else_body:
            _find_mult_stmt(s, results)
    elif isinstance(stmt, WhileStmt):
        for s in stmt.body:
            _find_mult_stmt(s, results)
    elif isinstance(stmt, ForStmt):
        for s in stmt.body:
            _find_mult_stmt(s, results)


def _find_mult_expr(
    expr: Expr,
    loc: SourceLocation,
    results: List[Tuple[BinaryOp, SourceLocation]],
) -> None:
    """Recursively find multiplication BinaryOps in an expression."""
    if isinstance(expr, BinaryOp):
        if expr.op == "*":
            expr_loc = getattr(expr, 'location', None) or loc
            results.append((expr, expr_loc))
        _find_mult_expr(expr.left, loc, results)
        _find_mult_expr(expr.right, loc, results)
    elif isinstance(expr, UnaryOp):
        _find_mult_expr(expr.operand, loc, results)
    elif isinstance(expr, FunctionCall):
        for arg in expr.args:
            _find_mult_expr(arg, loc, results)
    elif isinstance(expr, MethodCall):
        _find_mult_expr(expr.obj, loc, results)
        for arg in expr.args:
            _find_mult_expr(arg, loc, results)


def _expr_is_money_related(expr: Expr) -> bool:
    """Check if an expression references money/quantity-related names."""
    if isinstance(expr, Identifier):
        return _matches_any(expr.name, MONEY_CALC_NAMES)
    if isinstance(expr, FieldAccess):
        return _matches_any(expr.field_name, MONEY_CALC_NAMES)
    return False


# ---------------------------------------------------------------------------
# Business Logic Analyzer
# ---------------------------------------------------------------------------

class BusinessLogicAnalyzer:
    """Detects business logic vulnerabilities via heuristic AST analysis.

    Walks the AEON AST looking for:
    1. Race conditions in financial read-modify-write without locking
    2. Double-spend / double-submit without idempotency protection
    3. Negative quantity/amount parameters without positive guards
    4. Client-provided prices used without server-side verification
    5. Status transitions without current-status validation
    6. Discount/coupon application without usage limits
    7. Integer overflow risk in financial multiplications
    8. Unbounded resource creation without per-user quotas
    """

    def __init__(self):
        self.errors: List[AeonError] = []

    def check_program(self, program: Program) -> List[AeonError]:
        """Run business logic analysis on the entire program."""
        self.errors = []

        # Skip frontend files entirely — UI components are not API endpoints
        if _is_frontend_file(program):
            return self.errors

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.errors

    # ------------------------------------------------------------------
    # Function-level analysis
    # ------------------------------------------------------------------

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for all business logic vulnerability categories."""
        # Skip React/frontend component functions — these are UI, not API endpoints
        if _function_has_react_patterns(func):
            return

        func_name = func.name
        loc = func.location or SourceLocation(line=0, column=0)

        # Collect all call names in the function body for pattern matching
        all_calls = _collect_call_names(func.body)
        all_strings = _collect_string_literals(func.body)

        # 1. Race conditions in financial operations
        self._check_race_conditions(func, func_name, loc, all_calls)

        # 2. Double-spend / double-submit
        self._check_double_spend(func, func_name, loc, all_calls)

        # 3. Negative quantity/amount attacks
        self._check_negative_amounts(func, func_name, loc)

        # 4. Price manipulation
        self._check_price_manipulation(func, func_name, loc, all_calls)

        # 5. Insufficient workflow validation
        self._check_workflow_bypass(func, func_name, loc, all_calls, all_strings)

        # 6. Mass discount / coupon abuse
        self._check_coupon_abuse(func, func_name, loc, all_calls)

        # 7. Integer overflow in financial calculations
        self._check_integer_overflow(func, func_name, loc, all_calls)

        # 8. Unbounded resource allocation
        self._check_unbounded_allocation(func, func_name, loc, all_calls)

    # ------------------------------------------------------------------
    # 1. Race Conditions in Financial Operations (CWE-362)
    # ------------------------------------------------------------------

    def _check_race_conditions(
        self,
        func: PureFunc | TaskFunc,
        func_name: str,
        loc: SourceLocation,
        all_calls: Set[str],
    ) -> None:
        """Detect read-modify-write on financial data without transaction/lock.

        Pattern: function reads balance via get_balance(), performs arithmetic,
        then writes back via update_balance(), all without a wrapping
        transaction or lock acquisition.
        """
        # Check if function name suggests a financial operation
        is_financial = _matches_any(func_name, FINANCIAL_FUNC_PATTERNS)

        # Check for read-then-write pattern
        has_balance_read = any(
            _matches_exact(call, BALANCE_READ_PATTERNS)
            for call in all_calls
        )
        has_balance_write = any(
            _matches_exact(call, BALANCE_WRITE_PATTERNS)
            for call in all_calls
        )
        has_read_write_pattern = has_balance_read and has_balance_write

        if not has_read_write_pattern and not is_financial:
            return

        # Check if transaction/locking is present
        has_transaction = any(
            _matches_any(call, TRANSACTION_PATTERNS)
            for call in all_calls
        )

        # For financial functions with read-modify-write but no transaction
        if has_read_write_pattern and not has_transaction:
            read_calls = [c for c in all_calls if _matches_exact(c, BALANCE_READ_PATTERNS)]
            write_calls = [c for c in all_calls if _matches_exact(c, BALANCE_WRITE_PATTERNS)]
            self._report(
                category=BizLogicCategory.RACE_CONDITION,
                message=(
                    f"Race condition risk in '{func_name}': reads financial data "
                    f"via {sorted(read_calls)} and writes back via {sorted(write_calls)} "
                    f"without a transaction or lock. In concurrent execution, two "
                    f"requests can read the same balance, both subtract, and write "
                    f"back — losing one deduction entirely. Wrap the read-modify-write "
                    f"sequence in a database transaction with row-level locking "
                    f"(e.g., SELECT ... FOR UPDATE) or use an atomic operation."
                ),
                func_name=func_name,
                location=loc,
                extra={"read_calls": sorted(read_calls), "write_calls": sorted(write_calls)},
            )

        # For financial functions that don't use transactions at all
        if is_financial and not has_transaction and not has_read_write_pattern:
            # Only flag if there's at least arithmetic happening (not just a simple call)
            has_arithmetic = self._body_has_arithmetic(func.body)
            if has_arithmetic:
                self._report(
                    category=BizLogicCategory.RACE_CONDITION,
                    message=(
                        f"Financial function '{func_name}' performs arithmetic but "
                        f"does not use any transaction, lock, or atomic operation. "
                        f"Concurrent requests to this endpoint can produce inconsistent "
                        f"financial state. Wrap financial mutations in a database "
                        f"transaction (e.g., BEGIN/COMMIT) or use compare-and-swap."
                    ),
                    func_name=func_name,
                    location=loc,
                )

    def _body_has_arithmetic(self, stmts: List[Statement]) -> bool:
        """Check if a statement list contains arithmetic operations."""
        for stmt in stmts:
            if self._stmt_has_arithmetic(stmt):
                return True
        return False

    def _stmt_has_arithmetic(self, stmt: Statement) -> bool:
        """Check if a single statement contains arithmetic."""
        if isinstance(stmt, ExprStmt):
            return self._expr_has_arithmetic(stmt.expr)
        elif isinstance(stmt, LetStmt):
            return stmt.value is not None and self._expr_has_arithmetic(stmt.value)
        elif isinstance(stmt, AssignStmt):
            return self._expr_has_arithmetic(stmt.value)
        elif isinstance(stmt, ReturnStmt):
            return stmt.value is not None and self._expr_has_arithmetic(stmt.value)
        elif isinstance(stmt, IfStmt):
            return (
                self._body_has_arithmetic(stmt.then_body)
                or self._body_has_arithmetic(stmt.else_body)
            )
        return False

    def _expr_has_arithmetic(self, expr: Expr) -> bool:
        """Check if an expression contains arithmetic operators."""
        if isinstance(expr, BinaryOp):
            if expr.op in ("+", "-", "*", "/", "%"):
                return True
            return (
                self._expr_has_arithmetic(expr.left)
                or self._expr_has_arithmetic(expr.right)
            )
        if isinstance(expr, FunctionCall):
            return any(self._expr_has_arithmetic(a) for a in expr.args)
        if isinstance(expr, MethodCall):
            return any(self._expr_has_arithmetic(a) for a in expr.args)
        return False

    # ------------------------------------------------------------------
    # 2. Double-Spend / Double-Submit (CWE-837)
    # ------------------------------------------------------------------

    def _check_double_spend(
        self,
        func: PureFunc | TaskFunc,
        func_name: str,
        loc: SourceLocation,
        all_calls: Set[str],
    ) -> None:
        """Detect payment/bid/order endpoints without idempotency protection.

        Pattern: functions handling payments, orders, or bids that lack any
        form of duplicate submission prevention (no idempotency_key parameter,
        no dedup check, no unique constraint enforcement).
        """
        # Check if function handles payments/orders/bids
        is_order_func = _matches_any(func_name, ORDER_FUNC_PATTERNS)
        if not is_order_func:
            return

        # Check parameters for idempotency key
        param_names = {p.name for p in func.params}
        has_idempotency_param = any(
            _matches_any(pname, IDEMPOTENCY_PATTERNS)
            for pname in param_names
        )
        if has_idempotency_param:
            return

        # Check function body for dedup calls or unique constraint checks
        has_dedup_call = any(
            _matches_any(call, IDEMPOTENCY_PATTERNS)
            for call in all_calls
        )
        if has_dedup_call:
            return

        # Check for string patterns indicating dedup
        all_strings = _collect_string_literals(func.body)
        has_dedup_string = any(
            _matches_any(s, IDEMPOTENCY_PATTERNS)
            for s in all_strings
        )
        if has_dedup_string:
            return

        self._report(
            category=BizLogicCategory.DOUBLE_SPEND,
            message=(
                f"Double-submit risk in '{func_name}': this function handles a "
                f"financial/order operation but has no idempotency protection. "
                f"If a client retries the request (network timeout, user double-click, "
                f"webhook replay), the operation will execute twice — resulting in "
                f"double charges, duplicate orders, or duplicate bids. Add an "
                f"idempotency_key parameter and check for prior execution before "
                f"processing, or use a database unique constraint on a request identifier."
            ),
            func_name=func_name,
            location=loc,
        )

    # ------------------------------------------------------------------
    # 3. Negative Quantity/Amount Attacks (CWE-20)
    # ------------------------------------------------------------------

    def _check_negative_amounts(
        self,
        func: PureFunc | TaskFunc,
        func_name: str,
        loc: SourceLocation,
    ) -> None:
        """Detect parameters that accept money/quantity values without positive guards.

        Pattern: parameters named amount, price, quantity, discount, etc. that
        are used in arithmetic without a > 0 or >= 0 check in the function body.
        A negative amount in a transfer function reverses the direction; a negative
        price in a purchase function gives money to the buyer.
        """
        positive_ops = {">", ">=", "<", "<="}

        for param in func.params:
            param_lower = param.name.lower()
            is_amount_param = any(
                pat in param_lower for pat in AMOUNT_PARAM_PATTERNS
            )
            if not is_amount_param:
                continue

            # Check if there is a positive guard on this parameter
            has_guard = _has_comparison_guard(func.body, param.name, positive_ops)
            if has_guard:
                continue

            # Check if any validation function is called with this parameter
            all_calls = _collect_call_names(func.body)
            has_validation = any(
                _matches_any(call, {"validate", "assert", "check", "ensure", "verify"})
                for call in all_calls
            )
            # Even if there's a generic validation call, we can't confirm it checks
            # this specific parameter — but reduce confidence. Only flag if there's
            # no validation at all, or if the param is strongly money-typed.
            strongly_financial = any(
                pat == param_lower
                for pat in {"amount", "price", "total", "cost", "quantity", "discount"}
            )
            if has_validation and not strongly_financial:
                continue

            param_loc = getattr(param, 'location', None) or loc
            self._report(
                category=BizLogicCategory.NEGATIVE_AMOUNT,
                message=(
                    f"Negative value attack vector in '{func_name}': parameter "
                    f"'{param.name}' appears to represent a monetary amount or "
                    f"quantity but has no validation guard (> 0 or >= 0). An attacker "
                    f"can submit a negative value to reverse a payment direction, "
                    f"gain unauthorized credit, or manipulate inventory counts. "
                    f"Add explicit validation: if ({param.name} <= 0) throw Error."
                ),
                func_name=func_name,
                location=param_loc,
                extra={"parameter": param.name},
            )

    # ------------------------------------------------------------------
    # 4. Price Manipulation (CWE-472)
    # ------------------------------------------------------------------

    def _check_price_manipulation(
        self,
        func: PureFunc | TaskFunc,
        func_name: str,
        loc: SourceLocation,
        all_calls: Set[str],
    ) -> None:
        """Detect client-provided prices used without server-side lookup.

        Pattern: request.body.price or params.price used directly in
        calculation or storage without fetching the canonical price from
        the database. An attacker can modify the price field in the HTTP
        request to pay less (or nothing) for a product.
        """
        # Collect all client-source price expressions
        client_price_exprs: List[Tuple[Expr, SourceLocation]] = []
        self._find_client_prices(func.body, client_price_exprs)

        if not client_price_exprs:
            return

        # Check if function also performs a server-side price lookup
        has_price_lookup = any(
            _matches_any(call, PRICE_LOOKUP_PATTERNS)
            for call in all_calls
        )
        if has_price_lookup:
            return

        for expr, expr_loc in client_price_exprs:
            self._report(
                category=BizLogicCategory.PRICE_MANIPULATION,
                message=(
                    f"Price manipulation risk in '{func_name}': client-provided "
                    f"value '{_expr_str(expr)}' is used directly without fetching "
                    f"the canonical price from the server/database. An attacker can "
                    f"intercept the request and change the price to $0.01 or any "
                    f"value. Always look up the authoritative price from your "
                    f"database (e.g., product = getProduct(id); price = product.price) "
                    f"and ignore client-submitted price fields."
                ),
                func_name=func_name,
                location=expr_loc,
                extra={"client_expr": _expr_str(expr)},
            )

    def _find_client_prices(
        self,
        stmts: List[Statement],
        results: List[Tuple[Expr, SourceLocation]],
    ) -> None:
        """Find expressions that access client-provided price fields."""
        for stmt in stmts:
            self._find_client_prices_stmt(stmt, results)

    def _find_client_prices_stmt(
        self,
        stmt: Statement,
        results: List[Tuple[Expr, SourceLocation]],
    ) -> None:
        """Recursively find client price accesses in a statement."""
        loc = getattr(stmt, 'location', None) or SourceLocation(line=0, column=0)

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._find_client_prices_expr(stmt.value, loc, results)
        elif isinstance(stmt, AssignStmt):
            self._find_client_prices_expr(stmt.value, loc, results)
        elif isinstance(stmt, ExprStmt):
            self._find_client_prices_expr(stmt.expr, loc, results)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._find_client_prices_expr(stmt.value, loc, results)
        elif isinstance(stmt, IfStmt):
            self._find_client_prices_expr(stmt.condition, loc, results)
            for s in stmt.then_body:
                self._find_client_prices_stmt(s, results)
            for s in stmt.else_body:
                self._find_client_prices_stmt(s, results)
        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._find_client_prices_stmt(s, results)
        elif isinstance(stmt, ForStmt):
            for s in stmt.body:
                self._find_client_prices_stmt(s, results)

    def _find_client_prices_expr(
        self,
        expr: Expr,
        loc: SourceLocation,
        results: List[Tuple[Expr, SourceLocation]],
    ) -> None:
        """Recursively find client price accesses in an expression."""
        if _is_client_source_expr(expr):
            expr_loc = getattr(expr, 'location', None) or loc
            results.append((expr, expr_loc))

        if isinstance(expr, BinaryOp):
            self._find_client_prices_expr(expr.left, loc, results)
            self._find_client_prices_expr(expr.right, loc, results)
        elif isinstance(expr, UnaryOp):
            self._find_client_prices_expr(expr.operand, loc, results)
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._find_client_prices_expr(arg, loc, results)
        elif isinstance(expr, MethodCall):
            self._find_client_prices_expr(expr.obj, loc, results)
            for arg in expr.args:
                self._find_client_prices_expr(arg, loc, results)
        elif isinstance(expr, FieldAccess):
            self._find_client_prices_expr(expr.obj, loc, results)

    # ------------------------------------------------------------------
    # 5. Insufficient Workflow Validation (CWE-841)
    # ------------------------------------------------------------------

    def _check_workflow_bypass(
        self,
        func: PureFunc | TaskFunc,
        func_name: str,
        loc: SourceLocation,
        all_calls: Set[str],
        all_strings: Set[str],
    ) -> None:
        """Detect status transitions that skip required validation steps.

        Pattern: functions that update a status/state field (e.g.,
        order.status = "shipped") without first checking the current status
        (e.g., must be "paid" before "shipped"). This allows an attacker to
        skip workflow steps — e.g., shipping an unpaid order.
        """
        # Check if function name suggests a status update
        is_status_func = _matches_any(func_name, STATUS_UPDATE_PATTERNS)

        # Find status assignments in the body
        status_assignments = _find_status_assignments(func.body)

        if not status_assignments and not is_status_func:
            return

        # Check if current status is validated before the transition
        has_status_check = any(
            _matches_any(call, STATUS_CHECK_PATTERNS)
            for call in all_calls
        )

        # Check if there's a conditional that reads current status
        has_status_condition = self._has_status_condition_check(func.body)

        if has_status_check or has_status_condition:
            return

        # Report each status assignment that lacks validation
        if status_assignments:
            for field_name, new_value, assign_loc in status_assignments:
                value_desc = f" to '{new_value}'" if new_value else ""
                self._report(
                    category=BizLogicCategory.WORKFLOW_BYPASS,
                    message=(
                        f"Workflow bypass risk in '{func_name}': status field "
                        f"'{field_name}' is updated{value_desc} without first "
                        f"verifying the current status. An attacker can skip "
                        f"required workflow steps (e.g., marking an order as "
                        f"'shipped' when it is still 'pending' instead of 'paid'). "
                        f"Always check the current status and validate that the "
                        f"requested transition is allowed before updating. Use a "
                        f"state machine or explicit transition table."
                    ),
                    func_name=func_name,
                    location=assign_loc,
                    extra={"field": field_name, "new_value": new_value},
                )
        elif is_status_func:
            # Function is named like a status updater but we found no assignments
            # — it might be using a generic pattern. Still flag if no check.
            self._report(
                category=BizLogicCategory.WORKFLOW_BYPASS,
                message=(
                    f"Workflow bypass risk in '{func_name}': this function appears "
                    f"to update status/state but does not validate the current status "
                    f"before transitioning. Verify the current state and enforce "
                    f"allowed transitions to prevent workflow step-skipping attacks."
                ),
                func_name=func_name,
                location=loc,
            )

    def _has_status_condition_check(self, stmts: List[Statement]) -> bool:
        """Check if any if-statement condition references a status field."""
        for stmt in stmts:
            if isinstance(stmt, IfStmt):
                if self._condition_references_status(stmt.condition):
                    return True
                if self._has_status_condition_check(stmt.then_body):
                    return True
                if self._has_status_condition_check(stmt.else_body):
                    return True
            elif isinstance(stmt, WhileStmt):
                if self._has_status_condition_check(stmt.body):
                    return True
            elif isinstance(stmt, ForStmt):
                if self._has_status_condition_check(stmt.body):
                    return True
        return False

    def _condition_references_status(self, expr: Expr) -> bool:
        """Check if an expression references a status/state field or variable."""
        if isinstance(expr, Identifier):
            return expr.name.lower() in STATUS_FIELD_NAMES
        if isinstance(expr, FieldAccess):
            return expr.field_name.lower() in STATUS_FIELD_NAMES
        if isinstance(expr, BinaryOp):
            # Check for comparisons like status == "paid"
            if expr.op in ("==", "!=", "===", "!=="):
                left_is_status = self._condition_references_status(expr.left)
                right_is_status = self._condition_references_status(expr.right)
                # Also check if either side is a status literal
                if isinstance(expr.right, StringLiteral):
                    if expr.right.value.lower() in STATUS_LITERALS:
                        return left_is_status or True
                if isinstance(expr.left, StringLiteral):
                    if expr.left.value.lower() in STATUS_LITERALS:
                        return right_is_status or True
                return left_is_status or right_is_status
            # Logical operators: status == "paid" && role == "admin"
            if expr.op in ("&&", "||", "and", "or"):
                return (
                    self._condition_references_status(expr.left)
                    or self._condition_references_status(expr.right)
                )
        if isinstance(expr, UnaryOp):
            return self._condition_references_status(expr.operand)
        if isinstance(expr, FunctionCall):
            callee_name = _expr_name(expr.callee) if hasattr(expr, 'callee') else ""
            if _matches_any(callee_name, STATUS_CHECK_PATTERNS):
                return True
        if isinstance(expr, MethodCall):
            if _matches_any(expr.method_name, STATUS_CHECK_PATTERNS):
                return True
        return False

    # ------------------------------------------------------------------
    # 6. Mass Discount / Coupon Abuse (CWE-799)
    # ------------------------------------------------------------------

    def _check_coupon_abuse(
        self,
        func: PureFunc | TaskFunc,
        func_name: str,
        loc: SourceLocation,
        all_calls: Set[str],
    ) -> None:
        """Detect discount/coupon application without single-use or limit checks.

        Pattern: apply_discount, apply_coupon, or redeem functions that do not
        check used_count, max_uses, already_applied, or similar limit fields.
        Without limits, an attacker can apply the same coupon thousands of times
        or stack unlimited discounts.
        """
        # Check if function applies discounts or coupons
        is_discount_func = _matches_any(func_name, DISCOUNT_FUNC_PATTERNS)
        if not is_discount_func:
            return

        # Check if the function body references any limit/usage patterns
        has_limit_check = any(
            _matches_any(call, DISCOUNT_LIMIT_PATTERNS)
            for call in all_calls
        )
        if has_limit_check:
            return

        # Check parameter names for limit-related params
        param_names = {p.name for p in func.params}
        has_limit_param = any(
            _matches_any(pname, DISCOUNT_LIMIT_PATTERNS)
            for pname in param_names
        )
        if has_limit_param:
            return

        # Check string literals for limit-related strings
        all_strings = _collect_string_literals(func.body)
        has_limit_string = any(
            _matches_any(s, {"used", "expired", "limit", "max", "already", "redeemed"})
            for s in all_strings
        )
        if has_limit_string:
            return

        # Check for any variable names that suggest tracking usage
        body_ids = self._collect_all_identifiers_in_body(func.body)
        has_limit_var = any(
            _matches_any(v, DISCOUNT_LIMIT_PATTERNS)
            for v in body_ids
        )
        if has_limit_var:
            return

        self._report(
            category=BizLogicCategory.COUPON_ABUSE,
            message=(
                f"Coupon/discount abuse risk in '{func_name}': this function applies "
                f"a discount or coupon but does not check usage limits (used_count, "
                f"max_uses, already_applied, is_expired). An attacker can replay the "
                f"same coupon code across multiple orders or apply it repeatedly to "
                f"the same order. Add checks for: (1) coupon has not expired, "
                f"(2) coupon has not exceeded max_uses, (3) user has not already "
                f"redeemed this coupon, (4) only one discount per order."
            ),
            func_name=func_name,
            location=loc,
        )

    def _collect_all_identifiers_in_body(self, stmts: List[Statement]) -> Set[str]:
        """Collect all identifier names referenced anywhere in a statement list."""
        ids: Set[str] = set()
        for stmt in stmts:
            self._collect_ids_from_stmt(stmt, ids)
        return ids

    def _collect_ids_from_stmt(self, stmt: Statement, ids: Set[str]) -> None:
        """Recursively collect identifier names from a statement."""
        if isinstance(stmt, LetStmt):
            ids.add(stmt.name)
            if stmt.value:
                ids.update(_collect_identifiers(stmt.value))
        elif isinstance(stmt, AssignStmt):
            ids.update(_collect_identifiers(stmt.target))
            ids.update(_collect_identifiers(stmt.value))
        elif isinstance(stmt, ExprStmt):
            ids.update(_collect_identifiers(stmt.expr))
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                ids.update(_collect_identifiers(stmt.value))
        elif isinstance(stmt, IfStmt):
            ids.update(_collect_identifiers(stmt.condition))
            for s in stmt.then_body:
                self._collect_ids_from_stmt(s, ids)
            for s in stmt.else_body:
                self._collect_ids_from_stmt(s, ids)
        elif isinstance(stmt, WhileStmt):
            ids.update(_collect_identifiers(stmt.condition))
            for s in stmt.body:
                self._collect_ids_from_stmt(s, ids)
        elif isinstance(stmt, ForStmt):
            ids.add(stmt.var_name)
            ids.update(_collect_identifiers(stmt.iterable))
            for s in stmt.body:
                self._collect_ids_from_stmt(s, ids)

    # ------------------------------------------------------------------
    # 7. Integer Overflow in Financial Calculations (CWE-190)
    # ------------------------------------------------------------------

    def _check_integer_overflow(
        self,
        func: PureFunc | TaskFunc,
        func_name: str,
        loc: SourceLocation,
        all_calls: Set[str],
    ) -> None:
        """Detect multiplication of large numbers in financial context without overflow protection.

        Pattern: BinaryOp(*) where both operands relate to money/quantity names.
        quantity * price can overflow 32-bit integers when quantity and price are
        both large (e.g., 999999 * 999999 = ~10^12, which exceeds INT32_MAX).
        """
        multiplications = _find_multiplications(func.body)
        if not multiplications:
            return

        # Check if function uses any overflow protection
        overflow_protection_patterns: Set[str] = {
            "safe_multiply", "safeMultiply", "checked_mul", "checkedMul",
            "safe_math", "safeMath", "big_int", "bigInt", "BigInt",
            "BigNumber", "bigNumber", "Decimal", "decimal",
            "safe_add", "safeAdd", "checked_add", "checkedAdd",
            "overflow_check", "overflowCheck", "Math.clz32",
        }
        has_overflow_protection = any(
            _matches_any(call, overflow_protection_patterns)
            for call in all_calls
        )
        if has_overflow_protection:
            return

        for mult_expr, mult_loc in multiplications:
            left_is_money = _expr_is_money_related(mult_expr.left)
            right_is_money = _expr_is_money_related(mult_expr.right)

            if left_is_money and right_is_money:
                self._report(
                    category=BizLogicCategory.INTEGER_OVERFLOW,
                    message=(
                        f"Integer overflow risk in '{func_name}': multiplication "
                        f"'{_expr_str(mult_expr)}' involves two financial/quantity "
                        f"operands. If both values are large (e.g., quantity=999999, "
                        f"price=999999), the result (~10^12) overflows 32-bit integers "
                        f"and wraps to a small or negative number. Use 64-bit integers, "
                        f"BigInt, or a checked multiplication function (e.g., "
                        f"safe_multiply(a, b) that throws on overflow)."
                    ),
                    func_name=func_name,
                    location=mult_loc,
                    extra={"expression": _expr_str(mult_expr)},
                )

            elif left_is_money or right_is_money:
                # One operand is financial — still a risk if the other is a variable
                other = mult_expr.right if left_is_money else mult_expr.left
                # Skip if the other side is a small constant
                if isinstance(other, IntLiteral) and abs(other.value) < 1000:
                    continue
                if isinstance(other, FloatLiteral) and abs(other.value) < 1000.0:
                    continue
                # If the other side is also a variable, flag it
                if isinstance(other, (Identifier, FieldAccess)):
                    self._report(
                        category=BizLogicCategory.INTEGER_OVERFLOW,
                        message=(
                            f"Potential integer overflow in '{func_name}': "
                            f"multiplication '{_expr_str(mult_expr)}' involves a "
                            f"financial operand and a variable-sized operand. If both "
                            f"values are user-controlled, an attacker can craft inputs "
                            f"that cause integer overflow, wrapping to unexpected values. "
                            f"Validate input ranges and use checked arithmetic."
                        ),
                        func_name=func_name,
                        location=mult_loc,
                        extra={"expression": _expr_str(mult_expr)},
                    )

    # ------------------------------------------------------------------
    # 8. Unbounded Resource Allocation (CWE-770)
    # ------------------------------------------------------------------

    def _check_unbounded_allocation(
        self,
        func: PureFunc | TaskFunc,
        func_name: str,
        loc: SourceLocation,
        all_calls: Set[str],
    ) -> None:
        """Detect resource creation without per-user limits.

        Pattern: functions that create accounts, orders, API keys, sessions,
        or other resources without checking per-user quotas or rate limits.
        Without limits, an attacker can create millions of resources, exhausting
        storage, memory, or other system resources (denial of service).
        """
        # Check if function creates resources
        is_creator = _matches_any(func_name, RESOURCE_CREATE_PATTERNS)
        if not is_creator:
            return

        # Check if function has any allocation limiting
        has_limit = any(
            _matches_any(call, ALLOCATION_LIMIT_PATTERNS)
            for call in all_calls
        )
        if has_limit:
            return

        # Check parameters for limit-related params
        param_names = {p.name for p in func.params}
        has_limit_param = any(
            _matches_any(pname, ALLOCATION_LIMIT_PATTERNS)
            for pname in param_names
        )
        if has_limit_param:
            return

        # Check body identifiers for any limit-related variables
        body_ids = self._collect_all_identifiers_in_body(func.body)
        has_limit_var = any(
            _matches_any(v, ALLOCATION_LIMIT_PATTERNS)
            for v in body_ids
        )
        if has_limit_var:
            return

        # Check for any string indicating limits in the body
        all_strings = _collect_string_literals(func.body)
        has_limit_string = any(
            _matches_any(s, {"limit", "quota", "max", "throttle", "captcha"})
            for s in all_strings
        )
        if has_limit_string:
            return

        self._report(
            category=BizLogicCategory.UNBOUNDED_ALLOCATION,
            message=(
                f"Unbounded resource allocation in '{func_name}': this function "
                f"creates resources (accounts, orders, keys, sessions, etc.) without "
                f"any per-user limit, rate limit, or quota check. An attacker can "
                f"call this endpoint repeatedly to create millions of resources, "
                f"exhausting database storage, memory, or API quotas. Add per-user "
                f"limits (e.g., max 5 API keys per user), rate limiting (e.g., "
                f"10 requests/minute), or CAPTCHA verification for creation endpoints."
            ),
            func_name=func_name,
            location=loc,
        )

    # ------------------------------------------------------------------
    # Finding Emission
    # ------------------------------------------------------------------

    def _report(
        self,
        category: BizLogicCategory,
        message: str,
        func_name: str,
        location: SourceLocation,
        extra: Optional[Dict] = None,
    ) -> None:
        """Emit a structured finding as an AeonError via contract_error."""
        severity = SEVERITY_MAP[category]
        cwe = CWE_MAP[category]
        description = DESCRIPTION_MAP[category]

        details: Dict = {
            "engine": "Business Logic Security",
            "severity": severity.value,
            "cwe": cwe,
            "category": category.value,
            "description": description,
            "function": func_name,
        }
        if extra:
            details.update(extra)

        self.errors.append(contract_error(
            precondition=f"[{severity.value.upper()}] [{cwe}] {message}",
            failing_values=details,
            function_signature=func_name,
            location=location,
        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_business_logic(program: Program) -> list:
    """Run business logic security analysis on an AEON program.

    Detects business logic vulnerabilities that bypass traditional input
    validation and access control. These are application-level flaws in
    how the system handles financial transactions, state transitions,
    resource allocation, and pricing.

    Categories detected:

    1. Race conditions in financial operations (CWE-362)
       Read-modify-write on balances/inventory without transactions or locks.

    2. Double-spend / double-submit (CWE-837)
       Payment/bid/order endpoints without idempotency keys or dedup checks.

    3. Negative quantity/amount attacks (CWE-20)
       Monetary or quantity parameters accepted without positive-value guards.

    4. Price manipulation (CWE-472)
       Client-provided prices used in calculations without server-side lookup.

    5. Insufficient workflow validation (CWE-841)
       Status transitions that skip required steps (e.g., pending -> shipped
       without checking "paid" status first).

    6. Mass discount / coupon abuse (CWE-799)
       Discount or coupon application without single-use or usage-limit checks.

    7. Integer overflow in financial calculations (CWE-190)
       Multiplication of money/quantity values without overflow protection.

    8. Unbounded resource allocation (CWE-770)
       Resource creation (accounts, orders, API keys) without per-user limits.

    Severity levels:
      Critical — Race conditions, double-spend, price manipulation
      High     — Negative amounts, workflow bypass, integer overflow
      Medium   — Coupon abuse, unbounded allocation
    """
    analyzer = BusinessLogicAnalyzer()
    return analyzer.check_program(program)
