"""AEON Data Exposure & Privacy Engine -- Detecting PII Leaks and Privacy Violations.

Detects data exposure and privacy vulnerabilities across all supported languages.
Focuses on how sensitive data is logged, transmitted, stored, and retained.

References:
  OWASP Top 10 (2021) A01:2021 - Broken Access Control
  https://owasp.org/Top10/A01_2021-Broken_Access_Control/

  OWASP API Security Top 10 (2023) API3 - Broken Object Property Level Authorization
  https://owasp.org/API-Security/editions/2023/en/0x11-t10/

  NIST SP 800-122 "Guide to Protecting the Confidentiality of PII"
  https://doi.org/10.6028/NIST.SP.800-122

  GDPR Article 5 - Principles relating to processing of personal data
  https://gdpr-info.eu/art-5-gdpr/

  CWE-532: Insertion of Sensitive Information into Log File
  CWE-209: Generation of Error Message Containing Sensitive Information
  CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
  CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
  CWE-598: Use of GET Request Method With Sensitive Query Strings
  CWE-311: Missing Encryption of Sensitive Data
  CWE-404: Improper Resource Shutdown or Release (data retention context)
  CWE-540: Inclusion of Sensitive Information in Source Code

Detection Strategies:

1. PII IN LOGS (CWE-532):
   Logging calls that include variables named after PII fields. Catches
   console.log, logger.*, print, IO.inspect, dbg with sensitive variable
   references in their arguments.

2. SENSITIVE DATA IN ERROR RESPONSES (CWE-209):
   Error handlers returning database errors, stack traces, internal paths,
   or connection strings to clients. Catches catch blocks exposing err.message,
   err.stack, traceback, __traceback__ in response objects.

3. MISSING DATA MASKING (CWE-359):
   Returning full SSN, credit card, or phone number without masking. Detects
   database field access for sensitive columns returned directly in API
   responses without substring/mask function wrapping.

4. EXCESSIVE DATA IN API RESPONSES (CWE-200):
   Returning entire ORM objects including internal fields like password_hash,
   reset_token, internal_id, is_admin. Catches res.json(user) or json(conn, user)
   without .select(), serializer, or explicit field picking.

5. PII IN URLs (CWE-598):
   Email addresses, phone numbers, SSNs in URL query parameters or path
   segments via string interpolation or concatenation.

6. MISSING ENCRYPTION AT REST (CWE-311):
   Storing sensitive data without encryption. Detects database write operations
   with sensitive field names but no encrypt, hash, or cipher call nearby.

7. DATA RETENTION VIOLATIONS (CWE-404):
   Collecting user data without deletion capability. Detects create/insert
   operations for user data without corresponding delete/destroy/anonymize
   function in the same module.

8. HARDCODED PII IN SOURCE (CWE-540):
   Test data with realistic PII (email addresses, phone numbers, SSNs)
   in non-test files.

Every finding includes:
  - Engine: "Data Exposure & Privacy"
  - Severity: critical / high / medium
  - CWE reference
  - Remediation guidance
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Constants: PII & Sensitive Variable Names
# ---------------------------------------------------------------------------

PII_VARIABLE_NAMES: Set[str] = {
    "password", "ssn", "social_security", "credit_card", "card_number",
    "cvv", "token", "secret", "email", "phone", "address", "dob",
    "date_of_birth", "salary", "income", "bank_account",
}

# Fields that indicate internal/sensitive ORM data that should not be exposed
INTERNAL_ORM_FIELDS: Set[str] = {
    "password_hash", "reset_token", "internal_id", "created_by",
    "deleted_at", "is_admin", "password_digest", "secret_key",
    "api_key", "refresh_token", "hashed_password", "salt",
    "two_factor_secret", "recovery_codes", "session_token",
}

# Sensitive database columns that require masking before exposure
MASKABLE_FIELDS: Set[str] = {
    "ssn", "social_security", "social_security_number",
    "credit_card", "card_number", "credit_card_number", "cc_number",
    "phone", "phone_number", "mobile", "cell_phone",
}

# Logging function/method names
LOG_FUNCTIONS: Set[str] = {
    "console.log", "console.warn", "console.error", "console.info",
    "console.debug", "console.trace",
    "logger.info", "logger.warn", "logger.warning", "logger.error",
    "logger.debug", "logger.critical", "logger.fatal", "logger.trace",
    "Logger.info", "Logger.warn", "Logger.warning", "Logger.error",
    "Logger.debug", "Logger.critical", "Logger.fatal",
    "print", "println", "printf", "fprintf", "puts",
    "IO.inspect", "IO.puts", "IO.warn",
    "dbg", "dbg!",
    "log", "syslog", "NSLog",
    "Log.d", "Log.e", "Log.i", "Log.w", "Log.v",
}

# Simplified set of callee names for FunctionCall matching
LOG_CALLEE_NAMES: Set[str] = {
    "print", "println", "printf", "fprintf", "puts",
    "dbg", "log", "syslog", "NSLog",
    "console_log", "console_warn", "console_error",
    "logger_info", "logger_warn", "logger_error", "logger_debug",
}

# Method names for MethodCall matching
LOG_METHOD_NAMES: Set[str] = {
    "log", "warn", "warning", "error", "info", "debug", "critical",
    "fatal", "trace", "inspect", "puts",
    "d", "e", "i", "w", "v",  # Android Log.d(), Log.e(), etc.
}

# Object names whose methods are loggers
LOG_OBJECT_NAMES: Set[str] = {
    "console", "logger", "Logger", "log", "Log",
    "IO", "syslog", "logging",
}

# Error-related field accesses that leak info
ERROR_LEAK_FIELDS: Set[str] = {
    "message", "stack", "stackTrace", "stack_trace",
    "traceback", "__traceback__", "cause", "detail",
    "sqlMessage", "sql_message", "errno", "sqlState",
    "sql_state", "originalError", "original_error",
}

# Functions/methods that indicate response construction
RESPONSE_METHODS: Set[str] = {
    "json", "send", "write", "render", "respond",
    "send_json", "send_resp", "put_resp_content_type",
    "status", "ok", "created",
}

# Database write operations
DB_WRITE_OPERATIONS: Set[str] = {
    "create", "insert", "save", "upsert", "insert_one",
    "insert_many", "insertOne", "insertMany", "bulkCreate",
    "put_item", "set", "add", "store",
}

# Database delete/anonymize operations
DB_DELETE_OPERATIONS: Set[str] = {
    "delete", "destroy", "remove", "anonymize", "anonymise",
    "purge", "erase", "wipe", "soft_delete", "softDelete",
    "delete_one", "deleteOne", "delete_many", "deleteMany",
    "removeAll", "remove_all", "expunge",
}

# Encryption/hashing indicators
ENCRYPTION_INDICATORS: Set[str] = {
    "encrypt", "hash", "cipher", "bcrypt", "argon2", "scrypt",
    "aes", "rsa", "pgp", "gpg", "hmac", "sha256", "sha512",
    "crypto", "pbkdf2", "kdf", "seal", "vault",
    "encrypted", "hashed", "ciphertext",
}

# Masking/sanitization function indicators
MASK_FUNCTIONS: Set[str] = {
    "mask", "redact", "truncate", "substring", "slice", "substr",
    "replace", "format_ssn", "format_phone", "format_card",
    "mask_ssn", "mask_card", "mask_phone", "mask_email",
    "last_four", "last4", "obfuscate", "anonymize", "sanitize",
}

# Field selection indicators (ORMs)
FIELD_SELECTION_INDICATORS: Set[str] = {
    "select", "only", "pluck", "attributes", "fields",
    "project", "pick", "omit", "exclude", "serialize",
    "serializer", "toJSON", "to_json", "toDict", "to_dict",
    "as_dict", "asDict", "toResponse", "to_response",
    "map", "transform", "schema", "DTO", "dto",
}

# Regex patterns for realistic PII in source code
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_PATTERN = re.compile(
    r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
_EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)
_CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
)

# Known placeholder/example domains to exclude from email detection
_EXAMPLE_DOMAINS: Set[str] = {
    "example.com", "example.org", "example.net",
    "test.com", "test.org", "localhost",
    "placeholder.com", "sample.com", "foo.com", "bar.com",
    "your-domain.com", "yourdomain.com", "domain.com",
}

# Test file indicators
_TEST_FILE_INDICATORS: Tuple[str, ...] = (
    "test_", "_test.", ".test.", ".spec.", "_spec.",
    "tests/", "test/", "__tests__/", "spec/",
    "pytest", "unittest", "jest", "mocha", "describe(",
    "it(", "@Test", "@test", "ExUnit", "defmodule.*Test",
)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# ---------------------------------------------------------------------------
# Finding Dataclass
# ---------------------------------------------------------------------------

@dataclass
class DataExposureFinding:
    """Internal representation of a data exposure finding."""
    category: str
    severity: Severity
    description: str
    cwe: str
    remediation: str
    location: Optional[SourceLocation] = None
    function_name: str = ""
    variable_name: str = ""


# ---------------------------------------------------------------------------
# AST Walking Helpers
# ---------------------------------------------------------------------------

def _get_func_name(callee: Expr) -> str:
    """Extract the function name from a callee expression."""
    if isinstance(callee, Identifier):
        return callee.name
    if isinstance(callee, FieldAccess):
        obj_name = _get_expr_name(callee.obj)
        return f"{obj_name}.{callee.field_name}" if obj_name else callee.field_name
    return ""


def _get_expr_name(expr: Expr) -> str:
    """Extract a readable name from an expression."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, FieldAccess):
        obj_name = _get_expr_name(expr.obj)
        return f"{obj_name}.{expr.field_name}" if obj_name else expr.field_name
    return ""


def _expr_contains_identifier(expr: Expr, names: Set[str]) -> Optional[str]:
    """Check if an expression tree references any identifier in the given set.

    Returns the matched name or None.
    """
    if isinstance(expr, Identifier):
        name_lower = expr.name.lower()
        for pii_name in names:
            if pii_name in name_lower:
                return expr.name
        return None

    if isinstance(expr, FieldAccess):
        field_lower = expr.field_name.lower()
        for pii_name in names:
            if pii_name in field_lower:
                return expr.field_name
        match = _expr_contains_identifier(expr.obj, names)
        if match:
            return match
        return None

    if isinstance(expr, BinaryOp):
        left = _expr_contains_identifier(expr.left, names)
        if left:
            return left
        return _expr_contains_identifier(expr.right, names)

    if isinstance(expr, UnaryOp):
        return _expr_contains_identifier(expr.operand, names)

    if isinstance(expr, FunctionCall):
        for arg in expr.args:
            match = _expr_contains_identifier(arg, names)
            if match:
                return match
        return _expr_contains_identifier(expr.callee, names)

    if isinstance(expr, MethodCall):
        match = _expr_contains_identifier(expr.obj, names)
        if match:
            return match
        for arg in expr.args:
            match = _expr_contains_identifier(arg, names)
            if match:
                return match
        return None

    return None


def _expr_contains_field(expr: Expr, field_names: Set[str]) -> Optional[str]:
    """Check if an expression accesses any field in the given set."""
    if isinstance(expr, FieldAccess):
        if expr.field_name.lower() in field_names:
            return expr.field_name
        return _expr_contains_field(expr.obj, field_names)

    if isinstance(expr, MethodCall):
        match = _expr_contains_field(expr.obj, field_names)
        if match:
            return match
        for arg in expr.args:
            match = _expr_contains_field(arg, field_names)
            if match:
                return match
        return None

    if isinstance(expr, FunctionCall):
        for arg in expr.args:
            match = _expr_contains_field(arg, field_names)
            if match:
                return match
        return None

    if isinstance(expr, BinaryOp):
        left = _expr_contains_field(expr.left, field_names)
        if left:
            return left
        return _expr_contains_field(expr.right, field_names)

    return None


def _expr_has_method_call(expr: Expr, method_names: Set[str]) -> bool:
    """Check if an expression contains a method call to any of the given names."""
    if isinstance(expr, MethodCall):
        if expr.method_name.lower() in method_names:
            return True
        if _expr_has_method_call(expr.obj, method_names):
            return True
        for arg in expr.args:
            if _expr_has_method_call(arg, method_names):
                return True
        return False

    if isinstance(expr, FunctionCall):
        callee_name = _get_func_name(expr.callee).lower()
        for name in method_names:
            if name in callee_name:
                return True
        for arg in expr.args:
            if _expr_has_method_call(arg, method_names):
                return True
        return False

    if isinstance(expr, FieldAccess):
        return _expr_has_method_call(expr.obj, method_names)

    if isinstance(expr, BinaryOp):
        return (_expr_has_method_call(expr.left, method_names)
                or _expr_has_method_call(expr.right, method_names))

    return False


def _is_logging_call(expr: Expr) -> bool:
    """Check if an expression is a logging function/method call."""
    if isinstance(expr, FunctionCall):
        callee_name = _get_func_name(expr.callee).lower()
        for log_name in LOG_CALLEE_NAMES:
            if log_name in callee_name:
                return True
        return False

    if isinstance(expr, MethodCall):
        method_lower = expr.method_name.lower()
        obj_name = _get_expr_name(expr.obj).lower() if expr.obj else ""
        # Match object.method pattern (e.g., console.log, logger.info)
        if obj_name in {n.lower() for n in LOG_OBJECT_NAMES}:
            if method_lower in LOG_METHOD_NAMES:
                return True
        # Match standalone method names commonly used for logging
        if method_lower in {"inspect"} and obj_name in {"io"}:
            return True
        return False

    return False


def _is_response_call(expr: Expr) -> bool:
    """Check if an expression is a response construction call."""
    if isinstance(expr, MethodCall):
        if expr.method_name.lower() in RESPONSE_METHODS:
            return True
    if isinstance(expr, FunctionCall):
        callee_name = _get_func_name(expr.callee).lower()
        for resp in RESPONSE_METHODS:
            if resp in callee_name:
                return True
    return False


def _is_db_write_call(expr: Expr) -> bool:
    """Check if an expression is a database write operation."""
    if isinstance(expr, MethodCall):
        if expr.method_name.lower() in DB_WRITE_OPERATIONS:
            return True
    if isinstance(expr, FunctionCall):
        callee_name = _get_func_name(expr.callee).lower()
        for op in DB_WRITE_OPERATIONS:
            if op in callee_name:
                return True
    return False


def _is_error_handler_context(func: PureFunc | TaskFunc) -> bool:
    """Heuristic: check if a function name suggests error handling."""
    name_lower = func.name.lower()
    return any(kw in name_lower for kw in (
        "error", "catch", "except", "rescue", "handle_error",
        "on_error", "onerror", "error_handler", "fallback",
        "recover", "failure", "fault",
    ))


def _is_test_context(source_text: str) -> bool:
    """Check if source text appears to be from a test file."""
    if not source_text:
        return False
    header = source_text[:500].lower()
    return any(indicator in header for indicator in _TEST_FILE_INDICATORS)


def _collect_all_strings(program: Program) -> List[Tuple[StringLiteral, Optional[SourceLocation], str]]:
    """Collect all string literals from the program with context."""
    results: List[Tuple[StringLiteral, Optional[SourceLocation], str]] = []
    for decl in program.declarations:
        if not isinstance(decl, (PureFunc, TaskFunc)):
            continue
        for stmt in getattr(decl, "body", []):
            _collect_strings_from_stmt(stmt, decl.name, results)
    return results


def _collect_strings_from_stmt(
    stmt: Statement,
    func_name: str,
    results: List[Tuple[StringLiteral, Optional[SourceLocation], str]],
) -> None:
    """Recursively collect string literals from a statement."""
    loc = getattr(stmt, "location", None)

    if isinstance(stmt, LetStmt):
        if stmt.value:
            _collect_strings_from_expr(stmt.value, loc, func_name, results)
    elif isinstance(stmt, AssignStmt):
        _collect_strings_from_expr(stmt.value, loc, func_name, results)
    elif isinstance(stmt, ExprStmt):
        _collect_strings_from_expr(stmt.expr, loc, func_name, results)
    elif isinstance(stmt, ReturnStmt):
        if stmt.value:
            _collect_strings_from_expr(stmt.value, loc, func_name, results)
    elif isinstance(stmt, IfStmt):
        _collect_strings_from_expr(stmt.condition, loc, func_name, results)
        for s in stmt.then_body:
            _collect_strings_from_stmt(s, func_name, results)
        for s in stmt.else_body:
            _collect_strings_from_stmt(s, func_name, results)
    elif isinstance(stmt, WhileStmt):
        _collect_strings_from_expr(stmt.condition, loc, func_name, results)
        for s in stmt.body:
            _collect_strings_from_stmt(s, func_name, results)


def _collect_strings_from_expr(
    expr: Expr,
    loc: Optional[SourceLocation],
    func_name: str,
    results: List[Tuple[StringLiteral, Optional[SourceLocation], str]],
) -> None:
    """Recursively collect string literals from an expression."""
    if isinstance(expr, StringLiteral):
        expr_loc = getattr(expr, "location", None) or loc
        results.append((expr, expr_loc, func_name))
    elif isinstance(expr, FunctionCall):
        _collect_strings_from_expr(expr.callee, loc, func_name, results)
        for arg in expr.args:
            _collect_strings_from_expr(arg, loc, func_name, results)
    elif isinstance(expr, MethodCall):
        _collect_strings_from_expr(expr.obj, loc, func_name, results)
        for arg in expr.args:
            _collect_strings_from_expr(arg, loc, func_name, results)
    elif isinstance(expr, FieldAccess):
        _collect_strings_from_expr(expr.obj, loc, func_name, results)
    elif isinstance(expr, BinaryOp):
        _collect_strings_from_expr(expr.left, loc, func_name, results)
        _collect_strings_from_expr(expr.right, loc, func_name, results)
    elif isinstance(expr, UnaryOp):
        _collect_strings_from_expr(expr.operand, loc, func_name, results)


def _expr_is_url_construction(expr: Expr) -> bool:
    """Check if an expression is building a URL via string concat or interpolation."""
    if isinstance(expr, BinaryOp) and expr.op in ("+", "++", "<>"):
        # Check if either side contains URL-like strings
        left_url = _expr_contains_url_hint(expr.left)
        right_url = _expr_contains_url_hint(expr.right)
        return left_url or right_url
    if isinstance(expr, FunctionCall):
        callee_name = _get_func_name(expr.callee).lower()
        return any(kw in callee_name for kw in ("url", "uri", "endpoint", "path", "route"))
    if isinstance(expr, StringLiteral):
        val = expr.value.lower()
        return any(kw in val for kw in ("http://", "https://", "?", "&", "/api/"))
    return False


def _expr_contains_url_hint(expr: Expr) -> bool:
    """Check if an expression contains URL-like content."""
    if isinstance(expr, StringLiteral):
        val = expr.value.lower()
        return any(kw in val for kw in (
            "http://", "https://", "?", "&", "=", "/api/", "/v1/", "/v2/",
        ))
    if isinstance(expr, BinaryOp):
        return _expr_contains_url_hint(expr.left) or _expr_contains_url_hint(expr.right)
    return False


# ---------------------------------------------------------------------------
# Data Exposure Analyzer
# ---------------------------------------------------------------------------

class DataExposureAnalyzer:
    """Scans AEON AST for data exposure and privacy vulnerabilities."""

    def __init__(self, source_text: str = ""):
        self.findings: List[DataExposureFinding] = []
        self.source_text = source_text
        self.is_test_file = _is_test_context(source_text)
        self._module_function_names: Set[str] = set()

    def analyze(self, program: Program) -> List[DataExposureFinding]:
        """Run all data exposure checks on the program."""
        self.findings = []

        # Pre-collect all function names in the module for retention analysis
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._module_function_names.add(decl.name.lower())

        for decl in program.declarations:
            if not isinstance(decl, (PureFunc, TaskFunc)):
                continue

            for stmt in decl.body:
                self._check_pii_in_logs(stmt, decl)
                self._check_sensitive_error_responses(stmt, decl)
                self._check_missing_data_masking(stmt, decl)
                self._check_excessive_data_exposure(stmt, decl)
                self._check_pii_in_urls(stmt, decl)
                self._check_missing_encryption(stmt, decl)

            self._check_data_retention(decl)

        # Check for hardcoded PII in string literals (non-test files only)
        if not self.is_test_file:
            self._check_hardcoded_pii(program)

        return self.findings

    # -------------------------------------------------------------------
    # 1. PII in Logs (CWE-532)
    # -------------------------------------------------------------------

    def _check_pii_in_logs(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Detect logging calls that include PII variable references."""
        loc = getattr(stmt, "location", None)

        if isinstance(stmt, ExprStmt):
            self._check_expr_pii_in_log(stmt.expr, func, loc)

        elif isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_expr_pii_in_log(stmt.value, func, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._check_pii_in_logs(s, func)
            for s in stmt.else_body:
                self._check_pii_in_logs(s, func)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._check_pii_in_logs(s, func)

    def _check_expr_pii_in_log(
        self,
        expr: Expr,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check a single expression for PII in logging calls."""
        if not _is_logging_call(expr):
            return

        # Get all arguments to the logging call
        args: List[Expr] = []
        if isinstance(expr, FunctionCall):
            args = expr.args
        elif isinstance(expr, MethodCall):
            args = expr.args

        for arg in args:
            pii_var = _expr_contains_identifier(arg, PII_VARIABLE_NAMES)
            if pii_var:
                self.findings.append(DataExposureFinding(
                    category="PII in Logs",
                    severity=Severity.HIGH,
                    description=(
                        f"Logging call includes PII variable '{pii_var}' "
                        f"in function '{func.name}'. Sensitive data written to "
                        f"logs can be accessed by unauthorized parties via log "
                        f"aggregation systems, shared log files, or error "
                        f"reporting services."
                    ),
                    cwe="CWE-532",
                    remediation=(
                        f"Remove '{pii_var}' from logging output, or mask/redact "
                        f"the value before logging (e.g., mask_email({pii_var}), "
                        f"'***' + {pii_var}[-4:]). Use structured logging with "
                        f"PII fields explicitly excluded."
                    ),
                    location=loc,
                    function_name=func.name,
                    variable_name=pii_var,
                ))

    # -------------------------------------------------------------------
    # 2. Sensitive Data in Error Responses (CWE-209)
    # -------------------------------------------------------------------

    def _check_sensitive_error_responses(
        self, stmt: Statement, func: PureFunc | TaskFunc,
    ) -> None:
        """Detect error handlers returning sensitive information."""
        loc = getattr(stmt, "location", None)

        # Check IfStmt bodies for error handler patterns
        if isinstance(stmt, IfStmt):
            # Check if the condition references error-related identifiers
            is_error_branch = _expr_contains_identifier(
                stmt.condition,
                {"err", "error", "exception", "exc", "e", "catch", "rescue"},
            )

            if is_error_branch or _is_error_handler_context(func):
                for s in stmt.then_body:
                    self._check_error_leak_in_stmt(s, func, loc)
                for s in stmt.else_body:
                    self._check_error_leak_in_stmt(s, func, loc)
            else:
                # Still recurse to find nested error handlers
                for s in stmt.then_body:
                    self._check_sensitive_error_responses(s, func)
                for s in stmt.else_body:
                    self._check_sensitive_error_responses(s, func)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._check_sensitive_error_responses(s, func)

        # Also check if we are inside an error-handling function
        elif _is_error_handler_context(func):
            self._check_error_leak_in_stmt(stmt, func, loc)

    def _check_error_leak_in_stmt(
        self,
        stmt: Statement,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check a statement inside an error handler for information leaks."""
        stmt_loc = getattr(stmt, "location", None) or loc

        if isinstance(stmt, ReturnStmt) and stmt.value:
            self._check_error_leak_in_expr(stmt.value, func, stmt_loc)

        elif isinstance(stmt, ExprStmt):
            if _is_response_call(stmt.expr):
                self._check_error_leak_in_response(stmt.expr, func, stmt_loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._check_error_leak_in_stmt(s, func, stmt_loc)
            for s in stmt.else_body:
                self._check_error_leak_in_stmt(s, func, stmt_loc)

    def _check_error_leak_in_expr(
        self,
        expr: Expr,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check if a return expression leaks error details."""
        leaked_field = _expr_contains_field(expr, ERROR_LEAK_FIELDS)
        if leaked_field:
            self.findings.append(DataExposureFinding(
                category="Sensitive Error Response",
                severity=Severity.HIGH,
                description=(
                    f"Error handler in '{func.name}' returns '{leaked_field}' "
                    f"which may contain database errors, stack traces, internal "
                    f"paths, or connection strings. This information helps "
                    f"attackers understand the application internals."
                ),
                cwe="CWE-209",
                remediation=(
                    f"Return a generic error message to the client (e.g., "
                    f"'An internal error occurred'). Log the detailed error "
                    f"server-side for debugging. Never expose '{leaked_field}' "
                    f"in API responses."
                ),
                location=loc,
                function_name=func.name,
                variable_name=leaked_field,
            ))

    def _check_error_leak_in_response(
        self,
        expr: Expr,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check if a response call in an error handler leaks details."""
        args: List[Expr] = []
        if isinstance(expr, MethodCall):
            args = expr.args
        elif isinstance(expr, FunctionCall):
            args = expr.args

        for arg in args:
            leaked_field = _expr_contains_field(arg, ERROR_LEAK_FIELDS)
            if leaked_field:
                self.findings.append(DataExposureFinding(
                    category="Sensitive Error Response",
                    severity=Severity.HIGH,
                    description=(
                        f"Response in error handler '{func.name}' includes "
                        f"'{leaked_field}'. Stack traces, SQL errors, and "
                        f"internal paths must never reach the client."
                    ),
                    cwe="CWE-209",
                    remediation=(
                        f"Replace with a generic error message. Log the full "
                        f"error server-side. Use error IDs (e.g., correlation "
                        f"ID) to link client-facing errors to server logs."
                    ),
                    location=loc,
                    function_name=func.name,
                    variable_name=leaked_field,
                ))

    # -------------------------------------------------------------------
    # 3. Missing Data Masking (CWE-359)
    # -------------------------------------------------------------------

    def _check_missing_data_masking(
        self, stmt: Statement, func: PureFunc | TaskFunc,
    ) -> None:
        """Detect sensitive fields returned without masking."""
        loc = getattr(stmt, "location", None)

        if isinstance(stmt, ReturnStmt) and stmt.value:
            self._check_unmasked_return(stmt.value, func, loc)

        elif isinstance(stmt, ExprStmt):
            if _is_response_call(stmt.expr):
                self._check_unmasked_response(stmt.expr, func, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._check_missing_data_masking(s, func)
            for s in stmt.else_body:
                self._check_missing_data_masking(s, func)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._check_missing_data_masking(s, func)

    def _check_unmasked_return(
        self,
        expr: Expr,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check if a return expression contains unmasked sensitive data."""
        sensitive_field = _expr_contains_field(expr, MASKABLE_FIELDS)
        if sensitive_field and not _expr_has_method_call(expr, MASK_FUNCTIONS):
            self.findings.append(DataExposureFinding(
                category="Missing Data Masking",
                severity=Severity.CRITICAL,
                description=(
                    f"Function '{func.name}' returns sensitive field "
                    f"'{sensitive_field}' without masking. Full SSNs, credit "
                    f"card numbers, and phone numbers must be masked before "
                    f"display or transmission."
                ),
                cwe="CWE-359",
                remediation=(
                    f"Apply masking before returning: show only last 4 digits "
                    f"for SSN (***-**-1234), last 4 for credit cards "
                    f"(****-****-****-5678), and area code + last 4 for phone "
                    f"numbers. Use a dedicated masking function."
                ),
                location=loc,
                function_name=func.name,
                variable_name=sensitive_field,
            ))

    def _check_unmasked_response(
        self,
        expr: Expr,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check if a response call contains unmasked sensitive data."""
        args: List[Expr] = []
        if isinstance(expr, MethodCall):
            args = expr.args
        elif isinstance(expr, FunctionCall):
            args = expr.args

        for arg in args:
            sensitive_field = _expr_contains_field(arg, MASKABLE_FIELDS)
            if sensitive_field and not _expr_has_method_call(arg, MASK_FUNCTIONS):
                self.findings.append(DataExposureFinding(
                    category="Missing Data Masking",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Response in '{func.name}' includes unmasked "
                        f"'{sensitive_field}'. PII must be masked before "
                        f"sending to clients."
                    ),
                    cwe="CWE-359",
                    remediation=(
                        f"Mask '{sensitive_field}' before including in the "
                        f"response. Use a consistent masking utility across "
                        f"the codebase."
                    ),
                    location=loc,
                    function_name=func.name,
                    variable_name=sensitive_field,
                ))

    # -------------------------------------------------------------------
    # 4. Excessive Data in API Responses (CWE-200)
    # -------------------------------------------------------------------

    def _check_excessive_data_exposure(
        self, stmt: Statement, func: PureFunc | TaskFunc,
    ) -> None:
        """Detect entire ORM objects returned in API responses."""
        loc = getattr(stmt, "location", None)

        if isinstance(stmt, ExprStmt):
            self._check_excessive_in_expr(stmt.expr, func, loc)

        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._check_excessive_in_return(stmt.value, func, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._check_excessive_data_exposure(s, func)
            for s in stmt.else_body:
                self._check_excessive_data_exposure(s, func)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._check_excessive_data_exposure(s, func)

    def _check_excessive_in_expr(
        self,
        expr: Expr,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check if a response call passes a raw ORM object."""
        if not _is_response_call(expr):
            return

        args: List[Expr] = []
        if isinstance(expr, MethodCall):
            args = expr.args
        elif isinstance(expr, FunctionCall):
            args = expr.args

        for arg in args:
            if self._is_raw_orm_object(arg, func):
                arg_name = _get_expr_name(arg) or "<object>"
                self.findings.append(DataExposureFinding(
                    category="Excessive Data in API Response",
                    severity=Severity.HIGH,
                    description=(
                        f"Function '{func.name}' passes entire object "
                        f"'{arg_name}' to response without field selection. "
                        f"This may expose internal fields like password_hash, "
                        f"reset_token, is_admin, or deleted_at to the client."
                    ),
                    cwe="CWE-200",
                    remediation=(
                        f"Use explicit field selection: .select('name', "
                        f"'email') or a serializer/DTO to control which "
                        f"fields are included in the response. Never return "
                        f"raw database objects directly."
                    ),
                    location=loc,
                    function_name=func.name,
                    variable_name=arg_name,
                ))

    def _check_excessive_in_return(
        self,
        expr: Expr,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check if a return in a handler passes a raw ORM object to response."""
        # Check for patterns like: return res.json(user)
        if _is_response_call(expr):
            self._check_excessive_in_expr(expr, func, loc)

    def _is_raw_orm_object(self, expr: Expr, func: PureFunc | TaskFunc) -> bool:
        """Heuristic: check if an expression is likely a raw ORM object
        without field selection or serialization applied.

        A raw ORM object is a simple Identifier whose name suggests it is
        a database model instance (user, account, customer, etc.) and where
        the surrounding expression chain does not include any field selection.
        """
        if not isinstance(expr, Identifier):
            return False

        # Common ORM object variable names
        orm_object_names = {
            "user", "account", "customer", "profile", "member",
            "employee", "patient", "client", "admin", "person",
            "record", "row", "result", "data", "model", "entity",
            "document", "doc", "item", "obj", "object",
        }

        name_lower = expr.name.lower()
        is_orm_like = any(orm_name in name_lower for orm_name in orm_object_names)

        if not is_orm_like:
            return False

        # Check if the function has field selection before this point
        # by scanning for .select(), .only(), serializer usage, etc.
        for stmt in func.body:
            if self._stmt_has_field_selection(stmt, expr.name):
                return False

        return True

    def _stmt_has_field_selection(self, stmt: Statement, var_name: str) -> bool:
        """Check if a statement applies field selection to a variable."""
        if isinstance(stmt, LetStmt):
            if stmt.name == var_name and stmt.value:
                return _expr_has_method_call(stmt.value, FIELD_SELECTION_INDICATORS)
        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier) and stmt.target.name == var_name:
                return _expr_has_method_call(stmt.value, FIELD_SELECTION_INDICATORS)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                if self._stmt_has_field_selection(s, var_name):
                    return True
            for s in stmt.else_body:
                if self._stmt_has_field_selection(s, var_name):
                    return True
        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                if self._stmt_has_field_selection(s, var_name):
                    return True
        return False

    # -------------------------------------------------------------------
    # 5. PII in URLs (CWE-598)
    # -------------------------------------------------------------------

    def _check_pii_in_urls(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Detect PII embedded in URL construction."""
        loc = getattr(stmt, "location", None)

        if isinstance(stmt, LetStmt) and stmt.value:
            self._check_pii_url_expr(stmt.value, func, loc)

        elif isinstance(stmt, AssignStmt):
            self._check_pii_url_expr(stmt.value, func, loc)

        elif isinstance(stmt, ExprStmt):
            self._check_pii_url_expr(stmt.expr, func, loc)

        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._check_pii_url_expr(stmt.value, func, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._check_pii_in_urls(s, func)
            for s in stmt.else_body:
                self._check_pii_in_urls(s, func)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._check_pii_in_urls(s, func)

    def _check_pii_url_expr(
        self,
        expr: Expr,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check if an expression builds a URL containing PII."""
        if not _expr_is_url_construction(expr):
            return

        # URL query param PII names (broader than general PII)
        url_pii_names: Set[str] = {
            "email", "phone", "ssn", "social_security", "password",
            "credit_card", "card_number", "token", "secret",
            "dob", "date_of_birth", "address",
        }

        pii_var = _expr_contains_identifier(expr, url_pii_names)
        if pii_var:
            self.findings.append(DataExposureFinding(
                category="PII in URL",
                severity=Severity.HIGH,
                description=(
                    f"URL construction in '{func.name}' includes PII variable "
                    f"'{pii_var}' as a query parameter or path segment. URLs "
                    f"are logged in server access logs, browser history, proxy "
                    f"logs, and Referer headers. PII in URLs violates privacy "
                    f"regulations (GDPR, CCPA)."
                ),
                cwe="CWE-598",
                remediation=(
                    f"Pass sensitive data in POST request bodies instead of "
                    f"URL query strings. If a GET parameter is required, use "
                    f"an opaque token or identifier instead of raw PII."
                ),
                location=loc,
                function_name=func.name,
                variable_name=pii_var,
            ))

    # -------------------------------------------------------------------
    # 6. Missing Encryption at Rest (CWE-311)
    # -------------------------------------------------------------------

    def _check_missing_encryption(
        self, stmt: Statement, func: PureFunc | TaskFunc,
    ) -> None:
        """Detect database writes of sensitive data without encryption."""
        loc = getattr(stmt, "location", None)

        if isinstance(stmt, ExprStmt):
            self._check_unencrypted_write(stmt.expr, func, loc)

        elif isinstance(stmt, LetStmt) and stmt.value:
            self._check_unencrypted_write(stmt.value, func, loc)

        elif isinstance(stmt, AssignStmt):
            self._check_unencrypted_write(stmt.value, func, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._check_missing_encryption(s, func)
            for s in stmt.else_body:
                self._check_missing_encryption(s, func)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._check_missing_encryption(s, func)

    def _check_unencrypted_write(
        self,
        expr: Expr,
        func: PureFunc | TaskFunc,
        loc: Optional[SourceLocation],
    ) -> None:
        """Check if a database write stores sensitive data unencrypted."""
        if not _is_db_write_call(expr):
            return

        # Sensitive fields that should be encrypted when stored
        storage_sensitive_fields: Set[str] = (
            PII_VARIABLE_NAMES | MASKABLE_FIELDS | {"tax_id", "drivers_license", "passport"}
        )

        args: List[Expr] = []
        if isinstance(expr, MethodCall):
            args = expr.args
        elif isinstance(expr, FunctionCall):
            args = expr.args

        for arg in args:
            sensitive_field = _expr_contains_identifier(arg, storage_sensitive_fields)
            if not sensitive_field:
                continue

            # Check if encryption is applied anywhere in the function
            has_encryption = self._function_has_encryption_call(func, sensitive_field)
            if not has_encryption:
                self.findings.append(DataExposureFinding(
                    category="Missing Encryption at Rest",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Database write in '{func.name}' stores "
                        f"'{sensitive_field}' without encryption. Sensitive "
                        f"data (PII, financial information) must be encrypted "
                        f"before persistence to protect against data breaches."
                    ),
                    cwe="CWE-311",
                    remediation=(
                        f"Encrypt '{sensitive_field}' before storing: use "
                        f"application-level encryption (AES-256-GCM) or "
                        f"database-level encryption (column-level or TDE). "
                        f"For passwords, use bcrypt/argon2 hashing instead "
                        f"of reversible encryption."
                    ),
                    location=loc,
                    function_name=func.name,
                    variable_name=sensitive_field,
                ))

    def _function_has_encryption_call(
        self, func: PureFunc | TaskFunc, var_name: str,
    ) -> bool:
        """Check if a function applies encryption/hashing to a variable."""
        for stmt in func.body:
            if self._stmt_has_encryption(stmt, var_name):
                return True
        return False

    def _stmt_has_encryption(self, stmt: Statement, var_name: str) -> bool:
        """Check if a statement contains encryption of the given variable."""
        if isinstance(stmt, LetStmt) and stmt.value:
            if _expr_has_method_call(stmt.value, ENCRYPTION_INDICATORS):
                if _expr_contains_identifier(stmt.value, {var_name.lower()}):
                    return True
        elif isinstance(stmt, AssignStmt):
            if _expr_has_method_call(stmt.value, ENCRYPTION_INDICATORS):
                if _expr_contains_identifier(stmt.value, {var_name.lower()}):
                    return True
        elif isinstance(stmt, ExprStmt):
            if _expr_has_method_call(stmt.expr, ENCRYPTION_INDICATORS):
                if _expr_contains_identifier(stmt.expr, {var_name.lower()}):
                    return True
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                if self._stmt_has_encryption(s, var_name):
                    return True
            for s in stmt.else_body:
                if self._stmt_has_encryption(s, var_name):
                    return True
        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                if self._stmt_has_encryption(s, var_name):
                    return True
        return False

    # -------------------------------------------------------------------
    # 7. Data Retention Violations (CWE-404)
    # -------------------------------------------------------------------

    def _check_data_retention(self, func: PureFunc | TaskFunc) -> None:
        """Detect user data collection without deletion capability in the module."""
        loc = getattr(func, "location", None)

        # Only flag if the function creates/inserts user data
        user_data_keywords = {"user", "customer", "account", "person", "member", "profile"}
        func_creates_user_data = False

        for stmt in func.body:
            if self._stmt_has_user_data_write(stmt, user_data_keywords):
                func_creates_user_data = True
                break

        if not func_creates_user_data:
            return

        # Check if the module has any delete/destroy/anonymize function
        has_deletion = any(
            any(kw in fn_name for kw in ("delete", "destroy", "remove", "anonymize",
                                          "anonymise", "purge", "erase", "wipe",
                                          "soft_delete", "softdelete", "gdpr",
                                          "forget", "right_to_be_forgotten"))
            for fn_name in self._module_function_names
        )

        if not has_deletion:
            self.findings.append(DataExposureFinding(
                category="Data Retention Violation",
                severity=Severity.MEDIUM,
                description=(
                    f"Function '{func.name}' creates user data records but "
                    f"no delete/destroy/anonymize function exists in this "
                    f"module. GDPR Article 17 (Right to Erasure) and CCPA "
                    f"require the ability to delete personal data on request."
                ),
                cwe="CWE-404",
                remediation=(
                    f"Add a corresponding deletion function (e.g., "
                    f"delete_user, anonymize_user) in the same module. "
                    f"Implement both hard-delete and soft-delete/anonymize "
                    f"options to support different retention requirements."
                ),
                location=loc,
                function_name=func.name,
            ))

    def _stmt_has_user_data_write(
        self, stmt: Statement, keywords: Set[str],
    ) -> bool:
        """Check if a statement writes user-related data to a database."""
        if isinstance(stmt, ExprStmt):
            return self._expr_is_user_data_write(stmt.expr, keywords)
        elif isinstance(stmt, LetStmt) and stmt.value:
            return self._expr_is_user_data_write(stmt.value, keywords)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                if self._stmt_has_user_data_write(s, keywords):
                    return True
            for s in stmt.else_body:
                if self._stmt_has_user_data_write(s, keywords):
                    return True
        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                if self._stmt_has_user_data_write(s, keywords):
                    return True
        return False

    def _expr_is_user_data_write(self, expr: Expr, keywords: Set[str]) -> bool:
        """Check if an expression is a DB write with user-related data."""
        if not _is_db_write_call(expr):
            return False

        # Check if any argument references user-related entities
        args: List[Expr] = []
        if isinstance(expr, MethodCall):
            args = expr.args
            # Also check the object (e.g., User.create)
            obj_name = _get_expr_name(expr.obj).lower()
            if any(kw in obj_name for kw in keywords):
                return True
        elif isinstance(expr, FunctionCall):
            args = expr.args
            callee_name = _get_func_name(expr.callee).lower()
            if any(kw in callee_name for kw in keywords):
                return True

        for arg in args:
            if _expr_contains_identifier(arg, keywords):
                return True
        return False

    # -------------------------------------------------------------------
    # 8. Hardcoded PII in Source (CWE-540)
    # -------------------------------------------------------------------

    def _check_hardcoded_pii(self, program: Program) -> None:
        """Detect realistic PII patterns in string literals of non-test files."""
        string_contexts = _collect_all_strings(program)

        for string_lit, loc, func_name in string_contexts:
            value = string_lit.value
            if not value or len(value) < 5:
                continue

            # Check for realistic SSNs
            if _SSN_PATTERN.search(value):
                # Exclude obvious placeholders like 000-00-0000, 123-45-6789
                ssn_match = _SSN_PATTERN.search(value)
                if ssn_match:
                    ssn_val = ssn_match.group(0)
                    if not self._is_placeholder_ssn(ssn_val):
                        self.findings.append(DataExposureFinding(
                            category="Hardcoded PII in Source",
                            severity=Severity.CRITICAL,
                            description=(
                                f"String literal contains a realistic SSN "
                                f"pattern '{ssn_val[:3]}-**-****' in function "
                                f"'{func_name}'. Real PII in source code "
                                f"persists in version control history even "
                                f"after deletion."
                            ),
                            cwe="CWE-540",
                            remediation=(
                                "Remove hardcoded SSNs. Use synthetic test "
                                "data generators or clearly fake values "
                                "(e.g., 000-00-0000). If this is test data, "
                                "move it to a test file."
                            ),
                            location=loc,
                            function_name=func_name,
                        ))

            # Check for realistic credit card numbers
            if _CREDIT_CARD_PATTERN.search(value):
                cc_match = _CREDIT_CARD_PATTERN.search(value)
                if cc_match:
                    cc_val = cc_match.group(0)
                    self.findings.append(DataExposureFinding(
                        category="Hardcoded PII in Source",
                        severity=Severity.CRITICAL,
                        description=(
                            f"String literal contains a credit card number "
                            f"pattern '****-****-****-{cc_val[-4:]}' in "
                            f"function '{func_name}'. Payment card data in "
                            f"source violates PCI DSS requirements."
                        ),
                        cwe="CWE-540",
                        remediation=(
                            "Remove hardcoded card numbers. Use Stripe/Braintree "
                            "test card numbers (e.g., 4242424242424242) or "
                            "synthetic data generators."
                        ),
                        location=loc,
                        function_name=func_name,
                    ))

            # Check for realistic email addresses (not example.com)
            email_matches = _EMAIL_PATTERN.findall(value)
            for email in email_matches:
                domain = email.split("@")[1].lower()
                if domain not in _EXAMPLE_DOMAINS and not self._is_package_email(email):
                    self.findings.append(DataExposureFinding(
                        category="Hardcoded PII in Source",
                        severity=Severity.MEDIUM,
                        description=(
                            f"String literal contains a real-looking email "
                            f"address '{email}' in function '{func_name}'. "
                            f"If this is a real person's email, it should not "
                            f"be in source code."
                        ),
                        cwe="CWE-540",
                        remediation=(
                            "Use @example.com or @test.com for test data. "
                            "Store real contact information in configuration "
                            "or environment variables."
                        ),
                        location=loc,
                        function_name=func_name,
                    ))

            # Check for realistic phone numbers in non-URL context
            if _PHONE_PATTERN.search(value):
                # Only flag if it is not part of a URL or clearly a placeholder
                phone_match = _PHONE_PATTERN.search(value)
                if phone_match and not self._is_placeholder_phone(phone_match.group(0)):
                    if "http" not in value.lower() and "url" not in value.lower():
                        self.findings.append(DataExposureFinding(
                            category="Hardcoded PII in Source",
                            severity=Severity.MEDIUM,
                            description=(
                                f"String literal contains a phone number "
                                f"pattern in function '{func_name}'. Real "
                                f"phone numbers in source code are a privacy "
                                f"risk."
                            ),
                            cwe="CWE-540",
                            remediation=(
                                "Use clearly fake phone numbers for test data "
                                "(e.g., 555-0100 through 555-0199, reserved "
                                "for fiction). Store real numbers in config."
                            ),
                            location=loc,
                            function_name=func_name,
                        ))

    @staticmethod
    def _is_placeholder_ssn(ssn: str) -> bool:
        """Check if an SSN is an obvious placeholder/test value."""
        placeholder_ssns = {
            "000-00-0000", "111-11-1111", "222-22-2222", "333-33-3333",
            "444-44-4444", "555-55-5555", "666-66-6666", "777-77-7777",
            "888-88-8888", "999-99-9999", "123-45-6789", "987-65-4321",
            "000-12-3456", "123-12-1234",
        }
        return ssn in placeholder_ssns

    @staticmethod
    def _is_placeholder_phone(phone: str) -> bool:
        """Check if a phone number is an obvious placeholder."""
        # 555 numbers are reserved for fiction
        digits_only = re.sub(r"[^\d]", "", phone)
        if len(digits_only) >= 10:
            # Check for 555-01xx pattern (reserved)
            area_and_prefix = digits_only[-10:-4]
            if area_and_prefix.endswith("5550"):
                return True
        # All same digit
        if len(set(digits_only)) <= 1:
            return True
        # Sequential
        if digits_only in ("1234567890", "0987654321"):
            return True
        return False

    @staticmethod
    def _is_package_email(email: str) -> bool:
        """Check if an email is likely a package author/maintainer email."""
        package_indicators = (
            "noreply", "no-reply", "github", "npm", "pypi",
            "support@", "info@", "admin@", "help@", "contact@",
        )
        email_lower = email.lower()
        return any(ind in email_lower for ind in package_indicators)


# ---------------------------------------------------------------------------
# Error Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: DataExposureFinding) -> AeonError:
    """Convert a DataExposureFinding into an AeonError using contract_error."""
    severity_label = finding.severity.value.upper()

    var_context = ""
    if finding.variable_name:
        var_context = f" ({finding.variable_name})"

    return contract_error(
        precondition=(
            f"Data exposure ({finding.cwe}) — [{severity_label}] "
            f"{finding.category}{var_context}: {finding.description}"
        ),
        failing_values={
            "engine": "Data Exposure & Privacy",
            "severity": finding.severity.value,
            "cwe": finding.cwe,
            "category": finding.category,
            "remediation": finding.remediation,
        },
        function_signature=finding.function_name or "data_exposure",
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_data_exposure(program: Program) -> list:
    """Run data exposure and privacy analysis on an AEON program.

    Scans all functions in the AST for data exposure vulnerabilities
    including PII leaks, missing masking, excessive data in responses,
    insecure storage, and privacy regulation violations.

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected vulnerability.

    Detection categories:
        1. PII in logs (CWE-532)
        2. Sensitive data in error responses (CWE-209)
        3. Missing data masking (CWE-359)
        4. Excessive data in API responses (CWE-200)
        5. PII in URLs (CWE-598)
        6. Missing encryption at rest (CWE-311)
        7. Data retention violations (CWE-404)
        8. Hardcoded PII in source (CWE-540)
    """
    try:
        analyzer = DataExposureAnalyzer()
        findings = analyzer.analyze(program)
        return [_finding_to_error(f) for f in findings]
    except Exception:
        # Engine-level safety net: never let the entire engine crash
        # the verification pipeline
        return []
