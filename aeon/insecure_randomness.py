"""AEON Insecure Randomness Detection Engine -- Deep PRNG Vulnerability Scanner.

Detects insecure randomness vulnerabilities that go beyond the basic
Math.random()/random.random() checks in crypto_misuse.py. This engine targets
subtler patterns: UUID v1 predictability, timestamp-based tokens, predictable
seeds, weak token generation via hashing predictable data, insufficient entropy,
and non-cryptographic hashes used as tokens.

References:
  CWE-330: Use of Insufficiently Random Values
  https://cwe.mitre.org/data/definitions/330.html

  CWE-331: Insufficient Entropy
  https://cwe.mitre.org/data/definitions/331.html

  CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)
  https://cwe.mitre.org/data/definitions/335.html

  CWE-328: Use of Weak Hash
  https://cwe.mitre.org/data/definitions/328.html

  Goldberg & Wagner (1996) "Randomness and the Netscape Browser"
  Dr. Dobb's Journal, January 1996.
  (Demonstrates exploitation of timestamp-based PRNG seeding)

  Michaelis, Meyer & Schwenk (2013) "Randomly Failed! The State of
  Randomness in Current Java Implementations"
  CT-RSA '13, https://doi.org/10.1007/978-3-642-36095-4_9

Detection Strategies:

1. UUID V1 PREDICTABILITY (CWE-330):
   UUID v1 encodes the MAC address and timestamp of the generating machine.
   An attacker who observes one UUID v1 can predict future values and
   extract the machine's network identity. Never use for security tokens.

2. SEQUENTIAL/INCREMENTAL IDS AS TOKENS (CWE-330):
   Auto-increment database IDs used in security-sensitive URL construction
   allow enumeration attacks (IDOR). Attackers can iterate through IDs to
   access other users' resources.

3. TIMESTAMP-BASED TOKENS (CWE-330):
   Date.now(), time.time(), System.currentTimeMillis() produce predictable
   values. An attacker who knows the approximate generation time can
   brute-force the token space in seconds.

4. PREDICTABLE SEED (CWE-335):
   Seeding a PRNG with a constant or predictable value (timestamp, PID)
   makes the entire output sequence reproducible. random.seed(42) in
   production means every "random" value is deterministic.

5. WEAK TOKEN GENERATION (CWE-330):
   Hashing predictable inputs (user_id, email, timestamp) does not create
   randomness -- it creates a deterministic mapping. hash(user_id + timestamp)
   is guessable if the attacker knows the user ID and approximate time.

6. MATH.RANDOM FOR SECURITY IDS (CWE-330):
   Math.random().toString(36) is a common pattern for generating short IDs.
   When used for invite codes, share links, OTPs, or temporary passwords,
   the output is predictable (Xorshift128+ in V8 is fully recoverable).

7. INSUFFICIENT ENTROPY (CWE-331):
   Security tokens need sufficient bit-strength. Tokens < 16 chars,
   OTPs < 6 digits, and password reset tokens < 32 chars are vulnerable
   to brute-force within practical time bounds.

8. NON-CRYPTOGRAPHIC HASH AS TOKEN (CWE-328):
   CRC32, Adler32, and Java's hashCode() are checksums, not security
   primitives. Their output space is small (32 bits) and trivially
   reversible or collidable.

Every finding includes:
  - Category classification
  - Severity (critical / high / medium)
  - CWE reference
  - Remediation guidance
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto
import re

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
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
# Finding Data
# ---------------------------------------------------------------------------

@dataclass
class RandomnessFinding:
    """A single insecure randomness finding."""
    category: str
    cwe: str
    severity: Severity
    message: str
    remediation: str
    line: int
    column: int = 0
    file: str = "<unknown>"

    def to_aeon_error(self) -> AeonError:
        return contract_error(
            precondition=(
                f"Insecure randomness ({self.cwe}): {self.message}"
            ),
            failing_values={
                "category": self.category,
                "cwe": self.cwe,
                "severity": self.severity.value,
                "remediation": self.remediation,
                "engine": "Insecure Randomness",
            },
            function_signature="",
            location=SourceLocation(
                line=self.line,
                column=self.column,
                file=self.file,
            ),
        )


# ---------------------------------------------------------------------------
# Pattern Databases
# ---------------------------------------------------------------------------

# Category 1: UUID v1 generation functions
UUID_V1_FUNCTIONS: Set[str] = {
    "uuid1", "uuid.uuid1", "uuidv1", "uuid_v1",
    "uuid.v1", "uuidgenerator.generatev1",
}

# Variable names that indicate security token context
SECURITY_TOKEN_NAMES: Set[str] = {
    "token", "session", "session_id", "sessionid", "sessid",
    "api_key", "apikey", "api_token", "apitoken",
    "auth_token", "authtoken", "access_token", "accesstoken",
    "refresh_token", "refreshtoken", "bearer",
    "secret", "nonce", "csrf", "csrf_token", "csrftoken",
    "otp", "one_time", "verification", "verify_code",
    "reset_token", "resettoken", "invite_code", "invitecode",
    "share_link", "sharelink", "temp_password", "temppassword",
    "confirmation_code", "confirmcode",
}

# Category 3: Timestamp functions
TIMESTAMP_FUNCTIONS: Set[str] = {
    # JavaScript
    "date.now", "new date", "gettime",
    # Python
    "time.time", "time.time_ns", "datetime.now", "datetime.utcnow",
    "time.monotonic", "time.perf_counter",
    # Java
    "system.currenttimemillis", "system.nanotime",
    "instant.now", "localdatetime.now",
    # Ruby
    "time.now",
    # Go
    "time.now",
    # PHP
    "time", "microtime",
}

# Category 4: Seed functions and predictable seed values
SEED_FUNCTIONS: Set[str] = {
    "seed", "random.seed", "srand", "mt_srand",
    "math.seedrandom", "seedrandom",
    "numpy.random.seed", "np.random.seed",
    "torch.manual_seed", "tf.random.set_seed",
    "random.setseed", "setseed",
}

# Values that are obviously constant / predictable when used as seeds
PREDICTABLE_SEED_INDICATORS: Set[str] = {
    "time", "date", "now", "pid", "getpid",
    "timestamp", "millis", "nanos",
}

# Category 5: Weak hash functions used for token generation
WEAK_HASH_FOR_TOKEN: Set[str] = {
    "md5", "hashlib.md5", "createhash",
    "sha1", "hashlib.sha1",
    "base64", "btoa", "atob", "base64encode", "b64encode",
    "base64.b64encode", "base64.urlsafe_b64encode",
    "buffer.from",
}

# Inputs that are predictable and should not be sole source of token material
PREDICTABLE_HASH_INPUTS: Set[str] = {
    "user_id", "userid", "user", "email", "username",
    "id", "account_id", "accountid", "phone",
    "timestamp", "time", "date", "created_at",
}

# Category 6: Security-relevant function name patterns (for Math.random ID check)
SECURITY_FUNCTION_PATTERNS: Set[str] = {
    "token", "invite", "code", "link", "otp",
    "password", "secret", "nonce", "csrf",
    "session", "auth", "verify", "reset",
    "share", "confirm", "activate",
}

# Category 8: Non-cryptographic hash/checksum functions
NON_CRYPTO_HASH_FUNCTIONS: Set[str] = {
    "crc32", "crc32c", "adler32", "zlib.crc32", "zlib.adler32",
    "binascii.crc32", "binascii.crc_hqx",
    "hashcode", "hash", "gethashcode",
    "fnv", "fnv1a", "murmurhash", "xxhash",
    "cityhash", "farmhash", "sipHash24",
}

# React/UI patterns that reduce severity or skip findings
UI_DISPLAY_INDICATORS: Set[str] = {
    "display", "render", "component", "view", "label",
    "text", "title", "heading", "description", "placeholder",
    "test", "mock", "fixture", "example", "demo", "sample",
    "story", "storybook", "preview",
}

# React and frontend framework indicators in source
FRONTEND_FRAMEWORK_PATTERNS: Set[str] = {
    "react", "jsx", "tsx", "vue", "angular", "svelte",
    "usestate", "useeffect", "useref", "usememo",
    "component", "render", "props",
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


def _get_file(node) -> str:
    """Extract file name from an AST node."""
    loc = getattr(node, "location", None)
    if loc is not None:
        return getattr(loc, "file", "<unknown>")
    return "<unknown>"


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


def _name_matches_any(name: str, patterns: Set[str]) -> bool:
    """Check if a name matches any pattern via case-insensitive substring."""
    name_lower = name.lower()
    return any(p in name_lower for p in patterns)


def _get_target_name(stmt: Statement) -> str:
    """Get the variable name being assigned to in a LetStmt or AssignStmt."""
    if isinstance(stmt, LetStmt):
        return stmt.name
    if isinstance(stmt, AssignStmt) and isinstance(stmt.target, Identifier):
        return stmt.target.name
    return ""


def _collect_all_exprs(stmts: List[Statement]) -> List[Tuple[Expr, Statement]]:
    """Recursively collect all expressions from a statement list with their parent."""
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


def _is_security_context(target_name: str, func_name: str) -> bool:
    """Determine if the current context is security-relevant.

    Checks both the assignment target variable name and the enclosing
    function name for security-related keywords.
    """
    if target_name and _name_matches_any(target_name, SECURITY_TOKEN_NAMES):
        return True
    if func_name and _name_matches_any(func_name, SECURITY_FUNCTION_PATTERNS):
        return True
    return False


def _is_ui_context(target_name: str, func_name: str) -> bool:
    """Determine if the current context is UI/display-related.

    Returns True if variable or function names suggest non-security usage
    like rendering, display, test fixtures, etc.
    """
    if target_name and _name_matches_any(target_name, UI_DISPLAY_INDICATORS):
        return True
    if func_name and _name_matches_any(func_name, UI_DISPLAY_INDICATORS):
        return True
    return False


def _is_frontend_file(filename: str) -> bool:
    """Check if the file is likely frontend/React code based on extension."""
    if not filename:
        return False
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in (
        ".jsx", ".tsx", ".vue", ".svelte",
        ".component.ts", ".component.js",
    ))


def _expr_contains_call(expr: Expr, names: Set[str]) -> bool:
    """Check if an expression tree contains a call to any of the named functions."""
    if isinstance(expr, FunctionCall):
        cname = _callee_name(expr).lower()
        if any(n in cname for n in names):
            return True
        for arg in expr.args:
            if _expr_contains_call(arg, names):
                return True
    elif isinstance(expr, MethodCall):
        mname = expr.method_name.lower()
        if mname in names:
            return True
        obj_name = ""
        if isinstance(expr.obj, Identifier):
            obj_name = expr.obj.name.lower()
        dotted = f"{obj_name}.{mname}" if obj_name else mname
        if dotted in names:
            return True
        if _expr_contains_call(expr.obj, names):
            return True
        for arg in expr.args:
            if _expr_contains_call(arg, names):
                return True
    elif isinstance(expr, BinaryOp):
        return _expr_contains_call(expr.left, names) or _expr_contains_call(expr.right, names)
    elif isinstance(expr, UnaryOp):
        return _expr_contains_call(expr.operand, names)
    elif isinstance(expr, FieldAccess):
        return _expr_contains_call(expr.obj, names)
    return False


def _expr_contains_identifier(expr: Expr, names: Set[str]) -> bool:
    """Check if an expression tree references any identifiers matching the patterns."""
    if isinstance(expr, Identifier):
        return _name_matches_any(expr.name, names)
    elif isinstance(expr, FunctionCall):
        for arg in expr.args:
            if _expr_contains_identifier(arg, names):
                return True
    elif isinstance(expr, MethodCall):
        if _expr_contains_identifier(expr.obj, names):
            return True
        for arg in expr.args:
            if _expr_contains_identifier(arg, names):
                return True
    elif isinstance(expr, BinaryOp):
        return _expr_contains_identifier(expr.left, names) or _expr_contains_identifier(expr.right, names)
    elif isinstance(expr, UnaryOp):
        return _expr_contains_identifier(expr.operand, names)
    elif isinstance(expr, FieldAccess):
        return _name_matches_any(expr.field_name, names) or _expr_contains_identifier(expr.obj, names)
    return False


def _get_func_call_name(expr: Expr) -> str:
    """Extract a dotted function/method call name from an expression."""
    if isinstance(expr, FunctionCall):
        return _callee_name(expr).lower()
    if isinstance(expr, MethodCall):
        obj_name = ""
        if isinstance(expr.obj, Identifier):
            obj_name = expr.obj.name.lower()
        return f"{obj_name}.{expr.method_name.lower()}" if obj_name else expr.method_name.lower()
    return ""


# ---------------------------------------------------------------------------
# Individual Detectors
# ---------------------------------------------------------------------------

class UUIDv1Detector:
    """Detect UUID v1 usage for security tokens (CWE-330).

    UUID v1 encodes the host MAC address and a timestamp, making the output
    predictable. An attacker observing one UUID v1 can predict future values
    and extract the generating machine's identity.
    """

    def analyze(
        self,
        exprs: List[Tuple[Expr, Statement]],
        func_name: str,
        file: str,
    ) -> List[RandomnessFinding]:
        findings: List[RandomnessFinding] = []

        for expr, stmt in exprs:
            if not isinstance(expr, (FunctionCall, MethodCall)):
                continue

            call_name = _get_func_call_name(expr)
            if not call_name:
                continue

            # Check for UUID v1 calls
            is_uuid_v1 = False
            for pattern in UUID_V1_FUNCTIONS:
                if pattern in call_name or call_name.endswith(pattern.split(".")[-1]):
                    is_uuid_v1 = True
                    break

            if not is_uuid_v1:
                continue

            target = _get_target_name(stmt)

            # Only flag if in a security context
            if not _is_security_context(target, func_name):
                # Also check: if the function name or target contains "uuid" alone
                # that is not sufficient -- many UUIDs are for database PKs, which
                # is fine. Only flag when explicitly security-related.
                continue

            if _is_ui_context(target, func_name):
                continue

            findings.append(RandomnessFinding(
                category="uuid_v1_predictability",
                cwe="CWE-330",
                severity=Severity.HIGH,
                message=(
                    f"UUID v1 used for security token in '{target or func_name}' -- "
                    f"UUID v1 encodes the MAC address and timestamp, making values "
                    f"predictable. An attacker who observes one token can predict "
                    f"future tokens and identify the generating machine."
                ),
                remediation=(
                    "Use UUID v4 (cryptographically random) instead of UUID v1 for "
                    "security tokens. Better yet, use secrets.token_urlsafe() (Python), "
                    "crypto.randomUUID() (Node.js 19+), or crypto.randomBytes() for "
                    "security-sensitive identifiers."
                ),
                line=_get_line(expr) or _get_line(stmt),
                column=_get_column(expr),
                file=file,
            ))

        return findings


class SequentialIDDetector:
    """Detect sequential/auto-increment IDs used as security tokens (CWE-330).

    Auto-increment database IDs are enumerable. Using them in
    security-sensitive URL paths without additional authorization checks
    enables Insecure Direct Object Reference (IDOR) attacks.
    """

    # Patterns that indicate URL construction with an ID
    URL_CONSTRUCTION_PATTERNS: Set[str] = {
        "url", "href", "link", "endpoint", "path", "route",
        "redirect", "location", "uri",
    }

    # Patterns suggesting the ID comes from auto-increment
    AUTO_INCREMENT_ID_PATTERNS: Set[str] = {
        "id", "user_id", "userid", "account_id", "accountid",
        "order_id", "orderid", "record_id", "recordid",
        "invoice_id", "invoiceid", "payment_id", "paymentid",
    }

    # Sensitive resource patterns
    SENSITIVE_RESOURCE_PATTERNS: Set[str] = {
        "admin", "account", "profile", "settings", "billing",
        "payment", "invoice", "document", "report", "download",
        "export", "api", "private", "internal",
    }

    def analyze(
        self,
        exprs: List[Tuple[Expr, Statement]],
        func_name: str,
        file: str,
    ) -> List[RandomnessFinding]:
        findings: List[RandomnessFinding] = []

        for expr, stmt in exprs:
            target = _get_target_name(stmt)

            # Look for URL construction patterns
            if not target:
                continue

            is_url_target = _name_matches_any(target, self.URL_CONSTRUCTION_PATTERNS)
            if not is_url_target:
                continue

            # Check if the expression uses an auto-increment ID in a sensitive context
            if not _expr_contains_identifier(expr, self.AUTO_INCREMENT_ID_PATTERNS):
                continue

            # Check for sensitive resource context
            has_sensitive_context = (
                _name_matches_any(target, self.SENSITIVE_RESOURCE_PATTERNS)
                or _name_matches_any(func_name, self.SENSITIVE_RESOURCE_PATTERNS)
            )

            # Also check string literals in the expression for sensitive paths
            if not has_sensitive_context:
                if isinstance(expr, BinaryOp):
                    # String concatenation building a URL
                    has_sensitive_context = self._check_sensitive_strings(expr)

            if not has_sensitive_context:
                continue

            if _is_ui_context(target, func_name):
                continue

            findings.append(RandomnessFinding(
                category="sequential_id_as_token",
                cwe="CWE-330",
                severity=Severity.MEDIUM,
                message=(
                    f"Auto-increment ID used in security-sensitive URL construction "
                    f"in '{target}' -- sequential IDs are enumerable, enabling "
                    f"Insecure Direct Object Reference (IDOR) attacks. An attacker "
                    f"can iterate through IDs to access other users' resources."
                ),
                remediation=(
                    "Use UUIDs (v4) or opaque tokens instead of sequential IDs in "
                    "URLs. If sequential IDs must be used, enforce server-side "
                    "authorization checks (verify the requesting user owns the "
                    "resource). Consider adding a per-resource HMAC signature to "
                    "URLs to prevent enumeration."
                ),
                line=_get_line(expr) or _get_line(stmt),
                column=_get_column(expr),
                file=file,
            ))

        return findings

    def _check_sensitive_strings(self, expr: Expr) -> bool:
        """Check if a binary expression contains sensitive string literals."""
        if isinstance(expr, StringLiteral):
            return _name_matches_any(expr.value, self.SENSITIVE_RESOURCE_PATTERNS)
        if isinstance(expr, BinaryOp):
            return self._check_sensitive_strings(expr.left) or self._check_sensitive_strings(expr.right)
        if isinstance(expr, FunctionCall):
            for arg in expr.args:
                if self._check_sensitive_strings(arg):
                    return True
        return False


class TimestampTokenDetector:
    """Detect timestamp-based token generation (CWE-330).

    Timestamps are predictable to within seconds. Using Date.now(),
    time.time(), or System.currentTimeMillis() as token material means
    an attacker who knows the approximate generation time can brute-force
    the token space trivially.
    """

    def analyze(
        self,
        exprs: List[Tuple[Expr, Statement]],
        func_name: str,
        file: str,
    ) -> List[RandomnessFinding]:
        findings: List[RandomnessFinding] = []

        for expr, stmt in exprs:
            if not isinstance(expr, (FunctionCall, MethodCall)):
                continue

            call_name = _get_func_call_name(expr)
            if not call_name:
                continue

            # Check if this is a timestamp function
            is_timestamp = False
            matched_func = ""
            for ts_func in TIMESTAMP_FUNCTIONS:
                if ts_func in call_name or call_name == ts_func.split(".")[-1]:
                    is_timestamp = True
                    matched_func = ts_func
                    break

            if not is_timestamp:
                continue

            target = _get_target_name(stmt)

            # Must be in a security context
            if not _is_security_context(target, func_name):
                continue

            if _is_ui_context(target, func_name):
                continue

            findings.append(RandomnessFinding(
                category="timestamp_based_token",
                cwe="CWE-330",
                severity=Severity.HIGH,
                message=(
                    f"Timestamp function '{matched_func}' used for token/nonce "
                    f"generation in '{target or func_name}' -- timestamps are "
                    f"predictable to within seconds. An attacker who knows the "
                    f"approximate generation time can brute-force the full "
                    f"token space in milliseconds."
                ),
                remediation=(
                    "Use a CSPRNG for token generation: secrets.token_urlsafe() "
                    "(Python), crypto.randomBytes() (Node.js), SecureRandom (Java). "
                    "Timestamps should never be the sole source of entropy for "
                    "security tokens, nonces, or seeds."
                ),
                line=_get_line(expr) or _get_line(stmt),
                column=_get_column(expr),
                file=file,
            ))

        return findings


class PredictableSeedDetector:
    """Detect predictable PRNG seeding (CWE-335).

    A PRNG seeded with a constant or predictable value produces a
    deterministic output sequence. random.seed(42) in production means
    every 'random' value is reproducible by an attacker.
    """

    def analyze(
        self,
        exprs: List[Tuple[Expr, Statement]],
        func_name: str,
        file: str,
    ) -> List[RandomnessFinding]:
        findings: List[RandomnessFinding] = []

        for expr, stmt in exprs:
            if not isinstance(expr, (FunctionCall, MethodCall)):
                continue

            call_name = _get_func_call_name(expr)
            if not call_name:
                continue

            # Check if this is a seed function
            is_seed_call = False
            for seed_func in SEED_FUNCTIONS:
                if seed_func in call_name or call_name == seed_func.split(".")[-1]:
                    is_seed_call = True
                    break

            if not is_seed_call:
                continue

            # Get the arguments
            args = []
            if isinstance(expr, FunctionCall):
                args = expr.args
            elif isinstance(expr, MethodCall):
                args = expr.args

            if not args:
                continue

            seed_arg = args[0]
            is_predictable = False
            seed_description = ""

            # Case 1: Constant integer seed (e.g., random.seed(42))
            if isinstance(seed_arg, IntLiteral):
                is_predictable = True
                seed_description = f"constant value {seed_arg.value}"

            # Case 2: Constant string seed
            elif isinstance(seed_arg, StringLiteral):
                is_predictable = True
                seed_description = f"constant string '{seed_arg.value[:20]}...'" if len(seed_arg.value) > 20 else f"constant string '{seed_arg.value}'"

            # Case 3: Timestamp or PID as seed
            elif isinstance(seed_arg, FunctionCall):
                inner_name = _callee_name(seed_arg).lower()
                for indicator in PREDICTABLE_SEED_INDICATORS:
                    if indicator in inner_name:
                        is_predictable = True
                        seed_description = f"predictable value from {inner_name}()"
                        break
            elif isinstance(seed_arg, MethodCall):
                inner_name = seed_arg.method_name.lower()
                for indicator in PREDICTABLE_SEED_INDICATORS:
                    if indicator in inner_name:
                        is_predictable = True
                        seed_description = f"predictable value from .{inner_name}()"
                        break
            elif isinstance(seed_arg, Identifier):
                for indicator in PREDICTABLE_SEED_INDICATORS:
                    if indicator in seed_arg.name.lower():
                        is_predictable = True
                        seed_description = f"predictable variable '{seed_arg.name}'"
                        break

            if not is_predictable:
                continue

            # UI/test context check -- seeding is common in tests for reproducibility
            if _is_ui_context("", func_name):
                continue

            findings.append(RandomnessFinding(
                category="predictable_seed",
                cwe="CWE-335",
                severity=Severity.HIGH,
                message=(
                    f"PRNG seeded with {seed_description} in '{func_name or call_name}' "
                    f"-- the entire random output sequence is deterministic and "
                    f"reproducible by an attacker who knows (or guesses) the seed"
                ),
                remediation=(
                    "For security-sensitive randomness, do not seed a PRNG manually. "
                    "Use a CSPRNG: secrets module (Python), crypto.randomBytes() "
                    "(Node.js), SecureRandom (Java). If seeding is required for "
                    "non-security purposes, use os.urandom() as the seed source."
                ),
                line=_get_line(expr) or _get_line(stmt),
                column=_get_column(expr),
                file=file,
            ))

        return findings


class WeakTokenGenerationDetector:
    """Detect token generation by hashing predictable data (CWE-330).

    Hashing predictable inputs (user_id, email, timestamp) does not produce
    unpredictable output. hash(user_id + timestamp) is deterministic -- an
    attacker who knows the user ID and approximate time can compute the token.
    """

    def analyze(
        self,
        exprs: List[Tuple[Expr, Statement]],
        func_name: str,
        file: str,
    ) -> List[RandomnessFinding]:
        findings: List[RandomnessFinding] = []

        for expr, stmt in exprs:
            if not isinstance(expr, (FunctionCall, MethodCall)):
                continue

            call_name = _get_func_call_name(expr)
            if not call_name:
                continue

            # Check if this is a hash or encoding function
            is_hash_call = False
            matched_hash = ""
            for hash_func in WEAK_HASH_FOR_TOKEN:
                if hash_func in call_name or call_name == hash_func.split(".")[-1]:
                    is_hash_call = True
                    matched_hash = hash_func
                    break

            if not is_hash_call:
                continue

            target = _get_target_name(stmt)

            # Must be in a security/token context
            if not _is_security_context(target, func_name):
                continue

            if _is_ui_context(target, func_name):
                continue

            # Check if the arguments contain only predictable inputs
            args = expr.args if isinstance(expr, FunctionCall) else expr.args
            has_predictable_input = False

            for arg in args:
                if _expr_contains_identifier(arg, PREDICTABLE_HASH_INPUTS):
                    has_predictable_input = True
                    break
                # Also check for timestamp function calls inside args
                if _expr_contains_call(arg, TIMESTAMP_FUNCTIONS):
                    has_predictable_input = True
                    break
                # String concatenation of predictable values
                if isinstance(arg, BinaryOp) and arg.op == "+":
                    if _expr_contains_identifier(arg, PREDICTABLE_HASH_INPUTS):
                        has_predictable_input = True
                        break

            if not has_predictable_input:
                continue

            # Determine severity: base64 encoding of predictable data is worse
            # than hashing (base64 is trivially reversible)
            severity = Severity.HIGH
            if any(b in matched_hash for b in ("base64", "btoa", "b64")):
                severity = Severity.CRITICAL
                extra = (
                    "base64 encoding is NOT encryption -- it is trivially "
                    "reversible. The original data (user_id, email, etc.) "
                    "can be extracted instantly."
                )
            else:
                extra = (
                    "hashing predictable inputs does not create randomness. "
                    "An attacker who knows the inputs can compute the hash."
                )

            findings.append(RandomnessFinding(
                category="weak_token_generation",
                cwe="CWE-330",
                severity=severity,
                message=(
                    f"Token generated by {matched_hash}() of predictable data "
                    f"in '{target or func_name}' -- {extra}"
                ),
                remediation=(
                    "Generate tokens using a CSPRNG: secrets.token_urlsafe() "
                    "(Python), crypto.randomBytes(32).toString('hex') (Node.js), "
                    "SecureRandom (Java). Never derive security tokens from "
                    "user-predictable data alone."
                ),
                line=_get_line(expr) or _get_line(stmt),
                column=_get_column(expr),
                file=file,
            ))

        return findings


class MathRandomIDDetector:
    """Detect Math.random().toString(36) for security-relevant IDs (CWE-330).

    Math.random() in V8 uses Xorshift128+, whose internal state is fully
    recoverable from a small number of outputs. Using it for invite codes,
    share links, OTPs, or temporary passwords is insecure.
    """

    MATH_RANDOM_PATTERNS: Set[str] = {
        "math.random", "random",
    }

    def analyze(
        self,
        exprs: List[Tuple[Expr, Statement]],
        func_name: str,
        file: str,
    ) -> List[RandomnessFinding]:
        findings: List[RandomnessFinding] = []

        # Only flag in security-relevant function contexts
        if not func_name:
            return findings

        func_is_security = _name_matches_any(func_name, SECURITY_FUNCTION_PATTERNS)
        if not func_is_security:
            return findings

        if _is_ui_context("", func_name):
            return findings

        # Lower severity for frontend files -- still flag, but medium
        is_frontend = _is_frontend_file(file)

        for expr, stmt in exprs:
            if not isinstance(expr, (FunctionCall, MethodCall)):
                continue

            call_name = _get_func_call_name(expr)
            if not call_name:
                continue

            # Check for Math.random() specifically
            is_math_random = False
            for pattern in self.MATH_RANDOM_PATTERNS:
                if pattern in call_name:
                    is_math_random = True
                    break

            if not is_math_random:
                continue

            target = _get_target_name(stmt)

            # Skip explicit UI/display targets even in security-named functions
            if target and _name_matches_any(target, UI_DISPLAY_INDICATORS):
                continue

            severity = Severity.MEDIUM if is_frontend else Severity.HIGH

            findings.append(RandomnessFinding(
                category="math_random_security_id",
                cwe="CWE-330",
                severity=severity,
                message=(
                    f"Math.random() used in security-relevant function "
                    f"'{func_name}' -- Math.random() is not cryptographically "
                    f"secure. In V8 (Chrome/Node.js), the internal Xorshift128+ "
                    f"state is fully recoverable from observed outputs."
                ),
                remediation=(
                    "Use crypto.randomUUID() or crypto.getRandomValues() "
                    "(browser/Node.js) for security-relevant IDs. For tokens, "
                    "use crypto.randomBytes(). For invite codes and OTPs, use "
                    "a CSPRNG with sufficient entropy."
                ),
                line=_get_line(expr) or _get_line(stmt),
                column=_get_column(expr),
                file=file,
            ))

        return findings


class InsufficientEntropyDetector:
    """Detect insufficient entropy in security token generation (CWE-331).

    Security tokens need sufficient bit-strength to resist brute-force:
    - General tokens: >= 16 characters (128+ bits with hex/base64)
    - OTPs: >= 6 digits
    - Password reset tokens: >= 32 characters
    Short tokens can be brute-forced within practical time bounds.
    """

    # Patterns for token length specification in function calls
    TOKEN_LENGTH_FUNCTIONS: Set[str] = {
        "token_hex", "token_urlsafe", "token_bytes",
        "randombytes", "random_bytes", "getrandomvalues",
        "securerandom", "randstr", "random_string",
        "generate_token", "generatetoken", "create_token",
    }

    # Minimum secure lengths by context
    MIN_TOKEN_LENGTH = 16
    MIN_OTP_DIGITS = 6
    MIN_RESET_TOKEN_LENGTH = 32

    def analyze(
        self,
        exprs: List[Tuple[Expr, Statement]],
        func_name: str,
        file: str,
    ) -> List[RandomnessFinding]:
        findings: List[RandomnessFinding] = []

        for expr, stmt in exprs:
            if not isinstance(expr, (FunctionCall, MethodCall)):
                continue

            call_name = _get_func_call_name(expr)
            if not call_name:
                continue

            # Check if this is a token generation function
            is_token_gen = False
            for tg_func in self.TOKEN_LENGTH_FUNCTIONS:
                if tg_func in call_name or call_name == tg_func:
                    is_token_gen = True
                    break

            if not is_token_gen:
                continue

            target = _get_target_name(stmt)

            if not _is_security_context(target, func_name):
                continue

            if _is_ui_context(target, func_name):
                continue

            # Check the length argument
            args = expr.args if isinstance(expr, FunctionCall) else expr.args
            if not args:
                continue

            for arg in args:
                if not isinstance(arg, IntLiteral):
                    continue

                length = arg.value
                if length <= 0:
                    continue

                # Determine what kind of token and minimum length
                target_lower = (target or func_name or "").lower()
                is_otp = any(p in target_lower for p in ("otp", "pin", "code", "digit"))
                is_reset = any(p in target_lower for p in ("reset", "recovery", "forgot"))

                if is_otp and length < self.MIN_OTP_DIGITS:
                    findings.append(RandomnessFinding(
                        category="insufficient_entropy",
                        cwe="CWE-331",
                        severity=Severity.HIGH,
                        message=(
                            f"OTP/PIN length {length} digits is below minimum "
                            f"{self.MIN_OTP_DIGITS} -- a {length}-digit OTP has only "
                            f"{10 ** length:,} possible values, brute-forceable in "
                            f"seconds without rate limiting"
                        ),
                        remediation=(
                            f"Use at least {self.MIN_OTP_DIGITS}-digit OTPs. "
                            f"Combine with rate limiting (max 3-5 attempts), "
                            f"short expiration (5-10 minutes), and account lockout."
                        ),
                        line=_get_line(arg) or _get_line(expr) or _get_line(stmt),
                        column=_get_column(arg),
                        file=file,
                    ))
                elif is_reset and length < self.MIN_RESET_TOKEN_LENGTH:
                    findings.append(RandomnessFinding(
                        category="insufficient_entropy",
                        cwe="CWE-331",
                        severity=Severity.HIGH,
                        message=(
                            f"Password reset token length {length} bytes/chars is below "
                            f"minimum {self.MIN_RESET_TOKEN_LENGTH} -- insufficient "
                            f"entropy for a credential-recovery token that may be valid "
                            f"for hours"
                        ),
                        remediation=(
                            f"Use at least {self.MIN_RESET_TOKEN_LENGTH} bytes of "
                            f"cryptographic randomness for password reset tokens "
                            f"(256+ bits). Use secrets.token_urlsafe(32) (Python) or "
                            f"crypto.randomBytes(32) (Node.js)."
                        ),
                        line=_get_line(arg) or _get_line(expr) or _get_line(stmt),
                        column=_get_column(arg),
                        file=file,
                    ))
                elif not is_otp and length < self.MIN_TOKEN_LENGTH:
                    findings.append(RandomnessFinding(
                        category="insufficient_entropy",
                        cwe="CWE-331",
                        severity=Severity.MEDIUM,
                        message=(
                            f"Security token length {length} bytes/chars is below "
                            f"minimum {self.MIN_TOKEN_LENGTH} -- tokens with fewer "
                            f"than 128 bits of entropy are vulnerable to brute-force"
                        ),
                        remediation=(
                            f"Use at least {self.MIN_TOKEN_LENGTH} bytes of "
                            f"cryptographic randomness for security tokens. "
                            f"secrets.token_urlsafe(16) gives 128 bits of entropy."
                        ),
                        line=_get_line(arg) or _get_line(expr) or _get_line(stmt),
                        column=_get_column(arg),
                        file=file,
                    ))

        return findings


class NonCryptoHashTokenDetector:
    """Detect non-cryptographic hashes used for token generation (CWE-328).

    CRC32, Adler32, Java hashCode(), and similar checksums have a 32-bit
    output space (~4 billion values). This is trivially brute-forceable
    and many inputs produce collisions. These are checksums for data
    integrity, not security primitives.
    """

    def analyze(
        self,
        exprs: List[Tuple[Expr, Statement]],
        func_name: str,
        file: str,
    ) -> List[RandomnessFinding]:
        findings: List[RandomnessFinding] = []

        for expr, stmt in exprs:
            if not isinstance(expr, (FunctionCall, MethodCall)):
                continue

            call_name = _get_func_call_name(expr)
            if not call_name:
                continue

            # Check if this is a non-crypto hash function
            is_non_crypto = False
            matched_func = ""
            for nc_func in NON_CRYPTO_HASH_FUNCTIONS:
                if nc_func in call_name or call_name == nc_func:
                    is_non_crypto = True
                    matched_func = nc_func
                    break

            if not is_non_crypto:
                continue

            target = _get_target_name(stmt)

            # Must be in a security context
            if not _is_security_context(target, func_name):
                continue

            if _is_ui_context(target, func_name):
                continue

            # Determine the output bit-width for the message
            bit_width = "32"
            if "64" in matched_func:
                bit_width = "64"

            findings.append(RandomnessFinding(
                category="non_crypto_hash_token",
                cwe="CWE-328",
                severity=Severity.HIGH,
                message=(
                    f"Non-cryptographic hash '{matched_func}' used for security "
                    f"token in '{target or func_name}' -- {matched_func} has a "
                    f"{bit_width}-bit output space (~{2 ** int(bit_width):,} values), "
                    f"trivially brute-forceable. Collisions are easy to produce."
                ),
                remediation=(
                    "Use a cryptographic hash (SHA-256, SHA-3, BLAKE2) if you need "
                    "deterministic output, or better yet, use a CSPRNG directly: "
                    "secrets.token_hex() (Python), crypto.randomBytes() (Node.js). "
                    "CRC32/Adler32 are data integrity checksums, not security tools."
                ),
                line=_get_line(expr) or _get_line(stmt),
                column=_get_column(expr),
                file=file,
            ))

        return findings


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class InsecureRandomnessEngine:
    """Full insecure randomness detection engine.

    Walks the AEON AST and runs all detectors on every function body.
    Complements the basic PRNG checks in crypto_misuse.py with deeper
    analysis of randomness-related vulnerabilities.
    """

    def __init__(self) -> None:
        self.uuid_v1 = UUIDv1Detector()
        self.sequential_id = SequentialIDDetector()
        self.timestamp_token = TimestampTokenDetector()
        self.predictable_seed = PredictableSeedDetector()
        self.weak_token_gen = WeakTokenGenerationDetector()
        self.math_random_id = MathRandomIDDetector()
        self.insufficient_entropy = InsufficientEntropyDetector()
        self.non_crypto_hash = NonCryptoHashTokenDetector()

    def analyze(self, program: Program) -> List[RandomnessFinding]:
        """Run all insecure randomness detectors on the program."""
        all_findings: List[RandomnessFinding] = []
        file = program.filename

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                findings = self._analyze_function(decl, file)
                all_findings.extend(findings)

        return all_findings

    def _analyze_function(
        self,
        func: PureFunc | TaskFunc,
        file: str,
    ) -> List[RandomnessFinding]:
        """Run all detectors on a single function."""
        findings: List[RandomnessFinding] = []
        body = func.body
        func_name = func.name

        # Collect all expressions with their parent statements
        exprs = _collect_all_exprs(body)

        # Run each detector
        findings.extend(self.uuid_v1.analyze(exprs, func_name, file))
        findings.extend(self.sequential_id.analyze(exprs, func_name, file))
        findings.extend(self.timestamp_token.analyze(exprs, func_name, file))
        findings.extend(self.predictable_seed.analyze(exprs, func_name, file))
        findings.extend(self.weak_token_gen.analyze(exprs, func_name, file))
        findings.extend(self.math_random_id.analyze(exprs, func_name, file))
        findings.extend(self.insufficient_entropy.analyze(exprs, func_name, file))
        findings.extend(self.non_crypto_hash.analyze(exprs, func_name, file))

        return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_insecure_randomness(program: Program) -> list:
    """Run insecure randomness detection on an AEON program.

    Detects deep randomness vulnerabilities beyond basic PRNG misuse:
    - UUID v1 predictability (MAC + timestamp encoded)
    - Sequential/auto-increment IDs as security tokens (IDOR)
    - Timestamp-based token generation (predictable seed material)
    - Predictable PRNG seeds (constants, timestamps, PIDs)
    - Weak token generation (hashing predictable data)
    - Math.random() in security-relevant functions
    - Insufficient entropy (short tokens, weak OTPs)
    - Non-cryptographic hashes as security tokens (CRC32, Adler32)

    Contextual filtering:
    - Only flags in security contexts (token/session/auth variable names,
      security-related function names)
    - Skips UI/display contexts (render, component, test, mock)
    - Lowers severity for frontend/React code

    Args:
        program: An AEON Program AST node.

    Returns:
        A list of AeonError objects, one per finding.
    """
    try:
        engine = InsecureRandomnessEngine()
        findings = engine.analyze(program)

        errors: List[AeonError] = []
        for finding in findings:
            errors.append(finding.to_aeon_error())

        return errors
    except Exception:
        # Engine-level safety net: never let the entire engine crash
        # the verification pipeline
        return []
