"""AEON Secret Detection Engine -- Hardcoded Credentials Scanner.

Detects hardcoded secrets, API keys, tokens, passwords, and other sensitive
credentials embedded directly in source code.

References:
  CWE-798: Use of Hard-Coded Credentials
  https://cwe.mitre.org/data/definitions/798.html

  OWASP Testing Guide: Testing for Hard-Coded Credentials
  https://owasp.org/www-project-web-security-testing-guide/

  Shannon (1948) "A Mathematical Theory of Communication"
  Bell System Technical Journal 27(3), https://doi.org/10.1002/j.1538-7305.1948.tb01338.x
  (Entropy calculation for high-entropy string detection)

Detection Strategies:

1. HIGH-ENTROPY STRINGS:
   Shannon entropy calculation on string literals. Strings over 20 characters
   with entropy > 4.5 bits/char are statistically likely to be secrets
   (random keys, tokens, hashes) rather than natural language or code.

2. KNOWN SECRET PATTERNS:
   Regex-based detection of well-known credential formats:
   - AWS access keys (AKIA prefix)
   - GitHub tokens (ghp_, ghs_ prefix)
   - JWT tokens (eyJ prefix with dot-separated segments)
   - Private keys (PEM headers)
   - Database connection strings
   - Payment provider keys (Stripe, etc.)
   - Messaging service tokens (Slack, Twilio, SendGrid)

3. CONTEXTUAL ANALYSIS:
   - Variable name inspection (password, secret, token, key assignments)
   - Skip test files and placeholder strings
   - Skip environment variable references
   - Severity escalation for production-critical patterns

Every finding includes:
  - Secret type classification
  - Severity (critical / high / medium)
  - Masked value (first 4 chars + ****)
  - CWE-798 reference
  - Remediation guidance
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral,
    LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    ReturnStmt, FunctionCall, MethodCall, FieldAccess,
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
# Secret Pattern Definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecretPattern:
    """A regex pattern that identifies a specific type of secret."""
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str


# Compile all patterns once at module load for performance.
# Each pattern targets string literal content found in the AST.
SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity=Severity.CRITICAL,
        description="AWS access key ID — grants access to AWS services",
    ),
    SecretPattern(
        name="GitHub Token",
        pattern=re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
        severity=Severity.CRITICAL,
        description="GitHub personal access or service token",
    ),
    SecretPattern(
        name="Generic API Key Assignment",
        pattern=re.compile(
            r"(api[_\-]?key|apikey|api[_\-]?secret)\s*[:=]\s*['\"][^'\"]{8,}",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description="API key or secret embedded in code",
    ),
    SecretPattern(
        name="JWT Token",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
        severity=Severity.HIGH,
        description="JSON Web Token — may contain session or auth data",
    ),
    SecretPattern(
        name="Private Key",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="PEM-encoded private key — cryptographic identity material",
    ),
    SecretPattern(
        name="Database Connection URL",
        pattern=re.compile(r"(?:postgres|mysql|mongodb|redis)://[^'\"\\\s]{10,}"),
        severity=Severity.CRITICAL,
        description="Database connection string with embedded credentials",
    ),
    SecretPattern(
        name="Password in Assignment",
        pattern=re.compile(
            r"(?:password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{4,}",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description="Hardcoded password or secret value",
    ),
    SecretPattern(
        name="Slack Token",
        pattern=re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}"),
        severity=Severity.HIGH,
        description="Slack API token — grants workspace access",
    ),
    SecretPattern(
        name="Stripe Key",
        pattern=re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}"),
        severity=Severity.CRITICAL,
        description="Stripe API key — grants payment processing access",
    ),
    SecretPattern(
        name="Firebase API Key",
        pattern=re.compile(r"AIza[A-Za-z0-9_-]{35}"),
        severity=Severity.HIGH,
        description="Google/Firebase API key",
    ),
    SecretPattern(
        name="Twilio API Key",
        pattern=re.compile(r"SK[a-f0-9]{32}"),
        severity=Severity.HIGH,
        description="Twilio API key — grants telephony service access",
    ),
    SecretPattern(
        name="SendGrid API Key",
        pattern=re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        severity=Severity.HIGH,
        description="SendGrid API key — grants email sending access",
    ),
    SecretPattern(
        name="Heroku API Key",
        pattern=re.compile(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ),
        severity=Severity.MEDIUM,
        description="UUID-format key (Heroku API key pattern)",
    ),
]

# Variable names that suggest a value is a secret (for contextual hex detection)
SECRET_VARIABLE_NAMES: set[str] = {
    "key", "token", "secret", "password", "passwd", "pwd",
    "api_key", "apikey", "api_secret", "apisecret",
    "access_key", "secret_key", "private_key",
    "auth_token", "auth_key", "bearer_token",
    "client_secret", "client_id",
    "encryption_key", "signing_key",
    "db_password", "database_password",
    "smtp_password", "mail_password",
}

# Regex for long hex strings (32+ hex chars), used with variable name context
_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{32,}$")

# Patterns that indicate a placeholder, not a real secret
_PLACEHOLDER_PATTERNS: List[re.Pattern] = [
    re.compile(r"\$\{.+\}"),              # ${VAR_NAME}
    re.compile(r"\{\{.+\}\}"),            # {{VAR_NAME}} (template)
    re.compile(r"\{[a-zA-Z_]+\}"),        # {var_name} (format string)
    re.compile(r"os\.environ"),            # os.environ reference
    re.compile(r"process\.env"),           # process.env reference
    re.compile(r"env\("),                  # env() call
    re.compile(r"getenv\("),              # getenv() call
    re.compile(r"ENV\["),                 # ENV["KEY"]
    re.compile(r"<[A-Z_]+>"),            # <PLACEHOLDER>
    re.compile(r"your[_-]?.*[_-]?here", re.IGNORECASE),  # your_key_here
    re.compile(r"xxx+", re.IGNORECASE),   # xxxx placeholder
    re.compile(r"TODO", re.IGNORECASE),   # TODO placeholder
    re.compile(r"REPLACE_ME", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Shannon Entropy
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character.

    H(X) = -sum(p(x) * log2(p(x))) for each character x in the alphabet.

    High-entropy strings (> 4.5 bits/char) are statistically likely to be
    randomly generated secrets rather than natural language or identifiers.

    Returns 0.0 for empty strings.
    """
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------

def _mask_secret(value: str, reveal: int = 4) -> str:
    """Mask a secret value, showing only the first few characters.

    Example: "AKIAIOSFODNN7EXAMPLE" -> "AKIA****"
    """
    if len(value) <= reveal:
        return "****"
    return value[:reveal] + "****"


# ---------------------------------------------------------------------------
# Context Helpers
# ---------------------------------------------------------------------------

def _is_placeholder(value: str) -> bool:
    """Check if a string value is a placeholder, not a real secret."""
    for pattern in _PLACEHOLDER_PATTERNS:
        if pattern.search(value):
            return True
    return False


def _is_test_context(source_text: str) -> bool:
    """Check if the source appears to be from a test file.

    Looks for common test file indicators in the source text.
    """
    if not source_text:
        return False
    # Check for test file markers in the first few lines
    header = source_text[:500].lower()
    test_indicators = (
        "__file__" in header and "test" in header,
        "# test" in header,
        "// test" in header,
        "describe(" in header,
        "it(" in header,
        "@test" in header.lower(),
        "unittest" in header,
        "pytest" in header,
        "jest" in header,
        "spec." in header,
        "_test." in header,
        ".test." in header,
        ".spec." in header,
    )
    return any(test_indicators)


def _variable_name_from_let(stmt: LetStmt) -> str:
    """Extract the variable name from a let statement."""
    return getattr(stmt, "name", "")


def _variable_name_from_assign(stmt: AssignStmt) -> str:
    """Extract the variable name from an assignment target."""
    target = stmt.target
    if isinstance(target, Identifier):
        return target.name
    if isinstance(target, FieldAccess):
        return target.field_name
    return ""


# ---------------------------------------------------------------------------
# AST Walking
# ---------------------------------------------------------------------------

def _walk_string_contexts(program: Program):
    """Yield (StringLiteral, SourceLocation, variable_name) tuples from the AST.

    Walks all function bodies in the program, extracting string literals
    along with their context (location and the variable they are assigned to,
    if any).
    """
    for decl in program.declarations:
        if not isinstance(decl, (PureFunc, TaskFunc)):
            continue
        for stmt in getattr(decl, "body", []):
            yield from _walk_stmt_strings(stmt)


def _walk_stmt_strings(stmt: Statement):
    """Recursively yield (StringLiteral, location, var_name) from a statement."""
    loc = getattr(stmt, "location", None)

    if isinstance(stmt, LetStmt):
        var_name = _variable_name_from_let(stmt)
        if stmt.value:
            yield from _walk_expr_strings(stmt.value, loc, var_name)

    elif isinstance(stmt, AssignStmt):
        var_name = _variable_name_from_assign(stmt)
        yield from _walk_expr_strings(stmt.value, loc, var_name)

    elif isinstance(stmt, ExprStmt):
        yield from _walk_expr_strings(stmt.expr, loc, "")

    elif isinstance(stmt, ReturnStmt):
        if stmt.value:
            yield from _walk_expr_strings(stmt.value, loc, "")

    elif isinstance(stmt, IfStmt):
        yield from _walk_expr_strings(stmt.condition, loc, "")
        for s in stmt.then_body:
            yield from _walk_stmt_strings(s)
        for s in stmt.else_body:
            yield from _walk_stmt_strings(s)

    elif isinstance(stmt, WhileStmt):
        yield from _walk_expr_strings(stmt.condition, loc, "")
        for s in stmt.body:
            yield from _walk_stmt_strings(s)


def _walk_expr_strings(expr: Expr, loc: Optional[SourceLocation], var_name: str):
    """Recursively yield (StringLiteral, location, var_name) from an expression."""
    if isinstance(expr, StringLiteral):
        expr_loc = getattr(expr, "location", None) or loc
        yield expr, expr_loc, var_name

    elif isinstance(expr, FunctionCall):
        # Walk callee
        yield from _walk_expr_strings(expr.callee, loc, var_name)
        # Walk arguments
        for arg in expr.args:
            yield from _walk_expr_strings(arg, loc, "")

    elif isinstance(expr, MethodCall):
        yield from _walk_expr_strings(expr.obj, loc, var_name)
        for arg in expr.args:
            yield from _walk_expr_strings(arg, loc, "")

    elif isinstance(expr, FieldAccess):
        yield from _walk_expr_strings(expr.obj, loc, var_name)


# ---------------------------------------------------------------------------
# Secret Detection Logic
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    """Internal representation of a detected secret before conversion to AeonError."""
    secret_type: str
    severity: Severity
    masked_value: str
    description: str
    location: Optional[SourceLocation]
    variable_name: str
    cwe: str = "CWE-798"


class SecretDetector:
    """Scans AEON AST string literals for hardcoded secrets."""

    def __init__(self, source_text: str = ""):
        self.findings: List[SecretFinding] = []
        self.source_text = source_text
        self.is_test_file = _is_test_context(source_text)

    def scan(self, program: Program) -> List[SecretFinding]:
        """Scan all string literals in the program for secrets."""
        self.findings = []

        for string_lit, location, var_name in _walk_string_contexts(program):
            value = string_lit.value
            if not value or len(value) < 4:
                continue

            # Skip placeholders and env var references
            if _is_placeholder(value):
                continue

            # Skip strings in test files
            if self.is_test_file:
                continue

            # Run each detection strategy with isolation
            self._check_known_patterns(value, location, var_name)
            self._check_high_entropy(value, location, var_name)
            self._check_contextual_hex(value, location, var_name)

        return self.findings

    def _check_known_patterns(
        self,
        value: str,
        location: Optional[SourceLocation],
        var_name: str,
    ) -> None:
        """Check string against all known secret patterns."""
        for sp in SECRET_PATTERNS:
            try:
                # Heroku UUID pattern needs variable name context to avoid
                # false positives on regular UUIDs
                if sp.name == "Heroku API Key":
                    if not self._has_secret_variable_context(var_name):
                        continue

                match = sp.pattern.search(value)
                if match:
                    matched_text = match.group(0)
                    self.findings.append(SecretFinding(
                        secret_type=sp.name,
                        severity=sp.severity,
                        masked_value=_mask_secret(matched_text),
                        description=sp.description,
                        location=location,
                        variable_name=var_name,
                    ))
                    # Stop after first pattern match per string to avoid
                    # duplicate findings on the same literal
                    return
            except Exception:
                # Robust: one bad pattern must not kill the whole engine
                continue

    def _check_high_entropy(
        self,
        value: str,
        location: Optional[SourceLocation],
        var_name: str,
    ) -> None:
        """Flag strings with suspiciously high Shannon entropy."""
        try:
            if len(value) < 20:
                return

            entropy = _shannon_entropy(value)
            if entropy <= 4.5:
                return

            # Skip if already caught by a known pattern
            for finding in self.findings:
                if finding.location == location and finding.masked_value == _mask_secret(value):
                    return

            # Higher severity if variable name suggests a secret
            severity = Severity.MEDIUM
            if self._has_secret_variable_context(var_name):
                severity = Severity.HIGH

            self.findings.append(SecretFinding(
                secret_type="High-Entropy String",
                severity=severity,
                masked_value=_mask_secret(value),
                description=(
                    f"String with Shannon entropy {entropy:.2f} bits/char "
                    f"(threshold: 4.5) — likely a randomly generated secret"
                ),
                location=location,
                variable_name=var_name,
            ))
        except Exception:
            pass

    def _check_contextual_hex(
        self,
        value: str,
        location: Optional[SourceLocation],
        var_name: str,
    ) -> None:
        """Flag long hex strings assigned to secret-named variables."""
        try:
            if not self._has_secret_variable_context(var_name):
                return

            if not _HEX_PATTERN.match(value):
                return

            # Skip if already caught by another check
            for finding in self.findings:
                if finding.location == location:
                    return

            self.findings.append(SecretFinding(
                secret_type="Hardcoded Hex Secret",
                severity=Severity.HIGH,
                masked_value=_mask_secret(value),
                description=(
                    f"32+ character hex string in variable '{var_name}' — "
                    f"likely a hardcoded key, token, or hash"
                ),
                location=location,
                variable_name=var_name,
            ))
        except Exception:
            pass

    @staticmethod
    def _has_secret_variable_context(var_name: str) -> bool:
        """Check if a variable name suggests it holds a secret."""
        if not var_name:
            return False
        name_lower = var_name.lower()
        # Exact match
        if name_lower in SECRET_VARIABLE_NAMES:
            return True
        # Substring match for compound names (e.g., db_password, stripeApiKey)
        secret_keywords = {
            "key", "token", "secret", "password", "passwd", "pwd",
            "credential", "auth",
        }
        for keyword in secret_keywords:
            if keyword in name_lower:
                return True
        return False


# ---------------------------------------------------------------------------
# Error Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: SecretFinding) -> AeonError:
    """Convert a SecretFinding into an AeonError using contract_error."""
    severity_label = finding.severity.value.upper()

    remediation = "Use environment variables instead of hardcoded values"
    if "Private Key" in finding.secret_type:
        remediation = (
            "Store private keys in a secrets manager (e.g., AWS Secrets Manager, "
            "HashiCorp Vault) and load at runtime"
        )
    elif "Database" in finding.secret_type:
        remediation = (
            "Use environment variables (e.g., DATABASE_URL) or a secrets manager "
            "for connection strings"
        )
    elif "Stripe" in finding.secret_type or "Payment" in finding.secret_type:
        remediation = (
            "Use environment variables for payment keys and NEVER commit "
            "live keys to source control"
        )

    var_context = ""
    if finding.variable_name:
        var_context = f" in variable '{finding.variable_name}'"

    return contract_error(
        precondition=(
            f"No hardcoded secrets ({finding.cwe}) — "
            f"[{severity_label}] Hardcoded {finding.secret_type} detected"
            f"{var_context}: {finding.masked_value}"
        ),
        failing_values={
            "secret_type": finding.secret_type,
            "severity": finding.severity.value,
            "masked_value": finding.masked_value,
            "cwe": finding.cwe,
            "remediation": remediation,
            "engine": "Secret Detection",
        },
        function_signature="secret_detection",
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_secrets(program: Program, source_text: str = "") -> list:
    """Run secret detection on an AEON program.

    Scans all string literals in the AST for hardcoded secrets, API keys,
    tokens, passwords, and other sensitive credentials.

    Args:
        program: The parsed AEON Program AST.
        source_text: Optional raw source text, used for test-file detection
                     and contextual analysis.

    Returns:
        A list of AeonError instances, one per detected secret.

    Detection strategies:
        1. Known secret patterns (AWS, GitHub, Stripe, JWT, etc.)
        2. High-entropy strings (Shannon entropy > 4.5 bits/char)
        3. Contextual hex strings (long hex in secret-named variables)

    Contextual filtering:
        - Skips test files
        - Skips placeholder strings (${...}, process.env, etc.)
        - Adjusts severity based on secret type and variable context

    CWE: CWE-798 (Use of Hard-Coded Credentials)
    """
    try:
        detector = SecretDetector(source_text=source_text)
        findings = detector.scan(program)
        return [_finding_to_error(f) for f in findings]
    except Exception:
        # Engine-level safety net: never let the entire engine crash
        # the verification pipeline
        return []
