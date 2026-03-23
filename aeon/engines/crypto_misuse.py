"""AEON Cryptographic Misuse Detection Engine — Practical Crypto Implementation Bugs.

Detects common cryptographic implementation mistakes that developers make when
using crypto libraries. This is distinct from cryptographic_verify.py, which
performs formal Dolev-Yao protocol verification. This engine catches the
real-world mistakes: weak hashes for passwords, hardcoded keys, ECB mode,
predictable PRNGs, disabled certificate validation, and timing-attack-prone
comparisons.

Based on:
  Egele, M. et al. (2013) "An Empirical Study of Cryptographic Misuse
  in Android Applications"
  ACM CCS '13, https://doi.org/10.1145/2508859.2516693

  Lazar, D. et al. (2014) "Why Does Cryptographic Software Fail?
  A Case Study and Open Problems"
  APSys '14, https://doi.org/10.1145/2637166.2637237

  Nadi, S. et al. (2016) "Jumping Through Hoops: Why Do Java Developers
  Struggle with Cryptography APIs?"
  ICSE '16, https://doi.org/10.1145/2884781.2884790

  Rahaman, S. et al. (2019) "CryptoGuard: High Precision Detection of
  Cryptographic Vulnerabilities in Massive-Sized Java Projects"
  ACM CCS '19, https://doi.org/10.1145/3319535.3345659

Key Theory:

1. BROKEN HASH ALGORITHMS (CWE-327, CWE-328):
   MD5 and SHA-1 are cryptographically broken for collision resistance.
   Using them for password hashing, integrity, or signatures is insecure.
   CRC32 is not a cryptographic hash at all — trivially reversible.

2. INSECURE PASSWORD STORAGE (CWE-916):
   Passwords must be hashed with a slow, salted, memory-hard function:
   bcrypt, scrypt, argon2, or PBKDF2 with >= 100k iterations.
   Single-round SHA-256 is brute-forceable at billions/sec on GPUs.
   Reversible encryption of passwords is categorically wrong.

3. HARDCODED CRYPTOGRAPHIC MATERIAL (CWE-321, CWE-329):
   Hardcoded keys, IVs, nonces, and salts defeat their cryptographic
   purpose entirely. Keys must come from secure key management.
   IVs and nonces must be freshly generated per operation.

4. INSECURE CIPHER MODES (CWE-327):
   ECB mode leaks plaintext structure (the "penguin attack").
   CBC without HMAC is vulnerable to padding oracle attacks (Vaudenay 2002).
   Use authenticated encryption: AES-GCM or ChaCha20-Poly1305.

5. INSUFFICIENT KEY LENGTHS (CWE-326):
   RSA < 2048 bits: factorable with current hardware.
   AES < 128 bits: below the security margin.
   ECDSA < 256 bits: weak curve parameters.

6. INSECURE RANDOM NUMBER GENERATION (CWE-330, CWE-338):
   Math.random(), random.random(), rand() are PRNGs — predictable.
   Security-sensitive randomness requires a CSPRNG:
   secrets module, crypto.randomBytes, /dev/urandom.

7. CERTIFICATE VALIDATION DISABLED (CWE-295):
   verify=False, rejectUnauthorized: false, CURLOPT_SSL_VERIFYPEER = 0
   all disable TLS certificate checks, enabling MITM attacks.

8. TIMING ATTACKS (CWE-208):
   String equality (==) on secrets leaks information via timing.
   Use constant-time comparison: hmac.compare_digest, timingSafeEqual.
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
# Finding Severity and CWE Classifications
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


@dataclass
class CryptoFinding:
    """A single cryptographic misuse finding."""
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
                f"Crypto misuse ({self.cwe}): {self.message}"
            ),
            failing_values={
                "category": self.category,
                "cwe": self.cwe,
                "severity": self.severity.value,
                "remediation": self.remediation,
                "engine": "Crypto Misuse Detection",
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

# Category 1: Weak hash algorithms used for security
WEAK_HASH_FUNCTIONS: Dict[str, str] = {
    # Python
    "md5": "MD5",
    "hashlib.md5": "MD5",
    # JavaScript / Node.js
    "createhash": "HASH_FACTORY",
    # Java
    "getinstance": "HASH_FACTORY",
    # General
    "sha1": "SHA1",
    "hashlib.sha1": "SHA1",
    "crc32": "CRC32",
    "crc32c": "CRC32",
    "adler32": "CRC32",
}

WEAK_HASH_STRING_ARGS: Set[str] = {
    "md5", "sha1", "sha-1", "crc32",
}

# Category 2: Password hashing — functions that indicate single-round hashing
SINGLE_ROUND_HASH_NAMES: Set[str] = {
    "sha256", "sha384", "sha512", "sha224",
    "sha3_256", "sha3_384", "sha3_512",
    "md5", "sha1",
}

SECURE_PASSWORD_HASHERS: Set[str] = {
    "bcrypt", "scrypt", "argon2", "argon2id", "argon2i", "argon2d",
    "pbkdf2", "pbkdf2_hmac", "pbkdf2_sha256", "pbkdf2_sha512",
    "password_hash", "hashpw", "gensalt",
    "kdf", "derive_key",
}

PASSWORD_VARIABLE_PATTERNS: Set[str] = {
    "password", "passwd", "pass_hash", "pw_hash", "pwd",
    "passphrase", "credential", "secret_key",
}

REVERSIBLE_ENCRYPTION_NAMES: Set[str] = {
    "encrypt", "aes_encrypt", "des_encrypt", "cipher",
    "fernet", "aesgcm",
}

# Category 3: Hardcoded cryptographic material
CRYPTO_MATERIAL_PATTERNS: Set[str] = {
    "key", "secret", "iv", "nonce", "salt",
    "api_key", "apikey", "secret_key", "encryption_key",
    "aes_key", "rsa_key", "private_key", "signing_key",
    "hmac_key", "token_secret", "jwt_secret",
    "master_key", "session_secret",
}

# Category 4: Insecure cipher modes
INSECURE_MODE_STRINGS: Dict[str, str] = {
    "ecb": "ECB",
    "aes-128-ecb": "ECB",
    "aes-192-ecb": "ECB",
    "aes-256-ecb": "ECB",
    "aes.mode_ecb": "ECB",
    "mode_ecb": "ECB",
    "cbc": "CBC",
    "aes-128-cbc": "CBC",
    "aes-192-cbc": "CBC",
    "aes-256-cbc": "CBC",
    "aes.mode_cbc": "CBC",
    "mode_cbc": "CBC",
}

CIPHER_CREATION_NAMES: Set[str] = {
    "new", "createcipheriv", "createcipher", "createdecipher",
    "createdecipheriv", "cipher", "getinstance",
}

# Category 5: Key generation functions and minimum sizes
KEY_GENERATION_NAMES: Set[str] = {
    "generate_key", "generatekey", "gen_key", "genkey",
    "generate_key_pair", "generatekeypair", "gen_rsa",
    "rsa_generate", "rsa.generate", "create_key",
    "generatekeypairsync", "generatekeypairasync",
}

MIN_KEY_SIZES: Dict[str, int] = {
    "rsa": 2048,
    "aes": 128,
    "ecdsa": 256,
    "ecdh": 256,
    "dsa": 2048,
    "dh": 2048,
}

# Category 6: Insecure PRNGs
INSECURE_PRNG_FUNCTIONS: Set[str] = {
    # JavaScript
    "math.random",
    # Python
    "random.random", "random.randint", "random.randrange",
    "random.choice", "random.uniform", "random.sample",
    "random.shuffle", "random.getrandbits",
    # C / C++
    "rand", "srand", "random",
    # Java
    "math.random", "nextint", "nextlong", "nextdouble",
    # PHP
    "rand", "mt_rand", "array_rand",
    # Ruby
    "rand",
}

SECURITY_CONTEXT_PATTERNS: Set[str] = {
    "token", "key", "secret", "session", "nonce", "csrf",
    "otp", "password", "salt", "iv", "seed", "auth",
    "api_key", "apikey", "random_id", "uuid", "challenge",
    "verification", "code", "pin",
}

# Category 7: Certificate validation disabled
CERT_DISABLE_PATTERNS: Dict[str, str] = {
    "verify": "verify=False disables TLS certificate validation",
    "rejectunauthorized": "rejectUnauthorized: false disables TLS certificate validation",
    "ssl_verifypeer": "CURLOPT_SSL_VERIFYPEER = 0 disables certificate verification",
    "insecurerequestwarning": "Suppressing InsecureRequestWarning hides disabled TLS verification",
    "ssl_verify": "ssl_verify=False disables TLS certificate validation",
    "check_hostname": "check_hostname=False disables hostname verification",
    "cert_reqs": "cert_reqs=CERT_NONE disables certificate verification",
}

# Category 8: Timing attack — variable name patterns for secrets
SECRET_VARIABLE_PATTERNS: Set[str] = {
    "hash", "token", "hmac", "signature", "digest",
    "mac", "tag", "auth_tag", "api_key", "apikey",
    "secret", "password", "csrf", "session_id",
    "otp", "verification_code",
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


def _name_matches_pattern(name: str, patterns: Set[str]) -> bool:
    """Check if a variable name matches any of the given patterns (case-insensitive substring)."""
    name_lower = name.lower()
    return any(p in name_lower for p in patterns)


def _collect_all_exprs(stmts: List[Statement]) -> List[Tuple[Expr, Statement]]:
    """Recursively collect all expressions from a statement list with their parent statement."""
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


def _has_string_arg_matching(args: List[Expr], patterns: Set[str]) -> Optional[StringLiteral]:
    """Check if any argument is a StringLiteral whose value matches any pattern."""
    for arg in args:
        if isinstance(arg, StringLiteral) and arg.value.lower() in patterns:
            return arg
    return None


def _has_int_arg_below(args: List[Expr], threshold: int) -> Optional[IntLiteral]:
    """Check if any argument is an IntLiteral below the threshold and > 0."""
    for arg in args:
        if isinstance(arg, IntLiteral) and 0 < arg.value < threshold:
            return arg
    return None


def _function_contains_call(body: List[Statement], names: Set[str]) -> bool:
    """Check if a function body contains a call to any of the named functions."""
    exprs = _collect_all_exprs(body)
    for expr, _ in exprs:
        if isinstance(expr, FunctionCall):
            cname = _callee_name(expr).lower()
            if any(n in cname for n in names):
                return True
        elif isinstance(expr, MethodCall):
            if expr.method_name.lower() in names:
                return True
    return False


# ---------------------------------------------------------------------------
# Individual Detectors
# ---------------------------------------------------------------------------

class WeakHashDetector:
    """Detect use of MD5, SHA1, CRC32 for security purposes."""

    def analyze(self, exprs: List[Tuple[Expr, Statement]], file: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []

        for expr, stmt in exprs:
            # Pattern: FunctionCall to known weak hash functions
            if isinstance(expr, FunctionCall):
                cname = _callee_name(expr).lower()
                for weak_name, algo in WEAK_HASH_FUNCTIONS.items():
                    if weak_name in cname:
                        if algo == "HASH_FACTORY":
                            # Check string argument for algorithm name
                            match = _has_string_arg_matching(expr.args, WEAK_HASH_STRING_ARGS)
                            if match:
                                algo = match.value.upper()
                            else:
                                continue
                        findings.append(CryptoFinding(
                            category="weak_hash_algorithm",
                            cwe="CWE-327",
                            severity=Severity.HIGH,
                            message=(
                                f"{algo} is cryptographically broken and must not be "
                                f"used for security purposes (integrity, signatures, "
                                f"password hashing)"
                            ),
                            remediation=(
                                f"Replace {algo} with SHA-256 or SHA-3 for integrity. "
                                f"For password hashing, use bcrypt, argon2, or PBKDF2."
                            ),
                            line=_get_line(expr) or _get_line(stmt),
                            column=_get_column(expr),
                            file=file,
                        ))
                        break

            # Pattern: MethodCall with weak hash names
            elif isinstance(expr, MethodCall):
                mname = expr.method_name.lower()
                for weak_name, algo in WEAK_HASH_FUNCTIONS.items():
                    if weak_name == mname or weak_name.endswith(f".{mname}"):
                        if algo == "HASH_FACTORY":
                            match = _has_string_arg_matching(expr.args, WEAK_HASH_STRING_ARGS)
                            if match:
                                algo = match.value.upper()
                            else:
                                continue
                        findings.append(CryptoFinding(
                            category="weak_hash_algorithm",
                            cwe="CWE-327",
                            severity=Severity.HIGH,
                            message=(
                                f"{algo} is cryptographically broken and must not be "
                                f"used for security purposes"
                            ),
                            remediation=(
                                f"Replace {algo} with SHA-256 or SHA-3 for integrity. "
                                f"For password hashing, use bcrypt, argon2, or PBKDF2."
                            ),
                            line=_get_line(expr) or _get_line(stmt),
                            column=_get_column(expr),
                            file=file,
                        ))
                        break

            # Pattern: StringLiteral with weak algorithm names in context of hash creation
            elif isinstance(expr, StringLiteral):
                val = expr.value.lower().strip()
                if val in WEAK_HASH_STRING_ARGS:
                    # Only flag if parent is a function/method call (already handled above)
                    # This catches stray references in config-like assignments
                    target = _get_target_name(stmt)
                    if _name_matches_pattern(target, {"algorithm", "hash", "digest", "method"}):
                        algo = val.upper()
                        findings.append(CryptoFinding(
                            category="weak_hash_algorithm",
                            cwe="CWE-327",
                            severity=Severity.HIGH,
                            message=(
                                f"Algorithm '{algo}' assigned to '{target}' — "
                                f"{algo} is cryptographically broken"
                            ),
                            remediation=f"Use SHA-256, SHA-3, or BLAKE2 instead of {algo}.",
                            line=_get_line(expr) or _get_line(stmt),
                            column=_get_column(expr),
                            file=file,
                        ))

        return findings


class InsecurePasswordStorageDetector:
    """Detect passwords hashed with single-round algorithms or reversible encryption."""

    def analyze(
        self,
        exprs: List[Tuple[Expr, Statement]],
        func_body: List[Statement],
        file: str,
    ) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []

        for expr, stmt in exprs:
            target = _get_target_name(stmt)
            is_password_context = _name_matches_pattern(target, PASSWORD_VARIABLE_PATTERNS)

            if not is_password_context:
                # Also check if any argument is a password variable
                if isinstance(expr, FunctionCall):
                    is_password_context = any(
                        isinstance(a, Identifier) and _name_matches_pattern(a.name, PASSWORD_VARIABLE_PATTERNS)
                        for a in expr.args
                    )
                elif isinstance(expr, MethodCall):
                    is_password_context = any(
                        isinstance(a, Identifier) and _name_matches_pattern(a.name, PASSWORD_VARIABLE_PATTERNS)
                        for a in expr.args
                    )

            if not is_password_context:
                continue

            # Check for single-round hash on password
            if isinstance(expr, FunctionCall):
                cname = _callee_name(expr).lower()
                for hash_name in SINGLE_ROUND_HASH_NAMES:
                    if hash_name in cname:
                        findings.append(CryptoFinding(
                            category="insecure_password_storage",
                            cwe="CWE-916",
                            severity=Severity.CRITICAL,
                            message=(
                                f"Password hashed with single-round {hash_name.upper()} — "
                                f"brute-forceable at billions of hashes/sec on GPUs"
                            ),
                            remediation=(
                                f"Use bcrypt or argon2 instead of {hash_name.upper()} "
                                f"for password hashing. These are intentionally slow and "
                                f"memory-hard, making brute-force infeasible."
                            ),
                            line=_get_line(expr) or _get_line(stmt),
                            column=_get_column(expr),
                            file=file,
                        ))
                        break

                # Check for reversible encryption of passwords
                for enc_name in REVERSIBLE_ENCRYPTION_NAMES:
                    if enc_name in cname:
                        findings.append(CryptoFinding(
                            category="insecure_password_storage",
                            cwe="CWE-257",
                            severity=Severity.CRITICAL,
                            message=(
                                "Password stored with reversible encryption instead of "
                                "hashing — if the key is compromised, all passwords "
                                "are exposed"
                            ),
                            remediation=(
                                "Passwords must be hashed, never encrypted. Use bcrypt, "
                                "argon2, or PBKDF2. Encryption is reversible; hashing is not."
                            ),
                            line=_get_line(expr) or _get_line(stmt),
                            column=_get_column(expr),
                            file=file,
                        ))
                        break

            elif isinstance(expr, MethodCall):
                mname = expr.method_name.lower()
                for hash_name in SINGLE_ROUND_HASH_NAMES:
                    if hash_name in mname:
                        findings.append(CryptoFinding(
                            category="insecure_password_storage",
                            cwe="CWE-916",
                            severity=Severity.CRITICAL,
                            message=(
                                f"Password hashed with single-round {hash_name.upper()} — "
                                f"brute-forceable at billions of hashes/sec on GPUs"
                            ),
                            remediation=(
                                f"Use bcrypt or argon2 instead of {hash_name.upper()} "
                                f"for password hashing."
                            ),
                            line=_get_line(expr) or _get_line(stmt),
                            column=_get_column(expr),
                            file=file,
                        ))
                        break

        return findings


class HardcodedCryptoMaterialDetector:
    """Detect hardcoded keys, IVs, nonces, and salts."""

    def analyze(self, stmts: List[Statement], file: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []

        for stmt in stmts:
            target_name = ""
            value_expr: Optional[Expr] = None

            if isinstance(stmt, LetStmt) and stmt.value:
                target_name = stmt.name
                value_expr = stmt.value
            elif isinstance(stmt, AssignStmt) and isinstance(stmt.target, Identifier):
                target_name = stmt.target.name
                value_expr = stmt.value

            if not target_name or not value_expr:
                continue

            if not _name_matches_pattern(target_name, CRYPTO_MATERIAL_PATTERNS):
                continue

            # Check if the value is a string literal (hardcoded key/secret)
            is_hardcoded = isinstance(value_expr, StringLiteral)

            # Also check for byte-array-like literals (list of ints)
            if not is_hardcoded and isinstance(value_expr, FunctionCall):
                # Patterns like bytes([0x01, 0x02, ...]) or b"..."
                cname = _callee_name(value_expr).lower()
                if cname in ("bytes", "bytearray", "b", "buffer.from", "uint8array"):
                    is_hardcoded = True

            if not is_hardcoded:
                continue

            # Determine specific kind
            name_lower = target_name.lower()
            if any(p in name_lower for p in ("iv", "nonce")):
                kind = "IV/nonce"
                cwe = "CWE-329"
                extra = (
                    "IVs and nonces must be freshly generated for each encryption "
                    "operation. A hardcoded IV defeats the purpose of the IV entirely — "
                    "identical plaintexts will produce identical ciphertexts."
                )
                remediation = (
                    "Generate a fresh random IV/nonce per encryption operation using "
                    "os.urandom() or crypto.randomBytes(). Store the IV alongside "
                    "the ciphertext (IVs are not secret, only unique)."
                )
            elif "salt" in name_lower:
                kind = "salt"
                cwe = "CWE-760"
                extra = (
                    "A hardcoded salt means all users share the same salt, enabling "
                    "rainbow table attacks. Each password needs a unique random salt."
                )
                remediation = (
                    "Generate a unique random salt per user/password using os.urandom() "
                    "or bcrypt.gensalt(). Store the salt alongside the hash."
                )
            else:
                kind = "encryption key"
                cwe = "CWE-321"
                extra = (
                    "Hardcoded encryption keys can be extracted from source code, "
                    "version control, or compiled binaries. This compromises all "
                    "data encrypted with this key."
                )
                remediation = (
                    "Load encryption keys from environment variables, a secrets manager "
                    "(AWS Secrets Manager, HashiCorp Vault), or a KMS. Never commit "
                    "keys to source code."
                )

            findings.append(CryptoFinding(
                category="hardcoded_crypto_material",
                cwe=cwe,
                severity=Severity.HIGH,
                message=f"Hardcoded {kind} in variable '{target_name}' — {extra}",
                remediation=remediation,
                line=_get_line(stmt),
                column=_get_column(stmt),
                file=file,
            ))

        return findings

    def analyze_nested(self, stmts: List[Statement], file: str) -> List[CryptoFinding]:
        """Recursively analyze all statements including nested blocks."""
        findings = self.analyze(stmts, file)
        for stmt in stmts:
            if isinstance(stmt, IfStmt):
                findings.extend(self.analyze_nested(stmt.then_body, file))
                if stmt.else_body:
                    findings.extend(self.analyze_nested(stmt.else_body, file))
            elif isinstance(stmt, WhileStmt):
                findings.extend(self.analyze_nested(stmt.body, file))
        return findings


class InsecureCipherModeDetector:
    """Detect ECB mode and CBC without authentication."""

    def analyze(self, exprs: List[Tuple[Expr, Statement]], file: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []

        for expr, stmt in exprs:
            if not isinstance(expr, (FunctionCall, MethodCall)):
                continue

            # Get the function/method name
            if isinstance(expr, FunctionCall):
                cname = _callee_name(expr).lower()
                args = expr.args
            else:
                cname = expr.method_name.lower()
                args = expr.args

            # Check if this is a cipher creation call
            is_cipher_call = any(cn in cname for cn in CIPHER_CREATION_NAMES)
            if not is_cipher_call:
                continue

            # Check all arguments for insecure mode strings
            for arg in args:
                if not isinstance(arg, (StringLiteral, Identifier, FieldAccess)):
                    continue

                mode_str = ""
                if isinstance(arg, StringLiteral):
                    mode_str = arg.value.lower().strip()
                elif isinstance(arg, Identifier):
                    mode_str = arg.name.lower()
                elif isinstance(arg, FieldAccess):
                    mode_str = arg.field_name.lower()

                if not mode_str:
                    continue

                for pattern, mode in INSECURE_MODE_STRINGS.items():
                    if pattern in mode_str:
                        if mode == "ECB":
                            findings.append(CryptoFinding(
                                category="insecure_cipher_mode",
                                cwe="CWE-327",
                                severity=Severity.HIGH,
                                message=(
                                    "ECB mode leaks plaintext structure — identical "
                                    "plaintext blocks produce identical ciphertext blocks "
                                    "(the 'ECB penguin' attack)"
                                ),
                                remediation=(
                                    "Use AES-GCM (authenticated encryption) or "
                                    "ChaCha20-Poly1305. If you must use a block mode, "
                                    "use CBC with HMAC-SHA256 for authentication."
                                ),
                                line=_get_line(arg) or _get_line(expr) or _get_line(stmt),
                                column=_get_column(arg),
                                file=file,
                            ))
                        elif mode == "CBC":
                            findings.append(CryptoFinding(
                                category="insecure_cipher_mode",
                                cwe="CWE-327",
                                severity=Severity.MEDIUM,
                                message=(
                                    "CBC mode without authenticated encryption is "
                                    "vulnerable to padding oracle attacks (Vaudenay 2002). "
                                    "An attacker can decrypt ciphertext by observing "
                                    "padding error responses."
                                ),
                                remediation=(
                                    "Prefer AES-GCM or ChaCha20-Poly1305 (authenticated "
                                    "encryption). If CBC is required, apply HMAC-SHA256 "
                                    "over the ciphertext (Encrypt-then-MAC)."
                                ),
                                line=_get_line(arg) or _get_line(expr) or _get_line(stmt),
                                column=_get_column(arg),
                                file=file,
                            ))
                        break

        return findings


class InsufficientKeyLengthDetector:
    """Detect RSA < 2048, AES < 128, ECDSA < 256."""

    def analyze(self, exprs: List[Tuple[Expr, Statement]], file: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []

        for expr, stmt in exprs:
            if not isinstance(expr, (FunctionCall, MethodCall)):
                continue

            if isinstance(expr, FunctionCall):
                cname = _callee_name(expr).lower()
                args = expr.args
            else:
                cname = expr.method_name.lower()
                args = expr.args

            # Check if this is a key generation call
            is_keygen = any(kg in cname for kg in KEY_GENERATION_NAMES)
            if not is_keygen:
                continue

            # Determine algorithm from function name or arguments
            algo_detected = ""
            for algo in MIN_KEY_SIZES:
                if algo in cname:
                    algo_detected = algo
                    break
            if not algo_detected:
                for arg in args:
                    if isinstance(arg, StringLiteral):
                        val = arg.value.lower()
                        for algo in MIN_KEY_SIZES:
                            if algo in val:
                                algo_detected = algo
                                break
                    if algo_detected:
                        break

            if not algo_detected:
                # Default to RSA for generic key generation
                algo_detected = "rsa"

            min_size = MIN_KEY_SIZES.get(algo_detected, 2048)

            # Check for insufficient key size in arguments
            weak_key = _has_int_arg_below(args, min_size)
            if weak_key:
                findings.append(CryptoFinding(
                    category="insufficient_key_length",
                    cwe="CWE-326",
                    severity=Severity.MEDIUM,
                    message=(
                        f"{algo_detected.upper()} key size {weak_key.value} bits is below "
                        f"the minimum recommended {min_size} bits"
                    ),
                    remediation=(
                        f"Use at least {min_size}-bit keys for {algo_detected.upper()}. "
                        f"For RSA, NIST recommends 2048 bits minimum (3072+ preferred). "
                        f"For AES, use 128-bit minimum (256-bit for post-quantum safety)."
                    ),
                    line=_get_line(weak_key) or _get_line(expr) or _get_line(stmt),
                    column=_get_column(weak_key),
                    file=file,
                ))

        return findings


class InsecurePRNGDetector:
    """Detect use of non-cryptographic PRNGs for security-sensitive operations."""

    def analyze(self, exprs: List[Tuple[Expr, Statement]], file: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []

        for expr, stmt in exprs:
            target = _get_target_name(stmt)
            is_security_context = _name_matches_pattern(target, SECURITY_CONTEXT_PATTERNS)

            func_name = ""

            if isinstance(expr, FunctionCall):
                func_name = _callee_name(expr).lower()
            elif isinstance(expr, MethodCall):
                # Build dotted name from obj + method
                obj_name = ""
                if isinstance(expr.obj, Identifier):
                    obj_name = expr.obj.name.lower()
                func_name = f"{obj_name}.{expr.method_name.lower()}" if obj_name else expr.method_name.lower()

            if not func_name:
                continue

            # Check against known insecure PRNGs
            is_insecure = False
            matched_name = ""
            for prng in INSECURE_PRNG_FUNCTIONS:
                if prng == func_name or func_name.endswith(f".{prng}") or func_name == prng.split(".")[-1]:
                    is_insecure = True
                    matched_name = prng
                    break

            if not is_insecure:
                continue

            # Only flag in security-relevant contexts
            if not is_security_context:
                # Also check if the result flows into something security-related
                # by scanning the surrounding function calls
                continue

            findings.append(CryptoFinding(
                category="insecure_prng",
                cwe="CWE-330",
                severity=Severity.HIGH,
                message=(
                    f"'{matched_name}' is not a cryptographic PRNG — its output is "
                    f"predictable and must not be used for security purposes "
                    f"(tokens, keys, nonces, session IDs)"
                ),
                remediation=(
                    "Python: use secrets.token_hex() or os.urandom(). "
                    "JavaScript: use crypto.randomBytes() or crypto.getRandomValues(). "
                    "Java: use java.security.SecureRandom. "
                    "C: use /dev/urandom or platform CSPRNG."
                ),
                line=_get_line(expr) or _get_line(stmt),
                column=_get_column(expr),
                file=file,
            ))

        return findings


class CertValidationDisabledDetector:
    """Detect disabled TLS certificate validation."""

    def analyze(self, exprs: List[Tuple[Expr, Statement]], file: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []

        for expr, stmt in exprs:
            # Pattern 1: keyword argument verify=False in function calls
            # In AEON AST, this appears as assignments or named arguments
            # We detect: FunctionCall with BoolLiteral(False) args + callee hints
            if isinstance(expr, FunctionCall):
                cname = _callee_name(expr).lower()
                # Check for requests.get(..., verify=False) pattern
                # In the AST, keyword args may appear as regular args
                # Also check for method calls like .get, .post, .request
                http_names = {"get", "post", "put", "patch", "delete", "request",
                              "fetch", "urlopen", "http", "https", "session"}
                is_http_call = any(h in cname for h in http_names)

                if is_http_call:
                    for arg in expr.args:
                        if isinstance(arg, BoolLiteral) and not arg.value:
                            findings.append(CryptoFinding(
                                category="cert_validation_disabled",
                                cwe="CWE-295",
                                severity=Severity.CRITICAL,
                                message=(
                                    "TLS certificate validation appears to be disabled "
                                    "in an HTTP call — this enables man-in-the-middle attacks"
                                ),
                                remediation=(
                                    "Remove verify=False and use proper TLS certificates. "
                                    "For development, use mkcert for locally-trusted certs. "
                                    "For self-signed certs, pass the CA bundle explicitly."
                                ),
                                line=_get_line(expr) or _get_line(stmt),
                                column=_get_column(expr),
                                file=file,
                            ))
                            break

            elif isinstance(expr, MethodCall):
                mname = expr.method_name.lower()
                http_methods = {"get", "post", "put", "patch", "delete",
                                "request", "fetch", "send"}
                if mname in http_methods:
                    for arg in expr.args:
                        if isinstance(arg, BoolLiteral) and not arg.value:
                            findings.append(CryptoFinding(
                                category="cert_validation_disabled",
                                cwe="CWE-295",
                                severity=Severity.CRITICAL,
                                message=(
                                    "TLS certificate validation appears to be disabled "
                                    "in an HTTP call — this enables man-in-the-middle attacks"
                                ),
                                remediation=(
                                    "Remove verify=False and use proper TLS certificates. "
                                    "For development, use mkcert for locally-trusted certs."
                                ),
                                line=_get_line(expr) or _get_line(stmt),
                                column=_get_column(expr),
                                file=file,
                            ))
                            break

            # Pattern 2: Assignment of False to cert-verification variables
            target = _get_target_name(stmt)
            if target and isinstance(expr, Expr):
                target_lower = target.lower()
                for pattern, desc in CERT_DISABLE_PATTERNS.items():
                    if pattern in target_lower:
                        # Check if value is False, 0, or "none"/"CERT_NONE"
                        is_disabled = False
                        if isinstance(expr, BoolLiteral) and not expr.value:
                            is_disabled = True
                        elif isinstance(expr, IntLiteral) and expr.value == 0:
                            is_disabled = True
                        elif isinstance(expr, StringLiteral) and expr.value.lower() in (
                            "none", "cert_none", "false", "0"
                        ):
                            is_disabled = True
                        elif isinstance(expr, Identifier) and expr.name.lower() in (
                            "false", "none", "cert_none"
                        ):
                            is_disabled = True

                        if is_disabled:
                            findings.append(CryptoFinding(
                                category="cert_validation_disabled",
                                cwe="CWE-295",
                                severity=Severity.CRITICAL,
                                message=f"{desc} — enables man-in-the-middle attacks",
                                remediation=(
                                    "Enable TLS certificate validation. Use proper CA "
                                    "certificates. For development, use mkcert to create "
                                    "locally-trusted certificates."
                                ),
                                line=_get_line(stmt),
                                column=_get_column(stmt),
                                file=file,
                            ))
                        break

            # Pattern 3: Suppressing InsecureRequestWarning
            if isinstance(expr, FunctionCall):
                cname = _callee_name(expr).lower()
                if "disable_warnings" in cname or "filterwarnings" in cname:
                    for arg in expr.args:
                        if isinstance(arg, (StringLiteral, Identifier)):
                            val = ""
                            if isinstance(arg, StringLiteral):
                                val = arg.value.lower()
                            elif isinstance(arg, Identifier):
                                val = arg.name.lower()
                            if "insecurerequestwarning" in val or "insecure" in val:
                                findings.append(CryptoFinding(
                                    category="cert_validation_disabled",
                                    cwe="CWE-295",
                                    severity=Severity.CRITICAL,
                                    message=(
                                        "Suppressing InsecureRequestWarning hides the "
                                        "fact that TLS certificate validation is disabled"
                                    ),
                                    remediation=(
                                        "Fix the root cause — enable certificate validation "
                                        "instead of silencing the warning."
                                    ),
                                    line=_get_line(expr) or _get_line(stmt),
                                    column=_get_column(expr),
                                    file=file,
                                ))
                                break

        return findings


class TimingAttackDetector:
    """Detect non-constant-time comparison of secrets."""

    def analyze(self, exprs: List[Tuple[Expr, Statement]], file: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []

        for expr, stmt in exprs:
            if not isinstance(expr, BinaryOp):
                continue

            if expr.op not in ("==", "!=", "===", "!=="):
                continue

            # Check if either operand is a variable with a secret-like name
            left_name = ""
            right_name = ""

            if isinstance(expr.left, Identifier):
                left_name = expr.left.name
            elif isinstance(expr.left, FieldAccess):
                left_name = expr.left.field_name

            if isinstance(expr.right, Identifier):
                right_name = expr.right.name
            elif isinstance(expr.right, FieldAccess):
                right_name = expr.right.field_name

            left_is_secret = _name_matches_pattern(left_name, SECRET_VARIABLE_PATTERNS) if left_name else False
            right_is_secret = _name_matches_pattern(right_name, SECRET_VARIABLE_PATTERNS) if right_name else False

            if left_is_secret or right_is_secret:
                secret_var = left_name if left_is_secret else right_name
                findings.append(CryptoFinding(
                    category="timing_attack",
                    cwe="CWE-208",
                    severity=Severity.MEDIUM,
                    message=(
                        f"String comparison ('{expr.op}') on secret variable "
                        f"'{secret_var}' — leaks information via timing side-channel. "
                        f"An attacker can determine the secret byte-by-byte by "
                        f"measuring response times."
                    ),
                    remediation=(
                        "Python: use hmac.compare_digest(a, b). "
                        "Node.js: use crypto.timingSafeEqual(a, b). "
                        "Java: use MessageDigest.isEqual(a, b). "
                        "General: use a constant-time comparison function."
                    ),
                    line=_get_line(expr) or _get_line(stmt),
                    column=_get_column(expr),
                    file=file,
                ))

        return findings


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class CryptoMisuseEngine:
    """Full cryptographic misuse detection engine.

    Walks the AEON AST and runs all detectors on every function body.
    """

    def __init__(self) -> None:
        self.weak_hash = WeakHashDetector()
        self.password_storage = InsecurePasswordStorageDetector()
        self.hardcoded_material = HardcodedCryptoMaterialDetector()
        self.cipher_mode = InsecureCipherModeDetector()
        self.key_length = InsufficientKeyLengthDetector()
        self.prng = InsecurePRNGDetector()
        self.cert_validation = CertValidationDisabledDetector()
        self.timing = TimingAttackDetector()

    def analyze(self, program: Program) -> List[CryptoFinding]:
        """Run all crypto misuse detectors on the program."""
        all_findings: List[CryptoFinding] = []
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
    ) -> List[CryptoFinding]:
        """Run all detectors on a single function."""
        findings: List[CryptoFinding] = []
        body = func.body

        # Collect all expressions with their parent statements
        exprs = _collect_all_exprs(body)

        # Run each detector
        findings.extend(self.weak_hash.analyze(exprs, file))
        findings.extend(self.password_storage.analyze(exprs, body, file))
        findings.extend(self.hardcoded_material.analyze_nested(body, file))
        findings.extend(self.cipher_mode.analyze(exprs, file))
        findings.extend(self.key_length.analyze(exprs, file))
        findings.extend(self.prng.analyze(exprs, file))
        findings.extend(self.cert_validation.analyze(exprs, file))
        findings.extend(self.timing.analyze(exprs, file))

        return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_crypto_misuse(program: Program) -> list:
    """Run cryptographic misuse detection on an AEON program.

    Detects practical crypto implementation mistakes:
    - Weak hash algorithms for security (MD5, SHA1, CRC32)
    - Insecure password storage (single-round hashing, reversible encryption)
    - Hardcoded keys, IVs, nonces, salts
    - Insecure cipher modes (ECB, CBC without HMAC)
    - Insufficient key lengths (RSA < 2048, AES < 128, ECDSA < 256)
    - Non-cryptographic PRNGs for security (Math.random, random.random, rand)
    - Disabled TLS certificate validation
    - Timing attacks via string comparison of secrets

    Args:
        program: An AEON Program AST node.

    Returns:
        A list of AeonError objects, one per finding.
    """
    engine = CryptoMisuseEngine()
    findings = engine.analyze(program)

    # Convert findings to AeonError objects
    errors: List[AeonError] = []
    for finding in findings:
        errors.append(finding.to_aeon_error())

    return errors
