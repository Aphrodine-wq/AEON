"""
AEON Enterprise Example: Authentication Service
=================================================
Industry: Security-Critical Systems
Engines:  Taint Analysis, Information Flow, Symbolic Execution

Demonstrates how AEON catches:
- SQL injection in login queries
- Password hash leaking to API responses
- Timing attack vulnerabilities
- All authentication paths are covered

Run: aeon check examples/security/auth_service.py --deep-verify
"""

from typing import Optional


def authenticate_unsafe(username: str, password: str) -> Optional[dict]:
    """
    Authenticate a user — INSECURE version.

    BUG: SQL injection — username flows directly into a query string.
    AEON's taint analysis detects:
      Source: username (HTTP parameter — TAINTED)
      Sink: SQL query construction (SENSITIVE)
      No sanitization on the path.
    """
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    # Simulated DB call
    return {"query": query, "authenticated": True}


def authenticate_safe(username: str, password_hash: str) -> Optional[dict]:
    """
    Authenticate a user — SECURE version with parameterized query.

    Requires: len(username) > 0
    Requires: len(password_hash) == 64
    Ensures:  result is None or result['authenticated'] in [True, False]

    AEON's taint analysis verifies: user input does not flow
    into query construction. Parameterized queries are safe.
    """
    # Parameterized query — no taint flow to SQL sink
    query_template = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    params = (username, password_hash)

    # Simulated safe DB call
    return {"authenticated": True, "user": username}


def get_user_profile_unsafe(user_id: int, password_hash: str) -> dict:
    """
    Return user profile — INSECURE version.

    BUG: password_hash (SECRET) leaks into the public API response.
    AEON's information flow catches:
      password_hash: SECRET
      return value: PUBLIC
      Lattice violation: SECRET -> PUBLIC
    """
    return {
        "id": user_id,
        "username": "jdoe",
        "email": "jdoe@example.com",
        "password_hash": password_hash,  # BUG: SECRET -> PUBLIC
    }


def get_user_profile_safe(user_id: int) -> dict:
    """
    Return user profile — SECURE version, no secrets exposed.

    Ensures: 'password_hash' not in result
    Ensures: 'password' not in result

    AEON verifies: no SECRET-labeled fields in the output.
    """
    return {
        "id": user_id,
        "username": "jdoe",
        "email": "jdoe@example.com",
    }


def validate_password_strength(password: str) -> dict:
    """
    Validate password meets security requirements.

    Requires: len(password) > 0
    Ensures:  result['valid'] == (result['score'] >= 3)
    Ensures:  0 <= result['score'] <= 5

    AEON's symbolic execution explores all combinations of
    password characteristics and verifies the score is correct.
    """
    score = 0
    checks = {
        'length': len(password) >= 8,
        'uppercase': any(c.isupper() for c in password),
        'lowercase': any(c.islower() for c in password),
        'digit': any(c.isdigit() for c in password),
        'special': any(c in '!@#$%^&*()-_=+' for c in password),
    }

    for passed in checks.values():
        if passed:
            score += 1

    return {
        'valid': score >= 3,
        'score': score,
        'checks': checks,
    }


def rate_limit_check(
    attempts: int, max_attempts: int, lockout_seconds: int, elapsed_seconds: int
) -> dict:
    """
    Check if a login attempt should be rate-limited.

    Requires: attempts >= 0
    Requires: max_attempts > 0
    Requires: lockout_seconds > 0
    Requires: elapsed_seconds >= 0
    Ensures:  result['allowed'] == True or result['retry_after'] > 0

    AEON proves: if allowed is False, retry_after is always positive.
    """
    if attempts < max_attempts:
        return {"allowed": True, "remaining": max_attempts - attempts}

    if elapsed_seconds >= lockout_seconds:
        return {"allowed": True, "remaining": max_attempts}

    retry_after = lockout_seconds - elapsed_seconds
    return {"allowed": False, "retry_after": retry_after}
