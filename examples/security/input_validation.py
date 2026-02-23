"""
AEON Enterprise Example: Input Validation
===========================================
Industry: Security-Critical Systems
Engines:  Symbolic Execution, Taint Analysis, Abstract Interpretation

Demonstrates how AEON verifies:
- All user inputs are validated before use
- No path bypasses validation
- Tainted data never reaches sensitive sinks unvalidated

Run: aeon check examples/security/input_validation.py --deep-verify
"""

from typing import Optional, Tuple
import re


def sanitize_email(raw_email: str) -> Optional[str]:
    """
    Validate and sanitize an email address.

    Requires: len(raw_email) > 0
    Ensures:  result is None or '@' in result
    Ensures:  result is None or len(result) <= 254

    AEON's symbolic execution verifies both the None path
    (invalid email) and the valid path are reachable.
    """
    email = raw_email.strip().lower()

    if len(email) > 254:
        return None

    if '@' not in email:
        return None

    local, domain = email.rsplit('@', 1)
    if len(local) == 0 or len(domain) < 3:
        return None

    if '..' in email:
        return None

    return email


def sanitize_integer(raw_value: str, min_val: int, max_val: int) -> Tuple[bool, int]:
    """
    Parse and validate an integer from user input.

    Requires: min_val <= max_val
    Ensures:  result[0] == False or (min_val <= result[1] <= max_val)

    AEON's abstract interpretation verifies the clamped value
    always lies within [min_val, max_val].
    """
    try:
        value = int(raw_value)
    except (ValueError, TypeError):
        return (False, 0)

    if value < min_val or value > max_val:
        return (False, 0)

    return (True, value)


def sanitize_search_query(raw_query: str) -> str:
    """
    Sanitize a search query to prevent injection.

    Requires: len(raw_query) > 0
    Ensures:  '<' not in result
    Ensures:  '>' not in result
    Ensures:  "'" not in result
    Ensures:  '"' not in result
    Ensures:  len(result) <= 200

    AEON's taint analysis verifies the output is safe to use
    in HTML rendering (no XSS) and SQL queries (no injection).
    """
    # Remove HTML tags
    cleaned = re.sub(r'<[^>]+>', '', raw_query)

    # Remove SQL-dangerous characters
    cleaned = cleaned.replace("'", "").replace('"', "")

    # Remove special characters
    cleaned = re.sub(r'[<>&;|]', '', cleaned)

    # Truncate
    return cleaned[:200]


def validate_file_path(raw_path: str, allowed_base: str) -> Optional[str]:
    """
    Validate a file path to prevent path traversal attacks.

    Requires: len(raw_path) > 0
    Requires: len(allowed_base) > 0
    Ensures:  result is None or result.startswith(allowed_base)

    BUG (if missing normalization): '../../../etc/passwd' bypasses check.
    AEON's taint analysis catches path traversal:
      Source: raw_path (HTTP parameter — TAINTED)
      Sink: file system access (SENSITIVE)
      Without normalization, taint reaches the sink.
    """
    import os

    normalized = os.path.normpath(os.path.join(allowed_base, raw_path))

    if not normalized.startswith(allowed_base):
        return None

    if '..' in raw_path:
        return None

    return normalized


def validate_api_request(
    method: str,
    path: str,
    body: Optional[dict],
    api_key: str,
) -> dict:
    """
    Validate an incoming API request holistically.

    Requires: method in ['GET', 'POST', 'PUT', 'DELETE']
    Requires: len(path) > 0
    Requires: len(api_key) > 0
    Ensures:  result['valid'] == True or len(result['errors']) > 0

    AEON's symbolic execution explores all validation branches
    and proves no path returns valid=True with errors present,
    or valid=False with an empty error list.
    """
    errors = []

    if method not in ['GET', 'POST', 'PUT', 'DELETE']:
        errors.append("invalid_method")

    if not path.startswith('/'):
        errors.append("path_must_start_with_slash")

    if len(path) > 2048:
        errors.append("path_too_long")

    if method in ['POST', 'PUT'] and body is None:
        errors.append("body_required")

    if len(api_key) < 32:
        errors.append("invalid_api_key_format")

    return {
        'valid': len(errors) == 0,
        'errors': errors,
    }
