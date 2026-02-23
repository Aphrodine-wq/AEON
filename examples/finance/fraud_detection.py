"""
AEON Enterprise Example: Fraud Detection
=========================================
Industry: Financial Services
Engines:  Taint Analysis, Information Flow, Symbolic Execution

Demonstrates how AEON catches:
- Untrusted transaction data flowing to approval without validation
- Sensitive card data leaking to logs
- All fraud rule paths are reachable

Run: aeon check examples/finance/fraud_detection.py --deep-verify
"""

from typing import List, Optional


FRAUD_THRESHOLD = 10000
VELOCITY_LIMIT = 5


def check_transaction_velocity(
    recent_transactions: List[dict], time_window_minutes: int
) -> bool:
    """
    Check if too many transactions occurred in a short window.

    Requires: time_window_minutes > 0
    Requires: len(recent_transactions) >= 0
    Ensures:  result == (len(recent_transactions) > VELOCITY_LIMIT)

    AEON's symbolic execution proves all paths return correct boolean.
    """
    count = len(recent_transactions)
    return count > VELOCITY_LIMIT


def score_transaction_risk(
    amount: int,
    country_code: str,
    is_new_device: bool,
    velocity_count: int,
) -> int:
    """
    Score a transaction's fraud risk (0-100).

    Requires: amount >= 0
    Requires: len(country_code) == 2
    Requires: velocity_count >= 0
    Ensures:  0 <= result <= 100

    AEON's abstract interpretation verifies the score
    stays within [0, 100] on every path.
    """
    score = 0

    if amount > FRAUD_THRESHOLD:
        score += 30

    high_risk_countries = ["XX", "YY", "ZZ"]
    if country_code in high_risk_countries:
        score += 25

    if is_new_device:
        score += 20

    if velocity_count > VELOCITY_LIMIT:
        score += 25

    return min(score, 100)


def log_transaction_for_review(
    transaction_id: str,
    amount: int,
    card_number: str,
    risk_score: int,
) -> dict:
    """
    Log a flagged transaction for manual review.

    Requires: len(transaction_id) > 0
    Requires: len(card_number) >= 12

    BUG: card_number (SENSITIVE) leaks into the log output (PUBLIC).
    AEON's information flow analysis catches this:
      card_number is SECRET, log output is PUBLIC.
      Security lattice: SECRET <= PUBLIC violated.

    Fix: mask the card number before logging.
    """
    return {
        "transaction_id": transaction_id,
        "amount": amount,
        "card": card_number,  # BUG: SECRET leaks to PUBLIC
        "risk_score": risk_score,
        "action": "manual_review",
    }


def log_transaction_safe(
    transaction_id: str,
    amount: int,
    card_number: str,
    risk_score: int,
) -> dict:
    """
    Safely log a flagged transaction with masked card number.

    Requires: len(transaction_id) > 0
    Requires: len(card_number) >= 12
    Ensures:  'card' not in result or result['card_masked'][-4:] == card_number[-4:]

    AEON verifies: no SECRET data reaches PUBLIC output.
    """
    masked = "****-****-****-" + card_number[-4:]
    return {
        "transaction_id": transaction_id,
        "amount": amount,
        "card_masked": masked,
        "risk_score": risk_score,
        "action": "manual_review",
    }


def approve_or_decline(amount: int, risk_score: int, account_age_days: int) -> str:
    """
    Final fraud decision gate.

    Requires: amount > 0
    Requires: 0 <= risk_score <= 100
    Requires: account_age_days >= 0
    Ensures:  result in ['approved', 'declined', 'review']

    AEON's symbolic execution verifies all three outcomes are reachable
    and that no path falls through without a decision.
    """
    if risk_score >= 75:
        return "declined"

    if risk_score >= 40 and account_age_days < 30:
        return "review"

    if risk_score >= 50 and amount > FRAUD_THRESHOLD:
        return "review"

    return "approved"
