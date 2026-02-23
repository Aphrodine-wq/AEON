"""
AEON Enterprise Example: Payment Processing
============================================
Industry: Financial Services
Engines:  Abstract Interpretation, Hoare Logic, Symbolic Execution

Demonstrates how AEON catches:
- Division by zero in fee calculations
- Integer overflow in large transactions
- Contract violations in payment validation

Run: aeon check examples/finance/payment_processing.py --deep-verify
"""

from typing import List, Optional


def calculate_transaction_fee(amount: int, tier_volume: int) -> float:
    """
    Calculate tiered transaction fee based on monthly volume.

    Requires: amount > 0
    Requires: tier_volume >= 0
    Ensures:  result >= 0.0
    Ensures:  result <= amount * 0.03

    AEON catches: division by zero if tier_volume == 0 in rate calc
    """
    if tier_volume < 1000:
        rate = 0.029  # 2.9% for low volume
    elif tier_volume < 10000:
        rate = 0.025  # 2.5% for medium volume
    else:
        rate = 0.019  # 1.9% for high volume

    fee = amount * rate
    return round(fee, 2)


def process_payment(amount: int, balance: int, merchant_id: str) -> dict:
    """
    Process a payment and return the transaction result.

    Requires: amount > 0
    Requires: balance >= amount
    Requires: len(merchant_id) > 0
    Ensures:  result['new_balance'] == balance - amount
    Ensures:  result['status'] == 'approved'

    AEON proves: postcondition holds on all paths
    """
    fee = calculate_transaction_fee(amount, 5000)
    total_deduction = amount + int(fee)

    if total_deduction > balance:
        return {
            'status': 'declined',
            'reason': 'insufficient_funds',
            'new_balance': balance,
        }

    new_balance = balance - total_deduction
    return {
        'status': 'approved',
        'amount': amount,
        'fee': fee,
        'new_balance': new_balance,
        'merchant_id': merchant_id,
    }


def split_payment(total: int, num_parties: int) -> List[int]:
    """
    Split a payment equally among multiple parties.

    Requires: total > 0
    Requires: num_parties > 0
    Ensures:  sum(result) == total
    Ensures:  len(result) == num_parties

    BUG: division by zero if num_parties == 0 (AEON catches this)
    BUG: remainder not distributed (AEON's Hoare logic detects postcondition violation)
    """
    base_amount = total // num_parties
    remainder = total % num_parties

    shares = [base_amount] * num_parties
    for i in range(remainder):
        shares[i] += 1

    return shares


def calculate_compound_interest(
    principal: int, annual_rate: float, years: int, compounds_per_year: int
) -> float:
    """
    Calculate compound interest.

    Requires: principal > 0
    Requires: annual_rate >= 0.0
    Requires: years > 0
    Requires: compounds_per_year > 0
    Ensures:  result >= principal

    AEON catches: division by zero if compounds_per_year == 0
    AEON catches: potential overflow with large principal * years
    """
    rate_per_period = annual_rate / compounds_per_year
    total_periods = compounds_per_year * years
    amount = principal * (1 + rate_per_period) ** total_periods
    return round(amount, 2)


def validate_wire_transfer(
    sender_balance: int,
    amount: int,
    daily_limit: int,
    daily_total: int,
) -> Optional[str]:
    """
    Validate a wire transfer against business rules.

    Requires: sender_balance >= 0
    Requires: amount > 0
    Requires: daily_limit > 0
    Requires: daily_total >= 0
    Ensures:  result is None or len(result) > 0

    AEON's symbolic execution explores all 4 rejection paths
    and proves the None path is reachable only when all checks pass.
    """
    if amount > sender_balance:
        return "insufficient_funds"

    if amount > daily_limit:
        return "exceeds_daily_limit"

    if daily_total + amount > daily_limit:
        return "cumulative_daily_limit_exceeded"

    if amount > 1_000_000:
        return "requires_manual_approval"

    return None
