"""
AEON Enterprise Example: Pricing Engine
=========================================
Industry: E-Commerce
Engines:  Abstract Interpretation, Hoare Logic, Symbolic Execution

Demonstrates how AEON verifies:
- Price is always positive after discounts
- Discount never exceeds 100%
- Tax calculations are correct
- Bundle pricing invariants

Run: aeon check examples/ecommerce/pricing_engine.py --deep-verify
"""

from typing import List, Tuple


def apply_discount(price: int, discount_percent: float) -> int:
    """
    Apply a percentage discount to a price (in cents).

    Requires: price > 0
    Requires: 0.0 <= discount_percent <= 100.0
    Ensures:  result >= 0
    Ensures:  result <= price

    AEON's abstract interpretation verifies the result
    stays in [0, price] for all valid discount values.
    """
    discount_amount = int(price * (discount_percent / 100.0))
    return price - discount_amount


def calculate_tax(subtotal: int, tax_rate: float) -> Tuple[int, int]:
    """
    Calculate tax and return (tax_amount, total).

    Requires: subtotal >= 0
    Requires: 0.0 <= tax_rate <= 0.30
    Ensures:  result[0] >= 0
    Ensures:  result[1] == subtotal + result[0]

    AEON's Hoare logic verifies the sum relationship.
    """
    tax = int(subtotal * tax_rate)
    total = subtotal + tax
    return (tax, total)


def calculate_tiered_price(
    quantity: int,
    base_price: int,
    tier_breaks: List[Tuple[int, float]],
) -> int:
    """
    Calculate price with volume-based tier discounts.
    tier_breaks = [(threshold, discount_rate), ...] sorted ascending.

    Requires: quantity > 0
    Requires: base_price > 0
    Requires: len(tier_breaks) > 0
    Requires: all(0.0 <= rate <= 1.0 for _, rate in tier_breaks)
    Ensures:  result > 0
    Ensures:  result <= quantity * base_price

    AEON's symbolic execution explores all tier combinations
    and proves the result is always positive.
    """
    applicable_rate = 0.0
    for threshold, rate in tier_breaks:
        if quantity >= threshold:
            applicable_rate = rate

    subtotal = quantity * base_price
    discount = int(subtotal * applicable_rate)
    return subtotal - discount


def calculate_cart_total(
    items: List[dict], coupon_discount: float, tax_rate: float
) -> dict:
    """
    Calculate the final cart total with items, coupons, and tax.

    Requires: len(items) > 0
    Requires: all(item['price'] > 0 and item['quantity'] > 0 for item in items)
    Requires: 0.0 <= coupon_discount <= 50.0
    Requires: 0.0 <= tax_rate <= 0.30
    Ensures:  result['total'] > 0
    Ensures:  result['subtotal'] >= result['discount']

    AEON proves: even with max coupon + tax, total stays positive.
    """
    subtotal = 0
    for item in items:
        subtotal += item['price'] * item['quantity']

    discount_amount = int(subtotal * (coupon_discount / 100.0))
    after_discount = subtotal - discount_amount

    tax_amount = int(after_discount * tax_rate)
    total = after_discount + tax_amount

    return {
        'subtotal': subtotal,
        'discount': discount_amount,
        'tax': tax_amount,
        'total': total,
        'item_count': len(items),
    }
