"""
AEON Enterprise Example: Inventory Manager
============================================
Industry: E-Commerce
Engines:  Concurrency Verification, Model Checking, Contracts

Demonstrates how AEON catches:
- Race conditions in concurrent inventory updates (overselling)
- Stock count never goes negative
- Reservation timeout invariants

Run: aeon check examples/ecommerce/inventory_manager.py --deep-verify
"""

from typing import Dict, Optional, List


class InventoryItem:
    """Thread-safe inventory item with reservation support."""
    def __init__(self, sku: str, quantity: int, reserved: int = 0):
        """
        Requires: len(sku) > 0
        Requires: quantity >= 0
        Requires: reserved >= 0
        Requires: reserved <= quantity
        """
        self.sku = sku
        self.quantity = quantity
        self.reserved = reserved


def check_availability(item: InventoryItem, requested: int) -> bool:
    """
    Check if enough unreserved stock is available.

    Requires: requested > 0
    Ensures:  result == ((item.quantity - item.reserved) >= requested)

    AEON verifies the arithmetic never underflows.
    """
    available = item.quantity - item.reserved
    return available >= requested


def reserve_stock(item: InventoryItem, amount: int) -> Optional[InventoryItem]:
    """
    Reserve stock for a pending order.

    Requires: amount > 0
    Ensures:  result is None or result.reserved == item.reserved + amount
    Ensures:  result is None or result.quantity == item.quantity
    Ensures:  result is not None implies result.reserved <= result.quantity

    AEON's concurrency verification flags this function:
    without a lock, two threads could both pass the availability
    check and oversell. Needs atomic compare-and-swap.
    """
    available = item.quantity - item.reserved
    if available < amount:
        return None

    return InventoryItem(
        sku=item.sku,
        quantity=item.quantity,
        reserved=item.reserved + amount,
    )


def fulfill_order(item: InventoryItem, amount: int) -> Optional[InventoryItem]:
    """
    Convert reserved stock into a fulfilled order (reduce quantity).

    Requires: amount > 0
    Requires: amount <= item.reserved
    Ensures:  result.quantity == item.quantity - amount
    Ensures:  result.reserved == item.reserved - amount
    Ensures:  result.quantity >= 0
    Ensures:  result.reserved >= 0

    AEON's Hoare logic verifies the postconditions hold
    given the preconditions on amount and item.reserved.
    """
    new_quantity = item.quantity - amount
    new_reserved = item.reserved - amount

    return InventoryItem(
        sku=item.sku,
        quantity=new_quantity,
        reserved=new_reserved,
    )


def cancel_reservation(item: InventoryItem, amount: int) -> InventoryItem:
    """
    Cancel a stock reservation (release reserved units).

    Requires: amount > 0
    Requires: amount <= item.reserved
    Ensures:  result.reserved == item.reserved - amount
    Ensures:  result.quantity == item.quantity

    AEON verifies: quantity is unchanged, only reserved decreases.
    """
    return InventoryItem(
        sku=item.sku,
        quantity=item.quantity,
        reserved=item.reserved - amount,
    )


def bulk_availability_check(
    inventory: Dict[str, InventoryItem],
    order_items: List[Dict[str, int]],
) -> List[str]:
    """
    Check availability for multiple items in an order.
    Returns list of unavailable SKUs.

    Requires: len(order_items) > 0
    Ensures:  all(sku in inventory for sku in result) or sku not in inventory

    AEON's model checking explores all combinations of
    available/unavailable items to verify completeness.
    """
    unavailable = []
    for item in order_items:
        sku = item.get("sku", "")
        qty = item.get("quantity", 0)

        if sku not in inventory:
            unavailable.append(sku)
        elif not check_availability(inventory[sku], qty):
            unavailable.append(sku)

    return unavailable
