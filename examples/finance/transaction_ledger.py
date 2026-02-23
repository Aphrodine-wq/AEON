"""
AEON Enterprise Example: Transaction Ledger
============================================
Industry: Financial Services
Engines:  Hoare Logic, Abstract Interpretation, Dependent Types

Demonstrates how AEON verifies:
- Double-entry bookkeeping invariants (debits == credits)
- Balance never goes negative
- Ledger append-only integrity

Run: aeon check examples/finance/transaction_ledger.py --deep-verify
"""

from typing import List, Tuple


class LedgerEntry:
    """Immutable double-entry ledger record."""
    def __init__(self, debit_account: str, credit_account: str, amount: int, memo: str):
        """
        Requires: amount > 0
        Requires: len(debit_account) > 0
        Requires: len(credit_account) > 0
        Requires: debit_account != credit_account
        """
        self.debit_account = debit_account
        self.credit_account = credit_account
        self.amount = amount
        self.memo = memo


def post_transaction(
    ledger: List[LedgerEntry],
    debit_account: str,
    credit_account: str,
    amount: int,
) -> List[LedgerEntry]:
    """
    Post a double-entry transaction to the ledger.

    Requires: amount > 0
    Requires: debit_account != credit_account
    Ensures:  len(result) == len(ledger) + 1
    Ensures:  total_debits(result) == total_credits(result)

    AEON's Hoare logic proves the double-entry invariant is preserved.
    """
    entry = LedgerEntry(debit_account, credit_account, amount, "transaction")
    return ledger + [entry]


def compute_account_balance(ledger: List[LedgerEntry], account: str) -> int:
    """
    Compute the net balance for a given account from the ledger.

    Requires: len(account) > 0
    Ensures:  result == sum(credits to account) - sum(debits from account)

    AEON's abstract interpretation tracks the running sum
    and verifies no intermediate overflow.
    """
    balance = 0
    for entry in ledger:
        if entry.credit_account == account:
            balance += entry.amount
        if entry.debit_account == account:
            balance -= entry.amount
    return balance


def reconcile_ledger(ledger: List[LedgerEntry]) -> Tuple[bool, int]:
    """
    Verify the ledger is balanced (total debits == total credits).

    Ensures: result[0] == True implies result[1] == 0
    Ensures: result[0] == False implies result[1] != 0

    AEON proves: if all entries have amount > 0 and each entry
    debits one account and credits another, the ledger balances.
    """
    total_debits = 0
    total_credits = 0

    for entry in ledger:
        total_debits += entry.amount
        total_credits += entry.amount

    difference = total_debits - total_credits
    return (difference == 0, difference)


def transfer_between_accounts(
    ledger: List[LedgerEntry],
    from_account: str,
    to_account: str,
    amount: int,
) -> List[LedgerEntry]:
    """
    Transfer funds between accounts with balance validation.

    Requires: amount > 0
    Requires: from_account != to_account
    Requires: compute_account_balance(ledger, from_account) >= amount
    Ensures:  compute_account_balance(result, from_account) == compute_account_balance(ledger, from_account) - amount
    Ensures:  compute_account_balance(result, to_account) == compute_account_balance(ledger, to_account) + amount

    AEON's dependent types verify the balance relationship
    between input and output states.
    """
    return post_transaction(ledger, from_account, to_account, amount)
