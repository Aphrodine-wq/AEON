"""
AEON Enterprise Example: Connection Pool
==========================================
Industry: Infrastructure / DevOps
Engines:  Separation Logic, Concurrency Verification, Model Checking

Demonstrates how AEON catches:
- Double-free of connections (use-after-release)
- Connection leaks (acquired but never released)
- Pool exhaustion deadlocks

Run: aeon check examples/infrastructure/connection_pool.py --deep-verify
"""

from typing import Optional, List


class Connection:
    """Database connection handle."""
    def __init__(self, conn_id: int, in_use: bool = False):
        """
        Requires: conn_id >= 0
        """
        self.conn_id = conn_id
        self.in_use = in_use


class ConnectionPool:
    """Fixed-size connection pool."""
    def __init__(self, size: int):
        """
        Requires: size > 0
        Requires: size <= 100
        Ensures:  len(self.connections) == size
        """
        self.connections = [Connection(i) for i in range(size)]
        self.size = size


def acquire_connection(pool: ConnectionPool) -> Optional[Connection]:
    """
    Acquire an available connection from the pool.

    Ensures: result is None or result.in_use == True
    Ensures: result is not None implies (number of in_use connections increased by 1)

    AEON's separation logic verifies the acquired connection
    is exclusively owned by the caller (no aliasing).
    The frame rule ensures other connections are unaffected.

    AEON's model checking verifies: if all connections are busy,
    this returns None (no deadlock, no blocking forever).
    """
    for conn in pool.connections:
        if not conn.in_use:
            conn.in_use = True
            return conn
    return None


def release_connection(pool: ConnectionPool, conn: Connection) -> bool:
    """
    Release a connection back to the pool.

    Requires: conn.in_use == True
    Ensures:  result == True implies conn.in_use == False

    BUG risk: calling release twice on the same connection
    is a double-free. AEON's separation logic detects this:
    after the first release, the caller no longer owns the resource.
    A second release would violate the ownership invariant.
    """
    if not conn.in_use:
        return False  # Already released — double-free attempt

    conn.in_use = False
    return True


def pool_utilization(pool: ConnectionPool) -> float:
    """
    Calculate current pool utilization as a percentage.

    Requires: pool.size > 0
    Ensures:  0.0 <= result <= 100.0

    AEON's abstract interpretation verifies the percentage
    is always within [0, 100] given a positive pool size.
    """
    in_use_count = sum(1 for c in pool.connections if c.in_use)
    return (in_use_count / pool.size) * 100.0


def health_check(pool: ConnectionPool) -> dict:
    """
    Return pool health metrics.

    Requires: pool.size > 0
    Ensures:  result['total'] == pool.size
    Ensures:  result['available'] + result['in_use'] == result['total']
    Ensures:  result['utilization'] >= 0.0

    AEON's Hoare logic verifies the sum invariant.
    """
    in_use = sum(1 for c in pool.connections if c.in_use)
    available = pool.size - in_use

    return {
        'total': pool.size,
        'in_use': in_use,
        'available': available,
        'utilization': round((in_use / pool.size) * 100.0, 2),
    }
