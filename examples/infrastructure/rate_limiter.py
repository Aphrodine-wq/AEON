"""
AEON Enterprise Example: Rate Limiter
=======================================
Industry: Infrastructure / DevOps
Engines:  Model Checking, Abstract Interpretation, Concurrency Verification

Demonstrates how AEON verifies:
- No request starvation (liveness property)
- Token bucket invariants are maintained
- Concurrent access doesn't corrupt state

Run: aeon check examples/infrastructure/rate_limiter.py --deep-verify
"""

from typing import Tuple


class TokenBucket:
    """Token bucket rate limiter."""
    def __init__(self, capacity: int, refill_rate: float, tokens: float):
        """
        Requires: capacity > 0
        Requires: refill_rate > 0.0
        Requires: 0.0 <= tokens <= capacity
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = tokens


def refill_tokens(bucket: TokenBucket, elapsed_seconds: float) -> TokenBucket:
    """
    Refill tokens based on elapsed time.

    Requires: elapsed_seconds >= 0.0
    Ensures:  result.tokens >= bucket.tokens
    Ensures:  result.tokens <= result.capacity
    Ensures:  result.capacity == bucket.capacity

    AEON's abstract interpretation verifies tokens
    never exceeds capacity after min() clamping.
    """
    added = elapsed_seconds * bucket.refill_rate
    new_tokens = min(bucket.tokens + added, float(bucket.capacity))
    return TokenBucket(
        capacity=bucket.capacity,
        refill_rate=bucket.refill_rate,
        tokens=new_tokens,
    )


def try_consume(bucket: TokenBucket, cost: int) -> Tuple[bool, TokenBucket]:
    """
    Attempt to consume tokens for a request.

    Requires: cost > 0
    Ensures:  result[0] == True implies result[1].tokens == bucket.tokens - cost
    Ensures:  result[0] == False implies result[1].tokens == bucket.tokens

    AEON's model checking verifies the liveness property:
    after enough time passes, any request will eventually be allowed.
    AG(AF(tokens >= cost)) — for bounded cost and positive refill_rate.
    """
    if bucket.tokens >= cost:
        new_bucket = TokenBucket(
            capacity=bucket.capacity,
            refill_rate=bucket.refill_rate,
            tokens=bucket.tokens - cost,
        )
        return (True, new_bucket)
    else:
        return (False, bucket)


def calculate_retry_after(bucket: TokenBucket, cost: int) -> float:
    """
    Calculate how long a client should wait before retrying.

    Requires: cost > 0
    Requires: bucket.refill_rate > 0.0
    Ensures:  result >= 0.0

    AEON catches: division by zero if refill_rate == 0
    (precondition prevents this, which AEON verifies is enforced).
    """
    if bucket.tokens >= cost:
        return 0.0

    deficit = cost - bucket.tokens
    wait_time = deficit / bucket.refill_rate
    return round(wait_time, 2)


def sliding_window_count(
    request_timestamps: list, window_seconds: int, current_time: int
) -> int:
    """
    Count requests in a sliding time window.

    Requires: window_seconds > 0
    Requires: current_time > 0
    Ensures:  0 <= result <= len(request_timestamps)

    AEON's abstract interpretation verifies the count
    is bounded by the input list length.
    """
    window_start = current_time - window_seconds
    count = 0
    for ts in request_timestamps:
        if ts >= window_start:
            count += 1
    return count
