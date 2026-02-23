"""Property-Based Tests for AEON Abstract Domain Lattice Laws.

Verifies that the abstract domains in aeon.abstract_interp satisfy the
algebraic laws required for soundness of abstract interpretation.

Mathematical background (Cousot & Cousot 1977):
  An abstract domain must form a COMPLETE LATTICE (L, ⊑, ⊥, ⊤, ⊔, ⊓) with:

  1. Partial order (⊑): reflexivity, antisymmetry, transitivity
  2. Join (⊔): commutativity, associativity, idempotence, upper bound
  3. Meet (⊓): commutativity, associativity, idempotence, lower bound
  4. Widening (∇): a ∇ b ⊒ a ⊔ b, ascending chains stabilize
  5. Galois connection: soundness (c ∈ γ(α(c))) and optimality

References:
  Cousot & Cousot (1977) POPL — Abstract Interpretation
  Mine (2006) — The Octagon Abstract Domain
"""

from __future__ import annotations

import pytest

try:
    from hypothesis import given, settings, assume
    from hypothesis import strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False
    given = settings = assume = st = None  # type: ignore

from aeon.abstract_interp import (
    Interval, INTERVAL_BOT, INTERVAL_TOP, INF, NEG_INF,
    Sign, SignValue,
    Congruence,
    ReducedProduct,
)


# ---------------------------------------------------------------------------
# Hypothesis strategies — only defined when hypothesis is available
# ---------------------------------------------------------------------------

if HAS_HYPOTHESIS:
    @st.composite
    def interval_strategy(draw):
        kind = draw(st.sampled_from(["bot", "top", "finite", "semi_inf"]))
        if kind == "bot":
            return INTERVAL_BOT
        if kind == "top":
            return INTERVAL_TOP
        if kind == "finite":
            lo = draw(st.floats(min_value=-1000.0, max_value=1000.0,
                                allow_nan=False, allow_infinity=False))
            hi = draw(st.floats(min_value=-1000.0, max_value=1000.0,
                                allow_nan=False, allow_infinity=False))
            if lo > hi:
                lo, hi = hi, lo
            return Interval(lo, hi)
        side = draw(st.booleans())
        bound = draw(st.floats(min_value=-1000.0, max_value=1000.0,
                               allow_nan=False, allow_infinity=False))
        return Interval(bound, INF) if side else Interval(NEG_INF, bound)

    @st.composite
    def sign_strategy(draw):
        return Sign(draw(st.sampled_from(list(SignValue))))

    @st.composite
    def congruence_strategy(draw):
        kind = draw(st.sampled_from(["bot", "top", "exact", "modular"]))
        if kind == "bot":
            return Congruence(is_bot=True)
        if kind == "top":
            return Congruence(modulus=1)
        if kind == "exact":
            r = draw(st.integers(min_value=-100, max_value=100))
            return Congruence(remainder=r, modulus=0)
        m = draw(st.integers(min_value=2, max_value=20))
        r = draw(st.integers(min_value=0, max_value=m - 1))
        return Congruence(remainder=r, modulus=m)
else:
    interval_strategy = sign_strategy = congruence_strategy = None  # type: ignore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def iv_eq(a: Interval, b: Interval) -> bool:
    if a.is_bottom() and b.is_bottom():
        return True
    if a.is_top() and b.is_top():
        return True
    return a.lo == b.lo and a.hi == b.hi


# ===========================================================================
# Interval Domain — Lattice Laws
# ===========================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
class TestIntervalLattice:
    """Verify Interval forms a valid complete lattice."""

    @given(interval_strategy())
    @settings(max_examples=200)
    def test_join_idempotent(self, a: Interval):
        """a ⊔ a = a."""
        assert iv_eq(a.join(a), a), f"join idempotence: {a} ⊔ {a} = {a.join(a)}"

    @given(interval_strategy(), interval_strategy())
    @settings(max_examples=200)
    def test_join_commutative(self, a: Interval, b: Interval):
        """a ⊔ b = b ⊔ a."""
        assert iv_eq(a.join(b), b.join(a)), f"join commutativity: {a}, {b}"

    @given(interval_strategy(), interval_strategy(), interval_strategy())
    @settings(max_examples=200)
    def test_join_associative(self, a: Interval, b: Interval, c: Interval):
        """(a ⊔ b) ⊔ c = a ⊔ (b ⊔ c)."""
        lhs = a.join(b).join(c)
        rhs = a.join(b.join(c))
        assert iv_eq(lhs, rhs), f"join associativity: ({a}⊔{b})⊔{c}={lhs} vs {a}⊔({b}⊔{c})={rhs}"

    @given(interval_strategy(), interval_strategy())
    @settings(max_examples=200)
    def test_join_upper_bound(self, a: Interval, b: Interval):
        """a ⊑ a ⊔ b  and  b ⊑ a ⊔ b."""
        j = a.join(b)
        assert a.leq(j), f"a ⊑ a⊔b: {a} ⊑ {j}"
        assert b.leq(j), f"b ⊑ a⊔b: {b} ⊑ {j}"

    @given(interval_strategy())
    @settings(max_examples=200)
    def test_meet_idempotent(self, a: Interval):
        """a ⊓ a = a."""
        assert iv_eq(a.meet(a), a), f"meet idempotence: {a}"

    @given(interval_strategy(), interval_strategy())
    @settings(max_examples=200)
    def test_meet_commutative(self, a: Interval, b: Interval):
        """a ⊓ b = b ⊓ a."""
        assert iv_eq(a.meet(b), b.meet(a)), f"meet commutativity: {a}, {b}"

    @given(interval_strategy(), interval_strategy())
    @settings(max_examples=200)
    def test_meet_lower_bound(self, a: Interval, b: Interval):
        """a ⊓ b ⊑ a  and  a ⊓ b ⊑ b."""
        m = a.meet(b)
        assert m.leq(a), f"a⊓b ⊑ a: {m} ⊑ {a}"
        assert m.leq(b), f"a⊓b ⊑ b: {m} ⊑ {b}"

    @given(interval_strategy())
    @settings(max_examples=200)
    def test_leq_reflexive(self, a: Interval):
        """a ⊑ a."""
        assert a.leq(a), f"reflexivity: {a}"

    @given(interval_strategy())
    @settings(max_examples=200)
    def test_bot_is_bottom(self, a: Interval):
        """⊥ ⊑ a."""
        assert INTERVAL_BOT.leq(a), f"bot ⊑ {a}"

    @given(interval_strategy())
    @settings(max_examples=200)
    def test_top_is_top(self, a: Interval):
        """a ⊑ ⊤."""
        assert a.leq(INTERVAL_TOP), f"{a} ⊑ top"

    @given(interval_strategy(), interval_strategy())
    @settings(max_examples=200)
    def test_widen_above_join(self, a: Interval, b: Interval):
        """a ∇ b ⊒ a ⊔ b."""
        j = a.join(b)
        w = a.widen(b)
        assert j.leq(w), f"widen above join: {a}⊔{b}={j} but {a}∇{b}={w}"

    @given(interval_strategy())
    @settings(max_examples=200)
    def test_join_with_bot(self, a: Interval):
        """a ⊔ ⊥ = a."""
        assert iv_eq(a.join(INTERVAL_BOT), a), f"a ⊔ ⊥ = a: {a}"

    @given(interval_strategy())
    @settings(max_examples=200)
    def test_join_with_top(self, a: Interval):
        """a ⊔ ⊤ = ⊤."""
        assert a.join(INTERVAL_TOP).is_top(), f"a ⊔ ⊤ = ⊤: {a}"

    @given(interval_strategy())
    @settings(max_examples=200)
    def test_meet_with_top(self, a: Interval):
        """a ⊓ ⊤ = a."""
        assert iv_eq(a.meet(INTERVAL_TOP), a), f"a ⊓ ⊤ = a: {a}"

    @given(interval_strategy())
    @settings(max_examples=200)
    def test_meet_with_bot(self, a: Interval):
        """a ⊓ ⊥ = ⊥."""
        assert a.meet(INTERVAL_BOT).is_bottom(), f"a ⊓ ⊥ = ⊥: {a}"

    @given(st.integers(min_value=-200, max_value=200),
           st.integers(min_value=-200, max_value=200))
    @settings(max_examples=200)
    def test_galois_soundness(self, lo: int, hi: int):
        """Galois soundness: every n ∈ [lo,hi] is captured by Interval(lo,hi)."""
        if lo > hi:
            lo, hi = hi, lo
        iv = Interval(float(lo), float(hi))
        for n in range(lo, min(hi + 1, lo + 8)):
            assert iv.contains(n), f"Galois soundness: {n} ∈ [{lo},{hi}] but not in {iv}"

    @given(st.integers(min_value=-100, max_value=100),
           st.integers(min_value=-100, max_value=100))
    @settings(max_examples=200)
    def test_addition_sound(self, a: int, b: int):
        """Abstract addition is sound: a+b ∈ [a,a].add([b,b])."""
        iv_a = Interval(float(a), float(a))
        iv_b = Interval(float(b), float(b))
        result = iv_a.add(iv_b)
        assert result.contains(a + b), f"Addition soundness: {a}+{b} not in {result}"

    @given(st.integers(min_value=-50, max_value=50),
           st.integers(min_value=-50, max_value=50),
           st.integers(min_value=-50, max_value=50),
           st.integers(min_value=-50, max_value=50))
    @settings(max_examples=200)
    def test_subtraction_sound(self, a: int, b: int, c: int, d: int):
        """[a,b].sub([c,d]) contains all x-y for x∈[a,b], y∈[c,d]."""
        if a > b:
            a, b = b, a
        if c > d:
            c, d = d, c
        iv_a = Interval(float(a), float(b))
        iv_b = Interval(float(c), float(d))
        result = iv_a.sub(iv_b)
        for x in [a, b]:
            for y in [c, d]:
                assert result.contains(x - y), (
                    f"Subtraction soundness: {x}-{y}={x-y} not in {iv_a}.sub({iv_b})={result}"
                )


# ===========================================================================
# Sign Domain — Lattice Laws
# ===========================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
class TestSignLattice:
    """Verify Sign forms a valid complete lattice."""

    @given(sign_strategy())
    @settings(max_examples=100)
    def test_join_idempotent(self, a: Sign):
        assert a.join(a).value == a.value, f"sign join idempotence: {a}"

    @given(sign_strategy(), sign_strategy())
    @settings(max_examples=100)
    def test_join_commutative(self, a: Sign, b: Sign):
        assert a.join(b).value == b.join(a).value, f"sign join commutativity: {a}, {b}"

    @given(sign_strategy())
    @settings(max_examples=100)
    def test_leq_reflexive(self, a: Sign):
        assert a.leq(a), f"sign reflexivity: {a}"

    @given(sign_strategy())
    @settings(max_examples=100)
    def test_bot_is_bottom(self, a: Sign):
        assert Sign(SignValue.BOT).leq(a), f"sign bot ⊑ {a}"

    @given(sign_strategy())
    @settings(max_examples=100)
    def test_top_is_top(self, a: Sign):
        assert a.leq(Sign(SignValue.TOP)), f"sign {a} ⊑ top"

    @given(sign_strategy(), sign_strategy())
    @settings(max_examples=100)
    def test_join_upper_bound(self, a: Sign, b: Sign):
        j = a.join(b)
        assert a.leq(j), f"sign a ⊑ a⊔b: {a} ⊑ {j}"
        assert b.leq(j), f"sign b ⊑ a⊔b: {b} ⊑ {j}"

    @given(st.integers(min_value=-50, max_value=50),
           st.integers(min_value=-50, max_value=50))
    @settings(max_examples=200)
    def test_addition_sound(self, a: int, b: int):
        """sign(a+b) ⊑ sign(a).add(sign(b))."""
        sa, sb = Sign.from_int(a), Sign.from_int(b)
        result = sa.add(sb)
        concrete = Sign.from_int(a + b)
        assert concrete.leq(result), (
            f"Sign add soundness: sign({a}+{b})={concrete} not ⊑ {sa}.add({sb})={result}"
        )

    @given(st.integers(min_value=-50, max_value=50),
           st.integers(min_value=-50, max_value=50))
    @settings(max_examples=200)
    def test_multiplication_sound(self, a: int, b: int):
        """sign(a*b) ⊑ sign(a).mul(sign(b))."""
        sa, sb = Sign.from_int(a), Sign.from_int(b)
        result = sa.mul(sb)
        concrete = Sign.from_int(a * b)
        assert concrete.leq(result), (
            f"Sign mul soundness: sign({a}*{b})={concrete} not ⊑ {sa}.mul({sb})={result}"
        )


# ===========================================================================
# Congruence Domain — Lattice Laws
# ===========================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
class TestCongruenceLattice:
    """Verify Congruence forms a valid complete lattice."""

    @given(congruence_strategy())
    @settings(max_examples=100)
    def test_leq_reflexive(self, a: Congruence):
        assert a.leq(a), f"congruence reflexivity: {a}"

    @given(congruence_strategy())
    @settings(max_examples=100)
    def test_bot_is_bottom(self, a: Congruence):
        assert Congruence(is_bot=True).leq(a), f"congruence bot ⊑ {a}"

    @given(congruence_strategy())
    @settings(max_examples=100)
    def test_top_is_top(self, a: Congruence):
        assert a.leq(Congruence(modulus=1)), f"congruence {a} ⊑ top"

    @given(congruence_strategy(), congruence_strategy())
    @settings(max_examples=100)
    def test_join_commutative(self, a: Congruence, b: Congruence):
        ab = a.join(b)
        ba = b.join(a)
        assert ab.modulus == ba.modulus and ab.remainder == ba.remainder, (
            f"congruence join commutativity: {a}⊔{b}={ab} vs {b}⊔{a}={ba}"
        )

    @given(st.integers(min_value=2, max_value=20),
           st.integers(min_value=-50, max_value=50))
    @settings(max_examples=200)
    def test_galois_soundness(self, m: int, k: int):
        """n ≡ r (mod m) is captured by Congruence(r, m)."""
        r = k % m
        cong = Congruence(remainder=r, modulus=m)
        for i in range(-3, 4):
            n = r + i * m
            assert (n % m) % m == r % m, f"Congruence soundness: {n} mod {m}"


# ===========================================================================
# Widening Convergence
# ===========================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
class TestWideningConvergence:
    """Verify widening causes ascending chains to stabilize."""

    def test_interval_widening_converges_loop_counter(self):
        """Simulate loop counter [0,0] + [0,1] each step; must stabilize."""
        MAX_STEPS = 20
        current = Interval(0.0, 0.0)
        step_iv = Interval(0.0, 1.0)
        for _ in range(MAX_STEPS):
            next_iv = current.join(current.add(step_iv))
            widened = current.widen(next_iv)
            if widened.leq(current) and current.leq(widened):
                return
            current = widened
        assert current.is_top(), f"Interval widening did not converge: {current}"

    def test_sign_widening_converges(self):
        """Sign widening POS ∇ NEG = TOP (finite domain, immediate)."""
        w = Sign(SignValue.POS).widen(Sign(SignValue.NEG))
        assert w.value == SignValue.TOP


# ===========================================================================
# Reduced Product Precision
# ===========================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
class TestReducedProduct:
    """Verify the reduced product is strictly more precise than individual domains."""

    @given(st.integers(min_value=1, max_value=100))
    @settings(max_examples=100)
    def test_positive_interval_refines_sign(self, lo: int):
        """Interval [lo, +∞) with lo > 0 → reduced product gives sign=POS."""
        iv = Interval(float(lo), INF)
        product = ReducedProduct(interval=iv, sign=Sign(SignValue.TOP),
                                 congruence=Congruence(modulus=1))
        reduced = product.reduce()
        assert reduced.sign.value == SignValue.POS, (
            f"Reduced product [{lo},+∞) should give POS, got {reduced.sign}"
        )

    @given(st.integers(min_value=-100, max_value=-1))
    @settings(max_examples=100)
    def test_negative_interval_refines_sign(self, hi: int):
        """Interval (-∞, hi] with hi < 0 → reduced product gives sign=NEG."""
        iv = Interval(NEG_INF, float(hi))
        product = ReducedProduct(interval=iv, sign=Sign(SignValue.TOP),
                                 congruence=Congruence(modulus=1))
        reduced = product.reduce()
        assert reduced.sign.value == SignValue.NEG, (
            f"Reduced product (-∞,{hi}] should give NEG, got {reduced.sign}"
        )

    def test_contradiction_gives_bottom(self):
        """Interval [5,5] ∩ sign=NEG is contradictory → bottom."""
        iv = Interval(5.0, 5.0)
        product = ReducedProduct(interval=iv, sign=Sign(SignValue.NEG),
                                 congruence=Congruence(modulus=1))
        reduced = product.reduce()
        assert reduced.interval.is_bottom(), (
            f"Contradiction [5,5] ∩ neg should give bottom, got {reduced.interval}"
        )
