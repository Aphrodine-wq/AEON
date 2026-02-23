"""AEON Analysis Profiles — Zero-config presets for common use cases.

Profiles map friendly names to sets of analysis engines, so engineers
can run ``aeon check app.py --profile security`` instead of memorizing
fifteen flags.

Built-in profiles:
    quick       — fastest subset (~1 s), catches the most common bugs
    daily       — default "daily driver" covering security + correctness
    security    — taint + info-flow + noninterference + symbolic
    performance — complexity + abstract interp + termination
    safety      — all engines (equivalent to --deep-verify)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AnalysisProfile:
    """A named bundle of analysis engine toggles."""
    name: str
    description: str
    engines: Dict[str, bool] = field(default_factory=dict)

    def to_prove_kwargs(self) -> Dict[str, bool]:
        """Return keyword arguments suitable for ``prove()``."""
        return dict(self.engines)


# ── Built-in profiles ────────────────────────────────────────────────────

PROFILES: Dict[str, AnalysisProfile] = {}


def _register(name: str, description: str, engines: Dict[str, bool]) -> None:
    PROFILES[name] = AnalysisProfile(name=name, description=description, engines=engines)


# -- quick: fastest useful subset -----------------------------------------
_register("quick", "Fast check — symbolic execution + abstract interpretation", {
    "symbolic_exec": True,
    "abstract_interpretation": True,
    "verify_contracts": True,
})

# -- daily: sensible default for everyday use -----------------------------
_register("daily", "Daily driver — security + correctness + common bugs", {
    "verify_contracts": True,
    "symbolic_exec": True,
    "abstract_interpretation": True,
    "taint_analysis": True,
    "concurrency_check": True,
    "hoare_logic": True,
})

# -- security: focus on vulnerabilities -----------------------------------
_register("security", "Security focused — taint, info-flow, symbolic, separation", {
    "verify_contracts": True,
    "symbolic_exec": True,
    "taint_analysis": True,
    "information_flow": True,
    "separation_logic": True,
    "concurrency_check": True,
})

# -- performance: focus on efficiency & termination -----------------------
_register("performance", "Performance — complexity, abstract interp, termination", {
    "verify_contracts": True,
    "abstract_interpretation": True,
    "size_change": True,
    "analyze_termination": True,
    "complexity_analysis": True,
    "algebraic_effects": True,
})

# -- safety: everything (mirrors --deep-verify) ---------------------------
_register("safety", "All engines — maximum verification depth", {
    "deep_verify": True,
})


def get_profile(name: str) -> Optional[AnalysisProfile]:
    """Look up a profile by name (case-insensitive)."""
    return PROFILES.get(name.lower())


def list_profiles() -> List[AnalysisProfile]:
    """Return all registered profiles."""
    return list(PROFILES.values())


def profile_names() -> List[str]:
    """Return the names of all registered profiles."""
    return list(PROFILES.keys())


def resolve_profile_to_prove_kwargs(
    profile_name: Optional[str] = None,
    deep_verify: bool = False,
) -> Dict[str, bool]:
    """Resolve a profile name (or --deep-verify) into kwargs for ``prove()``.

    Priority:
        1. Explicit ``--deep-verify`` always wins → returns ``{deep_verify: True}``
        2. Named profile → returns engine toggles from the profile
        3. No profile, no deep-verify → returns the "daily" defaults
    """
    if deep_verify:
        return {"deep_verify": True}

    if profile_name:
        profile = get_profile(profile_name)
        if profile is None:
            available = ", ".join(profile_names())
            raise ValueError(
                f"Unknown profile '{profile_name}'. Available: {available}"
            )
        return profile.to_prove_kwargs()

    # Default: daily profile
    return PROFILES["daily"].to_prove_kwargs()
