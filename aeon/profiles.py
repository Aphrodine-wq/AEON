"""AEON Analysis Profiles — Zero-config presets for common use cases.

Profiles map friendly names to sets of analysis engines, so engineers
can run ``aeon check app.py --profile security`` instead of memorizing
fifteen flags.

Built-in profiles:
    quick        — fastest subset (~1 s), catches the most common bugs
    daily        — default "daily driver" covering security + correctness
    security     — taint + info-flow + noninterference + symbolic
    performance  — complexity + abstract interp + termination
    construction — money math + numeric safety + domain rules
    cybersecurity— full OWASP Top 10 + 22 cybersecurity engines
    safety       — all engines (equivalent to --deep-verify)

Stack-tuned profiles:
    nextjs    — Next.js/TypeScript/React (FTW, MHP, FairEstimator)
    rust      — Rust/Bevy (WOS, Driftlands)
    elixir    — Elixir/Phoenix (ftw-realtime)
    python    — Python/ML (ConstructionAI, AEON, Claude Eyes)
    portfolio — meta-profile, auto-selects per project
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
_register("security", "Security focused — taint, info-flow, symbolic, separation, money + cybersecurity engines", {
    "verify_contracts": True,
    "symbolic_exec": True,
    "taint_analysis": True,
    "information_flow": True,
    "separation_logic": True,
    "concurrency_check": True,
    "money_math": True,
    "numeric_safety": True,
    # Cybersecurity engines
    "secret_detection": True,
    "auth_check": True,
    "crypto_misuse": True,
    "injection_advanced": True,
    "session_jwt": True,
    "ssrf_advanced": True,
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

# -- construction: money math + security for estimation/invoicing ----------
_register("construction", "Construction & financial — money math, taint, numeric safety, domain rules", {
    "verify_contracts": True,
    "symbolic_exec": True,
    "taint_analysis": True,
    "information_flow": True,
    "numeric_safety": True,
    "money_math": True,
    "concurrency_check": True,
    "framework_rules": True,
    "construction_domain": True,
})

# -- cybersecurity: full OWASP + supply chain + infrastructure + advanced ---
_register("cybersecurity", "Full cybersecurity audit — 22 engines: OWASP Top 10, business logic, supply chain, infrastructure, privacy, advanced attacks", {
    "verify_contracts": True,
    "symbolic_exec": True,
    "taint_analysis": True,
    "information_flow": True,
    "separation_logic": True,
    "concurrency_check": True,
    # All 22 cybersecurity engines
    "secret_detection": True,
    "auth_check": True,
    "crypto_misuse": True,
    "injection_advanced": True,
    "api_security": True,
    "supply_chain": True,
    "session_jwt": True,
    "container_security": True,
    "ssrf_advanced": True,
    "prototype_pollution": True,
    # Tier 2
    "business_logic": True,
    "data_exposure": True,
    "security_misconfig": True,
    "oauth_oidc": True,
    "file_upload": True,
    "input_validation": True,
    "race_condition_security": True,
    "dependency_audit": True,
    "email_security": True,
    "insecure_randomness": True,
    "cache_poisoning": True,
    "http_smuggling": True,
})

# -- safety: everything (mirrors --deep-verify) ---------------------------
_register("safety", "All engines — maximum verification depth", {
    "deep_verify": True,
})


# ══════════════════════════════════════════════════════════════════════════
# Stack-Tuned Profiles — Tailored to James's tech stack
# ══════════════════════════════════════════════════════════════════════════

# -- nextjs: FTW, MHP, FairEstimator (Next.js / TypeScript / React) ------
_register("nextjs", (
    "Next.js/TypeScript/React — XSS, injection, auth bypass, API route security, "
    "React hook safety, type safety, full web cybersecurity. "
    "For FTW, MHP, FairEstimator. Skips systems-level engines "
    "(memory safety, ownership, separation logic)."
), {
    # Core verification
    "verify_contracts": True,
    "symbolic_exec": True,
    "hoare_logic": True,
    # Type safety & correctness
    "gradual_typing": True,
    "null_safety": True,
    "error_handling": True,
    "deadcode": True,
    # Web-specific analysis
    "taint_analysis": True,
    "information_flow": True,
    "framework_rules": True,
    "money_math": True,
    "numeric_safety": True,
    # Full web cybersecurity — OWASP Top 10 + advanced
    "secret_detection": True,
    "auth_check": True,
    "crypto_misuse": True,
    "injection_advanced": True,
    "api_security": True,
    "supply_chain": True,
    "session_jwt": True,
    "ssrf_advanced": True,
    "prototype_pollution": True,
    "business_logic": True,
    "data_exposure": True,
    "security_misconfig": True,
    "oauth_oidc": True,
    "file_upload": True,
    "input_validation": True,
    "race_condition_security": True,
    "dependency_audit": True,
    "insecure_randomness": True,
    "cache_poisoning": True,
    "http_smuggling": True,
})

# -- rust: WOS, Driftlands (Rust / Bevy) ---------------------------------
_register("rust", (
    "Rust/Bevy — ownership/borrowing correctness, unsafe blocks, concurrency, "
    "memory safety, panic paths, complexity analysis. "
    "For WOS, Driftlands. Skips web-specific engines."
), {
    # Core verification
    "verify_contracts": True,
    "symbolic_exec": True,
    "hoare_logic": True,
    # Memory & ownership (Rust's core concerns)
    "separation_logic": True,
    "linear_resource": True,
    "typestate": True,
    "shape_analysis": True,
    # Concurrency & correctness
    "concurrency_check": True,
    "model_checking": True,
    "abstract_interpretation": True,
    "abstract_refinement": True,
    # Termination & complexity
    "size_change": True,
    "complexity_analysis": True,
    "interpolation": True,
    # Safety nets
    "null_safety": True,
    "error_handling": True,
    "deadcode": True,
    "numeric_safety": True,
    # Minimal security (supply chain for crate audits)
    "dependency_audit": True,
    "secret_detection": True,
})

# -- elixir: ftw-realtime (Elixir / Phoenix) -----------------------------
_register("elixir", (
    "Elixir/Phoenix — channel security, auth, race conditions, process safety, "
    "OTP patterns, session types, taint analysis. "
    "For ftw-realtime. Skips memory management engines."
), {
    # Core verification
    "verify_contracts": True,
    "symbolic_exec": True,
    "hoare_logic": True,
    # Concurrency & process safety (Elixir's core concerns)
    "concurrency_check": True,
    "session_types": True,
    "race_condition_security": True,
    # Data flow & security
    "taint_analysis": True,
    "information_flow": True,
    # Web security (Phoenix channels, API endpoints)
    "auth_check": True,
    "secret_detection": True,
    "injection_advanced": True,
    "session_jwt": True,
    "ssrf_advanced": True,
    "input_validation": True,
    "data_exposure": True,
    "oauth_oidc": True,
    "security_misconfig": True,
    "api_security": True,
    "crypto_misuse": True,
    # Correctness
    "complexity_analysis": True,
    "error_handling": True,
    "null_safety": True,
    "deadcode": True,
})

# -- python: ConstructionAI, AEON, Claude Eyes ----------------------------
_register("python", (
    "Python — type safety, injection, dependency audit, ML pipeline safety, "
    "gradual typing, taint analysis, complexity. "
    "For ConstructionAI, AEON, Claude Eyes. Skips systems-level engines."
), {
    # Core verification
    "verify_contracts": True,
    "symbolic_exec": True,
    "hoare_logic": True,
    "abstract_interpretation": True,
    # Type safety (Python's biggest weakness)
    "gradual_typing": True,
    "null_safety": True,
    "error_handling": True,
    "deadcode": True,
    "api_contracts": True,
    "numeric_safety": True,
    # Data flow & injection
    "taint_analysis": True,
    "information_flow": True,
    "complexity_analysis": True,
    # Security (dependency supply chain is critical for Python)
    "secret_detection": True,
    "auth_check": True,
    "injection_advanced": True,
    "supply_chain": True,
    "dependency_audit": True,
    "input_validation": True,
    "data_exposure": True,
    "security_misconfig": True,
    "insecure_randomness": True,
})


# -- portfolio: meta-profile for scanning all projects at once ------------
_register("portfolio", (
    "Meta-profile — auto-selects the right profile per project. "
    "Maps FTW/MHP/FairEstimator to nextjs, Driftlands/WOS to rust, "
    "ftw-realtime to elixir, ConstructionAI/AEON/Claude Eyes to python. "
    "Use with 'aeon portfolio' or configure in ~/.aeon-portfolio.yml."
), {
    # Portfolio itself defaults to daily when used as a direct scan profile.
    # The real magic is in PORTFOLIO_PROJECT_PROFILES below, which maps
    # project aliases to their stack-tuned profiles for portfolio scans.
    "verify_contracts": True,
    "symbolic_exec": True,
    "abstract_interpretation": True,
    "taint_analysis": True,
    "concurrency_check": True,
    "hoare_logic": True,
})

# ── Portfolio Project Mapping ────────────────────────────────────────────
# Maps project aliases (as used in ~/.aeon-portfolio.yml) to the correct
# stack-tuned profile. Used by scan_portfolio() to auto-select engines.

PORTFOLIO_PROJECT_PROFILES: Dict[str, str] = {
    # Next.js / TypeScript / React projects
    "ftw": "nextjs",
    "fairtradeworker": "nextjs",
    "mhp": "nextjs",
    "mhp-web": "nextjs",
    "mhp-desktop": "nextjs",
    "mhpestimate": "nextjs",
    "fairestimator": "nextjs",
    # Rust / Bevy projects
    "driftlands": "rust",
    "wos": "rust",
    # Elixir / Phoenix projects
    "ftw-realtime": "elixir",
    # Python projects
    "constructionai": "python",
    "aeon": "python",
    "claude-eyes": "python",
    "claude-see-me": "python",
    "walt": "python",
}


def get_portfolio_profile(project_alias: str) -> str:
    """Look up the recommended profile for a project alias.

    Returns the stack-tuned profile name if the project is known,
    or 'daily' as a sensible default for unknown projects.
    """
    return PORTFOLIO_PROJECT_PROFILES.get(project_alias.lower(), "daily")


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
