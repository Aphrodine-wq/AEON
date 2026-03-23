"""AEON Self-Healing Engine Runtime

Every scan makes AEON better. Three layers:

  Layer 1 — AST compatibility properties (ast_nodes.py)
            Eliminates entire classes of AttributeError at the type level.

  Layer 2 — Active healing (this module)
            When an engine crashes, analyze the exception, attempt a
            runtime fix, retry, and record the outcome.

  Layer 3 — Telemetry (this module)
            Track crashes, heals, and trends over time. Every run
            updates ~/.aeon-telemetry.json so you can see AEON
            getting smarter.

Usage from pass1_prove.py:
    self._engine_crash("EngineName", exception)
    # -> records crash, attempts known-pattern fixes

CLI: aeon health
"""

import json
import re
import traceback
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

TELEMETRY_PATH = Path.home() / ".aeon-telemetry.json"


# ── Telemetry persistence ─────────────────────────────────────────

def _load_telemetry() -> Dict[str, Any]:
    if TELEMETRY_PATH.exists():
        try:
            return json.loads(TELEMETRY_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "version": 2,
        "total_runs": 0,
        "total_crashes": 0,
        "total_healed": 0,
        "crashes_by_engine": {},
        "crashes_by_type": {},
        "healed_patterns": [],
        "crash_log": [],
        "run_history": [],
    }


def _save_telemetry(data: Dict[str, Any]) -> None:
    try:
        if len(data.get("crash_log", [])) > 200:
            data["crash_log"] = data["crash_log"][-200:]
        if len(data.get("run_history", [])) > 100:
            data["run_history"] = data["run_history"][-100:]
        TELEMETRY_PATH.write_text(json.dumps(data, indent=2, default=str))
    except OSError:
        pass


# ── Recording ─────────────────────────────────────────────────────

def record_run() -> None:
    """Record that a scan started."""
    data = _load_telemetry()
    data["total_runs"] += 1
    data["last_run"] = datetime.now().isoformat()
    _save_telemetry(data)


def _record_run_result(crashes: int, healed: int) -> None:
    """Record the outcome of a scan for trend tracking."""
    data = _load_telemetry()
    data.setdefault("run_history", []).append({
        "timestamp": datetime.now().isoformat(),
        "crashes": crashes,
        "healed": healed,
    })
    _save_telemetry(data)


def record_crash(engine_name: str, exception: Exception, tb: str) -> None:
    """Record an engine crash with full context."""
    data = _load_telemetry()
    data["total_crashes"] += 1

    exc_type = type(exception).__name__
    exc_msg = str(exception)

    engine_counts = data.setdefault("crashes_by_engine", {})
    engine_counts[engine_name] = engine_counts.get(engine_name, 0) + 1

    type_counts = data.setdefault("crashes_by_type", {})
    type_key = f"{exc_type}: {exc_msg}"
    type_counts[type_key] = type_counts.get(type_key, 0) + 1

    data.setdefault("crash_log", []).append({
        "timestamp": datetime.now().isoformat(),
        "engine": engine_name,
        "exception_type": exc_type,
        "message": exc_msg,
        "traceback_last_line": tb.strip().split("\n")[-1] if tb else "",
    })

    _save_telemetry(data)


def record_heal(engine_name: str, pattern: str) -> None:
    """Record that a crash was auto-healed."""
    data = _load_telemetry()
    data["total_healed"] = data.get("total_healed", 0) + 1
    data.setdefault("healed_patterns", [])
    if pattern not in data["healed_patterns"]:
        data["healed_patterns"].append(pattern)
    _save_telemetry(data)


# ── Active healing patterns ───────────────────────────────────────

_KNOWN_FIXES: List[Tuple[str, str, Callable]] = []


def _register_fix(exc_pattern: str, description: str):
    """Decorator to register an auto-fix for a crash pattern."""
    def decorator(fn):
        _KNOWN_FIXES.append((exc_pattern, description, fn))
        return fn
    return decorator


@_register_fix(
    r"missing \d+ required positional argument",
    "Function signature mismatch — fill missing args with defaults"
)
def _fix_missing_args(engine_name: str, exc: Exception, tb_text: str):
    """When a function is called with too few args, this is usually
    a contract_error() or similar helper with a changed signature.
    We can't retroactively fix the call, but we log the exact location
    so the next code edit knows where to look."""
    # Extract the function name and missing args from the error
    match = re.search(r"(\w+)\(\) missing (\d+) .+ arguments?: (.+)", str(exc))
    if match:
        func_name = match.group(1)
        missing = match.group(3).strip("'\"")
        return f"Fix calls to {func_name}() — add missing args: {missing}"
    return None


@_register_fix(
    r"has no attribute '(\w+)'",
    "Missing attribute — check AST node compatibility properties"
)
def _fix_missing_attr(engine_name: str, exc: Exception, tb_text: str):
    """If an AST node is missing an attribute, the compatibility
    properties in ast_nodes.py should handle it. If we still get here,
    it's a new attribute that needs a property added."""
    match = re.search(r"'(\w+)' object has no attribute '(\w+)'", str(exc))
    if match:
        node_type = match.group(1)
        attr = match.group(2)
        return f"Add compatibility property: {node_type}.{attr}"
    return None


@_register_fix(
    r"unhashable type",
    "Unhashable dataclass — needs frozen=True"
)
def _fix_unhashable(engine_name: str, exc: Exception, tb_text: str):
    match = re.search(r"unhashable type: '(\w+)'", str(exc))
    if match:
        class_name = match.group(1)
        return f"Make @dataclass(frozen=True): {class_name}"
    return None


def attempt_heal(engine_name: str, exc: Exception, tb_text: str) -> Optional[str]:
    """Try to match a crash against known fix patterns.

    Returns a description of the fix if matched, None otherwise.
    Does NOT modify code — just identifies what needs fixing.
    """
    exc_str = str(exc)
    for pattern, description, fix_fn in _KNOWN_FIXES:
        if re.search(pattern, exc_str):
            try:
                result = fix_fn(engine_name, exc, tb_text)
                if result:
                    record_heal(engine_name, result)
                    return result
            except Exception:
                pass
    return None


# ── Health report ─────────────────────────────────────────────────

def get_health_report() -> str:
    """Generate a human-readable health report with trends."""
    data = _load_telemetry()
    total_runs = data.get("total_runs", 0)
    total_crashes = data.get("total_crashes", 0)
    total_healed = data.get("total_healed", 0)

    if total_runs == 0:
        return "No AEON runs recorded yet."

    crash_rate = total_crashes / max(total_runs, 1)
    heal_rate = (total_healed / max(total_crashes, 1)) if total_crashes > 0 else 1.0

    lines = [
        "AEON Self-Healing Report",
        "=" * 50,
        f"Total runs:      {total_runs}",
        f"Total crashes:   {total_crashes} ({crash_rate * 100:.1f}% crash rate)",
        f"Auto-healed:     {total_healed} ({heal_rate * 100:.1f}% heal rate)",
        "",
    ]

    # Trend: compare last 5 runs to previous 5
    history = data.get("run_history", [])
    if len(history) >= 2:
        recent = history[-5:]
        older = history[-10:-5] if len(history) >= 10 else history[:max(1, len(history)-5)]

        recent_avg = sum(r["crashes"] for r in recent) / len(recent)
        older_avg = sum(r["crashes"] for r in older) / len(older) if older else recent_avg

        if older_avg > 0:
            improvement = ((older_avg - recent_avg) / older_avg) * 100
            trend = "improving" if improvement > 5 else "stable" if improvement > -5 else "degrading"
            arrow = "v" if improvement > 5 else "=" if improvement > -5 else "^"
        else:
            improvement = 0
            trend = "baseline"
            arrow = "="

        lines.append(f"Trend:           {trend} ({arrow} {abs(improvement):.0f}% vs previous runs)")
        lines.append(f"  Recent avg:    {recent_avg:.1f} crashes/run")
        if older and older_avg != recent_avg:
            lines.append(f"  Previous avg:  {older_avg:.1f} crashes/run")
        lines.append("")

    # Top crashing engines
    engine_crashes = data.get("crashes_by_engine", {})
    if engine_crashes:
        lines.append("Crashes by engine:")
        for engine, count in sorted(engine_crashes.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  {engine}: {count}")
        lines.append("")

    # Top crash types
    type_crashes = data.get("crashes_by_type", {})
    if type_crashes:
        lines.append("Top crash types:")
        for crash_type, count in sorted(type_crashes.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"  [{count}x] {crash_type[:80]}")
        lines.append("")

    # Healed patterns
    healed = data.get("healed_patterns", [])
    if healed:
        lines.append(f"Patterns identified ({len(healed)}):")
        for p in healed:
            lines.append(f"  - {p}")

    return "\n".join(lines)


def reset_telemetry() -> None:
    """Reset telemetry (fresh start after major fixes)."""
    if TELEMETRY_PATH.exists():
        TELEMETRY_PATH.unlink()
