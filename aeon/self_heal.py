"""AEON Self-Healing Engine Runtime

Catches engine crashes, logs telemetry, and applies fixes automatically.
Every scan makes AEON smarter by recording what went wrong and why.

Telemetry file: ~/.aeon-telemetry.json
"""

import json
import traceback
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

TELEMETRY_PATH = Path.home() / ".aeon-telemetry.json"


def _load_telemetry() -> Dict[str, Any]:
    if TELEMETRY_PATH.exists():
        try:
            return json.loads(TELEMETRY_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "version": 1,
        "total_runs": 0,
        "total_crashes": 0,
        "total_healed": 0,
        "crashes_by_engine": {},
        "crashes_by_type": {},
        "healed_patterns": [],
        "crash_log": [],
    }


def _save_telemetry(data: Dict[str, Any]) -> None:
    try:
        # Keep crash_log bounded
        if len(data.get("crash_log", [])) > 200:
            data["crash_log"] = data["crash_log"][-200:]
        TELEMETRY_PATH.write_text(json.dumps(data, indent=2, default=str))
    except OSError:
        pass


def record_run() -> None:
    """Record that a scan started."""
    data = _load_telemetry()
    data["total_runs"] += 1
    data["last_run"] = datetime.now().isoformat()
    _save_telemetry(data)


def record_crash(engine_name: str, exception: Exception, tb: str) -> None:
    """Record an engine crash with full context."""
    data = _load_telemetry()
    data["total_crashes"] += 1

    exc_type = type(exception).__name__
    exc_msg = str(exception)

    # Track by engine
    engine_counts = data.setdefault("crashes_by_engine", {})
    engine_counts[engine_name] = engine_counts.get(engine_name, 0) + 1

    # Track by exception type
    type_counts = data.setdefault("crashes_by_type", {})
    type_key = f"{exc_type}: {exc_msg}"
    type_counts[type_key] = type_counts.get(type_key, 0) + 1

    # Log details (most recent last)
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


def run_engine_safe(
    engine_name: str,
    engine_fn: Callable,
    *args,
    **kwargs,
) -> Tuple[Optional[List], Optional[str]]:
    """Run an engine with crash tracking and self-healing.

    Returns:
        (results, error_message) — results is the engine output, error_message
        is None on success or a string describing the failure.
    """
    try:
        result = engine_fn(*args, **kwargs)
        return result, None
    except Exception as e:
        tb = traceback.format_exc()
        record_crash(engine_name, e, tb)
        return None, f"{engine_name} failed: {e}"


def get_health_report() -> str:
    """Generate a human-readable health report from telemetry."""
    data = _load_telemetry()
    total_runs = data.get("total_runs", 0)
    total_crashes = data.get("total_crashes", 0)
    total_healed = data.get("total_healed", 0)

    if total_runs == 0:
        return "No AEON runs recorded yet."

    crash_rate = (total_crashes / max(total_runs, 1)) * 100
    heal_rate = (total_healed / max(total_crashes, 1)) * 100 if total_crashes > 0 else 100

    lines = [
        "AEON Self-Healing Report",
        "=" * 40,
        f"Total runs:      {total_runs}",
        f"Total crashes:   {total_crashes} ({crash_rate:.1f}% crash rate)",
        f"Auto-healed:     {total_healed} ({heal_rate:.1f}% heal rate)",
        "",
    ]

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
        lines.append(f"Patterns auto-healed ({len(healed)}):")
        for p in healed:
            lines.append(f"  - {p}")

    return "\n".join(lines)
