"""AEON Finding Prioritization — Rank Findings by Real-World Impact.

Combines confidence score, severity, category, and code hotness
(git modification frequency) to produce a single priority ranking.

Formula:
  impact_score = confidence * severity_weight * category_weight * hotness_boost

Where:
  severity_weight: error=3.0, warning=1.0, info=0.3
  category_weight: security=2.5, money=2.0, correctness=1.0, performance=0.8, style=0.3
  hotness_boost:   1.0 (default) + 0.5 if modified in last 7 days
"""

from __future__ import annotations

import os
import subprocess
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta

from aeon.engines.finding_quality import QualifiedFinding


# ---------------------------------------------------------------------------
# Weight Tables
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: Dict[str, float] = {
    "error": 3.0,
    "warning": 1.0,
    "info": 0.3,
}

CATEGORY_WEIGHTS: Dict[str, float] = {
    "security": 2.5,
    "money": 2.0,
    "correctness": 1.0,
    "performance": 0.8,
    "style": 0.3,
}


# ---------------------------------------------------------------------------
# Git Hotness
# ---------------------------------------------------------------------------

def get_file_hotness(filepath: str, days: int = 30) -> float:
    """Get how 'hot' a file is based on recent git activity.

    Returns a multiplier:
      1.0 = no recent changes
      1.5 = changed in last 7 days
      1.3 = changed in last 30 days
      1.0 = not changed recently
    """
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", f"--since={days} days ago", "--", filepath],
            capture_output=True, text=True, timeout=5,
            cwd=os.path.dirname(filepath) or ".",
        )
        if result.returncode != 0:
            return 1.0

        commit_count = len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0

        if commit_count == 0:
            return 1.0
        elif commit_count >= 5:
            return 1.5  # Very active file
        elif commit_count >= 2:
            return 1.3
        else:
            return 1.1
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return 1.0


# ---------------------------------------------------------------------------
# Impact Scoring
# ---------------------------------------------------------------------------

def compute_impact_score(finding: QualifiedFinding,
                         hotness: float = 1.0) -> float:
    """Compute the impact score for a finding."""
    severity_w = SEVERITY_WEIGHTS.get(finding.severity, 1.0)
    category_w = CATEGORY_WEIGHTS.get(finding.category, 1.0)
    return finding.confidence * severity_w * category_w * hotness


def prioritize_findings(findings: List[QualifiedFinding],
                        project_root: str = "",
                        use_git: bool = True,
                        top_n: int = 0) -> List[QualifiedFinding]:
    """Sort findings by real-world impact.

    Args:
        findings: List of qualified findings
        project_root: Root directory for git hotness lookup
        use_git: Whether to use git log for hotness
        top_n: Only return top N findings (0=all)
    """
    # Compute hotness per file (cache to avoid repeated git calls)
    hotness_cache: Dict[str, float] = {}

    for f in findings:
        if f.suppressed:
            continue
        filepath = f.file
        if filepath and use_git and project_root:
            full_path = os.path.join(project_root, filepath)
            if filepath not in hotness_cache:
                hotness_cache[filepath] = get_file_hotness(full_path)

    # Score and sort
    scored: List[tuple[float, QualifiedFinding]] = []
    for f in findings:
        if f.suppressed:
            continue
        hotness = hotness_cache.get(f.file, 1.0)
        score = compute_impact_score(f, hotness)
        scored.append((score, f))

    scored.sort(key=lambda x: -x[0])

    result = [f for _, f in scored]
    if top_n > 0:
        result = result[:top_n]

    return result
