"""AEON Configuration — Project-level .aeonrc.yml support.

Loads configuration from .aeonrc.yml (or .aeonrc.yaml, .aeonrc.json)
in the project root. Allows teams to configure:
  - Which engines to enable/disable
  - Severity thresholds
  - File include/exclude patterns
  - Per-directory rule overrides

Example .aeonrc.yml:
    engines:
      symbolic_execution: true
      taint_analysis: true
      separation_logic: false   # disable for this project
    severity: warning            # minimum severity to report
    include:
      - "src/**/*.py"
      - "lib/**/*.go"
    exclude:
      - "tests/**"
      - "vendor/**"
    parallel: true
    baseline: .aeon-baseline.json
"""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class AeonConfig:
    """Project-level AEON configuration."""
    # Analysis profile: "quick", "daily", "security", "performance", "safety"
    profile: str = ""
    # Engine toggles
    engines: Dict[str, bool] = field(default_factory=dict)
    # Minimum severity: "error", "warning", "info"
    severity: str = "warning"
    # File patterns
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    # Features
    deep_verify: bool = True
    parallel: bool = False
    parallel_workers: int = 0  # 0 = auto (cpu_count)
    # Baseline
    baseline: str = ""
    # Output
    format: str = "pretty"  # "pretty", "text", "json", "sarif", "markdown"
    # Custom rules
    custom_taint_sources: List[str] = field(default_factory=list)
    custom_taint_sinks: List[str] = field(default_factory=list)

    def get_analyses(self) -> Optional[List[str]]:
        """Get the list of enabled analyses, or None for all."""
        enabled = [name for name, on in self.engines.items() if on]
        disabled = [name for name, on in self.engines.items() if not on]

        if not self.engines:
            return None  # No config = use deep_verify default

        if enabled and not disabled:
            return enabled

        return None  # Let deep_verify handle it

    def should_include(self, filepath: str) -> bool:
        """Check if a file should be included based on patterns."""
        import fnmatch
        if not self.include:
            return True
        return any(fnmatch.fnmatch(filepath, p) for p in self.include)

    def should_exclude(self, filepath: str) -> bool:
        """Check if a file should be excluded based on patterns."""
        import fnmatch
        if not self.exclude:
            return False
        return any(fnmatch.fnmatch(filepath, p) for p in self.exclude)


# ---------------------------------------------------------------------------
# Config file names (in priority order)
# ---------------------------------------------------------------------------

_CONFIG_FILES = [
    ".aeonrc.yml",
    ".aeonrc.yaml",
    ".aeonrc.json",
    "aeon.config.yml",
    "aeon.config.json",
]


def find_config(start_dir: str = ".") -> Optional[str]:
    """Find the nearest config file by walking up from start_dir."""
    current = os.path.abspath(start_dir)
    while True:
        for name in _CONFIG_FILES:
            path = os.path.join(current, name)
            if os.path.isfile(path):
                return path
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def load_config(path: Optional[str] = None, start_dir: str = ".") -> AeonConfig:
    """Load configuration from a file.

    If no path is given, searches for a config file starting from start_dir.
    If no config file is found, returns defaults.
    """
    if path is None:
        path = find_config(start_dir)

    if path is None:
        return AeonConfig()

    try:
        with open(path, "r") as f:
            content = f.read()
    except (IOError, OSError):
        return AeonConfig()

    # Parse based on extension
    if path.endswith(".json"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return AeonConfig()
    else:
        # YAML parsing (simple key-value for common cases, no PyYAML dependency)
        data = _parse_simple_yaml(content)

    return _dict_to_config(data)


def _parse_simple_yaml(content: str) -> Dict[str, Any]:
    """Parse simple YAML without requiring PyYAML.

    Handles flat key: value pairs and simple nested dicts/lists.
    For full YAML, install PyYAML.
    """
    try:
        import yaml
        return yaml.safe_load(content) or {}
    except ImportError:
        pass

    # Fallback: simple line-by-line parser
    result: Dict[str, Any] = {}
    current_section = None
    current_list = None

    for line in content.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0 and ':' in stripped:
            key, _, value = stripped.partition(':')
            key = key.strip()
            value = value.strip()
            if value:
                result[key] = _parse_yaml_value(value)
                current_section = None
                current_list = None
            else:
                result[key] = {}
                current_section = key
                current_list = None

        elif indent > 0 and current_section is not None:
            if stripped.startswith('- '):
                item = stripped[2:].strip()
                if not isinstance(result[current_section], list):
                    result[current_section] = []
                result[current_section].append(_parse_yaml_value(item))
            elif ':' in stripped:
                key, _, value = stripped.partition(':')
                key = key.strip()
                value = value.strip()
                if isinstance(result[current_section], dict):
                    result[current_section][key] = _parse_yaml_value(value)

    return result


def _parse_yaml_value(value: str) -> Any:
    """Parse a YAML scalar value."""
    if value.lower() in ('true', 'yes', 'on'):
        return True
    if value.lower() in ('false', 'no', 'off'):
        return False
    if value.lower() in ('null', 'none', '~'):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value.strip('"').strip("'")


def _dict_to_config(data: Dict[str, Any]) -> AeonConfig:
    """Convert a parsed dict to AeonConfig."""
    config = AeonConfig()

    if "profile" in data:
        config.profile = str(data["profile"])
    if "engines" in data and isinstance(data["engines"], dict):
        config.engines = {k: bool(v) for k, v in data["engines"].items()}
    if "severity" in data:
        config.severity = str(data["severity"])
    if "include" in data and isinstance(data["include"], list):
        config.include = [str(p) for p in data["include"]]
    if "exclude" in data and isinstance(data["exclude"], list):
        config.exclude = [str(p) for p in data["exclude"]]
    if "deep_verify" in data:
        config.deep_verify = bool(data["deep_verify"])
    if "parallel" in data:
        config.parallel = bool(data["parallel"])
    if "parallel_workers" in data:
        config.parallel_workers = int(data["parallel_workers"])
    if "baseline" in data:
        config.baseline = str(data["baseline"])
    if "format" in data:
        config.format = str(data["format"])
    if "custom_taint_sources" in data and isinstance(data["custom_taint_sources"], list):
        config.custom_taint_sources = [str(s) for s in data["custom_taint_sources"]]
    if "custom_taint_sinks" in data and isinstance(data["custom_taint_sinks"], list):
        config.custom_taint_sinks = [str(s) for s in data["custom_taint_sinks"]]

    return config
