"""AEON Test Suite Configuration.

Registers custom markers and shared fixtures for all test modules.
"""

import pytest


def pytest_configure(config):
    """Register custom markers to avoid PytestUnknownMarkWarning."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "requires_z3: marks tests that require the z3-solver package"
    )
    config.addinivalue_line(
        "markers", "requires_llvmlite: marks tests that require llvmlite"
    )
    config.addinivalue_line(
        "markers", "requires_hypothesis: marks tests that require hypothesis"
    )
    config.addinivalue_line(
        "markers", "requires_api_key: marks tests that require an API key"
    )
