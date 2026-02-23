"""AEON Dead Code Analysis — proxy module.

Re-exports from aeon.engines.deadcode for top-level access.
"""

from aeon.engines.deadcode import check_deadcode

__all__ = ["check_deadcode"]
