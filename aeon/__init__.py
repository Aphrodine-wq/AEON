"""AEON — AI-Native Programming Language & Compiler"""

__version__ = "0.5.0"

try:
    from aeon import compiler
except ImportError:
    pass

try:
    from aeon import engines
except ImportError:
    pass

try:
    from aeon import adapters
except ImportError:
    pass

try:
    from aeon import enterprise
except ImportError:
    pass

try:
    from aeon import ai
except ImportError:
    pass
