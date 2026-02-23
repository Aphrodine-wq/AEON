"""AEON compiler pipeline — lexer, parser, type system, IR, and 3-pass compilation."""

from .lexer import Lexer
from .parser import Parser
from .ast_nodes import *
from .types import *
from .ir import *
from .errors import AeonError, AeonTypeError, AeonContractError, CompileError
from .contracts import ContractVerifier
from .pass1_prove import prove
from .pass2_flatten import flatten
from .pass3_emit import emit, emit_and_compile
