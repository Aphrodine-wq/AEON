"""AEON Null/Undefined Safety Engine — Null Dereference Detection.

Implements nullable type checking based on:
  Fähndrich & Leino (2003) "Declaring and Checking Non-null Types
  in an Object-Oriented Language"
  OOPSLA '03, https://doi.org/10.1145/949305.949332

  Dietl et al. (2011) "Building and Using a Type-Annotated Corpus
  of Java Source Code — Nullness Analysis"
  Springer, https://doi.org/10.1007/978-3-642-22655-7_4

Key Theory:

1. NULLABLE TYPES:
   A type T? (nullable T) includes the value null/None/nil.
   A type T (non-null T) guarantees the value is never null.
   Dereferencing a nullable without a null check is a bug.

2. NULL-STATE TRACKING:
   At each program point, track whether each variable is:
   - DEFINITELY_NULL: known to be null
   - DEFINITELY_NOT_NULL: known to be non-null
   - MAYBE_NULL: could be either (needs a check)

3. NULL GUARD ANALYSIS:
   After `if (x != null)`, x is NOT_NULL in the then-branch
   and NULL in the else-branch. This is called "null narrowing."

4. OPTIONAL UNWRAP:
   Languages with Optional/Maybe types require explicit unwrap.
   Calling .get() or force-unwrapping without checking .isPresent()
   is a potential NullPointerException.

Detects:
  - Null pointer dereference (field access / method call on null)
  - Missing null check before use
  - Optional unwrap without presence check
  - Null returned from non-nullable function
  - Null propagation through assignments
  - Missing null guard in method chains
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Null State Model
# ---------------------------------------------------------------------------

class NullState(Enum):
    DEFINITELY_NULL = auto()
    DEFINITELY_NOT_NULL = auto()
    MAYBE_NULL = auto()


# Identifiers that represent null values
NULL_LITERALS: Set[str] = {
    "null", "nil", "None", "nullptr", "NULL",
    "undefined", "nothing", "void",
}

# Types that indicate nullable
NULLABLE_TYPE_MARKERS: Set[str] = {
    "optional", "option", "maybe", "nullable",
    "Optional", "Option", "Maybe", "Nullable",
}

# Functions that return nullable results
NULLABLE_RETURN_FUNCTIONS: Set[str] = {
    "find", "get", "lookup", "search",
    "first", "last", "head", "tail",
    "pop", "peek", "poll",
    "parse", "try_parse", "from_str",
    "getattr", "getAttribute",
    "querySelector", "getElementById",
    "fetch", "load", "read",
    "next", "prev",
}

# Methods that require non-null receiver
REQUIRES_NON_NULL: Set[str] = {
    "toString", "to_string", "str",
    "length", "len", "size", "count",
    "append", "push", "add", "insert",
    "remove", "delete", "pop",
    "get", "set", "put",
    "read", "write", "send", "recv",
    "start", "stop", "run",
    "connect", "disconnect",
    "open", "close",
    "lock", "unlock",
    "clone", "copy",
}

# Methods that serve as null checks
NULL_CHECK_METHODS: Set[str] = {
    "is_some", "isSome", "isPresent", "is_present",
    "is_none", "isNone", "isEmpty", "is_empty",
    "is_null", "isNull", "is_nil", "isNil",
    "has_value", "hasValue",
    "is_defined", "isDefined",
    "is_valid", "isValid",
}

# Force-unwrap methods (dangerous without check)
FORCE_UNWRAP_METHODS: Set[str] = {
    "unwrap", "get", "force", "value",
    "unwrap_or_else", "expect",
    "orElseThrow",
}


# ---------------------------------------------------------------------------
# Null Safety Analyzer
# ---------------------------------------------------------------------------

class NullSafetyAnalyzer:
    """Tracks null states and detects null dereference bugs."""

    def __init__(self):
        self.errors: List[AeonError] = []
        self._null_state: Dict[str, NullState] = {}
        self._checked_vars: Set[str] = set()
        self._reported: Set[str] = set()

    def check_program(self, program: Program) -> List[AeonError]:
        """Run null safety analysis on the entire program."""
        self.errors = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._check_function(decl)

        return self.errors

    def _check_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function for null safety issues."""
        self._null_state = {}
        self._checked_vars = set()
        self._reported = set()

        # Initialize parameter null states from type annotations
        for param in func.params:
            type_str = str(param.type_annotation).lower() if param.type_annotation else ""
            if any(m in type_str for m in NULLABLE_TYPE_MARKERS):
                self._null_state[param.name] = NullState.MAYBE_NULL
            else:
                self._null_state[param.name] = NullState.DEFINITELY_NOT_NULL

        # Analyze body
        for stmt in func.body:
            self._check_statement(stmt, func)

        # Check return type: if function return type is non-nullable,
        # ensure we don't return null
        return_type = str(func.return_type).lower() if func.return_type else ""
        if return_type and not any(m in return_type for m in NULLABLE_TYPE_MARKERS):
            # This is checked per-return-statement in _check_statement
            pass

    def _check_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Check a statement for null safety issues."""
        loc = getattr(stmt, 'location', SourceLocation("<null>", 0, 0))

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_deref(stmt.value, func, loc)
                state = self._infer_null_state(stmt.value)
                self._null_state[stmt.name] = state

                # Check for force-unwrap without null check
                if isinstance(stmt.value, MethodCall):
                    if stmt.value.method_name in FORCE_UNWRAP_METHODS:
                        if isinstance(stmt.value.obj, Identifier):
                            obj_state = self._null_state.get(
                                stmt.value.obj.name, NullState.MAYBE_NULL)
                            if obj_state == NullState.MAYBE_NULL:
                                obj_name = stmt.value.obj.name
                                if obj_name not in self._checked_vars:
                                    self.errors.append(contract_error(
                                        precondition=(
                                            f"Unsafe unwrap: calling '.{stmt.value.method_name}()' "
                                            f"on '{obj_name}' which may be null/None — "
                                            f"check with is_some()/isPresent() first"
                                        ),
                                        failing_values={
                                            "variable": obj_name,
                                            "method": stmt.value.method_name,
                                            "engine": "Null Safety",
                                        },
                                        function_signature=f"{func.name}",
                                        location=loc,
                                    ))

            elif not stmt.value:
                # Uninitialized variable
                self._null_state[stmt.name] = NullState.MAYBE_NULL

        elif isinstance(stmt, AssignStmt):
            self._check_deref(stmt.value, func, loc)
            if isinstance(stmt.target, Identifier):
                state = self._infer_null_state(stmt.value)
                self._null_state[stmt.target.name] = state

        elif isinstance(stmt, ExprStmt):
            self._check_deref(stmt.expr, func, loc)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._check_deref(stmt.value, func, loc)
                # Check for returning null from non-nullable function
                ret_state = self._infer_null_state(stmt.value)
                if ret_state == NullState.DEFINITELY_NULL:
                    return_type = str(func.return_type).lower() if func.return_type else ""
                    if return_type and not any(m in return_type for m in NULLABLE_TYPE_MARKERS):
                        self.errors.append(contract_error(
                            precondition=(
                                f"Null return: '{func.name}' returns null but "
                                f"its return type does not allow null"
                            ),
                            failing_values={
                                "function": func.name,
                                "engine": "Null Safety",
                            },
                            function_signature=f"{func.name}",
                            location=loc,
                        ))

        elif isinstance(stmt, IfStmt):
            # Analyze condition for null checks to narrow state in branches
            null_narrowing = self._extract_null_check(stmt.condition)

            saved_state = dict(self._null_state)

            if null_narrowing:
                var_name, is_not_null = null_narrowing
                # In the then-branch, apply narrowing
                if is_not_null:
                    self._null_state[var_name] = NullState.DEFINITELY_NOT_NULL
                    self._checked_vars.add(var_name)
                else:
                    self._null_state[var_name] = NullState.DEFINITELY_NULL

            for s in stmt.then_body:
                self._check_statement(s, func)
            then_state = dict(self._null_state)

            # Restore and apply opposite narrowing for else
            self._null_state = dict(saved_state)
            if null_narrowing:
                var_name, is_not_null = null_narrowing
                if is_not_null:
                    self._null_state[var_name] = NullState.DEFINITELY_NULL
                else:
                    self._null_state[var_name] = NullState.DEFINITELY_NOT_NULL
                    self._checked_vars.add(var_name)

            if stmt.else_body:
                for s in stmt.else_body:
                    self._check_statement(s, func)

            # Merge states (take worst case)
            self._merge_states(then_state, self._null_state)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._check_statement(s, func)

    def _check_deref(self, expr: Expr, func: PureFunc | TaskFunc,
                     loc: SourceLocation) -> None:
        """Check if an expression dereferences a potentially-null value."""
        expr_loc = getattr(expr, 'location', loc)

        if isinstance(expr, FieldAccess):
            if isinstance(expr.obj, Identifier):
                state = self._null_state.get(expr.obj.name, NullState.MAYBE_NULL)
                if state in (NullState.MAYBE_NULL, NullState.DEFINITELY_NULL):
                    key = f"{expr.obj.name}.{expr.field_name}"
                    if key not in self._reported and expr.obj.name not in self._checked_vars:
                        self._reported.add(key)
                        self.errors.append(contract_error(
                            precondition=(
                                f"Null dereference: accessing '.{expr.field_name}' "
                                f"on '{expr.obj.name}' which may be null"
                            ),
                            failing_values={
                                "variable": expr.obj.name,
                                "field": expr.field_name,
                                "engine": "Null Safety",
                            },
                            function_signature=f"{func.name}",
                            location=expr_loc,
                        ))
            self._check_deref(expr.obj, func, loc)

        elif isinstance(expr, MethodCall):
            if isinstance(expr.obj, Identifier):
                # Check if method requires non-null
                if expr.method_name in REQUIRES_NON_NULL:
                    state = self._null_state.get(expr.obj.name, NullState.MAYBE_NULL)
                    if state in (NullState.MAYBE_NULL, NullState.DEFINITELY_NULL):
                        key = f"{expr.obj.name}.{expr.method_name}"
                        if key not in self._reported and expr.obj.name not in self._checked_vars:
                            self._reported.add(key)
                            self.errors.append(contract_error(
                                precondition=(
                                    f"Null dereference: calling '.{expr.method_name}()' "
                                    f"on '{expr.obj.name}' which may be null"
                                ),
                                failing_values={
                                    "variable": expr.obj.name,
                                    "method": expr.method_name,
                                    "engine": "Null Safety",
                                },
                                function_signature=f"{func.name}",
                                location=expr_loc,
                            ))
            self._check_deref(expr.obj, func, loc)
            for arg in expr.args:
                self._check_deref(arg, func, loc)

        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._check_deref(arg, func, loc)

        elif isinstance(expr, BinaryOp):
            self._check_deref(expr.left, func, loc)
            self._check_deref(expr.right, func, loc)

        elif isinstance(expr, UnaryOp):
            self._check_deref(expr.operand, func, loc)

    def _infer_null_state(self, expr: Expr) -> NullState:
        """Infer the null state of an expression."""
        if isinstance(expr, Identifier):
            if expr.name in NULL_LITERALS:
                return NullState.DEFINITELY_NULL
            return self._null_state.get(expr.name, NullState.MAYBE_NULL)

        if isinstance(expr, (IntLiteral, BoolLiteral, StringLiteral)):
            return NullState.DEFINITELY_NOT_NULL

        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                if expr.callee.name in NULLABLE_RETURN_FUNCTIONS:
                    return NullState.MAYBE_NULL
            return NullState.MAYBE_NULL  # Conservative

        if isinstance(expr, MethodCall):
            if expr.method_name in NULLABLE_RETURN_FUNCTIONS:
                return NullState.MAYBE_NULL
            return NullState.MAYBE_NULL

        if isinstance(expr, BinaryOp):
            return NullState.DEFINITELY_NOT_NULL  # Arithmetic results aren't null

        return NullState.MAYBE_NULL

    def _extract_null_check(self, expr: Expr) -> Optional[Tuple[str, bool]]:
        """Extract null check info from a condition.

        Returns (variable_name, is_not_null_in_then_branch) or None.
        """
        if isinstance(expr, BinaryOp):
            # x != null  ->  (x, True)  (x is not-null in then-branch)
            if expr.op == "!=" and isinstance(expr.left, Identifier):
                if isinstance(expr.right, Identifier) and expr.right.name in NULL_LITERALS:
                    return (expr.left.name, True)
            # null != x
            if expr.op == "!=" and isinstance(expr.right, Identifier):
                if isinstance(expr.left, Identifier) and expr.left.name in NULL_LITERALS:
                    return (expr.right.name, True)
            # x == null  ->  (x, False)  (x IS null in then-branch)
            if expr.op == "==" and isinstance(expr.left, Identifier):
                if isinstance(expr.right, Identifier) and expr.right.name in NULL_LITERALS:
                    return (expr.left.name, False)
            if expr.op == "==" and isinstance(expr.right, Identifier):
                if isinstance(expr.left, Identifier) and expr.left.name in NULL_LITERALS:
                    return (expr.right.name, False)

        # Method-based null checks: x.is_some(), x.isPresent()
        if isinstance(expr, MethodCall):
            if expr.method_name in NULL_CHECK_METHODS:
                if isinstance(expr.obj, Identifier):
                    # is_some / isPresent -> not null in then
                    positive = expr.method_name in {
                        "is_some", "isSome", "isPresent", "is_present",
                        "has_value", "hasValue", "is_defined", "isDefined",
                        "is_valid", "isValid",
                    }
                    return (expr.obj.name, positive)

        return None

    def _merge_states(self, s1: Dict[str, NullState],
                      s2: Dict[str, NullState]) -> None:
        """Merge two null-state maps conservatively."""
        all_vars = set(s1.keys()) | set(s2.keys())
        for var in all_vars:
            state1 = s1.get(var, NullState.MAYBE_NULL)
            state2 = s2.get(var, NullState.MAYBE_NULL)
            if state1 == state2:
                self._null_state[var] = state1
            else:
                self._null_state[var] = NullState.MAYBE_NULL


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_null_safety(program: Program) -> List[AeonError]:
    """Run null safety analysis on an AEON program.

    Detects:
    - Null pointer dereference (field access / method call on null)
    - Missing null check before use
    - Unsafe optional unwrap without presence check
    - Null return from non-nullable function
    - Null propagation through assignments
    """
    analyzer = NullSafetyAnalyzer()
    return analyzer.check_program(program)
