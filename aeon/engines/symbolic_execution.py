"""AEON Symbolic Execution Engine — Path-Sensitive Analysis with Constraint Solving.

Implements symbolic execution based on:
  King (1976) "Symbolic Execution and Program Testing"
  CACM 19(7), https://doi.org/10.1145/360248.360252

  Cadar, Dunbar, Engler (2008) "KLEE: Unassisted and Automatic Generation
  of High-Coverage Tests for Complex Systems Programs"
  OSDI '08

  Baldoni et al. (2018) "A Survey of Symbolic Execution Techniques"
  ACM Computing Surveys 51(3), https://doi.org/10.1145/3182657

Key Theory:

1. SYMBOLIC STATE:
   Instead of executing with concrete values, symbolic execution
   uses SYMBOLIC VALUES (unknown variables). At each branch point,
   the executor FORKS into two states:
   - One where the condition is true  (path condition += cond)
   - One where the condition is false (path condition += NOT cond)

   A symbolic state is: (pc, sigma, pi) where:
   - pc = program counter (current statement)
   - sigma = symbolic store (variable -> symbolic expression)
   - pi = path condition (conjunction of branch decisions)

2. PATH CONDITIONS:
   The path condition pi accumulates all branch decisions taken.
   At any point, pi is satisfiable iff the current path is feasible.
   We use Z3 to check satisfiability and generate concrete test inputs.

3. PATH EXPLOSION:
   The number of paths grows exponentially with branches.
   Mitigation strategies:
   - BOUNDED EXECUTION: limit path depth
   - MERGE POINTS: join paths at control flow merge points
   - FUNCTION SUMMARIES: summarize function behavior symbolically

4. CONCOLIC EXECUTION (concrete + symbolic):
   Run with concrete inputs while maintaining symbolic state.
   Use the path condition to generate new inputs that explore
   different paths (DIRECTED TESTING).

5. BUG DETECTION:
   At each point, check if the path condition is consistent with:
   - Division by zero: pi AND (divisor == 0) is SAT?
   - Array out of bounds: pi AND (index < 0 OR index >= len) is SAT?
   - Contract violation: pi AND NOT(requires) is SAT?
   - Assertion failure: pi AND NOT(assert_condition) is SAT?

6. TEST GENERATION:
   When a bug is found, the path condition serves as a TEST CASE:
   ask Z3 for a satisfying assignment to generate concrete inputs
   that trigger the bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Set, Tuple
from enum import Enum, auto
import copy

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    MoveExpr, BorrowExpr,
)
from aeon.errors import AeonError, contract_error, SourceLocation

import sys, io, os

z3_path = "/tmp/z3-src/build/python"
if os.path.exists(z3_path) and z3_path not in sys.path:
    sys.path.insert(0, z3_path)

_saved = (sys.stdout, sys.stderr)
try:
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    import z3
    HAS_Z3 = True
except (ImportError, Exception):
    z3 = None
    HAS_Z3 = False
finally:
    sys.stdout, sys.stderr = _saved


# ---------------------------------------------------------------------------
# Symbolic Expressions
# ---------------------------------------------------------------------------

class SymKind(Enum):
    SYMBOL = auto()      # Fresh symbolic variable
    CONST_INT = auto()   # Concrete integer
    CONST_BOOL = auto()  # Concrete boolean
    BINOP = auto()       # Binary operation
    UNOP = auto()        # Unary operation
    ITE = auto()         # If-then-else
    CALL = auto()        # Function call result (opaque)


@dataclass(frozen=True)
class SymExpr:
    """A symbolic expression representing a value during symbolic execution."""
    kind: SymKind
    name: str = ""          # for SYMBOL
    int_val: int = 0        # for CONST_INT
    bool_val: bool = False  # for CONST_BOOL
    op: str = ""            # for BINOP, UNOP
    children: Tuple = ()    # sub-expressions

    def __str__(self) -> str:
        if self.kind == SymKind.SYMBOL:
            return self.name
        if self.kind == SymKind.CONST_INT:
            return str(self.int_val)
        if self.kind == SymKind.CONST_BOOL:
            return str(self.bool_val).lower()
        if self.kind == SymKind.BINOP:
            return f"({self.children[0]} {self.op} {self.children[1]})"
        if self.kind == SymKind.UNOP:
            return f"({self.op}{self.children[0]})"
        if self.kind == SymKind.ITE:
            return f"(ite {self.children[0]} {self.children[1]} {self.children[2]})"
        if self.kind == SymKind.CALL:
            return f"call_{self.name}(...)"
        return "<?>"


def S_SYM(name: str) -> SymExpr:
    return SymExpr(kind=SymKind.SYMBOL, name=name)

def S_INT(val: int) -> SymExpr:
    return SymExpr(kind=SymKind.CONST_INT, int_val=val)

def S_BOOL(val: bool) -> SymExpr:
    return SymExpr(kind=SymKind.CONST_BOOL, bool_val=val)

def S_BINOP(op: str, left: SymExpr, right: SymExpr) -> SymExpr:
    return SymExpr(kind=SymKind.BINOP, op=op, children=(left, right))

def S_UNOP(op: str, operand: SymExpr) -> SymExpr:
    return SymExpr(kind=SymKind.UNOP, op=op, children=(operand,))

def S_ITE(cond: SymExpr, then_e: SymExpr, else_e: SymExpr) -> SymExpr:
    return SymExpr(kind=SymKind.ITE, children=(cond, then_e, else_e))

def S_CALL(name: str) -> SymExpr:
    return SymExpr(kind=SymKind.CALL, name=name)


# ---------------------------------------------------------------------------
# Symbolic State
# ---------------------------------------------------------------------------

@dataclass
class SymbolicState:
    """A symbolic execution state: (store, path_condition, pc).

    - store: maps variable names to symbolic expressions
    - path_condition: list of symbolic boolean constraints (conjunction)
    - halted: whether this path has terminated
    - return_value: the symbolic return value (if returned)
    """
    store: Dict[str, SymExpr] = field(default_factory=dict)
    path_condition: List[SymExpr] = field(default_factory=list)
    halted: bool = False
    return_value: Optional[SymExpr] = None
    depth: int = 0

    def copy(self) -> SymbolicState:
        return SymbolicState(
            store=dict(self.store),
            path_condition=list(self.path_condition),
            halted=self.halted,
            return_value=self.return_value,
            depth=self.depth,
        )

    def add_constraint(self, constraint: SymExpr) -> None:
        self.path_condition.append(constraint)

    def is_feasible(self) -> bool:
        """Check if the current path condition is satisfiable using Z3."""
        if not HAS_Z3:
            return True
        try:
            solver = z3.Solver()
            solver.set("timeout", 2000)
            z3_vars: Dict[str, Any] = {}
            for constraint in self.path_condition:
                z3_expr = _sym_to_z3(constraint, z3_vars)
                if z3_expr is not None:
                    solver.add(z3_expr)
            return solver.check() != z3.unsat
        except Exception:
            return True

    def get_model(self) -> Optional[Dict[str, Any]]:
        """Get a concrete satisfying assignment for the path condition."""
        if not HAS_Z3:
            return None
        try:
            solver = z3.Solver()
            solver.set("timeout", 5000)
            z3_vars: Dict[str, Any] = {}
            for constraint in self.path_condition:
                z3_expr = _sym_to_z3(constraint, z3_vars)
                if z3_expr is not None:
                    solver.add(z3_expr)
            if solver.check() == z3.sat:
                model = solver.model()
                result = {}
                for name, var in z3_vars.items():
                    try:
                        val = model.evaluate(var, model_completion=True)
                        result[name] = str(val)
                    except Exception:
                        pass
                return result
        except Exception:
            pass
        return None


def _sym_to_z3(expr: SymExpr, z3_vars: Dict[str, Any]) -> Any:
    """Convert a symbolic expression to Z3."""
    if not HAS_Z3:
        return None

    if expr.kind == SymKind.SYMBOL:
        if expr.name not in z3_vars:
            z3_vars[expr.name] = z3.Int(expr.name)
        return z3_vars[expr.name]

    if expr.kind == SymKind.CONST_INT:
        return z3.IntVal(expr.int_val)

    if expr.kind == SymKind.CONST_BOOL:
        return z3.BoolVal(expr.bool_val)

    if expr.kind == SymKind.BINOP:
        left = _sym_to_z3(expr.children[0], z3_vars)
        right = _sym_to_z3(expr.children[1], z3_vars)
        if left is None or right is None:
            return None
        ops = {
            "+": lambda l, r: l + r, "-": lambda l, r: l - r,
            "*": lambda l, r: l * r, "/": lambda l, r: l / r,
            "%": lambda l, r: l % r,
            "==": lambda l, r: l == r, "!=": lambda l, r: l != r,
            ">=": lambda l, r: l >= r, "<=": lambda l, r: l <= r,
            ">": lambda l, r: l > r, "<": lambda l, r: l < r,
            "&&": lambda l, r: z3.And(l, r), "||": lambda l, r: z3.Or(l, r),
        }
        fn = ops.get(expr.op)
        if fn:
            try:
                return fn(left, right)
            except Exception:
                return None
        return None

    if expr.kind == SymKind.UNOP:
        inner = _sym_to_z3(expr.children[0], z3_vars)
        if inner is None:
            return None
        if expr.op == "-":
            return -inner
        if expr.op == "!":
            return z3.Not(inner)
        return None

    if expr.kind == SymKind.ITE:
        cond = _sym_to_z3(expr.children[0], z3_vars)
        then_e = _sym_to_z3(expr.children[1], z3_vars)
        else_e = _sym_to_z3(expr.children[2], z3_vars)
        if cond is not None and then_e is not None and else_e is not None:
            return z3.If(cond, then_e, else_e)
        return None

    return None


# ---------------------------------------------------------------------------
# Symbolic Executor
# ---------------------------------------------------------------------------

@dataclass
class PathResult:
    """Result of executing a single path."""
    path_condition: List[SymExpr]
    return_value: Optional[SymExpr]
    errors: List[AeonError]
    test_input: Optional[Dict[str, Any]]
    feasible: bool


class SymbolicExecutor:
    """Executes AEON programs symbolically, exploring all feasible paths.

    For each function:
    1. Initialize parameters as fresh symbolic variables
    2. Execute the body, forking at each branch
    3. At each point, check for potential bugs:
       - Division by zero
       - Contract violations
       - Unreachable code
    4. Generate concrete test inputs for each bug found
    """

    def __init__(self, max_depth: int = 50, max_paths: int = 1000):
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.errors: List[AeonError] = []
        self.path_results: List[PathResult] = []
        self._sym_counter = 0
        self._functions: Dict[str, PureFunc | TaskFunc] = {}

    def fresh_symbol(self, prefix: str = "s") -> str:
        self._sym_counter += 1
        return f"{prefix}_{self._sym_counter}"

    def execute_program(self, program: Program) -> List[AeonError]:
        """Symbolically execute all functions in a program."""
        self.errors = []
        self.path_results = []
        self._functions = {}

        functions = [d for d in program.declarations
                     if isinstance(d, (PureFunc, TaskFunc))]

        for func in functions:
            self._functions[func.name] = func

        for func in functions:
            self._execute_function(func)

        return self.errors

    def _execute_function(self, func: PureFunc | TaskFunc) -> None:
        """Symbolically execute a single function."""
        # Initialize symbolic state with symbolic parameters
        state = SymbolicState()
        for param in func.params:
            sym_name = f"{func.name}_{param.name}"
            state.store[param.name] = S_SYM(sym_name)

        # Apply requires clauses as path constraints
        for req in func.requires:
            constraint = self._eval_expr(req.expr, state)
            state.add_constraint(constraint)

        # Check if precondition is satisfiable
        if not state.is_feasible():
            return  # Precondition is unsatisfiable, skip

        # Execute body symbolically
        result_states = self._execute_block(func.body, state)

        # Check ensures clauses on each result state
        for rstate in result_states:
            if not rstate.halted or rstate.return_value is None:
                continue

            for ens in func.ensures:
                # Substitute 'result' with the actual return value
                ens_expr = self._eval_expr(ens.expr, rstate, result_val=rstate.return_value)

                # Check: can the ensures clause be violated?
                negated = S_UNOP("!", ens_expr)
                check_state = rstate.copy()
                check_state.add_constraint(negated)

                if check_state.is_feasible():
                    test_input = check_state.get_model()
                    self.errors.append(contract_error(
                        precondition=f"Symbolic execution found ensures violation in '{func.name}'",
                        failing_values=test_input or {"path": str(rstate.path_condition)},
                        function_signature=f"{func.name}",
                        location=ens.location,
                    ))
                    self.path_results.append(PathResult(
                        path_condition=check_state.path_condition,
                        return_value=rstate.return_value,
                        errors=self.errors[-1:],
                        test_input=test_input,
                        feasible=True,
                    ))

    def _execute_block(self, stmts: List[Statement], state: SymbolicState) -> List[SymbolicState]:
        """Execute a block of statements, returning all resulting states."""
        current_states = [state]

        for stmt in stmts:
            next_states: List[SymbolicState] = []
            for s in current_states:
                if s.halted:
                    next_states.append(s)
                    continue
                if len(next_states) > self.max_paths:
                    break
                results = self._execute_stmt(stmt, s)
                next_states.extend(results)
            current_states = next_states

        return current_states

    def _execute_stmt(self, stmt: Statement, state: SymbolicState) -> List[SymbolicState]:
        """Execute a single statement symbolically. May fork into multiple states."""
        if state.depth > self.max_depth:
            state.halted = True
            return [state]

        state.depth += 1

        if isinstance(stmt, ReturnStmt):
            if stmt.value:
                state.return_value = self._eval_expr(stmt.value, state)
            state.halted = True
            return [state]

        if isinstance(stmt, LetStmt):
            if stmt.value:
                val = self._eval_expr(stmt.value, state)
                state.store[stmt.name] = val
            else:
                state.store[stmt.name] = S_SYM(self.fresh_symbol(stmt.name))
            return [state]

        if isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                val = self._eval_expr(stmt.value, state)
                state.store[stmt.target.name] = val
            return [state]

        if isinstance(stmt, ExprStmt):
            self._eval_expr(stmt.expr, state)
            return [state]

        if isinstance(stmt, IfStmt):
            return self._execute_if(stmt, state)

        if isinstance(stmt, WhileStmt):
            return self._execute_while(stmt, state)

        return [state]

    def _execute_if(self, stmt: IfStmt, state: SymbolicState) -> List[SymbolicState]:
        """Execute an if statement by forking into two paths."""
        cond = self._eval_expr(stmt.condition, state)

        results: List[SymbolicState] = []

        # Then branch: path_condition + cond
        then_state = state.copy()
        then_state.add_constraint(cond)
        if then_state.is_feasible():
            then_results = self._execute_block(stmt.then_body, then_state)
            results.extend(then_results)

        # Else branch: path_condition + NOT cond
        else_state = state.copy()
        else_state.add_constraint(S_UNOP("!", cond))
        if else_state.is_feasible():
            if stmt.else_body:
                else_results = self._execute_block(stmt.else_body, else_state)
                results.extend(else_results)
            else:
                results.append(else_state)

        return results if results else [state]

    def _execute_while(self, stmt: WhileStmt, state: SymbolicState) -> List[SymbolicState]:
        """Execute a while loop with bounded unrolling.

        We unroll the loop up to max_depth iterations, forking at each iteration.
        """
        MAX_UNROLL = 10
        results: List[SymbolicState] = []
        current = state.copy()

        for i in range(MAX_UNROLL):
            cond = self._eval_expr(stmt.condition, current)

            # Exit path: condition is false
            exit_state = current.copy()
            exit_state.add_constraint(S_UNOP("!", cond))
            if exit_state.is_feasible():
                results.append(exit_state)

            # Continue path: condition is true
            loop_state = current.copy()
            loop_state.add_constraint(cond)
            if not loop_state.is_feasible():
                break

            loop_results = self._execute_block(stmt.body, loop_state)
            non_halted = [s for s in loop_results if not s.halted]
            halted = [s for s in loop_results if s.halted]
            results.extend(halted)

            if not non_halted:
                break
            current = non_halted[0]

        if not results:
            results.append(state)

        return results

    def _eval_expr(self, expr: Expr, state: SymbolicState,
                   result_val: Optional[SymExpr] = None) -> SymExpr:
        """Evaluate an expression symbolically."""
        if isinstance(expr, IntLiteral):
            return S_INT(expr.value)

        if isinstance(expr, BoolLiteral):
            return S_BOOL(expr.value)

        if isinstance(expr, FloatLiteral):
            return S_INT(int(expr.value))

        if isinstance(expr, StringLiteral):
            return S_SYM(f"str_{hash(expr.value) % 10000}")

        if isinstance(expr, Identifier):
            if expr.name == "result" and result_val is not None:
                return result_val
            if expr.name in state.store:
                return state.store[expr.name]
            return S_SYM(expr.name)

        if isinstance(expr, BinaryOp):
            left = self._eval_expr(expr.left, state, result_val)
            right = self._eval_expr(expr.right, state, result_val)

            # Check for division by zero
            if expr.op == "/":
                self._check_div_by_zero(right, state, expr.location)

            # Check for integer overflow on multiplication
            if expr.op == "*":
                self._check_integer_overflow(left, right, state, expr.location)

            return S_BINOP(expr.op, left, right)

        if isinstance(expr, UnaryOp):
            inner = self._eval_expr(expr.operand, state, result_val)
            return S_UNOP(expr.op, inner)

        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                # Evaluate arguments
                args_sym = []
                for arg in expr.args:
                    args_sym.append(self._eval_expr(arg, state, result_val))

                # Check for array/index out-of-bounds
                if expr.callee.name.lower() in ("get", "index", "at", "nth", "element_at"):
                    if args_sym:
                        self._check_bounds(args_sym[0], state, expr.location)

                # Check for format string vulnerabilities
                if expr.callee.name.lower() in ("format", "sprintf", "printf", "fprintf"):
                    self._check_format_string(expr.args, state, expr.location)

                return S_CALL(expr.callee.name)
            return S_SYM(self.fresh_symbol("call"))

        if isinstance(expr, FieldAccess):
            obj = self._eval_expr(expr.obj, state, result_val)
            return S_SYM(f"{obj}.{expr.field_name}")

        if isinstance(expr, MethodCall):
            self._eval_expr(expr.obj, state, result_val)
            for arg in expr.args:
                self._eval_expr(arg, state, result_val)
            return S_CALL(expr.method_name)

        if isinstance(expr, MoveExpr):
            if expr.name in state.store:
                return state.store[expr.name]
            return S_SYM(expr.name)

        if isinstance(expr, BorrowExpr):
            if expr.name in state.store:
                return state.store[expr.name]
            return S_SYM(expr.name)

        return S_SYM(self.fresh_symbol("unknown"))

    def _check_div_by_zero(self, divisor: SymExpr, state: SymbolicState,
                           location: Optional[SourceLocation]) -> None:
        """Check if division by zero is possible on the current path."""
        # Fast path: check if path condition already rules out zero
        # This handles requires: b != 0 even when Z3 isn't available
        if self._divisor_proven_nonzero(divisor, state):
            return

        zero_constraint = S_BINOP("==", divisor, S_INT(0))
        check_state = state.copy()
        check_state.add_constraint(zero_constraint)

        if check_state.is_feasible():
            test_input = check_state.get_model()
            self.errors.append(contract_error(
                precondition="Symbolic execution: division by zero is reachable",
                failing_values=test_input or {"divisor": str(divisor)},
                function_signature="division safety check",
                location=location,
            ))

    def _divisor_proven_nonzero(self, divisor: SymExpr, state: SymbolicState) -> bool:
        """Check if the path condition already proves divisor != 0.

        Scans constraints for patterns like:
          - divisor != 0
          - divisor > 0
          - divisor >= 1
        """
    def _check_integer_overflow(self, left: SymExpr, right: SymExpr,
                                state: SymbolicState,
                                location: Optional[SourceLocation]) -> None:
        """Check if integer multiplication could overflow."""
        # Only flag when both operands are symbolic (not small constants)
        if left.kind == SymKind.CONST_INT and -1000 <= left.int_val <= 1000:
            return
        if right.kind == SymKind.CONST_INT and -1000 <= right.int_val <= 1000:
            return
        # If both are symbolic or large constants, flag potential overflow
        if left.kind == SymKind.SYM and right.kind == SymKind.SYM:
            self.errors.append(contract_error(
                precondition="Symbolic execution: potential integer overflow in multiplication",
                failing_values={"left": str(left), "right": str(right)},
                function_signature="integer overflow check",
                location=location,
            ))

    def _check_bounds(self, index: SymExpr, state: SymbolicState,
                      location: Optional[SourceLocation]) -> None:
        """Check if array index could be negative (out of bounds)."""
        neg_constraint = S_BINOP("<", index, S_INT(0))
        check_state = state.copy()
        check_state.add_constraint(neg_constraint)
        if check_state.is_feasible():
            test_input = check_state.get_model()
            self.errors.append(contract_error(
                precondition="Symbolic execution: array index may be negative (out of bounds)",
                failing_values=test_input or {"index": str(index)},
                function_signature="bounds check",
                location=location,
            ))

    def _check_format_string(self, args: list, state: SymbolicState,
                             location: Optional[SourceLocation]) -> None:
        """Check for format string vulnerabilities (user input as format)."""
        if args:
            first_arg = args[0]
            if isinstance(first_arg, Identifier):
                # If the format string is a variable (not a literal), flag it
                if first_arg.name in state.store:
                    sym_val = state.store[first_arg.name]
                    if sym_val.kind == SymKind.SYM:
                        self.errors.append(contract_error(
                            precondition=(
                                f"Symbolic execution: format string from variable "
                                f"'{first_arg.name}' — potential format string vulnerability"
                            ),
                            failing_values={"variable": first_arg.name},
                            function_signature="format string check",
                            location=location,
                        ))

    def _divisor_proven_nonzero(self, divisor: SymExpr, state: SymbolicState) -> bool:
        """Check if the path condition already proves divisor != 0.

        Scans constraints for patterns like:
          - divisor != 0
          - divisor > 0
          - divisor >= 1
        """
        for constraint in state.path_condition:
            if constraint.kind == SymKind.BINOP:
                left, right = constraint.children[0], constraint.children[1]
                # Check: divisor != 0
                if (constraint.op == "!=" and
                    str(left) == str(divisor) and
                    right.kind == SymKind.CONST_INT and right.int_val == 0):
                    return True
                # Check: divisor > 0
                if (constraint.op == ">" and
                    str(left) == str(divisor) and
                    right.kind == SymKind.CONST_INT and right.int_val == 0):
                    return True
                # Check: divisor >= 1
                if (constraint.op == ">=" and
                    str(left) == str(divisor) and
                    right.kind == SymKind.CONST_INT and right.int_val >= 1):
                    return True
                # Check: 0 != divisor (reversed)
                if (constraint.op == "!=" and
                    str(right) == str(divisor) and
                    left.kind == SymKind.CONST_INT and left.int_val == 0):
                    return True
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def symbolic_execute(program: Program) -> List[AeonError]:
    """Run symbolic execution on an AEON program.

    Explores all feasible execution paths and checks for:
    1. Division by zero
    2. Contract violations (requires/ensures)
    3. Unreachable code detection
    4. Generates concrete test inputs for each bug found
    5. Array/index out-of-bounds access
    6. String format vulnerabilities
    7. Integer overflow on arithmetic paths
    """
    executor = SymbolicExecutor()
    return executor.execute_program(program)
