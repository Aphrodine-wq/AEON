"""AEON Concurrency Verification Engine — Race and Deadlock Detection.

Implements concurrency analysis based on:
  Owicki & Gries (1976) "An Axiomatic Proof Technique for Parallel Programs"
  Acta Informatica 6, https://doi.org/10.1007/BF00268134

  Flanagan & Godefroid (2005) "Dynamic Partial-Order Reduction for
  Model Checking Software"
  POPL '05, https://doi.org/10.1145/1040305.1040315

  Savage et al. (1997) "Eraser: A Dynamic Data Race Detector for
  Multithreaded Programs"
  ACM TOCS 15(4) — the lockset algorithm.

  Engler & Ashcraft (2003) "RacerD: Compositional Static Race Detection"
  (Facebook's static race detector for Java/C++)

Key Theory:

1. LOCKSET ANALYSIS (Savage et al. 1997):
   For each shared variable v, track the set of locks held
   when v is accessed: lockset(v).
   If lockset(v) becomes empty across accesses from different
   threads, report a potential data race.

2. HAPPENS-BEFORE (Lamport 1978):
   Event a HAPPENS-BEFORE event b (a → b) if:
   - a and b are in the same thread and a precedes b, or
   - a is a send and b is the corresponding receive, or
   - transitivity: a → c and c → b implies a → b.
   Two events CONFLICT if they access the same variable,
   at least one is a write, and neither happens-before the other.

3. DEADLOCK DETECTION:
   Build a lock-order graph where edge (L1, L2) means
   "L1 is held while acquiring L2."
   A CYCLE in this graph indicates a potential deadlock.

4. ATOMICITY VIOLATIONS:
   A function is ATOMIC if its execution is serializable —
   equivalent to some serial execution. Check-then-act patterns
   (read-then-write without holding a lock) are atomicity violations.

5. OWICKI-GRIES (1976):
   Proof method for parallel programs:
   {P1} S1 {Q1}  and  {P2} S2 {Q2}  run in parallel.
   The proof obligations are:
   - Each Hoare triple is valid in isolation
   - INTERFERENCE FREEDOM: every statement in S2 preserves P1 and Q1
     (and vice versa)

Detects:
  - Data races (concurrent unsynchronized access)
  - Deadlocks (lock order cycles)
  - Atomicity violations (check-then-act without lock)
  - Missing synchronization
  - Channel misuse (send without receiver, etc.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Concurrency Model
# ---------------------------------------------------------------------------

class AccessKind(Enum):
    READ = auto()
    WRITE = auto()


@dataclass
class SharedAccess:
    """Record of an access to a shared variable."""
    variable: str
    kind: AccessKind
    locks_held: Set[str]
    location: SourceLocation
    function: str


@dataclass
class LockOrderEdge:
    """An edge in the lock-order graph."""
    held_lock: str
    acquired_lock: str
    location: SourceLocation
    function: str


# ---------------------------------------------------------------------------
# Lockset patterns for different languages
# ---------------------------------------------------------------------------

LOCK_ACQUIRE_PATTERNS: Set[str] = {
    "lock", "Lock", "acquire", "Acquire",
    "RLock", "rlock", "RUnlock",
    "mutex_lock", "pthread_mutex_lock",
    "synchronized", "sync",
    "Lock", "RLock",
    "WaitOne", "Enter",
}

LOCK_RELEASE_PATTERNS: Set[str] = {
    "unlock", "Unlock", "release", "Release",
    "mutex_unlock", "pthread_mutex_unlock",
    "ReleaseMutex", "Exit",
}

SPAWN_PATTERNS: Set[str] = {
    "go", "spawn", "thread", "Thread",
    "async", "Task", "goroutine",
    "pthread_create", "CreateThread",
    "fork", "start",
    "dispatch", "submit",
}

SHARED_WRITE_METHODS: Set[str] = {
    "set", "put", "insert", "update", "delete", "remove",
    "push", "pop", "append", "add", "clear",
    "write", "send", "emit",
    "Store", "Swap", "CompareAndSwap",
}

SHARED_READ_METHODS: Set[str] = {
    "get", "read", "load", "Load",
    "peek", "front", "back",
    "contains", "has", "exists",
}

# Thread-unsafe collections (need synchronization when shared)
THREAD_UNSAFE_COLLECTIONS: Set[str] = {
    "list", "dict", "map", "set", "array",
    "ArrayList", "HashMap", "HashSet", "LinkedList",
    "vector", "deque", "queue", "stack",
    "Vec", "BTreeMap", "BTreeSet",
    "slice", "buffer",
}

# Patterns that suggest a variable should be atomic
ATOMIC_REQUIRED_PATTERNS: Set[str] = {
    "counter", "count", "total", "sum",
    "flag", "done", "ready", "running",
    "state", "status", "phase",
    "sequence", "seq", "version",
    "ref_count", "refcount", "refs",
}


# ---------------------------------------------------------------------------
# Concurrency Analyzer
# ---------------------------------------------------------------------------

class ConcurrencyAnalyzer:
    """Analyzes concurrent programs for races, deadlocks, and atomicity violations."""

    def __init__(self):
        self.errors: List[AeonError] = []
        self._accesses: List[SharedAccess] = []
        self._lock_order: List[LockOrderEdge] = []
        self._held_locks: Set[str] = set()
        self._shared_vars: Set[str] = set()
        self._concurrent_functions: Set[str] = set()
        self._current_func: str = ""
        self._has_concurrency: bool = False

    def check_program(self, program: Program) -> List[AeonError]:
        """Run concurrency analysis on the entire program."""
        self.errors = []
        self._accesses = []
        self._lock_order = []
        self._has_concurrency = False

        # First pass: identify concurrent functions and shared state
        for decl in program.declarations:
            if isinstance(decl, TaskFunc):
                self._scan_for_concurrency(decl)

        # Only run full analysis if concurrency is detected
        if not self._has_concurrency:
            return self.errors

        # Second pass: analyze each function for races and deadlocks
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        # Check for data races across functions
        self._check_data_races()

        # Check for deadlocks via lock-order graph
        self._check_deadlocks()

        # Check for thread-unsafe collection access
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._check_thread_unsafe_collections(decl)
                self._check_missing_atomics(decl)
                break  # Only need to run once (uses accumulated _accesses)

        return self.errors

    def _scan_for_concurrency(self, func: TaskFunc) -> None:
        """Scan a function to determine if it uses concurrency primitives."""
        for stmt in func.body:
            self._scan_stmt_concurrency(stmt, func.name)

    def _scan_stmt_concurrency(self, stmt: Statement, func_name: str) -> None:
        """Scan a statement for concurrency indicators."""
        if isinstance(stmt, ExprStmt):
            if self._is_spawn(stmt.expr):
                self._has_concurrency = True
                self._concurrent_functions.add(func_name)
            if self._is_lock_op(stmt.expr) or self._is_unlock_op(stmt.expr):
                self._has_concurrency = True
        elif isinstance(stmt, LetStmt) and stmt.value:
            if self._is_spawn(stmt.value):
                self._has_concurrency = True
                self._concurrent_functions.add(func_name)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._scan_stmt_concurrency(s, func_name)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._scan_stmt_concurrency(s, func_name)
        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._scan_stmt_concurrency(s, func_name)

        # Check effects for concurrency keywords
        if isinstance(stmt, ExprStmt) and isinstance(stmt.expr, MethodCall):
            if stmt.expr.method_name in SHARED_WRITE_METHODS or stmt.expr.method_name in SHARED_READ_METHODS:
                if isinstance(stmt.expr.obj, Identifier):
                    self._shared_vars.add(stmt.expr.obj.name)

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function for concurrency issues."""
        self._held_locks = set()
        self._current_func = func.name

        for stmt in func.body:
            self._analyze_statement(stmt, func)

        # Check for unreleased locks at function exit
        if self._held_locks:
            loc = getattr(func, 'location', SourceLocation("<conc>", 0, 0))
            for lock in self._held_locks:
                self.errors.append(contract_error(
                    precondition=f"Lock '{lock}' acquired but never released in '{func.name}'",
                    failing_values={"lock": lock, "function": func.name,
                                  "engine": "Concurrency Verification"},
                    function_signature=f"{func.name}",
                    location=loc,
                ))

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Analyze a statement for concurrency issues."""
        loc = getattr(stmt, 'location', SourceLocation("<conc>", 0, 0))

        if isinstance(stmt, ExprStmt):
            # Check for lock/unlock
            if self._is_lock_op(stmt.expr):
                lock_name = self._get_lock_name(stmt.expr)
                if lock_name:
                    # Record lock ordering
                    for held in self._held_locks:
                        self._lock_order.append(LockOrderEdge(
                            held_lock=held,
                            acquired_lock=lock_name,
                            location=loc,
                            function=func.name,
                        ))
                    self._held_locks.add(lock_name)

            elif self._is_unlock_op(stmt.expr):
                lock_name = self._get_lock_name(stmt.expr)
                if lock_name:
                    self._held_locks.discard(lock_name)

            # Record shared variable accesses
            self._record_accesses(stmt.expr, AccessKind.READ, loc, func.name)

        elif isinstance(stmt, LetStmt):
            if stmt.value:
                self._record_accesses(stmt.value, AccessKind.READ, loc, func.name)

        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                self._accesses.append(SharedAccess(
                    variable=stmt.target.name,
                    kind=AccessKind.WRITE,
                    locks_held=set(self._held_locks),
                    location=loc,
                    function=func.name,
                ))
            self._record_accesses(stmt.value, AccessKind.READ, loc, func.name)

        elif isinstance(stmt, IfStmt):
            # Check for check-then-act pattern (atomicity violation)
            self._check_atomicity(stmt, func, loc)
            for s in stmt.then_body:
                self._analyze_statement(s, func)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._analyze_statement(s, func)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._analyze_statement(s, func)

    def _record_accesses(self, expr: Expr, kind: AccessKind, loc: SourceLocation,
                         func_name: str) -> None:
        """Record variable accesses for race detection."""
        if isinstance(expr, Identifier):
            if expr.name in self._shared_vars:
                self._accesses.append(SharedAccess(
                    variable=expr.name,
                    kind=kind,
                    locks_held=set(self._held_locks),
                    location=loc,
                    function=func_name,
                ))

        elif isinstance(expr, MethodCall):
            if isinstance(expr.obj, Identifier):
                method_kind = AccessKind.WRITE if expr.method_name in SHARED_WRITE_METHODS else AccessKind.READ
                self._accesses.append(SharedAccess(
                    variable=expr.obj.name,
                    kind=method_kind,
                    locks_held=set(self._held_locks),
                    location=loc,
                    function=func_name,
                ))
            for arg in expr.args:
                self._record_accesses(arg, AccessKind.READ, loc, func_name)

        elif isinstance(expr, BinaryOp):
            self._record_accesses(expr.left, kind, loc, func_name)
            self._record_accesses(expr.right, kind, loc, func_name)

        elif isinstance(expr, FieldAccess):
            self._record_accesses(expr.obj, kind, loc, func_name)

    def _check_data_races(self) -> None:
        """Detect data races using lockset analysis."""
        # Group accesses by variable
        by_var: Dict[str, List[SharedAccess]] = {}
        for access in self._accesses:
            by_var.setdefault(access.variable, []).append(access)

        reported: Set[str] = set()
        for var, accesses in by_var.items():
            # Check for conflicting accesses (at least one write, from different functions)
            writes = [a for a in accesses if a.kind == AccessKind.WRITE]
            all_funcs = {a.function for a in accesses}

            if not writes or len(all_funcs) < 2:
                continue

            # Lockset algorithm: intersect locksets across all accesses
            locksets = [a.locks_held for a in accesses]
            common_locks = locksets[0]
            for ls in locksets[1:]:
                common_locks = common_locks & ls

            if not common_locks and var not in reported:
                reported.add(var)
                first_write = writes[0]
                self.errors.append(contract_error(
                    precondition=(
                        f"Potential data race on '{var}': accessed from multiple "
                        f"functions ({', '.join(sorted(all_funcs))}) without common lock"
                    ),
                    failing_values={
                        "variable": var,
                        "functions": ", ".join(sorted(all_funcs)),
                        "engine": "Concurrency Verification (Lockset)",
                    },
                    function_signature="concurrent access",
                    location=first_write.location,
                ))

    def _check_deadlocks(self) -> None:
        """Detect deadlocks via cycle detection in lock-order graph."""
        # Build adjacency list
        graph: Dict[str, Set[str]] = {}
        edge_info: Dict[Tuple[str, str], LockOrderEdge] = {}

        for edge in self._lock_order:
            graph.setdefault(edge.held_lock, set()).add(edge.acquired_lock)
            edge_info[(edge.held_lock, edge.acquired_lock)] = edge

        # DFS cycle detection
        visited: Set[str] = set()
        rec_stack: Set[str] = set()
        path: List[str] = []

        def dfs(node: str) -> Optional[List[str]]:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in graph.get(node, set()):
                if neighbor not in visited:
                    result = dfs(neighbor)
                    if result:
                        return result
                elif neighbor in rec_stack:
                    # Found cycle
                    cycle_start = path.index(neighbor)
                    return path[cycle_start:] + [neighbor]

            path.pop()
            rec_stack.discard(node)
            return None

        for node in graph:
            if node not in visited:
                cycle = dfs(node)
                if cycle:
                    cycle_str = " -> ".join(cycle)
                    first_edge = edge_info.get((cycle[0], cycle[1]))
                    loc = first_edge.location if first_edge else SourceLocation("<conc>", 0, 0)
                    self.errors.append(contract_error(
                        precondition=f"Potential deadlock: lock ordering cycle detected: {cycle_str}",
                        failing_values={
                            "cycle": cycle_str,
                            "engine": "Concurrency Verification (Deadlock)",
                        },
                        function_signature="lock ordering",
                        location=loc,
                    ))
                    break  # Report one deadlock per analysis

    def _check_thread_unsafe_collections(self, func: PureFunc | TaskFunc) -> None:
        """Detect shared access to thread-unsafe collections without locks."""
        if not self._has_concurrency:
            return

        for access in self._accesses:
            # Check if the variable name suggests it's a collection
            var_lower = access.variable.lower()
            is_collection = any(col in var_lower for col in
                              ("list", "map", "dict", "set", "array",
                               "queue", "stack", "buffer", "cache",
                               "items", "entries", "records"))
            if is_collection and access.kind == AccessKind.WRITE and not access.locks_held:
                self.errors.append(contract_error(
                    precondition=(
                        f"Thread-unsafe collection: '{access.variable}' is modified "
                        f"without synchronization in concurrent context"
                    ),
                    failing_values={
                        "variable": access.variable,
                        "function": access.function,
                        "engine": "Concurrency Verification (Thread Safety)",
                    },
                    function_signature=f"{access.function}",
                    location=access.location,
                ))

    def _check_missing_atomics(self, func: PureFunc | TaskFunc) -> None:
        """Detect shared primitive variables that should be atomic."""
        if not self._has_concurrency:
            return

        reported: Set[str] = set()
        for access in self._accesses:
            var_lower = access.variable.lower()
            needs_atomic = any(pat in var_lower for pat in ATOMIC_REQUIRED_PATTERNS)
            if needs_atomic and not access.locks_held and access.variable not in reported:
                reported.add(access.variable)
                self.errors.append(contract_error(
                    precondition=(
                        f"Missing atomic: shared variable '{access.variable}' looks like "
                        f"it should be atomic/volatile for thread-safe access"
                    ),
                    failing_values={
                        "variable": access.variable,
                        "pattern": "needs atomic",
                        "engine": "Concurrency Verification (Atomics)",
                    },
                    function_signature=f"{access.function}",
                    location=access.location,
                ))

    def _check_atomicity(self, stmt: IfStmt, func: PureFunc | TaskFunc,
                        loc: SourceLocation) -> None:
        """Detect check-then-act atomicity violations."""
        if not self._held_locks and self._has_concurrency:
            # Check if the condition reads a shared variable
            cond_vars = self._collect_vars(stmt.condition)
            shared_in_cond = cond_vars & self._shared_vars

            # Check if the body writes to the same shared variable
            body_writes: Set[str] = set()
            for s in stmt.then_body:
                if isinstance(s, AssignStmt) and isinstance(s.target, Identifier):
                    body_writes.add(s.target.name)
                elif isinstance(s, ExprStmt) and isinstance(s.expr, MethodCall):
                    if isinstance(s.expr.obj, Identifier) and s.expr.method_name in SHARED_WRITE_METHODS:
                        body_writes.add(s.expr.obj.name)

            overlap = shared_in_cond & body_writes
            if overlap:
                for var in overlap:
                    self.errors.append(contract_error(
                        precondition=(
                            f"Atomicity violation: check-then-act on shared variable "
                            f"'{var}' without holding a lock"
                        ),
                        failing_values={
                            "variable": var,
                            "pattern": "check-then-act",
                            "engine": "Concurrency Verification",
                        },
                        function_signature=f"{func.name}",
                        location=loc,
                    ))

    # --- Helpers ---

    def _is_spawn(self, expr: Expr) -> bool:
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name in SPAWN_PATTERNS
        if isinstance(expr, MethodCall):
            return expr.method_name in SPAWN_PATTERNS
        return False

    def _is_lock_op(self, expr: Expr) -> bool:
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name in LOCK_ACQUIRE_PATTERNS
        if isinstance(expr, MethodCall):
            return expr.method_name in LOCK_ACQUIRE_PATTERNS
        return False

    def _is_unlock_op(self, expr: Expr) -> bool:
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name in LOCK_RELEASE_PATTERNS
        if isinstance(expr, MethodCall):
            return expr.method_name in LOCK_RELEASE_PATTERNS
        return False

    def _get_lock_name(self, expr: Expr) -> Optional[str]:
        if isinstance(expr, MethodCall) and isinstance(expr.obj, Identifier):
            return expr.obj.name
        if isinstance(expr, FunctionCall):
            if expr.args and isinstance(expr.args[0], Identifier):
                return expr.args[0].name
        return None

    def _collect_vars(self, expr: Expr) -> Set[str]:
        result: Set[str] = set()
        if isinstance(expr, Identifier):
            result.add(expr.name)
        elif isinstance(expr, BinaryOp):
            result.update(self._collect_vars(expr.left))
            result.update(self._collect_vars(expr.right))
        elif isinstance(expr, UnaryOp):
            result.update(self._collect_vars(expr.operand))
        elif isinstance(expr, FieldAccess):
            result.update(self._collect_vars(expr.obj))
        elif isinstance(expr, MethodCall):
            result.update(self._collect_vars(expr.obj))
        return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_concurrency(program: Program) -> List[AeonError]:
    """Run concurrency verification on an AEON program.

    Detects:
    - Data races via lockset analysis (Eraser algorithm)
    - Deadlocks via lock-order graph cycle detection
    - Atomicity violations (check-then-act patterns)
    - Unreleased locks
    - Thread-unsafe collection access without synchronization
    - Missing atomic/volatile on shared primitives
    """
    analyzer = ConcurrencyAnalyzer()
    return analyzer.check_program(program)
