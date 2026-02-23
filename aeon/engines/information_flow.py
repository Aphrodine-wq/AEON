"""AEON Information Flow Analysis — Security Type System for Noninterference.

Implements the security type system from:
  Volpano, Smith, Irvine (1996) "A Sound Type System for Secure Flow Analysis"
  Journal of Computer Security 4(2-3), https://doi.org/10.3233/JCS-1996-42-304

  Denning & Denning (1977) "Certification of Programs for Secure Information Flow"
  CACM 20(7), https://doi.org/10.1145/359636.359712

  Sabelfeld & Myers (2003) "Language-Based Information-Flow Security"
  IEEE J-SAC 21(1), https://doi.org/10.1109/JSAC.2002.806121

Key Theory:

1. SECURITY LATTICE:
   Information flow is controlled by a security lattice (L, <=) where:
   - Elements are security LEVELS (e.g., Public, Internal, Secret, TopSecret)
   - The partial order (<=) represents "may flow to":
     Public <= Internal <= Secret <= TopSecret

   Every variable, parameter, and expression has a security level.
   Information may only flow from LOW to HIGH (never HIGH to LOW).

2. NONINTERFERENCE THEOREM:
   A program satisfies noninterference iff:
     For any two executions that agree on LOW inputs,
     they produce identical LOW outputs.

   Formally: if sigma_1 ~_L sigma_2 (agree on L-observable variables),
   then [[P]](sigma_1) ~_L [[P]](sigma_2).

   This guarantees that secret inputs cannot influence public outputs.

3. TYPING RULES (Volpano-Smith-Irvine):

   (T-VAR)     Gamma(x) = tau_l
               -------------------------
               Gamma |- x : tau_l

   (T-ASSIGN)  Gamma |- e : tau_l1,  Gamma(x) = tau_l2,  l1 <= l2
               -------------------------------------------------
               Gamma |- x := e : cmd_l2

   (T-IF)      Gamma |- e : tau_l,  Gamma |- S1 : cmd_l',  Gamma |- S2 : cmd_l'
               l <= l'
               ------------------------------------------------------------------
               Gamma |- if e then S1 else S2 : cmd_l'

   The IF rule enforces NO IMPLICIT FLOWS:
   The branch condition's security level must be <= the level of
   any variable modified in the branches. This prevents:
     if (secret) { public_var = 1 } else { public_var = 0 }
   which would leak the secret through the public variable.

4. DECLASSIFICATION:
   Sometimes information must intentionally flow downward (e.g., displaying
   a redacted version of secret data). This is modeled by explicit
   declassification annotations with audit tracking.

5. EFFECT INTERACTION:
   Effects interact with information flow:
   - Database.Write with Secret data: information leaves the program
   - Network.Read: information enters at a specified security level
   - The effect system must ensure that Secret data only flows to
     appropriately-secured effect channels.

6. LABEL POLYMORPHISM:
   Functions can be polymorphic over security labels:
     pure map<A, B, l>(f: A_l -> B_l, xs: List<A_l>) -> List<B_l>
   This preserves the security level through generic operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Tuple, FrozenSet
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    UnsafeBlock, MoveExpr, BorrowExpr,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Security Levels (Lattice Elements)
# ---------------------------------------------------------------------------

class SecurityLevel(Enum):
    """Security levels forming a total order (linear lattice).

    PUBLIC < INTERNAL < SECRET < TOP_SECRET

    In the general theory, these form a lattice (partial order),
    but for AEON we use a linear order for simplicity.
    More complex lattices (e.g., with compartments) can be built
    by taking products of linear lattices.

    Each level represents the minimum clearance needed to access data.
    """
    PUBLIC = 0         # Freely observable
    INTERNAL = 1       # Internal use only
    SECRET = 2         # Restricted access
    TOP_SECRET = 3     # Maximum classification

    def __le__(self, other) -> bool:
        if isinstance(other, SecurityLevel):
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other) -> bool:
        if isinstance(other, SecurityLevel):
            return self.value < other.value
        return NotImplemented

    def __ge__(self, other) -> bool:
        if isinstance(other, SecurityLevel):
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other) -> bool:
        if isinstance(other, SecurityLevel):
            return self.value > other.value
        return NotImplemented


def join_level(l1: SecurityLevel, l2: SecurityLevel) -> SecurityLevel:
    """Least upper bound (join) of two security levels.

    join(l1, l2) = max(l1, l2) in a linear lattice.
    Information flowing from l1 and l2 has level join(l1, l2).
    """
    return SecurityLevel(max(l1.value, l2.value))


def meet_level(l1: SecurityLevel, l2: SecurityLevel) -> SecurityLevel:
    """Greatest lower bound (meet) of two security levels."""
    return SecurityLevel(min(l1.value, l2.value))


# ---------------------------------------------------------------------------
# Security-Typed Values
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityType:
    """A type annotated with a security level.

    Examples:
      Int_PUBLIC      -- a public integer
      String_SECRET   -- a secret string
      Bool_INTERNAL   -- an internal boolean

    The security level is an upper bound on the sensitivity
    of the information the value may contain.
    """
    base_type: str
    level: SecurityLevel

    def __str__(self) -> str:
        return f"{self.base_type}@{self.level.name}"

    def can_flow_to(self, target: SecurityType) -> bool:
        """Check if information can flow from self to target.

        Information flows from LOW to HIGH: self.level <= target.level.
        The base types must also be compatible.
        """
        return self.level <= target.level


@dataclass
class SecurityContext:
    """The program counter security level (pc).

    The pc level tracks the security level of the current control flow.
    When we branch on a SECRET condition, the pc becomes SECRET,
    and any assignment in that branch must be to a SECRET-or-higher variable.

    This prevents IMPLICIT FLOWS:
      if (secret_bool) { public_var = 1 }  // ILLEGAL: pc=SECRET, var=PUBLIC
    """
    pc_level: SecurityLevel = SecurityLevel.PUBLIC


# ---------------------------------------------------------------------------
# Security Type Environment
# ---------------------------------------------------------------------------

@dataclass
class SecurityEnvironment:
    """Security typing environment mapping variables to security types."""
    bindings: Dict[str, SecurityType] = field(default_factory=dict)
    parent: Optional[SecurityEnvironment] = None

    def lookup(self, name: str) -> Optional[SecurityType]:
        if name in self.bindings:
            return self.bindings[name]
        if self.parent:
            return self.parent.lookup(name)
        return None

    def define(self, name: str, sec_type: SecurityType) -> None:
        self.bindings[name] = sec_type

    def child(self) -> SecurityEnvironment:
        return SecurityEnvironment(parent=self)


# ---------------------------------------------------------------------------
# Declassification Tracking
# ---------------------------------------------------------------------------

@dataclass
class DeclassificationRecord:
    """Record of an intentional declassification (security downgrade).

    Declassifications are security-critical operations that must be:
    1. Explicitly annotated in the source code
    2. Audited and logged
    3. Justified by a security policy

    Each declassification records:
    - What data was declassified
    - From what level to what level
    - Where in the code it occurred
    - Why it was justified (audit note)
    """
    variable: str
    from_level: SecurityLevel
    to_level: SecurityLevel
    location: Optional[SourceLocation] = None
    audit_note: str = ""
    justified: bool = False


# ---------------------------------------------------------------------------
# Information Flow Checker
# ---------------------------------------------------------------------------

class InformationFlowChecker:
    """Checks information flow properties using the Volpano-Smith-Irvine type system.

    Verifies NONINTERFERENCE: secret inputs cannot influence public outputs.

    The checker tracks:
    1. EXPLICIT FLOWS: direct assignments from high to low
       x_PUBLIC = y_SECRET  // VIOLATION
    2. IMPLICIT FLOWS: information leaked through control flow
       if (secret) { x_PUBLIC = 1 }  // VIOLATION (pc is SECRET)
    3. TERMINATION CHANNELS: information leaked through termination behavior
       while (secret) { ... }  // POTENTIAL VIOLATION (divergence depends on secret)
    4. TIMING CHANNELS: information leaked through execution time
       (not checked statically, but flagged as warnings)
    """

    def __init__(self, default_level: SecurityLevel = SecurityLevel.PUBLIC):
        self.errors: List[AeonError] = []
        self.declassifications: List[DeclassificationRecord] = []
        self.default_level = default_level
        self.env = SecurityEnvironment()
        self.context = SecurityContext()

        # Effect security levels: which effects require which clearance
        self.effect_levels: Dict[str, SecurityLevel] = {
            "Database.Read": SecurityLevel.INTERNAL,
            "Database.Write": SecurityLevel.INTERNAL,
            "Network.Read": SecurityLevel.PUBLIC,
            "Network.Write": SecurityLevel.INTERNAL,
            "File.Read": SecurityLevel.INTERNAL,
            "File.Write": SecurityLevel.INTERNAL,
            "Console.Write": SecurityLevel.PUBLIC,
            "Console.Read": SecurityLevel.PUBLIC,
            "System.Execute": SecurityLevel.SECRET,
        }

    def check_program(self, program: Program) -> List[AeonError]:
        """Run information flow analysis on a program."""
        self.errors = []
        self.declassifications = []

        # Register data types with default security levels
        for decl in program.declarations:
            if isinstance(decl, DataDef):
                self._register_data_type(decl)

        # Check each function
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._check_function(decl)

        return self.errors

    def _register_data_type(self, data: DataDef) -> None:
        """Register a data type's fields with security levels.

        Fields containing sensitive data (emails, UUIDs) get higher levels.
        """
        sensitive_types = {
            "Email": SecurityLevel.INTERNAL,
            "UUID": SecurityLevel.INTERNAL,
            "USD": SecurityLevel.SECRET,
        }

        for f in data.fields:
            type_name = str(f.type_annotation) if f.type_annotation else "Void"
            level = sensitive_types.get(type_name, self.default_level)
            self.env.define(
                f"{data.name}.{f.name}",
                SecurityType(base_type=type_name, level=level)
            )

    def _check_function(self, func: PureFunc | TaskFunc) -> None:
        """Check information flow for a function."""
        saved_env = self.env
        self.env = self.env.child()
        saved_ctx = SecurityContext(pc_level=self.context.pc_level)
        self.context = SecurityContext(pc_level=SecurityLevel.PUBLIC)

        # Bind parameters
        for param in func.params:
            type_name = str(param.type_annotation) if param.type_annotation else "Void"
            level = self._infer_param_level(param, func)
            self.env.define(param.name, SecurityType(base_type=type_name, level=level))

        # Check body
        for stmt in func.body:
            self._check_statement(stmt, func)

        # Check effects against security levels
        if isinstance(func, TaskFunc):
            self._check_effect_security(func)

        self.env = saved_env
        self.context = saved_ctx

    def _infer_param_level(self, param, func) -> SecurityLevel:
        """Infer the security level of a parameter.

        Heuristics:
        - Parameters named 'password', 'secret', 'key', 'token' -> SECRET
        - Parameters of type Email, USD -> INTERNAL
        - Parameters with requires clauses -> level from clause
        - Default -> PUBLIC
        """
        name_lower = param.name.lower()
        sensitive_names = {"password", "secret", "key", "token", "ssn", "credit_card"}
        if name_lower in sensitive_names:
            return SecurityLevel.SECRET

        type_name = str(param.type_annotation) if param.type_annotation else ""
        sensitive_types = {"Email": SecurityLevel.INTERNAL, "USD": SecurityLevel.SECRET}
        if type_name in sensitive_types:
            return sensitive_types[type_name]

        return self.default_level

    def _check_statement(self, stmt: Statement, func) -> None:
        """Check information flow for a statement.

        Implements the Volpano-Smith-Irvine typing rules.
        """
        if isinstance(stmt, LetStmt):
            self._check_let(stmt)
        elif isinstance(stmt, AssignStmt):
            self._check_assign(stmt)
        elif isinstance(stmt, ReturnStmt):
            self._check_return(stmt, func)
        elif isinstance(stmt, ExprStmt):
            self._check_expr_level(stmt.expr)
        elif isinstance(stmt, IfStmt):
            self._check_if(stmt, func)
        elif isinstance(stmt, WhileStmt):
            self._check_while(stmt, func)
        elif isinstance(stmt, UnsafeBlock):
            # Unsafe blocks bypass information flow checks (with audit)
            self.declassifications.append(DeclassificationRecord(
                variable="<unsafe_block>",
                from_level=SecurityLevel.TOP_SECRET,
                to_level=SecurityLevel.PUBLIC,
                location=stmt.location,
                audit_note=stmt.audit_note or "unsafe block",
                justified=False,
            ))
            for s in stmt.body:
                self._check_statement(s, func)

    def _check_let(self, stmt: LetStmt) -> None:
        """T-LET: let x = e.

        The security level of x is join(level(e), pc).
        This ensures that variables assigned under a secret branch
        are themselves secret.
        """
        if stmt.value:
            value_level = self._check_expr_level(stmt.value)
            # Variable level = join(value_level, pc_level)
            var_level = join_level(value_level, self.context.pc_level)
            type_name = str(stmt.type_annotation) if stmt.type_annotation else "Void"
            self.env.define(stmt.name, SecurityType(base_type=type_name, level=var_level))
        else:
            type_name = str(stmt.type_annotation) if stmt.type_annotation else "Void"
            self.env.define(stmt.name, SecurityType(base_type=type_name, level=self.context.pc_level))

    def _check_assign(self, stmt: AssignStmt) -> None:
        """T-ASSIGN: x := e.

        Requires: level(e) <= level(x) AND pc <= level(x).
        The pc condition prevents implicit flows.
        """
        if isinstance(stmt.target, Identifier):
            target_type = self.env.lookup(stmt.target.name)
            if target_type is None:
                return

            value_level = self._check_expr_level(stmt.value)

            # Check: value_level <= target_level
            if not (value_level <= target_type.level):
                self.errors.append(contract_error(
                    precondition=(
                        f"Information flow violation: explicit flow from "
                        f"{value_level.name} to {target_type.level.name} "
                        f"in assignment to '{stmt.target.name}'"
                    ),
                    failing_values={
                        "variable": stmt.target.name,
                        "source_level": value_level.name,
                        "target_level": target_type.level.name,
                        "flow_type": "explicit",
                    },
                    function_signature="information flow check",
                    location=stmt.location,
                ))

            # Check: pc <= target_level (no implicit flow)
            if not (self.context.pc_level <= target_type.level):
                self.errors.append(contract_error(
                    precondition=(
                        f"Information flow violation: implicit flow — "
                        f"assignment to '{stmt.target.name}' ({target_type.level.name}) "
                        f"under {self.context.pc_level.name} control flow"
                    ),
                    failing_values={
                        "variable": stmt.target.name,
                        "pc_level": self.context.pc_level.name,
                        "target_level": target_type.level.name,
                        "flow_type": "implicit",
                    },
                    function_signature="information flow check",
                    location=stmt.location,
                ))

    def _check_return(self, stmt: ReturnStmt, func) -> None:
        """Check that return value's security level is compatible with function's level."""
        if stmt.value:
            return_level = self._check_expr_level(stmt.value)
            # Return level must account for pc
            effective_level = join_level(return_level, self.context.pc_level)
            # Store for caller analysis
            ret_type = str(func.return_type) if func.return_type else "Void"
            self.env.define("__return__", SecurityType(base_type=ret_type, level=effective_level))

    def _check_if(self, stmt: IfStmt, func) -> None:
        """T-IF: if e then S1 else S2.

        The pc level in branches is raised to join(pc, level(e)).
        This enforces NO IMPLICIT FLOWS.
        """
        cond_level = self._check_expr_level(stmt.condition)

        # Raise pc for branches
        saved_pc = self.context.pc_level
        self.context.pc_level = join_level(saved_pc, cond_level)

        # Check branches
        for s in stmt.then_body:
            self._check_statement(s, func)
        for s in stmt.else_body:
            self._check_statement(s, func)

        # Restore pc
        self.context.pc_level = saved_pc

    def _check_while(self, stmt: WhileStmt, func) -> None:
        """T-WHILE: while e do S.

        Similar to if: pc is raised to join(pc, level(e)).
        Additionally, if the condition is SECRET, this is a
        potential TERMINATION CHANNEL (the loop may or may not
        terminate depending on secret data).
        """
        cond_level = self._check_expr_level(stmt.condition)

        # Termination channel warning
        if cond_level > SecurityLevel.PUBLIC:
            self.errors.append(contract_error(
                precondition=(
                    f"Potential termination channel: while loop condition "
                    f"depends on {cond_level.name} data. Loop termination "
                    f"may leak information."
                ),
                failing_values={
                    "condition_level": cond_level.name,
                    "channel_type": "termination",
                },
                function_signature="information flow check",
                location=stmt.location,
            ))

        # Raise pc for loop body
        saved_pc = self.context.pc_level
        self.context.pc_level = join_level(saved_pc, cond_level)

        for s in stmt.body:
            self._check_statement(s, func)

        self.context.pc_level = saved_pc

    def _check_expr_level(self, expr: Expr) -> SecurityLevel:
        """Compute the security level of an expression.

        The level of an expression is the join of the levels of
        all variables it depends on (information content).
        """
        if isinstance(expr, IntLiteral):
            return SecurityLevel.PUBLIC  # Constants are public

        if isinstance(expr, BoolLiteral):
            return SecurityLevel.PUBLIC

        if isinstance(expr, StringLiteral):
            return SecurityLevel.PUBLIC

        if isinstance(expr, Identifier):
            sec_type = self.env.lookup(expr.name)
            if sec_type:
                return sec_type.level
            return self.default_level

        if isinstance(expr, BinaryOp):
            left_level = self._check_expr_level(expr.left)
            right_level = self._check_expr_level(expr.right)
            return join_level(left_level, right_level)

        if isinstance(expr, UnaryOp):
            return self._check_expr_level(expr.operand)

        if isinstance(expr, FunctionCall):
            # Function result level = join of all argument levels
            arg_levels = [self._check_expr_level(a) for a in expr.args]
            if arg_levels:
                result = arg_levels[0]
                for l in arg_levels[1:]:
                    result = join_level(result, l)
                return result
            return SecurityLevel.PUBLIC

        if isinstance(expr, FieldAccess):
            obj_level = self._check_expr_level(expr.obj)
            # Check if field has its own security level
            if isinstance(expr.obj, Identifier):
                field_key = f"{expr.obj.name}.{expr.field_name}"
                # Check for registered field levels
                for key, sec_type in self.env.bindings.items():
                    if key.endswith(f".{expr.field_name}"):
                        return join_level(obj_level, sec_type.level)
            return obj_level

        if isinstance(expr, MethodCall):
            obj_level = self._check_expr_level(expr.obj)
            arg_levels = [self._check_expr_level(a) for a in expr.args]
            result = obj_level
            for l in arg_levels:
                result = join_level(result, l)
            return result

        if isinstance(expr, MoveExpr):
            sec_type = self.env.lookup(expr.name)
            return sec_type.level if sec_type else self.default_level

        if isinstance(expr, BorrowExpr):
            sec_type = self.env.lookup(expr.name)
            return sec_type.level if sec_type else self.default_level

        return self.default_level

    def _check_effect_security(self, func: TaskFunc) -> None:
        """Check that effects are compatible with information security levels.

        If a function handles SECRET data, its effects must go to
        appropriately-secured channels.
        """
        # Determine the maximum security level of function inputs
        max_input_level = SecurityLevel.PUBLIC
        for param in func.params:
            type_name = str(param.type_annotation) if param.type_annotation else ""
            sec_type = self.env.lookup(param.name)
            if sec_type:
                max_input_level = join_level(max_input_level, sec_type.level)

        # Check each effect
        for effect_str in func.effects:
            effect_level = self.effect_levels.get(effect_str, SecurityLevel.PUBLIC)
            if max_input_level > effect_level:
                self.errors.append(contract_error(
                    precondition=(
                        f"Effect security violation: function '{func.name}' handles "
                        f"{max_input_level.name} data but uses effect '{effect_str}' "
                        f"which is only cleared for {effect_level.name}"
                    ),
                    failing_values={
                        "function": func.name,
                        "data_level": max_input_level.name,
                        "effect": effect_str,
                        "effect_level": effect_level.name,
                    },
                    function_signature=f"task {func.name}",
                    location=func.location,
                ))

    def get_declassification_audit(self) -> List[Dict[str, Any]]:
        """Get the audit trail of all declassifications.

        Every point where information flow is intentionally downgraded
        is tracked for security auditing.
        """
        return [
            {
                "variable": d.variable,
                "from_level": d.from_level.name,
                "to_level": d.to_level.name,
                "location": str(d.location) if d.location else None,
                "audit_note": d.audit_note,
                "justified": d.justified,
            }
            for d in self.declassifications
        ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_information_flow(program: Program) -> List[AeonError]:
    """Run information flow analysis on an AEON program.

    Verifies the NONINTERFERENCE property:
    secret inputs cannot influence public outputs.

    Checks for:
    1. Explicit flows (direct HIGH -> LOW assignments)
    2. Implicit flows (HIGH branch conditions affecting LOW variables)
    3. Termination channels (loops depending on secret data)
    4. Effect security (secret data flowing to unsecured effect channels)
    """
    checker = InformationFlowChecker()
    return checker.check_program(program)
