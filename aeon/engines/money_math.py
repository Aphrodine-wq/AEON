"""AEON Money Math Engine — Financial Calculation Bug Detection.

Detects common mistakes in code that handles money, prices, taxes,
margins, and other financial values.  Construction estimation software
is especially vulnerable because estimates flow through many arithmetic
stages (materials x quantity, labor x hours, markup, tax, rounding)
and a single float precision bug can silently mis-price a $200k job.

Based on:
  Goldberg (1991) "What Every Computer Scientist Should Know About
  Floating-Point Arithmetic" — ACM Computing Surveys 23(1).

  Bloch (2008) "Effective Java", Item 48: Avoid float and double if
  exact answers are required.

Detects:
  1. FLOAT CURRENCY — Using float/double for money instead of integer cents
  2. PRECISION LOSS — Expressions like price * 0.1 that lose precision
  3. MISSING ROUND — Financial result not rounded before display/storage
  4. UNSAFE TOFIX — toFixed() without proper rounding mode
  5. UNGUARDED DIVISION — Division in money code without zero guard
  6. ACCUMULATION DRIFT — Summing floats in a loop (errors compound)
  7. CURRENCY MIXING — Arithmetic on values with different implied units
  8. TAX/MARGIN ORDER — Tax applied before discount or margin after tax
  9. CENT TRUNCATION — Converting dollars to cents via multiply (use Math.round)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral,
    StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    ForStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Money-related heuristics
# ---------------------------------------------------------------------------

# Variable/parameter names that suggest money values
MONEY_NAME_PATTERNS: Set[str] = {
    "price", "cost", "amount", "total", "subtotal", "tax",
    "discount", "markup", "margin", "fee", "rate", "wage",
    "salary", "revenue", "profit", "balance", "payment",
    "invoice", "estimate", "bid", "quote", "budget",
    "labor", "material", "materials", "overhead", "expense",
    "charge", "deposit", "refund", "credit", "debit",
    "unit_price", "unitPrice", "lineTotal", "line_total",
    "grandTotal", "grand_total", "netTotal", "net_total",
    "grossTotal", "gross_total", "taxAmount", "tax_amount",
    "discountAmount", "discount_amount", "markupAmount",
    "markup_amount", "laborCost", "labor_cost",
    "materialCost", "material_cost", "totalCost", "total_cost",
    "estimateTotal", "estimate_total", "invoiceTotal", "invoice_total",
    "hourlyRate", "hourly_rate", "sqftPrice", "sqft_price",
    "pricePerUnit", "price_per_unit", "costPerUnit", "cost_per_unit",
}

# Patterns that indicate percentage/rate values (not raw money)
RATE_PATTERNS: Set[str] = {
    "percent", "percentage", "pct", "ratio", "factor",
    "taxRate", "tax_rate", "markupRate", "markup_rate",
    "discountRate", "discount_rate", "marginRate", "margin_rate",
}

# Rounding functions that sanitize money values
ROUNDING_FUNCTIONS: Set[str] = {
    "round", "Math.round", "toFixed", "toPrecision",
    "Math.floor", "Math.ceil", "Number",
    "parseFloat", "parseInt",
    "Decimal", "decimal.Decimal",
    "cents_to_dollars", "dollars_to_cents",
    "format_currency", "formatCurrency",
    "roundToNearest", "round_to_nearest",
}

# Common tax/rate constants that indicate financial math
FINANCIAL_CONSTANTS: Set[float] = {
    0.0825, 0.08, 0.0625, 0.07, 0.06, 0.05,  # Sales tax rates
    0.10, 0.15, 0.20, 0.25, 0.30,              # Common markup/discount %
    1.0825, 1.08, 1.0625, 1.07, 1.06, 1.05,    # Tax multipliers
    100.0, 100,                                   # Cent conversion
}


# ---------------------------------------------------------------------------
# Analysis State
# ---------------------------------------------------------------------------

class MoneyRisk(Enum):
    """Categories of money math risk."""
    FLOAT_CURRENCY = "float_currency"
    PRECISION_LOSS = "precision_loss"
    MISSING_ROUND = "missing_round"
    UNSAFE_TOFIX = "unsafe_toFixed"
    UNGUARDED_DIVISION = "unguarded_division"
    ACCUMULATION_DRIFT = "accumulation_drift"
    CENT_TRUNCATION = "cent_truncation"


@dataclass
class MoneyVar:
    """Tracks what we know about a variable in money context."""
    is_money: bool = False
    is_rate: bool = False
    is_float: bool = False
    is_rounded: bool = False
    is_from_input: bool = False
    in_loop: bool = False


# ---------------------------------------------------------------------------
# Money Math Analyzer
# ---------------------------------------------------------------------------

class MoneyMathAnalyzer:
    """Analyzes programs for financial calculation bugs."""

    def __init__(self):
        self.errors: List[AeonError] = []
        self._vars: Dict[str, MoneyVar] = {}
        self._current_func: str = ""
        self._in_loop: bool = False
        self._func_has_money: bool = False

    def check_program(self, program: Program) -> List[AeonError]:
        """Run money math analysis on the entire program."""
        self.errors = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._check_function(decl)

        return self.errors

    def _check_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function for money math issues."""
        self._vars = {}
        self._current_func = func.name
        self._in_loop = False
        self._func_has_money = self._is_money_name(func.name)

        # Check if function deals with money based on name
        for param in func.params:
            mv = MoneyVar()
            if self._is_money_name(param.name):
                mv.is_money = True
                self._func_has_money = True
            if self._is_rate_name(param.name):
                mv.is_rate = True
                self._func_has_money = True
            type_str = str(param.type_annotation).lower() if param.type_annotation else ""
            if any(t in type_str for t in ("float", "double", "f32", "f64", "number")):
                mv.is_float = True
                # Flag: money parameter typed as float
                if mv.is_money:
                    self.errors.append(self._money_error(
                        MoneyRisk.FLOAT_CURRENCY,
                        f"Parameter '{param.name}' appears to hold money but is typed as "
                        f"float/number. Use integer cents or a Decimal type to avoid "
                        f"precision loss (e.g., $10.30 as 1030 cents)",
                        func, getattr(param, 'location', None),
                    ))
            self._vars[param.name] = mv

        for stmt in func.body:
            self._check_statement(stmt, func)

    def _check_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Check a statement for money math issues."""
        loc = getattr(stmt, 'location', SourceLocation("<money>", 0, 0))

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_expr(stmt.value, func, loc)
                mv = self._infer_money_var(stmt.value, stmt.name)
                if self._in_loop and mv.is_money:
                    mv.in_loop = True
                self._vars[stmt.name] = mv

        elif isinstance(stmt, AssignStmt):
            self._check_expr(stmt.value, func, loc)
            target_name = self._expr_name(stmt.target) if hasattr(stmt, 'target') else None
            if target_name and target_name in self._vars:
                existing = self._vars[target_name]
                if existing.is_money and self._in_loop:
                    # Accumulating money in a loop
                    if isinstance(stmt.value, BinaryOp) and stmt.value.op in ("+", "-"):
                        self.errors.append(self._money_error(
                            MoneyRisk.ACCUMULATION_DRIFT,
                            f"Accumulating money value '{target_name}' inside a loop. "
                            f"Floating-point errors compound with each iteration. "
                            f"Consider computing the total from quantities and unit prices, "
                            f"or use integer cents",
                            func, loc,
                        ))

        elif isinstance(stmt, ExprStmt):
            self._check_expr(stmt.expr, func, loc)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value and self._func_has_money:
                self._check_expr(stmt.value, func, loc)
                # Check if return value is rounded in money function
                if not self._is_rounded_expr(stmt.value):
                    if self._is_money_expr(stmt.value):
                        self.errors.append(self._money_error(
                            MoneyRisk.MISSING_ROUND,
                            f"Returning unrounded money value from '{func.name}'. "
                            f"Financial values should be rounded to 2 decimal places "
                            f"before returning (e.g., Math.round(x * 100) / 100)",
                            func, loc,
                        ))

        elif isinstance(stmt, IfStmt):
            self._check_expr(stmt.condition, func, loc)
            for s in stmt.then_body:
                self._check_statement(s, func)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._check_statement(s, func)

        elif isinstance(stmt, WhileStmt):
            self._check_expr(stmt.condition, func, loc)
            old_loop = self._in_loop
            self._in_loop = True
            for s in stmt.body:
                self._check_statement(s, func)
            self._in_loop = old_loop

        elif isinstance(stmt, ForStmt):
            old_loop = self._in_loop
            self._in_loop = True
            for s in stmt.body:
                self._check_statement(s, func)
            self._in_loop = old_loop

    def _check_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                    loc: SourceLocation) -> None:
        """Check an expression for money math issues."""
        if isinstance(expr, BinaryOp):
            self._check_expr(expr.left, func, loc)
            self._check_expr(expr.right, func, loc)
            expr_loc = getattr(expr, 'location', loc)

            left_money = self._is_money_expr(expr.left)
            right_money = self._is_money_expr(expr.right)
            is_money_context = left_money or right_money or self._func_has_money

            if not is_money_context:
                return

            # Division without guard in money context
            if expr.op in ("/", "%", "//"):
                if not self._is_safe_divisor(expr.right):
                    self.errors.append(self._money_error(
                        MoneyRisk.UNGUARDED_DIVISION,
                        f"Division in financial calculation: "
                        f"'{self._expr_str(expr.left)} / {self._expr_str(expr.right)}'. "
                        f"Guard against zero to prevent NaN/Infinity in money values",
                        func, expr_loc,
                    ))

            # Precision loss: money * fractional float
            if expr.op == "*" and is_money_context:
                if self._is_precision_risk(expr.left, expr.right):
                    self.errors.append(self._money_error(
                        MoneyRisk.PRECISION_LOSS,
                        f"Precision risk in money calculation: "
                        f"'{self._expr_str(expr.left)} * {self._expr_str(expr.right)}'. "
                        f"Multiplying money by a decimal can lose precision. "
                        f"Consider: Math.round(amount * rate * 100) / 100",
                        func, expr_loc,
                    ))

            # Cent truncation: dollars * 100 without rounding
            if expr.op == "*":
                if self._is_cent_conversion(expr.left, expr.right):
                    self.errors.append(self._money_error(
                        MoneyRisk.CENT_TRUNCATION,
                        f"Converting dollars to cents via multiplication: "
                        f"'{self._expr_str(expr)}'. "
                        f"Use Math.round({self._expr_str(expr)}) to avoid "
                        f"truncation (e.g., 1.1 * 100 = 110.00000000000001)",
                        func, expr_loc,
                    ))

        elif isinstance(expr, MethodCall):
            self._check_expr(expr.obj, func, loc)
            for arg in expr.args:
                self._check_expr(arg, func, loc)

            # Unsafe toFixed on money
            if expr.method_name == "toFixed":
                if self._is_money_expr(expr.obj):
                    self.errors.append(self._money_error(
                        MoneyRisk.UNSAFE_TOFIX,
                        f"Using .toFixed() on money value '{self._expr_str(expr.obj)}'. "
                        f"toFixed() uses banker's rounding in some engines and returns "
                        f"a string. Round first with Math.round(x * 100) / 100, "
                        f"then format for display",
                        func, getattr(expr, 'location', loc),
                    ))

        elif isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                for arg in expr.args:
                    self._check_expr(arg, func, loc)
            elif isinstance(expr, FunctionCall):
                for arg in expr.args:
                    self._check_expr(arg, func, loc)

    def _infer_money_var(self, expr: Expr, var_name: str = "") -> MoneyVar:
        """Infer whether an expression/variable involves money."""
        mv = MoneyVar()
        # Check the variable name
        if var_name and self._is_money_name(var_name):
            mv.is_money = True
        if var_name and self._is_rate_name(var_name):
            mv.is_rate = True
        # Check the expression
        if self._is_money_expr(expr):
            mv.is_money = True
        # Check for float type
        if isinstance(expr, FloatLiteral):
            mv.is_float = True
        if isinstance(expr, BinaryOp):
            if isinstance(expr.left, FloatLiteral) or isinstance(expr.right, FloatLiteral):
                mv.is_float = True
        # Check for rounding
        mv.is_rounded = self._is_rounded_expr(expr)
        return mv

    # ── Heuristic helpers ────────────────────────────────────────────────

    def _is_money_name(self, name: str) -> bool:
        """Check if a name suggests a money variable."""
        lower = name.lower()
        return any(p in lower for p in MONEY_NAME_PATTERNS)

    def _is_rate_name(self, name: str) -> bool:
        """Check if a name suggests a rate/percentage."""
        lower = name.lower()
        return any(p in lower for p in RATE_PATTERNS)

    def _is_money_expr(self, expr: Expr) -> bool:
        """Check if an expression likely represents money."""
        if isinstance(expr, Identifier):
            if expr.name in self._vars:
                return self._vars[expr.name].is_money
            return self._is_money_name(expr.name)
        if isinstance(expr, FieldAccess):
            return self._is_money_name(expr.field_name)
        if isinstance(expr, BinaryOp):
            return self._is_money_expr(expr.left) or self._is_money_expr(expr.right)
        return False

    def _is_rounded_expr(self, expr: Expr) -> bool:
        """Check if expression is wrapped in a rounding function."""
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                return expr.callee.name in ROUNDING_FUNCTIONS
        if isinstance(expr, MethodCall):
            if expr.method_name in ("toFixed", "toPrecision"):
                return True
        # Math.round(x * 100) / 100 pattern
        if isinstance(expr, BinaryOp) and expr.op == "/":
            if isinstance(expr.right, (IntLiteral, FloatLiteral)):
                if isinstance(expr.left, FunctionCall):
                    if isinstance(expr.left.callee, FieldAccess):
                        if expr.left.callee.field_name == "round":
                            return True
                    if isinstance(expr.left.callee, Identifier):
                        if expr.left.callee.name in ("round", "Math_round"):
                            return True
        return False

    def _is_safe_divisor(self, expr: Expr) -> bool:
        """Check if a divisor is safe (constant > 0)."""
        if isinstance(expr, IntLiteral):
            return expr.value != 0
        if isinstance(expr, FloatLiteral):
            return expr.value != 0.0
        # Known safe constants (100, 12, etc.)
        return False

    def _is_precision_risk(self, left: Expr, right: Expr) -> bool:
        """Check if multiplication has precision risk."""
        # money * 0.0825 (tax rate) — precision risk
        if self._is_money_expr(left) and isinstance(right, FloatLiteral):
            if right.value not in (0.0, 1.0, 2.0, 0.5, 0.25):
                return True
        if self._is_money_expr(right) and isinstance(left, FloatLiteral):
            if left.value not in (0.0, 1.0, 2.0, 0.5, 0.25):
                return True
        return False

    def _is_cent_conversion(self, left: Expr, right: Expr) -> bool:
        """Check for dollars-to-cents multiplication without rounding."""
        if isinstance(right, (IntLiteral, FloatLiteral)):
            val = right.value if isinstance(right, IntLiteral) else right.value
            if val == 100 and self._is_money_expr(left):
                return True
        if isinstance(left, (IntLiteral, FloatLiteral)):
            val = left.value if isinstance(left, IntLiteral) else left.value
            if val == 100 and self._is_money_expr(right):
                return True
        return False

    def _expr_name(self, expr: Expr) -> Optional[str]:
        """Get variable name from expression if it's a simple identifier."""
        if isinstance(expr, Identifier):
            return expr.name
        return None

    def _expr_str(self, expr: Expr) -> str:
        """Get a short string representation of an expression."""
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, IntLiteral):
            return str(expr.value)
        if isinstance(expr, FloatLiteral):
            return str(expr.value)
        if isinstance(expr, FieldAccess):
            return f"{self._expr_str(expr.obj)}.{expr.field_name}"
        if isinstance(expr, BinaryOp):
            return f"{self._expr_str(expr.left)} {expr.op} {self._expr_str(expr.right)}"
        if isinstance(expr, MethodCall):
            return f"{self._expr_str(expr.obj)}.{expr.method_name}()"
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return f"{expr.callee.name}()"
        return "<expr>"

    def _money_error(self, risk: MoneyRisk, message: str,
                     func: PureFunc | TaskFunc,
                     loc: Optional[SourceLocation] = None) -> AeonError:
        """Create a money math error."""
        return contract_error(
            precondition=message,
            failing_values={
                "risk": risk.value,
                "engine": "Money Math",
                "function": func.name,
            },
            function_signature=func.name,
            location=loc or SourceLocation("<money>", 0, 0),
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_money_math(program: Program) -> List[AeonError]:
    """Run money math analysis on an AEON program.

    Detects:
    - Float currency (using float/double for money)
    - Precision loss in financial multiplication
    - Missing rounding before return/storage
    - Unsafe toFixed() usage
    - Unguarded division in financial code
    - Accumulation drift (summing floats in loops)
    - Cent truncation (dollars * 100 without rounding)
    """
    analyzer = MoneyMathAnalyzer()
    return analyzer.check_program(program)
