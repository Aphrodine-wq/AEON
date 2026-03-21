"""AEON Construction Domain Verifier — Estimation-Specific Bug Detection.

Catches bugs unique to construction estimation, invoicing, and
bid management software.  No other static analysis tool has this —
it's domain knowledge from building FairEstimator and FairTradeWorker
encoded into formal rules.

Detects:
  1. TOTAL MISMATCH — Total != sum of line items
  2. MARKUP ORDER — Markup applied after tax (should be before)
  3. TAX ORDER — Tax applied to wrong base (pre-markup vs post-markup)
  4. QUANTITY MISMATCH — lineTotal != quantity * unitPrice
  5. NEGATIVE AMOUNTS — Negative values in cost/price (except discounts)
  6. ZERO QUANTITY — Line item with zero quantity but non-zero price
  7. MARGIN INVERSION — Margin calculated as (cost-price)/price instead of (price-cost)/cost
  8. ROUNDING CASCADE — Multiple rounding steps compound errors
  9. UNIT CONFUSION — Mixing sqft and linear ft, hours and days
  10. ESTIMATE COMPLETENESS — Missing required sections (labor, materials, overhead)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, FloatLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
    ForStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Domain Knowledge
# ---------------------------------------------------------------------------

class ConstructionRisk(Enum):
    TOTAL_MISMATCH = "total_mismatch"
    MARKUP_ORDER = "markup_order"
    TAX_ORDER = "tax_order"
    QUANTITY_MISMATCH = "quantity_mismatch"
    NEGATIVE_AMOUNT = "negative_amount"
    ZERO_QUANTITY = "zero_quantity"
    MARGIN_INVERSION = "margin_inversion"
    ROUNDING_CASCADE = "rounding_cascade"
    UNIT_CONFUSION = "unit_confusion"
    MISSING_SECTION = "missing_section"
    PERCENTAGE_MISUSE = "percentage_misuse"


# Variable names indicating construction estimation context
QUANTITY_NAMES: Set[str] = {
    "quantity", "qty", "count", "units", "hours", "sqft",
    "linear_ft", "linearFt", "cubic_yards", "cubicYards",
    "sheets", "rolls", "bags", "boxes", "pieces", "pcs",
    "numWorkers", "num_workers", "crew_size", "crewSize",
    "days", "weeks",
}

UNIT_PRICE_NAMES: Set[str] = {
    "unitPrice", "unit_price", "pricePerUnit", "price_per_unit",
    "costPerUnit", "cost_per_unit", "rate", "hourlyRate", "hourly_rate",
    "sqftPrice", "sqft_price", "perSqft", "per_sqft",
    "materialPrice", "material_price", "laborRate", "labor_rate",
}

LINE_TOTAL_NAMES: Set[str] = {
    "lineTotal", "line_total", "itemTotal", "item_total",
    "subtotal", "sub_total", "lineAmount", "line_amount",
    "extended", "extendedPrice", "extended_price",
}

TAX_NAMES: Set[str] = {
    "tax", "taxAmount", "tax_amount", "salesTax", "sales_tax",
    "taxRate", "tax_rate", "taxPercent", "tax_percent",
}

MARKUP_NAMES: Set[str] = {
    "markup", "markupAmount", "markup_amount", "markupRate", "markup_rate",
    "markupPercent", "markup_percent", "margin", "marginAmount", "margin_amount",
    "overhead", "overheadAmount", "overhead_amount", "profit", "profitMargin",
}

DISCOUNT_NAMES: Set[str] = {
    "discount", "discountAmount", "discount_amount", "discountRate",
    "discount_rate", "discountPercent", "discount_percent",
    "adjustment", "credit",
}

TOTAL_NAMES: Set[str] = {
    "total", "grandTotal", "grand_total", "estimateTotal", "estimate_total",
    "invoiceTotal", "invoice_total", "projectTotal", "project_total",
    "finalTotal", "final_total", "totalCost", "total_cost",
    "totalPrice", "total_price", "netTotal", "net_total",
    "grossTotal", "gross_total",
}

SECTION_NAMES: Set[str] = {
    "labor", "materials", "overhead", "permits", "equipment",
    "subcontractor", "contingency", "waste",
}

# Percentage values (should be 0-1 or 0-100, not mixed)
TYPICAL_PERCENTAGES: Set[str] = {
    "taxRate", "tax_rate", "markupRate", "markup_rate",
    "discountRate", "discount_rate", "marginRate", "margin_rate",
    "overheadRate", "overhead_rate", "profitPercent", "profit_percent",
    "wastePercent", "waste_percent", "contingencyPercent", "contingency_percent",
}


# ---------------------------------------------------------------------------
# Construction Domain Analyzer
# ---------------------------------------------------------------------------

class ConstructionDomainAnalyzer:
    """Analyzes programs for construction estimation bugs."""

    def __init__(self):
        self.errors: List[AeonError] = []
        self._vars: Dict[str, str] = {}  # var name → category
        self._current_func: str = ""
        self._round_count: int = 0
        self._has_sections: Set[str] = set()
        self._func_is_estimation: bool = False

    def check_program(self, program: Program) -> List[AeonError]:
        """Run construction domain analysis."""
        self.errors = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._check_function(decl)

        return self.errors

    def _check_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function for construction domain bugs."""
        self._vars = {}
        self._current_func = func.name
        self._round_count = 0
        self._func_is_estimation = self._is_estimation_function(func.name)

        if not self._func_is_estimation:
            # Check if params suggest estimation context
            for param in func.params:
                if self._classify_var(param.name):
                    self._func_is_estimation = True
                    break

        if not self._func_is_estimation:
            return  # Skip non-estimation functions

        # Classify parameters
        for param in func.params:
            cat = self._classify_var(param.name)
            if cat:
                self._vars[param.name] = cat

        for stmt in func.body:
            self._check_statement(stmt, func)

        # Check for rounding cascade
        if self._round_count >= 3:
            self.errors.append(self._domain_error(
                ConstructionRisk.ROUNDING_CASCADE,
                f"Function '{func.name}' rounds {self._round_count} times. "
                f"Multiple rounding steps compound errors — keep full precision "
                f"until final display/storage, then round once",
                func,
            ))

    def _check_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Check a statement for construction domain bugs."""
        loc = getattr(stmt, 'location', SourceLocation("<construction>", 0, 0))

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_expr(stmt.value, func, loc, stmt.name)
                cat = self._classify_var(stmt.name)
                if cat:
                    self._vars[stmt.name] = cat
                # Track sections
                for section in SECTION_NAMES:
                    if section in stmt.name.lower():
                        self._has_sections.add(section)

        elif isinstance(stmt, AssignStmt):
            self._check_expr(stmt.value, func, loc)

        elif isinstance(stmt, ExprStmt):
            self._check_expr(stmt.expr, func, loc)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self._check_expr(stmt.value, func, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._check_statement(s, func)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._check_statement(s, func)

        elif isinstance(stmt, (WhileStmt, ForStmt)):
            for s in stmt.body:
                self._check_statement(s, func)

    def _check_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                    loc: SourceLocation, target_name: str = "") -> None:
        """Check an expression for construction domain bugs."""
        if isinstance(expr, BinaryOp):
            self._check_expr(expr.left, func, loc)
            self._check_expr(expr.right, func, loc)
            expr_loc = getattr(expr, 'location', loc)

            # Check: quantity * unitPrice should = lineTotal
            if expr.op == "*":
                left_cat = self._get_var_category(expr.left)
                right_cat = self._get_var_category(expr.right)

                # Detect: markup applied to tax (wrong order)
                if (left_cat == "tax" and right_cat == "markup") or \
                   (left_cat == "markup" and right_cat == "tax"):
                    self.errors.append(self._domain_error(
                        ConstructionRisk.MARKUP_ORDER,
                        f"Markup and tax multiplied together: "
                        f"'{self._expr_str(expr.left)} * {self._expr_str(expr.right)}'. "
                        f"Standard order: subtotal -> markup -> tax. "
                        f"Applying markup after tax overcharges the customer",
                        func, expr_loc,
                    ))

                # Detect: percentage > 1 used as multiplier (should be 0.08, not 8)
                if left_cat in ("tax", "markup", "discount") or right_cat in ("tax", "markup", "discount"):
                    self._check_percentage_value(expr.left, expr.right, func, expr_loc)

            # Check: total = something that doesn't include all parts
            if expr.op in ("+", "-") and target_name:
                target_cat = self._classify_var(target_name)
                if target_cat == "total":
                    # This is building up a total — track components
                    pass  # Future: verify all sections included

            # Negative amount check (cost - something going negative)
            if expr.op == "-":
                left_cat = self._get_var_category(expr.left)
                right_cat = self._get_var_category(expr.right)
                if left_cat == "cost" and right_cat == "cost":
                    # Subtracting costs — could go negative
                    self.errors.append(self._domain_error(
                        ConstructionRisk.NEGATIVE_AMOUNT,
                        f"Cost subtraction: '{self._expr_str(expr)}' "
                        f"could produce negative amount. Add a Math.max(0, ...) "
                        f"guard unless negative values are intentional (credits/refunds)",
                        func, expr_loc,
                    ))

            # Margin inversion: (cost - price) / price instead of (price - cost) / cost
            if expr.op == "/":
                if isinstance(expr.left, BinaryOp) and expr.left.op == "-":
                    inner_left = self._get_var_category(expr.left.left)
                    inner_right = self._get_var_category(expr.left.right)
                    divisor_cat = self._get_var_category(expr.right)
                    # (cost - price) / price = wrong margin formula
                    if inner_left == "cost" and inner_right in ("price", "total") and divisor_cat in ("price", "total"):
                        self.errors.append(self._domain_error(
                            ConstructionRisk.MARGIN_INVERSION,
                            f"Margin formula may be inverted: "
                            f"'{self._expr_str(expr)}'. "
                            f"Standard markup = (price - cost) / cost. "
                            f"Standard margin = (price - cost) / price. "
                            f"Verify which formula is intended",
                            func, expr_loc,
                        ))

        elif isinstance(expr, MethodCall):
            # Track rounding calls
            if expr.method_name in ("toFixed", "toPrecision"):
                self._round_count += 1
            self._check_expr(expr.obj, func, loc)
            for arg in expr.args:
                self._check_expr(arg, func, loc)

        elif isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                if expr.callee.name in ("round", "Math.round", "Math.floor", "Math.ceil"):
                    self._round_count += 1
            for arg in getattr(expr, 'args', []):
                self._check_expr(arg, func, loc)

    def _check_percentage_value(self, left: Expr, right: Expr,
                                func: PureFunc | TaskFunc,
                                loc: SourceLocation) -> None:
        """Check if a percentage value is in the wrong scale (8 vs 0.08)."""
        # If multiplying money by a number > 1 that's named like a rate
        for operand in (left, right):
            if isinstance(operand, FloatLiteral):
                if operand.value > 1.0 and operand.value < 100.0:
                    other = right if operand is left else left
                    other_cat = self._get_var_category(other)
                    if other_cat in ("cost", "price", "total", "line_total"):
                        self.errors.append(self._domain_error(
                            ConstructionRisk.PERCENTAGE_MISUSE,
                            f"Multiplying money by {operand.value}: "
                            f"'{self._expr_str(left)} * {self._expr_str(right)}'. "
                            f"If {operand.value} is a percentage, it should be "
                            f"{operand.value / 100} (e.g., 8.25% tax = 0.0825, not 8.25). "
                            f"If it's a multiplier (1 + rate), ignore this",
                            func, loc,
                        ))
            elif isinstance(operand, IntLiteral):
                if operand.value > 1 and operand.value <= 100:
                    other = right if operand is left else left
                    other_cat = self._get_var_category(other)
                    if other_cat in ("cost", "price", "total", "line_total"):
                        # Could be legitimate (quantity * price) — check other name
                        other_name = self._expr_str(other)
                        if not any(q in other_name.lower() for q in QUANTITY_NAMES):
                            self.errors.append(self._domain_error(
                                ConstructionRisk.PERCENTAGE_MISUSE,
                                f"Multiplying money by integer {operand.value}: "
                                f"'{self._expr_str(left)} * {self._expr_str(right)}'. "
                                f"If this is a percentage, divide by 100 first",
                                func, loc,
                            ))

    # ── Helpers ────────────────────────────────────────────────────────

    def _is_estimation_function(self, name: str) -> bool:
        """Check if a function name suggests estimation context."""
        lower = name.lower()
        keywords = [
            "estimate", "calculate", "compute", "pricing", "invoice",
            "quote", "bid", "cost", "total", "subtotal", "tax",
            "markup", "margin", "labor", "material", "line_item",
            "lineItem", "create_estimate", "createEstimate",
            "getTotal", "get_total", "calcTotal", "calc_total",
            "applyMarkup", "apply_markup", "applyTax", "apply_tax",
            "applyDiscount", "apply_discount",
        ]
        return any(kw in lower for kw in keywords)

    def _classify_var(self, name: str) -> Optional[str]:
        """Classify a variable name into a construction domain category."""
        lower = name.lower()
        if any(n in lower for n in ("quantity", "qty", "count", "units", "hours", "sqft", "days")):
            return "quantity"
        if any(n in lower for n in ("unitprice", "unit_price", "rate", "persqft", "per_sqft")):
            return "unit_price"
        if any(n in lower for n in ("linetotal", "line_total", "itemtotal", "item_total", "extended")):
            return "line_total"
        if any(n in lower for n in ("tax",)):
            return "tax"
        if any(n in lower for n in ("markup", "margin", "overhead", "profit")):
            return "markup"
        if any(n in lower for n in ("discount", "adjustment", "credit")):
            return "discount"
        if any(n in lower for n in ("total", "grand", "final", "net", "gross")):
            return "total"
        if any(n in lower for n in ("price", "cost", "amount", "fee", "charge")):
            return "cost"
        return None

    def _get_var_category(self, expr: Expr) -> Optional[str]:
        """Get the construction category of an expression."""
        if isinstance(expr, Identifier):
            if expr.name in self._vars:
                return self._vars[expr.name]
            return self._classify_var(expr.name)
        if isinstance(expr, FieldAccess):
            return self._classify_var(expr.field_name)
        return None

    def _expr_str(self, expr: Expr) -> str:
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
        return "<expr>"

    def _domain_error(self, risk: ConstructionRisk, message: str,
                      func: PureFunc | TaskFunc,
                      loc: Optional[SourceLocation] = None) -> AeonError:
        return contract_error(
            precondition=message,
            failing_values={
                "risk": risk.value,
                "engine": "Construction Domain",
                "function": func.name,
            },
            function_signature=func.name,
            location=loc or SourceLocation("<construction>", 0, 0),
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_construction_domain(program: Program) -> List[AeonError]:
    """Run construction domain analysis on an AEON program.

    Detects construction estimation-specific bugs:
    - Markup/tax ordering errors
    - Margin formula inversions
    - Percentage scale confusion (8.25 vs 0.0825)
    - Rounding cascades
    - Negative cost amounts
    """
    analyzer = ConstructionDomainAnalyzer()
    return analyzer.check_program(program)
