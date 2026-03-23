"""Tests for the JS/TS adapter — particularly the _find_op_outside_strings fix.

Regression tests for the false-positive bug where URL paths inside string
literals and JSX attributes (e.g. href="/homeowner/settings") were parsed
as division operators, generating phantom division-by-zero findings.

Fixed: 2026-03-23
"""

import pytest
from aeon.adapters.js_adapter import TSTranslator, JSTranslator
from aeon.ast_nodes import BinaryOp, StringLiteral, Identifier, IntLiteral
from aeon.errors import SourceLocation


@pytest.fixture
def ts():
    return TSTranslator()


@pytest.fixture
def js():
    return JSTranslator()


@pytest.fixture
def loc():
    return SourceLocation(line=1, column=0, file="test.tsx")


# ---------------------------------------------------------------------------
# _find_op_outside_strings
# ---------------------------------------------------------------------------

class TestFindOpOutsideStrings:
    """Test the operator-finding logic that respects string boundaries."""

    def test_finds_division_in_plain_expr(self, ts):
        assert ts._find_op_outside_strings("a / b", "/") == 2

    def test_ignores_division_inside_double_quotes(self, ts):
        assert ts._find_op_outside_strings('"/homeowner/settings"', "/") == -1

    def test_ignores_division_inside_single_quotes(self, ts):
        assert ts._find_op_outside_strings("'/api/v1/users'", "/") == -1

    def test_ignores_division_inside_backticks(self, ts):
        assert ts._find_op_outside_strings("`/path/${id}/thing`", "/") == -1

    def test_ignores_division_inside_jsx_tag(self, ts):
        assert ts._find_op_outside_strings('<Link href="/home">', "/") == -1

    def test_finds_op_after_string(self, ts):
        expr = '"hello" + "world"'
        pos = ts._find_op_outside_strings(expr, "+")
        assert pos == 8

    def test_handles_escaped_quotes(self, ts):
        expr = r'"path\/to\/thing"'
        assert ts._find_op_outside_strings(expr, "/") == -1

    def test_multi_char_op_outside_string(self, ts):
        assert ts._find_op_outside_strings("a === b", "===") == 2

    def test_multi_char_op_inside_string(self, ts):
        assert ts._find_op_outside_strings('"a === b"', "===") == -1

    def test_nested_quotes_handled(self, ts):
        # Single quotes inside double quotes
        expr = '''"it's a /path"'''
        assert ts._find_op_outside_strings(expr, "/") == -1

    def test_empty_string(self, ts):
        assert ts._find_op_outside_strings("", "/") == -1

    def test_op_at_start(self, ts):
        assert ts._find_op_outside_strings("/ b", "/") == 0

    def test_jsx_nested_attributes(self, ts):
        expr = '<Component path="/api/v1" label="test">'
        assert ts._find_op_outside_strings(expr, "/") == -1


# ---------------------------------------------------------------------------
# _parse_simple_expr — URL paths should NOT become division
# ---------------------------------------------------------------------------

class TestParseSimpleExprURLPaths:
    """Regression tests: URL paths in strings must not be parsed as division."""

    def test_double_quoted_url_is_string_literal(self, ts, loc):
        expr = ts._parse_simple_expr('"/homeowner/settings"', loc)
        assert isinstance(expr, StringLiteral)
        assert expr.value == "/homeowner/settings"

    def test_single_quoted_url_is_string_literal(self, ts, loc):
        expr = ts._parse_simple_expr("'/api/v1/users'", loc)
        assert isinstance(expr, StringLiteral)
        assert expr.value == "/api/v1/users"

    def test_template_literal_url_is_string_literal(self, ts, loc):
        expr = ts._parse_simple_expr("`/path/to/resource`", loc)
        assert isinstance(expr, StringLiteral)
        assert expr.value == "/path/to/resource"

    def test_jsx_tag_with_url_not_division(self, ts, loc):
        expr = ts._parse_simple_expr('<Link href="/homeowner/settings">', loc)
        assert isinstance(expr, Identifier)
        assert expr.name == "__jsx__"

    def test_jsx_self_closing_tag(self, ts, loc):
        expr = ts._parse_simple_expr('<img src="/images/logo.png" />', loc)
        assert isinstance(expr, Identifier)
        assert expr.name == "__jsx__"

    def test_jsx_attr_with_url_not_division(self, ts, loc):
        # This is the key regression case — JSX attribute value reaches parser
        expr = ts._parse_simple_expr('href="/homeowner/settings"', loc)
        assert not isinstance(expr, BinaryOp), \
            "URL path in JSX attribute must not be parsed as division"


# ---------------------------------------------------------------------------
# _parse_simple_expr — real division still works
# ---------------------------------------------------------------------------

class TestParseSimpleExprDivision:
    """Ensure real arithmetic division is still parsed correctly."""

    def test_simple_variable_division(self, ts, loc):
        expr = ts._parse_simple_expr("a / b", loc)
        assert isinstance(expr, BinaryOp)
        assert expr.op == "/"

    def test_numeric_division(self, ts, loc):
        expr = ts._parse_simple_expr("total / count", loc)
        assert isinstance(expr, BinaryOp)
        assert expr.op == "/"

    def test_modulo_still_works(self, ts, loc):
        expr = ts._parse_simple_expr("x % 2", loc)
        assert isinstance(expr, BinaryOp)
        assert expr.op == "%"

    def test_addition_still_works(self, ts, loc):
        expr = ts._parse_simple_expr("a + b", loc)
        assert isinstance(expr, BinaryOp)
        assert expr.op == "+"

    def test_comparison_still_works(self, ts, loc):
        expr = ts._parse_simple_expr("a === b", loc)
        assert isinstance(expr, BinaryOp)
        assert expr.op == "=="

    def test_inequality_still_works(self, ts, loc):
        expr = ts._parse_simple_expr("a !== b", loc)
        assert isinstance(expr, BinaryOp)
        assert expr.op == "!="


# ---------------------------------------------------------------------------
# _parse_simple_expr — literals and identifiers
# ---------------------------------------------------------------------------

class TestParseSimpleExprBasics:
    """Basic expression parsing still works."""

    def test_boolean_true(self, ts, loc):
        assert ts._parse_simple_expr("true", loc).value is True

    def test_boolean_false(self, ts, loc):
        assert ts._parse_simple_expr("false", loc).value is False

    def test_null(self, ts, loc):
        expr = ts._parse_simple_expr("null", loc)
        assert isinstance(expr, IntLiteral)
        assert expr.value == 0

    def test_integer(self, ts, loc):
        expr = ts._parse_simple_expr("42", loc)
        assert isinstance(expr, IntLiteral)
        assert expr.value == 42

    def test_identifier(self, ts, loc):
        expr = ts._parse_simple_expr("myVar", loc)
        assert isinstance(expr, Identifier)
        assert expr.name == "myVar"

    def test_string_no_slashes(self, ts, loc):
        expr = ts._parse_simple_expr('"hello"', loc)
        assert isinstance(expr, StringLiteral)
        assert expr.value == "hello"


# ---------------------------------------------------------------------------
# JS translator has the same fix
# ---------------------------------------------------------------------------

class TestJSTranslatorSameFix:
    """Verify the JSTranslator (not just TS) also has the fix."""

    def test_js_url_in_string_not_division(self, js, loc):
        expr = js._parse_simple_expr('"/api/v1/users"', loc)
        assert isinstance(expr, StringLiteral)

    def test_js_real_division_works(self, js, loc):
        expr = js._parse_simple_expr("a / b", loc)
        assert isinstance(expr, BinaryOp)
        assert expr.op == "/"

    def test_js_jsx_tag_handled(self, js, loc):
        expr = js._parse_simple_expr('<div className="test">', loc)
        assert isinstance(expr, Identifier)
        assert expr.name == "__jsx__"
