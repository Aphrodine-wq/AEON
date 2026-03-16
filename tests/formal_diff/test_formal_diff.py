"""Tests for AEON formal diff."""
import pytest
from aeon.formal_diff import FormalDiffer


@pytest.fixture
def differ():
    return FormalDiffer()


OLD_PYTHON = '''
def safe_divide(a, b):
    """
    Requires: b != 0
    Ensures: result * b <= a
    """
    return a // b

def process(data):
    """
    Requires: data is not None
    Ensures: result >= 0
    """
    return len(data)
'''

NEW_PYTHON_PRESERVED = '''
def safe_divide(a, b):
    """
    Requires: b != 0
    Ensures: result * b <= a
    """
    if b == 0:
        raise ValueError
    return a // b

def process(data):
    """
    Requires: data is not None
    Ensures: result >= 0
    """
    return max(0, len(data))
'''

NEW_PYTHON_BROKEN = '''
def safe_divide(a, b):
    """
    Requires: b != 0
    """
    return a // b

def process(data):
    """
    Requires: data is not None
    Ensures: result >= 0
    Ensures: result <= 1000
    """
    return len(data)
'''


class TestPreservedInvariants:
    def test_all_preserved(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_PRESERVED, "python")
        preserved = [c for c in result.invariant_changes if c.change_type == "preserved"]
        assert len(preserved) > 0
        assert result.safety_preserved is True

    def test_risk_safe(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_PRESERVED, "python")
        assert result.risk_assessment == "safe"


class TestBrokenInvariants:
    def test_removed_detected(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_BROKEN, "python")
        removed = [c for c in result.invariant_changes if c.change_type == "removed"]
        assert len(removed) > 0

    def test_safety_not_preserved(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_BROKEN, "python")
        assert result.safety_preserved is False

    def test_risk_elevated(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_BROKEN, "python")
        assert result.risk_assessment in ("caution", "dangerous")


class TestAddedInvariants:
    def test_added_detected(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_BROKEN, "python")
        added = [c for c in result.invariant_changes if c.change_type == "added"]
        assert len(added) > 0


class TestFormatting:
    def test_pretty_format(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_BROKEN, "python")
        output = differ.format_diff(result, "pretty")
        assert "FORMAL DIFF" in output

    def test_json_format(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_BROKEN, "python")
        import json
        output = differ.format_diff(result, "json")
        data = json.loads(output)
        assert "risk_assessment" in data

    def test_markdown_format(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_BROKEN, "python")
        output = differ.format_diff(result, "markdown")
        assert "## AEON Formal Diff" in output


class TestSummary:
    def test_summary_populated(self, differ):
        result = differ.diff_files(OLD_PYTHON, NEW_PYTHON_BROKEN, "python")
        assert result.summary
        assert "preserved" in result.summary or "broken" in result.summary
