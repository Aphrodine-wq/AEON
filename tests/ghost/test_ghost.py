"""Tests for AEON ghost assertion shadowing."""
import tempfile
import pytest
from aeon.ghost import GhostAnalyzer


@pytest.fixture
def analyzer():
    return GhostAnalyzer()


@pytest.fixture
def unguarded_python(tmp_path):
    f = tmp_path / "unguarded.py"
    f.write_text(
        "def calculate(a, b):\n"
        "    return a / b\n"
        "\n"
        "def get_item(items, index):\n"
        "    return items[index]\n"
        "\n"
        "def read_file(path):\n"
        "    f = open(path)\n"
        "    data = f.read()\n"
        "    return data\n"
        "\n"
        "def process_payment(amount: float, card: str):\n"
        "    charge(card, amount)\n"
    )
    return str(f)


@pytest.fixture
def guarded_python(tmp_path):
    f = tmp_path / "guarded.py"
    f.write_text(
        "def calculate(a, b):\n"
        "    if b == 0:\n"
        "        raise ValueError\n"
        "    return a / b\n"
        "\n"
        "def get_item(items, index):\n"
        "    if index < len(items):\n"
        "        return items[index]\n"
        "    return None\n"
    )
    return str(f)


class TestDivisionDetection:
    def test_unguarded_division(self, analyzer, unguarded_python):
        ghosts = analyzer.analyze_file(unguarded_python)
        div_ghosts = [g for g in ghosts if "!= 0" in g.assertion]
        assert len(div_ghosts) > 0
        assert div_ghosts[0].matches_code is False

    def test_guarded_division(self, analyzer, guarded_python):
        ghosts = analyzer.analyze_file(guarded_python)
        div_ghosts = [g for g in ghosts if "!= 0" in g.assertion]
        if div_ghosts:
            assert div_ghosts[0].matches_code is True


class TestBoundsDetection:
    def test_unguarded_index(self, analyzer, unguarded_python):
        ghosts = analyzer.analyze_file(unguarded_python)
        bounds_ghosts = [g for g in ghosts if "bounds" in g.category]
        assert len(bounds_ghosts) > 0


class TestResourceDetection:
    def test_unguarded_file(self, analyzer, unguarded_python):
        ghosts = analyzer.analyze_file(unguarded_python)
        resource_ghosts = [g for g in ghosts if g.category == "resource"]
        assert len(resource_ghosts) > 0
        assert "file" in resource_ghosts[0].assertion.lower() or "close" in resource_ghosts[0].assertion.lower()


class TestFinancialDetection:
    def test_amount_param(self, analyzer, unguarded_python):
        ghosts = analyzer.analyze_file(unguarded_python)
        amount_ghosts = [g for g in ghosts if "amount" in g.assertion]
        assert len(amount_ghosts) > 0


class TestConfidence:
    def test_confidence_range(self, analyzer, unguarded_python):
        ghosts = analyzer.analyze_file(unguarded_python)
        for g in ghosts:
            assert 0.0 <= g.confidence <= 1.0


class TestToDict:
    def test_serializable(self, analyzer, unguarded_python):
        ghosts = analyzer.analyze_file(unguarded_python)
        if ghosts:
            d = ghosts[0].to_dict()
            assert "function" in d
            assert "assertion" in d
            assert "confidence" in d
