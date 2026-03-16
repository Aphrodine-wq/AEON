"""Tests for AEON bug graveyard."""
import pytest
from aeon.graveyard import BugGraveyard


@pytest.fixture
def graveyard():
    return BugGraveyard()


class TestBugAnalysis:
    def test_heartbleed(self, graveyard):
        result = graveyard.analyze_bug("heartbleed")
        assert result.aeon_catches is True
        assert "500M" in result.impact
        assert result.year == 2014

    def test_log4shell(self, graveyard):
        result = graveyard.analyze_bug("log4shell")
        assert result.aeon_catches is True
        assert result.year == 2021

    def test_goto_fail(self, graveyard):
        result = graveyard.analyze_bug("goto_fail")
        assert result.aeon_catches is True

    def test_therac25(self, graveyard):
        result = graveyard.analyze_bug("therac25")
        assert result.aeon_catches is True
        assert "concurrency" in result.aeon_engine

    def test_ariane5(self, graveyard):
        result = graveyard.analyze_bug("ariane5")
        assert result.aeon_catches is True
        assert "numeric" in result.aeon_engine or "bounds" in result.aeon_engine

    def test_knight_capital(self, graveyard):
        result = graveyard.analyze_bug("knight_capital")
        assert result.aeon_catches is True

    def test_crowdstrike(self, graveyard):
        result = graveyard.analyze_bug("crowdstrike")
        assert result.aeon_catches is True
        assert "null" in result.aeon_engine.lower()

    def test_unknown_bug(self, graveyard):
        result = graveyard.analyze_bug("nonexistent_bug")
        assert result.aeon_catches is False


class TestAnalyzeAll:
    def test_all_bugs_caught(self, graveyard):
        results = graveyard.analyze_all()
        assert len(results) >= 8
        for r in results:
            assert r.aeon_catches is True

    def test_detection_time(self, graveyard):
        results = graveyard.analyze_all()
        total_ms = sum(r.detection_time_ms for r in results)
        assert total_ms < 5000  # All bugs in under 5 seconds


class TestFormatting:
    def test_pretty_format(self, graveyard):
        results = graveyard.analyze_all()
        output = graveyard.format_all(results, "pretty")
        assert "AEON GRAVEYARD" in output
        assert "pip install aeon-lang" in output

    def test_markdown_format(self, graveyard):
        results = graveyard.analyze_all()
        output = graveyard.format_all(results, "markdown")
        assert "# The AEON Graveyard" in output

    def test_single_bug_format(self, graveyard):
        result = graveyard.analyze_bug("heartbleed")
        output = graveyard.format_result(result, "pretty")
        assert "Heartbleed" in output
        assert "memcpy" in output
