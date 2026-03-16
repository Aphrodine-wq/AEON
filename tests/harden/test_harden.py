"""Tests for AEON hardening engine."""
import os
import tempfile
import pytest
from aeon.harden import CodeHardener, HardenPlan


@pytest.fixture
def hardener():
    return CodeHardener()


@pytest.fixture
def risky_python(tmp_path):
    f = tmp_path / "risky.py"
    f.write_text(
        "import os\n"
        "import subprocess\n\n"
        "def run_command(cmd):\n"
        "    os.system(cmd)\n\n"
        "def process_payment(amount, card):\n"
        "    charge(card, amount)\n\n"
        "def login(username, password):\n"
        "    token = authenticate(username, password)\n"
        "    return token\n\n"
        "def safe_function(x):\n"
        "    return x + 1\n"
    )
    return str(f)


class TestRiskScoring:
    def test_high_risk_detected(self, hardener, risky_python):
        plan = hardener.analyze(risky_python)
        assert plan.total_functions > 0
        critical = plan.phases.get("critical", [])
        assert len(critical) > 0

    def test_risk_factors_populated(self, hardener, risky_python):
        plan = hardener.analyze(risky_python)
        for t in plan.targets:
            if t.risk_score > 0.5:
                assert len(t.risk_factors) > 0

    def test_os_system_is_critical(self, hardener, risky_python):
        plan = hardener.analyze(risky_python)
        names = [t.name for t in plan.phases.get("critical", [])]
        assert "run_command" in names


class TestContractInference:
    def test_financial_contracts(self, hardener, risky_python):
        plan = hardener.analyze(risky_python)
        payment_targets = [t for t in plan.targets if t.name == "process_payment"]
        if payment_targets:
            contracts = payment_targets[0].suggested_contracts
            assert any("amount" in c or "balance" in c for c in contracts)

    def test_auth_contracts(self, hardener, risky_python):
        plan = hardener.analyze(risky_python)
        auth_targets = [t for t in plan.targets if t.name == "login"]
        if auth_targets:
            assert auth_targets[0].risk_score > 0


class TestPlanGeneration:
    def test_phases_exist(self, hardener, risky_python):
        plan = hardener.analyze(risky_python)
        assert "critical" in plan.phases
        assert "high" in plan.phases
        assert "medium" in plan.phases
        assert "low" in plan.phases

    def test_coverage_increases(self, hardener, risky_python):
        plan = hardener.analyze(risky_python)
        if plan.total_functions > 0:
            coverages = list(plan.coverage_by_phase.values())
            for i in range(1, len(coverages)):
                assert coverages[i] >= coverages[i-1]


class TestReport:
    def test_markdown_report(self, hardener, risky_python):
        plan = hardener.analyze(risky_python)
        report = hardener.generate_report(plan)
        assert "# AEON Hardening Report" in report
        assert "Total Functions" in report


class TestHardenFunction:
    def test_harden_specific(self, hardener, risky_python):
        result = hardener.harden_function(risky_python, "run_command")
        assert result.target.name == "run_command"
