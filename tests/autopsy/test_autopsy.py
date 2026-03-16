"""Tests for AEON incident autopsy."""
import pytest
from aeon.autopsy import IncidentAutopsy


@pytest.fixture
def autopsy():
    return IncidentAutopsy()


PYTHON_TRACEBACK = """
Traceback (most recent call last):
  File "app.py", line 42, in process_order
    total = subtotal / discount_rate
ZeroDivisionError: division by zero
"""

JAVA_STACKTRACE = """
Exception in thread "main" java.lang.NullPointerException: Cannot invoke method on null
    at com.example.Service.processRequest(Service.java:87)
    at com.example.Controller.handle(Controller.java:23)
"""

JS_ERROR = """
TypeError: Cannot read properties of undefined (reading 'name')
    at processUser (/app/src/users.js:45:12)
    at handleRequest (/app/src/server.js:120:8)
"""

GO_PANIC = """
goroutine 1 [running]:
runtime error: index out of range [5] with length 3
main.processData(main.go:42)
main.main(main.go:15)
"""

RUST_PANIC = """
thread 'main' panicked at 'called `Option::unwrap()` on a `None` value', src/parser.rs:156:24
"""


class TestPythonParsing:
    def test_parse_traceback(self, autopsy):
        incident = autopsy.parse_stacktrace(PYTHON_TRACEBACK)
        assert incident.error_type == "ZeroDivisionError"
        assert incident.language == "python"
        assert len(incident.stack_trace) >= 1

    def test_stack_frame_details(self, autopsy):
        incident = autopsy.parse_stacktrace(PYTHON_TRACEBACK)
        frame = incident.stack_trace[0]
        assert frame.file == "app.py"
        assert frame.function == "process_order"
        assert frame.line == 42


class TestJavaParsing:
    def test_parse_stacktrace(self, autopsy):
        incident = autopsy.parse_stacktrace(JAVA_STACKTRACE)
        assert incident.error_type == "NullPointerException"
        assert incident.language == "java"
        assert len(incident.stack_trace) >= 1


class TestJavaScriptParsing:
    def test_parse_error(self, autopsy):
        incident = autopsy.parse_stacktrace(JS_ERROR)
        assert incident.error_type == "TypeError"
        assert incident.language == "javascript"


class TestGoParsing:
    def test_parse_panic(self, autopsy):
        incident = autopsy.parse_stacktrace(GO_PANIC)
        assert "index out of range" in incident.error_message
        assert incident.language == "go"


class TestRustParsing:
    def test_parse_panic(self, autopsy):
        incident = autopsy.parse_stacktrace(RUST_PANIC)
        assert "unwrap" in incident.error_message.lower() or "None" in incident.error_message
        assert incident.language == "rust"


class TestContractGeneration:
    def test_division_contract(self, autopsy):
        incident = autopsy.parse_stacktrace(PYTHON_TRACEBACK)
        result = autopsy.analyze(incident)
        contracts = [gc.contract for gc in result.generated_contracts]
        assert any("!= 0" in c or "divisor" in c for c in contracts)

    def test_null_contract(self, autopsy):
        incident = autopsy.parse_stacktrace(JAVA_STACKTRACE)
        result = autopsy.analyze(incident)
        contracts = [gc.contract for gc in result.generated_contracts]
        assert any("null" in c.lower() or "None" in c for c in contracts)


class TestSeverity:
    def test_critical_severity(self, autopsy):
        incident = autopsy.parse_stacktrace(JAVA_STACKTRACE)
        result = autopsy.analyze(incident)
        assert result.severity == "critical"

    def test_high_severity(self, autopsy):
        incident = autopsy.parse_stacktrace(PYTHON_TRACEBACK)
        result = autopsy.analyze(incident)
        assert result.severity == "high"


class TestReportGeneration:
    def test_markdown_report(self, autopsy):
        incident = autopsy.parse_stacktrace(PYTHON_TRACEBACK)
        result = autopsy.analyze(incident)
        report = autopsy.format_report(result)
        assert "# AEON Incident Autopsy" in report
        assert "ZeroDivisionError" in report

    def test_regression_test_generated(self, autopsy):
        incident = autopsy.parse_stacktrace(PYTHON_TRACEBACK)
        result = autopsy.analyze(incident)
        assert len(result.generated_tests) > 0
        test_code = result.generated_tests[0].test_code
        assert "test_" in result.generated_tests[0].test_name


class TestLogParsing:
    def test_multi_error_log(self, autopsy):
        log = (
            "2024-01-15T10:30:00Z ERROR app crashed\n"
            + PYTHON_TRACEBACK
        )
        incidents = autopsy.parse_log(log)
        assert len(incidents) >= 1
