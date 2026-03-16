"""Tests for AEON code synthesizer."""
import pytest
from aeon.synthesizer import CodeSynthesizer, FunctionSpec, SynthesisResult, format_synthesis_result


class TestTemplateSynthesis:
    def test_safe_divide(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_spec("safely divide two numbers")
        assert result.proof_status == "proven"
        assert result.confidence == 1.0
        assert "safe_divide" in result.function_name

    def test_factorial(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_spec("compute factorial")
        assert result.proof_status == "proven"

    def test_binary_search(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_spec("binary search in sorted array")
        assert result.proof_status == "proven"

    def test_fibonacci(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_spec("fibonacci number")
        assert result.proof_status == "proven"

    def test_palindrome(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_spec("check if palindrome")
        assert result.proof_status == "proven"

    def test_gcd(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_spec("greatest common divisor")
        assert result.proof_status == "proven"

    def test_stack(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_spec("stack data structure")
        assert result.proof_status == "proven"
        assert "push" in result.source_code

    def test_unknown_spec(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_spec("quantum entanglement simulator")
        assert result.proof_status == "unverified"
        assert result.confidence == 0.0


class TestMultiLanguage:
    def test_python_default(self):
        synth = CodeSynthesizer(target_language="python")
        result = synth.synthesize_from_spec("safe divide")
        assert result.language == "python"

    def test_javascript(self):
        synth = CodeSynthesizer(target_language="javascript")
        result = synth.synthesize_from_spec("safe divide")
        assert result.language == "javascript"

    def test_rust(self):
        synth = CodeSynthesizer(target_language="rust")
        result = synth.synthesize_from_spec("safe divide")
        assert result.language == "rust"

    def test_go(self):
        synth = CodeSynthesizer(target_language="go")
        result = synth.synthesize_from_spec("safe divide")
        assert result.language == "go"


class TestAeonParsing:
    def test_parse_pure_fn(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_aeon(
            "pure fn safe_divide(a: i32, b: i32) -> i32\n"
            "  requires b != 0\n"
            "  ensures result * b <= a\n"
        )
        assert result.function_name != "unknown"

    def test_parse_invalid(self):
        synth = CodeSynthesizer()
        result = synth.synthesize_from_aeon("not valid aeon code")
        assert result.proof_status == "unverified"


class TestFormatting:
    def test_proven_format(self):
        result = SynthesisResult(
            source_code="def foo(): pass", language="python",
            function_name="foo", proof_status="proven",
            confidence=1.0, contracts_satisfied=["x > 0"],
        )
        output = format_synthesis_result(result)
        assert "[PROVEN]" in output

    def test_verbose_alternatives(self):
        result = SynthesisResult(
            source_code="def foo(): pass", language="python",
            function_name="foo", proof_status="proven",
            confidence=1.0, alternatives=["function foo() {}"],
        )
        output = format_synthesis_result(result, verbose=True)
        assert "Alternative" in output


class TestTemplateList:
    def test_has_templates(self):
        synth = CodeSynthesizer()
        templates = synth.list_templates()
        assert len(templates) >= 10
        names = [t["name"] for t in templates]
        assert "safe_divide" in names
        assert "binary_search" in names
