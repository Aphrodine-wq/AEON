"""AEON AI Model Tests — AI-001 through AI-006.

These tests validate the AI model's ability to generate, understand,
and refactor AEON code. Stubs for model-dependent tests.
"""

import json
import pytest

from aeon.parser import parse
from aeon.pass1_prove import prove
from aeon.pass2_flatten import flatten


class TestAI001:
    """AI-001: Model generates syntactically valid AEON for 100 prompts.
    Pass Criteria: 100% pass compiler Pass 1.
    Priority: P0
    """

    def test_known_valid_programs_parse(self):
        """priority_p0: Known valid AEON programs should parse."""
        programs = [
            "pure id(x: Int) -> Int { return x }",
            "pure add(a: Int, b: Int) -> Int { return a + b }",
            "pure neg(x: Int) -> Int { return 0 - x }",
            "data Point { x: Int  y: Int }",
            "pure zero() -> Int { return 0 }",
            "pure one() -> Int { return 1 }",
            "pure isPositive(x: Int) -> Bool { return x > 0 }",
            "pure isZero(x: Int) -> Bool { return x == 0 }",
            "pure double(x: Int) -> Int { return x + x }",
            "pure triple(x: Int) -> Int { return x * 3 }",
        ]
        for src in programs:
            program = parse(src)
            errors = prove(program)
            assert errors == [], f"Failed on: {src} -> {[e.to_dict() for e in errors]}"


class TestAI002:
    """AI-002: Model generates semantically correct code for typed signatures.
    Pass Criteria: 90%+ pass all 3 compiler passes.
    Priority: P1
    """

    def test_typed_programs_pass_all_passes(self):
        """priority_p1: Typed programs pass all 3 passes."""
        programs = [
            """
pure add(a: Int, b: Int) -> Int {
  return a + b
}
""",
            """
pure max(a: Int, b: Int) -> Int {
  if a >= b {
    return a
  } else {
    return b
  }
}
""",
            """
pure abs(x: Int) -> Int {
  if x >= 0 {
    return x
  } else {
    return 0 - x
  }
}
""",
        ]

        passed = 0
        for src in programs:
            program = parse(src)
            errors = prove(program)
            if not errors:
                ir_module = flatten(program)
                if ir_module.functions:
                    passed += 1

        assert passed / len(programs) >= 0.9


class TestAI003:
    """AI-003: Model refactors function while satisfying same contract.
    Pass Criteria: Refactored version passes same contract tests.
    Priority: P1
    """

    def test_refactored_add_still_passes(self):
        """priority_p1: Refactored add function should still type-check."""
        original = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  return a + b
}
"""
        refactored = """
pure add(a: Int, b: Int) -> Int {
  ensures: result == a + b
  let sum: Int = a + b
  return sum
}
"""
        for src in [original, refactored]:
            program = parse(src)
            errors = prove(program)
            assert errors == [], f"Failed: {[e.to_dict() for e in errors]}"


class TestAI004:
    """AI-004: Model reads a contract and describes behavior accurately.
    Pass Criteria: Human eval: 90%+ accuracy on 50 samples.
    Priority: P1
    """

    def test_contract_extraction(self):
        """priority_p1: Contracts are extractable from IR for AI reading."""
        source = """
pure safeDivide(a: Int, b: Int) -> Int {
  requires: b != 0
  ensures: result == a / b
  return a / b
}
"""
        program = parse(source)
        ir_module = flatten(program)
        func_ir = ir_module.functions[0]

        ir_dict = func_ir.to_dict()
        assert "contracts" in ir_dict
        assert "requires" in ir_dict["contracts"]
        assert "ensures" in ir_dict["contracts"]

        # Contracts should be machine-readable
        json_str = json.dumps(ir_dict)
        parsed = json.loads(json_str)
        assert parsed["contracts"]["requires"][0].startswith("requires:")


class TestAI005:
    """AI-005: Model improves after 1 round of compiler-feedback RL.
    Pass Criteria: Pass rate increases vs baseline on held-out set.
    Priority: P2
    """

    def test_rl_feedback_loop_structure(self):
        """priority_p2: Validate that compiler feedback can be structured for RL."""
        source_bad = "pure bad() -> Int { return \"hello\" }"
        source_good = "pure good() -> Int { return 42 }"

        program_bad = parse(source_bad)
        errors_bad = prove(program_bad)

        program_good = parse(source_good)
        errors_good = prove(program_good)

        # RL signal: bad code produces errors (negative reward), good code passes (positive reward)
        assert len(errors_bad) > 0, "Bad code should produce errors for negative RL signal"
        assert len(errors_good) == 0, "Good code should pass for positive RL signal"

        # Feedback is structured as JSON for model consumption
        feedback = [e.to_dict() for e in errors_bad]
        assert all("kind" in f for f in feedback), "Feedback must be structured with kind field"


class TestAI006:
    """AI-006: End-to-end: prompt -> AEON code -> binary -> correct output.
    Pass Criteria: 50 diverse prompts, 80%+ produce correct binaries.
    Priority: P2
    """

    def test_end_to_end_pipeline_exists(self):
        """priority_p2: Validate e2e pipeline components exist and connect."""
        # Validate that the full pipeline (parse -> prove -> flatten) works end-to-end
        source = """
pure factorial(n: Int) -> Int {
  if n <= 1 {
    return 1
  } else {
    return n * factorial(n - 1)
  }
}
"""
        program = parse(source)
        assert program is not None, "Parse stage must succeed"

        errors = prove(program)
        assert errors == [], f"Prove stage should pass: {[e.to_dict() for e in errors]}"

        ir_module = flatten(program)
        assert ir_module is not None, "Flatten stage must succeed"
        assert len(ir_module.functions) == 1, "Should produce 1 function in IR"

        # Validate IR is serializable (required for binary emission)
        json_str = ir_module.to_json()
        import json
        parsed_ir = json.loads(json_str)
        assert "functions" in parsed_ir, "IR JSON must contain functions"
