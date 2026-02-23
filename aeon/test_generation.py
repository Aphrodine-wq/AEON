"""AEON Automated Test Generation.

Generates comprehensive test cases from verification gaps and formal contracts.
Creates edge case tests that exercise the boundaries identified by formal analysis.

Usage:
    from aeon.test_generation import TestGenerator
    generator = TestGenerator()
    tests = generator.generate_tests("function.py", verification_result)
"""

from __future__ import annotations

import ast
import json
import re
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class TestType(Enum):
    """Types of tests that can be generated."""
    BOUNDARY = "boundary"
    EDGE_CASE = "edge_case"
    ERROR_CASE = "error_case"
    CONTRACT = "contract"
    PROPERTY = "property"
    PERFORMANCE = "performance"
    SECURITY = "security"


@dataclass
class GeneratedTest:
    """A generated test case."""
    name: str
    test_type: TestType
    description: str
    setup_code: str
    test_code: str
    expected_result: str
    assertions: List[str]
    tags: List[str]
    confidence: float
    rationale: str


class TestGenerator:
    """Generates test cases from verification results and contracts."""
    
    def __init__(self, model: str = "gpt-3.5-turbo", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key
        
        if OPENAI_AVAILABLE and api_key:
            openai.api_key = api_key
            self.use_ai = True
        else:
            self.use_ai = False
    
    def generate_tests(self, file_path: str, verification_result: Dict[str, Any]) -> List[GeneratedTest]:
        """Generate comprehensive tests from verification results."""
        tests = []
        
        # Generate tests based on verification errors
        error_tests = self._generate_error_tests(file_path, verification_result)
        tests.extend(error_tests)
        
        # Generate tests based on contracts
        contract_tests = self._generate_contract_tests(file_path, verification_result)
        tests.extend(contract_tests)
        
        # Generate boundary tests
        boundary_tests = self._generate_boundary_tests(file_path, verification_result)
        tests.extend(boundary_tests)
        
        # Generate security tests
        security_tests = self._generate_security_tests(file_path, verification_result)
        tests.extend(security_tests)
        
        # If AI is available, generate additional tests
        if self.use_ai:
            ai_tests = self._generate_with_ai(file_path, verification_result)
            tests.extend(ai_tests)
        
        # Remove duplicates and sort by confidence
        tests = self._deduplicate_tests(tests)
        tests.sort(key=lambda t: t.confidence, reverse=True)
        
        return tests
    
    def _generate_error_tests(self, file_path: str, verification_result: Dict[str, Any]) -> List[GeneratedTest]:
        """Generate tests that trigger verification errors."""
        tests = []
        
        for error in verification_result.get('errors', []):
            test = self._create_test_from_error(error, file_path)
            if test:
                tests.append(test)
        
        return tests
    
    def _create_test_from_error(self, error: Dict[str, Any], file_path: str) -> Optional[GeneratedTest]:
        """Create a test case from a verification error."""
        error_type = error.get('type', 'unknown')
        message = error.get('message', '')
        line = error.get('line', 0)
        
        if 'division by zero' in message.lower():
            return self._create_division_by_zero_test(error, file_path)
        elif 'null' in message.lower() or 'none' in message.lower():
            return self._create_null_pointer_test(error, file_path)
        elif 'overflow' in message.lower() or 'underflow' in message.lower():
            return self._create_overflow_test(error, file_path)
        elif 'bounds' in message.lower() or 'range' in message.lower():
            return self._create_bounds_test(error, file_path)
        elif 'assertion' in message.lower():
            return self._create_assertion_test(error, file_path)
        elif 'race condition' in message.lower() or 'concurrency' in message.lower():
            return self._create_concurrency_test(error, file_path)
        elif 'taint' in message.lower() or 'injection' in message.lower():
            return self._create_security_test(error, file_path)
        
        return None
    
    def _create_division_by_zero_test(self, error: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for division by zero."""
        return GeneratedTest(
            name="test_division_by_zero",
            test_type=TestType.ERROR_CASE,
            description="Test division by zero error case",
            setup_code="",
            test_code=self._generate_division_test_code(error),
            expected_result="ZeroDivisionError or equivalent",
            assertions=["with pytest.raises(ZeroDivisionError):"],
            tags=["error", "division", "edge_case"],
            confidence=0.95,
            rationale="Division by zero detected in verification"
        )
    
    def _create_null_pointer_test(self, error: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for null pointer dereference."""
        return GeneratedTest(
            name="test_null_pointer",
            test_type=TestType.ERROR_CASE,
            description="Test null pointer/None dereference",
            setup_code="",
            test_code=self._generate_null_test_code(error),
            expected_result="TypeError or AttributeError",
            assertions=["with pytest.raises((TypeError, AttributeError)):"],
            tags=["error", "null", "edge_case"],
            confidence=0.9,
            rationale="Null pointer dereference detected in verification"
        )
    
    def _create_overflow_test(self, error: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for overflow/underflow."""
        return GeneratedTest(
            name="test_overflow_underflow",
            test_type=TestType.BOUNDARY,
            description="Test numeric overflow/underflow conditions",
            setup_code="import sys",
            test_code=self._generate_overflow_test_code(error),
            expected_result="OverflowError or correct wrapping behavior",
            assertions=["# Check for overflow behavior"],
            tags=["boundary", "overflow", "edge_case"],
            confidence=0.85,
            rationale="Overflow/underflow detected in verification"
        )
    
    def _create_bounds_test(self, error: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for bounds checking."""
        return GeneratedTest(
            name="test_bounds_checking",
            test_type=TestType.BOUNDARY,
            description="Test array/string bounds checking",
            setup_code="",
            test_code=self._generate_bounds_test_code(error),
            expected_result="IndexError or correct bounds handling",
            assertions=["# Verify bounds are respected"],
            tags=["boundary", "bounds", "edge_case"],
            confidence=0.9,
            rationale="Bounds violation detected in verification"
        )
    
    def _create_assertion_test(self, error: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for assertion failures."""
        return GeneratedTest(
            name="test_assertion_failure",
            test_type=TestType.ERROR_CASE,
            description="Test assertion failure conditions",
            setup_code="",
            test_code=self._generate_assertion_test_code(error),
            expected_result="AssertionError",
            assertions=["with pytest.raises(AssertionError):"],
            tags=["error", "assertion", "contract"],
            confidence=0.95,
            rationale="Assertion failure detected in verification"
        )
    
    def _create_concurrency_test(self, error: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for race conditions."""
        return GeneratedTest(
            name="test_race_condition",
            test_type=TestType.SECURITY,
            description="Test concurrent access for race conditions",
            setup_code="import threading\nimport time",
            test_code=self._generate_concurrency_test_code(error),
            expected_result="No race conditions or data corruption",
            assertions=["# Verify no data races occurred"],
            tags=["concurrency", "race_condition", "security"],
            confidence=0.8,
            rationale="Race condition detected in verification"
        )
    
    def _create_security_test(self, error: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for security vulnerabilities."""
        return GeneratedTest(
            name="test_security_vulnerability",
            test_type=TestType.SECURITY,
            description="Test security vulnerability exploitation",
            setup_code="",
            test_code=self._generate_security_test_code(error),
            expected_result="Proper input validation and sanitization",
            assertions=["# Verify security measures work"],
            tags=["security", "vulnerability", "taint"],
            confidence=0.85,
            rationale="Security vulnerability detected in verification"
        )
    
    def _generate_division_test_code(self, error: Dict[str, Any]) -> str:
        """Generate test code for division by zero."""
        # This is a simplified version - in practice would parse the actual function
        function_name = error.get('function', 'divide_function')
        
        return f"""
def test_division_by_zero():
    # Test case that triggers division by zero
    result = {function_name}(10, 0)  # Division by zero
    # This should raise an exception or be handled properly
"""
    
    def _generate_null_test_code(self, error: Dict[str, Any]) -> str:
        """Generate test code for null pointer dereference."""
        function_name = error.get('function', 'process_function')
        
        return f"""
def test_null_pointer():
    # Test case with None/null input
    result = {function_name}(None)  # Should handle None properly
    # Verify None is handled correctly
"""
    
    def _generate_overflow_test_code(self, error: Dict[str, Any]) -> str:
        """Generate test code for overflow/underflow."""
        function_name = error.get('function', 'calculate_function')
        
        return f"""
def test_overflow_underflow():
    # Test with maximum integer values
    max_int = sys.maxsize
    min_int = -sys.maxsize - 1
    
    result1 = {function_name}(max_int, 1)  # Potential overflow
    result2 = {function_name}(min_int, -1)  # Potential underflow
    
    # Verify behavior with extreme values
"""
    
    def _generate_bounds_test_code(self, error: Dict[str, Any]) -> str:
        """Generate test code for bounds checking."""
        function_name = error.get('function', 'access_function')
        
        return f"""
def test_bounds_checking():
    # Test with out-of-bounds access
    data = [1, 2, 3]
    
    # Test negative index
    result1 = {function_name}(data, -1)
    
    # Test index beyond array length
    result2 = {function_name}(data, 10)
    
    # Verify bounds are respected
"""
    
    def _generate_assertion_test_code(self, error: Dict[str, Any]) -> str:
        """Generate test code for assertion failures."""
        function_name = error.get('function', 'validate_function')
        
        return f"""
def test_assertion_failure():
    # Test case that violates assertions
    invalid_input = -1  # Assuming positive values expected
    
    with pytest.raises(AssertionError):
        {function_name}(invalid_input)
"""
    
    def _generate_concurrency_test_code(self, error: Dict[str, Any]) -> str:
        """Generate test code for race conditions."""
        function_name = error.get('function', 'shared_resource_function')
        
        return f"""
def test_race_condition():
    # Test concurrent access
    shared_data = {{}}
    errors = []
    
    def worker():
        try:
            {function_name}(shared_data)
        except Exception as e:
            errors.append(e)
    
    threads = []
    for i in range(10):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # Verify no race conditions occurred
    assert len(errors) == 0, f"Errors occurred: {{errors}}"
"""
    
    def _generate_security_test_code(self, error: Dict[str, Any]) -> str:
        """Generate test code for security vulnerabilities."""
        function_name = error.get('function', 'process_input_function')
        
        return f"""
def test_security_vulnerability():
    # Test with malicious inputs
    malicious_inputs = [
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "{{7*7}}",  # Template injection
        "{{{{config}}}}"  # Jinja injection
    ]
    
    for malicious_input in malicious_inputs:
        result = {function_name}(malicious_input)
        # Verify input is properly sanitized
        assert "DROP TABLE" not in str(result)
        assert "<script>" not in str(result)
"""
    
    def _generate_contract_tests(self, file_path: str, verification_result: Dict[str, Any]) -> List[GeneratedTest]:
        """Generate tests from formal contracts."""
        tests = []
        
        contracts = verification_result.get('contracts', [])
        for contract in contracts:
            test = self._create_test_from_contract(contract, file_path)
            if test:
                tests.append(test)
        
        return tests
    
    def _create_test_from_contract(self, contract: Dict[str, Any], file_path: str) -> Optional[GeneratedTest]:
        """Create a test from a formal contract."""
        contract_type = contract.get('type', 'precondition')
        specification = contract.get('specification', '')
        
        if contract_type == 'precondition':
            return self._create_precondition_test(contract, file_path)
        elif contract_type == 'postcondition':
            return self._create_postcondition_test(contract, file_path)
        elif contract_type == 'invariant':
            return self._create_invariant_test(contract, file_path)
        
        return None
    
    def _create_precondition_test(self, contract: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for precondition violations."""
        function_name = contract.get('function', 'target_function')
        specification = contract.get('specification', '')
        
        return GeneratedTest(
            name="test_precondition_violation",
            test_type=TestType.CONTRACT,
            description=f"Test precondition violation: {specification}",
            setup_code="",
            test_code=f"""
def test_precondition_violation():
    # Test precondition: {specification}
    
    # Generate inputs that violate the precondition
    invalid_inputs = [
        # This would be customized based on the specific precondition
        None,  # Violates non-null requirement
        -1,    # Violates positive requirement
        0,     # Violates non-zero requirement
    ]
    
    for invalid_input in invalid_inputs:
        with pytest.raises((ValueError, AssertionError, TypeError)):
            {function_name}(invalid_input)
""",
            expected_result="Exception raised for precondition violation",
            assertions=["with pytest.raises((ValueError, AssertionError, TypeError)):"],
            tags=["contract", "precondition", "error_case"],
            confidence=0.9,
            rationale=f"Test precondition: {specification}"
        )
    
    def _create_postcondition_test(self, contract: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for postcondition verification."""
        function_name = contract.get('function', 'target_function')
        specification = contract.get('specification', '')
        
        return GeneratedTest(
            name="test_postcondition_verification",
            test_type=TestType.CONTRACT,
            description=f"Test postcondition: {specification}",
            setup_code="",
            test_code=f"""
def test_postcondition_verification():
    # Test postcondition: {specification}
    
    # Generate valid inputs
    valid_inputs = [
        # This would be customized based on the function
        1, 5, 10, 100
    ]
    
    for valid_input in valid_inputs:
        result = {function_name}(valid_input)
        
        # Verify postcondition holds
        # This would be customized based on the specific postcondition
        assert result is not None  # Example: non-null result
        assert isinstance(result, (int, float))  # Example: numeric result
""",
            expected_result="Postcondition holds for all valid inputs",
            assertions=["assert result is not None"],
            tags=["contract", "postcondition", "property"],
            confidence=0.85,
            rationale=f"Test postcondition: {specification}"
        )
    
    def _create_invariant_test(self, contract: Dict[str, Any], file_path: str) -> GeneratedTest:
        """Create a test for invariant preservation."""
        function_name = contract.get('function', 'target_function')
        specification = contract.get('specification', '')
        
        return GeneratedTest(
            name="test_invariant_preservation",
            test_type=TestType.CONTRACT,
            description=f"Test invariant preservation: {specification}",
            setup_code="",
            test_code=f"""
def test_invariant_preservation():
    # Test invariant: {specification}
    
    # Initialize object/state
    obj = SomeClass()  # This would be customized
    
    # Store initial state
    initial_state = obj.get_state()
    
    # Apply operations
    {function_name}(obj)
    
    # Verify invariant still holds
    final_state = obj.get_state()
    
    # Check invariant-specific properties
    # This would be customized based on the specific invariant
    assert final_state['property'] == initial_state['property']
""",
            expected_result="Invariant preserved after operations",
            assertions=["assert final_state['property'] == initial_state['property']"],
            tags=["contract", "invariant", "property"],
            confidence=0.8,
            rationale=f"Test invariant: {specification}"
        )
    
    def _generate_boundary_tests(self, file_path: str, verification_result: Dict[str, Any]) -> List[GeneratedTest]:
        """Generate boundary value tests."""
        tests = []
        
        # Analyze function signatures and types
        functions = verification_result.get('functions_analyzed', [])
        
        for function in functions:
            boundary_tests = self._create_boundary_tests_for_function(function, file_path)
            tests.extend(boundary_tests)
        
        return tests
    
    def _create_boundary_tests_for_function(self, function: Dict[str, Any], file_path: str) -> List[GeneratedTest]:
        """Create boundary tests for a specific function."""
        tests = []
        function_name = function.get('name', 'unknown_function')
        parameters = function.get('parameters', [])
        
        for param in parameters:
            param_name = param.get('name', 'param')
            param_type = param.get('type', 'unknown')
            
            if param_type in ['int', 'integer']:
                tests.extend(self._create_integer_boundary_tests(function_name, param_name))
            elif param_type in ['float', 'double']:
                tests.extend(self._create_float_boundary_tests(function_name, param_name))
            elif param_type in ['str', 'string']:
                tests.extend(self._create_string_boundary_tests(function_name, param_name))
            elif param_type in ['list', 'array']:
                tests.extend(self._create_list_boundary_tests(function_name, param_name))
        
        return tests
    
    def _create_integer_boundary_tests(self, function_name: str, param_name: str) -> List[GeneratedTest]:
        """Create boundary tests for integer parameters."""
        tests = []
        
        # Test common integer boundaries
        boundaries = [
            (-2**31, "INT32_MIN"),
            (-2**31 + 1, "INT32_MIN + 1"),
            (-1, "NEGATIVE_ONE"),
            (0, "ZERO"),
            (1, "POSITIVE_ONE"),
            (2**31 - 1, "INT32_MAX"),
            (2**31, "INT32_MAX + 1"),
        ]
        
        for value, description in boundaries:
            tests.append(GeneratedTest(
                name=f"test_{function_name}_{param_name}_{description.lower()}",
                test_type=TestType.BOUNDARY,
                description=f"Test {function_name} with {param_name} = {value} ({description})",
                setup_code="",
                test_code=f"""
def test_{function_name}_{param_name}_{description.lower()}():
    result = {function_name}({value})
    # Verify behavior with boundary value: {description}
""",
                expected_result="Proper handling of boundary value",
                assertions=[f"# Verify result for {param_name} = {value}"],
                tags=["boundary", "integer", param_name],
                confidence=0.8,
                rationale=f"Test integer boundary: {description}"
            ))
        
        return tests
    
    def _create_float_boundary_tests(self, function_name: str, param_name: str) -> List[GeneratedTest]:
        """Create boundary tests for float parameters."""
        tests = []
        
        # Test common float boundaries
        boundaries = [
            (float('-inf'), "NEGATIVE_INFINITY"),
            (-1.7976931348623157e+308, "FLOAT_MIN"),
            (-1.0, "NEGATIVE_ONE"),
            (0.0, "ZERO"),
            (1.0, "POSITIVE_ONE"),
            (1.7976931348623157e+308, "FLOAT_MAX"),
            (float('inf'), "POSITIVE_INFINITY"),
            (float('nan'), "NAN"),
        ]
        
        for value, description in boundaries:
            tests.append(GeneratedTest(
                name=f"test_{function_name}_{param_name}_{description.lower()}",
                test_type=TestType.BOUNDARY,
                description=f"Test {function_name} with {param_name} = {value} ({description})",
                setup_code="import math",
                test_code=f"""
def test_{function_name}_{param_name}_{description.lower()}():
    result = {function_name}({value})
    # Verify behavior with boundary value: {description}
""",
                expected_result="Proper handling of boundary value",
                assertions=[f"# Verify result for {param_name} = {value}"],
                tags=["boundary", "float", param_name],
                confidence=0.8,
                rationale=f"Test float boundary: {description}"
            ))
        
        return tests
    
    def _create_string_boundary_tests(self, function_name: str, param_name: str) -> List[GeneratedTest]:
        """Create boundary tests for string parameters."""
        tests = []
        
        # Test common string boundaries
        boundaries = [
            ("", "EMPTY_STRING"),
            ("a", "SINGLE_CHAR"),
            ("a" * 1000, "LONG_STRING"),
            ("a" * 1000000, "VERY_LONG_STRING"),
            ("\\n\\r\\t", "SPECIAL_CHARS"),
            ("\\x00\\x01\\x02", "CONTROL_CHARS"),
            ("🚀🌟💫", "UNICODE_EMOJI"),
            ("'\"\\", "QUOTE_CHARS"),
        ]
        
        for value, description in boundaries:
            tests.append(GeneratedTest(
                name=f"test_{function_name}_{param_name}_{description.lower()}",
                test_type=TestType.BOUNDARY,
                description=f"Test {function_name} with {param_name} = '{value}' ({description})",
                setup_code="",
                test_code=f"""
def test_{function_name}_{param_name}_{description.lower()}():
    test_input = {repr(value)}
    result = {function_name}(test_input)
    # Verify behavior with boundary value: {description}
""",
                expected_result="Proper handling of boundary value",
                assertions=[f"# Verify result for {param_name} = {repr(value)}"],
                tags=["boundary", "string", param_name],
                confidence=0.8,
                rationale=f"Test string boundary: {description}"
            ))
        
        return tests
    
    def _create_list_boundary_tests(self, function_name: str, param_name: str) -> List[GeneratedTest]:
        """Create boundary tests for list parameters."""
        tests = []
        
        # Test common list boundaries
        boundaries = [
            ([], "EMPTY_LIST"),
            ([1], "SINGLE_ELEMENT"),
            (list(range(1000)), "LARGE_LIST"),
            ([None, None, None], "NONE_ELEMENTS"),
            ([1, 2, 3, 4, 5], "NORMAL_LIST"),
        ]
        
        for value, description in boundaries:
            tests.append(GeneratedTest(
                name=f"test_{function_name}_{param_name}_{description.lower()}",
                test_type=TestType.BOUNDARY,
                description=f"Test {function_name} with {param_name} = {value} ({description})",
                setup_code="",
                test_code=f"""
def test_{function_name}_{param_name}_{description.lower()}():
    test_input = {value}
    result = {function_name}(test_input)
    # Verify behavior with boundary value: {description}
""",
                expected_result="Proper handling of boundary value",
                assertions=[f"# Verify result for {param_name} = {value}"],
                tags=["boundary", "list", param_name],
                confidence=0.8,
                rationale=f"Test list boundary: {description}"
            ))
        
        return tests
    
    def _generate_security_tests(self, file_path: str, verification_result: Dict[str, Any]) -> List[GeneratedTest]:
        """Generate security-focused tests."""
        tests = []
        
        # Generate tests for common security vulnerabilities
        security_tests = [
            self._create_sql_injection_test(file_path),
            self._create_xss_test(file_path),
            self._create_path_traversal_test(file_path),
            self._create_command_injection_test(file_path),
            self._create_buffer_overflow_test(file_path),
        ]
        
        tests.extend([test for test in security_tests if test])
        
        return tests
    
    def _create_sql_injection_test(self, file_path: str) -> Optional[GeneratedTest]:
        """Create SQL injection test."""
        return GeneratedTest(
            name="test_sql_injection",
            test_type=TestType.SECURITY,
            description="Test SQL injection vulnerability",
            setup_code="",
            test_code="""
def test_sql_injection():
    # Test SQL injection payloads
    sql_payloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; INSERT INTO users VALUES ('hacker', 'password'); --",
        "' UNION SELECT * FROM sensitive_data --"
    ]
    
    for payload in sql_payloads:
        result = process_user_input(payload)  # Replace with actual function
        # Verify SQL injection is prevented
        assert "DROP TABLE" not in str(result)
        assert "UNION SELECT" not in str(result)
""",
            expected_result="SQL injection attempts blocked",
            assertions=["assert 'DROP TABLE' not in str(result)"],
            tags=["security", "sql_injection", "taint"],
            confidence=0.9,
            rationale="Test for SQL injection vulnerabilities"
        )
    
    def _create_xss_test(self, file_path: str) -> Optional[GeneratedTest]:
        """Create XSS test."""
        return GeneratedTest(
            name="test_xss_prevention",
            test_type=TestType.SECURITY,
            description="Test XSS vulnerability",
            setup_code="",
            test_code="""
def test_xss_prevention():
    # Test XSS payloads
    xss_payloads = [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "';alert('xss');//"
    ]
    
    for payload in xss_payloads:
        result = sanitize_html(payload)  # Replace with actual function
        # Verify XSS is prevented
        assert "<script>" not in str(result)
        assert "javascript:" not in str(result)
        assert "onerror=" not in str(result)
""",
            expected_result="XSS attempts blocked",
            assertions=["assert '<script>' not in str(result)"],
            tags=["security", "xss", "taint"],
            confidence=0.9,
            rationale="Test for XSS vulnerabilities"
        )
    
    def _create_path_traversal_test(self, file_path: str) -> Optional[GeneratedTest]:
        """Create path traversal test."""
        return GeneratedTest(
            name="test_path_traversal",
            test_type=TestType.SECURITY,
            description="Test path traversal vulnerability",
            setup_code="",
            test_code="""
def test_path_traversal():
    # Test path traversal payloads
    path_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]
    
    for payload in path_payloads:
        result = read_file(payload)  # Replace with actual function
        # Verify path traversal is prevented
        assert "root:x:0:0" not in str(result)  # Shouldn't read /etc/passwd
""",
            expected_result="Path traversal attempts blocked",
            assertions=["assert 'root:x:0:0' not in str(result)"],
            tags=["security", "path_traversal", "taint"],
            confidence=0.9,
            rationale="Test for path traversal vulnerabilities"
        )
    
    def _create_command_injection_test(self, file_path: str) -> Optional[GeneratedTest]:
        """Create command injection test."""
        return GeneratedTest(
            name="test_command_injection",
            test_type=TestType.SECURITY,
            description="Test command injection vulnerability",
            setup_code="",
            test_code="""
def test_command_injection():
    # Test command injection payloads
    cmd_payloads = [
        "; ls -la",
        "| cat /etc/passwd",
        "&& echo 'hacked'",
        "`whoami`",
        "$(id)"
    ]
    
    for payload in cmd_payloads:
        result = execute_command(payload)  # Replace with actual function
        # Verify command injection is prevented
        assert "hacked" not in str(result)
        assert "root:" not in str(result)
        assert "uid=" not in str(result)
""",
            expected_result="Command injection attempts blocked",
            assertions=["assert 'hacked' not in str(result)"],
            tags=["security", "command_injection", "taint"],
            confidence=0.9,
            rationale="Test for command injection vulnerabilities"
        )
    
    def _create_buffer_overflow_test(self, file_path: str) -> Optional[GeneratedTest]:
        """Create buffer overflow test."""
        return GeneratedTest(
            name="test_buffer_overflow",
            test_type=TestType.SECURITY,
            description="Test buffer overflow vulnerability",
            setup_code="",
            test_code="""
def test_buffer_overflow():
    # Test buffer overflow payloads
    overflow_payloads = [
        "A" * 1000,
        "A" * 10000,
        "A" * 100000,
        "\\x00" * 1000,
        "\\xff" * 1000
    ]
    
    for payload in overflow_payloads:
        try:
            result = process_buffer(payload)  # Replace with actual function
            # Verify no crash or memory corruption
            assert result is not None
        except (MemoryError, BufferError, SegmentationError):
            # These might be acceptable for extreme inputs
            pass
""",
            expected_result="Buffer overflow handled gracefully",
            assertions=["assert result is not None"],
            tags=["security", "buffer_overflow", "memory"],
            confidence=0.8,
            rationale="Test for buffer overflow vulnerabilities"
        )
    
    def _generate_with_ai(self, file_path: str, verification_result: Dict[str, Any]) -> List[GeneratedTest]:
        """Generate additional tests using AI."""
        if not self.use_ai:
            return []
        
        try:
            prompt = self._build_ai_test_prompt(file_path, verification_result)
            
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a software testing expert. Generate comprehensive test cases based on verification results. Return JSON with test cases including name, description, setup_code, test_code, and assertions."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1000
            )
            
            ai_response = response.choices[0].message.content
            
            # Parse AI response
            try:
                ai_data = json.loads(ai_response)
                return self._parse_ai_tests(ai_data, file_path)
            except json.JSONDecodeError:
                return self._parse_ai_test_text(ai_response, file_path)
                
        except Exception as e:
            return []
    
    def _build_ai_test_prompt(self, file_path: str, verification_result: Dict[str, Any]) -> str:
        """Build prompt for AI test generation."""
        prompt = f"""
Generate comprehensive test cases for this file based on verification results:

File: {file_path}

Verification Results:
- Errors: {len(verification_result.get('errors', []))}
- Warnings: {len(verification_result.get('warnings', []))}
- Functions analyzed: {verification_result.get('functions_analyzed', [])}

Errors:
{json.dumps(verification_result.get('errors', []), indent=2)}

Functions:
{json.dumps(verification_result.get('functions', []), indent=2)}

Generate test cases that:
1. Cover all error conditions found
2. Test boundary values for all parameters
3. Verify contract conditions
4. Test security vulnerabilities
5. Include edge cases and corner cases

For each test, provide:
- name: test function name
- description: what the test covers
- setup_code: any setup needed
- test_code: the actual test implementation
- assertions: what should be verified
- test_type: one of [boundary, edge_case, error_case, contract, property, security]
- confidence: 0.0 to 1.0

Return as JSON array of test cases.
"""
        
        return prompt
    
    def _parse_ai_tests(self, ai_data: Any, file_path: str) -> List[GeneratedTest]:
        """Parse AI-generated test data."""
        tests = []
        
        if isinstance(ai_data, list):
            for item in ai_data:
                test = self._parse_ai_test(item, file_path)
                if test:
                    tests.append(test)
        elif isinstance(ai_data, dict):
            test = self._parse_ai_test(ai_data, file_path)
            if test:
                tests.append(test)
        
        return tests
    
    def _parse_ai_test(self, test_data: Dict[str, Any], file_path: str) -> Optional[GeneratedTest]:
        """Parse a single AI-generated test."""
        try:
            test_type_str = test_data.get('test_type', 'edge_case')
            
            try:
                test_type = TestType(test_type_str)
            except ValueError:
                test_type = TestType.EDGE_CASE
            
            return GeneratedTest(
                name=test_data.get('name', 'generated_test'),
                test_type=test_type,
                description=test_data.get('description', 'AI-generated test'),
                setup_code=test_data.get('setup_code', ''),
                test_code=test_data.get('test_code', ''),
                expected_result=test_data.get('expected_result', 'Test passes'),
                assertions=test_data.get('assertions', []),
                tags=test_data.get('tags', ['ai_generated']),
                confidence=float(test_data.get('confidence', 0.7)),
                rationale="AI-generated test case"
            )
        except (KeyError, ValueError, TypeError):
            return None
    
    def _parse_ai_test_text(self, response: str, file_path: str) -> List[GeneratedTest]:
        """Parse AI test response when it's not valid JSON."""
        tests = []
        
        # Try to extract test-like blocks
        lines = response.split('\n')
        current_test = []
        
        for line in lines:
            if line.strip().startswith('def test_'):
                if current_test:
                    test_code = '\n'.join(current_test)
                    tests.append(GeneratedTest(
                        name="ai_generated_test",
                        test_type=TestType.EDGE_CASE,
                        description="AI-generated test from text response",
                        setup_code="",
                        test_code=test_code,
                        expected_result="Test passes",
                        assertions=["# AI-generated assertions"],
                        tags=["ai_generated"],
                        confidence=0.6,
                        rationale="Extracted from AI text response"
                    ))
                current_test = [line]
            elif current_test:
                current_test.append(line)
        
        # Add the last test if exists
        if current_test:
            test_code = '\n'.join(current_test)
            tests.append(GeneratedTest(
                name="ai_generated_test_final",
                test_type=TestType.EDGE_CASE,
                description="AI-generated test from text response",
                setup_code="",
                test_code=test_code,
                expected_result="Test passes",
                assertions=["# AI-generated assertions"],
                tags=["ai_generated"],
                confidence=0.6,
                rationale="Extracted from AI text response"
            ))
        
        return tests
    
    def _deduplicate_tests(self, tests: List[GeneratedTest]) -> List[GeneratedTest]:
        """Remove duplicate tests."""
        seen = set()
        unique_tests = []
        
        for test in tests:
            # Create a key based on test name and type
            key = (test.name.lower(), test.test_type)
            
            if key not in seen:
                seen.add(key)
                unique_tests.append(test)
        
        return unique_tests
    
    def generate_test_file(self, tests: List[GeneratedTest], output_path: str, language: str = 'python') -> None:
        """Generate a complete test file from the test cases."""
        if language.lower() == 'python':
            self._generate_python_test_file(tests, output_path)
        elif language.lower() == 'java':
            self._generate_java_test_file(tests, output_path)
        elif language.lower() == 'javascript':
            self._generate_javascript_test_file(tests, output_path)
        else:
            raise ValueError(f"Unsupported language: {language}")
    
    def _generate_python_test_file(self, tests: List[GeneratedTest], output_path: str) -> None:
        """Generate Python test file."""
        content = '''"""Automatically generated test cases by AEON.

This file contains comprehensive test cases generated from formal verification results.
"""

import pytest
import sys
import threading
import time
from unittest.mock import patch, MagicMock

# Import the module to test
# TODO: Update this import
# from your_module import your_function

'''
        
        # Group tests by type
        tests_by_type = {}
        for test in tests:
            test_type = test.test_type
            if test_type not in tests_by_type:
                tests_by_type[test_type] = []
            tests_by_type[test_type].append(test)
        
        # Generate test sections
        for test_type, type_tests in tests_by_type.items():
            content += f"\n# {test_type.value.title()} Tests\n"
            content += "# " + "=" * 50 + "\n\n"
            
            for test in type_tests:
                content += f"def {test.name}():\n"
                content += f'    """\n    {test.description}\n    \n    Confidence: {test.confidence:.1%}\n    Rationale: {test.rationale}\n    Tags: {", ".join(test.tags)}\n    """\n'
                
                if test.setup_code:
                    for line in test.setup_code.strip().split('\n'):
                        content += f"    {line}\n"
                    content += "\n"
                
                for line in test.test_code.strip().split('\n'):
                    content += f"    {line}\n"
                
                content += "\n"
        
        # Write to file
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_java_test_file(self, tests: List[GeneratedTest], output_path: str) -> None:
        """Generate Java test file."""
        # Simplified Java test generation
        content = '''// Automatically generated test cases by AEON

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.*;

'''
        
        for test in tests:
            content += f"    @Test\n"
            content += f"    public void {test.name}() {{\n"
            content += f'        // {test.description}\n'
            content += f'        // Confidence: {test.confidence:.1%}\n'
            content += f'        // Rationale: {test.rationale}\n\n'
            
            for line in test.test_code.strip().split('\n'):
                content += f"        {line}\n"
            
            content += "    }\n\n"
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_javascript_test_file(self, tests: List[GeneratedTest], output_path: str) -> None:
        """Generate JavaScript test file."""
        content = '''// Automatically generated test cases by AEON

const assert = require('assert');

'''
        
        for test in tests:
            content += f"test('{test.name}', () => {{\n"
            content += f'  // {test.description}\n'
            content += f'  // Confidence: {test.confidence:.1%}\n'
            content += f'  // Rationale: {test.rationale}\n\n'
            
            for line in test.test_code.strip().split('\n'):
                content += f"  {line}\n"
            
            content += "});\n\n"
        
        with open(output_path, 'w') as f:
            f.write(content)
