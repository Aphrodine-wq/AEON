"""AEON Natural Language Contract Generation.

Converts plain English requirements into formal contracts that AEON can verify.
Uses AI to bridge the gap between natural language specifications and
mathematically verifiable contracts.

Usage:
    from aeon.nl_contracts import NLContractGenerator
    generator = NLContractGenerator()
    contracts = generator.generate_from_text("Function should never return negative numbers")
"""

from __future__ import annotations

import re
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class ContractType(Enum):
    """Types of contracts that can be generated."""
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"
    INVARIANT = "invariant"
    BOUNDS = "bounds"
    NULL_CHECK = "null_check"
    DIVISION_CHECK = "division_check"
    RANGE_CHECK = "range_check"
    TYPE_CHECK = "type_check"


@dataclass
class GeneratedContract:
    """A generated formal contract."""
    contract_type: ContractType
    formal_spec: str
    natural_language: str
    confidence: float
    variables: List[str]
    rationale: str


class NLContractGenerator:
    """Generates formal contracts from natural language descriptions."""
    
    def __init__(self, model: str = "gpt-3.5-turbo", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key
        self.patterns = self._init_patterns()
        
        if OPENAI_AVAILABLE and api_key:
            openai.api_key = api_key
            self.use_ai = True
        else:
            self.use_ai = False
    
    def _init_patterns(self) -> Dict[ContractType, List[re.Pattern]]:
        """Initialize regex patterns for common contract patterns."""
        return {
            ContractType.PRECONDITION: [
                re.compile(r'(?i)(?:require|must|should|need to|has to)\s+(?:be\s+)?(.+?)\s+(?:before|prior to)'),
                re.compile(r'(?i)(?:input|parameter|arg(?:ument)?)\s+(?:must|should)\s+(?:be\s+)?(.+)'),
                re.compile(r'(?i)(?:assume|given)\s+that\s+(.+)'),
                re.compile(r'(?i)(?:only|just)\s+(?:accept|allow|take)\s+(.+)'),
            ],
            ContractType.POSTCONDITION: [
                re.compile(r'(?i)(?:ensure|guarantee|return|output|result)\s+(?:must|should|will)\s+(?:be\s+)?(.+)'),
                re.compile(r'(?i)(?:function|method)\s+(?:must|should)\s+(?:return|output)\s+(.+)'),
                re.compile(r'(?i)(?:after|when)\s+(?:complete|done|finished),?\s*(.+)'),
                re.compile(r'(?i)(?:the\s+)?result\s+(?:must|should)\s+(?:be\s+)?(.+)'),
            ],
            ContractType.BOUNDS: [
                re.compile(r'(?i)(?:between|from)\s+(\d+)\s+(?:and|to)\s+(\d+)'),
                re.compile(r'(?i)(?:greater than|more than|>\s*)(\d+)'),
                re.compile(r'(?i)(?:less than|fewer than|<\s*)(\d+)'),
                re.compile(r'(?i)(?:at least|minimum|min\s*=\s*)(\d+)'),
                re.compile(r'(?i)(?:at most|maximum|max\s*=\s*)(\d+)'),
            ],
            ContractType.NULL_CHECK: [
                re.compile(r'(?i)(?:not\s+)?null|(?:not\s+)?none|(?:not\s+)?undefined'),
                re.compile(r'(?i)(?:must\s+)?(?:not\s+)?be\s+(?:null|none|undefined)'),
                re.compile(r'(?i)(?:should\s+)?(?:not\s+)?be\s+(?:null|none|undefined)'),
            ],
            ContractType.DIVISION_CHECK: [
                re.compile(r'(?i)(?:divide|division|/\s*)(?:by\s+)?zero'),
                re.compile(r'(?i)(?:denominator|divisor)\s+(?:must\s+)?(?:not\s+)?be\s+zero'),
                re.compile(r'(?i)(?:check|verify)\s+(?:for\s+)?zero\s+division'),
            ],
            ContractType.RANGE_CHECK: [
                re.compile(r'(?i)(?:positive|negative|non-negative|non-positive)'),
                re.compile(r'(?i)(?:valid|acceptable|allowed)\s+(?:range|values?)'),
                re.compile(r'(?i)(?:within|inside|in)\s+(?:the\s+)?range\s+(.+)'),
            ],
            ContractType.TYPE_CHECK: [
                re.compile(r'(?i)(?:must\s+)?be\s+(?:a\s+)?(?:integer|string|float|boolean|list|dict)'),
                re.compile(r'(?i)(?:should\s+)?be\s+(?:a\s+)?(?:integer|string|float|boolean|list|dict)'),
                re.compile(r'(?i)(?:type\s+)?(?:must\s+)?(?:be\s+)?(?:int|str|float|bool|array|object)'),
            ],
        }
    
    def generate_from_text(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[GeneratedContract]:
        """Generate formal contracts from natural language text."""
        contracts = []
        
        # Try pattern-based generation first
        pattern_contracts = self._generate_from_patterns(text)
        contracts.extend(pattern_contracts)
        
        # If AI is available, enhance with AI-generated contracts
        if self.use_ai:
            ai_contracts = self._generate_with_ai(text, context)
            contracts.extend(ai_contracts)
        
        # Remove duplicates and sort by confidence
        contracts = self._deduplicate_contracts(contracts)
        contracts.sort(key=lambda c: c.confidence, reverse=True)
        
        return contracts
    
    def _generate_from_patterns(self, text: str) -> List[GeneratedContract]:
        """Generate contracts using regex patterns."""
        contracts = []
        
        for contract_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = pattern.finditer(text)
                for match in matches:
                    contract = self._create_contract_from_match(
                        contract_type, match, text
                    )
                    if contract:
                        contracts.append(contract)
        
        return contracts
    
    def _create_contract_from_match(self, contract_type: ContractType, 
                                   match: re.Match, original_text: str) -> Optional[GeneratedContract]:
        """Create a contract from a regex match."""
        try:
            if contract_type == ContractType.PRECONDITION:
                return self._create_precondition(match, original_text)
            elif contract_type == ContractType.POSTCONDITION:
                return self._create_postcondition(match, original_text)
            elif contract_type == ContractType.BOUNDS:
                return self._create_bounds_contract(match, original_text)
            elif contract_type == ContractType.NULL_CHECK:
                return self._create_null_check(match, original_text)
            elif contract_type == ContractType.DIVISION_CHECK:
                return self._create_division_check(match, original_text)
            elif contract_type == ContractType.RANGE_CHECK:
                return self._create_range_check(match, original_text)
            elif contract_type == ContractType.TYPE_CHECK:
                return self._create_type_check(match, original_text)
        except Exception:
            # If pattern matching fails, skip this contract
            pass
        
        return None
    
    def _create_precondition(self, match: re.Match, original_text: str) -> GeneratedContract:
        """Create a precondition contract."""
        condition = match.group(1) if match.groups() else match.group(0)
        
        # Extract variables
        variables = self._extract_variables(condition)
        
        # Generate formal specification
        formal_spec = self._generate_formal_precondition(condition, variables)
        
        return GeneratedContract(
            contract_type=ContractType.PRECONDITION,
            formal_spec=formal_spec,
            natural_language=match.group(0),
            confidence=0.8,
            variables=variables,
            rationale=f"Precondition extracted from: '{match.group(0)}'"
        )
    
    def _create_postcondition(self, match: re.Match, original_text: str) -> GeneratedContract:
        """Create a postcondition contract."""
        condition = match.group(1) if match.groups() else match.group(0)
        
        # Extract variables
        variables = self._extract_variables(condition)
        variables.append('result')  # Postconditions often refer to return value
        
        # Generate formal specification
        formal_spec = self._generate_formal_postcondition(condition, variables)
        
        return GeneratedContract(
            contract_type=ContractType.POSTCONDITION,
            formal_spec=formal_spec,
            natural_language=match.group(0),
            confidence=0.8,
            variables=variables,
            rationale=f"Postcondition extracted from: '{match.group(0)}'"
        )
    
    def _create_bounds_contract(self, match: re.Match, original_text: str) -> GeneratedContract:
        """Create a bounds checking contract."""
        groups = match.groups()
        
        if len(groups) >= 2:
            # Range: between X and Y
            lower, upper = groups[0], groups[1]
            formal_spec = f"value >= {lower} and value <= {upper}"
            variables = ['value']
        elif len(groups) == 1:
            bound = groups[0]
            if 'greater' in match.group(0).lower() or '>' in match.group(0):
                formal_spec = f"value > {bound}"
            elif 'less' in match.group(0).lower() or '<' in match.group(0):
                formal_spec = f"value < {bound}"
            elif 'least' in match.group(0).lower() or 'min' in match.group(0).lower():
                formal_spec = f"value >= {bound}"
            elif 'most' in match.group(0).lower() or 'max' in match.group(0).lower():
                formal_spec = f"value <= {bound}"
            else:
                formal_spec = f"value == {bound}"
            variables = ['value']
        else:
            return None
        
        return GeneratedContract(
            contract_type=ContractType.BOUNDS,
            formal_spec=formal_spec,
            natural_language=match.group(0),
            confidence=0.9,
            variables=variables,
            rationale=f"Bounds check extracted from: '{match.group(0)}'"
        )
    
    def _create_null_check(self, match: re.Match, original_text: str) -> GeneratedContract:
        """Create a null checking contract."""
        text = match.group(0).lower()
        
        if 'not' in text:
            formal_spec = "value is not null"
        else:
            formal_spec = "value is null"
        
        return GeneratedContract(
            contract_type=ContractType.NULL_CHECK,
            formal_spec=formal_spec,
            natural_language=match.group(0),
            confidence=0.85,
            variables=['value'],
            rationale=f"Null check extracted from: '{match.group(0)}'"
        )
    
    def _create_division_check(self, match: re.Match, original_text: str) -> GeneratedContract:
        """Create a division by zero check contract."""
        return GeneratedContract(
            contract_type=ContractType.DIVISION_CHECK,
            formal_spec="divisor != 0",
            natural_language=match.group(0),
            confidence=0.95,
            variables=['divisor'],
            rationale=f"Division by zero check extracted from: '{match.group(0)}'"
        )
    
    def _create_range_check(self, match: re.Match, original_text: str) -> GeneratedContract:
        """Create a range checking contract."""
        text = match.group(0).lower()
        
        if 'positive' in text:
            formal_spec = "value > 0"
        elif 'negative' in text:
            formal_spec = "value < 0"
        elif 'non-negative' in text:
            formal_spec = "value >= 0"
        elif 'non-positive' in text:
            formal_spec = "value <= 0"
        else:
            # Try to extract range from context
            formal_spec = "value in valid_range"
        
        return GeneratedContract(
            contract_type=ContractType.RANGE_CHECK,
            formal_spec=formal_spec,
            natural_language=match.group(0),
            confidence=0.8,
            variables=['value'],
            rationale=f"Range check extracted from: '{match.group(0)}'"
        )
    
    def _create_type_check(self, match: re.Match, original_text: str) -> GeneratedContract:
        """Create a type checking contract."""
        text = match.group(0).lower()
        
        type_map = {
            'integer': 'int',
            'int': 'int',
            'string': 'str',
            'str': 'str',
            'float': 'float',
            'boolean': 'bool',
            'bool': 'bool',
            'list': 'list',
            'array': 'list',
            'dict': 'dict',
            'object': 'dict'
        }
        
        detected_type = 'unknown'
        for type_name, formal_type in type_map.items():
            if type_name in text:
                detected_type = formal_type
                break
        
        formal_spec = f"isinstance(value, {detected_type})"
        
        return GeneratedContract(
            contract_type=ContractType.TYPE_CHECK,
            formal_spec=formal_spec,
            natural_language=match.group(0),
            confidence=0.85,
            variables=['value'],
            rationale=f"Type check extracted from: '{match.group(0)}'"
        )
    
    def _generate_formal_precondition(self, condition: str, variables: List[str]) -> str:
        """Generate formal precondition specification."""
        # Simple heuristic-based generation
        condition = condition.strip()
        
        # Handle common patterns
        if 'not null' in condition.lower():
            return f"{variables[0] if variables else 'input'} is not null"
        elif 'positive' in condition.lower():
            return f"{variables[0] if variables else 'input'} > 0"
        elif 'negative' in condition.lower():
            return f"{variables[0] if variables else 'input'} < 0"
        elif 'between' in condition.lower():
            # Try to extract bounds
            numbers = re.findall(r'\d+', condition)
            if len(numbers) >= 2:
                return f"{numbers[0]} <= {variables[0] if variables else 'input'} <= {numbers[1]}"
        
        # Default: return as-is with proper formatting
        return condition
    
    def _generate_formal_postcondition(self, condition: str, variables: List[str]) -> str:
        """Generate formal postcondition specification."""
        condition = condition.strip()
        
        # Handle common patterns
        if 'return' in condition.lower():
            if 'positive' in condition.lower():
                return "result > 0"
            elif 'negative' in condition.lower():
                return "result < 0"
            elif 'not null' in condition.lower():
                return "result is not null"
        
        # Default: use result variable
        return f"result {condition}"
    
    def _extract_variables(self, text: str) -> List[str]:
        """Extract potential variable names from text."""
        # Simple heuristic: look for words that might be variables
        # This is a basic implementation - could be enhanced with NLP
        
        # Common variable name patterns
        var_patterns = [
            r'\b[a-z][a-zA-Z0-9_]*\b',  # camelCase
            r'\b[a-z][a-z0-9_]*\b',     # snake_case
        ]
        
        variables = []
        for pattern in var_patterns:
            matches = re.findall(pattern, text)
            variables.extend(matches)
        
        # Filter out common English words
        common_words = {
            'the', 'and', 'or', 'but', 'for', 'with', 'from', 'that', 'this',
            'must', 'should', 'will', 'can', 'may', 'need', 'have', 'been',
            'are', 'is', 'was', 'were', 'be', 'being', 'been', 'have', 'has',
            'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should',
            'might', 'must', 'shall', 'can', 'may', 'a', 'an', 'in', 'on',
            'at', 'by', 'to', 'of', 'as', 'if', 'when', 'then', 'else',
            'not', 'null', 'none', 'undefined', 'true', 'false', 'yes', 'no'
        }
        
        filtered_vars = []
        for var in variables:
            if var.lower() not in common_words and len(var) > 1:
                filtered_vars.append(var)
        
        # Remove duplicates and return first few
        return list(dict.fromkeys(filtered_vars))[:5]
    
    def _generate_with_ai(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[GeneratedContract]:
        """Generate contracts using AI model."""
        if not self.use_ai:
            return []
        
        try:
            prompt = self._build_ai_prompt(text, context)
            
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a formal verification expert. Convert natural language requirements into formal contracts. Return JSON with: contract_type, formal_spec, confidence, variables, rationale."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            ai_response = response.choices[0].message.content
            
            # Parse AI response
            try:
                ai_data = json.loads(ai_response)
                contracts = []
                
                if isinstance(ai_data, list):
                    for item in ai_data:
                        contracts.append(self._parse_ai_contract(item, text))
                else:
                    contracts.append(self._parse_ai_contract(ai_data, text))
                
                return contracts
            except json.JSONDecodeError:
                # If AI response is not valid JSON, try to extract contracts manually
                return self._parse_ai_text_response(ai_response, text)
                
        except Exception as e:
            # AI generation failed, return empty list
            return []
    
    def _build_ai_prompt(self, text: str, context: Optional[Dict[str, Any]]) -> str:
        """Build prompt for AI model."""
        prompt = f"""
Convert this natural language requirement into formal verification contracts:

Requirement: "{text}"

"""
        
        if context:
            prompt += f"""
Context:
- Function name: {context.get('function_name', 'unknown')}
- Parameters: {context.get('parameters', [])}
- Return type: {context.get('return_type', 'unknown')}
- Language: {context.get('language', 'unknown')}

"""
        
        prompt += """
Generate contracts for:
1. Preconditions (input validation)
2. Postconditions (output guarantees) 
3. Invariants (state constraints)
4. Bounds checks (range validation)
5. Null/None checks
6. Division by zero checks
7. Type checks

For each contract, provide:
- contract_type: one of ["precondition", "postcondition", "invariant", "bounds", "null_check", "division_check", "type_check"]
- formal_spec: the formal specification (e.g., "x > 0 and y != null")
- confidence: 0.0 to 1.0
- variables: list of variable names involved
- rationale: explanation of the contract

Return as JSON array of contracts.
"""
        
        return prompt
    
    def _parse_ai_contract(self, ai_data: Dict[str, Any], original_text: str) -> GeneratedContract:
        """Parse AI-generated contract data."""
        contract_type_str = ai_data.get('contract_type', 'precondition')
        
        try:
            contract_type = ContractType(contract_type_str)
        except ValueError:
            contract_type = ContractType.PRECONDITION
        
        return GeneratedContract(
            contract_type=contract_type,
            formal_spec=ai_data.get('formal_spec', ''),
            natural_language=original_text,
            confidence=float(ai_data.get('confidence', 0.7)),
            variables=ai_data.get('variables', []),
            rationale=ai_data.get('rationale', 'AI-generated contract')
        )
    
    def _parse_ai_text_response(self, response: str, original_text: str) -> List[GeneratedContract]:
        """Parse AI response when it's not valid JSON."""
        contracts = []
        
        # Try to extract contract-like statements
        lines = response.split('\n')
        for line in lines:
            if ':' in line and any(keyword in line.lower() for keyword in ['require', 'ensure', 'check', 'must']):
                # This looks like a contract
                contracts.append(GeneratedContract(
                    contract_type=ContractType.PRECONDITION,
                    formal_spec=line.strip(),
                    natural_language=original_text,
                    confidence=0.6,  # Lower confidence for parsed text
                    variables=self._extract_variables(line),
                    rationale="Extracted from AI text response"
                ))
        
        return contracts
    
    def _deduplicate_contracts(self, contracts: List[GeneratedContract]) -> List[GeneratedContract]:
        """Remove duplicate contracts."""
        seen = set()
        unique_contracts = []
        
        for contract in contracts:
            # Create a key based on contract type and formal spec
            key = (contract.contract_type, contract.formal_spec.lower().strip())
            
            if key not in seen:
                seen.add(key)
                unique_contracts.append(contract)
        
        return unique_contracts
    
    def generate_aeon_contracts(self, contracts: List[GeneratedContract]) -> str:
        """Convert generated contracts to AEON syntax."""
        aeon_contracts = []
        
        for contract in contracts:
            if contract.contract_type == ContractType.PRECONDITION:
                aeon_contracts.append(f"  requires: {contract.formal_spec}")
            elif contract.contract_type == ContractType.POSTCONDITION:
                aeon_contracts.append(f"  ensures: {contract.formal_spec}")
            elif contract.contract_type == ContractType.INVARIANT:
                aeon_contracts.append(f"  invariant: {contract.formal_spec}")
        
        return '\n'.join(aeon_contracts)
    
    def explain_contracts(self, contracts: List[GeneratedContract]) -> str:
        """Generate human-readable explanation of contracts."""
        explanation = "Generated Formal Contracts:\n\n"
        
        for i, contract in enumerate(contracts, 1):
            explanation += f"{i}. {contract.contract_type.value.title()}\n"
            explanation += f"   Natural Language: {contract.natural_language}\n"
            explanation += f"   Formal Specification: {contract.formal_spec}\n"
            explanation += f"   Variables: {', '.join(contract.variables)}\n"
            explanation += f"   Confidence: {contract.confidence:.1%}\n"
            explanation += f"   Rationale: {contract.rationale}\n\n"
        
        return explanation
