"""Synthetic data pipeline for AI model training.

Generates synthetic AEON programs and compiler outputs to train
AI models on code generation, understanding, and refactoring.
"""

import random
import json
import math
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

from aeon.parser import parse
from aeon.pass1_prove import prove
from aeon.pass2_flatten import flatten
from aeon.pass3_emit import emit
from aeon.errors import AeonError


@dataclass
class SyntheticExample:
    """A synthetic training example."""
    prompt: str  # Natural language description
    source_code: str  # AEON source code
    ir_output: Optional[str]  # Flat IR JSON
    llvm_output: Optional[str]  # LLVM IR
    errors: List[Dict[str, Any]]  # Compiler errors
    metadata: Dict[str, Any]  # Additional metadata


class SyntheticDataGenerator:
    """Generates synthetic AEON programs for AI training."""

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.templates = self._load_templates()
        self.type_names = ["Int", "Float", "Bool", "String", "UUID", "Email", "USD"]
        self.function_names = [
            "add", "sub", "mul", "div", "mod", "pow", "sqrt", "abs", "min", "max",
            "clamp", "lerp", "distance", "normalize", "dot", "cross", "reflect",
            "refract", "length", "normalize", "floor", "ceil", "round", "trunc",
            "fract", "sign", "step", "smoothstep", "mix", "clamp", "lerp"
        ]
        self.data_names = [
            "Point", "Vector", "Color", "Rect", "Circle", "Line", "Triangle",
            "Matrix", "Quaternion", "Transform", "BoundingBox", "Ray", "Plane",
            "User", "Account", "Transaction", "Product", "Order", "Invoice"
        ]

    def _load_templates(self) -> Dict[str, List[str]]:
        """Load code generation templates."""
        return {
            "pure_functions": [
                "pure {name}({params}) -> {return_type} {{\n  {body}\n}}",
                "pure {name}({params}) -> {return_type} {{\n  {doc}\n  {body}\n}}",
            ],
            "task_functions": [
                "task {name}({params}) -> {return_type} {{\n  effects: [{effects}]\n  {body}\n}}",
                "task {name}({params}) -> {return_type} {{\n  effects: [{effects}]\n  {doc}\n  {body}\n}}",
            ],
            "data_types": [
                "data {name} {{\n  {fields}\n}}",
                "data {name} {{\n  {doc}\n  {fields}\n}}",
            ],
            "contracts": [
                "  requires: {requires}",
                "  ensures: {ensures}",
                "  requires: {requires}\n  ensures: {ensures}",
            ],
            "expressions": {
                "binary": ["{left} {op} {right}"],
                "unary": ["{op}{operand}"],
                "call": ["{name}({args})"],
                "if": ["if {cond} {{ {then_body} }} else {{ {else_body} }}"],
                "let": ["let {name}: {type} = {value}"],
                "return": ["return {value}", "return"],
            }
        }

    def generate_dataset(self, size: int, output_dir: str) -> None:
        """Generate a synthetic dataset of specified size."""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        examples = []
        for i in range(size):
            example = self._generate_example(i)
            examples.append(example)

            # Save individual examples
            example_file = output_path / f"example_{i:06d}.json"
            with open(example_file, 'w') as f:
                json.dump(asdict(example), f, indent=2)

        # Save dataset manifest
        manifest = {
            "size": size,
            "total_examples": len(examples),
            "categories": self._categorize_examples(examples),
            "statistics": self._compute_statistics(examples)
        }
        
        with open(output_path / "manifest.json", 'w') as f:
            json.dump(manifest, f, indent=2)

        print(f"Generated {len(examples)} synthetic examples in {output_dir}")

    def _generate_example(self, index: int) -> SyntheticExample:
        """Generate a single synthetic example."""
        # Choose example type
        example_types = ["pure_function", "task_function", "data_type", "mixed"]
        example_type = random.choice(example_types)

        if example_type == "pure_function":
            return self._generate_pure_function_example(index)
        elif example_type == "task_function":
            return self._generate_task_function_example(index)
        elif example_type == "data_type":
            return self._generate_data_type_example(index)
        else:
            return self._generate_mixed_example(index)

    def _generate_pure_function_example(self, index: int) -> SyntheticExample:
        """Generate a pure function example."""
        # Generate function signature
        name = random.choice(self.function_names) + f"_{index}"
        num_params = random.randint(0, 3)
        params = self._generate_parameters(num_params)
        return_type = random.choice(self.type_names)

        # Generate function body
        body_type = random.choice(["simple", "conditional", "recursive"])
        if body_type == "simple":
            body = self._generate_simple_body(params, return_type)
        elif body_type == "conditional":
            body = self._generate_conditional_body(params, return_type)
        else:
            body = self._generate_recursive_body(name, params, return_type)

        # Generate contracts (50% chance)
        contracts = ""
        if random.random() < 0.5:
            contracts = self._generate_contracts(params, return_type)

        # Assemble source code
        source = f"pure {name}({params}) -> {return_type} {{\n{contracts}{body}\n}}"

        # Generate prompt
        prompt = self._generate_pure_function_prompt(name, params, return_type, body_type)

        # Compile to get outputs
        ir_output, llvm_output, errors = self._compile_source(source)

        return SyntheticExample(
            prompt=prompt,
            source_code=source,
            ir_output=ir_output,
            llvm_output=llvm_output,
            errors=[error.to_dict() for error in errors],
            metadata={
                "type": "pure_function",
                "complexity": self._estimate_complexity(source),
                "has_contracts": bool(contracts),
                "body_type": body_type
            }
        )

    def _generate_task_function_example(self, index: int) -> SyntheticExample:
        """Generate a task function example."""
        name = random.choice(self.function_names) + f"_{index}"
        num_params = random.randint(1, 3)
        params = self._generate_parameters(num_params)
        return_type = random.choice(self.type_names)

        # Generate effects
        effect_types = ["Database", "Network", "File", "Console", "System"]
        num_effects = random.randint(1, 2)
        effects = [f"{random.choice(effect_types)}.{random.choice(['Read', 'Write', 'Query'])}" 
                  for _ in range(num_effects)]

        # Generate body (must use effects)
        body = self._generate_effectful_body(params, effects)

        # Generate source
        effects_str = ", ".join(effects)
        source = f"task {name}({params}) -> {return_type} {{\n  effects: [{effects_str}]\n{body}\n}}"

        # Generate prompt
        prompt = f"Create a task function '{name}' that performs {', '.join(effects).lower()} operations"

        # Compile
        ir_output, llvm_output, errors = self._compile_source(source)

        return SyntheticExample(
            prompt=prompt,
            source_code=source,
            ir_output=ir_output,
            llvm_output=llvm_output,
            errors=[error.to_dict() for error in errors],
            metadata={
                "type": "task_function",
                "complexity": self._estimate_complexity(source),
                "effects": effects
            }
        )

    def _generate_data_type_example(self, index: int) -> SyntheticExample:
        """Generate a data type example."""
        name = random.choice(self.data_names) + f"_{index}"
        num_fields = random.randint(2, 5)
        fields = self._generate_fields(num_fields)

        source = f"data {name} {{\n  {fields}\n}}"

        prompt = f"Define a data type '{name}' with {num_fields} fields for {random.choice(['geometry', 'business logic', 'graphics', 'data processing'])}"

        ir_output, llvm_output, errors = self._compile_source(source)

        return SyntheticExample(
            prompt=prompt,
            source_code=source,
            ir_output=ir_output,
            llvm_output=llvm_output,
            errors=[error.to_dict() for error in errors],
            metadata={
                "type": "data_type",
                "complexity": self._estimate_complexity(source),
                "num_fields": num_fields
            }
        )

    def _generate_mixed_example(self, index: int) -> SyntheticExample:
        """Generate a mixed example with multiple declarations."""
        # Generate a data type and a function that uses it
        data_name = random.choice(self.data_names) + f"_{index}"
        num_fields = random.randint(2, 4)
        fields = self._generate_fields(num_fields)
        data_def = f"data {data_name} {{\n  {fields}\n}}"

        # Generate function that uses the data type
        func_name = random.choice(self.function_names) + f"_{index}"
        params = f"x: {data_name}"
        return_type = random.choice(["Int", "Bool", "String"])
        
        # Simple body that accesses a field
        field_names = [f.split(":")[0].strip() for f in fields.split("\n") if f.strip()]
        if field_names:
            field = random.choice(field_names)
            if return_type == "Int":
                body = f"  return x.{field}"
            elif return_type == "Bool":
                body = f"  return x.{field} > 0"
            else:
                body = f"  return x.{field}.toString()"
        else:
            body = "  return 0"

        func_def = f"pure {func_name}({params}) -> {return_type} {{\n{body}\n}}"

        source = f"{data_def}\n\n{func_def}"

        prompt = f"Create a data type '{data_name}' and a function '{func_name}' that operates on it"

        ir_output, llvm_output, errors = self._compile_source(source)

        return SyntheticExample(
            prompt=prompt,
            source_code=source,
            ir_output=ir_output,
            llvm_output=llvm_output,
            errors=[error.to_dict() for error in errors],
            metadata={
                "type": "mixed",
                "complexity": self._estimate_complexity(source),
                "declarations": 2
            }
        )

    def _generate_parameters(self, count: int) -> str:
        """Generate parameter list."""
        if count == 0:
            return ""
        
        params = []
        for i in range(count):
            type_name = random.choice(self.type_names)
            param_name = chr(ord('a') + i)
            params.append(f"{param_name}: {type_name}")
        
        return ", ".join(params)

    def _generate_fields(self, count: int) -> str:
        """Generate field list for data type."""
        fields = []
        for i in range(count):
            type_name = random.choice(self.type_names)
            field_name = f"field_{i}"
            fields.append(f"  {field_name}: {type_name}")
        
        return "\n".join(fields)

    def _generate_simple_body(self, params: str, return_type: str) -> str:
        """Generate a simple function body."""
        if not params:
            if return_type == "Int":
                return "  return 0"
            elif return_type == "Bool":
                return "  return true"
            elif return_type == "String":
                return '  return ""'
            else:
                return "  return 0.0"

        # Simple arithmetic or return a parameter
        param_list = [p.split(":")[0].strip() for p in params.split(",") if p.strip()]
        if len(param_list) == 1:
            return f"  return {param_list[0]}"
        elif len(param_list) == 2 and return_type in ["Int", "Float"]:
            return f"  return {param_list[0]} + {param_list[1]}"
        else:
            return f"  return {param_list[0]}"

    def _generate_conditional_body(self, params: str, return_type: str) -> str:
        """Generate a conditional function body."""
        if not params:
            return "  return 0"

        param_list = [p.split(":")[0].strip() for p in params.split(",") if p.strip()]
        cond_param = param_list[0]
        
        if return_type in ["Int", "Float"]:
            return f"  if {cond_param} > 0 {{\n    return {cond_param}\n  }} else {{\n    return 0\n  }}"
        elif return_type == "Bool":
            return f"  return {cond_param} > 0"
        else:
            return f"  return {cond_param}.toString()"

    def _generate_recursive_body(self, name: str, params: str, return_type: str) -> str:
        """Generate a recursive function body."""
        if not params or return_type not in ["Int", "Float"]:
            return "  return 0"

        param_list = [p.split(":")[0].strip() for p in params.split(",") if p.strip()]
        if len(param_list) != 1:
            return "  return 0"

        param = param_list[0]
        return f"  if {param} <= 1 {{\n    return 1\n  }} else {{\n    return {param} * {name}({param} - 1)\n  }}"

    def _generate_contracts(self, params: str, return_type: str) -> str:
        """Generate contract clauses."""
        contracts = []
        
        # Add requires clause (50% chance)
        if random.random() < 0.5 and params:
            param_list = [p.split(":")[0].strip() for p in params.split(",") if p.strip()]
            if param_list:
                param = param_list[0]
                if return_type in ["Int", "Float"]:
                    contracts.append(f"  requires: {param} >= 0")
                else:
                    contracts.append(f"  requires: {param} != null")

        # Add ensures clause (50% chance)
        if random.random() < 0.5:
            if return_type in ["Int", "Float"]:
                contracts.append("  ensures: result >= 0")
            elif return_type == "Bool":
                contracts.append("  ensures: result == true or result == false")

        return "\n".join(contracts) + "\n" if contracts else ""

    def _generate_effectful_body(self, params: str, effects: List[str]) -> str:
        """Generate a body that uses effects."""
        # Simple body that calls a runtime object method
        if "Database" in str(effects):
            return "  return db.insert(value)"
        elif "Network" in str(effects):
            return "  return net.get(url)"
        elif "File" in str(effects):
            return "  return file.read(path)"
        elif "Console" in str(effects):
            return '  console.print("Hello")\n  return true'
        else:
            return "  return system.time()"

    def _generate_pure_function_prompt(self, name: str, params: str, return_type: str, body_type: str) -> str:
        """Generate a natural language prompt for pure function."""
        param_desc = f"with parameters {params}" if params else "with no parameters"
        
        if body_type == "simple":
            return f"Create a pure function '{name}' {param_desc} that returns {return_type.lower()}"
        elif body_type == "conditional":
            return f"Create a pure function '{name}' {param_desc} that uses conditional logic"
        else:
            return f"Create a recursive pure function '{name}' {param_desc}"

    def _compile_source(self, source: str) -> Tuple[Optional[str], Optional[str], List[AeonError]]:
        """Compile source code and return outputs."""
        try:
            program = parse(source)
            errors = prove(program)
            
            if errors:
                return None, None, errors
            
            ir_module = flatten(program)
            ir_output = ir_module.to_json()
            
            try:
                llvm_output = emit(ir_module)
            except Exception:
                llvm_output = None
            
            return ir_output, llvm_output, []
            
        except Exception as e:
            return None, None, [e]

    def _estimate_complexity(self, source: str) -> str:
        """Estimate code complexity."""
        lines = len([l for l in source.split('\n') if l.strip()])
        if lines <= 5:
            return "simple"
        elif lines <= 10:
            return "medium"
        else:
            return "complex"

    def _categorize_examples(self, examples: List[SyntheticExample]) -> Dict[str, int]:
        """Categorize examples by type."""
        categories = {}
        for example in examples:
            category = example.metadata.get("type", "unknown")
            categories[category] = categories.get(category, 0) + 1
        return categories

    def _compute_statistics(self, examples: List[SyntheticExample]) -> Dict[str, Any]:
        """Compute dataset statistics."""
        total_examples = len(examples)
        with_errors = sum(1 for ex in examples if ex.errors)
        with_contracts = sum(1 for ex in examples if ex.metadata.get("has_contracts", False))
        
        complexities = {}
        for example in examples:
            complexity = example.metadata.get("complexity", "unknown")
            complexities[complexity] = complexities.get(complexity, 0) + 1
        
        return {
            "total_examples": total_examples,
            "examples_with_errors": with_errors,
            "examples_with_contracts": with_contracts,
            "error_rate": with_errors / total_examples if total_examples > 0 else 0,
            "contract_rate": with_contracts / total_examples if total_examples > 0 else 0,
            "complexity_distribution": complexities
        }


def main():
    """CLI for synthetic data generation."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate synthetic AEON training data")
    parser.add_argument("--size", type=int, default=1000, help="Number of examples to generate")
    parser.add_argument("--output", type=str, default="synthetic_data", help="Output directory")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    
    args = parser.parse_args()
    
    generator = SyntheticDataGenerator(seed=args.seed)
    generator.generate_dataset(args.size, args.output)


if __name__ == "__main__":
    main()
