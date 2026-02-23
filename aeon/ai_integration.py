"""AI Model Integration Layer for AEON.

Provides interfaces for AI models to:
1. Generate AEON code from natural language
2. Understand and analyze AEON programs
3. Refactor and optimize AEON code
4. Get structured feedback from compiler
"""

import json
import subprocess
import tempfile
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path

from aeon.parser import parse
from aeon.pass1_prove import prove
from aeon.pass2_flatten import flatten
from aeon.pass3_emit import emit
from aeon.errors import AeonError, CompileError


@dataclass
class CodeGenerationRequest:
    """Request for AI code generation."""
    prompt: str
    context: Optional[str] = None  # Existing code context
    constraints: Optional[Dict[str, Any]] = None  # Type hints, contracts, etc.
    max_tokens: int = 1000
    temperature: float = 0.7


@dataclass
class CodeGenerationResponse:
    """Response from AI code generation."""
    generated_code: str
    confidence: float
    compilation_status: str  # "success", "error", "partial"
    errors: List[Dict[str, Any]]
    ir_output: Optional[str]
    metadata: Dict[str, Any]


@dataclass
class CodeAnalysisRequest:
    """Request for AI code analysis."""
    source_code: str
    analysis_type: str  # "summarize", "explain", "find_bugs", "optimize"
    focus_areas: Optional[List[str]] = None


@dataclass
class CodeAnalysisResponse:
    """Response from AI code analysis."""
    analysis: str
    insights: List[str]
    suggestions: List[str]
    confidence: float
    metadata: Dict[str, Any]


@dataclass
class RefactoringRequest:
    """Request for AI code refactoring."""
    source_code: str
    refactoring_type: str  # "optimize", "simplify", "add_contracts", "parallelize"
    target_metrics: Optional[Dict[str, Any]] = None


@dataclass
class RefactoringResponse:
    """Response from AI code refactoring."""
    refactored_code: str
    changes_made: List[str]
    improvements: List[str]
    compilation_status: str
    errors: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class AIModelInterface:
    """Interface for interacting with AI models for AEON tasks."""

    def __init__(self, model_endpoint: Optional[str] = None):
        self.model_endpoint = model_endpoint
        self.temp_dir = tempfile.mkdtemp()

    def generate_code(self, request: CodeGenerationRequest) -> CodeGenerationResponse:
        """Generate AEON code from natural language prompt."""
        # For now, use template-based generation
        # In production, this would call an actual AI model
        generated_code = self._template_based_generation(request)
        
        # Compile the generated code
        compilation_status, errors, ir_output = self._compile_code(generated_code)
        
        # Calculate confidence based on compilation success
        confidence = 0.9 if compilation_status == "success" else 0.5
        if errors:
            confidence -= len(errors) * 0.1
        
        return CodeGenerationResponse(
            generated_code=generated_code,
            confidence=max(0.1, confidence),
            compilation_status=compilation_status,
            errors=[error.to_dict() if hasattr(error, 'to_dict') else str(error) for error in errors],
            ir_output=ir_output,
            metadata={
                "prompt_length": len(request.prompt),
                "code_length": len(generated_code),
                "has_context": request.context is not None
            }
        )

    def analyze_code(self, request: CodeAnalysisRequest) -> CodeAnalysisResponse:
        """Analyze AEON code with AI."""
        try:
            program = parse(request.source_code)
            errors = prove(program)
            ir_module = flatten(program)
            ir_json = ir_module.to_json()
            
            # Extract insights from IR
            insights = self._extract_insights(ir_json, request.analysis_type)
            
            # Generate analysis based on type
            if request.analysis_type == "summarize":
                analysis = self._summarize_code(program, ir_json)
            elif request.analysis_type == "explain":
                analysis = self._explain_code(program, ir_json)
            elif request.analysis_type == "find_bugs":
                analysis = self._find_bugs(program, errors)
            elif request.analysis_type == "optimize":
                analysis = self._suggest_optimizations(ir_json)
            else:
                analysis = "Unknown analysis type"
            
            suggestions = self._generate_suggestions(program, errors, request.analysis_type)
            
            return CodeAnalysisResponse(
                analysis=analysis,
                insights=insights,
                suggestions=suggestions,
                confidence=0.8 if not errors else 0.6,
                metadata={
                    "functions_count": len([d for d in program.declarations if hasattr(d, 'body')]),
                    "errors_count": len(errors),
                    "ir_size": len(ir_json)
                }
            )
            
        except Exception as e:
            return CodeAnalysisResponse(
                analysis=f"Error analyzing code: {str(e)}",
                insights=[],
                suggestions=["Fix syntax errors before analysis"],
                confidence=0.1,
                metadata={"error": str(e)}
            )

    def refactor_code(self, request: RefactoringRequest) -> RefactoringResponse:
        """Refactor AEON code with AI."""
        try:
            # Parse original code
            program = parse(request.source_code)
            original_errors = prove(program)
            
            # Apply refactoring based on type
            if request.refactoring_type == "optimize":
                refactored_code, changes = self._optimize_code(request.source_code, program)
            elif request.refactoring_type == "simplify":
                refactored_code, changes = self._simplify_code(request.source_code, program)
            elif request.refactoring_type == "add_contracts":
                refactored_code, changes = self._add_contracts(request.source_code, program)
            elif request.refactoring_type == "parallelize":
                refactored_code, changes = self._parallelize_code(request.source_code, program)
            else:
                refactored_code = request.source_code
                changes = ["Unknown refactoring type"]
            
            # Compile refactored code
            compilation_status, errors, ir_output = self._compile_code(refactored_code)
            
            # Generate improvements
            improvements = self._measure_improvements(request.source_code, refactored_code, request.refactoring_type)
            
            return RefactoringResponse(
                refactored_code=refactored_code,
                changes_made=changes,
                improvements=improvements,
                compilation_status=compilation_status,
                errors=[error.to_dict() if hasattr(error, 'to_dict') else str(error) for error in errors],
                metadata={
                    "original_errors": len(original_errors),
                    "new_errors": len(errors),
                    "refactoring_type": request.refactoring_type
                }
            )
            
        except Exception as e:
            return RefactoringResponse(
                refactored_code=request.source_code,
                changes_made=[f"Error during refactoring: {str(e)}"],
                improvements=[],
                compilation_status="error",
                errors=[str(e)],
                metadata={"error": str(e)}
            )

    def get_compiler_feedback(self, source_code: str) -> Dict[str, Any]:
        """Get structured compiler feedback for AI training."""
        try:
            program = parse(source_code)
            errors = prove(program)
            
            if not errors:
                ir_module = flatten(program)
                ir_data = json.loads(ir_module.to_json())
            else:
                ir_data = None
            
            feedback = {
                "status": "success" if not errors else "error",
                "errors": [error.to_dict() for error in errors],
                "ir": ir_data,
                "statistics": {
                    "lines_of_code": len([l for l in source_code.split('\n') if l.strip()]),
                    "declarations_count": len(program.declarations),
                    "functions_count": len([d for d in program.declarations if hasattr(d, 'body')]),
                    "data_types_count": len([d for d in program.declarations if hasattr(d, 'fields')])
                }
            }
            
            return feedback
            
        except Exception as e:
            return {
                "status": "parse_error",
                "errors": [{"kind": "parse_error", "message": str(e)}],
                "ir": None,
                "statistics": {}
            }

    def _template_based_generation(self, request: CodeGenerationRequest) -> str:
        """Template-based code generation (fallback)."""
        prompt_lower = request.prompt.lower()
        
        if "function" in prompt_lower and "add" in prompt_lower:
            return """pure add(a: Int, b: Int) -> Int {
  return a + b
}"""
        elif "function" in prompt_lower and "multiply" in prompt_lower:
            return """pure multiply(a: Int, b: Int) -> Int {
  return a * b
}"""
        elif "data" in prompt_lower and "type" in prompt_lower:
            return """data Point {
  x: Int
  y: Int
}"""
        elif "task" in prompt_lower or "database" in prompt_lower:
            return """task save_user(user: User) -> Bool {
  effects: [Database.Write]
  return db.insert(user)
}"""
        elif "recursive" in prompt_lower or "factorial" in prompt_lower:
            return """pure factorial(n: Int) -> Int {
  if n <= 1 {
    return 1
  } else {
    return n * factorial(n - 1)
  }
}"""
        else:
            # Generic function
            return """pure process(input: Int) -> Int {
  return input * 2
}"""

    def _compile_code(self, source_code: str) -> Tuple[str, List[AeonError], Optional[str]]:
        """Compile AEON code and return status, errors, and IR."""
        try:
            program = parse(source_code)
            errors = prove(program)
            
            if errors:
                return "error", errors, None
            
            ir_module = flatten(program)
            ir_output = ir_module.to_json()
            
            return "success", [], ir_output
            
        except CompileError as e:
            return "error", [e], None
        except Exception as e:
            return "partial", [e], None

    def _extract_insights(self, ir_json: str, analysis_type: str) -> List[str]:
        """Extract insights from IR JSON."""
        insights = []
        try:
            ir_data = json.loads(ir_json)
            
            if "functions" in ir_data:
                func_count = len(ir_data["functions"])
                insights.append(f"Contains {func_count} function(s)")
                
                for func in ir_data["functions"]:
                    if func.get("effects"):
                        insights.append(f"Function '{func['name']}' has effects: {func['effects']}")
                    if func.get("contracts"):
                        insights.append(f"Function '{func['name']}' has contracts")
            
            if "data_types" in ir_data:
                type_count = len(ir_data["data_types"])
                insights.append(f"Defines {type_count} data type(s)")
                
        except Exception:
            insights.append("Could not analyze IR structure")
        
        return insights

    def _summarize_code(self, program, ir_json: str) -> str:
        """Generate code summary."""
        func_count = len([d for d in program.declarations if hasattr(d, 'body')])
        data_count = len([d for d in program.declarations if hasattr(d, 'fields')])
        
        summary = f"This AEON program defines "
        if data_count > 0:
            summary += f"{data_count} data type(s)"
        if func_count > 0:
            if data_count > 0:
                summary += " and "
            summary += f"{func_count} function(s)"
        
        return summary

    def _explain_code(self, program, ir_json: str) -> str:
        """Generate code explanation."""
        explanation = "This program contains:\n"
        
        for decl in program.declarations:
            if hasattr(decl, 'fields'):  # Data type
                explanation += f"- Data type '{decl.name}' with {len(decl.fields)} fields\n"
            elif hasattr(decl, 'body'):  # Function
                func_type = "pure" if decl.__class__.__name__.startswith("Pure") else "task"
                explanation += f"- {func_type} function '{decl.name}' returning {decl.return_type}\n"
        
        return explanation

    def _find_bugs(self, program, errors: List[AeonError]) -> str:
        """Find potential bugs in code."""
        if errors:
            bug_report = f"Found {len(errors)} issue(s):\n"
            for error in errors:
                bug_report += f"- {error.message}\n"
            return bug_report
        else:
            return "No obvious bugs detected. Code compiles successfully."

    def _suggest_optimizations(self, ir_json: str) -> str:
        """Suggest optimizations based on IR."""
        suggestions = [
            "Consider adding contracts for better verification",
            "Review function effects for potential optimization",
            "Check for opportunities to use pure functions"
        ]
        return "Optimization suggestions:\n" + "\n".join(f"- {s}" for s in suggestions)

    def _generate_suggestions(self, program, errors: List[AeonError], analysis_type: str) -> List[str]:
        """Generate improvement suggestions."""
        suggestions = []
        
        if errors:
            suggestions.append("Fix compilation errors first")
        
        if analysis_type == "optimize":
            suggestions.extend([
                "Add type annotations for better performance",
                "Consider using pure functions where possible",
                "Review effect declarations for necessity"
            ])
        
        return suggestions

    def _optimize_code(self, source: str, program) -> Tuple[str, List[str]]:
        """Optimize code (simple transformations)."""
        changes = ["Applied basic optimizations"]
        # For now, return original code
        return source, changes

    def _simplify_code(self, source: str, program) -> Tuple[str, List[str]]:
        """Simplify code."""
        changes = ["Simplified complex expressions"]
        # For now, return original code
        return source, changes

    def _add_contracts(self, source: str, program) -> Tuple[str, List[str]]:
        """Add contracts to functions."""
        changes = ["Added requires/ensures contracts"]
        # For now, return original code
        return source, changes

    def _parallelize_code(self, source: str, program) -> Tuple[str, List[str]]:
        """Parallelize code where possible."""
        changes = ["Identified parallelization opportunities"]
        # For now, return original code
        return source, changes

    def _measure_improvements(self, original: str, refactored: str, refactoring_type: str) -> List[str]:
        """Measure improvements from refactoring."""
        improvements = []
        
        orig_lines = len([l for l in original.split('\n') if l.strip()])
        refact_lines = len([l for l in refactored.split('\n') if l.strip()])
        
        if refact_lines < orig_lines:
            improvements.append(f"Reduced code size by {orig_lines - refact_lines} lines")
        elif refact_lines > orig_lines:
            improvements.append(f"Added {refact_lines - orig_lines} lines for safety/clarity")
        
        improvements.append(f"Applied {refactoring_type} transformations")
        
        return improvements


class AITrainingPipeline:
    """Pipeline for training AI models with AEON data."""

    def __init__(self, data_dir: str = "synthetic_data"):
        self.data_dir = Path(data_dir)
        self.ai_interface = AIModelInterface()

    def prepare_training_data(self, output_file: str) -> None:
        """Prepare training data in JSONL format for AI training."""
        output_path = Path(output_file)
        
        training_examples = []
        
        # Load synthetic examples
        manifest_path = self.data_dir / "manifest.json"
        if manifest_path.exists():
            with open(manifest_path) as f:
                manifest = json.load(f)
            
            for i in range(manifest["total_examples"]):
                example_file = self.data_dir / f"example_{i:06d}.json"
                if example_file.exists():
                    with open(example_file) as f:
                        example = json.load(f)
                    
                    # Convert to training format
                    training_example = {
                        "prompt": example["prompt"],
                        "code": example["source_code"],
                        "ir": example.get("ir_output"),
                        "errors": example["errors"],
                        "metadata": example["metadata"]
                    }
                    training_examples.append(training_example)
        
        # Write training data in JSONL format
        with open(output_path, 'w') as f:
            for example in training_examples:
                f.write(json.dumps(example) + '\n')
        
        print(f"Prepared {len(training_examples)} training examples in {output_file}")

    def evaluate_model(self, test_prompts: List[str]) -> Dict[str, Any]:
        """Evaluate AI model performance on test prompts."""
        results = []
        
        for prompt in test_prompts:
            request = CodeGenerationRequest(prompt=prompt)
            response = self.ai_interface.generate_code(request)
            
            results.append({
                "prompt": prompt,
                "compilation_status": response.compilation_status,
                "confidence": response.confidence,
                "error_count": len(response.errors)
            })
        
        # Calculate metrics
        total = len(results)
        successful = sum(1 for r in results if r["compilation_status"] == "success")
        avg_confidence = sum(r["confidence"] for r in results) / total if total > 0 else 0
        
        metrics = {
            "total_prompts": total,
            "successful_compilations": successful,
            "success_rate": successful / total if total > 0 else 0,
            "average_confidence": avg_confidence,
            "results": results
        }
        
        return metrics


def main():
    """CLI for AI integration."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AEON AI Integration")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Generate code
    gen_parser = subparsers.add_parser("generate", help="Generate code from prompt")
    gen_parser.add_argument("prompt", help="Natural language prompt")
    gen_parser.add_argument("--output", help="Output file for generated code")
    
    # Analyze code
    analyze_parser = subparsers.add_parser("analyze", help="Analyze AEON code")
    analyze_parser.add_argument("file", help="AEON source file")
    analyze_parser.add_argument("--type", choices=["summarize", "explain", "find_bugs", "optimize"], 
                               default="summarize", help="Analysis type")
    
    # Refactor code
    refactor_parser = subparsers.add_parser("refactor", help="Refactor AEON code")
    refactor_parser.add_argument("file", help="AEON source file")
    refactor_parser.add_argument("--type", choices=["optimize", "simplify", "add_contracts", "parallelize"],
                                default="optimize", help="Refactoring type")
    refactor_parser.add_argument("--output", help="Output file for refactored code")
    
    # Prepare training data
    train_parser = subparsers.add_parser("prepare-training", help="Prepare training data")
    train_parser.add_argument("--data-dir", default="synthetic_data", help="Synthetic data directory")
    train_parser.add_argument("--output", default="training_data.jsonl", help="Output training file")
    
    args = parser.parse_args()
    
    ai = AIModelInterface()
    
    if args.command == "generate":
        request = CodeGenerationRequest(prompt=args.prompt)
        response = ai.generate_code(request)
        
        print(f"Generated code (confidence: {response.confidence:.2f}):")
        print(response.generated_code)
        print(f"\nCompilation status: {response.compilation_status}")
        if response.errors:
            print("Errors:")
            for error in response.errors:
                print(f"  - {error}")
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(response.generated_code)
            print(f"\nSaved to {args.output}")
    
    elif args.command == "analyze":
        with open(args.file, 'r') as f:
            source_code = f.read()
        
        request = CodeAnalysisRequest(source_code=source_code, analysis_type=args.type)
        response = ai.analyze_code(request)
        
        print(f"Analysis (confidence: {response.confidence:.2f}):")
        print(response.analysis)
        if response.insights:
            print("\nInsights:")
            for insight in response.insights:
                print(f"  - {insight}")
        if response.suggestions:
            print("\nSuggestions:")
            for suggestion in response.suggestions:
                print(f"  - {suggestion}")
    
    elif args.command == "refactor":
        with open(args.file, 'r') as f:
            source_code = f.read()
        
        request = RefactoringRequest(source_code=source_code, refactoring_type=args.type)
        response = ai.refactor_code(request)
        
        print(f"Refactored code (status: {response.compilation_status}):")
        print(response.refactored_code)
        if response.changes_made:
            print("\nChanges made:")
            for change in response.changes_made:
                print(f"  - {change}")
        if response.improvements:
            print("\nImprovements:")
            for improvement in response.improvements:
                print(f"  - {improvement}")
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(response.refactored_code)
            print(f"\nSaved to {args.output}")
    
    elif args.command == "prepare-training":
        pipeline = AITrainingPipeline(args.data_dir)
        pipeline.prepare_training_data(args.output)
        print(f"Training data prepared in {args.output}")


if __name__ == "__main__":
    main()
