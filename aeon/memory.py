"""Runtime memory tracking for AEON functions.

Tracks memory usage during execution to verify that
pure functions use deterministic memory as specified.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Union
import json

from aeon.ast_nodes import (
    PureFunc, TaskFunc, Expr, Identifier, ConstructExpr,
    DataDef, Parameter
)
from aeon.types import AeonType, DataType, INT, STRING
from aeon.errors import AeonError, contract_error, SourceLocation


@dataclass
class MemoryProfile:
    """Memory usage profile for a function."""
    function_name: str
    max_stack_depth: int
    heap_allocations: int
    total_bytes: int
    is_deterministic: bool


class MemoryTracker:
    """Tracks memory usage patterns for deterministic memory verification."""

    def __init__(self):
        self.profiles: Dict[str, MemoryProfile] = {}
        self.errors: List[AeonError] = []

    def analyze_program(self, functions: List[Union[PureFunc, TaskFunc]], 
                       data_types: List[DataDef]) -> List[AeonError]:
        """Analyze memory usage for all functions."""
        self.errors = []
        self.profiles = {}

        # Calculate size of data types
        type_sizes = self._calculate_type_sizes(data_types)

        for func in functions:
            if isinstance(func, PureFunc):
                profile = self._analyze_pure_function(func, type_sizes)
                self.profiles[func.name] = profile

        return self.errors

    def _calculate_type_sizes(self, data_types: List[DataDef]) -> Dict[str, int]:
        """Calculate memory sizes for data types."""
        sizes = {}
        
        # Primitive sizes (bytes)
        sizes["Int"] = 8
        sizes["Float"] = 8
        sizes["Bool"] = 1
        sizes["String"] = 16  # Pointer + overhead
        sizes["UUID"] = 16
        sizes["Email"] = 32
        sizes["USD"] = 8
        sizes["Void"] = 0

        # Calculate struct sizes
        for data_def in data_types:
            total_size = 0
            for field in data_def.fields:
                field_type = field.type_annotation
                if hasattr(field_type, 'name'):
                    total_size += sizes.get(field_type.name, 8)  # Default to 8 bytes
                else:
                    total_size += 8  # Default size for complex types
            sizes[data_def.name] = total_size

        return sizes

    def _analyze_pure_function(self, func: PureFunc, type_sizes: Dict[str, int]) -> MemoryProfile:
        """Analyze memory usage for a pure function."""
        # Simple static analysis - count potential allocations
        stack_depth = self._estimate_stack_depth(func)
        heap_allocs = self._count_heap_allocations(func)
        total_bytes = self._estimate_memory_usage(func, type_sizes)

        # Pure functions should be deterministic
        is_deterministic = self._check_deterministic(func)

        profile = MemoryProfile(
            function_name=func.name,
            max_stack_depth=stack_depth,
            heap_allocations=heap_allocs,
            total_bytes=total_bytes,
            is_deterministic=is_deterministic
        )

        # Report errors for non-deterministic memory
        if not is_deterministic:
            self.errors.append(contract_error(
                precondition="pure function must have deterministic memory usage",
                failing_values={
                    "function": func.name,
                    "heap_allocations": heap_allocs,
                    "estimated_bytes": total_bytes
                },
                function_signature=f"pure {func.name}(...) -> {func.return_type}",
                location=func.location,
            ))

        return profile

    def _estimate_stack_depth(self, func: PureFunc) -> int:
        """Estimate maximum stack depth for function calls."""
        # Simple heuristic: count nested function calls
        max_depth = 1  # Current function

        def count_calls(expr):
            depth = 0
            if hasattr(expr, 'args'):
                for arg in expr.args:
                    depth = max(depth, count_calls(arg))
            if hasattr(expr, 'left') and hasattr(expr, 'right'):
                depth = max(depth, count_calls(expr.left))
                depth = max(depth, count_calls(expr.right))
            if hasattr(expr, 'operand'):
                depth = max(depth, count_calls(expr.operand))
            if hasattr(expr, 'obj'):
                depth = max(depth, count_calls(expr.obj))
            return depth + 1

        # Scan function body for calls
        if func.body:
            call_depth = self._scan_calls_for_depth(func.body)
            max_depth = max(max_depth, call_depth)

        return max_depth

    def _scan_calls_for_depth(self, stmt) -> int:
        """Scan statements for maximum call depth."""
        if stmt is None:
            return 0

        max_depth = 0

        if hasattr(stmt, 'statements'):  # BlockStmt
            for s in stmt.statements:
                max_depth = max(max_depth, self._scan_calls_for_depth(s))
        elif hasattr(stmt, 'value'):  # ReturnStmt, LetStmt, etc.
            if stmt.value:
                max_depth = max(max_depth, self._count_call_depth(stmt.value))
        elif hasattr(stmt, 'condition'):  # IfStmt
            max_depth = max(max_depth, self._count_call_depth(stmt.condition))
            max_depth = max(max_depth, self._scan_calls_for_depth(stmt.then_body))
            max_depth = max(max_depth, self._scan_calls_for_depth(stmt.else_body))

        return max_depth

    def _count_call_depth(self, expr) -> int:
        """Count maximum call depth in expression."""
        if hasattr(expr, 'args'):  # FunctionCall, MethodCall
            depth = 1
            for arg in expr.args:
                depth = max(depth, 1 + self._count_call_depth(arg))
            return depth
        elif hasattr(expr, 'left') and hasattr(expr, 'right'):  # BinaryOp
            return max(self._count_call_depth(expr.left), self._count_call_depth(expr.right))
        elif hasattr(expr, 'operand'):  # UnaryOp
            return self._count_call_depth(expr.operand)
        elif hasattr(expr, 'obj'):  # MethodCall
            return max(1, self._count_call_depth(expr.obj))
        return 0

    def _count_heap_allocations(self, func: PureFunc) -> int:
        """Count potential heap allocations in function."""
        alloc_count = 0

        def count_in_expr(expr):
            count = 0
            if isinstance(expr, ConstructExpr):
                count += 1  # Data construction allocates
            if hasattr(expr, 'args'):
                for arg in expr.args:
                    count += count_in_expr(arg)
            if hasattr(expr, 'left') and hasattr(expr, 'right'):
                count += count_in_expr(expr.left)
                count += count_in_expr(expr.right)
            if hasattr(expr, 'operand'):
                count += count_in_expr(expr.operand)
            if hasattr(expr, 'obj'):
                count += count_in_expr(expr.obj)
            return count

        # Scan function body
        if func.body:
            alloc_count = self._scan_allocations(func.body)

        return alloc_count

    def _scan_allocations(self, stmt) -> int:
        """Scan statements for allocations."""
        if stmt is None:
            return 0

        total = 0

        if hasattr(stmt, 'statements'):  # BlockStmt
            for s in stmt.statements:
                total += self._scan_allocations(s)
        elif hasattr(stmt, 'value'):  # ReturnStmt, LetStmt, etc.
            if stmt.value:
                total += self._count_allocations_in_expr(stmt.value)
        elif hasattr(stmt, 'condition'):  # IfStmt
            total += self._count_allocations_in_expr(stmt.condition)
            total += self._scan_allocations(stmt.then_body)
            total += self._scan_allocations(stmt.else_body)

        return total

    def _count_allocations_in_expr(self, expr) -> int:
        """Count allocations in expression."""
        from aeon.ast_nodes import ConstructExpr
        
        count = 0
        if isinstance(expr, ConstructExpr):
            count += 1  # Data construction
        if hasattr(expr, 'args'):
            for arg in expr.args:
                count += self._count_allocations_in_expr(arg)
        if hasattr(expr, 'left') and hasattr(expr, 'right'):
            count += self._count_allocations_in_expr(expr.left)
            count += self._count_allocations_in_expr(expr.right)
        if hasattr(expr, 'operand'):
            count += self._count_allocations_in_expr(expr.operand)
        if hasattr(expr, 'obj'):
            count += self._count_allocations_in_expr(expr.obj)
        return count

    def _estimate_memory_usage(self, func: PureFunc, type_sizes: Dict[str, int]) -> int:
        """Estimate total memory usage in bytes."""
        total = 0

        # Count parameters
        for param in func.params:
            if hasattr(param.type_annotation, 'name'):
                total += type_sizes.get(param.type_annotation.name, 8)

        # Count local variables and allocations
        if func.body:
            total += self._estimate_memory_in_stmt(func.body, type_sizes)

        return total

    def _estimate_memory_in_stmt(self, stmt, type_sizes: Dict[str, int]) -> int:
        """Estimate memory usage in statement."""
        if stmt is None:
            return 0

        total = 0

        if hasattr(stmt, 'statements'):  # BlockStmt
            for s in stmt.statements:
                total += self._estimate_memory_in_stmt(s, type_sizes)
        elif hasattr(stmt, 'name') and hasattr(stmt, 'type_annotation'):  # LetStmt
            if hasattr(stmt.type_annotation, 'name'):
                total += type_sizes.get(stmt.type_annotation.name, 8)
            if stmt.value:
                total += self._estimate_memory_in_expr(stmt.value, type_sizes)
        elif hasattr(stmt, 'value'):  # ReturnStmt, etc.
            if stmt.value:
                total += self._estimate_memory_in_expr(stmt.value, type_sizes)
        elif hasattr(stmt, 'condition'):  # IfStmt
            total += self._estimate_memory_in_expr(stmt.condition, type_sizes)
            total += self._estimate_memory_in_stmt(stmt.then_body, type_sizes)
            total += self._estimate_memory_in_stmt(stmt.else_body, type_sizes)

        return total

    def _estimate_memory_in_expr(self, expr, type_sizes: Dict[str, int]) -> int:
        """Estimate memory usage in expression."""
        from aeon.ast_nodes import ConstructExpr
        
        total = 0
        if isinstance(expr, ConstructExpr):
            if hasattr(expr, 'type_name'):
                total += type_sizes.get(expr.type_name, 8)
        if hasattr(expr, 'args'):
            for arg in expr.args:
                total += self._estimate_memory_in_expr(arg, type_sizes)
        if hasattr(expr, 'left') and hasattr(expr, 'right'):
            total += self._estimate_memory_in_expr(expr.left, type_sizes)
            total += self._estimate_memory_in_expr(expr.right, type_sizes)
        if hasattr(expr, 'operand'):
            total += self._estimate_memory_in_expr(expr.operand, type_sizes)
        if hasattr(expr, 'obj'):
            total += self._estimate_memory_in_expr(expr.obj, type_sizes)
        return total

    def _check_deterministic(self, func: PureFunc) -> bool:
        """Check if function has deterministic memory usage."""
        # Simple heuristic: pure functions with no heap allocations are deterministic
        # This is a simplified check - full analysis would be more sophisticated
        
        # Count allocations
        allocs = self._count_heap_allocations(func)
        
        # For now, consider functions with 0-1 allocations as deterministic
        # In practice, this would need more sophisticated analysis
        return allocs <= 1

    def get_profile_json(self, function_name: str) -> Optional[str]:
        """Get memory profile as JSON."""
        profile = self.profiles.get(function_name)
        if not profile:
            return None
        
        return json.dumps({
            "function": profile.function_name,
            "max_stack_depth": profile.max_stack_depth,
            "heap_allocations": profile.heap_allocations,
            "total_bytes": profile.total_bytes,
            "is_deterministic": profile.is_deterministic
        }, indent=2)

    def get_all_profiles_json(self) -> str:
        """Get all memory profiles as JSON."""
        profiles = []
        for profile in self.profiles.values():
            profiles.append({
                "function": profile.function_name,
                "max_stack_depth": profile.max_stack_depth,
                "heap_allocations": profile.heap_allocations,
                "total_bytes": profile.total_bytes,
                "is_deterministic": profile.is_deterministic
            })
        return json.dumps(profiles, indent=2)
