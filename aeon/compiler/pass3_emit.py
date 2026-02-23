"""AEON Pass 3 — Emit.

Flat IR → LLVM IR via llvmlite. All optimization (vectorization, loop unrolling,
inlining, cache layout) is handled by LLVM's mature backend.
We write zero backend optimization code.
"""

from __future__ import annotations

from typing import Optional, Any

from aeon.ir import IRModule, IRFunction, IRNode, IROpKind

try:
    from llvmlite import ir as llvm_ir
    from llvmlite import binding as llvm_binding
    HAS_LLVMLITE = True
except ImportError:
    HAS_LLVMLITE = False


# ---------------------------------------------------------------------------
# LLVM type mapping
# ---------------------------------------------------------------------------

def _get_llvm_type(type_name: str) -> Any:
    """Map AEON type name to llvmlite IR type."""
    if not HAS_LLVMLITE:
        return None
    mapping = {
        "Int": llvm_ir.IntType(64),
        "Float": llvm_ir.DoubleType(),
        "Bool": llvm_ir.IntType(1),
        "Void": llvm_ir.VoidType(),
        "String": llvm_ir.IntType(8).as_pointer(),
        "UUID": llvm_ir.IntType(8).as_pointer(),
        "Email": llvm_ir.IntType(8).as_pointer(),
        "USD": llvm_ir.IntType(64),
        "Error": llvm_ir.IntType(64),
    }
    return mapping.get(type_name, llvm_ir.IntType(64))


class LLVMEmitter:
    """Emits LLVM IR from flat IR."""

    def __init__(self):
        if not HAS_LLVMLITE:
            raise RuntimeError("llvmlite is required for Pass 3 (Emit). Install with: pip install llvmlite")

        self.module: Optional[Any] = None
        self._builder: Optional[Any] = None
        self._func: Optional[Any] = None
        self._values: dict[int, Any] = {}
        self._named_values: dict[str, Any] = {}

    def emit_module(self, ir_module: IRModule) -> str:
        """Emit LLVM IR for an entire module. Returns LLVM IR string."""
        self.module = llvm_ir.Module(name=ir_module.name)
        self.module.triple = llvm_binding.get_default_triple()

        # Emit struct types for data definitions
        for dt in ir_module.data_types:
            self._emit_struct_type(dt)

        # Emit functions
        for func in ir_module.functions:
            self._emit_function(func)

        return str(self.module)

    def _emit_struct_type(self, dt) -> None:
        """Emit an LLVM struct type for a data definition."""
        field_types = []
        for fname, ftype in dt.fields:
            field_types.append(_get_llvm_type(ftype))
        struct = self.module.context.get_identified_type(dt.name)
        struct.set_body(*field_types)

    def _emit_function(self, func: IRFunction) -> None:
        """Emit LLVM IR for a single function."""
        # Build function type
        param_types = []
        for p in func.params:
            param_types.append(_get_llvm_type(p.type_name))

        ret_type = _get_llvm_type(func.return_type)
        if isinstance(ret_type, llvm_ir.VoidType):
            fn_type = llvm_ir.FunctionType(ret_type, param_types)
        else:
            fn_type = llvm_ir.FunctionType(ret_type, param_types)

        self._func = llvm_ir.Function(self.module, fn_type, name=func.name)

        # Mark pure functions
        if func.is_pure:
            self._func.attributes.add("readonly")

        # Create entry block
        block = self._func.append_basic_block(name="entry")
        self._builder = llvm_ir.IRBuilder(block)
        self._values = {}
        self._named_values = {}

        # Map parameters
        for i, param_node in enumerate(func.params):
            self._func.args[i].name = param_node.label
            self._values[param_node.id] = self._func.args[i]
            self._named_values[param_node.label] = self._func.args[i]

        # Process nodes (skip params, func_start, func_end)
        has_terminator = False
        for node in func.nodes:
            if node.op in (IROpKind.PARAM, IROpKind.FUNC_START, IROpKind.FUNC_END):
                continue
            if node.op in (IROpKind.BLOCK_START, IROpKind.BLOCK_END):
                continue

            if self._builder.block.is_terminated:
                has_terminator = True
                continue

            self._emit_node(node, func)

        # Add implicit return if needed
        if not self._builder.block.is_terminated:
            if isinstance(ret_type, llvm_ir.VoidType):
                self._builder.ret_void()
            else:
                self._builder.ret(llvm_ir.Constant(ret_type, 0))

    def _emit_node(self, node: IRNode, func: IRFunction) -> None:
        """Emit LLVM IR for a single IR node."""
        if node.op == IROpKind.CONST_INT:
            val = llvm_ir.Constant(llvm_ir.IntType(64), node.value or 0)
            self._values[node.id] = val

        elif node.op == IROpKind.CONST_FLOAT:
            val = llvm_ir.Constant(llvm_ir.DoubleType(), node.value or 0.0)
            self._values[node.id] = val

        elif node.op == IROpKind.CONST_BOOL:
            val = llvm_ir.Constant(llvm_ir.IntType(1), 1 if node.value else 0)
            self._values[node.id] = val

        elif node.op == IROpKind.CONST_STRING:
            # Create global string constant
            s = node.value or ""
            str_val = bytearray((s + "\0").encode("utf-8"))
            str_type = llvm_ir.ArrayType(llvm_ir.IntType(8), len(str_val))
            global_str = llvm_ir.GlobalVariable(self.module, str_type, name=f".str.{node.id}")
            global_str.initializer = llvm_ir.Constant(str_type, str_val)
            global_str.global_constant = True
            ptr = self._builder.bitcast(global_str, llvm_ir.IntType(8).as_pointer())
            self._values[node.id] = ptr

        elif node.op == IROpKind.VAR_REF:
            if node.label in self._named_values:
                self._values[node.id] = self._named_values[node.label]
            else:
                self._values[node.id] = llvm_ir.Constant(llvm_ir.IntType(64), 0)

        elif node.op == IROpKind.LET_BIND:
            if node.inputs and node.inputs[0] in self._values:
                val = self._values[node.inputs[0]]
                self._values[node.id] = val
                if node.label:
                    self._named_values[node.label] = val

        elif node.op == IROpKind.ASSIGN:
            if node.inputs and node.inputs[0] in self._values:
                val = self._values[node.inputs[0]]
                self._values[node.id] = val
                if node.label:
                    self._named_values[node.label] = val

        elif node.op in (IROpKind.ADD, IROpKind.SUB, IROpKind.MUL, IROpKind.DIV, IROpKind.MOD):
            self._emit_arithmetic(node)

        elif node.op == IROpKind.NEG:
            if node.inputs and node.inputs[0] in self._values:
                val = self._values[node.inputs[0]]
                zero = llvm_ir.Constant(val.type, 0)
                self._values[node.id] = self._builder.sub(zero, val, name=f"neg.{node.id}")

        elif node.op in (IROpKind.EQ, IROpKind.NEQ, IROpKind.LT, IROpKind.GT, IROpKind.LTE, IROpKind.GTE):
            self._emit_comparison(node)

        elif node.op == IROpKind.AND:
            if len(node.inputs) >= 2:
                left = self._get_value(node.inputs[0])
                right = self._get_value(node.inputs[1])
                if left and right:
                    self._values[node.id] = self._builder.and_(left, right, name=f"and.{node.id}")

        elif node.op == IROpKind.OR:
            if len(node.inputs) >= 2:
                left = self._get_value(node.inputs[0])
                right = self._get_value(node.inputs[1])
                if left and right:
                    self._values[node.id] = self._builder.or_(left, right, name=f"or.{node.id}")

        elif node.op == IROpKind.NOT:
            if node.inputs and node.inputs[0] in self._values:
                val = self._values[node.inputs[0]]
                self._values[node.id] = self._builder.not_(val, name=f"not.{node.id}")

        elif node.op == IROpKind.CALL:
            self._emit_call(node)

        elif node.op == IROpKind.METHOD_CALL:
            # For now, method calls are emitted as regular calls
            self._emit_call(node)

        elif node.op == IROpKind.RETURN:
            if node.inputs and node.inputs[0] in self._values:
                val = self._values[node.inputs[0]]
                ret_type = _get_llvm_type(func.return_type)
                if isinstance(ret_type, llvm_ir.VoidType):
                    self._builder.ret_void()
                else:
                    # Cast if needed
                    val = self._coerce(val, ret_type)
                    self._builder.ret(val)
            else:
                ret_type = _get_llvm_type(func.return_type)
                if isinstance(ret_type, llvm_ir.VoidType):
                    self._builder.ret_void()
                else:
                    self._builder.ret(llvm_ir.Constant(ret_type, 0))

        elif node.op == IROpKind.FIELD_GET:
            # Simplified field access — would need struct GEP in full impl
            self._values[node.id] = llvm_ir.Constant(llvm_ir.IntType(64), 0)

        elif node.op == IROpKind.CONSTRUCT:
            # Simplified struct construction
            self._values[node.id] = llvm_ir.Constant(llvm_ir.IntType(64), 0)

    def _emit_arithmetic(self, node: IRNode) -> None:
        if len(node.inputs) < 2:
            return
        left = self._get_value(node.inputs[0])
        right = self._get_value(node.inputs[1])
        if left is None or right is None:
            self._values[node.id] = llvm_ir.Constant(llvm_ir.IntType(64), 0)
            return

        # Ensure types match
        right = self._coerce(right, left.type)

        name = f"op.{node.id}"
        is_float = isinstance(left.type, llvm_ir.DoubleType)

        if node.op == IROpKind.ADD:
            self._values[node.id] = self._builder.fadd(left, right, name=name) if is_float else self._builder.add(left, right, name=name)
        elif node.op == IROpKind.SUB:
            self._values[node.id] = self._builder.fsub(left, right, name=name) if is_float else self._builder.sub(left, right, name=name)
        elif node.op == IROpKind.MUL:
            self._values[node.id] = self._builder.fmul(left, right, name=name) if is_float else self._builder.mul(left, right, name=name)
        elif node.op == IROpKind.DIV:
            self._values[node.id] = self._builder.fdiv(left, right, name=name) if is_float else self._builder.sdiv(left, right, name=name)
        elif node.op == IROpKind.MOD:
            self._values[node.id] = self._builder.srem(left, right, name=name)

    def _emit_comparison(self, node: IRNode) -> None:
        if len(node.inputs) < 2:
            return
        left = self._get_value(node.inputs[0])
        right = self._get_value(node.inputs[1])
        if left is None or right is None:
            self._values[node.id] = llvm_ir.Constant(llvm_ir.IntType(1), 0)
            return

        right = self._coerce(right, left.type)
        name = f"cmp.{node.id}"
        is_float = isinstance(left.type, llvm_ir.DoubleType)

        cmp_map = {
            IROpKind.EQ: ("==", "=="),
            IROpKind.NEQ: ("!=", "!="),
            IROpKind.LT: ("<", "<"),
            IROpKind.GT: (">", ">"),
            IROpKind.LTE: ("<=", "<="),
            IROpKind.GTE: (">=", ">="),
        }
        int_op, float_op = cmp_map[node.op]

        if is_float:
            self._values[node.id] = self._builder.fcmp_ordered(float_op, left, right, name=name)
        else:
            self._values[node.id] = self._builder.icmp_signed(int_op, left, right, name=name)

    def _emit_call(self, node: IRNode) -> None:
        """Emit a function call."""
        callee_name = node.label
        if not callee_name:
            self._values[node.id] = llvm_ir.Constant(llvm_ir.IntType(64), 0)
            return

        # Look up function in module
        callee = None
        for fn in self.module.functions:
            if fn.name == callee_name:
                callee = fn
                break

        if callee is None:
            # External function — declare it
            arg_types = []
            for inp in node.inputs:
                val = self._get_value(inp)
                if val:
                    arg_types.append(val.type)
                else:
                    arg_types.append(llvm_ir.IntType(64))
            fn_type = llvm_ir.FunctionType(llvm_ir.IntType(64), arg_types)
            callee = llvm_ir.Function(self.module, fn_type, name=callee_name)

        args = []
        for i, inp in enumerate(node.inputs):
            val = self._get_value(inp)
            if val:
                if i < len(callee.args):
                    val = self._coerce(val, callee.args[i].type)
                args.append(val)

        if isinstance(callee.return_type, llvm_ir.VoidType):
            self._builder.call(callee, args)
            self._values[node.id] = llvm_ir.Constant(llvm_ir.IntType(64), 0)
        else:
            self._values[node.id] = self._builder.call(callee, args, name=f"call.{node.id}")

    def _get_value(self, node_id: int) -> Optional[Any]:
        return self._values.get(node_id)

    def _coerce(self, val: Any, target_type: Any) -> Any:
        """Coerce a value to the target type if needed."""
        if val.type == target_type:
            return val
        # Int to Float
        if isinstance(val.type, llvm_ir.IntType) and isinstance(target_type, llvm_ir.DoubleType):
            return self._builder.sitofp(val, target_type)
        # Float to Int
        if isinstance(val.type, llvm_ir.DoubleType) and isinstance(target_type, llvm_ir.IntType):
            return self._builder.fptosi(val, target_type)
        # Int width conversions
        if isinstance(val.type, llvm_ir.IntType) and isinstance(target_type, llvm_ir.IntType):
            if val.type.width < target_type.width:
                return self._builder.sext(val, target_type)
            elif val.type.width > target_type.width:
                return self._builder.trunc(val, target_type)
        return val


# ---------------------------------------------------------------------------
# Compilation to object file / binary
# ---------------------------------------------------------------------------

def _initialize_llvm() -> None:
    """Initialize LLVM target machinery."""
    if not HAS_LLVMLITE:
        return
    llvm_binding.initialize()
    llvm_binding.initialize_native_target()
    llvm_binding.initialize_native_asmprinter()


def compile_to_object(llvm_ir_str: str) -> bytes:
    """Compile LLVM IR string to native object code."""
    if not HAS_LLVMLITE:
        raise RuntimeError("llvmlite required")

    _initialize_llvm()
    mod = llvm_binding.parse_assembly(llvm_ir_str)
    mod.verify()

    target = llvm_binding.Target.from_default_triple()
    target_machine = target.create_target_machine(opt=3)  # O3 optimization
    return target_machine.emit_object(mod)


def compile_to_assembly(llvm_ir_str: str) -> str:
    """Compile LLVM IR string to native assembly."""
    if not HAS_LLVMLITE:
        raise RuntimeError("llvmlite required")

    _initialize_llvm()
    mod = llvm_binding.parse_assembly(llvm_ir_str)
    mod.verify()

    target = llvm_binding.Target.from_default_triple()
    target_machine = target.create_target_machine(opt=3)
    return target_machine.emit_assembly(mod)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def emit(ir_module: IRModule) -> str:
    """Run Pass 3: emit LLVM IR from flat IR. Returns LLVM IR string."""
    emitter = LLVMEmitter()
    return emitter.emit_module(ir_module)


def emit_and_compile(ir_module: IRModule, output_path: str) -> str:
    """Emit LLVM IR and compile to object file. Returns LLVM IR string."""
    llvm_ir_str = emit(ir_module)

    obj_code = compile_to_object(llvm_ir_str)
    obj_path = output_path + ".o"
    with open(obj_path, "wb") as f:
        f.write(obj_code)

    return llvm_ir_str
