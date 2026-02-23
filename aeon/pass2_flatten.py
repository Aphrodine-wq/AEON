"""AEON Pass 2 — Flatten.

Lowers the AST to a typed flat IR (directed acyclic graph of data-flow operations).
No nesting. No ambiguity. This IR is what the AI model reasons about at inference time.
"""

from __future__ import annotations

from typing import Optional

from aeon.ast_nodes import (
    Program, Declaration, DataDef, EnumDef, PureFunc, TaskFunc,
    TraitDef, ImplBlock, TypeAlias, UseDecl,
    Statement, ReturnStmt, LetStmt, AssignStmt, ExprStmt,
    IfStmt, WhileStmt, ForStmt, UnsafeBlock, BreakStmt, ContinueStmt,
    Expr, IntLiteral, FloatLiteral, StringLiteral, BoolLiteral,
    Identifier, BinaryOp, UnaryOp, FunctionCall, FieldAccess,
    MethodCall, ListLiteral, ConstructExpr, MoveExpr, BorrowExpr,
    LambdaExpr, MatchExpr, PipeExpr, SpawnExpr, AwaitExpr,
    ContractClause,
)
from aeon.ir import IRModule, IRFunction, IRDataType, IRNode, IROpKind
from aeon.types import (
    TypeEnvironment, resolve_type_annotation,
    INT, FLOAT, STRING, BOOL, VOID,
)


class Flattener:
    """Lowers AST to flat IR."""

    def __init__(self):
        self._next_id = 0
        self._var_map: dict[str, int] = {}
        self._nodes: list[IRNode] = []
        self._env = TypeEnvironment()

    def _new_id(self) -> int:
        nid = self._next_id
        self._next_id += 1
        return nid

    def _emit(self, op: IROpKind, type_name: str = "Void",
              inputs: list[int] | None = None, value=None,
              label: str = "", metadata: dict | None = None) -> IRNode:
        node = IRNode(
            id=self._new_id(),
            op=op,
            type_name=type_name,
            inputs=inputs or [],
            value=value,
            label=label,
            metadata=metadata or {},
        )
        self._nodes.append(node)
        return node

    def flatten_program(self, program: Program) -> IRModule:
        """Flatten an entire program to IR."""
        module = IRModule(name=program.filename)

        for decl in program.declarations:
            if isinstance(decl, DataDef):
                module.data_types.append(self._flatten_data(decl))
            elif isinstance(decl, EnumDef):
                # Flatten enum as a data type with variant tags
                for v in decl.variants:
                    fields = [(f.name, str(f.type_annotation)) for f in v.fields]
                    module.data_types.append(IRDataType(
                        name=f"{decl.name}::{v.name}", fields=fields,
                    ))
            elif isinstance(decl, PureFunc):
                module.functions.append(self._flatten_func(decl, is_pure=True))
            elif isinstance(decl, TaskFunc):
                module.functions.append(self._flatten_func(decl, is_pure=False))
            elif isinstance(decl, TraitDef):
                for method in decl.methods:
                    is_pure = isinstance(method, PureFunc)
                    module.functions.append(self._flatten_func(method, is_pure=is_pure))
            elif isinstance(decl, ImplBlock):
                for method in decl.methods:
                    is_pure = isinstance(method, PureFunc)
                    module.functions.append(self._flatten_func(method, is_pure=is_pure))
            # TypeAlias and UseDecl don't produce IR

        return module

    def _flatten_data(self, data: DataDef) -> IRDataType:
        fields = []
        for f in data.fields:
            fields.append((f.name, str(f.type_annotation)))
        return IRDataType(name=data.name, fields=fields)

    def _flatten_func(self, func: PureFunc | TaskFunc, is_pure: bool) -> IRFunction:
        self._next_id = 0
        self._nodes = []
        self._var_map = {}

        # Emit function start
        self._emit(IROpKind.FUNC_START, label=func.name)

        # Emit params
        params: list[IRNode] = []
        for p in func.params:
            type_name = str(p.type_annotation) if p.type_annotation else "Void"
            node = self._emit(IROpKind.PARAM, type_name=type_name, label=p.name)
            self._var_map[p.name] = node.id
            params.append(node)

        # Flatten body
        for stmt in func.body:
            self._flatten_statement(stmt)

        # Emit function end
        self._emit(IROpKind.FUNC_END, label=func.name)

        # Build contracts dict
        contracts: dict = {}
        if func.requires:
            contracts["requires"] = [self._contract_to_str(c) for c in func.requires]
        if func.ensures:
            contracts["ensures"] = [self._contract_to_str(c) for c in func.ensures]

        ret_type = str(func.return_type) if func.return_type else "Void"
        effects = func.effects if isinstance(func, TaskFunc) else []

        return IRFunction(
            name=func.name,
            params=params,
            return_type=ret_type,
            nodes=list(self._nodes),
            is_pure=is_pure,
            effects=effects,
            contracts=contracts,
        )

    def _contract_to_str(self, clause: ContractClause) -> str:
        return f"{clause.kind}: {self._expr_to_str(clause.expr)}"

    def _expr_to_str(self, expr: Expr) -> str:
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, IntLiteral):
            return str(expr.value)
        if isinstance(expr, BoolLiteral):
            return str(expr.value).lower()
        if isinstance(expr, BinaryOp):
            return f"{self._expr_to_str(expr.left)} {expr.op} {self._expr_to_str(expr.right)}"
        if isinstance(expr, FieldAccess):
            return f"{self._expr_to_str(expr.obj)}.{expr.field_name}"
        if isinstance(expr, MethodCall):
            args = ", ".join(self._expr_to_str(a) for a in expr.args)
            return f"{self._expr_to_str(expr.obj)}.{expr.method_name}({args})"
        if isinstance(expr, UnaryOp):
            return f"{expr.op}{self._expr_to_str(expr.operand)}"
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                args = ", ".join(self._expr_to_str(a) for a in expr.args)
                return f"{expr.callee.name}({args})"
        return "<?>"

    # -------------------------------------------------------------------
    # Statements
    # -------------------------------------------------------------------

    def _flatten_statement(self, stmt: Statement) -> None:
        if isinstance(stmt, ReturnStmt):
            if stmt.value:
                val = self._flatten_expr(stmt.value)
                self._emit(IROpKind.RETURN, inputs=[val])
            else:
                self._emit(IROpKind.RETURN)

        elif isinstance(stmt, LetStmt):
            if stmt.value:
                val = self._flatten_expr(stmt.value)
                type_name = str(stmt.type_annotation) if stmt.type_annotation else "Void"
                node = self._emit(IROpKind.LET_BIND, type_name=type_name,
                                  inputs=[val], label=stmt.name)
                self._var_map[stmt.name] = node.id

        elif isinstance(stmt, AssignStmt):
            val = self._flatten_expr(stmt.value)
            if isinstance(stmt.target, Identifier):
                self._emit(IROpKind.ASSIGN, inputs=[val], label=stmt.target.name)
                self._var_map[stmt.target.name] = val

        elif isinstance(stmt, ExprStmt):
            self._flatten_expr(stmt.expr)

        elif isinstance(stmt, IfStmt):
            cond = self._flatten_expr(stmt.condition)
            then_start = self._emit(IROpKind.BLOCK_START, label="then")
            for s in stmt.then_body:
                self._flatten_statement(s)
            self._emit(IROpKind.BLOCK_END, label="then")

            if stmt.else_body:
                self._emit(IROpKind.BLOCK_START, label="else")
                for s in stmt.else_body:
                    self._flatten_statement(s)
                self._emit(IROpKind.BLOCK_END, label="else")

            self._emit(IROpKind.BRANCH, inputs=[cond, then_start.id])

        elif isinstance(stmt, WhileStmt):
            self._emit(IROpKind.BLOCK_START, label="while_header")
            cond = self._flatten_expr(stmt.condition)
            self._emit(IROpKind.BLOCK_START, label="while_body")
            for s in stmt.body:
                self._flatten_statement(s)
            self._emit(IROpKind.BLOCK_END, label="while_body")
            self._emit(IROpKind.BRANCH, inputs=[cond])
            self._emit(IROpKind.BLOCK_END, label="while_header")

        elif isinstance(stmt, ForStmt):
            self._emit(IROpKind.BLOCK_START, label="for_header")
            iter_id = self._flatten_expr(stmt.iterable)
            self._emit(IROpKind.BLOCK_START, label="for_body")
            for s in stmt.body:
                self._flatten_statement(s)
            self._emit(IROpKind.BLOCK_END, label="for_body")
            self._emit(IROpKind.BLOCK_END, label="for_header")

        elif isinstance(stmt, UnsafeBlock):
            self._emit(IROpKind.BLOCK_START, label="unsafe",
                       metadata={"unsafe": True})
            for s in stmt.body:
                self._flatten_statement(s)
            self._emit(IROpKind.BLOCK_END, label="unsafe")

    # -------------------------------------------------------------------
    # Expressions
    # -------------------------------------------------------------------

    def _flatten_expr(self, expr: Expr) -> int:
        if isinstance(expr, IntLiteral):
            return self._emit(IROpKind.CONST_INT, type_name="Int", value=expr.value).id

        if isinstance(expr, FloatLiteral):
            return self._emit(IROpKind.CONST_FLOAT, type_name="Float", value=expr.value).id

        if isinstance(expr, StringLiteral):
            return self._emit(IROpKind.CONST_STRING, type_name="String", value=expr.value).id

        if isinstance(expr, BoolLiteral):
            return self._emit(IROpKind.CONST_BOOL, type_name="Bool", value=expr.value).id

        if isinstance(expr, Identifier):
            if expr.name in self._var_map:
                return self._var_map[expr.name]
            return self._emit(IROpKind.VAR_REF, label=expr.name).id

        if isinstance(expr, MoveExpr):
            if expr.name in self._var_map:
                return self._var_map[expr.name]
            return self._emit(IROpKind.VAR_REF, label=expr.name, metadata={"move": True}).id

        if isinstance(expr, BorrowExpr):
            if expr.name in self._var_map:
                return self._var_map[expr.name]
            return self._emit(IROpKind.VAR_REF, label=expr.name, metadata={"borrow": True}).id

        if isinstance(expr, BinaryOp):
            left = self._flatten_expr(expr.left)
            right = self._flatten_expr(expr.right)
            op_map = {
                "+": IROpKind.ADD, "-": IROpKind.SUB,
                "*": IROpKind.MUL, "/": IROpKind.DIV, "%": IROpKind.MOD,
                "==": IROpKind.EQ, "!=": IROpKind.NEQ,
                "<": IROpKind.LT, ">": IROpKind.GT,
                "<=": IROpKind.LTE, ">=": IROpKind.GTE,
                "&&": IROpKind.AND, "||": IROpKind.OR,
            }
            ir_op = op_map.get(expr.op, IROpKind.ADD)
            type_name = "Bool" if expr.op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||") else "Int"
            return self._emit(ir_op, type_name=type_name, inputs=[left, right]).id

        if isinstance(expr, UnaryOp):
            operand = self._flatten_expr(expr.operand)
            if expr.op == "-":
                return self._emit(IROpKind.NEG, type_name="Int", inputs=[operand]).id
            if expr.op == "!":
                return self._emit(IROpKind.NOT, type_name="Bool", inputs=[operand]).id

        if isinstance(expr, FunctionCall):
            arg_ids = [self._flatten_expr(a) for a in expr.args]
            callee_name = ""
            if isinstance(expr.callee, Identifier):
                callee_name = expr.callee.name
            return self._emit(IROpKind.CALL, inputs=arg_ids, label=callee_name).id

        if isinstance(expr, MethodCall):
            obj_id = self._flatten_expr(expr.obj)
            arg_ids = [self._flatten_expr(a) for a in expr.args]
            return self._emit(IROpKind.METHOD_CALL,
                              inputs=[obj_id] + arg_ids,
                              label=expr.method_name).id

        if isinstance(expr, FieldAccess):
            obj_id = self._flatten_expr(expr.obj)
            return self._emit(IROpKind.FIELD_GET, inputs=[obj_id],
                              label=expr.field_name).id

        if isinstance(expr, ConstructExpr):
            field_ids = []
            for fname, fexpr in expr.fields.items():
                fid = self._flatten_expr(fexpr)
                field_ids.append(fid)
            return self._emit(IROpKind.CONSTRUCT, inputs=field_ids,
                              label=expr.type_name).id

        if isinstance(expr, ListLiteral):
            elem_ids = [self._flatten_expr(e) for e in expr.elements]
            return self._emit(IROpKind.LIST_NEW, inputs=elem_ids).id

        if isinstance(expr, PipeExpr):
            left = self._flatten_expr(expr.left)
            right = self._flatten_expr(expr.right)
            return self._emit(IROpKind.CALL, inputs=[left], label="pipe").id

        if isinstance(expr, MatchExpr):
            subj = self._flatten_expr(expr.subject)
            # Flatten each arm's body
            for arm in expr.arms:
                self._emit(IROpKind.BLOCK_START, label="match_arm")
                for s in arm.body:
                    self._flatten_statement(s)
                self._emit(IROpKind.BLOCK_END, label="match_arm")
            return self._emit(IROpKind.BRANCH, inputs=[subj], label="match").id

        if isinstance(expr, LambdaExpr):
            body_id = self._flatten_expr(expr.body)
            return self._emit(IROpKind.CALL, inputs=[body_id], label="lambda").id

        if isinstance(expr, SpawnExpr):
            call_id = self._flatten_expr(expr.call)
            return self._emit(IROpKind.CALL, inputs=[call_id],
                              label="spawn", metadata={"spawn": True}).id

        if isinstance(expr, AwaitExpr):
            expr_id = self._flatten_expr(expr.expr)
            return self._emit(IROpKind.CALL, inputs=[expr_id],
                              label="await", metadata={"await": True}).id

        return self._emit(IROpKind.CONST_INT, type_name="Void", value=0).id


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def flatten(program: Program) -> IRModule:
    """Run Pass 2: flatten AST to IR."""
    return Flattener().flatten_program(program)
