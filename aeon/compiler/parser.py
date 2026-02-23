"""AEON Parser — LL(1) recursive-descent parser.

Parses token stream into AST. Grammar is LL(1) — no backtracking, no ambiguity.
One canonical form for every construct.
"""

from __future__ import annotations

from typing import Optional

from aeon.lexer import Token, TokenType, tokenize
from aeon.ast_nodes import (
    Program, Declaration, DataDef, PureFunc, TaskFunc,
    FieldDef, Parameter, TypeAnnotation, ContractClause,
    Statement, ReturnStmt, LetStmt, AssignStmt, ExprStmt,
    IfStmt, WhileStmt, BreakStmt, ContinueStmt, UnsafeBlock,
    Expr, IntLiteral, FloatLiteral, StringLiteral, BoolLiteral,
    Identifier, BinaryOp, UnaryOp, FunctionCall, FieldAccess,
    MethodCall, ListLiteral, ConstructExpr, MoveExpr, BorrowExpr,
)
from aeon.errors import SourceLocation, syntax_error, CompileError


class Parser:
    """LL(1) recursive-descent parser for AEON."""

    def __init__(self, tokens: list[Token], filename: str = "<stdin>"):
        self.tokens = tokens
        self.pos = 0
        self.filename = filename

    def _current(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return self.tokens[-1]  # EOF

    def _peek(self) -> TokenType:
        return self._current().type

    def _peek_value(self) -> str:
        return self._current().value

    def _loc(self) -> SourceLocation:
        return self._current().location

    def _advance(self) -> Token:
        tok = self._current()
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return tok

    def _expect(self, tt: TokenType) -> Token:
        tok = self._current()
        if tok.type != tt:
            raise CompileError(syntax_error(
                f"Expected {tt.name}, got {tok.type.name} ('{tok.value}')",
                tok.location,
            ))
        return self._advance()

    def _match(self, tt: TokenType) -> Optional[Token]:
        if self._peek() == tt:
            return self._advance()
        return None

    # -------------------------------------------------------------------
    # Top-level
    # -------------------------------------------------------------------

    def parse(self) -> Program:
        decls: list[Declaration] = []
        while self._peek() != TokenType.EOF:
            decls.append(self._parse_declaration())
        return Program(declarations=decls, filename=self.filename)

    def _parse_declaration(self) -> Declaration:
        tt = self._peek()
        if tt == TokenType.DATA:
            return self._parse_data_def()
        elif tt == TokenType.PURE:
            return self._parse_pure_func()
        elif tt == TokenType.TASK:
            return self._parse_task_func()
        else:
            raise CompileError(syntax_error(
                f"Expected 'data', 'pure', or 'task', got '{self._current().value}'",
                self._loc(),
            ))

    # -------------------------------------------------------------------
    # data
    # -------------------------------------------------------------------

    def _parse_data_def(self) -> DataDef:
        loc = self._loc()
        self._expect(TokenType.DATA)
        name = self._expect(TokenType.IDENT).value
        self._expect(TokenType.LBRACE)
        fields: list[FieldDef] = []
        while self._peek() != TokenType.RBRACE:
            fields.append(self._parse_field_def())
        self._expect(TokenType.RBRACE)
        return DataDef(name=name, fields=fields, location=loc)

    def _parse_field_def(self) -> FieldDef:
        loc = self._loc()
        name = self._expect(TokenType.IDENT).value
        self._expect(TokenType.COLON)
        type_ann = self._parse_type_annotation()
        return FieldDef(name=name, type_annotation=type_ann, location=loc)

    # -------------------------------------------------------------------
    # Type annotations
    # -------------------------------------------------------------------

    def _parse_type_annotation(self) -> TypeAnnotation:
        loc = self._loc()
        name = self._expect(TokenType.IDENT).value
        generic_args: list[TypeAnnotation] = []
        if self._peek() == TokenType.LT:
            self._advance()
            generic_args.append(self._parse_type_annotation())
            while self._match(TokenType.COMMA):
                generic_args.append(self._parse_type_annotation())
            self._expect(TokenType.GT)
        return TypeAnnotation(name=name, generic_args=generic_args, location=loc)

    # -------------------------------------------------------------------
    # pure function
    # -------------------------------------------------------------------

    def _parse_pure_func(self) -> PureFunc:
        loc = self._loc()
        self._expect(TokenType.PURE)
        name = self._expect(TokenType.IDENT).value
        self._expect(TokenType.LPAREN)
        params = self._parse_param_list()
        self._expect(TokenType.RPAREN)

        return_type: Optional[TypeAnnotation] = None
        if self._match(TokenType.ARROW):
            return_type = self._parse_type_annotation()

        self._expect(TokenType.LBRACE)

        requires_clauses: list[ContractClause] = []
        ensures_clauses: list[ContractClause] = []

        while self._peek() in (TokenType.REQUIRES, TokenType.ENSURES):
            if self._peek() == TokenType.REQUIRES:
                requires_clauses.append(self._parse_contract_clause("requires"))
            elif self._peek() == TokenType.ENSURES:
                ensures_clauses.append(self._parse_contract_clause("ensures"))

        body = self._parse_body()
        self._expect(TokenType.RBRACE)

        return PureFunc(
            name=name, params=params, return_type=return_type,
            requires=requires_clauses, ensures=ensures_clauses,
            body=body, location=loc,
        )

    # -------------------------------------------------------------------
    # task function
    # -------------------------------------------------------------------

    def _parse_task_func(self) -> TaskFunc:
        loc = self._loc()
        self._expect(TokenType.TASK)
        name = self._expect(TokenType.IDENT).value
        self._expect(TokenType.LPAREN)
        params = self._parse_param_list()
        self._expect(TokenType.RPAREN)

        return_type: Optional[TypeAnnotation] = None
        if self._match(TokenType.ARROW):
            return_type = self._parse_type_annotation()

        self._expect(TokenType.LBRACE)

        requires_clauses: list[ContractClause] = []
        ensures_clauses: list[ContractClause] = []
        effects: list[str] = []

        while self._peek() in (TokenType.REQUIRES, TokenType.ENSURES, TokenType.EFFECTS):
            if self._peek() == TokenType.REQUIRES:
                requires_clauses.append(self._parse_contract_clause("requires"))
            elif self._peek() == TokenType.ENSURES:
                ensures_clauses.append(self._parse_contract_clause("ensures"))
            elif self._peek() == TokenType.EFFECTS:
                effects = self._parse_effects_clause()

        body = self._parse_body()
        self._expect(TokenType.RBRACE)

        return TaskFunc(
            name=name, params=params, return_type=return_type,
            requires=requires_clauses, ensures=ensures_clauses,
            effects=effects, body=body, location=loc,
        )

    # -------------------------------------------------------------------
    # Parameters
    # -------------------------------------------------------------------

    def _parse_param_list(self) -> list[Parameter]:
        params: list[Parameter] = []
        if self._peek() == TokenType.RPAREN:
            return params
        params.append(self._parse_parameter())
        while self._match(TokenType.COMMA):
            params.append(self._parse_parameter())
        return params

    def _parse_parameter(self) -> Parameter:
        loc = self._loc()
        name = self._expect(TokenType.IDENT).value
        self._expect(TokenType.COLON)
        type_ann = self._parse_type_annotation()
        return Parameter(name=name, type_annotation=type_ann, location=loc)

    # -------------------------------------------------------------------
    # Contract / Effects clauses
    # -------------------------------------------------------------------

    def _parse_contract_clause(self, kind: str) -> ContractClause:
        loc = self._loc()
        self._advance()  # consume requires/ensures keyword
        self._expect(TokenType.COLON)
        expr = self._parse_expression()
        return ContractClause(kind=kind, expr=expr, location=loc)

    def _parse_effects_clause(self) -> list[str]:
        self._expect(TokenType.EFFECTS)
        self._expect(TokenType.COLON)
        self._expect(TokenType.LBRACKET)
        effects: list[str] = []
        if self._peek() != TokenType.RBRACKET:
            effect_name = self._expect(TokenType.IDENT).value
            if self._match(TokenType.DOT):
                effect_name += "." + self._expect(TokenType.IDENT).value
            effects.append(effect_name)
            while self._match(TokenType.COMMA):
                ename = self._expect(TokenType.IDENT).value
                if self._match(TokenType.DOT):
                    ename += "." + self._expect(TokenType.IDENT).value
                effects.append(ename)
        self._expect(TokenType.RBRACKET)
        return effects

    # -------------------------------------------------------------------
    # Body (list of statements)
    # -------------------------------------------------------------------

    def _parse_body(self) -> list[Statement]:
        stmts: list[Statement] = []
        while self._peek() not in (TokenType.RBRACE, TokenType.EOF):
            stmts.append(self._parse_statement())
        return stmts

    # -------------------------------------------------------------------
    # Statements
    # -------------------------------------------------------------------

    def _parse_statement(self) -> Statement:
        tt = self._peek()

        if tt == TokenType.RETURN:
            return self._parse_return()
        elif tt == TokenType.LET:
            return self._parse_let()
        elif tt == TokenType.IF:
            return self._parse_if()
        elif tt == TokenType.WHILE:
            return self._parse_while()
        elif tt == TokenType.BREAK:
            loc = self._loc()
            self._advance()
            return BreakStmt(location=loc)
        elif tt == TokenType.CONTINUE:
            loc = self._loc()
            self._advance()
            return ContinueStmt(location=loc)
        elif tt == TokenType.UNSAFE:
            return self._parse_unsafe_block()
        else:
            return self._parse_expr_or_assign_stmt()

    def _parse_return(self) -> ReturnStmt:
        loc = self._loc()
        self._expect(TokenType.RETURN)
        value: Optional[Expr] = None
        if self._peek() not in (TokenType.RBRACE, TokenType.EOF):
            value = self._parse_expression()
        return ReturnStmt(value=value, location=loc)

    def _parse_let(self) -> LetStmt:
        loc = self._loc()
        self._expect(TokenType.LET)
        mutable = bool(self._match(TokenType.MUT))
        name = self._expect(TokenType.IDENT).value
        type_ann: Optional[TypeAnnotation] = None
        if self._match(TokenType.COLON):
            type_ann = self._parse_type_annotation()
        value: Optional[Expr] = None
        if self._match(TokenType.ASSIGN):
            value = self._parse_expression()
        return LetStmt(name=name, type_annotation=type_ann, value=value, mutable=mutable, location=loc)

    def _parse_if(self) -> IfStmt:
        loc = self._loc()
        self._expect(TokenType.IF)
        condition = self._parse_expression()
        self._expect(TokenType.LBRACE)
        then_body = self._parse_body()
        self._expect(TokenType.RBRACE)
        else_body: list[Statement] = []
        if self._match(TokenType.ELSE):
            if self._peek() == TokenType.IF:
                else_body = [self._parse_if()]
            else:
                self._expect(TokenType.LBRACE)
                else_body = self._parse_body()
                self._expect(TokenType.RBRACE)
        return IfStmt(condition=condition, then_body=then_body, else_body=else_body, location=loc)

    def _parse_while(self) -> WhileStmt:
        loc = self._loc()
        self._expect(TokenType.WHILE)
        condition = self._parse_expression()
        self._expect(TokenType.LBRACE)
        body = self._parse_body()
        self._expect(TokenType.RBRACE)
        return WhileStmt(condition=condition, body=body, location=loc)

    def _parse_unsafe_block(self) -> UnsafeBlock:
        loc = self._loc()
        self._expect(TokenType.UNSAFE)
        self._expect(TokenType.LBRACE)
        body = self._parse_body()
        self._expect(TokenType.RBRACE)
        return UnsafeBlock(body=body, location=loc)

    def _parse_expr_or_assign_stmt(self) -> Statement:
        loc = self._loc()
        expr = self._parse_expression()
        if self._match(TokenType.ASSIGN):
            value = self._parse_expression()
            return AssignStmt(target=expr, value=value, location=loc)
        return ExprStmt(expr=expr, location=loc)

    # -------------------------------------------------------------------
    # Expressions (precedence climbing)
    # -------------------------------------------------------------------

    def _parse_expression(self) -> Expr:
        return self._parse_or()

    def _parse_or(self) -> Expr:
        left = self._parse_and()
        while self._peek() == TokenType.OR:
            loc = self._loc()
            self._advance()
            right = self._parse_and()
            left = BinaryOp(op="||", left=left, right=right, location=loc)
        return left

    def _parse_and(self) -> Expr:
        left = self._parse_equality()
        while self._peek() == TokenType.AND:
            loc = self._loc()
            self._advance()
            right = self._parse_equality()
            left = BinaryOp(op="&&", left=left, right=right, location=loc)
        return left

    def _parse_equality(self) -> Expr:
        left = self._parse_comparison()
        while self._peek() in (TokenType.EQ, TokenType.NEQ):
            loc = self._loc()
            op = self._advance().value
            right = self._parse_comparison()
            left = BinaryOp(op=op, left=left, right=right, location=loc)
        return left

    def _parse_comparison(self) -> Expr:
        left = self._parse_additive()
        while self._peek() in (TokenType.LT, TokenType.GT, TokenType.LTE, TokenType.GTE):
            loc = self._loc()
            op = self._advance().value
            right = self._parse_additive()
            left = BinaryOp(op=op, left=left, right=right, location=loc)
        return left

    def _parse_additive(self) -> Expr:
        left = self._parse_multiplicative()
        while self._peek() in (TokenType.PLUS, TokenType.MINUS):
            loc = self._loc()
            op = self._advance().value
            right = self._parse_multiplicative()
            left = BinaryOp(op=op, left=left, right=right, location=loc)
        return left

    def _parse_multiplicative(self) -> Expr:
        left = self._parse_unary()
        while self._peek() in (TokenType.STAR, TokenType.SLASH, TokenType.PERCENT):
            loc = self._loc()
            op = self._advance().value
            right = self._parse_unary()
            left = BinaryOp(op=op, left=left, right=right, location=loc)
        return left

    def _parse_unary(self) -> Expr:
        if self._peek() == TokenType.MINUS:
            loc = self._loc()
            self._advance()
            operand = self._parse_unary()
            return UnaryOp(op="-", operand=operand, location=loc)
        if self._peek() == TokenType.NOT:
            loc = self._loc()
            self._advance()
            operand = self._parse_unary()
            return UnaryOp(op="!", operand=operand, location=loc)
        return self._parse_postfix()

    def _parse_postfix(self) -> Expr:
        expr = self._parse_primary()
        while True:
            if self._peek() == TokenType.LPAREN:
                loc = self._loc()
                self._advance()
                args: list[Expr] = []
                if self._peek() != TokenType.RPAREN:
                    args.append(self._parse_expression())
                    while self._match(TokenType.COMMA):
                        args.append(self._parse_expression())
                self._expect(TokenType.RPAREN)
                expr = FunctionCall(callee=expr, args=args, location=loc)
            elif self._peek() == TokenType.DOT:
                loc = self._loc()
                self._advance()
                field_name = self._expect(TokenType.IDENT).value
                if self._peek() == TokenType.LPAREN:
                    self._advance()
                    args = []
                    if self._peek() != TokenType.RPAREN:
                        args.append(self._parse_expression())
                        while self._match(TokenType.COMMA):
                            args.append(self._parse_expression())
                    self._expect(TokenType.RPAREN)
                    expr = MethodCall(obj=expr, method_name=field_name, args=args, location=loc)
                else:
                    expr = FieldAccess(obj=expr, field_name=field_name, location=loc)
            else:
                break
        return expr

    def _parse_primary(self) -> Expr:
        tt = self._peek()
        loc = self._loc()

        if tt == TokenType.INT_LIT:
            tok = self._advance()
            return IntLiteral(value=int(tok.value), location=loc)

        if tt == TokenType.FLOAT_LIT:
            tok = self._advance()
            return FloatLiteral(value=float(tok.value), location=loc)

        if tt == TokenType.STRING_LIT:
            tok = self._advance()
            return StringLiteral(value=tok.value, location=loc)

        if tt == TokenType.TRUE:
            self._advance()
            return BoolLiteral(value=True, location=loc)

        if tt == TokenType.FALSE:
            self._advance()
            return BoolLiteral(value=False, location=loc)

        if tt == TokenType.MOVE:
            self._advance()
            name = self._expect(TokenType.IDENT).value
            return MoveExpr(name=name, location=loc)

        if tt == TokenType.BORROW:
            self._advance()
            name = self._expect(TokenType.IDENT).value
            return BorrowExpr(name=name, location=loc)

        if tt == TokenType.IDENT:
            tok = self._advance()
            # Check for struct construction: TypeName { field: value, ... }
            if self._peek() == TokenType.LBRACE and tok.value[0].isupper():
                return self._parse_construct_expr(tok.value, loc)
            return Identifier(name=tok.value, location=loc)

        if tt == TokenType.LPAREN:
            self._advance()
            expr = self._parse_expression()
            self._expect(TokenType.RPAREN)
            return expr

        if tt == TokenType.LBRACKET:
            self._advance()
            elements: list[Expr] = []
            if self._peek() != TokenType.RBRACKET:
                elements.append(self._parse_expression())
                while self._match(TokenType.COMMA):
                    elements.append(self._parse_expression())
            self._expect(TokenType.RBRACKET)
            return ListLiteral(elements=elements, location=loc)

        raise CompileError(syntax_error(
            f"Unexpected token '{self._current().value}' ({tt.name})",
            loc,
        ))

    def _parse_construct_expr(self, type_name: str, loc: SourceLocation) -> ConstructExpr:
        self._expect(TokenType.LBRACE)
        fields: dict[str, Expr] = {}
        if self._peek() != TokenType.RBRACE:
            fname = self._expect(TokenType.IDENT).value
            self._expect(TokenType.COLON)
            fval = self._parse_expression()
            fields[fname] = fval
            while self._match(TokenType.COMMA):
                fname = self._expect(TokenType.IDENT).value
                self._expect(TokenType.COLON)
                fval = self._parse_expression()
                fields[fname] = fval
        self._expect(TokenType.RBRACE)
        return ConstructExpr(type_name=type_name, fields=fields, location=loc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse(source: str, filename: str = "<stdin>") -> Program:
    """Parse AEON source code into an AST."""
    tokens = tokenize(source, filename)
    parser = Parser(tokens, filename)
    return parser.parse()
