"""AEON Lexer — Tokenizer with line/column tracking.

Produces a stream of tokens from AEON source code.
No whitespace-sensitive parsing. Every token is meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from aeon.errors import SourceLocation, syntax_error, CompileError


class TokenType(Enum):
    # Keywords
    PURE = auto()
    TASK = auto()
    DATA = auto()
    REQUIRES = auto()
    ENSURES = auto()
    EFFECTS = auto()
    RETURN = auto()
    IF = auto()
    ELSE = auto()
    TRUE = auto()
    FALSE = auto()
    UNSAFE = auto()
    LET = auto()
    MUT = auto()
    MOVE = auto()
    BORROW = auto()
    IMPORT = auto()
    MATCH = auto()
    WHILE = auto()
    FOR = auto()
    IN = auto()
    BREAK = auto()
    CONTINUE = auto()

    # Literals
    INT_LIT = auto()
    FLOAT_LIT = auto()
    STRING_LIT = auto()

    # Identifier
    IDENT = auto()

    # Operators
    PLUS = auto()
    MINUS = auto()
    STAR = auto()
    SLASH = auto()
    PERCENT = auto()
    EQ = auto()
    NEQ = auto()
    GTE = auto()
    LTE = auto()
    GT = auto()
    LT = auto()
    ARROW = auto()
    AND = auto()
    OR = auto()
    NOT = auto()
    ASSIGN = auto()
    DOT = auto()
    DOUBLE_COLON = auto()

    # Delimiters
    LBRACE = auto()
    RBRACE = auto()
    LPAREN = auto()
    RPAREN = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    COLON = auto()
    COMMA = auto()
    SEMICOLON = auto()

    # Special
    EOF = auto()
    NEWLINE = auto()


KEYWORDS: dict[str, TokenType] = {
    "pure": TokenType.PURE,
    "task": TokenType.TASK,
    "data": TokenType.DATA,
    "requires": TokenType.REQUIRES,
    "ensures": TokenType.ENSURES,
    "effects": TokenType.EFFECTS,
    "return": TokenType.RETURN,
    "if": TokenType.IF,
    "else": TokenType.ELSE,
    "true": TokenType.TRUE,
    "false": TokenType.FALSE,
    "unsafe": TokenType.UNSAFE,
    "let": TokenType.LET,
    "mut": TokenType.MUT,
    "move": TokenType.MOVE,
    "borrow": TokenType.BORROW,
    "import": TokenType.IMPORT,
    "match": TokenType.MATCH,
    "while": TokenType.WHILE,
    "for": TokenType.FOR,
    "in": TokenType.IN,
    "break": TokenType.BREAK,
    "continue": TokenType.CONTINUE,
}


@dataclass
class Token:
    type: TokenType
    value: str
    location: SourceLocation

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, {self.location})"


class Lexer:
    """Tokenizer for AEON source code."""

    def __init__(self, source: str, filename: str = "<stdin>"):
        self.source = source
        self.filename = filename
        self.pos = 0
        self.line = 1
        self.column = 1

    def _loc(self) -> SourceLocation:
        return SourceLocation(self.line, self.column, self.filename)

    def _peek(self) -> Optional[str]:
        if self.pos < len(self.source):
            return self.source[self.pos]
        return None

    def _peek_ahead(self, offset: int = 1) -> Optional[str]:
        idx = self.pos + offset
        if idx < len(self.source):
            return self.source[idx]
        return None

    def _advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return ch

    def _skip_whitespace_and_comments(self) -> None:
        while self.pos < len(self.source):
            ch = self.source[self.pos]
            if ch in (" ", "\t", "\r", "\n"):
                self._advance()
            elif ch == "/" and self._peek_ahead() == "/":
                while self.pos < len(self.source) and self.source[self.pos] != "\n":
                    self._advance()
            elif ch == "/" and self._peek_ahead() == "*":
                self._advance()
                self._advance()
                while self.pos < len(self.source):
                    if self.source[self.pos] == "*" and self._peek_ahead() == "/":
                        self._advance()
                        self._advance()
                        break
                    self._advance()
            else:
                break

    def _read_string(self) -> Token:
        loc = self._loc()
        self._advance()  # opening quote
        value = ""
        while self.pos < len(self.source):
            ch = self._advance()
            if ch == '"':
                return Token(TokenType.STRING_LIT, value, loc)
            if ch == "\\":
                next_ch = self._advance()
                escape_map = {"n": "\n", "t": "\t", "\\": "\\", '"': '"'}
                value += escape_map.get(next_ch, next_ch)
            else:
                value += ch
        raise CompileError(syntax_error("Unterminated string literal", loc))

    def _read_number(self) -> Token:
        loc = self._loc()
        value = ""
        is_float = False
        while self.pos < len(self.source) and (self.source[self.pos].isdigit() or self.source[self.pos] == "."):
            if self.source[self.pos] == ".":
                if is_float:
                    break
                if self._peek_ahead() and self._peek_ahead().isdigit():
                    is_float = True
                else:
                    break
            value += self._advance()
        token_type = TokenType.FLOAT_LIT if is_float else TokenType.INT_LIT
        return Token(token_type, value, loc)

    def _read_identifier(self) -> Token:
        loc = self._loc()
        value = ""
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            value += self._advance()
        token_type = KEYWORDS.get(value, TokenType.IDENT)
        return Token(token_type, value, loc)

    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []
        while self.pos < len(self.source):
            self._skip_whitespace_and_comments()
            if self.pos >= len(self.source):
                break

            ch = self._peek()
            loc = self._loc()

            if ch == '"':
                tokens.append(self._read_string())
            elif ch.isdigit():
                tokens.append(self._read_number())
            elif ch.isalpha() or ch == "_":
                tokens.append(self._read_identifier())
            elif ch == "+" :
                self._advance()
                tokens.append(Token(TokenType.PLUS, "+", loc))
            elif ch == "-":
                self._advance()
                if self._peek() == ">":
                    self._advance()
                    tokens.append(Token(TokenType.ARROW, "->", loc))
                else:
                    tokens.append(Token(TokenType.MINUS, "-", loc))
            elif ch == "*":
                self._advance()
                tokens.append(Token(TokenType.STAR, "*", loc))
            elif ch == "/":
                self._advance()
                tokens.append(Token(TokenType.SLASH, "/", loc))
            elif ch == "%":
                self._advance()
                tokens.append(Token(TokenType.PERCENT, "%", loc))
            elif ch == "=":
                self._advance()
                if self._peek() == "=":
                    self._advance()
                    tokens.append(Token(TokenType.EQ, "==", loc))
                else:
                    tokens.append(Token(TokenType.ASSIGN, "=", loc))
            elif ch == "!":
                self._advance()
                if self._peek() == "=":
                    self._advance()
                    tokens.append(Token(TokenType.NEQ, "!=", loc))
                else:
                    tokens.append(Token(TokenType.NOT, "!", loc))
            elif ch == ">":
                self._advance()
                if self._peek() == "=":
                    self._advance()
                    tokens.append(Token(TokenType.GTE, ">=", loc))
                else:
                    tokens.append(Token(TokenType.GT, ">", loc))
            elif ch == "<":
                self._advance()
                if self._peek() == "=":
                    self._advance()
                    tokens.append(Token(TokenType.LTE, "<=", loc))
                else:
                    tokens.append(Token(TokenType.LT, "<", loc))
            elif ch == "&":
                self._advance()
                if self._peek() == "&":
                    self._advance()
                    tokens.append(Token(TokenType.AND, "&&", loc))
                else:
                    raise CompileError(syntax_error(f"Unexpected character '&'", loc))
            elif ch == "|":
                self._advance()
                if self._peek() == "|":
                    self._advance()
                    tokens.append(Token(TokenType.OR, "||", loc))
                else:
                    raise CompileError(syntax_error(f"Unexpected character '|'", loc))
            elif ch == "{":
                self._advance()
                tokens.append(Token(TokenType.LBRACE, "{", loc))
            elif ch == "}":
                self._advance()
                tokens.append(Token(TokenType.RBRACE, "}", loc))
            elif ch == "(":
                self._advance()
                tokens.append(Token(TokenType.LPAREN, "(", loc))
            elif ch == ")":
                self._advance()
                tokens.append(Token(TokenType.RPAREN, ")", loc))
            elif ch == "[":
                self._advance()
                tokens.append(Token(TokenType.LBRACKET, "[", loc))
            elif ch == "]":
                self._advance()
                tokens.append(Token(TokenType.RBRACKET, "]", loc))
            elif ch == ":":
                self._advance()
                if self._peek() == ":":
                    self._advance()
                    tokens.append(Token(TokenType.DOUBLE_COLON, "::", loc))
                else:
                    tokens.append(Token(TokenType.COLON, ":", loc))
            elif ch == ",":
                self._advance()
                tokens.append(Token(TokenType.COMMA, ",", loc))
            elif ch == ";":
                self._advance()
                tokens.append(Token(TokenType.SEMICOLON, ";", loc))
            elif ch == ".":
                self._advance()
                tokens.append(Token(TokenType.DOT, ".", loc))
            else:
                self._advance()
                raise CompileError(syntax_error(f"Unexpected character '{ch}'", loc))

        tokens.append(Token(TokenType.EOF, "", self._loc()))
        return tokens


def tokenize(source: str, filename: str = "<stdin>") -> list[Token]:
    """Convenience function to tokenize AEON source code."""
    return Lexer(source, filename).tokenize()
