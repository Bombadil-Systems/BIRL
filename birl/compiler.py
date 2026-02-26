"""
BIRL Syntax Compiler (Phase 3)

Compiles BIRL pipe-syntax programs into executable plans.

BIRL Spec v1.1, Section 5: The Compiler/Planner

Compilation phases:
1. Lexical Analysis → Token stream
2. Parsing → Abstract Syntax Tree (AST)
3. Context Resolution → Validate all context references
4. Path Planning → A* search for REWRITE/FIND_PATH operations
5. Optimization → Collapse adjacent operations where possible
6. Execution Plan → DAG of Operation objects for the Runtime

Example BIRL program:
    LOAD "file.exe"
    | AS PE
    | SELECT .sections['.text']
    | AS x86_64
    | FIND_OFFSET PATTERN="59 C3"
    | SAVE_COORDINATE AS "gadget_pop_rcx"
    | EMIT payload
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional


# ============================================================================
# Token Types
# ============================================================================

class TokenType(Enum):
    LOAD = auto()
    AS = auto()
    SELECT = auto()
    REWRITE = auto()
    EMIT = auto()
    ASSERT = auto()
    FIND_OFFSET = auto()
    FIND_PATH = auto()
    SAVE_COORDINATE = auto()
    LABEL = auto()
    REVERT_TO = auto()
    RESIDUE = auto()
    FORK = auto()
    JOIN = auto()
    DEFINE = auto()
    EMIT_STRUCTURE = auto()
    PIPE = auto()         # |
    STRING = auto()       # "quoted" or 'quoted'
    IDENTIFIER = auto()   # bareword
    SELECTOR = auto()     # .field[index] style
    PATTERN = auto()      # PATTERN="xx xx"
    KEYWORD_ARG = auto()  # key=value
    LBRACKET = auto()     # [
    RBRACKET = auto()     # ]
    LPAREN = auto()       # (
    RPAREN = auto()       # )
    COMMA = auto()
    ARROW = auto()        # ->
    NUMBER = auto()
    HEX_NUMBER = auto()   # 0xNN
    NEWLINE = auto()
    EOF = auto()


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    col: int

    def __repr__(self) -> str:
        return f"<{self.type.name}:{self.value!r}>"


# ============================================================================
# Lexer
# ============================================================================

KEYWORDS = {
    "LOAD": TokenType.LOAD,
    "AS": TokenType.AS,
    "SELECT": TokenType.SELECT,
    "REWRITE": TokenType.REWRITE,
    "EMIT": TokenType.EMIT,
    "ASSERT": TokenType.ASSERT,
    "FIND_OFFSET": TokenType.FIND_OFFSET,
    "FIND_PATH": TokenType.FIND_PATH,
    "SAVE_COORDINATE": TokenType.SAVE_COORDINATE,
    "LABEL": TokenType.LABEL,
    "REVERT_TO": TokenType.REVERT_TO,
    "RESIDUE": TokenType.RESIDUE,
    "FORK": TokenType.FORK,
    "JOIN": TokenType.JOIN,
    "DEFINE": TokenType.DEFINE,
    "EMIT_STRUCTURE": TokenType.EMIT_STRUCTURE,
}


class LexerError(Exception):
    def __init__(self, message: str, line: int, col: int):
        super().__init__(f"Line {line}, Col {col}: {message}")
        self.line = line
        self.col = col


def tokenize(source: str) -> list[Token]:
    """Tokenize BIRL source into a token stream."""
    tokens: list[Token] = []
    lines = source.split("\n")

    for line_num, line_text in enumerate(lines, 1):
        # Strip comments
        comment_idx = line_text.find("//")
        if comment_idx >= 0:
            line_text = line_text[:comment_idx]

        col = 0
        text = line_text

        while col < len(text):
            # Skip whitespace
            if text[col] in " \t":
                col += 1
                continue

            # Pipe
            if text[col] == "|":
                tokens.append(Token(TokenType.PIPE, "|", line_num, col))
                col += 1
                continue

            # Arrow ->
            if text[col:col+2] == "->":
                tokens.append(Token(TokenType.ARROW, "->", line_num, col))
                col += 2
                continue

            # Comparison operators (>=, <=, ==, >, <) — used in ASSERT
            if text[col:col+2] in (">=", "<=", "=="):
                tokens.append(Token(TokenType.IDENTIFIER, text[col:col+2], line_num, col))
                col += 2
                continue
            if text[col] in (">", "<"):
                tokens.append(Token(TokenType.IDENTIFIER, text[col], line_num, col))
                col += 1
                continue

            # Brackets and parens
            if text[col] == "[":
                tokens.append(Token(TokenType.LBRACKET, "[", line_num, col))
                col += 1
                continue
            if text[col] == "]":
                tokens.append(Token(TokenType.RBRACKET, "]", line_num, col))
                col += 1
                continue
            if text[col] == "(":
                tokens.append(Token(TokenType.LPAREN, "(", line_num, col))
                col += 1
                continue
            if text[col] == ")":
                tokens.append(Token(TokenType.RPAREN, ")", line_num, col))
                col += 1
                continue
            if text[col] == ",":
                tokens.append(Token(TokenType.COMMA, ",", line_num, col))
                col += 1
                continue

            # Quoted string
            if text[col] in '"\'':
                quote = text[col]
                end = text.find(quote, col + 1)
                if end < 0:
                    raise LexerError(f"Unterminated string", line_num, col)
                value = text[col+1:end]
                tokens.append(Token(TokenType.STRING, value, line_num, col))
                col = end + 1
                continue

            # Selector (.field[index])
            if text[col] == ".":
                match = re.match(r"\.[a-zA-Z_][\w]*(\[\s*[^\]]+\s*\])*", text[col:])
                if match:
                    tokens.append(Token(TokenType.SELECTOR, match.group(), line_num, col))
                    col += match.end()
                    continue

            # Hex number
            if text[col:col+2] in ("0x", "0X"):
                match = re.match(r"0[xX][0-9a-fA-F]+", text[col:])
                if match:
                    tokens.append(Token(TokenType.HEX_NUMBER, match.group(), line_num, col))
                    col += match.end()
                    continue

            # Number
            if text[col].isdigit():
                match = re.match(r"\d+(\.\d+)?", text[col:])
                if match:
                    tokens.append(Token(TokenType.NUMBER, match.group(), line_num, col))
                    col += match.end()
                    continue

            # Keyword=Value pattern (e.g., PATTERN="59 C3", coverage=0.6)
            kv_match = re.match(r"([a-zA-Z_]\w*)=", text[col:])
            if kv_match:
                key = kv_match.group(1)
                col += kv_match.end()
                # Value follows
                if col < len(text) and text[col] in '"\'':
                    quote = text[col]
                    end = text.find(quote, col + 1)
                    if end < 0:
                        raise LexerError("Unterminated string in kwarg", line_num, col)
                    value = text[col+1:end]
                    col = end + 1
                elif col < len(text):
                    val_match = re.match(r"[^\s,)\]]+", text[col:])
                    if val_match:
                        value = val_match.group()
                        col += val_match.end()
                    else:
                        value = ""
                else:
                    value = ""
                tokens.append(Token(TokenType.KEYWORD_ARG, f"{key}={value}", line_num, col))
                continue

            # Identifier / Keyword
            if text[col].isalpha() or text[col] == "_":
                match = re.match(r"[a-zA-Z_][\w]*", text[col:])
                if match:
                    word = match.group()
                    if word in KEYWORDS:
                        tokens.append(Token(KEYWORDS[word], word, line_num, col))
                    else:
                        tokens.append(Token(TokenType.IDENTIFIER, word, line_num, col))
                    col += match.end()
                    continue

            raise LexerError(f"Unexpected character: {text[col]!r}", line_num, col)

    tokens.append(Token(TokenType.EOF, "", len(lines), 0))
    return tokens


# ============================================================================
# AST Nodes
# ============================================================================

class ASTNode:
    """Base class for all AST nodes."""
    pass


@dataclass
class LoadNode(ASTNode):
    source: str  # File path or identifier

@dataclass
class AsNode(ASTNode):
    context_name: str
    kwargs: dict[str, str] = field(default_factory=dict)

@dataclass
class SelectNode(ASTNode):
    selector: str

@dataclass 
class RewriteNode(ASTNode):
    strategy: str
    kwargs: dict[str, str] = field(default_factory=dict)

@dataclass
class EmitNode(ASTNode):
    target: str

@dataclass
class AssertNode(ASTNode):
    condition: str
    kwargs: dict[str, str] = field(default_factory=dict)

@dataclass
class FindOffsetNode(ASTNode):
    pattern: Optional[str] = None
    kwargs: dict[str, str] = field(default_factory=dict)

@dataclass
class SaveCoordinateNode(ASTNode):
    name: str

@dataclass
class LabelNode(ASTNode):
    name: str

@dataclass
class RevertToNode(ASTNode):
    label: str

@dataclass
class ResidueNode(ASTNode):
    pass

@dataclass
class EmitStructureNode(ASTNode):
    elements: list[str]
    target_name: str = ""
    kwargs: dict[str, str] = field(default_factory=dict)

@dataclass
class FindPathNode(ASTNode):
    source: str
    target: str
    kwargs: dict[str, str] = field(default_factory=dict)

@dataclass
class PipelineNode(ASTNode):
    """A complete BIRL program: a sequence of operations."""
    operations: list[ASTNode]


# ============================================================================
# Parser
# ============================================================================

class ParseError(Exception):
    def __init__(self, message: str, token: Token):
        super().__init__(f"Line {token.line}, Col {token.col}: {message} (got {token})")
        self.token = token


class Parser:
    """Parses a BIRL token stream into an AST."""

    def __init__(self, tokens: list[Token]):
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, ttype: TokenType) -> Token:
        tok = self._advance()
        if tok.type != ttype:
            raise ParseError(f"Expected {ttype.name}", tok)
        return tok

    def _at(self, ttype: TokenType) -> bool:
        return self._peek().type == ttype

    def _collect_kwargs(self) -> dict[str, str]:
        """Collect any keyword=value arguments."""
        kwargs = {}
        while self._at(TokenType.KEYWORD_ARG):
            kv = self._advance().value
            key, _, val = kv.partition("=")
            kwargs[key] = val
        return kwargs

    def parse(self) -> PipelineNode:
        """Parse a complete BIRL program."""
        ops: list[ASTNode] = []

        while not self._at(TokenType.EOF):
            # Skip leading pipes
            while self._at(TokenType.PIPE):
                self._advance()

            if self._at(TokenType.EOF):
                break

            op = self._parse_operation()
            if op:
                ops.append(op)

        return PipelineNode(operations=ops)

    def _parse_operation(self) -> Optional[ASTNode]:
        tok = self._peek()

        if tok.type == TokenType.LOAD:
            return self._parse_load()
        elif tok.type == TokenType.AS:
            return self._parse_as()
        elif tok.type == TokenType.SELECT:
            return self._parse_select()
        elif tok.type == TokenType.REWRITE:
            return self._parse_rewrite()
        elif tok.type == TokenType.EMIT:
            return self._parse_emit()
        elif tok.type == TokenType.ASSERT:
            return self._parse_assert()
        elif tok.type == TokenType.FIND_OFFSET:
            return self._parse_find_offset()
        elif tok.type == TokenType.SAVE_COORDINATE:
            return self._parse_save_coordinate()
        elif tok.type == TokenType.LABEL:
            return self._parse_label()
        elif tok.type == TokenType.REVERT_TO:
            return self._parse_revert_to()
        elif tok.type == TokenType.RESIDUE:
            self._advance()
            return ResidueNode()
        elif tok.type == TokenType.EMIT_STRUCTURE:
            return self._parse_emit_structure()
        elif tok.type == TokenType.FIND_PATH:
            return self._parse_find_path()
        elif tok.type == TokenType.PIPE:
            self._advance()
            return None
        else:
            raise ParseError(f"Unexpected token in pipeline", tok)

    def _parse_load(self) -> LoadNode:
        self._expect(TokenType.LOAD)
        if self._at(TokenType.STRING):
            source = self._advance().value
        elif self._at(TokenType.IDENTIFIER):
            source = self._advance().value
        else:
            raise ParseError("Expected file path or identifier after LOAD", self._peek())
        return LoadNode(source=source)

    def _parse_as(self) -> AsNode:
        self._expect(TokenType.AS)
        name = self._advance().value
        kwargs = self._collect_kwargs()
        return AsNode(context_name=name, kwargs=kwargs)

    def _parse_select(self) -> SelectNode:
        self._expect(TokenType.SELECT)
        if self._at(TokenType.SELECTOR):
            selector = self._advance().value
        elif self._at(TokenType.IDENTIFIER):
            selector = self._advance().value
        elif self._at(TokenType.STRING):
            selector = self._advance().value
        else:
            raise ParseError("Expected selector after SELECT", self._peek())
        return SelectNode(selector=selector)

    def _parse_rewrite(self) -> RewriteNode:
        self._expect(TokenType.REWRITE)
        strategy = ""
        if self._at(TokenType.IDENTIFIER):
            strategy = self._advance().value
        kwargs = self._collect_kwargs()
        return RewriteNode(strategy=strategy, kwargs=kwargs)

    def _parse_emit(self) -> EmitNode:
        self._expect(TokenType.EMIT)
        target = ""
        if self._at(TokenType.STRING):
            target = self._advance().value
        elif self._at(TokenType.IDENTIFIER):
            target = self._advance().value
        return EmitNode(target=target)

    def _parse_assert(self) -> AssertNode:
        self._expect(TokenType.ASSERT)
        parts = []
        kwargs = {}
        paren_depth = 0

        while not self._at(TokenType.PIPE) and not self._at(TokenType.EOF):
            if self._at(TokenType.LPAREN):
                paren_depth += 1
                parts.append(self._advance().value)
                continue
            if self._at(TokenType.RPAREN):
                paren_depth -= 1
                parts.append(self._advance().value)
                if paren_depth <= 0:
                    break
                continue
            if self._at(TokenType.COMMA) and paren_depth > 0:
                self._advance()  # skip comma inside parens
                continue
            if self._at(TokenType.KEYWORD_ARG):
                kv = self._advance().value
                key, _, val = kv.partition("=")
                kwargs[key] = val
                continue
            parts.append(self._advance().value)

        # Also collect kwargs after the parenthesized expression
        while self._at(TokenType.KEYWORD_ARG):
            kv = self._advance().value
            key, _, val = kv.partition("=")
            kwargs[key] = val

        return AssertNode(condition=" ".join(parts), kwargs=kwargs)

    def _parse_find_offset(self) -> FindOffsetNode:
        self._expect(TokenType.FIND_OFFSET)
        kwargs = self._collect_kwargs()
        pattern = kwargs.pop("PATTERN", None) or kwargs.pop("pattern", None)
        return FindOffsetNode(pattern=pattern, kwargs=kwargs)

    def _parse_save_coordinate(self) -> SaveCoordinateNode:
        self._expect(TokenType.SAVE_COORDINATE)
        self._expect(TokenType.AS)
        if self._at(TokenType.STRING):
            name = self._advance().value
        else:
            name = self._advance().value
        return SaveCoordinateNode(name=name)

    def _parse_label(self) -> LabelNode:
        self._expect(TokenType.LABEL)
        name = self._advance().value
        return LabelNode(name=name)

    def _parse_revert_to(self) -> RevertToNode:
        self._expect(TokenType.REVERT_TO)
        label = self._advance().value
        return RevertToNode(label=label)

    def _parse_emit_structure(self) -> EmitStructureNode:
        self._expect(TokenType.EMIT_STRUCTURE)
        elements = []
        # Parse bracket-enclosed list
        if self._at(TokenType.LBRACKET):
            self._advance()
            while not self._at(TokenType.RBRACKET) and not self._at(TokenType.EOF):
                if self._at(TokenType.COMMA):
                    self._advance()
                    continue
                elements.append(self._advance().value)
            if self._at(TokenType.RBRACKET):
                self._advance()
        kwargs = self._collect_kwargs()
        target = kwargs.pop("AS", "") or kwargs.pop("as", "")
        # Also check for trailing AS keyword
        if self._at(TokenType.AS):
            self._advance()
            target = self._advance().value
        return EmitStructureNode(elements=elements, target_name=target, kwargs=kwargs)

    def _parse_find_path(self) -> FindPathNode:
        self._expect(TokenType.FIND_PATH)
        kwargs = self._collect_kwargs()
        source = kwargs.pop("SOURCE", kwargs.pop("source", ""))
        target = kwargs.pop("TARGET", kwargs.pop("target", ""))
        return FindPathNode(source=source, target=target, kwargs=kwargs)


# ============================================================================
# Public API
# ============================================================================

def compile_birl(source: str) -> PipelineNode:
    """Compile BIRL source code into an AST.
    
    Args:
        source: BIRL program text
        
    Returns:
        PipelineNode containing the parsed operations
    """
    tokens = tokenize(source)
    parser = Parser(tokens)
    return parser.parse()
