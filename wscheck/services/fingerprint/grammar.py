"""FOFA 风格指纹表达式解析（词法 + 递归下降）。

文法：
    expr   := or_expr
    or_expr  := and_expr ("||" and_expr)*
    and_expr := unary ("&&" unary)*
    unary    := "!" unary | "(" expr ")" | condition
    condition:= FIELD OP STRING      OP ∈ {=, !=, ==, ~=}

字段支持别名（banner/content_type→header、icon_hash→favicon、status_code→status），
`~=` 为正则匹配，非法正则永不命中。
"""

from __future__ import annotations

import re

FIELDS = ("title", "body", "header", "server", "cert", "port", "status",
          "app", "product", "favicon")
OPERATORS = ("==", "!=", "=", "~=")
# 兼容 FOFA / webfinger 常见写法，解析时统一归一化到上面的字段
FIELD_ALIASES = {"banner": "header", "content_type": "header",
                 "icon_hash": "favicon", "status_code": "status"}

_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<op>==|!=|~=|=)
    | (?P<and>&&)
    | (?P<or>\|\|)
    | (?P<not>!)
    | (?P<lp>\()
    | (?P<rp>\))
    | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    | (?P<field>[A-Za-z_][A-Za-z0-9_.\-]*)
    """,
    re.VERBOSE,
)


class ParseError(ValueError):
    pass


def parse(expr: str) -> tuple:
    tokens = tokenize(expr)
    if not tokens:
        raise ParseError("表达式为空")
    node, rest = _parse_or(tokens)
    if rest:
        raise ParseError(f"无法解析的内容: {' '.join(rest[:4])}")
    return node


def tokenize(expr: str) -> list[str]:
    tokens: list[str] = []
    text = expr or ""
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if not match:
            raise ParseError(f"位置 {position} 处存在非法字符: {text[position]!r}")
        position = match.end()
        if match.lastgroup != "ws":
            tokens.append(match.group())
    return tokens


def _parse_or(tokens: list[str]):
    node, rest = _parse_and(tokens)
    while rest[:1] == ["||"]:
        right, rest = _parse_and(rest[1:])
        node = ("or", node, right)
    return node, rest


def _parse_and(tokens: list[str]):
    node, rest = _parse_unary(tokens)
    while rest[:1] == ["&&"]:
        right, rest = _parse_unary(rest[1:])
        node = ("and", node, right)
    return node, rest


def _parse_unary(tokens: list[str]):
    if not tokens:
        raise ParseError("表达式不完整")
    if tokens[0] == "!":
        node, rest = _parse_unary(tokens[1:])
        return ("not", node), rest
    if tokens[0] == "(":
        node, rest = _parse_or(tokens[1:])
        if rest[:1] != [")"]:
            raise ParseError("缺少右括号")
        return node, rest[1:]
    return _parse_condition(tokens)


def _parse_condition(tokens: list[str]):
    if len(tokens) < 3:
        raise ParseError("条件需要 字段 运算符 值")
    raw_field, op, value = tokens[0], tokens[1], tokens[2]
    field = FIELD_ALIASES.get(raw_field.lower(), raw_field.lower())
    if field not in FIELDS:
        supported = ", ".join(FIELDS)
        raise ParseError(f"不支持的字段: {raw_field}（可用: {supported}，"
                         f"别名: {', '.join(FIELD_ALIASES)}）")
    if op not in OPERATORS:
        raise ParseError(f"不支持的运算符: {op}（可用: {', '.join(OPERATORS)}）")
    if not (value.startswith(('"', "'")) and value.endswith(('"', "'")) and len(value) >= 2):
        raise ParseError("比较值需要用引号包裹")
    return ("cond", field, op, _unquote(value)), tokens[3:]


def _unquote(value: str) -> str:
    """只还原引号与反斜杠转义，保留 ~= 正则里的 \\s、\\d 等写法。"""
    inner = value[1:-1]
    return re.sub(r"\\([\"'\\])", r"\1", inner)


def describe(node: tuple, indent: int = 0) -> str:
    pad = "  " * indent
    kind = node[0]
    if kind == "cond":
        _, field, op, value = node
        return f'{pad}{field} {op} "{value}"'
    if kind == "not":
        return f"{pad}NOT (\n{describe(node[1], indent + 1)}\n{pad})"
    _, left, right = node
    joiner = "AND" if kind == "and" else "OR"
    return f"{pad}{joiner} (\n{describe(left, indent + 1)}\n{describe(right, indent + 1)}\n{pad})"


def conditions(node: tuple) -> list[tuple]:
    if node[0] == "cond":
        return [node]
    if node[0] == "not":
        return conditions(node[1])
    return conditions(node[1]) + conditions(node[2])
