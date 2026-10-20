"""Falco condition ASTs as the engine reports them (docs/engine-protocol.md, "AST")."""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any


class AstError(ValueError):
    pass


@dataclass(frozen=True)
class And:
    children: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    children: tuple[Node, ...]


@dataclass(frozen=True)
class Not:
    child: Node


@dataclass(frozen=True)
class Identifier:
    name: str


@dataclass(frozen=True)
class Field:
    field: str
    arg: str | None = None


@dataclass(frozen=True)
class Transformer:
    name: str
    args: tuple[Operand, ...]


@dataclass(frozen=True)
class Value:
    value: str


@dataclass(frozen=True)
class ListValue:
    values: tuple[str, ...]


@dataclass(frozen=True)
class Check:
    op: str
    lhs: Field | Transformer
    rhs: Operand | None = None
    id: int | None = None

    @property
    def base_op(self) -> str:
        return self.op.split(" ", 1)[0]

    @property
    def modifier(self) -> str | None:
        parts = self.op.split(" ", 1)
        return parts[1] if len(parts) == 2 else None


type Node = And | Or | Not | Identifier | Check
type Operand = Field | Transformer | Value | ListValue


def parse(obj: Any, path: str = "$") -> Node:
    kind = _member(obj, "type", str, path)
    match kind:
        case "and" | "or":
            children = _member(obj, "children", list, path)
            nodes = tuple(parse(c, f"{path}.children[{i}]") for i, c in enumerate(children))
            return And(nodes) if kind == "and" else Or(nodes)
        case "not":
            return Not(parse(_member(obj, "child", dict, path), f"{path}.child"))
        case "identifier":
            return Identifier(_member(obj, "name", str, path))
        case "check":
            op = _member(obj, "op", str, path)
            lhs = _operand(_member(obj, "lhs", dict, path), f"{path}.lhs")
            if not isinstance(lhs, Field | Transformer):
                raise AstError(f"{path}.lhs: expected a field or transformer")
            rhs = None if op == "exists" else _operand(_member(obj, "rhs", dict, path), f"{path}.rhs")
            leaf_id = obj.get("id")
            if leaf_id is not None and not isinstance(leaf_id, int):
                raise AstError(f"{path}.id: expected an integer")
            return Check(op, lhs, rhs, leaf_id)
    raise AstError(f"{path}: unknown condition node type {kind!r}")


def _operand(obj: Any, path: str) -> Operand:
    kind = _member(obj, "type", str, path)
    match kind:
        case "field":
            arg = obj.get("arg")
            if arg is not None and not isinstance(arg, str):
                raise AstError(f"{path}.arg: expected a string or null")
            return Field(_member(obj, "field", str, path), arg)
        case "transformer":
            args = _member(obj, "args", list, path)
            return Transformer(
                _member(obj, "name", str, path),
                tuple(_operand(a, f"{path}.args[{i}]") for i, a in enumerate(args)),
            )
        case "value":
            return Value(_member(obj, "value", str, path))
        case "list":
            values = _member(obj, "values", list, path)
            if not all(isinstance(v, str) for v in values):
                raise AstError(f"{path}.values: expected strings")
            return ListValue(tuple(values))
    raise AstError(f"{path}: unknown operand type {kind!r}")


def _member(obj: Any, key: str, kind: type, path: str) -> Any:
    if not isinstance(obj, dict):
        raise AstError(f"{path}: expected an object")
    value = obj.get(key)
    if not isinstance(value, kind):
        raise AstError(f"{path}.{key}: expected {kind.__name__}")
    return value


def walk(node: Node) -> Iterator[Node]:
    yield node
    match node:
        case And(children) | Or(children):
            for child in children:
                yield from walk(child)
        case Not(child):
            yield from walk(child)


def checks(node: Node) -> Iterator[Check]:
    return (n for n in walk(node) if isinstance(n, Check))


def conjuncts(node: Node) -> list[Node]:
    if isinstance(node, And):
        return [c for child in node.children for c in conjuncts(child)]
    return [node]


def evaluate(node: Node, leaves: Sequence[bool]) -> bool:
    match node:
        case And(children):
            return all(evaluate(c, leaves) for c in children)
        case Or(children):
            return any(evaluate(c, leaves) for c in children)
        case Not(child):
            return not evaluate(child, leaves)
        case Check(id=leaf_id) if leaf_id is not None:
            return leaves[leaf_id]
    raise AstError(f"cannot evaluate {render(node)!r}: not a compiled condition")


_BARE = re.compile(r"""[^()"'\s=,]+""")
_KEYWORDS = frozenset({"and", "or", "not"})


def quote(value: str) -> str:
    if _BARE.fullmatch(value) and value not in _KEYWORDS:
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(node: Node | Operand, max_items: int | None = None) -> str:
    """Condition text in Falco syntax. With max_items, long lists are elided for display only."""
    match node:
        case And(children) | Or(children):
            word = " and " if isinstance(node, And) else " or "
            return word.join(_grouped(c, max_items) for c in children)
        case Not(child):
            return f"not {_grouped(child, max_items)}"
        case Identifier(name):
            return name
        case Check(op=op, lhs=lhs, rhs=rhs):
            text = f"{render(lhs, max_items)} {op}"
            return text if rhs is None else f"{text} {render(rhs, max_items)}"
        case Field(field, arg):
            return field if arg is None else f"{field}[{arg}]"
        case Transformer(name, args):
            return f"{name}({', '.join(render(a, max_items) for a in args)})"
        case Value(value):
            return quote(value)
        case ListValue(values):
            shown = values if max_items is None or len(values) <= max_items else values[:max_items]
            more = len(values) - len(shown)
            items = ", ".join(quote(v) for v in shown)
            return f"({items}, ... +{more})" if more else f"({items})"
    raise AstError(f"cannot render {node!r}")


def _grouped(node: Node, max_items: int | None) -> str:
    text = render(node, max_items)
    return f"({text})" if isinstance(node, And | Or) else text
