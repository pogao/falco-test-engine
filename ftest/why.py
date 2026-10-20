"""Which checks of a rule's compiled condition decided its value on one case."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from ftest.cond import (
    And,
    Check,
    Field,
    Node,
    Not,
    Operand,
    Or,
    Transformer,
    TransformerList,
    evaluate,
    render,
)
from ftest.engine import Rule, Trace
from ftest.shape import Shape


@dataclass(frozen=True)
class Decider:
    check: str
    value: bool
    where: str
    unset: tuple[str, ...]


def deciders(rule: Rule, shape: Shape, trace: Trace) -> tuple[Decider, ...]:
    missing = set(trace.missing_fields)
    found = (
        Decider(
            shape.display(c),
            trace.leaves[c.id],
            shape.where(c),
            tuple(dict.fromkeys(f for o in (c.lhs, c.rhs) for f in _fields(o) if f in missing)),
        )
        for c in _deciding(rule.compiled, trace.leaves)
    )
    return tuple(dict.fromkeys(found))


def _deciding(node: Node, leaves: Sequence[bool]) -> Iterator[Check]:
    match node:
        case Check():
            yield node
        case Not(child):
            yield from _deciding(child, leaves)
        case And(children) | Or(children):
            # The children that share the node's value decide it: all of a true `and` or a false `or`,
            # the false children of a false `and`, the true children of a true `or`.
            value = evaluate(node, leaves)
            for child in children:
                if evaluate(child, leaves) == value:
                    yield from _deciding(child, leaves)


def _fields(operand: Operand | None) -> Iterator[str]:
    """Fields as the engine names them in `missing_fields`: a transformer reads the fields inside it."""
    match operand:
        case Field():
            yield render(operand)
        case Transformer(args=items) | TransformerList(items):
            for item in items:
                yield from _fields(item)
