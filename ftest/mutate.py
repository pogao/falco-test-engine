"""Inversion mutants of a rule's compiled condition.

A mutant negates, swaps, or drops one part of the condition. It never adds a check, so the leaf
values the engine reports for a case evaluate the mutant directly with `cond.evaluate`.

Mutation sites are the nodes written in the rule itself, each exception clause, and each macro the
rule uses. A macro is one site (it is negated as a whole) unless the user's files define or change
it relative to the base rules; then its insides are sites too.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterator
from dataclasses import dataclass
from enum import Enum

from ftest.cond import And, Node, Not, Or, render
from ftest.engine import Rule
from ftest.shape import Shape

MAX_MUTANTS = 80
_MAX_LABEL = 100


class Kind(Enum):
    NEGATE = "negate"
    SWAP = "swap"
    DROP = "drop"


@dataclass(frozen=True)
class Mutant:
    kind: Kind
    site_label: str
    ast: Node

    @property
    def description(self) -> str:
        return f"{MUTATIONS[self.kind].verb} {self.site_label}"


@dataclass(frozen=True)
class Site:
    node: Node
    label: str
    atomic: bool
    parent: Node | None
    droppable: bool


@dataclass(frozen=True)
class Mutation:
    verb: str
    apply: Callable[[Site], Iterator[tuple[Node, Node]]]


def _negate(site: Site) -> Iterator[tuple[Node, Node]]:
    # Negating the child of a `not` is the same mutant as removing that `not`.
    if not isinstance(site.parent, Not):
        yield site.node, site.node.child if isinstance(site.node, Not) else Not(site.node)


def _swap(site: Site) -> Iterator[tuple[Node, Node]]:
    if not site.atomic and isinstance(site.node, And | Or):
        yield site.node, (Or if isinstance(site.node, And) else And)(site.node.children)


def _drop(site: Site) -> Iterator[tuple[Node, Node]]:
    parent = site.parent
    if site.droppable and isinstance(parent, And | Or):
        rest = tuple(c for c in parent.children if c is not site.node)
        yield parent, rest[0] if len(rest) == 1 else type(parent)(rest)


MUTATIONS: dict[Kind, Mutation] = {
    Kind.NEGATE: Mutation("inverting", _negate),
    Kind.SWAP: Mutation("swapping `and` and `or` in", _swap),
    Kind.DROP: Mutation("dropping", _drop),
}


def sites(rule: Rule, shape: Shape, changed_macros: Collection[str]) -> list[Site]:
    macro_roots = {id(use.node): use.name for use in shape.macros}

    def owned(node: Node | None) -> bool:
        if node is None:
            return False
        if not shape.aligned or id(node) in shape.raw_of:
            return True
        return shape.macro_of.get(id(node)) in changed_macros

    def label(node: Node) -> str:
        if node is shape.body:
            return "the whole condition"
        if id(node) in macro_roots:
            return f"macro `{macro_roots[id(node)]}`"
        text = shape.display(node)
        text = text if len(text) <= _MAX_LABEL else text[: _MAX_LABEL - 3] + "..."
        where = shape.where(node) if shape.aligned else "in the compiled condition"
        return f"`{text}` {where}"

    found: list[Site] = []

    def visit(node: Node, parent: Node | None) -> None:
        macro = macro_roots.get(id(node))
        atomic = macro is not None and macro not in changed_macros
        if owned(node) or macro is not None:
            droppable = owned(parent) and isinstance(parent, And | Or) and len(parent.children) >= 2
            found.append(Site(node, label(node), atomic, parent, droppable))
        if not atomic:
            for child in _children(node):
                visit(child, node)

    visit(shape.body, None)
    root = rule.compiled
    if shape.exceptions and isinstance(root, And):
        for wrapper, clause in zip(root.children[1:], shape.exceptions):
            found.append(Site(wrapper, clause.label, True, root, True))
    return found


def mutants(rule: Rule, shape: Shape, changed_macros: Collection[str]) -> tuple[Mutant, ...]:
    """Every distinct mutant, in site order: the whole condition first, then its parts."""
    seen = {render(rule.compiled)}
    found = []
    for site in sites(rule, shape, changed_macros):
        for kind, mutation in MUTATIONS.items():
            for old, new in mutation.apply(site):
                ast = replace(rule.compiled, old, new)
                text = render(ast)
                if text not in seen:
                    seen.add(text)
                    found.append(Mutant(kind, site.label, ast))
    return tuple(found)


def replace(node: Node, old: Node, new: Node) -> Node:
    """`node` with the subtree `old` (by identity) replaced by `new`."""
    if node is old:
        return new
    match node:
        case And(children):
            return And(tuple(replace(c, old, new) for c in children))
        case Or(children):
            return Or(tuple(replace(c, old, new) for c in children))
        case Not(child):
            return Not(replace(child, old, new))
    return node


def _children(node: Node) -> tuple[Node, ...]:
    match node:
        case And(children) | Or(children):
            return children
        case Not(child):
            return (child,)
    return ()
