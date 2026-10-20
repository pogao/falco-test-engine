"""Where each compiled node came from: the rule's own text, a macro, or an exception clause.

Falco compiles a rule as `(<condition>) and not <exception 1> and not <exception 2> ...`
and then replaces each macro identifier with the macro's condition. So the compiled
AST is the raw AST with identifiers expanded, optionally wrapped with exception
clauses. Aligning the two recovers ownership without the engine having to mark it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ftest.cond import And, Check, Identifier, Node, Not, Or, checks, render, walk
from ftest.engine import Rule


@dataclass(frozen=True)
class MacroUse:
    name: str
    node: Node


@dataclass(frozen=True)
class ExceptionClause:
    label: str
    node: Node


@dataclass(frozen=True)
class Shape:
    raw: Node
    body: Node
    exceptions: tuple[ExceptionClause, ...]
    macros: tuple[MacroUse, ...]
    raw_of: Mapping[int, Node]
    macro_of: Mapping[int, str]
    exception_of: Mapping[int, str]
    aligned: bool

    def where(self, node: Node) -> str:
        if id(node) in self.macro_of:
            return f"in macro `{self.macro_of[id(node)]}`"
        if id(node) in self.exception_of:
            return f"in {self.exception_of[id(node)]}"
        return "in the rule condition"

    def display(self, node: Node, max_items: int | None = 6) -> str:
        """Prefer the raw text (macro and list names kept) when the node has one."""
        return render(self.raw_of.get(id(node), node), max_items)

    def in_body(self, node: Node) -> bool:
        return id(node) not in self.exception_of


def shape_of(rule: Rule) -> Shape:
    compiled = rule.compiled
    attempts: list[tuple[Node, tuple[Node, ...]]] = [(compiled, ())]
    if (
        isinstance(compiled, And)
        and len(compiled.children) >= 2
        and all(isinstance(c, Not) for c in compiled.children[1:])
    ):
        split = (compiled.children[0], tuple(c.child for c in compiled.children[1:]))
        attempts.insert(0 if rule.exception_names else 1, split)

    for body, clauses in attempts:
        raw_of: dict[int, Node] = {}
        macro_of: dict[int, str] = {}
        macros: list[MacroUse] = []
        if _align(rule.raw, body, raw_of, macro_of, macros):
            return _shape(rule, body, clauses, raw_of, macro_of, tuple(macros), aligned=True)
    return _shape(rule, compiled, (), {}, {}, (), aligned=False)


def _shape(rule, body, clauses, raw_of, macro_of, macros, aligned) -> Shape:
    labelled = tuple(ExceptionClause(_label(rule, i, c, len(clauses)), c) for i, c in enumerate(clauses))
    exception_of = {id(n): e.label for e in labelled for n in walk(e.node)}
    return Shape(rule.raw, body, labelled, macros, raw_of, macro_of, exception_of, aligned)


def _label(rule: Rule, index: int, clause: Node, total: int) -> str:
    if total == 1 and len(rule.exception_names) == 1:
        return f"exception `{rule.exception_names[0]}`"
    fields = sorted({render(c.lhs) for c in checks(clause)})
    return f"exception {index + 1} (on {', '.join(fields)})"


def _align(raw: Node, comp: Node, raw_of: dict, macro_of: dict, macros: list) -> bool:
    if isinstance(raw, Identifier):
        macros.append(MacroUse(raw.name, comp))
        for n in walk(comp):
            macro_of.setdefault(id(n), raw.name)
        return True
    if type(raw) is not type(comp):
        return False
    raw_of[id(comp)] = raw
    match raw, comp:
        case ((And(rc) | Or(rc)), (And(cc) | Or(cc))):
            return len(rc) == len(cc) and all(_align(r, c, raw_of, macro_of, macros) for r, c in zip(rc, cc))
        case Not(r), Not(c):
            return _align(r, c, raw_of, macro_of, macros)
        case Check(), Check():
            return raw.op == comp.op and render(raw.lhs) == render(comp.lhs)
    return False
