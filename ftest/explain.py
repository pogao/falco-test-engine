"""A deterministic plain-English account of what a rule matches."""

from __future__ import annotations

from collections.abc import Mapping

from ftest.cond import And, Identifier, Node, Not, render
from ftest.engine import Macro, Rule

_MAX_EVENT_NAMES = 8
_MAX_MACRO_TEXT = 110


def explain(rule: Rule, macros: Mapping[str, Macro]) -> tuple[str, ...]:
    lines = [_events(rule)]
    root = rule.raw if rule.raw is not None else rule.compiled
    terms = list(root.children) if isinstance(root, And) else [root]
    if len(terms) == 1:
        lines.append(f"Fires when {_term(terms[0], macros)}.")
    else:
        lines.append("Fires when all of:")
        lines.extend(f"  - {_term(t, macros)}" for t in terms)
    if rule.exception_names:
        names = ", ".join(f"`{n}`" for n in rule.exception_names)
        fields = ", ".join(f"`{f}`" for f in rule.exception_fields)
        lines.append(f"Unless an exception matches: {names} (on {fields}).")
    status = "enabled" if rule.enabled else "disabled"
    lines.append(f"Priority {rule.priority}, {status}.")
    if rule.output_fields:
        lines.append("Output fields: " + ", ".join(f"`{f}`" for f in rule.output_fields) + ".")
    uses = []
    if rule.macros:
        uses.append("macros " + ", ".join(f"`{m}`" for m in rule.macros))
    if rule.lists:
        uses.append("lists " + ", ".join(f"`{x}`" for x in rule.lists))
    if uses:
        lines.append("Uses " + "; ".join(uses) + ".")
    return tuple(lines)


def _events(rule: Rule) -> str:
    n = len(rule.evttypes)
    if n == 0:
        return "Matches no event type, so it can never fire."
    if n > _MAX_EVENT_NAMES:
        return f"Matches {n} event types."
    names = ", ".join(f"`{e}`" for e in rule.evttypes)
    return f"Matches {'event' if n == 1 else 'events'} {names}."


def _term(node: Node, macros: Mapping[str, Macro]) -> str:
    match node:
        case Identifier(name):
            return _macro(name, macros)
        case Not(Identifier(name)):
            return f"not {_macro(name, macros)}"
    return f"`{render(node, max_items=6)}`"


def _macro(name: str, macros: Mapping[str, Macro]) -> str:
    macro = macros.get(name)
    if macro is None:
        return f"`{name}`"
    text = _unwrap(macro.condition)
    if len(text) > _MAX_MACRO_TEXT:
        text = text[: _MAX_MACRO_TEXT - 3].rstrip() + "..."
    return f"`{name}` ({text})"


def _unwrap(text: str) -> str:
    """Drop one pair of parentheses that encloses the whole text, as macro definitions often have."""
    if not (text.startswith("(") and text.endswith(")")):
        return text
    depth = 0
    for i, ch in enumerate(text):
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if depth == 0 and i < len(text) - 1:
            return text
    return text[1:-1].strip()
