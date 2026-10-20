"""Performance and correctness lints over a rule's compiled condition, plus a work metric.

Semantics these lints rely on, from libs 0.26 (libsinsp/filter):
- `regex` is RE2 POSIX matched with ANCHOR_BOTH: the pattern must match the whole value.
- `glob` is fnmatch(3) without FNM_PATHNAME or FNM_PERIOD: `*` matches any characters.
- String operators accept the `anyof` modifier (`contains anyof (a, b)`), except that the
  unindexed ancestor walks (`proc.aname` etc.) ignore modifiers and IP fields reject them.
- `and`/`or` operands have no side effects, so reordering them never changes the result.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import IntEnum

from ftest.cond import (
    And,
    Check,
    Field,
    ListValue,
    Node,
    Not,
    Or,
    Transformer,
    Value,
    checks,
    conjuncts,
    quote,
    render,
    walk,
)
from ftest.engine import Alert, ListDef, Load, Macro, Rule, Trace
from ftest.findings import Finding, Severity
from ftest.shape import Shape

MAX_EVENT_TYPES = 100

ANCESTOR_FIELDS = frozenset({"proc.aname", "proc.apid", "proc.aexe", "proc.aexepath", "proc.acmdline"})
ANY_OF_FIELDS = ANCESTOR_FIELDS | {"fd.ip", "fd.port", "fd.net", "fd.proto"}
IP_FIELDS = frozenset(
    {"fd.ip", "fd.cip", "fd.sip", "fd.lip", "fd.rip", "fd.net", "fd.cnet", "fd.snet", "fd.lnet", "fd.rnet"}
)
DNS_FIELDS = frozenset({"fd.cip.name", "fd.sip.name", "fd.lip.name", "fd.rip.name"})
CHEAP_FIELDS = frozenset(
    {"evt.type", "evt.dir", "proc.name", "proc.pid", "user.uid", "container.id", "fd.typechar"}
)
LONG_STRING_FIELDS = frozenset({"proc.cmdline", "fd.name", "proc.exepath", "proc.args"})
STRING_OPS = frozenset({"contains", "icontains", "startswith", "endswith", "bcontains", "bstartswith"})
ANYOF_OPS = frozenset({"contains", "icontains", "startswith", "endswith", "glob", "iglob"})


class Cost(IntEnum):
    CHEAP = 1
    MEDIUM = 2
    EXPENSIVE = 3


WEIGHT = {Cost.CHEAP: 1, Cost.MEDIUM: 4, Cost.EXPENSIVE: 16}


def _field(check: Check) -> str:
    lhs = check.lhs
    while isinstance(lhs, Transformer):
        lhs = next((a for a in lhs.args if isinstance(a, Field | Transformer)), None)
    return lhs.field if isinstance(lhs, Field) else ""


def _unindexed_any_of(check: Check) -> bool:
    return isinstance(check.lhs, Field) and check.lhs.field in ANY_OF_FIELDS and check.lhs.arg is None


@dataclass(frozen=True)
class CostRule:
    applies: Callable[[Check], bool]
    cost: Cost
    reason: str


# First match wins, so the most expensive reasons come first.
COST_TABLE: tuple[CostRule, ...] = (
    CostRule(lambda c: c.base_op == "regex", Cost.EXPENSIVE, "regex match"),
    CostRule(
        lambda c: _field(c) in ANCESTOR_FIELDS and isinstance(c.lhs, Field) and c.lhs.arg is None,
        Cost.EXPENSIVE,
        "walks every ancestor process",
    ),
    CostRule(
        lambda c: _field(c) in {"proc.env", "proc.aenv"}, Cost.EXPENSIVE, "scans the process environment"
    ),
    CostRule(lambda c: _field(c) in DNS_FIELDS, Cost.EXPENSIVE, "DNS name lookup"),
    CostRule(lambda c: c.base_op in ("glob", "iglob"), Cost.MEDIUM, "glob match"),
    CostRule(
        lambda c: c.base_op in STRING_OPS and _field(c) in LONG_STRING_FIELDS,
        Cost.MEDIUM,
        "substring scan of a long string",
    ),
    CostRule(lambda c: _field(c) in ANCESTOR_FIELDS, Cost.MEDIUM, "looks up one ancestor process"),
    CostRule(
        lambda c: _field(c).startswith(("container.", "k8s.")) and _field(c) != "container.id",
        Cost.MEDIUM,
        "plugin field extraction",
    ),
    CostRule(lambda c: isinstance(c.lhs, Transformer), Cost.MEDIUM, "applies a transformer"),
)


def check_cost(check: Check) -> tuple[Cost, str]:
    for rule in COST_TABLE:
        if rule.applies(check):
            return rule.cost, rule.reason
    return Cost.CHEAP, "direct field read"


def node_cost(node: Node) -> Cost:
    return max((check_cost(c)[0] for c in checks(node)), default=Cost.CHEAP)


def _costliest(node: Node) -> tuple[Cost, str]:
    return max((check_cost(c) for c in checks(node)), key=lambda cr: cr[0], default=(Cost.CHEAP, ""))


@dataclass(frozen=True)
class CaseRun:
    case: str
    trace: Trace | None
    alert: Alert | None


@dataclass(frozen=True)
class RuleView:
    rule: Rule
    shape: Shape
    macros: Mapping[str, Macro]
    lists: Mapping[str, ListDef]
    runs: tuple[CaseRun, ...] = ()


@dataclass(frozen=True)
class Lint:
    code: str
    title: str
    check: Callable[[RuleView], Iterable[Finding]]


def _finding(
    view: RuleView, code: str, severity: Severity, message: str, suggestion: str | None = None
) -> Finding:
    return Finding(code, severity, view.rule.name, message, suggestion)


def _body_nodes(view: RuleView) -> Iterator[Node]:
    return walk(view.shape.body)


def _event_types(view: RuleView) -> Iterator[Finding]:
    n = len(view.rule.evttypes)
    if n > MAX_EVENT_TYPES:
        yield _finding(
            view,
            "FTE001",
            Severity.WARNING,
            f"matches {n} event types, so Falco evaluates it on nearly every event (Falco warns about this too)",
            "Start the condition with an event-type restriction such as `evt.type in (...)` or a macro like "
            "`spawned_process`. That narrows what the rule matches, so it is not an equivalent rewrite.",
        )


def _is_negative_event_type(node: Node) -> bool:
    match node:
        case Check(op="!=", lhs=Field("evt.type")):
            return True
        case Not(Check(lhs=Field("evt.type"), op=op)) if op in ("=", "==", "in"):
            return True
    return False


def _negative_event_type(view: RuleView) -> Iterator[Finding]:
    broad = len(view.rule.evttypes) > MAX_EVENT_TYPES
    for term in conjuncts(view.shape.body):
        if not _is_negative_event_type(term):
            continue
        text = view.shape.display(term)
        if broad:
            yield _finding(
                view,
                "FTE002",
                Severity.WARNING,
                f"top-level negative event-type check `{text}` lets the rule match every other event type",
                "Replace it with a positive `evt.type in (...)` that lists the types the rule is for. "
                "Not equivalent unless that list covers every type you mean.",
            )
        else:
            yield _finding(
                view,
                "FTE002",
                Severity.INFO,
                f"top-level negative event-type check `{text}`; other terms already restrict the event types, "
                "so it costs one comparison",
            )


def _merge_or(view: RuleView, key: Callable[[Check], str | None], merged_op: Callable[[str], str]):
    for node in _body_nodes(view):
        if not isinstance(node, Or):
            continue
        groups: dict[tuple[str, str], list[Check]] = {}
        for child in node.children:
            if isinstance(child, Check) and isinstance(child.rhs, Value | ListValue) and (op := key(child)):
                groups.setdefault((render(child.lhs), op), []).append(child)
        for (lhs_text, op), members in groups.items():
            if len(members) < 2:
                continue
            shown = [view.shape.raw_of.get(id(m), m) for m in members]
            values = tuple(v for m in shown for v in _values(m))
            merged = Check(merged_op(op), members[0].lhs, ListValue(values))
            rest = [view.shape.display(c, None) for c in node.children if all(c is not m for m in members)]
            before = " or ".join(view.shape.display(m, None) for m in members)
            after = " or ".join([render(merged), *rest])
            yield members, lhs_text, op, before, after


def _values(check) -> tuple[str, ...]:
    return check.rhs.values if isinstance(check.rhs, ListValue) else (check.rhs.value,)


def _equals_to_in(view: RuleView) -> Iterator[Finding]:
    def key(c: Check) -> str | None:
        return "in" if c.modifier is None and c.base_op in ("=", "==", "in") else None

    for members, lhs, _, before, after in _merge_or(view, key, lambda _: "in"):
        yield _finding(
            view,
            "FTE003",
            Severity.INFO,
            f"{view.shape.where(members[0])}: {len(members)} equality checks on `{lhs}` joined by `or`",
            f"`{before}` -> `{after}`. Equivalent: `in` is one set lookup.",
        )


def _string_ops_to_anyof(view: RuleView) -> Iterator[Finding]:
    def key(c: Check) -> str | None:
        if c.base_op not in ANYOF_OPS or c.modifier not in (None, "anyof"):
            return None
        if _unindexed_any_of(c) or _field(c) in IP_FIELDS:
            return None
        return c.base_op

    for members, lhs, op, before, after in _merge_or(view, key, lambda op: f"{op} anyof"):
        yield _finding(
            view,
            "FTE004",
            Severity.INFO,
            f"{view.shape.where(members[0])}: {len(members)} `{op}` checks on `{lhs}` joined by `or`",
            f"`{before}` -> `{after}`. Equivalent: `{op} anyof` is true when any value matches "
            "(string-operator modifiers are accepted by the libs 0.26 parser).",
        )


def reorder(node: Node) -> Node:
    """Cheapest operands first in every and/or; stable, so equal-cost operands keep their order."""
    match node:
        case And(children) | Or(children):
            ordered = tuple(sorted((reorder(c) for c in children), key=node_cost))
            return And(ordered) if isinstance(node, And) else Or(ordered)
        case Not(child):
            return Not(reorder(child))
    return node


def _reorder_raw(raw: Node, comp: Node) -> Node:
    match raw, comp:
        case ((And(rc) | Or(rc)), (And(cc) | Or(cc))):
            pairs = sorted(((_reorder_raw(r, c), c) for r, c in zip(rc, cc)), key=lambda p: node_cost(p[1]))
            ordered = tuple(r for r, _ in pairs)
            return And(ordered) if isinstance(raw, And) else Or(ordered)
        case Not(r), Not(c):
            return Not(_reorder_raw(r, c))
    return raw


def _first_inversion(root: Node, owned: Callable[[Node], bool]) -> tuple[Node, str] | None:
    for node in walk(root):
        if isinstance(node, And | Or) and owned(node):
            costs = [node_cost(c) for c in node.children]
            for i, child in enumerate(node.children):
                if any(costs[i] > later for later in costs[i + 1 :]):
                    return child, _costliest(child)[1]
    return None


def _ordering(view: RuleView) -> Iterator[Finding]:
    shape = view.shape
    equivalent = "Equivalent: `and`/`or` operands have no side effects in Falco."
    if shape.aligned:
        reordered = _reorder_raw(shape.raw, shape.body)
        if render(reordered) != render(shape.raw):
            child, reason = _first_inversion(shape.body, lambda n: id(n) in shape.raw_of)
            yield _finding(
                view,
                "FTE005",
                _ordering_severity(shape.body),
                f"`{shape.display(child)}` ({reason}) is evaluated before cheaper checks",
                f"Reorder the condition: `{render(reordered)}`. {equivalent}",
            )
        seen = set()
        for use in shape.macros:
            if use.name in seen:
                continue
            seen.add(use.name)
            reordered_macro = reorder(use.node)
            if render(reordered_macro) != render(use.node):
                child, reason = _first_inversion(use.node, lambda n: True)
                yield _finding(
                    view,
                    "FTE005",
                    _ordering_severity(use.node),
                    f"in macro `{use.name}`: `{render(child, 6)}` ({reason}) is evaluated before cheaper checks",
                    f"Reorder the macro condition (lists and nested macros shown expanded): "
                    f"`{render(reordered_macro)}`. {equivalent}",
                )
    else:
        reordered = reorder(shape.body)
        if render(reordered) != render(shape.body):
            child, reason = _first_inversion(shape.body, lambda n: True)
            yield _finding(
                view,
                "FTE005",
                _ordering_severity(shape.body),
                f"`{render(child, 6)}` ({reason}) is evaluated before cheaper checks",
                f"Reorder the compiled condition: `{render(reordered)}`. {equivalent}",
            )


def _ordering_severity(root: Node) -> Severity:
    for node in walk(root):
        if isinstance(node, And | Or):
            costs = [node_cost(c) for c in node.children]
            for i, cost in enumerate(costs):
                if cost == Cost.EXPENSIVE and Cost.CHEAP in costs[i + 1 :]:
                    return Severity.WARNING
    return Severity.INFO


_VERB = {"startswith": "start with", "endswith": "end with"}
_RE_SPECIAL = frozenset(".^$*+?()[]{}|\\")
_GLOB_SPECIAL = frozenset("*?[\\")


def _regex_literal(text: str) -> str | None:
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            if i + 1 < len(text) and not text[i + 1].isalnum():
                out.append(text[i + 1])
                i += 2
                continue
            return None
        if ch in _RE_SPECIAL:
            return None
        out.append(ch)
        i += 1
    return "".join(out) or None


def regex_rewrite(pattern: str) -> tuple[str, str, str | None] | None:
    """(operator, literal, hint) when a regex is a literal with optional anchors and `.*` ends."""
    body = pattern
    starts = body.startswith("^")
    body = body[1:] if starts else body
    ends = body.endswith("$") and not body.endswith("\\$")
    body = body[:-1] if ends else body
    lead = body.startswith(".*")
    body = body[2:] if lead else body
    trail = body.endswith(".*") and not body.endswith("\\.*")
    body = body[:-2] if trail else body
    literal = _regex_literal(body)
    if literal is None:
        return None
    op = {
        (False, False): "=",
        (True, False): "endswith",
        (False, True): "startswith",
        (True, True): "contains",
    }[(lead, trail)]
    hint = None
    if op == "=" and starts and not ends:
        hint = "startswith"
    elif op == "=" and ends and not starts:
        hint = "endswith"
    return op, literal, hint


def glob_rewrite(op: str, pattern: str) -> tuple[str, str] | None:
    def plain(s: str) -> bool:
        return bool(s) and not any(ch in _GLOB_SPECIAL for ch in s)

    if len(pattern) > 2 and pattern[0] == "*" and pattern[-1] == "*" and plain(pattern[1:-1]):
        return ("contains" if op == "glob" else "icontains"), pattern[1:-1]
    if op != "glob":
        return None
    if plain(pattern):
        return "=", pattern
    if pattern.endswith("*") and plain(pattern[:-1]):
        return "startswith", pattern[:-1]
    if pattern.startswith("*") and plain(pattern[1:]):
        return "endswith", pattern[1:]
    return None


def _simple_patterns(view: RuleView) -> Iterator[Finding]:
    for check in checks(view.shape.body):
        if check.modifier is not None or not isinstance(check.rhs, Value):
            continue
        lhs = render(check.lhs)
        text = view.shape.display(check)
        if check.base_op == "regex" and (rewrite := regex_rewrite(check.rhs.value)):
            op, literal, hint = rewrite
            if op == "=":
                message = f"`{text}` only matches the exact value `{literal}`: Falco regexes must match the whole value"
                suggestion = f"Use `{lhs} = {quote(literal)}`. Equivalent, without the regex engine."
                if hint:
                    suggestion += (
                        f" If you meant values that {_VERB[hint]} `{literal}`, use "
                        f"`{lhs} {hint} {quote(literal)}`; that changes what the rule matches."
                    )
            else:
                message = f"`{text}` is a regex for a plain `{op}` test"
                suggestion = (
                    f"Use `{lhs} {op} {quote(literal)}`. Equivalent for values without newlines "
                    "(`.` in Falco's RE2 regex does not match a newline)."
                )
            yield _finding(view, "FTE006", Severity.WARNING, message, suggestion)
        elif check.base_op in ("glob", "iglob") and (rewrite := glob_rewrite(check.base_op, check.rhs.value)):
            op, literal = rewrite
            yield _finding(
                view,
                "FTE006",
                Severity.INFO,
                f"`{text}` is a glob for a plain `{op}` test",
                f"Use `{lhs} {op} {quote(literal)}`. Equivalent: Falco's glob has no path rules, "
                "so `*` matches any characters.",
            )


def _duplicates(items: Iterable[str]) -> list[str]:
    seen, dups = set(), []
    for item in items:
        if item in seen and item not in dups:
            dups.append(item)
        seen.add(item)
    return dups


def _repeats(view: RuleView) -> Iterator[Finding]:
    rule = view.rule
    names = list(rule.lists) + [x for m in rule.macros if m in view.macros for x in view.macros[m].lists]
    for name in dict.fromkeys(names):
        if name in view.lists and (dups := _duplicates(view.lists[name].items)):
            yield _finding(
                view,
                "FTE007",
                Severity.INFO,
                f"list `{name}` repeats {', '.join(f'`{d}`' for d in dups)}",
                "Remove the repeated items. Equivalent: list membership is a set lookup.",
            )
    for check in checks(view.shape.raw) if view.shape.raw is not None else ():
        if isinstance(check.rhs, ListValue) and (dups := _duplicates(check.rhs.values)):
            yield _finding(
                view,
                "FTE007",
                Severity.INFO,
                f"`{render(check, 6)}` repeats {', '.join(f'`{d}`' for d in dups)}",
                "Remove the repeated values. Equivalent: list membership is a set lookup.",
            )
    for node in _body_nodes(view):
        if isinstance(node, And | Or):
            for text in _duplicates(render(c) for c in node.children):
                word = "and" if isinstance(node, And) else "or"
                yield _finding(
                    view,
                    "FTE007",
                    Severity.WARNING,
                    f"{view.shape.where(node)}: `{text}` appears twice in the same `{word}`",
                    f"Remove one copy. Equivalent: `x {word} x` is `x`.",
                )


def _contradiction(terms: list[Node]) -> list[Check] | None:
    """The equality and `in` terms on one field whose allowed values have no common member."""
    allowed: dict[str, tuple[set[str], list[Check]]] = {}
    for term in terms:
        if not (
            isinstance(term, Check)
            and term.modifier is None
            and term.base_op in ("=", "==", "in")
            and isinstance(term.rhs, Value | ListValue)
            and not _unindexed_any_of(term)
        ):
            continue
        key = render(term.lhs)
        values = set(_values(term))
        if key in allowed:
            narrowed = allowed[key][0] & values
            involved = [*allowed[key][1], term]
            if not narrowed:
                return involved
            allowed[key] = (narrowed, involved)
        else:
            allowed[key] = (values, [term])
    return None


def _all_of(shape: Shape, terms: list[Check]) -> str:
    shown = [f"`{shape.display(t)}`" for t in terms]
    return (" and " if len(shown) == 2 else ", ").join(shown)


def _and_chains(node: Node, under_and: bool = False) -> Iterator[And]:
    if isinstance(node, And) and not under_and:
        yield node
    match node:
        case And(children):
            for c in children:
                yield from _and_chains(c, True)
        case Or(children):
            for c in children:
                yield from _and_chains(c, False)
        case Not(child):
            yield from _and_chains(child, False)


def _never_fires(view: RuleView) -> Iterator[Finding]:
    rule, shape = view.rule, view.shape
    why = None
    if not rule.evttypes:
        why = "no event type can satisfy its condition"
    elif terms := _contradiction(conjuncts(shape.body)):
        why = f"{_all_of(shape, terms)} can never {'both' if len(terms) == 2 else 'all'} be true"
    if why:
        if "never_true" in rule.macros:
            yield _finding(
                view,
                "FTE008",
                Severity.INFO,
                f"can never fire: {why}. It uses `never_true`, so this is on purpose.",
            )
        elif not rule.enabled:
            yield _finding(view, "FTE008", Severity.INFO, f"can never fire: {why}. The rule is disabled.")
        else:
            yield _finding(
                view,
                "FTE008",
                Severity.ERROR,
                f"can never fire: {why}. The rule is enabled and is not the `never_true` idiom, so this is a bug.",
            )
    root = shape.body if isinstance(shape.body, And) else None
    for chain in _and_chains(shape.body):
        if chain is root:
            continue
        if terms := _contradiction(conjuncts(chain)):
            yield _finding(
                view,
                "FTE008",
                Severity.WARNING,
                f"{shape.where(chain)}: `{shape.display(chain)}` can never be true "
                f"({_all_of(shape, terms)} conflict)",
            )


_OUTPUT_TOKEN = re.compile(r"%(\()?([A-Za-z_][\w.]*(?:\[[^\]]*\])?)(?(1)\))")


def na_fields(template: str, output: str) -> list[str]:
    """Output fields that rendered `<NA>`, found by matching the output against its template."""
    template = template.removeprefix("*")
    parts, fields, pos = [], [], 0
    for m in _OUTPUT_TOKEN.finditer(template):
        parts += [re.escape(template[pos : m.start()]), "(.*?)"]
        fields.append(m.group(2))
        pos = m.end()
    parts.append(re.escape(template[pos:]))
    match = re.search("".join(parts) + r"\Z", output, re.DOTALL)
    if match is None:
        return ["(unmatched output)"] if "<NA>" in output else []
    return list(dict.fromkeys(f for f, v in zip(fields, match.groups()) if v == "<NA>"))


def _na_outputs(view: RuleView) -> Iterator[Finding]:
    cases_by_field: dict[str, list[str]] = {}
    for run in view.runs:
        if run.alert is not None:
            for field in na_fields(view.rule.output, run.alert.output):
                cases_by_field.setdefault(field, []).append(run.case)
    for field, cases in cases_by_field.items():
        names = ", ".join(f"`{c}`" for c in cases[:3]) + (
            f" (+{len(cases) - 3} more)" if len(cases) > 3 else ""
        )
        yield _finding(
            view,
            "FTE009",
            Severity.INFO,
            f"output field `{field}` rendered `<NA>` on matching case(s) {names}",
            "Set the field in the test event. If real events of this type cannot carry it, drop it from "
            "the output.",
        )


LINTS: tuple[Lint, ...] = (
    Lint("FTE001", "no or broad event-type restriction", _event_types),
    Lint("FTE002", "top-level negative event type", _negative_event_type),
    Lint("FTE003", "equality checks that could be one `in`", _equals_to_in),
    Lint("FTE004", "string checks that could use `anyof`", _string_ops_to_anyof),
    Lint("FTE005", "costly checks before cheap ones", _ordering),
    Lint("FTE006", "regex or glob that is a plain string test", _simple_patterns),
    Lint("FTE007", "duplicate list items or predicates", _repeats),
    Lint("FTE008", "condition that can never be true", _never_fires),
    Lint("FTE009", "output fields rendered <NA>", _na_outputs),
)

_UNUSED_CODES = frozenset({"LOAD_UNUSED_MACRO", "LOAD_UNUSED_LIST"})


def lint_rule(view: RuleView, disabled: frozenset[str] = frozenset()) -> list[Finding]:
    found: dict[tuple, Finding] = {}
    for lint in LINTS:
        if lint.code in disabled:
            continue
        for f in lint.check(view):
            found.setdefault((f.code, f.message, f.suggestion), f)
    return list(found.values())


def load_warnings(load: Load, disabled: frozenset[str] = frozenset()) -> list[Finding]:
    """FTE010: Falco's own load warnings, one finding per warning code."""
    if "FTE010" in disabled:
        return []
    by_code: dict[str, list] = {}
    for w in load.warnings:
        by_code.setdefault(w.code, []).append(w)
    findings = []
    for code, warnings in by_code.items():
        names = list(dict.fromkeys(w.item_name for w in warnings if w.item_name))
        shown = ", ".join(f"`{n}`" for n in names[:5]) + (
            f" (+{len(names) - 5} more)" if len(names) > 5 else ""
        )
        what = warnings[0].description or warnings[0].message
        detail = f": {warnings[0].message}" if len(warnings) == 1 and warnings[0].message else ""
        findings.append(
            Finding(
                "FTE010",
                Severity.INFO if code in _UNUSED_CODES else Severity.WARNING,
                None,
                f"Falco load warning {code} ({what}) x{len(warnings)}"
                + (f" on {shown}" if shown else "")
                + detail,
            )
        )
    return findings


@dataclass(frozen=True)
class Work:
    cases: int
    current: int
    current_weighted: int
    suggested: int
    suggested_weighted: int

    @property
    def summary(self) -> str:
        text = (
            f"predicates evaluated on the test cases (not a production timing): {self.current} "
            f"(cost-weighted {self.current_weighted}) over {self.cases} cases"
        )
        if self.suggested_weighted < self.current_weighted:
            text += f"; {self.suggested} (cost-weighted {self.suggested_weighted}) with the suggested order"
        return text


def _simulate(node: Node, leaves: tuple[bool, ...]) -> tuple[bool, int, int]:
    match node:
        case Check(id=leaf_id):
            return leaves[leaf_id], 1, WEIGHT[check_cost(node)[0]]
        case Not(child):
            value, n, w = _simulate(child, leaves)
            return not value, n, w
        case And(children) | Or(children):
            stop_on = isinstance(node, Or)
            n = w = 0
            for child in children:
                value, cn, cw = _simulate(child, leaves)
                n, w = n + cn, w + cw
                if value == stop_on:
                    return stop_on, n, w
            return not stop_on, n, w
    raise ValueError(f"cannot simulate {node!r}")


def suggested_condition(view: RuleView) -> Node:
    compiled = view.rule.compiled
    if view.shape.body is not compiled and isinstance(compiled, And):
        return And((reorder(view.shape.body), *compiled.children[1:]))
    return reorder(compiled)


def work(view: RuleView) -> Work | None:
    traces = [r.trace for r in view.runs if r.trace is not None]
    if not traces:
        return None
    suggested = suggested_condition(view)
    now = [_simulate(view.rule.compiled, t.leaves) for t in traces]
    then = [_simulate(suggested, t.leaves) for t in traces]
    return Work(
        cases=len(traces),
        current=sum(n for _, n, _ in now),
        current_weighted=sum(w for _, _, w in now),
        suggested=sum(n for _, n, _ in then),
        suggested_weighted=sum(w for _, _, w in then),
    )
