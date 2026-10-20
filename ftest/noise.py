"""The noise check: how often each analyzed rule fires on ordinary, benign activity."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from ftest.cond import quote
from ftest.engine import CaseResult, CaseRun, Rule
from ftest.findings import Finding, Severity
from ftest.suite import Case, Suite

MAX_EXAMPLES = 3
_EXAMPLE_FIELDS = 8


@dataclass(frozen=True)
class Example:
    label: str
    fields: str


@dataclass(frozen=True)
class Noise:
    """`total` counts only the ordinary events of the rule's event types: the ones Falco would
    evaluate the rule on. A share of the whole corpus would mostly measure the corpus's mix of
    event types, and would hide an inverted process rule behind hundreds of file opens."""

    fired: int
    total: int
    budget: float
    base_fired: int | None
    base_total: int | None
    examples: tuple[Example, ...]

    @property
    def rate(self) -> float:
        return self.fired / self.total if self.total else 0.0

    @property
    def over(self) -> bool:
        return self.rate > self.budget

    @property
    def summary(self) -> str:
        if not self.total:
            return "not measured: no ordinary event has one of the rule's event types"
        text = f"fired on {self.fired} of the {self.total} ordinary events of its event types ({percent(self.rate)})"
        text += (
            f", over the {percent(self.budget)} budget" if self.over else f"; budget {percent(self.budget)}"
        )
        if self.base_fired is not None:
            text += f"; the base version fired on {self.base_fired} of {self.base_total}"
        return text


def percent(share: float) -> str:
    text = f"{share * 100:.1f}"
    return (text[:-2] if text.endswith(".0") else text) + "%"


def budget(rule: str, suites: Iterable[Suite], default: float) -> float:
    """A suite's `max_fire_rate` overrides the default; with several suites the largest wins."""
    overrides = [s.max_fire_rate for s in suites if s.rule == rule and s.max_fire_rate is not None]
    return max(overrides) if overrides else default


def measure(
    rule: Rule,
    events: Sequence[Case],
    full: Mapping[str, CaseResult],
    base: tuple[Rule, Mapping[str, CaseResult]] | None,
    limit: float,
) -> Noise:
    seen = _seen_by(rule, events)
    fired = [e for e in seen if _fires(full.get(e.id), rule.name)]
    base_fired = base_total = None
    if base is not None:
        base_rule, base_cases = base
        base_seen = _seen_by(base_rule, events)
        base_fired = sum(1 for e in base_seen if _fires(base_cases.get(e.id), rule.name))
        base_total = len(base_seen)
    examples = tuple(example(e, rule) for e in _diverse(fired)[:MAX_EXAMPLES])
    return Noise(len(fired), len(seen), limit, base_fired, base_total, examples)


def _seen_by(rule: Rule, events: Sequence[Case]) -> list[Case]:
    types = frozenset(rule.evttypes)
    return [e for e in events if e.event["evt.type"][0] in types]


def finding(rule: str, noise: Noise) -> Finding | None:
    if not noise.over:
        return None
    base = "" if noise.base_fired is None else f"; the base version fires on {noise.base_fired}"
    return Finding(
        "FTE013",
        Severity.ERROR,
        rule,
        f"fires on {percent(noise.rate)} of ordinary activity ({noise.fired} of {noise.total} benign events "
        f"of its event types), over the {percent(noise.budget)} budget{base}. A rule that fires this often "
        "is likely inverted or missing a filter",
        "Look for a `not` that should not be there or a condition that went missing. If the rule is meant "
        "to fire this often, set `max_fire_rate` in its suite.",
    )


def example(event: Case, rule: Rule) -> Example:
    """The fields the rule reads, as compact field=value pairs."""
    keys = list(dict.fromkeys(["evt.type", "proc.name", *rule.condition_fields]))
    shown = [k for k in keys if k in event.event][:_EXAMPLE_FIELDS]
    return Example(event.name, " ".join(f"{k}={_value(event.event[k])}" for k in shown))


def _value(values: tuple[str, ...]) -> str:
    if len(values) == 1:
        return quote(values[0])
    return "[" + ", ".join(quote(v) for v in values) + "]"


def _fires(result: CaseResult | None, rule: str) -> bool:
    return isinstance(result, CaseRun) and result.alert_for(rule) is not None


def _diverse(events: list[Case]) -> list[Case]:
    """One event per event type first, so the examples show how broadly the rule fires."""
    first: dict[str, Case] = {}
    for e in events:
        first.setdefault(e.event["evt.type"][0], e)
    picked = {id(e) for e in first.values()}
    return list(first.values()) + [e for e in events if id(e) not in picked]
