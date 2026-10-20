"""Distinguishing events: field values on which a rule and one of its surviving mutants disagree.

The search starts from each test case's real leaf values and flips as few leaves as it can (1, then
2, then 3) until the rule and the mutant disagree. Then it turns the flipped leaves back into field
values: it starts from the case's event and changes only the fields those leaves read, picking a
value the operator model says gives every leaf on that field its wanted truth value.

The operator model is a search heuristic, not Falco. The engine evaluates every candidate (see
`verified`), and a candidate counts only when the engine's own leaf values separate the two.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations

from ftest.cond import Check, Field, ListValue, Node, Value, checks, evaluate, render
from ftest.engine import CaseResult, CaseRun, Rule
from ftest.fixtures import derive
from ftest.mutate import Mutant
from ftest.strength import Generated, Run
from ftest.suite import Case

MAX_FLIPS = 3
MAX_CANDIDATES = 3
MAX_TRIES = 20_000
FALLBACK = "ftest-other"
ID_PREFIX = "generated::"


class _Absent:
    """The candidate "leave the field unset": every check on the field is then false."""


ABSENT = _Absent()
type Choice = str | _Absent


@dataclass(frozen=True)
class Operator:
    true_candidates: Callable[[tuple[str, ...]], list[Choice]]
    false_candidates: Callable[[tuple[str, ...]], list[Choice]]
    holds: Callable[[str, tuple[str, ...]], bool]


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if "/" not in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _number(text: str) -> int | None:
    try:
        return int(text)
    except ValueError:
        return None


def _equal(value: str, target: str) -> bool:
    """Falco compares IP fields with networks by membership and numbers by value."""
    ip, net = _ip(value), _network(target)
    if ip is not None and net is not None:
        return ip in net
    if ip is not None and (other := _ip(target)) is not None:
        return ip == other
    a, b = _number(value), _number(target)
    if a is not None and b is not None:
        return a == b
    return value == target


def _member(target: str) -> str:
    net = _network(target)
    return str(next(net.hosts(), net.network_address)) if net is not None else target


def _others(rhs: tuple[str, ...]) -> list[Choice]:
    """Values of each target's type that equal none of the targets."""
    found: list[str] = []
    for target in rhs:
        if target in ("true", "false"):
            found.append("false" if target == "true" else "true")
        elif (n := _number(target)) is not None:
            found += [str(n + 1), str(n - 1)]
        elif _ip(target) is not None or _network(target) is not None:
            found += ["203.0.113.7", "198.51.100.7", "10.255.255.254"]
    return [v for v in found if not any(_equal(v, t) for t in rhs)]


def _glob_example(pattern: str) -> list[Choice]:
    if "[" in pattern:
        return []
    return [pattern.replace("*", "x").replace("?", "x")]


def _compare(test: Callable[[int, int], bool]) -> Callable[[str, tuple[str, ...]], bool]:
    def holds(value: str, rhs: tuple[str, ...]) -> bool:
        a, b = _number(value), _number(rhs[0])
        return a is not None and b is not None and test(a, b)

    return holds


def _numbers(*offsets: int) -> Callable[[tuple[str, ...]], list[Choice]]:
    def candidates(rhs: tuple[str, ...]) -> list[Choice]:
        n = _number(rhs[0])
        return [] if n is None else [str(n + d) for d in offsets]

    return candidates


def _any(test: Callable[[str, str], bool]) -> Callable[[str, tuple[str, ...]], bool]:
    return lambda value, rhs: any(test(value, target) for target in rhs)


def _same(rhs: tuple[str, ...]) -> list[Choice]:
    return [_member(t) for t in rhs]


def _nothing(rhs: tuple[str, ...]) -> list[Choice]:
    return []


def _under(value: str, prefix: str) -> bool:
    return value == prefix or value.startswith(prefix.rstrip("/") + "/")


_equals = Operator(_same, _others, _any(_equal))
OPERATORS: dict[str, Operator] = {
    "=": _equals,
    "==": _equals,
    "in": _equals,
    "!=": Operator(_others, _same, lambda value, rhs: not _equal(value, rhs[0])),
    "pmatch": Operator(_same, _nothing, _any(_under)),
    "startswith": Operator(_same, _nothing, _any(lambda v, t: v.startswith(t))),
    "endswith": Operator(_same, _nothing, _any(lambda v, t: v.endswith(t))),
    "contains": Operator(_same, _nothing, _any(lambda v, t: t in v)),
    "icontains": Operator(_same, _nothing, _any(lambda v, t: t.lower() in v.lower())),
    "glob": Operator(
        lambda rhs: [c for t in rhs for c in _glob_example(t)], _nothing, _any(fnmatch.fnmatchcase)
    ),
    "exists": Operator(_nothing, lambda rhs: [ABSENT], lambda value, rhs: True),
    "<": Operator(_numbers(-1), _numbers(0, 1), _compare(lambda a, b: a < b)),
    "<=": Operator(_numbers(0, -1), _numbers(1), _compare(lambda a, b: a <= b)),
    ">": Operator(_numbers(1), _numbers(0, -1), _compare(lambda a, b: a > b)),
    ">=": Operator(_numbers(0, 1), _numbers(-1), _compare(lambda a, b: a >= b)),
}
_MODIFIERS = frozenset({None, "anyof"})


def modelable(check: Check) -> bool:
    """Whether the operator model can predict this check. Transformers, `val()`, `regex`, and
    modifiers other than `anyof` are left alone: assignments that need to flip them are skipped."""
    return (
        isinstance(check.lhs, Field)
        and check.base_op in OPERATORS
        and check.modifier in _MODIFIERS
        and (check.rhs is None or isinstance(check.rhs, Value | ListValue))
    )


def rhs_values(check: Check) -> tuple[str, ...]:
    match check.rhs:
        case Value(value):
            return (value,)
        case ListValue(values):
            return values
    return ()


def holds(check: Check, values: tuple[str, ...] | None) -> bool:
    """The model's truth value for a check, given the field's values (None when unset)."""
    if values is None:
        return False
    op = OPERATORS[check.base_op]
    return any(op.holds(v, rhs_values(check)) for v in values)


@dataclass(frozen=True)
class Candidate:
    run: Run
    changes: Mapping[str, tuple[str, ...] | None]
    given: Mapping[str, tuple[str, ...]]
    event: Mapping[str, tuple[str, ...]]

    @property
    def name(self) -> str:
        parts = [f"{k}={','.join(v)}" if v is not None else f"no {k}" for k, v in self.changes.items()]
        return f"{self.run.case.name}, with {', '.join(parts)}"


@dataclass(frozen=True)
class _Leaves:
    checks: Mapping[int, Check]
    keys: Mapping[int, str]
    by_key: Mapping[str, tuple[int, ...]]
    flippable: tuple[int, ...]


def _leaves(compiled: Node) -> _Leaves:
    found = {c.id: c for c in checks(compiled) if c.id is not None}
    keys = {i: render(c.lhs) for i, c in found.items() if isinstance(c.lhs, Field)}
    by_key: dict[str, list[int]] = {}
    for i, key in keys.items():
        by_key.setdefault(key, []).append(i)
    flippable = tuple(i for i, c in sorted(found.items()) if modelable(c))
    return _Leaves(found, keys, {k: tuple(v) for k, v in by_key.items()}, flippable)


def search(
    rule: Rule, mutant: Mutant, runs: Sequence[Run], pool: Mapping[str, tuple[str, ...]]
) -> list[Candidate]:
    """Up to MAX_CANDIDATES candidate events, fewest flipped leaves first."""
    leaves = _leaves(rule.compiled)
    found: list[Candidate] = []
    seen: set[str] = set()
    tries = 0
    for size in range(1, MAX_FLIPS + 1):
        for run in runs:
            for flips in combinations(leaves.flippable, size):
                tries += 1
                if tries > MAX_TRIES:
                    return found
                target = list(run.trace.leaves)
                for i in flips:
                    target[i] = not target[i]
                if evaluate(rule.compiled, target) == evaluate(mutant.ast, target):
                    continue
                candidate = _synthesize(rule.compiled, mutant.ast, leaves, run, flips, target, pool)
                if candidate is not None and (key := repr(sorted(candidate.event.items()))) not in seen:
                    seen.add(key)
                    found.append(candidate)
                    if len(found) == MAX_CANDIDATES:
                        return found
    return found


def _synthesize(original, mutant, leaves, run, flips, target, pool) -> Candidate | None:
    defaults, given = run.suite.defaults, run.case.given
    changes: dict[str, tuple[str, ...] | None] = {}
    for key in dict.fromkeys(leaves.keys[i] for i in flips):
        on_key = [i for i in leaves.by_key[key] if modelable(leaves.checks[i])]
        wanted = [(leaves.checks[i], target[i]) for i in on_key if i in flips]
        kept = [(leaves.checks[i], target[i]) for i in on_key if i not in flips]
        removable = key in given and key not in defaults
        value = solve(wanted, pool.get(key, ()), removable, kept)
        if value is None:
            return None
        changes[key] = None if value is ABSENT else (value,)
    new_given = {k: changes.get(k, v) for k, v in given.items()} | changes
    new_given = {k: v for k, v in new_given.items() if v is not None}
    event = derive({**defaults, **new_given})
    if any(v is None and k in event for k, v in changes.items()):
        return None
    predicted = _predict(leaves, run, event)
    if evaluate(original, predicted) == evaluate(mutant, predicted):
        return None
    return Candidate(run, changes, new_given, event)


def solve(
    wanted: Sequence[tuple[Check, bool]],
    pool: Sequence[str],
    removable: bool,
    kept: Sequence[tuple[Check, bool]] = (),
) -> str | _Absent | None:
    """A value that gives every wanted check on one field its truth value, or None.

    `kept` are the field's other checks. A value that keeps them as they are wins; when none
    exists, they may change too, and the caller recomputes them."""
    candidates: list[Choice] = []
    for check, truth in [*wanted, *kept]:
        op = OPERATORS[check.base_op]
        candidates += (op.true_candidates if truth else op.false_candidates)(rhs_values(check))
    candidates += [*_composed(wanted), *pool, FALLBACK]
    for constraints in ([*wanted, *kept], wanted):
        for value in _distinct(candidates):
            if value is ABSENT:
                if removable and not any(truth for _, truth in constraints):
                    return ABSENT
            elif all(holds(check, (value,)) == truth for check, truth in constraints):
                return value
    return None


def _composed(wanted: Sequence[tuple[Check, bool]]) -> list[Choice]:
    """One string that starts, contains, and ends with what several true checks on a field ask."""
    parts = {"startswith": [], "contains": [], "icontains": [], "endswith": []}
    for check, truth in wanted:
        if truth and check.base_op in parts and check.modifier is None:
            parts[check.base_op].append(rhs_values(check)[0])
    middle = parts["contains"] + parts["icontains"]
    if not middle and not (parts["startswith"] and parts["endswith"]):
        return []
    return [" ".join([*parts["startswith"][:1], *middle, *parts["endswith"][:1]])]


def _distinct(values: Sequence[Choice]) -> Iterator[Choice]:
    seen: set[str] = set()
    for v in values:
        key = "\0absent" if v is ABSENT else v
        if key not in seen:
            seen.add(key)
            yield v


def _predict(leaves: _Leaves, run: Run, event: Mapping[str, tuple[str, ...]]) -> list[bool]:
    """The engine's leaf values with every modelable check on a changed field recomputed."""
    predicted = list(run.trace.leaves)
    for i, check in leaves.checks.items():
        key = leaves.keys.get(i)
        if key is not None and modelable(check) and run.case.event.get(key) != event.get(key):
            predicted[i] = holds(check, event.get(key))
    return predicted


def job_case(candidate: Candidate, rule: str, index: str) -> Case:
    return Case(f"{ID_PREFIX}{rule}::{index}", candidate.name, candidate.event, (), candidate.given)


def verified(candidate: Candidate, rule: Rule, mutant: Mutant, result: CaseResult | None) -> Generated | None:
    """The candidate as a generated case, when the engine's leaf values separate rule and mutant."""
    if not isinstance(result, CaseRun) or rule.name not in result.traces:
        return None
    leaves = result.traces[rule.name].leaves
    fired = result.alert_for(rule.name) is not None
    if evaluate(rule.compiled, leaves) != result.traces[rule.name].result:
        return None
    if fired == (rule.enabled and evaluate(mutant.ast, leaves)):
        return None
    base = candidate.run.case
    changes = {k: (", ".join(base.event.get(k, ("unset",))), v) for k, v in candidate.changes.items()}
    return Generated(candidate.name, base.name, candidate.run.suite, candidate.given, changes, fired)
