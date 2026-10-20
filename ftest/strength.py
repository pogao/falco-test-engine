"""Test strength: how many inversion mutants of a rule its test cases would catch.

A mutant is killed when some case of a suite for the rule would fail under it: the case's
expectation agrees with the current rule and disagrees with the mutant. Each verdict comes from the
engine's leaf values for that case, so scoring needs no extra engine run.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import yaml

from ftest.cond import evaluate
from ftest.engine import Rule, Trace
from ftest.findings import Finding, Severity
from ftest.mutate import MAX_MUTANTS, Mutant
from ftest.noise import percent
from ftest.suite import Case, ExpectExactRules, ExpectFires, Suite


@dataclass(frozen=True)
class Run:
    suite: Suite
    case: Case
    trace: Trace
    fired: bool


@dataclass(frozen=True)
class Generated:
    """A case on which the current rule and a mutant disagree, as the engine evaluated it.

    `expect` is what the current rule does there, not what anyone said it should do."""

    name: str
    extends: str
    suite: Suite
    given: Mapping[str, tuple[str, ...]]
    changes: Mapping[str, tuple[str, tuple[str, ...] | None]]
    expect: bool

    @property
    def verdict(self) -> str:
        return "match" if self.expect else "no_match"

    @property
    def changed(self) -> str:
        return "; ".join(
            f"`{k}` from `{before}` to `{', '.join(after)}`" if after else f"unsets `{k}` (was `{before}`)"
            for k, (before, after) in self.changes.items()
        )

    def case(self, with_defaults: bool = False) -> dict:
        """The suite case. With `with_defaults`, the event also holds its source suite's defaults."""
        fields = {**self.suite.defaults, **self.given} if with_defaults else self.given
        event = {k: v[0] if len(v) == 1 else list(v) for k, v in fields.items()}
        return {"name": self.name, "expect": self.verdict, "event": event}

    def yaml(self, with_defaults: bool = False) -> str:
        doc = [self.case(with_defaults)]
        return yaml.safe_dump(doc, sort_keys=False, default_flow_style=None, width=10_000)


@dataclass(frozen=True)
class Survivor:
    mutant: Mutant
    example: Generated | None = None


@dataclass(frozen=True)
class Strength:
    killed: int
    total: int
    generated: int
    survivors: tuple[Survivor, ...]
    min_score: float | None
    unchecked: str | None = None

    @property
    def score(self) -> float:
        return self.killed / self.total if self.total else 1.0

    @property
    def below_min(self) -> bool:
        return self.min_score is not None and self.score < self.min_score

    @property
    def summary(self) -> str:
        if not self.total:
            return "no mutants: the condition has nothing to invert"
        text = f"{self.killed} of {self.total} mutants killed ({percent(self.score)})"
        if self.generated > self.total:
            text += f"; scored the first {self.total} of {self.generated}"
        if self.min_score is not None:
            text += f", {'below' if self.below_min else 'meets'} the {percent(self.min_score)} minimum"
        return text


def verdicts(case: Case, rule: str) -> tuple[bool, ...]:
    """What the case expects the rule to do: fire (True) or not (False), once per expectation."""
    found = []
    for e in case.expectations:
        match e:
            case ExpectFires(fires):
                found.append(fires)
            case ExpectExactRules(rules):
                found.append(rule in rules)
    return tuple(found)


def killed(rule: Rule, mutant: Mutant, runs: Sequence[Run]) -> bool:
    for run in runs:
        fires = rule.enabled and evaluate(mutant.ast, run.trace.leaves)
        if any(expected == run.fired and expected != fires for expected in verdicts(run.case, rule.name)):
            return True
    return False


def measure(rule: Rule, mutants: Sequence[Mutant], runs: Sequence[Run], min_score: float | None) -> Strength:
    scored = mutants[:MAX_MUTANTS]
    survivors = tuple(Survivor(m) for m in scored if not killed(rule, m, runs))
    return Strength(len(scored) - len(survivors), len(scored), len(mutants), survivors, min_score)


def findings(rule: str, strength: Strength) -> list[Finding]:
    return [
        Finding("FTE012", Severity.WARNING, rule, f"your tests would not catch {s.mutant.description}")
        for s in strength.survivors
    ]
