"""Pass or fail for each test case, with the reason in the user's terms."""

from __future__ import annotations

import difflib
from collections.abc import Iterable
from dataclasses import dataclass

from ftest.engine import CaseError, CaseResult, CaseRun
from ftest.suite import Case, Expectation, ExpectExactRules, ExpectFires, ExpectOutput


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    name: str
    rule: str
    expected: str
    actual: str
    failures: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.failures


def judge(
    case: Case,
    rule: str,
    result: CaseResult | None,
    known_rules: Iterable[str],
    known_fields: Iterable[str],
) -> CaseOutcome:
    expected = "; ".join(_describe(e) for e in case.expectations)

    def outcome(actual: str, failures: list[str], warnings: tuple[str, ...] = ()) -> CaseOutcome:
        return CaseOutcome(case.id, case.name, rule, expected, actual, tuple(failures), warnings)

    if result is None:
        return outcome("no result", ["the engine returned no result for this case"])
    if isinstance(result, CaseError):
        failures = [f"engine error: {result.error}"]
        failures += [f"unknown field `{f}`{_did_you_mean(f, known_fields)}" for f in result.unknown_fields]
        return outcome("error", failures)
    if rule not in set(known_rules):
        return outcome("rule not loaded", [f"rule `{rule}` is not loaded{_did_you_mean(rule, known_rules)}"])

    fired = frozenset(a.rule for a in result.alerts)
    failures = [f for e in case.expectations if (f := _check(e, rule, result, fired))]
    trace = result.traces.get(rule)
    warnings = ()
    if trace and trace.missing_fields:
        missing = ", ".join(f"`{f}`" for f in trace.missing_fields)
        warnings = (f"the rule read fields this case does not set: {missing}",)
    actual = f"fired: {', '.join(sorted(fired))}" if fired else "nothing fired"
    return outcome(actual, failures, warnings)


def _check(expectation: Expectation, rule: str, run: CaseRun, fired: frozenset[str]) -> str | None:
    match expectation:
        case ExpectFires(True) if rule not in fired:
            trace = run.traces.get(rule)
            if trace and trace.result:
                return f"expected `{rule}` to fire: its condition matched but the rule is disabled"
            return f"expected `{rule}` to fire; it did not"
        case ExpectFires(False) if rule in fired:
            return f"expected `{rule}` not to fire; it fired"
        case ExpectExactRules(rules) if rules != fired:
            parts = []
            if missing := rules - fired:
                parts.append("did not fire: " + ", ".join(f"`{r}`" for r in sorted(missing)))
            if unexpected := fired - rules:
                parts.append("also fired: " + ", ".join(f"`{r}`" for r in sorted(unexpected)))
            return "expected rule set differs; " + "; ".join(parts)
        case ExpectOutput(needles):
            alert = run.alert_for(rule)
            # When the rule did not fire, the fires expectation already reports it.
            if alert is None:
                return None
            absent = [n for n in needles if n not in alert.output]
            if absent:
                return f"output lacks {', '.join(repr(n) for n in absent)}: {alert.output!r}"
    return None


def _describe(expectation: Expectation) -> str:
    match expectation:
        case ExpectFires(fires):
            return "match" if fires else "no match"
        case ExpectExactRules(rules):
            return f"exactly: {', '.join(sorted(rules))}" if rules else "no rules fire"
        case ExpectOutput(needles):
            return f"output contains {', '.join(repr(n) for n in needles)}"


def _did_you_mean(name: str, candidates: Iterable[str]) -> str:
    close = difflib.get_close_matches(name, list(candidates), n=1, cutoff=0.6)
    return f" (did you mean `{close[0]}`?)" if close else ""
