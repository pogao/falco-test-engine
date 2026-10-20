"""Jev as a test oracle: for one event, does the suite's `intent` call for an alert?

The engine already decided what the rule does. Jev reads only the intent and the event's fields,
never the rule, so a disagreement points at a rule bug, a wrong `expect`, or a vague intent. Each
event is its own request, so no other event sits in Jev's state.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ftest.engine import CaseResult, CaseRun
from ftest.jev import JevClient, JevError, Verdict
from ftest.strength import verdicts
from ftest.suite import Suite

YES_FROM = 0.7
NO_BELOW = 0.3
WORKERS = 4

EVENT_QUESTIONS: dict[str, Any] = {
    "in_scope": {
        "type": "noul",
        "instructions": "`event` is an instance of the activity that `intent` asks to alert on.",
        "criteria": {
            "true": "The action in `event` (its process, file, or connection) and where it runs (a "
            "container or the host) fit the activity that `intent` describes.",
            "false": "`event` shows a different action, or it runs somewhere other than where `intent` "
            "looks.",
        },
    },
    "exception": {
        "type": "noul",
        "instructions": "`event` matches an exception that `intent` names.",
        "criteria": {
            "true": "`intent` names something to leave out or allow, such as an image, namespace, "
            "process, user, path, or destination, and `event` has that value.",
            "false": "The values in `event` differ from each exception that `intent` names, or `intent` "
            "names only what to alert on.",
        },
    },
}


class Stance(Enum):
    """How Jev's call relates to the rule's verdict and, for a suite case, to its `expect`."""

    AGREES = "agrees"
    UNSURE = "unsure"
    DISPUTES_RULE = "disputes_rule"
    DISPUTES_EXPECT = "disputes_expect"


_VERDICTS = {
    Stance.AGREES: Verdict.OK,
    Stance.UNSURE: Verdict.OK,
    Stance.DISPUTES_RULE: Verdict.FINDING,
    Stance.DISPUTES_EXPECT: Verdict.REVIEW,
}


@dataclass(frozen=True)
class EventBrief:
    """One event for Jev, with what the engine and the suite said about it.

    `event` holds the fields as the suite writes them: its defaults under the case's own values,
    with no derived fields and no trimming to the fields the rule reads, so Jev can see a field the
    rule ignores. `matched` is the engine's verdict for the rule's condition. `expect` is what the
    suite case says, or None for a generated case, whose `expect` only copies the rule."""

    id: str
    name: str
    suite: str
    intent: str
    event: Mapping[str, tuple[str, ...]]
    matched: bool
    expect: bool | None

    @property
    def generated(self) -> bool:
        return self.expect is None


@dataclass(frozen=True)
class Judgment:
    brief: EventBrief
    in_scope: float
    exception: float
    model: str
    request_id: str | None

    @property
    def call(self) -> bool | None:
        """Whether the intent calls for an alert, or None when Jev is unsure.

        Three-valued `in_scope and not exception`: either answer alone settles False; True needs
        both."""
        scope, excluded = _read(self.in_scope), _read(self.exception)
        if scope is False or excluded is True:
            return False
        if scope is True and excluded is False:
            return True
        return None

    @property
    def stance(self) -> Stance:
        call = self.call
        if call is None:
            return Stance.UNSURE
        if call != self.brief.matched:
            return Stance.DISPUTES_RULE
        if self.brief.expect is not None and call != self.brief.expect:
            return Stance.DISPUTES_EXPECT
        return Stance.AGREES

    @property
    def verdict(self) -> Verdict:
        return _VERDICTS[self.stance]

    @property
    def why(self) -> str:
        return f"in scope p={self.in_scope:.2f}, exception p={self.exception:.2f}"


@dataclass(frozen=True)
class Unjudged:
    brief: EventBrief
    error: str


def _read(p: float) -> bool | None:
    return True if p >= YES_FROM else False if p < NO_BELOW else None


def word(matches: bool) -> str:
    return "match" if matches else "no_match"


def events(
    rule: str, suites: Sequence[Suite], cases: Mapping[str, CaseResult]
) -> tuple[tuple[EventBrief, ...], tuple[str, ...]]:
    """Every suite case the engine traced for `rule`, and the suites for `rule` that state no
    intent. Cases in those suites get no brief.

    `matched` is the trace's condition result, not whether an alert fired, so a disabled rule is
    compared on its logic."""
    briefs = []
    no_intent = []
    for suite in (s for s in suites if s.rule == rule):
        if suite.intent is None:
            no_intent.append(suite.display)
            continue
        for case in suite.cases:
            result = cases.get(case.id)
            if isinstance(result, CaseRun) and rule in result.traces:
                event = {**suite.defaults, **case.given}
                matched = result.traces[rule].result
                expect = verdicts(case, rule)[0]
                briefs.append(
                    EventBrief(case.id, case.name, suite.display, suite.intent, event, matched, expect)
                )
    return tuple(briefs), tuple(no_intent)


def state(brief: EventBrief) -> dict[str, Any]:
    """Only the intent and the event. The case name, `expect`, and rule stay out: case names often
    state the verdict, and the rest is what Jev's call is compared against."""
    event = {k: v[0] if len(v) == 1 else list(v) for k, v in brief.event.items()}
    return {"intent": brief.intent, "event": event}


def judge(client: JevClient, model: str, briefs: Sequence[EventBrief]) -> tuple[Judgment | Unjudged, ...]:
    """One request per brief, WORKERS at a time, results in input order."""
    with ThreadPoolExecutor(WORKERS) as pool:
        return tuple(pool.map(lambda b: _judge(client, model, b), briefs))


def _judge(client: JevClient, model: str, brief: EventBrief) -> Judgment | Unjudged:
    try:
        answers, used_model, request_id = client.ask(model, state(brief), EVENT_QUESTIONS, brief.id)
    except JevError as e:
        return Unjudged(brief, str(e))
    return Judgment(
        brief, float(answers["in_scope"]["noul"]), float(answers["exception"]["noul"]), used_model, request_id
    )
