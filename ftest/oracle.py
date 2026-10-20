"""Jev as a test oracle: for one event, does the suite's `intent` call for an alert?

The engine already decided what the rule does. Jev reads only the intent and the event's fields,
never the rule, so a disagreement points at a rule bug, a wrong `expect`, or a vague intent. Each
event is its own request, so no other event sits in Jev's state. The same two questions sort the
ordinary events a rule fires on into false positives and hits its intent wants.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ftest.engine import CaseResult, CaseRun
from ftest.jev import JevClient, JevError, Verdict
from ftest.noise import Hit, sample
from ftest.strength import Generated, Strength, verdicts
from ftest.suite import Suite

YES_FROM = 0.7
NO_BELOW = 0.3
WORKERS = 4
# Within the default 5% budget on the built-in corpus, a rule of one event type fires on at most 7
# events (7 of 146 opens), so Jev reads every hit of such a rule. Eight hits are enough to tell an inverted rule from one
# meant to fire often, and cap the cost at 8 requests per rule and intent.
MAX_TRIAGED = 8

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


class Origin(Enum):
    SUITE = "suite"
    GENERATED = "generated"
    ORDINARY = "ordinary"


@dataclass(frozen=True)
class EventBrief:
    """One event for Jev, with what the engine and the suite said about it.

    `event` holds the fields as their source writes them: for a case, its suite's defaults under the
    case's own values. It has no derived fields and no trimming to the fields the rule reads, so Jev
    can see a field the rule ignores. `matched` is the engine's verdict for the rule's condition; an
    ordinary event gets a brief only because the rule fired on it. `expect` is what the suite case
    says, and None unless `origin` is SUITE: a generated case's `expect` only copies the rule."""

    id: str
    name: str
    suite: str
    intent: str
    event: Mapping[str, tuple[str, ...]]
    matched: bool
    expect: bool | None
    origin: Origin


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


class Reading(Enum):
    """What Jev makes of an ordinary event the rule fired on. Order is display order."""

    FALSE_POSITIVE = "false_positive"
    INTENDED = "intended"
    UNSURE = "unsure"


@dataclass(frozen=True)
class Triaged:
    """Jev's calls on one ordinary event a rule fired on, one per distinct intent of the rule's suites.

    The rule serves every intent, so the hit is intended when any intent calls for the alert and a
    false positive only when every intent rules it out."""

    hit: Hit
    calls: tuple[Judgment | Unjudged, ...]

    @property
    def reading(self) -> Reading | None:
        """None when every request failed."""
        found = [c.call for c in self.calls if isinstance(c, Judgment)]
        if not found:
            return None
        if True in found:
            return Reading.INTENDED
        if len(found) == len(self.calls) and all(call is False for call in found):
            return Reading.FALSE_POSITIVE
        return Reading.UNSURE

    @property
    def why(self) -> str:
        judged = [c for c in self.calls if isinstance(c, Judgment)]
        if len(self.calls) == 1:
            return "; ".join(c.why for c in judged)
        return "; ".join(f"{c.brief.suite}: {c.why}" for c in judged)


def _read(p: float) -> bool | None:
    return True if p >= YES_FROM else False if p < NO_BELOW else None


def word(matches: bool) -> str:
    return "match" if matches else "no_match"


def events(
    rule: str, suites: Sequence[Suite], cases: Mapping[str, CaseResult], strength: Strength | None
) -> tuple[tuple[EventBrief, ...], tuple[str, ...]]:
    """Every suite case the engine traced for `rule`, then each distinct generated case, and the
    suites for `rule` that state no intent. Cases in those suites get no brief.

    `matched` is the trace's condition result, not whether an alert fired, so a disabled rule is
    compared on its logic."""
    briefs: dict[str, EventBrief] = {}
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
                briefs[case.id] = EventBrief(
                    case.id, case.name, suite.display, suite.intent, event, matched, expect, Origin.SUITE
                )
    for survivor in strength.survivors if strength else ():
        if survivor.example is not None and (brief := generated(survivor.example)) is not None:
            briefs.setdefault(brief.id, brief)
    return tuple(briefs.values()), tuple(no_intent)


def generated(g: Generated) -> EventBrief | None:
    """The brief for a generated case, or None when its suite states no intent.

    `matched` is `g.expect`. That equals the condition result because generated cases come only
    from enabled rules."""
    if g.suite.intent is None:
        return None
    event = {**g.suite.defaults, **g.given}
    return EventBrief(
        generated_id(g), g.name, g.suite.display, g.suite.intent, event, g.expect, None, Origin.GENERATED
    )


def generated_id(g: Generated) -> str:
    return f"generated::{g.suite.display}::{g.name}"


def intents(rule: str, suites: Sequence[Suite]) -> tuple[Suite, ...]:
    """The first suite for `rule` with each distinct intent, in load order."""
    first: dict[str, Suite] = {}
    for s in suites:
        if s.rule == rule and s.intent is not None:
            first.setdefault(s.intent, s)
    return tuple(first.values())


def ordinary(hit: Hit, suite: Suite) -> EventBrief:
    return EventBrief(
        f"{hit.id}::{suite.display}",
        hit.label,
        suite.display,
        suite.intent,
        hit.given,
        True,
        None,
        Origin.ORDINARY,
    )


def triage(
    client: JevClient, model: str, rule: str, suites: Sequence[Suite], hits: Sequence[Hit]
) -> tuple[Triaged, ...]:
    """Jev's reading of up to MAX_TRIAGED of the rule's noise hits, each against every distinct intent
    of its suites: min(len(hits), MAX_TRIAGED) x intents requests. () when no suite states an intent."""
    stated = intents(rule, suites)
    if not stated:
        return ()
    chosen = sample(hits, MAX_TRIAGED)
    judged = judge(client, model, [ordinary(h, s) for h in chosen for s in stated])
    n = len(stated)
    return tuple(Triaged(h, judged[i * n : (i + 1) * n]) for i, h in enumerate(chosen))


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
