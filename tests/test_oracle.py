from pathlib import Path

import pytest
from test_jev import answering, client, stubs  # noqa: F401

from ftest.engine import CaseError, CaseRun, Trace
from ftest.jev import Verdict
from ftest.oracle import (
    EVENT_QUESTIONS,
    EventBrief,
    Judgment,
    Origin,
    Stance,
    Unjudged,
    events,
    generated,
    judge,
)
from ftest.strength import Generated, Strength, Survivor
from ftest.suite import parse_suite

INTENT = "Alert on an interactive shell in any container except our CI runner image."


def shell_suite(intent=INTENT, display="tests/shell.yaml"):
    return parse_suite(
        {
            "rule": "R",
            "intent": intent,
            "defaults": {
                "evt.type": "execve",
                "container.id": "3ad7b26ded6d",
                "proc.aname": ["bash", "runc"],
            },
            "cases": [
                {"name": "bash in nginx alerts", "expect": "match", "event": {"proc.name": "bash"}},
                {
                    "name": "CI runner image is allowed",
                    "expect": "no_match",
                    "event": {"proc.name": "bash", "container.image.repository": "ghcr.io/acme/ci-runner"},
                },
            ],
        },
        Path("shell.yaml"),
        display,
    )


def ran(suite, *results):
    """Engine results for the suite's cases: the rule's condition result for each, and no alerts, as
    for a disabled rule."""
    return {c.id: CaseRun(c.id, (), {"R": Trace(r, (r,), ())}) for c, r in zip(suite.cases, results)}


def brief(matched, expect):
    origin = Origin.SUITE if expect is not None else Origin.GENERATED
    return EventBrief("s::c", "c", "s", INTENT, {"evt.type": ("execve",)}, matched, expect, origin)


@pytest.mark.parametrize(
    ("in_scope", "exception", "call"),
    [
        (0.9, 0.1, True),
        (0.7, 0.29, True),
        (0.1, 0.5, False),
        (0.29, 0.1, False),
        (0.5, 0.9, False),
        (0.9, 0.7, False),
        (0.9, 0.5, None),
        (0.5, 0.1, None),
        (0.9, 0.3, None),
    ],
)
def test_jev_calls_an_alert_only_when_the_event_is_in_scope_and_no_exception(in_scope, exception, call):
    assert Judgment(brief(True, True), in_scope, exception, "m", None).call is call


@pytest.mark.parametrize(
    ("matched", "expect", "in_scope", "stance", "verdict"),
    [
        (True, True, 0.9, Stance.AGREES, Verdict.OK),
        (False, False, 0.9, Stance.DISPUTES_RULE, Verdict.FINDING),
        (False, True, 0.9, Stance.DISPUTES_RULE, Verdict.FINDING),
        (True, False, 0.9, Stance.DISPUTES_EXPECT, Verdict.REVIEW),
        (True, True, 0.5, Stance.UNSURE, Verdict.OK),
        (False, None, 0.9, Stance.DISPUTES_RULE, Verdict.FINDING),
        (True, None, 0.9, Stance.AGREES, Verdict.OK),
    ],
)
def test_a_call_against_the_rule_is_a_finding_and_against_only_the_case_a_review(
    matched, expect, in_scope, stance, verdict
):
    j = Judgment(brief(matched, expect), in_scope, 0.1, "m", None)
    assert (j.stance, j.verdict) == (stance, verdict)


def test_jev_sees_only_the_intent_and_the_authored_event(stubs):  # noqa: F811
    suite = shell_suite()
    briefs, no_intent = events("R", (suite,), ran(suite, True, False), None)
    stub = stubs(answering())
    result = judge(client(stub.url), "jev-latest", briefs)

    assert no_intent == ()
    assert [j.stance for j in result] == [Stance.AGREES, Stance.DISPUTES_RULE]
    bodies = sorted((r["body"] for r in stub.requests), key=lambda b: len(b["state"]["event"]))
    assert bodies[0] == {
        "model": "jev-latest",
        "state": {
            "intent": INTENT,
            "event": {
                "evt.type": "execve",
                "container.id": "3ad7b26ded6d",
                "proc.aname": ["bash", "runc"],
                "proc.name": "bash",
            },
        },
        "questions": EVENT_QUESTIONS,
    }
    assert bodies[1]["state"]["event"]["container.image.repository"] == "ghcr.io/acme/ci-runner"


def test_a_suite_without_a_real_intent_is_named_and_not_judged():
    for intent in (None, "TODO say what this rule must catch and what it must ignore."):
        suite = shell_suite(intent)
        assert events("R", (suite,), ran(suite, True, False), None) == ((), ("tests/shell.yaml",))


def test_a_disabled_rule_is_compared_on_what_its_condition_matched():
    suite = shell_suite()
    briefs, _ = events("R", (suite,), ran(suite, True, False), None)
    assert [(b.matched, b.expect) for b in briefs] == [(True, True), (False, False)]


def test_cases_the_engine_did_not_trace_get_no_brief():
    suite = shell_suite()
    results = {suite.cases[0].id: CaseError(suite.cases[0].id, "unknown field", ("proc.nme",))}
    assert events("R", (suite,), results, None) == ((), ())


def test_one_failed_request_costs_only_its_own_event(stubs):  # noqa: F811
    suite = shell_suite()
    briefs, _ = events("R", (suite,), ran(suite, True, False), None)
    allow = answering(lambda state: (0.9, 0.9))

    def respond(body):
        if "container.image.repository" not in body["state"]["event"]:
            return 500, {}, {"detail": "boom"}
        return allow(body)

    result = judge(client(stubs(respond).url), "m", briefs)
    assert isinstance(result[0], Unjudged) and result[0].error.startswith("HTTP 500")
    assert isinstance(result[1], Judgment) and result[1].stance is Stance.AGREES


def zsh_case(suite):
    name = "bash in nginx alerts, with proc.name=zsh"
    return Generated(name, "bash in nginx alerts", suite, {"proc.name": ("zsh",)}, {}, False)


def test_each_generated_case_is_judged_once_against_its_own_suite():
    first, second = shell_suite(), shell_suite(display="tests/more_shells.yaml")
    shared = zsh_case(first)
    survivors = (Survivor(None, shared), Survivor(None, shared), Survivor(None, zsh_case(second)))
    briefs, _ = events("R", (first, second), {}, Strength(0, 3, 3, survivors, None))
    assert [b.id for b in briefs] == [
        "generated::tests/shell.yaml::bash in nginx alerts, with proc.name=zsh",
        "generated::tests/more_shells.yaml::bash in nginx alerts, with proc.name=zsh",
    ]
    assert (briefs[0].matched, briefs[0].expect, briefs[0].origin) == (False, None, Origin.GENERATED)
    assert briefs[0].event["proc.name"] == ("zsh",) and briefs[0].event["container.id"] == ("3ad7b26ded6d",)
    assert generated(zsh_case(shell_suite(None))) is None
