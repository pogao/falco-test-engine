"""Readiness, a pure function of the finished run: expected values come from the README formulas."""

from ftest.findings import Finding, Severity
from ftest.noise import Hit, Noise
from ftest.oracle import EventBrief, Judgment, Origin, Triaged
from ftest.outcomes import CaseOutcome
from ftest.report import NotReady, Part, RuleSection, RunReport, failures, readiness
from ftest.startup import StartupSkipped
from ftest.strength import Strength

YES, NO, UNSURE = (0.9, 0.1), (0.1, 0.1), (0.5, 0.5)


def outcome(i, failed=False):
    return CaseOutcome(f"c{i}", f"c{i}", "R", "", "", ("it did not fire",) if failed else (), ())


def finding(code, severity):
    return Finding(code, severity, "R", "")


def judged(answer, matched=True, expect=True):
    brief = EventBrief("e", "e", "s", "intent", {}, matched, expect, Origin.SUITE)
    return Judgment(brief, *answer, "m", None)


def hit(i):
    return Hit(f"ordinary::{i}", f"event {i}", "", {"evt.type": ("execve",)})


def triaged(h, answer):
    brief = EventBrief(h.id, h.label, "s", "intent", h.given, True, None, Origin.ORDINARY)
    return Triaged(h, (Judgment(brief, *answer, "m", None),))


def section(name="R", cases=6, failed=0, enabled=True, findings=(), **analysis):
    outcomes = tuple(outcome(i, failed=i < failed) for i in range(cases))
    return RuleSection(name, "WARNING", enabled, True, None, (), outcomes, None, findings, None, **analysis)


def run(*sections, **gates):
    return RunReport(
        None, StartupSkipped("no falco"), None, None, "", (), sections, (), "", 0, "", "", **gates
    )


def strength(killed, total):
    return Strength(killed, total, total, (), None)


def noise(fired, total, budget=0.05):
    return Noise(tuple(hit(i) for i in range(fired)), total, budget, None, None)


def test_a_rule_with_every_part_scores_their_weighted_mean():
    hits = noise(2, 97)
    r = readiness(
        run(
            section(
                strength=strength(10, 12),
                noise=hits,
                triage=(triaged(hits.hits[0], YES), triaged(hits.hits[1], NO)),
                judgments=(*[judged(YES)] * 5, *[judged(UNSURE)] * 2, judged(NO)),
                findings=(
                    finding("FTE005", Severity.WARNING),
                    finding("FTE009", Severity.INFO),
                    finding("FTE012", Severity.WARNING),
                    finding("FTE013", Severity.ERROR),
                ),
            )
        )
    )
    strength_pct = 100 * 10 // 12
    noise_pct = int(100 * (1 - (2 - 1) / (0.05 * 97)))
    jev_pct = 100 * 5 // 8
    lint_pct = 100 - 20
    assert r.rules[0].parts == (
        ("strength", 4, Part(strength_pct, "10 of 12 mutants killed")),
        ("noise", 3, Part(noise_pct, "2 of 97 fired, 1 intended; budget 5%")),
        ("Jev events", 2, Part(jev_pct, "5 of 8 agree, 2 unsure")),
        ("lint", 1, Part(lint_pct, "1 warning")),
    )
    assert (strength_pct, noise_pct, jev_pct) == (83, 79, 62)
    assert r.score == (4 * 83 + 3 * 79 + 2 * 62 + 1 * 80) // 10 == 77


def test_an_untested_rule_scores_zero_strength_and_sets_the_run_score():
    tested = section("tested", strength=strength(12, 12), noise=noise(0, 97))
    untested = section(
        "untested", cases=0, noise=noise(0, 97), findings=(finding("FTE011", Severity.WARNING),)
    )
    r = readiness(run(tested, untested))
    assert r.rules[1].parts[0] == ("strength", 4, Part(0, "no tests"))
    assert r.rules[1].parts[3] == ("lint", 1, Part(100, "no errors or warnings"))
    assert r.rules[1].score == (4 * 0 + 3 * 100 + 1 * 100) // 8 == 50
    assert (r.score, r.weakest.rule) == (50, "untested")


def test_parts_that_were_not_measured_drop_out_of_the_mean():
    lint_only = section(findings=(finding("FTE005", Severity.WARNING),))
    assert [p for _, _, p in readiness(run(lint_only)).rules[0].parts] == [
        None,
        None,
        None,
        Part(80, "1 warning"),
    ]
    assert readiness(run(lint_only)).score == 80
    no_ordinary = section(strength=strength(9, 10), noise=noise(0, 0))
    assert readiness(run(no_ordinary)).score == (4 * 90 + 1 * 100) // 5
    disabled = section(enabled=False, noise=noise(0, 97), judgments=(judged(YES),))
    assert readiness(run(disabled)).score == (2 * 100 + 1 * 100) // 3


def test_an_unsure_call_lowers_the_jev_part():
    sure = section(judgments=[judged(YES)] * 4)
    unsure = section(judgments=(*[judged(YES)] * 3, judged(UNSURE)))
    assert readiness(run(sure)).score == 100
    assert readiness(run(unsure)).rules[0].parts[2] == ("Jev events", 2, Part(75, "3 of 4 agree, 1 unsure"))
    assert readiness(run(unsure)).score == (2 * 75 + 1 * 100) // 3


def test_a_hit_jev_reads_as_intended_is_not_held_against_the_rule():
    hits = noise(4, 97)
    plain = section(noise=hits)
    read = section(noise=hits, triage=tuple(triaged(h, YES) for h in hits.hits))
    assert readiness(run(plain)).rules[0].parts[1] == ("noise", 3, Part(17, "4 of 97 fired; budget 5%"))
    assert int(100 * (1 - 4 / (0.05 * 97))) == 17
    assert readiness(run(read)).rules[0].parts[1] == (
        "noise",
        3,
        Part(100, "4 of 97 fired, 4 intended; budget 5%"),
    )


def test_a_failing_run_is_not_ready_and_has_no_score():
    for report in (
        run(section(failed=1, strength=strength(12, 12))),
        run(section(noise=noise(5, 97))),
        run(section(findings=(finding("FTE001", Severity.ERROR),)), strict=True),
        run(section(judgments=(judged(NO),)), jev_gate=True),
    ):
        result = readiness(report)
        assert isinstance(result, NotReady) and not hasattr(result, "score")
        assert list(result.reasons) == failures(report) != []
    assert readiness(run(section(failed=1))).reasons == ("1 test case failed",)
    assert readiness(run(section(noise=noise(5, 97)))).reasons == ("1 rule over the noise budget",)


def test_only_a_rule_perfect_in_every_measured_part_scores_100():
    almost = section(strength=strength(159, 160), noise=noise(0, 97), judgments=(judged(YES),))
    assert readiness(run(almost)).rules[0].parts[0][2].percent == 99
    assert readiness(run(almost)).score == (4 * 99 + 3 * 100 + 2 * 100 + 1 * 100) // 10 == 99
    perfect = section(strength=strength(160, 160), noise=noise(0, 97), judgments=(judged(YES),))
    assert readiness(run(perfect)).score == 100


def test_a_passing_run_with_no_rule_has_nothing_to_score():
    assert readiness(run()) is None
