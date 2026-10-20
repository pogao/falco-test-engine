from pathlib import Path

import pytest
from builders import describe_rule, result, rule_entry
from samples import PKG, SHELL, World, engine_result

from ftest.cond import checks, evaluate, render
from ftest.engine import parse_result
from ftest.mutate import MAX_MUTANTS, Kind, mutants
from ftest.shape import shape_of
from ftest.strength import Run, measure
from ftest.suite import load_suites

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def rule_of(raw: str, compiled: str | None = None, exception_names=()):
    res = parse_result(
        result(
            rules=[rule_entry("R", raw, compiled or raw)],
            describe_rules=[describe_rule("R", raw, exception_names=exception_names)],
        )
    )
    return res.rules["R"]


def texts(rule, changed=()):
    return {(m.kind, render(m.ast)) for m in mutants(rule, shape_of(rule), changed)}


def test_negate_wraps_a_part_or_removes_its_not():
    found = texts(rule_of("proc.name = a and not user.name = b"))
    assert (Kind.NEGATE, "not proc.name = a and not user.name = b") in found
    assert (Kind.NEGATE, "proc.name = a and user.name = b") in found
    assert (Kind.NEGATE, "not (proc.name = a and not user.name = b)") in found
    assert not any("not not" in text for _, text in found)


def test_swap_turns_and_into_or_and_back():
    found = texts(rule_of("proc.name = a and (user.name = b or user.uid = 0)"))
    assert (Kind.SWAP, "proc.name = a or (user.name = b or user.uid = 0)") in found
    assert (Kind.SWAP, "proc.name = a and (user.name = b and user.uid = 0)") in found


def test_drop_removes_one_part_and_unwraps_a_single_survivor():
    found = {text for kind, text in texts(rule_of("proc.name = a and user.name = b and user.uid = 0"))}
    assert {"user.name = b and user.uid = 0", "proc.name = a and user.uid = 0"} <= found
    pair = {text for kind, text in texts(rule_of("proc.name = a and user.name = b")) if kind is Kind.DROP}
    assert pair == {"user.name = b", "proc.name = a"}


def test_mutants_are_distinct_and_never_equal_the_rule():
    rule = rule_of("proc.name = a and proc.name = a")
    found = [render(m.ast) for m in mutants(rule, shape_of(rule), ())]
    assert len(found) == len(set(found))
    assert render(rule.compiled) not in found


def test_a_stock_macro_is_one_site_unless_the_user_changed_it():
    rule = rule_of(
        "evt.type = execve and container", "evt.type = execve and (container.id != host and user.uid != 0)"
    )
    inside = (
        "evt.type = execve and (container.id != host or user.uid != 0)",
        "evt.type = execve and user.uid != 0",
    )
    stock = {text for _, text in texts(rule)}
    assert "evt.type = execve and not (container.id != host and user.uid != 0)" in stock
    assert stock.isdisjoint(inside)

    changed = {text for _, text in texts(rule, changed={"container"})}
    assert set(inside) <= changed
    labels = {m.site_label for m in mutants(rule, shape_of(rule), {"container"})}
    assert "`user.uid != 0` in macro `container`" in labels


def test_each_exception_can_be_inverted_or_dropped():
    rule = rule_of(
        "proc.name = bash",
        "proc.name = bash and not (container.image.repository = ci)",
        exception_names=["ci_image"],
    )
    by_desc = {m.description: render(m.ast) for m in mutants(rule, shape_of(rule), ())}
    assert by_desc["inverting exception `ci_image`"] == "proc.name = bash and container.image.repository = ci"
    assert by_desc["dropping exception `ci_image`"] == "proc.name = bash"


def test_mutants_evaluate_on_the_original_leaves():
    world = World.full()
    rule = engine_result(world, []).rules[SHELL]
    ids = {c.id for c in checks(rule.compiled)}
    leaves = tuple(i % 2 == 0 for i in range(rule.leaf_count))
    for m in mutants(rule, shape_of(rule), ()):
        assert {c.id for c in checks(m.ast)} <= ids
        assert evaluate(m.ast, leaves) in (True, False)


@pytest.fixture(scope="module")
def suites():
    return load_suites([EXAMPLES / "tests"], EXAMPLES)


def score(world, suites, rule_name, changed=(), drop_case=None):
    res = engine_result(world, suites)
    rule = res.rules[rule_name]
    runs = [
        Run(c, res.cases[c.id].traces[rule_name], res.cases[c.id].alert_for(rule_name) is not None)
        for s in suites
        if s.rule == rule_name
        for c in s.cases
        if c.name != drop_case
    ]
    return measure(rule, mutants(rule, shape_of(rule), changed), runs, None)


def score_only(world, suites, rule_name, keep):
    res = engine_result(world, suites)
    rule = res.rules[rule_name]
    case = next(c for s in suites if s.rule == rule_name for c in s.cases if c.name == keep)
    run = Run(case, res.cases[case.id].traces[rule_name], res.cases[case.id].alert_for(rule_name) is not None)
    return measure(rule, mutants(rule, shape_of(rule), ()), [run], None)


def test_the_package_manager_suite_misses_two_drops(suites):
    strength = score(World.full(), suites, PKG)
    assert (strength.killed, strength.total) == (10, 12)
    assert {s.mutant.description for s in strength.survivors} == {
        "dropping macro `spawned_process`",
        "dropping `proc.name in (package_managers)` in the rule condition",
    }


def test_removing_the_host_case_lets_dropping_container_survive(suites):
    weaker = score(World.full(), suites, PKG, drop_case="yum on the host is out of scope")
    assert "dropping macro `container`" in {s.mutant.description for s in weaker.survivors}
    assert weaker.killed == 9


def test_a_case_that_already_fails_does_not_kill_a_mutant_that_fails_it_the_same_way(suites):
    world = World.full()
    world.rules[PKG]["condition"] = "spawned_process and container"
    failing = score_only(world, suites, PKG, keep="CI runner installs packages by design")
    assert "dropping macro `spawned_process`" in {s.mutant.description for s in failing.survivors}


def test_only_the_first_mutants_are_scored(suites):
    terms = " and ".join(f"proc.name != p{i}" for i in range(60))
    rule = rule_of(terms)
    strength = measure(rule, mutants(rule, shape_of(rule), ()), [], 0.5)
    assert strength.total == MAX_MUTANTS and strength.generated > MAX_MUTANTS
    assert f"scored the first {MAX_MUTANTS} of {strength.generated}" in strength.summary
    assert strength.below_min
