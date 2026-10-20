from pathlib import Path

import pytest
from samples import META, PKG, SHELL, World, broken_world, engine_result

from ftest.coverage import consistency, coverage
from ftest.engine import Trace
from ftest.explain import explain
from ftest.outcomes import judge
from ftest.shape import shape_of
from ftest.suite import load_suites

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture(scope="module")
def suites():
    return load_suites([EXAMPLES / "tests"], EXAMPLES)


def outcomes(world, suites):
    res = engine_result(world, suites)
    return {
        c.name: judge(c, s.rule, res.cases.get(c.id), res.rules, res.known_fields)
        for s in suites
        for c in s.cases
    }


def test_example_suites_pass_against_the_example_rules(suites):
    results = outcomes(World.full(), suites)
    assert [name for name, o in results.items() if not o.passed] == []
    assert results["kubectl exec bash into nginx"].actual == f"fired: {SHELL}"


def test_broken_rules_fail_with_reasons(suites):
    results = outcomes(broken_world(), suites)
    failed = {name: o.failures for name, o in results.items() if not o.passed}
    assert failed["yum on the host is out of scope"] == (f"expected `{PKG}` not to fire; it fired",)
    assert failed["pip from sh"] == (f"expected `{PKG}` to fire; it did not",)
    assert failed["other acme images still alert"] == (f"expected `{SHELL}` to fire; it did not",)


def test_exact_rule_sets_report_missing_and_unexpected(suites):
    world = World.full()
    world.rules[SHELL]["condition"] = "spawned_process"
    pkg_suite = next(s for s in suites if s.rule == PKG)
    case = pkg_suite.cases[-1]
    res = engine_result(world, [pkg_suite])
    outcome = judge(case, PKG, res.cases[case.id], res.rules, res.known_fields)
    assert outcome.failures == (f"expected rule set differs; also fired: `{SHELL}`",)


def test_output_mismatch_and_missing_fields_are_reported(suites, tmp_path):
    world = World.full()
    world.rules[META]["output"] = "Metadata contacted (dest=%fd.sip)"
    meta_suite = next(s for s in suites if s.rule == META)
    res = engine_result(world, [meta_suite])
    case = meta_suite.cases[0]
    outcome = judge(case, META, res.cases[case.id], res.rules, res.known_fields)
    assert outcome.failures == (
        "output lacks 'dest=169.254.169.254:80': 'Metadata contacted (dest=169.254.169.254)'",
    )


def test_unknown_fields_suggest_the_nearest_known_field(suites):
    shell = next(s for s in suites if s.rule == SHELL)
    case = shell.cases[0]
    typo = type(case)(case.id, case.name, {**case.event, "prc.name": ("bash",)}, case.expectations)
    res = engine_result(World.full(), [type(shell)(shell.path, shell.display, shell.rule, None, (typo,))])
    outcome = judge(typo, SHELL, res.cases[typo.id], res.rules, {"proc.name", "proc.pname"})
    assert "unknown field `prc.name` (did you mean `proc.name`?)" in outcome.failures


def test_rule_not_loaded_suggests_a_name(suites):
    shell = next(s for s in suites if s.rule == SHELL)
    res = engine_result(World.full(), [shell])
    case = shell.cases[0]
    outcome = judge(case, "Terminal shell in contaner", res.cases[case.id], res.rules, res.known_fields)
    assert outcome.failures == (
        "rule `Terminal shell in contaner` is not loaded (did you mean `Terminal shell in container`?)",
    )


def test_cases_that_leave_rule_fields_unset_get_a_warning(suites):
    world = World.full()
    world.rules[PKG]["condition"] += " and not k8s.ns.name = kube-system"
    pkg = next(s for s in suites if s.rule == PKG)
    case = next(c for c in pkg.cases if c.name == "pip from sh")
    res = engine_result(world, [pkg])
    stripped = {k: v for k, v in case.event.items() if k != "k8s.ns.name"}
    res2 = engine_result(
        world,
        [
            type(pkg)(
                pkg.path,
                pkg.display,
                pkg.rule,
                None,
                (type(case)(case.id, case.name, stripped, case.expectations),),
            )
        ],
    )
    assert judge(case, PKG, res.cases[case.id], res.rules, ()).warnings == ()
    warned = judge(case, PKG, res2.cases[case.id], res2.rules, ()).warnings
    assert warned == ("the rule read fields this case does not set: `k8s.ns.name`",)


def traces_for(res, suite):
    return [res.cases[c.id].traces[suite.rule] for c in suite.cases]


def test_coverage_reports_honest_counts_and_gaps(suites):
    shell = next(s for s in suites if s.rule == SHELL)
    res = engine_result(World.full(), [shell])
    rule = res.rules[SHELL]
    cov = coverage(shape_of(rule), rule.compiled, traces_for(res, shell))
    assert cov.total == rule.leaf_count == 8
    assert cov.summary == "4 of 8 conditions seen both true and false across 6 cases"
    assert {(g.text, g.never) for g in cov.leaves} == {
        ("evt.type in (execve, execveat)", "never false"),
        ("proc.name in (ash, bash, csh, ksh, sh, tcsh, ... +2)", "never false"),
        ("proc.pname exists", "never false"),
        (
            "proc.pname in (runc:[0:PARENT], runc:[1:CHILD], runc, docker-runc, exe, docker-runc-cur, ... +4)",
            "never false",
        ),
    }
    assert {(g.text, g.never) for g in cov.parts} == {
        ("macro `spawned_process`", "never false"),
        ("macro `shell_procs`", "never false"),
        ("macro `container_entrypoint`", "never false"),
    }


def test_exception_clauses_that_never_trigger_are_listed(suites):
    world = World.full()
    world.rules[PKG]["exceptions"] = ["proc.pname = make"]
    world.rules[PKG]["exception_names"] = ["build_tools"]
    pkg = next(s for s in suites if s.rule == PKG)
    res = engine_result(world, [pkg])
    rule = res.rules[PKG]
    cov = coverage(shape_of(rule), rule.compiled, traces_for(res, pkg))
    assert ("exception `build_tools`", "never triggered") in {(g.text, g.never) for g in cov.parts}


def test_consistency_flags_engine_results_that_contradict_leaves(suites):
    shell = next(s for s in suites if s.rule == SHELL)
    res = engine_result(World.full(), [shell])
    rule = res.rules[SHELL]
    good = res.cases[shell.cases[0].id].traces[SHELL]
    bad = Trace(not good.result, good.leaves, ())
    findings = consistency(rule, [("a", good), ("b", bad)])
    assert [(f.code, f.severity.value) for f in findings] == [("FTE900", "error")]
    assert "case `b`" in findings[0].message


def test_explain_states_events_terms_macros_and_output(suites):
    res = engine_result(World.full(), [])
    lines = explain(res.rules[META], res.macros)
    assert lines[0] == "Matches event `connect`."
    assert "  - `cloud_metadata_endpoint` (fd.sip = 169.254.169.254 or fd.sip = 169.254.170.2)" in lines
    assert "  - `not proc.exepath = /usr/bin/aws-node`" in lines
    assert "Priority WARNING, enabled." in lines
    assert any(line.startswith("Output fields: `proc.name`, `proc.cmdline`, `fd.sip`") for line in lines)
    shell = explain(res.rules[SHELL], res.macros)
    assert (
        "  - not `user_expected_terminal_shell_in_container_conditions` "
        "(container.image.repository = ghcr.io/acme/ci-runner or k8s.ns.name = break-glass)"
    ) in shell
    assert shell[0] == "Matches events `execve`, `execveat`."
