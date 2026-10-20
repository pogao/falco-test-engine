from pathlib import Path

import pytest
from builders import describe_rule, result, rule_entry

from ftest.cond import Check, Field, ListValue, Not, Transformer, Value, checks, render
from ftest.engine import Alert, CaseRun, Trace, parse_result
from ftest.fixtures import derive
from ftest.mutate import Kind, Mutant, replace
from ftest.strength import Run
from ftest.suite import Case, Suite
from ftest.synth import ABSENT, OPERATORS, holds, modelable, search, solve, verified

# Falco semantics each operator must model: (op, rhs, values that hold, values that do not).
SEMANTICS = [
    ("=", ("bash",), ["bash"], ["sh", "bash2"]),
    ("==", ("0",), ["0"], ["1"]),
    ("=", ("127.0.0.0/8",), ["127.0.0.1"], ["10.0.0.1"]),
    ("in", ("apt", "yum"), ["apt", "yum"], ["dnf"]),
    ("in", ("10.0.0.0/8", "192.168.0.0/16"), ["10.1.2.3", "192.168.1.1"], ["172.16.0.1"]),
    ("!=", ("host",), ["3ad7b26ded6d"], ["host"]),
    ("pmatch", ("/usr/bin", "/etc/"), ["/usr/bin", "/usr/bin/ls", "/etc/passwd"], ["/usr/binx", "/opt/etc"]),
    ("startswith", ("/dev/shm/",), ["/dev/shm/x"], ["/tmp/dev/shm/"]),
    ("endswith", ("release_agent",), ["/sys/fs/cgroup/release_agent"], ["release_agent.bak"]),
    ("contains", (" -e",), ["nc -e /bin/sh"], ["nc -l 80"]),
    ("icontains", ("sys_module",), ["CAP_SYS_MODULE"], ["CAP_SYS_ADMIN"]),
    ("glob", ("/home/*/.ssh/*",), ["/home/ann/.ssh/id_rsa"], ["/root/.ssh/id_rsa"]),
    ("exists", (), ["anything"], []),
    ("<", ("5",), ["4"], ["5", "x"]),
    ("<=", ("5",), ["5"], ["6"]),
    (">", ("0",), ["1"], ["0"]),
    (">=", ("0",), ["0"], ["-1"]),
]


def check(op: str, rhs: tuple[str, ...], field: str = "proc.name") -> Check:
    value = None if op == "exists" else (ListValue(rhs) if op == "in" or len(rhs) > 1 else Value(rhs[0]))
    return Check(op, Field(field), value, 0)


@pytest.mark.parametrize(("op", "rhs", "yes", "no"), SEMANTICS)
def test_each_operator_models_falco(op, rhs, yes, no):
    c = check(op, rhs)
    assert [v for v in yes if not holds(c, (v,))] == []
    assert [v for v in no if holds(c, (v,))] == []
    assert holds(c, None) is False


@pytest.mark.parametrize(("op", "rhs", "yes", "no"), SEMANTICS)
def test_operator_candidates_give_the_truth_value_they_promise(op, rhs, yes, no):
    c, model = check(op, rhs), OPERATORS[op]
    assert all(holds(c, (v,)) for v in model.true_candidates(rhs))
    assert all(v is ABSENT or not holds(c, (v,)) for v in model.false_candidates(rhs))


def test_checks_the_model_cannot_predict_are_not_flippable():
    assert modelable(check("contains anyof", ("a", "b")))
    assert not modelable(check("regex", ("^/usr/bin/x$",)))
    assert not modelable(check("contains allof", ("a", "b")))
    assert not modelable(Check("=", Transformer("tolower", (Field("proc.name"),)), Value("bash"), 0))
    assert not modelable(Check("=", Field("proc.name"), Transformer("val", (Field("proc.pname"),)), 0))


def test_one_value_satisfies_every_check_on_its_field():
    wanted = [(check("startswith", ("ap",)), True), (check("!=", ("apt",)), False)]
    assert solve(wanted, ["nginx", "apk"], removable=False) == "apt"
    assert solve([(check("=", ("a",)), True), (check("=", ("b",)), True)], [], removable=False) is None


def test_other_checks_on_the_field_stay_as_they_are_when_a_value_allows_it():
    wanted = [(check("=", ("/etc/pam.d",)), True)]
    keep_false = [(check("in", ("/etc/sudoers.d", "/etc/pam.d")), False)]
    assert solve(wanted, [], removable=False, kept=keep_false) == "/etc/pam.d"
    keep_true = [(check("startswith", ("/etc",)), True)]
    assert solve([(check("endswith", ("pam.d",)), True)], ["/etc/pam.d", "/opt/pam.d"], False, keep_true) == (
        "/etc/pam.d"
    )


def test_several_true_string_checks_get_one_composed_value():
    wanted = [
        (check("startswith", ("-e",)), True),
        (check("contains", ("getpwnam(",)), True),
        (check("contains", ("/usr/bin/mandb",)), True),
    ]
    value = solve(wanted, [], removable=False)
    assert value is not None and all(holds(c, (value,)) for c, _ in wanted)


def test_unsetting_a_field_needs_every_check_false_and_a_field_the_case_owns():
    exists = [(check("exists", ()), False)]
    assert solve(exists, [], removable=True) is ABSENT
    assert solve(exists, [], removable=False) is None


def test_realistic_values_come_before_generated_ones():
    assert solve([(check("in", ("apt", "yum")), False)], ["apt", "nginx"], removable=False) == "nginx"
    assert solve([(check("in", ("apt", "yum")), False)], [], removable=False) == "ftest-other"


def rule_of(condition: str):
    res = parse_result(
        result(rules=[rule_entry("R", condition, condition)], describe_rules=[describe_rule("R", condition)])
    )
    return res.rules["R"]


def drop(rule, text: str) -> Mutant:
    parent = rule.compiled
    target = next(c for c in parent.children if render(c) == text)
    rest = tuple(c for c in parent.children if c is not target)
    return Mutant(Kind.DROP, text, replace(parent, parent, type(parent)(rest) if len(rest) > 1 else rest[0]))


def run_of(rule, given, defaults=None, fired=True, leaves=None):
    defaults = defaults or {}
    event = derive({**defaults, **given})
    leaves = leaves or tuple(
        holds(c, event.get(render(c.lhs))) for c in sorted(checks(rule.compiled), key=lambda c: c.id)
    )
    suite = Suite(Path("s.yaml"), "s.yaml", "R", None, (), defaults)
    case = Case("s.yaml::base", "base", event, (), given)
    return Run(suite, case, Trace(fired, leaves, ()), fired)


POOL = {"proc.name": ("nginx", "sh"), "container.id": ("host", "3ad7b26ded6d"), "proc.aname": ("systemd",)}


def test_the_search_flips_the_fewest_leaves():
    rule = rule_of("evt.type = execve and container.id != host and proc.name = apt")
    base = run_of(rule, {"evt.type": ("execve",), "container.id": ("c1",), "proc.name": ("apt",)})
    found = search(rule, drop(rule, "container.id != host"), [base], POOL)
    assert found and found[0].changes == {"container.id": ("host",)}
    assert found[0].given == {"evt.type": ("execve",), "container.id": ("host",), "proc.name": ("apt",)}


def test_the_search_flips_two_leaves_when_one_is_not_enough():
    rule = rule_of("evt.type = execve and (proc.name = apt or proc.name = yum or user.name = root)")
    base = run_of(rule, {"evt.type": ("execve",), "proc.name": ("apt",), "user.name": ("root",)})
    either = rule.compiled.children[1]
    mutant = Mutant(Kind.DROP, "x", replace(rule.compiled, rule.compiled, rule.compiled.children[0]))
    found = search(rule, mutant, [base], POOL)
    assert found and set(found[0].changes) == {"proc.name", "user.name"}
    assert not any(holds(c, found[0].event.get(render(c.lhs))) for c in checks(either))


def test_the_search_skips_assignments_that_need_an_unmodelable_check():
    rule = rule_of("proc.cmdline regex .*curl.* and container.id != host")
    base = run_of(rule, {"proc.cmdline": ("curl x",), "container.id": ("c1",)}, leaves=(True, True))
    assert search(rule, drop(rule, "proc.cmdline regex .*curl.*"), [base], POOL) == []


def test_generated_events_are_derived_again_from_the_changed_fields():
    rule = rule_of("proc.aname in (sh, bash) and container.id != host")
    base = run_of(rule, {}, defaults={"proc.aname": ("bash", "runc"), "container.id": ("c1",)})
    found = search(rule, drop(rule, "proc.aname in (sh, bash)"), [base], POOL)
    assert found[0].changes == {"proc.aname": ("systemd",)}
    assert found[0].event["proc.pname"] == ("systemd",)


def test_a_field_the_case_sets_can_be_unset_but_a_default_cannot():
    rule = rule_of("proc.pname exists and container.id != host")
    own = run_of(rule, {"proc.pname": ("runc",), "container.id": ("c1",)})
    found = search(rule, drop(rule, "proc.pname exists"), [own], POOL)
    assert found[0].changes == {"proc.pname": None} and "proc.pname" not in found[0].event
    defaulted = run_of(rule, {"container.id": ("c1",)}, defaults={"proc.pname": ("runc",)})
    assert search(rule, drop(rule, "proc.pname exists"), [defaulted], POOL) == []


def test_only_engine_leaves_that_separate_rule_and_mutant_verify():
    rule = rule_of("evt.type = execve and container.id != host")
    mutant = drop(rule, "container.id != host")
    base = run_of(rule, {"evt.type": ("execve",), "container.id": ("c1",)})
    candidate = search(rule, mutant, [base], POOL)[0]

    def engine_says(leaves, fired):
        alerts = (Alert("R", "NOTICE", ""),) if fired else ()
        return CaseRun("x", alerts, {"R": Trace(fired, leaves, ())})

    generated = verified(candidate, rule, mutant, engine_says((True, False), False))
    assert generated is not None and generated.expect is False and generated.extends == "base"
    assert generated.changes == {"container.id": ("c1", ("host",))}
    assert verified(candidate, rule, mutant, engine_says((True, True), True)) is None
    assert verified(candidate, rule, mutant, engine_says((True, False), True)) is None


def test_mutants_never_need_new_leaves():
    rule = rule_of("evt.type = execve and not container.id = host")
    negated = Mutant(
        Kind.NEGATE, "x", replace(rule.compiled, rule.compiled.children[1], rule.compiled.children[1].child)
    )
    assert isinstance(rule.compiled.children[1], Not)
    assert {c.id for c in checks(negated.ast)} <= {c.id for c in checks(rule.compiled)}
