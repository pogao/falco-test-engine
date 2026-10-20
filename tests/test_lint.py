import itertools
from pathlib import Path

from builders import load_ok, warning
from samples import META, PKG, World, engine_result

from ftest.cond import evaluate
from ftest.engine import CaseRun as EngineCaseRun
from ftest.engine import Trace as EngineTrace
from ftest.engine import parse_result
from ftest.lint import (
    CaseRun,
    RuleView,
    glob_rewrite,
    lint_rule,
    load_warnings,
    na_fields,
    regex_rewrite,
    suggested_condition,
    work,
)
from ftest.shape import shape_of
from ftest.suite import load_suites

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def view(condition, macros=None, lists=None, runs=(), evttypes=("execve",), **spec):
    rule = dict(
        condition=condition,
        desc="",
        output=spec.pop("output", "x"),
        priority="NOTICE",
        evttypes=list(evttypes),
        **spec,
    )
    res = parse_result(World(macros or {}, lists or {}, {"R": rule}, ["/r.yaml"]).result())
    parsed = res.rules["R"]
    return RuleView(parsed, shape_of(parsed), res.macros, res.lists, runs)


def codes(findings, code):
    return [(f.severity.value, f.message, f.suggestion) for f in findings if f.code == code]


def example_view(world, rule_name):
    suites = [s for s in load_suites([EXAMPLES / "tests"], EXAMPLES) if s.rule == rule_name]
    res = engine_result(world, suites)
    rule = res.rules[rule_name]
    runs = []
    for case in suites[0].cases:
        r = res.cases[case.id]
        assert isinstance(r, EngineCaseRun)
        runs.append(CaseRun(case.name, r.traces.get(rule_name), r.alert_for(rule_name)))
    return RuleView(rule, shape_of(rule), res.macros, res.lists, tuple(runs))


def test_fte001_flags_rules_matching_too_many_event_types():
    broad = codes(lint_rule(view("proc.name = bash", evttypes=[f"e{i}" for i in range(150)])), "FTE001")
    assert broad and broad[0][0] == "warning" and "matches 150 event types" in broad[0][1]
    assert "not an equivalent rewrite" in broad[0][2]
    assert codes(lint_rule(view("evt.type = execve and proc.name = bash")), "FTE001") == []


def test_fte002_flags_top_level_negative_event_types():
    broad = codes(
        lint_rule(view("evt.type != open and proc.name = x", evttypes=[f"e{i}" for i in range(150)])),
        "FTE002",
    )
    assert [(s, m) for s, m, _ in broad] == [
        (
            "warning",
            "top-level negative event-type check `evt.type != open` lets the rule match every other event type",
        )
    ]
    narrow = codes(lint_rule(view("evt.type in (execve, execveat) and not evt.type = execveat")), "FTE002")
    assert [s for s, _, _ in narrow] == ["info"]
    assert codes(lint_rule(view("evt.type = execve and (evt.type != open or proc.name = x)")), "FTE002") == []


def test_fte003_merges_equalities_inside_macros_and_keeps_list_names():
    meta = codes(
        lint_rule(
            view(
                "evt.type = connect and endpoint",
                macros={"endpoint": "(fd.sip = 1.1.1.1 or fd.sip = 2.2.2.2)"},
            )
        ),
        "FTE003",
    )
    assert meta == [
        (
            "info",
            "in macro `endpoint`: 2 equality checks on `fd.sip` joined by `or`",
            "`fd.sip = 1.1.1.1 or fd.sip = 2.2.2.2` -> `fd.sip in (1.1.1.1, 2.2.2.2)`. Equivalent: `in` is one set lookup.",
        )
    ]
    body = codes(
        lint_rule(view("proc.name in (shells) or proc.name = zsh or fd.name = /x", lists={"shells": ["sh"]})),
        "FTE003",
    )
    assert body[0][2].startswith(
        "`proc.name in (shells) or proc.name = zsh` -> `proc.name in (shells, zsh) or fd.name = /x`"
    )


def test_fte004_suggests_anyof_only_where_libs_honors_it():
    found = codes(lint_rule(view("proc.cmdline contains curl or proc.cmdline contains wget")), "FTE004")
    assert found[0][2].startswith(
        "`proc.cmdline contains curl or proc.cmdline contains wget` -> `proc.cmdline contains anyof (curl, wget)`"
    )
    assert codes(lint_rule(view("proc.aname startswith a or proc.aname startswith b")), "FTE004") == []
    assert codes(lint_rule(view("fd.sip startswith 10. or fd.sip startswith 192.")), "FTE004") == []
    assert codes(lint_rule(view("proc.aname[2] endswith sh or proc.aname[2] endswith bash")), "FTE004") != []


def test_fte005_reorders_costly_checks_last():
    found = codes(lint_rule(example_view(World.full(), PKG)), "FTE005")
    assert found == [
        (
            "warning",
            "`proc.aname in (sh, bash)` (walks every ancestor process) is evaluated before cheaper checks",
            "Reorder the condition: `spawned_process and container and proc.name in (package_managers) and not "
            "container.image.repository = ghcr.io/acme/ci-runner and proc.aname in (sh, bash)`. "
            "Equivalent: `and`/`or` operands have no side effects in Falco.",
        )
    ]
    in_macro = codes(
        lint_rule(
            view("evt.type = execve and m", macros={"m": "(proc.cmdline contains x and proc.name = y)"})
        ),
        "FTE005",
    )
    assert (
        in_macro[0][1]
        == "in macro `m`: `proc.cmdline contains x` (substring scan of a long string) is evaluated before cheaper checks"
    )
    assert "`proc.name = y and proc.cmdline contains x`" in in_macro[0][2]


def test_suggested_order_is_equivalent_on_every_leaf_assignment():
    v = view(
        "evt.type = execve and (proc.aname = a or proc.name = b) and not (proc.cmdline regex x or user.uid = 0)",
        exceptions=["proc.pname = make"],
    )
    suggested = suggested_condition(v)
    for leaves in itertools.product([False, True], repeat=v.rule.leaf_count):
        assert evaluate(suggested, leaves) == evaluate(v.rule.compiled, leaves)


def test_work_metric_counts_short_circuit_evaluation():
    v = view("proc.aname = a and proc.name = b")
    leaves_false_name = EngineTrace(False, (True, False), ())
    w = work(RuleView(v.rule, v.shape, v.macros, v.lists, (CaseRun("c", leaves_false_name, None),)))
    assert (w.current, w.current_weighted, w.suggested, w.suggested_weighted) == (2, 17, 1, 1)
    assert w.summary.startswith("predicates evaluated on the test cases (not a production timing): 2")
    assert work(v) is None


def test_fte006_rewrites_simple_regexes_and_globs():
    found = codes(lint_rule(example_view(World.full(), META)), "FTE006")
    assert found == [
        (
            "warning",
            "`proc.cmdline regex ^/usr/bin/aws-node` only matches the exact value `/usr/bin/aws-node`: "
            "Falco regexes must match the whole value",
            "Use `proc.cmdline = /usr/bin/aws-node`. Equivalent, without the regex engine. If you meant values that "
            "start with `/usr/bin/aws-node`, use `proc.cmdline startswith /usr/bin/aws-node`; that changes what the "
            "rule matches.",
        )
    ]
    assert regex_rewrite(".*curl.*") == ("contains", "curl", None)
    assert regex_rewrite(r"/usr/bin/aws\-node.*") == ("startswith", "/usr/bin/aws-node", None)
    assert regex_rewrite("^a$") == ("=", "a", None)
    assert regex_rewrite("^a[0-9]") is None
    assert regex_rewrite(r"\d+") is None
    assert glob_rewrite("glob", "*miner*") == ("contains", "miner")
    assert glob_rewrite("glob", "/tmp/*") == ("startswith", "/tmp/")
    assert glob_rewrite("glob", "*.sh") == ("endswith", ".sh")
    assert glob_rewrite("glob", "a?b") is None
    assert glob_rewrite("iglob", "*X*") == ("icontains", "X")
    assert glob_rewrite("iglob", "X*") is None


def test_fte007_finds_repeated_list_items_and_predicates():
    meta = codes(lint_rule(example_view(World.full(), META)), "FTE007")
    assert ("info", "list `metadata_allowed_images` repeats `ghcr.io/acme/node-agent`") in [
        (s, m) for s, m, _ in meta
    ]
    literal = codes(lint_rule(view("proc.name in (a, b, a)")), "FTE007")
    assert literal[0][1] == "`proc.name in (a, b, a)` repeats `a`"
    twice = codes(
        lint_rule(view("evt.type = execve and c and c", macros={"c": "(container.id != host)"})), "FTE007"
    )
    assert twice == [
        (
            "warning",
            "in the rule condition: `container.id != host` appears twice in the same `and`",
            "Remove one copy. Equivalent: `x and x` is `x`.",
        )
    ]


def test_fte008_says_why_a_rule_can_never_fire():
    enabled = codes(lint_rule(view("proc.name = a and evt.type = execve and proc.name = b")), "FTE008")
    assert enabled == [
        (
            "error",
            "can never fire: `proc.name = a` and `proc.name = b` can never both be true. "
            "The rule is enabled and is not the `never_true` idiom, so this is a bug.",
            None,
        )
    ]
    disabled = codes(lint_rule(view("proc.name = a and proc.name in (b, c)", enabled=False)), "FTE008")
    assert disabled[0][0] == "info" and disabled[0][1].endswith("The rule is disabled.")
    idiom = codes(
        lint_rule(view("never_true and proc.name = a", macros={"never_true": "(evt.num = 0)"}, evttypes=())),
        "FTE008",
    )
    assert (
        idiom[0][0] == "info" and "no event type can satisfy" in idiom[0][1] and "on purpose" in idiom[0][1]
    )
    nested = codes(
        lint_rule(view("evt.type = execve and ((proc.name = a and proc.name = b) or user.uid = 0)")), "FTE008"
    )
    assert [s for s, _, _ in nested] == ["warning"]
    assert codes(lint_rule(view("proc.aname = a and proc.aname = b")), "FTE008") == []
    assert codes(lint_rule(view("proc.name = a and proc.name in (a, b)")), "FTE008") == []


def test_fte009_reports_output_fields_that_rendered_na():
    found = codes(lint_rule(example_view(World.full(), META)), "FTE009")
    assert [m for _, m, _ in found] == [
        "output field `k8s.pod.name` rendered `<NA>` on matching case(s) `curl to IMDS`, `ECS task metadata endpoint`"
    ]
    assert na_fields("a=%x.y b=%(z.w)", "a=<NA> b=1") == ["x.y"]
    assert na_fields("a=%x.y", "unrelated <NA>") == ["(unmatched output)"]


def test_fte010_summarizes_falco_load_warnings():
    load = parse_result(
        World.full().result(
            load=load_ok(
                ["/r.yaml"],
                warnings=[
                    warning("LOAD_UNUSED_MACRO", "m1", codedesc="Unused macro"),
                    warning("LOAD_UNUSED_MACRO", "m2", codedesc="Unused macro"),
                    warning(
                        "LOAD_UNSAFE_NA_CHECK",
                        "R",
                        "comparing with <NA>",
                        item_type="rule",
                        codedesc="Unsafe <NA> comparison in condition",
                    ),
                ],
            )
        )
    ).load
    found = load_warnings(load)
    assert [(f.severity.value, f.message) for f in found] == [
        ("info", "Falco load warning LOAD_UNUSED_MACRO (Unused macro) x2 on `m1`, `m2`"),
        (
            "warning",
            "Falco load warning LOAD_UNSAFE_NA_CHECK (Unsafe <NA> comparison in condition) x1 on `R`: "
            "comparing with <NA>",
        ),
    ]
    assert load_warnings(load, frozenset({"FTE010"})) == []


def test_disabled_codes_are_skipped():
    v = view("proc.name in (a, b, a)")
    assert codes(lint_rule(v, frozenset({"FTE007"})), "FTE007") == []
