from pathlib import Path

import pytest
from builders import (
    ast_json,
    case_run,
    describe_rule,
    install_fake_engine,
    received_jobs,
    result,
    rule_entry,
    trace,
)

from ftest.cond import render
from ftest.config import DEFAULT_PLUGIN
from ftest.engine import CaseError, CaseRun, EngineError, JobCase, build_job, parse_result, run_engine
from ftest.shape import shape_of
from ftest.suite import Case, ExpectFires

SHELL = "Terminal shell in container"


def make_case(case_id="s.yaml::bash", **event):
    fields = {"evt.type": ("execve",), **{k.replace("_", "."): (v,) for k, v in event.items()}}
    return Case(case_id, case_id.split("::")[1], fields, (ExpectFires(True),))


def test_job_sends_cases_with_list_values_and_traces_the_rule_under_test():
    job = build_job(
        [Path("/etc/falco/falco_rules.yaml")], [DEFAULT_PLUGIN], [JobCase(make_case(proc_name="bash"), SHELL)]
    )
    assert job["describe"] is True
    assert job["plugins"] == [
        {"name": "container", "library_path": "/usr/share/falco/plugins/libcontainer.so", "init_config": "{}"}
    ]
    assert job["cases"] == [
        {
            "id": "s.yaml::bash",
            "source": "syscall",
            "fields": {"evt.type": ["execve"], "proc.name": ["bash"]},
            "trace_rules": [SHELL],
        }
    ]


def shell_result():
    raw = "spawned_process and container and proc.tty != 0"
    compiled = (
        "(evt.type in (execve, execveat) and container.id != host and proc.tty != 0) "
        "and not (container.image.repository = ci or k8s.ns.name = break-glass)"
    )
    return result(
        rules=[rule_entry(SHELL, raw, compiled)],
        describe_rules=[describe_rule(SHELL, raw, priority="Notice", exception_names=["allowed"])],
        cases=[
            case_run(
                "s.yaml::bash",
                [{"name": SHELL, "priority": "Notice", "output": "shell"}],
                {SHELL: trace(True, [True, True, True, False, False], ["k8s.ns.name"])},
            ),
            {"id": "s.yaml::typo", "error": "unknown field", "unknown_fields": ["proc.nam"]},
        ],
    )


def test_result_parses_into_typed_rules_and_case_results():
    parsed = parse_result(shell_result())
    rule = parsed.rules[SHELL]
    assert rule.priority == "NOTICE"
    assert rule.leaf_count == 5
    assert rule.exception_names == ("allowed",)
    run = parsed.cases["s.yaml::bash"]
    assert isinstance(run, CaseRun)
    assert run.alert_for(SHELL).output == "shell"
    assert run.traces[SHELL].missing_fields == ("k8s.ns.name",)
    assert parsed.cases["s.yaml::typo"] == CaseError("s.yaml::typo", "unknown field", ("proc.nam",))


def test_result_that_breaks_the_protocol_is_an_engine_error():
    doc = shell_result()
    del doc["rules"][0]["condition_ast"]
    with pytest.raises(EngineError, match="does not follow the protocol"):
        parse_result(doc)


def test_shape_separates_macros_from_exception_clauses():
    shape = shape_of(parse_result(shell_result()).rules[SHELL])
    assert shape.aligned
    assert [(m.name, render(m.node)) for m in shape.macros] == [
        ("spawned_process", "evt.type in (execve, execveat)"),
        ("container", "container.id != host"),
    ]
    assert [(e.label, render(e.node)) for e in shape.exceptions] == [
        ("exception `allowed`", "container.image.repository = ci or k8s.ns.name = break-glass")
    ]
    check = shape.exceptions[0].node.children[0]
    assert shape.where(check) == "in exception `allowed`"
    assert shape.where(shape.macros[1].node) == "in macro `container`"


def test_shape_without_exceptions_aligns_the_whole_condition():
    raw = "evt.type = connect and not proc.name in (allowed)"
    rule = parse_result(
        result(rules=[rule_entry("R", raw, "evt.type = connect and not proc.name in (a, b)")])
    ).rules["R"]
    shape = shape_of(rule)
    assert shape.exceptions == ()
    assert shape.display(rule.compiled.children[1].child) == "proc.name in (allowed)"


def test_run_engine_round_trips_through_the_binary(tmp_path, monkeypatch):
    doc = shell_result()
    doc["cases_by_id"] = {c["id"]: c for c in doc.pop("cases")}
    install_fake_engine(tmp_path / "bin", tmp_path / "state", [{"rules_files": None, "result": doc}])
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/bin:/bin")
    job = build_job([Path("/r.yaml")], [], [JobCase(make_case(), SHELL)])
    parsed = run_engine("falco-test-engine", job)
    assert list(parsed.cases) == ["s.yaml::bash"]
    assert received_jobs(tmp_path / "state") == [job]


def test_run_engine_reports_fatal_and_crashes(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/bin:/bin")
    install_fake_engine(
        tmp_path / "bin",
        tmp_path / "s1",
        [{"rules_files": None, "exit": 2, "stdout": '{"fatal": "plugin failed to load"}'}],
    )
    with pytest.raises(EngineError, match="plugin failed to load"):
        run_engine("falco-test-engine", build_job([], [], []))
    install_fake_engine(
        tmp_path / "bin", tmp_path / "s2", [{"rules_files": None, "exit": 139, "stderr": "segv"}]
    )
    with pytest.raises(EngineError, match="code 139: segv"):
        run_engine("falco-test-engine", build_job([], [], []))
    with pytest.raises(EngineError, match="not found"):
        run_engine("no-such-engine", build_job([], [], []))


def test_raw_ast_builder_matches_contract_example():
    assert ast_json("proc.name in (bash, sh)") == {
        "type": "check",
        "op": "in",
        "lhs": {"type": "field", "field": "proc.name", "arg": None},
        "rhs": {"type": "list", "values": ["bash", "sh"]},
    }


def test_null_raw_ast_falls_back_to_the_compiled_condition():
    from ftest.explain import explain

    doc = shell_result()
    doc["rules"][0]["condition_raw_ast"] = None
    rule = parse_result(doc).rules[SHELL]
    assert rule.raw is None
    shape = shape_of(rule)
    assert not shape.aligned and shape.body is rule.compiled
    assert explain(rule, {})[1] == "Fires when all of:"


def test_case_error_for_an_unknown_traced_rule_reads_as_rule_not_loaded():
    from ftest.outcomes import judge

    doc = shell_result()
    doc["cases"] = [
        {"id": "s.yaml::bash", "error": "unknown rule in trace_rules: Terminal shel", "unknown_fields": []}
    ]
    parsed = parse_result(doc)
    outcome = judge(make_case(), "Terminal shel", parsed.cases["s.yaml::bash"], parsed.rules, ())
    assert outcome.failures == (
        "rule `Terminal shel` is not loaded (did you mean `Terminal shell in container`?)",
    )
