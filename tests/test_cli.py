"""End to end: `ftest` against a fake `falco-test-engine` on PATH that evaluates a sample world."""

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from functools import partial
from pathlib import Path

import pytest
import yaml
from builders import install_fake_engine, received_jobs
from samples import META, PKG, SHELL, World, broken_world
from test_diff_and_startup import fake_falco
from test_jev import Stub, answering

import ftest
from ftest.cli import main
from ftest.config import ConfigError, load_config, parse_config
from ftest.fixtures import derive
from ftest.strength import verdicts
from ftest.suite import SuiteError, load_suites, parse_suite

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    shutil.copytree(EXAMPLES, tmp_path / "repo")
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/bin:/bin")
    for var in ("JEV_API_KEY", "TYPESAFE_API_KEY", "JEV_BASE_URL", "GITHUB_STEP_SUMMARY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path / "repo")
    return tmp_path / "repo"


def engine(repo: Path, full: World, base: World | None = None, config="falco-test.yaml", extra=()):
    cfg = load_config(repo / config)
    full.files = [str(p) for p in cfg.rules_files]
    responses = [*extra, {"rules_files": full.files, "world": full.spec()}]
    if base is not None:
        base.files = [str(p) for p in cfg.base_rules_files]
        responses.append({"rules_files": base.files, "world": base.spec()})
    install_fake_engine(repo.parent / "bin", repo.parent / "state", responses)
    return repo.parent / "state"


def report(repo: Path) -> str:
    return (repo / "falco-test-report.md").read_text()


def test_run_passes_on_the_example_rules(repo, capsys):
    state = engine(repo, World.full(), World.stock())
    assert main(["run"]) == 0
    md = report(repo)
    assert "**PASS**." in md
    assert "- Startup: skipped: no `falco` binary on PATH." in md
    assert "- Tests: 18 of 18 cases passed across 3 rules." in md
    assert "- Changes vs base: 1 changed, 2 added, 0 removed." in md
    assert "- 1 other loaded rule unchanged and untested; not analyzed." in md
    assert "- Jev: skipped (set JEV_API_KEY or TYPESAFE_API_KEY to enable)." in md
    assert f"## {PKG}\n\nWARNING, enabled. Added. Tests: 6 of 6 passed. Needs optimizing: yes (FTE005)." in md
    assert f"## {SHELL}\n\nNOTICE, enabled. Changed vs base: condition changed." in md
    assert "FTE007 (info): list `metadata_allowed_images` repeats `ghcr.io/acme/node-agent`." in md
    assert "- Work: predicates evaluated on the test cases (not a production timing)" in md

    doc = json.loads((repo / "falco-test-report.json").read_text())
    assert doc["result"] == "pass" and doc["exit_code"] == 0
    assert {r["name"] for r in doc["rules"]} == {SHELL, PKG, META}

    # PKG: strength 10/12 floors to 83, noise 0 fired is 100, lint has one warning (FTE005), Jev is off.
    pkg = (4 * (100 * 10 // 12) + 3 * 100 + 1 * (100 - 20)) // (4 + 3 + 1)
    assert pkg == 89
    assert f"- Readiness: {pkg}% (weakest: {PKG})." in md
    assert (
        f"**Readiness.** {pkg}%: strength 83% (10 of 12 mutants killed), noise 100% (0 of 97 fired; budget 5%), "
        "lint 80% (1 warning), weighted 4, 3, 1; not measured: Jev events." in md
    )
    assert (doc["readiness"]["status"], doc["readiness"]["score"], doc["readiness"]["weakest"]) == (
        "ready",
        pkg,
        PKG,
    )
    parts = next(r for r in doc["readiness"]["rules"] if r["rule"] == PKG)["parts"]
    assert parts[2] == {"name": "Jev events", "weight": 2, "percent": None, "inputs": None}

    full_job, base_job, generated_job = received_jobs(state)
    assert generated_job["rules_files"] == full_job["rules_files"]
    assert all(c["id"].startswith(f"generated::{c['trace_rules'][0]}::") for c in generated_job["cases"])
    assert base_job["rules_files"] == ["/etc/falco/falco_rules.yaml"]
    assert base_job["cases"] and all(c["trace_rules"] == [] for c in base_job["cases"])
    assert {c["id"] for c in base_job["cases"]} < {c["id"] for c in full_job["cases"]}
    pip = next(c for c in full_job["cases"] if c["id"].endswith("::pip from sh"))
    assert pip["trace_rules"] == [PKG]
    assert pip["fields"]["proc.pname"] == ["sh"] and pip["fields"]["proc.aname[2]"] == ["runc"]
    out = capsys.readouterr().out
    assert out.startswith("ftest: PASS")
    assert f"  ready    {pkg}% (weakest: {PKG})" in out
    assert (
        f"  ok       {PKG}: 6/6 cases; noise 0/97 (0%); strength 10/12; needs optimizing: yes (FTE005); ready {pkg}%"
        in out
    )


def test_run_fails_on_the_broken_rules_and_says_why(repo, capsys):
    engine(repo, broken_world(), World.stock(), config="falco-test.broken.yaml")
    assert main(["run", "-c", "falco-test.broken.yaml"]) == 1
    md = report(repo)
    assert "**FAIL**: 6 test cases failed." in md
    # The broken PKG condition parses as `(spawned_process and container and proc.name = apt)
    # or (proc.name = yum and not container.image.repository = ghcr.io/acme/ci-runner)`.
    assert (
        f"- FAIL `yum on the host is out of scope`: expected `{PKG}` not to fire; it fired.\n"
        "  - `proc.name = yum` was true, in the rule condition.\n"
        "  - `container.image.repository = ghcr.io/acme/ci-runner` was false, in the rule condition.\n"
    ) in md
    assert (
        f"- FAIL `pip from sh`: expected `{PKG}` to fire; it did not.\n"
        "  - `proc.name = apt` was false, in the rule condition.\n"
        "  - `proc.name = yum` was false, in the rule condition.\n"
    ) in md
    assert (
        "- FAIL `no other rule fires on apt-get in a container`: expected rule set differs; "
        f"did not fire: `{PKG}`.\n"
        "  - `proc.name = apt` was false, in the rule condition.\n"
        "  - `proc.name = yum` was false, in the rule condition.\n"
    ) in md
    assert (
        f"- FAIL `other acme images still alert`: expected `{SHELL}` to fire; it did not.\n"
        "  - `container.image.repository startswith ghcr.io/acme` was true, "
        "in macro `user_expected_terminal_shell_in_container_conditions`.\n"
    ) in md
    assert "- Readiness: not ready (see the failures above)." in md
    assert "**Readiness.**" not in md
    doc = json.loads((repo / "falco-test-report.json").read_text())
    assert doc["readiness"] == {"status": "not_ready", "reasons": ["6 test cases failed"]}
    outcomes = {o["name"]: o for r in doc["rules"] for o in r["outcomes"]}
    assert outcomes["pip from sh"]["why"] == [
        {"check": "proc.name = apt", "value": False, "where": "in the rule condition", "unset": []},
        {"check": "proc.name = yum", "value": False, "where": "in the rule condition", "unset": []},
    ]
    assert sum(not o["passed"] for o in outcomes.values()) == 6
    assert all((o["why"] == []) == o["passed"] for o in outcomes.values())
    out = capsys.readouterr().out
    assert out.startswith("ftest: FAIL (6 test cases failed)")
    assert "  ready    not ready (see the failures above)" in out
    assert f"  FAIL     {PKG}: 1/6 cases" in out
    assert "; ready " not in out


def test_failures_name_unset_fields_and_exception_checks(repo):
    world = World.full()
    world.rules[PKG]["exceptions"] = ["proc.pname = make"]
    world.rules[PKG]["exception_names"] = ["build_tools"]
    engine(repo, world, World.stock())
    nginx = {"evt.type": "execve", "container.id": "9f2c51b0a1d4", "container.image.repository": "nginx"}
    suite = {
        "rule": PKG,
        "cases": [
            {
                "name": "apt-get with no ancestors given",
                "expect": "match",
                "event": {**nginx, "proc.name": "apt-get", "container.id": "host"},
            },
            {
                "name": "apt from gmake is a build step",
                "expect": "no_match",
                "event": {**nginx, "proc.name": "apt", "proc.aname": "bash", "proc.pname": "gmake"},
            },
        ],
    }
    (repo / "tests" / "why.yaml").write_text(yaml.safe_dump(suite))
    assert main(["run"]) == 1
    md = report(repo)
    assert (
        f"- FAIL `apt-get with no ancestors given`: expected `{PKG}` to fire; it did not.\n"
        "  - `proc.aname in (sh, bash)` was false, in the rule condition. The case does not set `proc.aname`.\n"
        "  - `container.id != host` was false, in macro `container`.\n"
    ) in md
    assert (
        f"- FAIL `apt from gmake is a build step`: expected `{PKG}` not to fire; it fired.\n"
        "  - `evt.type in (execve, execveat)` was true, in macro `spawned_process`.\n"
        "  - `proc.aname in (sh, bash)` was true, in the rule condition.\n"
        "  - `container.id != host` was true, in macro `container`.\n"
        "  - `proc.name in (package_managers)` was true, in the rule condition.\n"
        "  - `container.image.repository = ghcr.io/acme/ci-runner` was false, in the rule condition.\n"
        "  - `proc.pname = make` was false, in exception `build_tools`.\n"
    ) in md
    doc = json.loads((repo / "falco-test-report.json").read_text())
    outcomes = {o["name"]: o for r in doc["rules"] for o in r["outcomes"]}
    assert outcomes["apt-get with no ancestors given"]["why"][0] == {
        "check": "proc.aname in (sh, bash)",
        "value": False,
        "where": "in the rule condition",
        "unset": ["proc.aname"],
    }
    assert all(o["why"] == [] for o in outcomes.values() if o["passed"])


def test_readiness_scores_only_the_parts_that_were_measured(repo):
    engine(repo, World.full(), World.stock())
    cfg = yaml.safe_load((repo / "falco-test.yaml").read_text())
    cfg["noise"] = {"enabled": False}
    cfg["mutation"] = {"enabled": False}
    (repo / "falco-test.yaml").write_text(yaml.safe_dump(cfg))
    assert main(["run"]) == 0
    md = report(repo)
    assert (
        "**Readiness.** 80%: lint 80% (1 warning), weighted 1; not measured: strength, noise, Jev events."
        in md
    )
    assert f"- Readiness: 80% (weakest: {PKG})." in md


def test_step_summary_gets_the_markdown(repo, monkeypatch):
    engine(repo, World.full(), World.stock())
    summary = repo / "summary.md"
    summary.write_text("earlier step\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main(["run"])
    assert summary.read_text() == "earlier step\n" + report(repo)


def test_strict_fails_on_error_findings(repo):
    world = World.full()
    world.rules[PKG]["condition"] += " and proc.name = apt and proc.name = yum"
    engine(repo, world, World.stock())
    (repo / "tests" / "package_manager_in_container.yaml").unlink()
    assert main(["run"]) == 0
    assert (
        "can never fire: `proc.name in (package_managers)`, `proc.name = apt`, `proc.name = yum` can never all be true"
        in report(repo)
    )
    assert main(["run", "--strict"]) == 1
    assert "1 error finding (--strict)" in report(repo)


def test_startup_failure_fails_the_run(repo):
    engine(repo, World.full(), World.stock())
    fake_falco(repo.parent / "bin", 1, "Error: rule loading failed")
    assert main(["run"]) == 1
    md = report(repo)
    assert "**FAIL**: Falco did not start (exit code 1)." in md
    assert "Error: rule loading failed" in md


def test_load_errors_fail_the_run_and_are_listed(repo):
    cfg = load_config(repo / "falco-test.yaml")
    failed = {
        "versions": {"falco": "0.45.1", "engine": "0.65.0", "libs": "0.26.1", "plugins": {}},
        "load": {
            "successful": False,
            "results": [
                {
                    "name": str(cfg.rules_files[1]),
                    "successful": False,
                    "warnings": [],
                    "errors": [
                        {
                            "context": {
                                "locations": [
                                    {
                                        "item_type": "rule",
                                        "item_name": PKG,
                                        "position": {
                                            "name": str(cfg.rules_files[1]),
                                            "line": 9,
                                            "column": 3,
                                            "offset": 1,
                                        },
                                    }
                                ],
                                "snippet": "",
                            },
                            "code": "LOAD_ERR_COMPILE_CONDITION",
                            "codedesc": "Error compiling condition",
                            "message": "unexpected token",
                        }
                    ],
                }
            ],
        },
        "plugin_requirements": {"ok": True, "error": ""},
        "rules": [],
        "cases_by_id": {},
    }
    engine(
        repo, World.full(), None, extra=[{"rules_files": [str(p) for p in cfg.rules_files], "result": failed}]
    )
    assert main(["run"]) == 1
    md = report(repo)
    assert "**FAIL**: rules failed to load." in md
    assert f"- `LOAD_ERR_COMPILE_CONDITION` {cfg.rules_files[1]}:10 rule `{PKG}`: unexpected token" in md
    assert "- Tests: not run: rules did not load." in md
    assert "- Noise: not run: rules did not load." in md
    assert "- Test strength: not run: rules did not load." in md


def test_engine_fatal_fails_the_run(repo):
    engine(
        repo,
        World.full(),
        None,
        extra=[{"rules_files": None, "exit": 2, "stdout": '{"fatal": "plugin failed"}'}],
    )
    assert main(["run"]) == 1
    assert "**FAIL**: engine failed: plugin failed." in report(repo)


def test_config_and_suite_errors_exit_2(repo, capsys):
    engine(repo, World.full())
    assert main(["run", "-c", "missing.yaml"]) == 2
    (repo / "tests" / "bad.yaml").write_text(yaml.safe_dump({"rule": "x", "cases": [{"name": "a"}]}))
    assert main(["run"]) == 2
    assert "give `expect` or `expect_rules`" in capsys.readouterr().err


def test_describe_explains_and_lints_one_rule(repo, capsys):
    engine(repo, World.full())
    assert main(["describe", META]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"{META}\n\n- Matches event `connect`.")
    assert "- FTE003 (info): in macro `cloud_metadata_endpoint`" in out
    assert main(["describe", "Cloud metadata acces"]) == 2
    assert f"did you mean '{META}'" in capsys.readouterr().err


def test_scaffold_writes_a_suite_that_lists_every_field(repo, capsys):
    engine(repo, World.full())
    assert main(["scaffold", PKG, "-o", "tests/new.yaml"]) == 0
    suite = yaml.safe_load((repo / "tests" / "new.yaml").read_text())
    assert suite["rule"] == PKG
    assert suite["defaults"] == {
        "evt.type": "execve",
        "proc.aname": "sh",
        "container.id": "TODO",
        "proc.name": "apt",
        "container.image.repository": "TODO",
    }
    assert [c["expect"] for c in suite["cases"]] == ["match", "no_match"]
    assert (
        "# from `proc.name in (apt, apt-get, dpkg, yum, ... +5)`" in (repo / "tests" / "new.yaml").read_text()
    )
    assert main(["scaffold", PKG, "-o", "tests/new.yaml"]) == 1


def reading_intents_as_the_cases_do(repo, flipped=(), priority="NOTICE", generated=lambda event: None):
    """A Stub responder for Jev that reads each suite case's event the way the case expects, except the
    cases named in `flipped`. Other events, the generated ones, get `generated`'s call, None for unsure."""
    calls = {}
    for suite in load_suites([repo / "tests"], repo):
        for case in suite.cases:
            fields = {**suite.defaults, **case.given}
            event = {k: v[0] if len(v) == 1 else list(v) for k, v in fields.items()}
            calls[json.dumps(event, sort_keys=True)] = verdicts(case, suite.rule)[0] != (case.name in flipped)

    def judge(state):
        key = json.dumps(state["event"], sort_keys=True)
        call = calls[key] if key in calls else generated(state["event"])
        return (0.5, 0.5) if call is None else (0.9, 0.1) if call else (0.1, 0.1)

    return answering(judge, priority)


def test_jev_judges_each_event_against_its_suite_intent(repo, monkeypatch):
    stub = Stub(reading_intents_as_the_cases_do(repo))
    try:
        monkeypatch.setenv("JEV_API_KEY", "sk-test")
        monkeypatch.setenv("JEV_BASE_URL", stub.url)
        engine(repo, World.full(), World.stock())
        assert main(["run"]) == 0
        priority = [r["body"]["state"]["rule"] for r in stub.requests if "priority" in r["body"]["questions"]]
        assert sorted(priority) == sorted([SHELL, PKG, META])
        suite_cases, generated_cases = 18, 6
        assert len(stub.requests) == 3 + suite_cases + generated_cases
        md = report(repo)
        assert "- Jev: 3 rules reviewed and 24 events judged with model jev-latest (advisory)." in md
        assert "**Jev** (advisory; model jev-1.13).\n\n- ok: priority NOTICE fits (confidence 0.80)." in md
        assert (
            "- Jev judged 9 events against their suite's intent: it agrees with the rule on 6, is unsure on 3."
            in md
        )
        # SHELL: strength 16/19 floors to 84, Jev agrees on 6 of 9 (the 3 unsure count against it).
        shell = (4 * (100 * 16 // 19) + 3 * 100 + 2 * (100 * 6 // 9) + 1 * 100) // 10
        assert shell == 86
        assert (
            f"**Readiness.** {shell}%: strength 84% (16 of 19 mutants killed), noise 100% (0 of 97 fired; "
            "budget 5%), Jev events 66% (6 of 9 agree, 3 unsure), lint 100% (no errors or warnings), "
            "weighted 4, 3, 2, 1." in md
        )

        cfg = yaml.safe_load((repo / "falco-test.yaml").read_text())
        cfg["jev"] = {"gate": True}
        (repo / "falco-test.yaml").write_text(yaml.safe_dump(cfg))
        stub.script = reading_intents_as_the_cases_do(
            repo,
            flipped={"CI runner installs packages by design"},
            priority="EMERGENCY",
            generated=lambda event: event.get("proc.name") == "node" or None,
        )
        assert main(["run"]) == 1
        md = report(repo)
        assert "Jev gate: 6 findings, 0 failed requests" in md
        assert "; Jev disputes the rule on 3 events." in md
        assert "- finding: suggests EMERGENCY, declared NOTICE (confidence 0.80)." in md
        assert (
            "- finding: `CI runner installs packages by design`: the rule and the case say no_match; "
            "Jev reads the intent as match (in scope p=0.90, exception p=0.10). "
            "The intent may be vague, or the case and the rule may both be wrong." in md
        )
        assert (
            "- finding: generated case `apt-get from bash in nginx, with proc.name=node`: the rule says "
            "no_match; Jev reads the intent as match (in scope p=0.90, exception p=0.10). Its `expect` only "
            "copies the rule, so this may be a rule bug: if Jev is right, set `expect: match` and fix the rule."
            in md
        )
        doc = json.loads((repo / "falco-test-report.json").read_text())
        judged = {j["case"]: j for r in doc["rules"] for j in r["judgments"]}
        assert judged["apt-get from bash in nginx, with proc.name=node"]["origin"] == "generated"
        assert judged["CI runner installs packages by design"] == {
            "case": "CI runner installs packages by design",
            "suite": "tests/package_manager_in_container.yaml",
            "origin": "suite",
            "rule_says": "no_match",
            "expect": "no_match",
            "jev_says": "match",
            "stance": "disputes_rule",
            "verdict": "finding",
            "in_scope": 0.9,
            "exception": 0.1,
            "model": "jev-1.13",
            "request_id": "req-1",
        }

        stub.script = reading_intents_as_the_cases_do(repo)
        assert main(["run"]) == 0
        sent = len(stub.requests)
        stub.script = reading_intents_as_the_cases_do(repo, flipped={"CI runner installs packages by design"})
        assert main(["run", "--no-jev"]) == 0
        assert len(stub.requests) == sent
    finally:
        stub.close()


def test_jev_sides_with_the_cases_a_broken_rule_fails(repo, monkeypatch):
    stub = Stub(reading_intents_as_the_cases_do(repo))
    try:
        monkeypatch.setenv("JEV_API_KEY", "sk-test")
        monkeypatch.setenv("JEV_BASE_URL", stub.url)
        engine(repo, broken_world(), World.stock(), config="falco-test.broken.yaml")
        assert main(["run", "-c", "falco-test.broken.yaml"]) == 1
        md = report(repo)
        assert "; Jev disputes the rule on 6 events." in md
        assert (
            "- finding: `pip from sh` fails, and Jev sides with the case: it reads the intent as match "
            "(in scope p=0.90, exception p=0.10). The rule is the likely culprit." in md
        )
        assert (
            "- finding: `yum on the host is out of scope` fails, and Jev sides with the case: it reads the "
            "intent as no_match (in scope p=0.10, exception p=0.10). The rule is the likely culprit." in md
        )
    finally:
        stub.close()


def test_python_dash_m_entry_point(repo):
    engine(repo, World.full(), World.stock())
    env = {**os.environ, "PATH": f"{repo.parent / 'bin'}:/usr/bin:/bin"}
    proc = subprocess.run(
        [sys.executable, "-m", "ftest", "run"], cwd=repo, env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("ftest: PASS")


@pytest.fixture
def guide(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["guide"]) == 0, "`ftest guide` must work with no falco-test.yaml"
    return capsys.readouterr().out


def allowed_keys(error: type[Exception], parse, raw) -> list[str]:
    with pytest.raises(error) as e:
        parse(raw)
    return ast.literal_eval(str(e.value).split("allowed: ", 1)[1])


def test_help_points_to_the_guide(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0
    assert "ftest guide" in capsys.readouterr().out


def test_guide_names_every_subcommand(guide, capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    commands = re.search(r"\{([\w,]+)\}", capsys.readouterr().out).group(1).split(",")
    assert "guide" in commands
    assert [c for c in commands if f"ftest {c}" not in guide] == []


def test_guide_names_every_finding_code(guide):
    sources = Path(ftest.__file__).parent.glob("*.py")
    codes = {code for p in sources for code in re.findall(r"FTE\d{3}", p.read_text())}
    assert len(codes) > 10
    assert sorted(c for c in codes if c not in guide) == []


def test_guide_names_every_suite_and_config_key(guide):
    suite = partial(parse_suite, path=Path("s.yaml"), display="s.yaml")
    config = partial(parse_config, path=Path("/r/falco-test.yaml"))
    keys = allowed_keys(SuiteError, suite, {"unknown_key": 1})
    keys += allowed_keys(SuiteError, suite, {"rule": "r", "cases": [{"unknown_key": 1}]})
    keys += allowed_keys(ConfigError, config, {"unknown_key": 1})
    assert {"max_fire_rate", "output_contains", "rules_files"} <= set(keys)
    assert [k for k in keys if f"`{k}" not in guide] == []


def test_guide_names_every_derived_field(guide):
    own = ("proc.name", "proc.pid", "proc.exe", "proc.exepath", "proc.cmdline")
    ancestors = ("proc.aname", "proc.apid", "proc.aexe", "proc.aexepath", "proc.acmdline")
    probe = {f: ("bash",) for f in own} | {f: ("sh", "runc") for f in ancestors}
    probe |= {"fd.cip": ("10.0.0.1",), "fd.sip": ("169.254.169.254",), "fd.cport": ("41000",)}
    probe |= {"fd.sport": ("80",), "fd.cproto": ("tcp",), "fd.sproto": ("tcp",), "fd.name": ("/etc/passwd",)}
    derived = {re.sub(r"\[\d+\]$", "[N]", f) for f in derive(probe) if f not in probe}
    assert {"proc.pname", "proc.aname[N]", "fd.net", "fd.filename"} <= derived
    assert sorted(f for f in derived if f"`{f}`" not in guide) == []
