"""End to end: `ftest` against a fake `falco-test-engine` on PATH that evaluates a sample world."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from builders import install_fake_engine, received_jobs
from samples import META, PKG, SHELL, World, broken_world
from test_diff_and_startup import fake_falco
from test_jev import Stub, answers

from ftest.cli import main
from ftest.config import load_config

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
    assert "- Tests: 17 of 17 cases passed across 3 rules." in md
    assert "- Changes vs base: 1 changed, 2 added, 0 removed." in md
    assert "- 1 other loaded rule unchanged and untested; not analyzed." in md
    assert "- Jev: skipped (set JEV_API_KEY or TYPESAFE_API_KEY to enable)." in md
    assert f"## {PKG}\n\nWARNING, enabled. Added. Tests: 6 of 6 passed. Needs optimizing: yes (FTE005)." in md
    assert f"## {SHELL}\n\nNOTICE, enabled. Changed vs base: condition changed." in md
    assert "FTE006 (warning): `proc.cmdline regex ^/usr/bin/aws-node` only matches the exact value" in md
    assert "- Work: predicates evaluated on the test cases (not a production timing)" in md

    doc = json.loads((repo / "falco-test-report.json").read_text())
    assert doc["result"] == "pass" and doc["exit_code"] == 0
    assert {r["name"] for r in doc["rules"]} == {SHELL, PKG, META}

    full_job, base_job = received_jobs(state)
    assert base_job["cases"] == [] and base_job["rules_files"] == ["/etc/falco/falco_rules.yaml"]
    pip = next(c for c in full_job["cases"] if c["id"].endswith("::pip from sh"))
    assert pip["trace_rules"] == [PKG]
    assert pip["fields"]["proc.pname"] == ["sh"] and pip["fields"]["proc.aname[2]"] == ["runc"]
    assert capsys.readouterr().out.startswith("ftest: PASS")


def test_run_fails_on_the_broken_rules_and_says_why(repo, capsys):
    engine(repo, broken_world(), World.stock(), config="falco-test.broken.yaml")
    assert main(["run", "-c", "falco-test.broken.yaml"]) == 1
    md = report(repo)
    assert "**FAIL**: 6 test cases failed." in md
    assert f"- FAIL `yum on the host is out of scope`: expected `{PKG}` not to fire; it fired." in md
    assert f"- FAIL `pip from sh`: expected `{PKG}` to fire; it did not." in md
    assert f"- FAIL `other acme images still alert`: expected `{SHELL}` to fire; it did not." in md
    out = capsys.readouterr().out
    assert out.startswith("ftest: FAIL (6 test cases failed)")
    assert f"  FAIL     {PKG}: 1/6 cases" in out


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
    assert f"- `LOAD_ERR_COMPILE_CONDITION` {cfg.rules_files[1]}:9 rule `{PKG}`: unexpected token" in md
    assert "- Tests: not run: rules did not load." in md


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
    assert "  Suggestion: Use `proc.cmdline = /usr/bin/aws-node`." in out
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


def test_jev_reviews_each_rule_under_test_through_the_api(repo, monkeypatch):
    ok = {"model": "jev-1.13", "answers": answers(desc=0.1), "usage": {"input_tokens": 1, "output_tokens": 1}}
    stub = Stub([(200, {"x-typesafe-request-id": f"req-{i}"}, ok) for i in range(3)])
    try:
        monkeypatch.setenv("JEV_API_KEY", "sk-test")
        monkeypatch.setenv("JEV_BASE_URL", stub.url)
        engine(repo, World.full(), World.stock())
        assert main(["run"]) == 0
        assert len(stub.requests) == 3
        assert {r["body"]["state"]["rule"] for r in stub.requests} == {SHELL, PKG, META}
        md = report(repo)
        assert "- Jev: 3 rules reviewed with model jev-latest (advisory)." in md
        assert "**Jev** (advisory; model jev-1.13, request req-" in md
        assert "- finding: description may not match the condition (p=0.10)." in md

        cfg = yaml.safe_load((repo / "falco-test.yaml").read_text())
        cfg["jev"] = {"gate": True}
        (repo / "falco-test.yaml").write_text(yaml.safe_dump(cfg))
        stub.script = [(200, {}, ok) for _ in range(3)]
        assert main(["run"]) == 1
        assert "Jev gate: 3 findings, 0 failed requests" in report(repo)
        assert main(["run", "--no-jev"]) == 0
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
