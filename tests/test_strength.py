"""Test strength and generated cases, end to end through `ftest` against the sample world."""

import json

import yaml
from samples import META, PKG, World
from test_cli import engine, repo, report  # noqa: F401

from ftest.cli import main


def configure(repo, **sections):  # noqa: F811
    cfg = yaml.safe_load((repo / "falco-test.yaml").read_text())
    cfg.update(sections)
    (repo / "falco-test.yaml").write_text(yaml.safe_dump(cfg))


def test_each_rule_reports_its_score_and_survivors(repo, capsys):  # noqa: F811
    engine(repo, World.full(), World.stock())
    assert main(["run"]) == 0
    md = report(repo)
    assert "- Test strength: " in md and " mutants killed across 3 rules; " in md
    assert "**Test strength.** 10 of 12 mutants killed (83.3%)." in md
    assert (
        "- FTE012 (warning): your tests would not catch dropping `proc.name in (package_managers)` "
        "in the rule condition." in md
    )
    assert f"  ok       {PKG}: 6/6 cases; noise 0/" in capsys.readouterr().out


def test_a_score_below_min_score_fails_the_run(repo, capsys):  # noqa: F811
    engine(repo, World.full(), World.stock())
    configure(repo, mutation={"min_score": 0.9})
    assert main(["run"]) == 1
    md = report(repo)
    assert "rules below the test-strength minimum" in md
    assert "**Test strength.** FAIL. 10 of 12 mutants killed (83.3%), below the 90% minimum." in md
    assert f"  FAIL     {PKG}: 6/6 cases" in capsys.readouterr().out


def test_mutation_can_be_turned_off(repo):  # noqa: F811
    engine(repo, World.full(), World.stock())
    configure(repo, mutation={"enabled": False})
    assert main(["run"]) == 0
    md = report(repo)
    assert "- Test strength: off." in md
    assert "FTE012" not in md and f"## {META}" in md


HOST_CASE = "yum on the host is out of scope"


def weaken(repo):  # noqa: F811
    path = repo / "tests" / "package_manager_in_container.yaml"
    suite = yaml.safe_load(path.read_text())
    suite["cases"] = [c for c in suite["cases"] if c["name"] != HOST_CASE]
    path.write_text(yaml.safe_dump(suite, sort_keys=False))


def test_a_survivor_comes_with_a_case_the_engine_checked(repo):  # noqa: F811
    engine(repo, World.full(), World.stock())
    weaken(repo)
    assert main(["run"]) == 0
    md = report(repo)
    assert "- FTE012 (warning): your tests would not catch dropping macro `container`." in md
    assert (
        "  The current rule says no_match here; confirm that is what you want, then add it to your suite. "
        "This case extends `apt-get from bash in nginx` in tests/package_manager_in_container.yaml and "
        "changes `container.id` from `9f2c51b0a1d4` to `host`." in md
    )
    assert "  - name: apt-get from bash in nginx, with container.id=host\n    expect: no_match\n" in md


def test_generate_writes_a_suite_that_kills_the_survivors(repo, capsys):  # noqa: F811
    engine(repo, World.full(), World.stock())
    weaken(repo)
    assert main(["generate", PKG]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"{PKG}: 9 of 12 mutants killed (75%)")
    path = repo / "tests" / "package_manager_run_in_container_generated.yaml"
    text = path.read_text()
    assert "not a verified intent" in text and "confirm it is what you want" in text
    suite = yaml.safe_load(text)
    assert suite["rule"] == PKG and suite["defaults"]["container.id"] == "9f2c51b0a1d4"
    host = next(c for c in suite["cases"] if c["event"].get("container.id") == "host")
    assert host["expect"] == "no_match" and host["event"]["proc.name"] == "apt-get"

    assert main(["run"]) == 0
    assert "**Test strength.** 12 of 12 mutants killed (100%)." in report(repo)
    assert main(["generate", PKG, "-o", str(path)]) == 0
    assert path.read_text() == text
    assert "12 of 12 mutants killed" in capsys.readouterr().out


def test_generate_refuses_to_overwrite_and_needs_cases(repo, capsys):  # noqa: F811
    engine(repo, World.full(), World.stock())
    weaken(repo)
    assert main(["generate", PKG, "-o", "tests/package_manager_in_container.yaml"]) == 1
    assert "exists" in capsys.readouterr().err
    assert main(["generate", "Package manager run in containr"]) == 2
    assert f"did you mean '{PKG}'" in capsys.readouterr().err
    (repo / "tests" / "package_manager_in_container.yaml").unlink()
    assert main(["generate", PKG]) == 1
    assert "write a suite first" in capsys.readouterr().err


def test_a_failed_check_of_generated_events_is_reported_not_hidden(repo):  # noqa: F811
    engine(repo, World.full(), World.stock())
    weaken(repo)
    fake = repo.parent / "bin" / "falco-test-engine"
    shebang, rest = fake.read_text().split("\n", 1)
    crash = (
        "import json, pathlib, sys\n"
        "job = json.loads(pathlib.Path(sys.argv[sys.argv.index('--job') + 1]).read_text())\n"
        "if any(c['id'].startswith('generated::') for c in job['cases']):\n"
        "    print(json.dumps({'fatal': 'verification crashed'}))\n"
        "    sys.exit(2)\n"
    )
    fake.write_text(f"{shebang}\n{crash}{rest}")
    assert main(["run"]) == 0
    assert "  Generated events were not checked: engine failed: verification crashed." in report(repo)


def test_the_json_report_gives_survivors_as_text_and_cases(repo):  # noqa: F811
    engine(repo, World.full(), World.stock())
    weaken(repo)
    assert main(["run"]) == 0
    doc = json.loads((repo / "falco-test-report.json").read_text())
    strength = next(r for r in doc["rules"] if r["name"] == PKG)["strength"]
    assert (strength["killed"], strength["total"]) == (9, 12)
    dropped = next(s for s in strength["survivors"] if s["description"] == "dropping macro `container`")
    assert dropped["kind"] == "drop" and "container.id != host" not in dropped["condition"]
    assert dropped["generated"]["suite"] == "tests/package_manager_in_container.yaml"
    assert dropped["generated"]["case"]["event"]["container.id"] == "host"
