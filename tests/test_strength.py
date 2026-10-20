"""Test strength and generated cases, end to end through `ftest` against the sample world."""

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
