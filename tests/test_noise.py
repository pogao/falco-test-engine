"""The noise check, end to end through `ftest run` against the sample world."""

import json

import yaml
from samples import PKG, SHELL, World
from test_cli import engine, repo, report  # noqa: F401

from ftest.cli import main
from ftest.corpus import builtin

PKG_TERMS = (
    "spawned_process and proc.aname in (sh, bash) and container and proc.name in (package_managers) "
    "and not container.image.repository = ghcr.io/acme/ci-runner"
)
EXECS = sum(1 for e in builtin() if e.event["evt.type"] == ("execve",))


def inverted(world: World) -> World:
    world.rules[PKG]["condition"] = PKG_TERMS.replace("and proc.name in", "and not proc.name in")
    return world


def test_the_example_rules_fire_on_no_ordinary_event(repo):  # noqa: F811
    engine(repo, World.full(), World.stock())
    assert main(["run"]) == 0
    md = report(repo)
    assert f"- Noise: 3 rules checked on {len(builtin())} ordinary events; none over budget." in md
    assert f"**Noise.** Fired on 0 of the {EXECS} ordinary events of its event types (0%); budget 5%." in md


def test_an_inverted_rule_without_tests_fails_the_run(repo, capsys):  # noqa: F811
    engine(repo, inverted(World.full()), World.stock())
    (repo / "tests" / "package_manager_in_container.yaml").unlink()
    assert main(["run"]) == 1
    md = report(repo)
    assert "**FAIL**: 1 rule over the noise budget." in md
    assert f"**1 over budget** (`{PKG}` fired on " in md
    assert "FTE013 (error): fires on " in md and "likely inverted or missing a filter" in md
    assert "**Noise.** FAIL. Fired on " in md and ", over the 5% budget." in md
    examples = [line for line in md.splitlines() if line.startswith("- Fired on ")]
    assert 1 <= len(examples) <= 3
    assert all("proc.aname=[sh," in e or "proc.aname=[bash," in e for e in examples)
    assert f"  FAIL     {PKG}: no tests; noise " in capsys.readouterr().out
    assert json.loads((repo / "falco-test-report.json").read_text())["exit_code"] == 1


def test_a_suite_can_raise_the_budget_for_a_rule_that_fires_often(repo):  # noqa: F811
    engine(repo, inverted(World.full()), World.stock())
    suite_path = repo / "tests" / "package_manager_in_container.yaml"
    suite = yaml.safe_load(suite_path.read_text())
    suite["cases"] = [{"name": "any shell child", "expect": "match", "event": {"proc.name": "envsubst"}}]
    suite["max_fire_rate"] = 0.5
    suite_path.write_text(yaml.safe_dump(suite))
    assert main(["run"]) == 0
    assert "over the noise budget" not in report(repo)
    assert "; budget 50%." in report(repo)


def test_a_changed_stock_rule_is_compared_with_its_base_version(repo):  # noqa: F811
    world = World.full()
    world.rules[SHELL]["condition"] = world.rules[SHELL]["condition"].replace("proc.tty != 0", "proc.tty = 0")
    engine(repo, world, World.stock())
    assert main(["run"]) == 1
    md = report(repo)
    assert f"the base version fired on 0 of {EXECS}." in md
    assert f"`{SHELL}` fired on " in md


def test_the_noise_check_can_be_turned_off(repo):  # noqa: F811
    engine(repo, inverted(World.full()), World.stock())
    (repo / "tests" / "package_manager_in_container.yaml").unlink()
    cfg = yaml.safe_load((repo / "falco-test.yaml").read_text())
    cfg["noise"] = {"enabled": False}
    (repo / "falco-test.yaml").write_text(yaml.safe_dump(cfg))
    assert main(["run"]) == 0
    assert "- Noise: off." in report(repo)


def test_user_corpus_events_join_the_builtin_ones(repo):  # noqa: F811
    (repo / "ordinary.yaml").write_text(
        yaml.safe_dump(
            [{"evt.type": "execve", "proc.name": "apt", "proc.aname": ["sh"], "container.id": "c1"}]
        )
    )
    cfg = yaml.safe_load((repo / "falco-test.yaml").read_text())
    cfg["noise"] = {"corpus": ["ordinary.yaml"], "max_fire_rate": 0}
    (repo / "falco-test.yaml").write_text(yaml.safe_dump(cfg))
    engine(repo, World.full(), World.stock())
    assert main(["run"]) == 1
    md = report(repo)
    assert f"checked on {len(builtin()) + 1} ordinary events" in md
    assert f"Fired on 1 of the {EXECS + 1} ordinary events of its event types" in md
    assert "- Fired on ordinary.yaml event 1: `evt.type=execve proc.name=apt" in md
