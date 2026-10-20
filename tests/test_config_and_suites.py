from pathlib import Path

import pytest
import yaml

from ftest.config import DEFAULT_PLUGIN, ConfigError, JevMode, load_config
from ftest.suite import (
    ExpectExactRules,
    ExpectFires,
    ExpectOutput,
    SuiteError,
    load_suites,
    parse_suite,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def write(path: Path, doc) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc))
    return path


def test_example_config_resolves_paths_and_defaults():
    cfg = load_config(EXAMPLES / "falco-test.yaml")
    assert cfg.rules_files == (Path("/etc/falco/falco_rules.yaml"), EXAMPLES / "rules/custom_rules.yaml")
    assert cfg.base_rules_files == (Path("/etc/falco/falco_rules.yaml"),)
    assert cfg.plugins == (DEFAULT_PLUGIN,)
    assert cfg.jev.mode is JevMode.AUTO
    assert cfg.report.markdown == EXAMPLES / "falco-test-report.md"
    assert cfg.engine_binary == "falco-test-engine"
    assert cfg.startup.falco_config == Path("/etc/falco/falco.yaml")


def test_config_serializes_plugin_init_config_and_reads_options(tmp_path):
    path = write(
        tmp_path / "falco-test.yaml",
        {
            "rules_files": ["r.yaml"],
            "tests": ["t/"],
            "plugins": [{"name": "container", "library_path": "/p.so", "init_config": {"a": 1}}],
            "jev": {"enabled": False, "gate": True},
            "report": {"json": None},
            "engine": {"binary": "bin/engine"},
            "lint": {"disable": ["FTE005"]},
        },
    )
    cfg = load_config(path)
    assert cfg.plugins[0].init_config == '{"a": 1}'
    assert cfg.jev.mode is JevMode.OFF and cfg.jev.gate
    assert cfg.report.json is None
    assert cfg.engine_binary == str(tmp_path / "bin/engine")
    assert cfg.lint_disable == {"FTE005"}


def test_config_rejects_unknown_keys(tmp_path):
    path = write(tmp_path / "c.yaml", {"rules_files": ["r.yaml"], "tests": ["t"], "rule_files": []})
    with pytest.raises(ConfigError, match="unknown keys"):
        load_config(path)


def test_example_suites_parse_with_defaults_merged_and_fields_derived():
    suites = load_suites([EXAMPLES / "tests"], EXAMPLES)
    by_rule = {s.rule: s for s in suites}
    pkg = by_rule["Package manager run in container"]
    first = pkg.cases[0]
    assert first.id == "tests/package_manager_in_container.yaml::apt-get from bash in nginx"
    assert first.event["proc.name"] == ("apt-get",)
    assert first.event["proc.pname"] == ("bash",)
    assert first.event["proc.aname[2]"] == ("runc",)
    assert first.expectations == (
        ExpectFires(True),
        ExpectOutput(("apt-get install -y curl", "pod=web-6d4cf56db6-x7k2p")),
    )
    assert pkg.cases[-1].expectations == (ExpectExactRules(frozenset({"Package manager run in container"})),)
    shell = by_rule["Terminal shell in container"]
    assert shell.cases[0].event["proc.tty"] == ("34816",)
    assert shell.intent.startswith("Alert when someone opens an interactive shell")


def suite(cases, **extra):
    return {"rule": "R", "defaults": {"evt.type": "execve"}, "cases": cases, **extra}


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        (suite([{"name": "a", "event": {}}]), "give `expect` or `expect_rules`"),
        (suite([{"name": "a", "expect": "yes"}]), "match or no_match"),
        (suite([{"name": "a", "expect": "no_match", "output_contains": "x"}]), "needs the case to expect"),
        (suite([{"name": "a", "expect": "match"}, {"name": "a", "expect": "match"}]), "duplicate case"),
        ({"rule": "R", "cases": [{"name": "a", "expect": "match"}]}, "exactly one evt.type"),
        (suite([{"name": "a", "expect": "match", "event": {"proc.name": {"x": 1}}}]), "scalars"),
        (suite([]), "non-empty"),
    ],
)
def test_suite_errors_name_the_problem(doc, message):
    with pytest.raises(SuiteError, match=message):
        parse_suite(doc, Path("s.yaml"), "s.yaml")


def test_expect_and_expect_rules_combine():
    parsed = parse_suite(
        suite([{"name": "a", "expect": "no_match", "expect_rules": ["Other"], "event": {"x.y": True}}]),
        Path("s.yaml"),
        "s.yaml",
    )
    case = parsed.cases[0]
    assert case.expectations == (ExpectFires(False), ExpectExactRules(frozenset({"Other"})))
    assert case.event["x.y"] == ("true",)
