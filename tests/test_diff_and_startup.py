import os
import sys
from pathlib import Path

from samples import META, PKG, SENSITIVE, SHELL, World

from ftest.diff import RuleChange, diff_rules, untested
from ftest.engine import parse_result
from ftest.startup import StartupFailed, StartupPassed, StartupSkipped, check_startup


def test_diff_names_added_changed_and_removed_rules():
    base = World.stock()
    base.rules["Retired rule"] = dict(base.rules[SENSITIVE])
    full = World.full()
    full.rules[SENSITIVE]["priority"] = "ERROR"
    full.rules[SENSITIVE]["enabled"] = False
    full.rules[SENSITIVE]["evttypes"] = ["openat", "openat2"]
    changes = diff_rules(parse_result(base.result()).rules, parse_result(full.result()).rules)
    assert set(changes) == {
        RuleChange(SHELL, "changed", ("condition changed",)),
        RuleChange(
            SENSITIVE, "changed", ("disabled", "priority WARNING -> ERROR", "event types +openat2 -open")
        ),
        RuleChange(PKG, "added"),
        RuleChange(META, "added"),
        RuleChange("Retired rule", "removed"),
    }
    warned = untested(changes, tested={PKG, META})
    assert [(f.code, f.rule, f.message) for f in warned] == [
        ("FTE011", SHELL, "modified stock rule has no tests"),
        ("FTE011", SENSITIVE, "modified stock rule has no tests"),
    ]


def fake_falco(bin_dir: Path, exit_code: int, output: str) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / "falco"
    script.write_text(
        f"#!{sys.executable}\nimport sys\nprint({output!r})\nprint(' '.join(sys.argv[1:]))\nsys.exit({exit_code})\n"
    )
    os.chmod(script, 0o755)


def test_startup_runs_falco_dry_run_with_every_rules_file(tmp_path, monkeypatch):
    fake_falco(tmp_path / "bin", 0, "Falco initialized")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    result = check_startup(True, Path("/etc/falco/falco.yaml"), [Path("/a.yaml"), Path("/b.yaml")])
    assert isinstance(result, StartupPassed)
    assert result.command == "falco -c /etc/falco/falco.yaml --dry-run -r /a.yaml -r /b.yaml"
    assert result.tail.splitlines() == [
        "Falco initialized",
        "-c /etc/falco/falco.yaml --dry-run -r /a.yaml -r /b.yaml",
    ]


def test_startup_failure_keeps_the_output_tail(tmp_path, monkeypatch):
    fake_falco(tmp_path / "bin", 1, "Error: LOAD_ERR_COMPILE_CONDITION")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    result = check_startup(True, Path("/c.yaml"), [Path("/a.yaml")])
    assert isinstance(result, StartupFailed)
    assert result.reason == "exit code 1" and "LOAD_ERR_COMPILE_CONDITION" in result.tail


def test_startup_skips_without_falco_or_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    assert check_startup(True, Path("/c.yaml"), []) == StartupSkipped("no `falco` binary on PATH")
    assert check_startup(False, Path("/c.yaml"), []) == StartupSkipped("disabled in falco-test.yaml")
