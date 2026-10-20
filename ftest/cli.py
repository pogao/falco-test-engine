"""ftest: prove Falco rules start, behave as their tests say, and say how to make them cheaper."""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import json
import re
import sys
from pathlib import Path

import yaml

from ftest.cond import Check, ListValue, Not, Value, render, walk
from ftest.config import Config, ConfigError, load_config
from ftest.engine import EngineError, EngineResult, Rule, build_job, run_engine
from ftest.explain import explain
from ftest.lint import RuleView, lint_rule
from ftest.report import console, exit_code
from ftest.run import run, write_reports
from ftest.shape import shape_of
from ftest.strength import Survivor
from ftest.suite import SuiteError, parse_suite

USAGE_ERROR = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ftest", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    run_cmd = commands.add_parser("run", help="run every suite and write the report")
    run_cmd.add_argument("--strict", action="store_true", help="fail on error-severity lint findings too")
    run_cmd.add_argument("--no-jev", action="store_true", help="skip Jev review")
    describe_cmd = commands.add_parser("describe", help="explain and lint one rule")
    describe_cmd.add_argument("rule")
    scaffold_cmd = commands.add_parser("scaffold", help="write a suite skeleton for one rule")
    scaffold_cmd.add_argument("rule")
    scaffold_cmd.add_argument("-o", "--output", type=Path, help="suite file to write")
    generate_cmd = commands.add_parser(
        "generate", help="write a suite of generated cases that catch one rule's surviving mutants"
    )
    generate_cmd.add_argument("rule")
    generate_cmd.add_argument("-o", "--output", type=Path, help="suite file to write")
    for cmd in (run_cmd, describe_cmd, scaffold_cmd, generate_cmd):
        cmd.add_argument("-c", "--config", type=Path, default=Path("falco-test.yaml"))

    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
        match args.command:
            case "run":
                report = run(cfg, strict=args.strict, use_jev=not args.no_jev)
                written = write_reports(report, cfg)
                print(console(report, written))
                return exit_code(report)
            case "describe":
                return _describe(cfg, args.rule)
            case "scaffold":
                return _scaffold(cfg, args.rule, args.output)
            case "generate":
                return _generate(cfg, args.rule, args.output)
    except (ConfigError, SuiteError, EngineError) as e:
        print(f"ftest: error: {e}", file=sys.stderr)
        return USAGE_ERROR
    return USAGE_ERROR


def _load_rule(cfg: Config, name: str) -> tuple[EngineResult, Rule]:
    result = run_engine(cfg.engine_binary, build_job(cfg.rules_files, cfg.plugins, []))
    if not result.load.ok:
        errors = "; ".join(f"{e.code} {e.item_name}: {e.message}" for e in result.load.errors)
        raise EngineError(f"rules failed to load: {errors or result.load.plugin_error}")
    if name not in result.rules:
        close = difflib.get_close_matches(name, list(result.rules), n=1, cutoff=0.6)
        hint = f" (did you mean {close[0]!r}?)" if close else ""
        raise EngineError(f"rule {name!r} is not loaded{hint}")
    return result, result.rules[name]


def _describe(cfg: Config, name: str) -> int:
    result, rule = _load_rule(cfg, name)
    print(f"{rule.name}\n")
    for line in explain(rule, result.macros):
        print(line if line.startswith("  ") else f"- {line}")
    findings = lint_rule(RuleView(rule, shape_of(rule), result.macros, result.lists), cfg.lint_disable)
    print("\nLint:" if findings else "\nLint: no findings.")
    for f in findings:
        print(f"- {f.code} ({f.severity.value}): {f.message}")
        if f.suggestion:
            print(f"  Suggestion: {f.suggestion}")
    return 0


def _scaffold(cfg: Config, name: str, output: Path | None) -> int:
    result, rule = _load_rule(cfg, name)
    target = output or _default_suite_path(cfg, name)
    if target.exists():
        print(f"ftest: error: {target} exists; pass -o to choose another file", file=sys.stderr)
        return 1
    text = suite_skeleton(rule)
    parse_suite(yaml.safe_load(text), target, str(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    print(f"wrote {target}")
    return 0


def _default_suite_path(cfg: Config, name: str, suffix: str = "") -> Path:
    tests_dir = next((t for t in cfg.tests if t.is_dir() or not t.suffix), cfg.root)
    return tests_dir / (re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") + suffix + ".yaml")


def _generate(cfg: Config, name: str, output: Path | None) -> int:
    cfg = dataclasses.replace(
        cfg,
        noise=dataclasses.replace(cfg.noise, enabled=False),
        mutation=dataclasses.replace(cfg.mutation, enabled=True),
    )
    report = run(cfg, use_jev=False)
    if report.engine_error or report.load is None or not report.load.ok:
        raise EngineError(report.engine_error or "rules failed to load; run `ftest run` to see why")
    section = next((s for s in report.sections if s.name == name), None)
    if section is None or section.strength is None:
        print(
            f"ftest: error: no test case traces {name!r}; write a suite first (`ftest scaffold`)",
            file=sys.stderr,
        )
        return 1
    survivors = section.strength.survivors
    found = [s for s in survivors if s.example is not None]
    print(f"{name}: {section.strength.summary}")
    for s in survivors:
        print(
            f"- {'generated a case for' if s.example else 'no distinguishing event for'} {s.mutant.description}"
        )
    if not found:
        return 0
    target = output or _default_suite_path(cfg, name, "_generated")
    if target.exists():
        print(f"ftest: error: {target} exists; pass -o to choose another file", file=sys.stderr)
        return 1
    text = generated_suite(name, found)
    parse_suite(yaml.safe_load(text), target, str(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    print(f"wrote {target}: {len(found)} cases; each `expect` is the current rule's verdict, confirm it")
    return 0


def generated_suite(rule: str, survivors: list[Survivor]) -> str:
    """A suite file of generated cases. One source suite lends its defaults; several do not."""
    sources = {s.example.suite.display: s.example.suite for s in survivors}
    shared = next(iter(sources.values())) if len(sources) == 1 else None
    lines = [
        f"# Generated by `ftest generate` for {json.dumps(rule)} from {', '.join(sources)}.",
        "# Each case is an event on which the current rule and one of its mutants disagree. The engine",
        "# evaluated every one. Each `expect` is what the current rule does there, not a verified intent:",
        "# confirm it, then keep the case or fix the rule.",
        f"rule: {json.dumps(rule)}",
    ]
    if shared is not None and shared.defaults:
        defaults = {k: v[0] if len(v) == 1 else list(v) for k, v in shared.defaults.items()}
        lines += ["defaults:", *(f"  {line}" for line in _flow(defaults).splitlines())]
    lines.append("cases:")
    cases: dict[str, list[Survivor]] = {}
    for s in survivors:
        cases.setdefault(s.example.yaml(with_defaults=shared is None), []).append(s)
    for text, catching in cases.items():
        g = catching[0].example
        lines.append(f"  # Generated from `{g.extends}`: changes {g.changed.replace('`', '')}.")
        for s in catching:
            lines.append(f"  # Catches {s.mutant.description.replace('`', '')}.")
        lines.append(
            f"  # `expect: {g.verdict}` is what the current rule does here; confirm it is what you want."
        )
        lines += [f"  {line}" for line in text.splitlines()]
    return "\n".join(lines) + "\n"


def _flow(doc: dict) -> str:
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=None, width=10_000)


def suite_skeleton(rule: Rule) -> str:
    """Every field the rule reads, each with a value taken from the condition when one exists."""
    samples: dict[str, tuple[str, str]] = {}
    negated = {id(n) for top in walk(rule.compiled) if isinstance(top, Not) for n in walk(top.child)}
    for node in walk(rule.compiled):
        if isinstance(node, Check) and node.op != "exists" and isinstance(node.rhs, Value | ListValue):
            values = node.rhs.values if isinstance(node.rhs, ListValue) else (node.rhs.value,)
            if values and id(node) not in negated and node.base_op in ("=", "==", "in"):
                samples.setdefault(render(node.lhs), (values[0], f"from `{render(node, 4)}`"))
    fields = ["evt.type"] + [f for f in rule.condition_fields if f != "evt.type"]
    lines = [
        f"# Suite skeleton for {json.dumps(rule.name)}. Replace each TODO, then make the two cases real.",
        f"rule: {json.dumps(rule.name)}",
        "intent: TODO say what this rule must catch and what it must ignore.",
        "defaults:",
    ]
    for field in fields:
        if field == "evt.type":
            value, hint = (
                (rule.evttypes[0], "one of the rule's event types") if rule.evttypes else ("TODO", "")
            )
        else:
            value, hint = samples.get(field, ("TODO", "the rule reads this field"))
        lines.append(f"  {field}: {json.dumps(value)}" + (f"  # {hint}" if hint else ""))
    lines += [
        "cases:",
        "  - name: TODO an event the rule should alert on",
        "    expect: match",
        "    event: {}",
        "  - name: TODO a similar event the rule must ignore",
        "    expect: no_match",
        "    event: {}",
    ]
    return "\n".join(lines) + "\n"
