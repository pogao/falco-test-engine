"""Suite YAML files: one rule under test per file, parsed into frozen Suites."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ftest.fixtures import derive


class SuiteError(Exception):
    pass


@dataclass(frozen=True)
class ExpectFires:
    fires: bool


@dataclass(frozen=True)
class ExpectExactRules:
    rules: frozenset[str]


@dataclass(frozen=True)
class ExpectOutput:
    needles: tuple[str, ...]


type Expectation = ExpectFires | ExpectExactRules | ExpectOutput


@dataclass(frozen=True)
class Case:
    id: str
    name: str
    event: Mapping[str, tuple[str, ...]]
    expectations: tuple[Expectation, ...]


@dataclass(frozen=True)
class Suite:
    path: Path
    display: str
    rule: str
    intent: str | None
    cases: tuple[Case, ...]


def suite_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.suffix in (".yaml", ".yml")))
        elif path.is_file():
            files.append(path)
        else:
            raise SuiteError(f"test path does not exist: {path}")
    return files


def load_suites(paths: Iterable[Path], root: Path) -> tuple[Suite, ...]:
    suites = []
    for file in suite_files(paths):
        display = str(file.relative_to(root)) if file.is_relative_to(root) else str(file)
        try:
            raw = yaml.safe_load(file.read_text())
        except yaml.YAMLError as e:
            raise SuiteError(f"{display}: invalid YAML: {e}") from e
        suites.append(parse_suite(raw, file, display))
    return tuple(suites)


def parse_suite(raw: Any, path: Path, display: str) -> Suite:
    doc = _mapping(raw, display, {"rule", "intent", "defaults", "cases"})
    rule = doc.get("rule")
    if not isinstance(rule, str) or not rule:
        raise SuiteError(f"{display}: `rule` must name the rule under test")
    intent = doc.get("intent")
    if intent is not None and not isinstance(intent, str):
        raise SuiteError(f"{display}: `intent` must be text")
    defaults = _event(doc.get("defaults", {}), f"{display}: defaults")
    cases_raw = doc.get("cases")
    if not isinstance(cases_raw, list) or not cases_raw:
        raise SuiteError(f"{display}: `cases` must be a non-empty list")

    cases: list[Case] = []
    for i, item in enumerate(cases_raw):
        case = _case(item, rule, defaults, f"{display}: cases[{i}]", display)
        if any(c.name == case.name for c in cases):
            raise SuiteError(f"{display}: duplicate case name {case.name!r}")
        cases.append(case)
    return Suite(path, display, rule, " ".join(intent.split()) if intent else None, tuple(cases))


def _case(raw: Any, rule: str, defaults: dict[str, tuple[str, ...]], where: str, display: str) -> Case:
    doc = _mapping(raw, where, {"name", "expect", "expect_rules", "event", "output_contains"})
    name = doc.get("name")
    if not isinstance(name, str) or not name:
        raise SuiteError(f"{where}: every case needs a `name`")
    where = f"{display}: case {name!r}"

    expectations: list[Expectation] = []
    match doc.get("expect"):
        case None:
            pass
        case "match" | "no_match" as word:
            expectations.append(ExpectFires(word == "match"))
        case other:
            raise SuiteError(f"{where}: expect must be match or no_match, not {other!r}")
    if "expect_rules" in doc:
        rules = doc["expect_rules"]
        if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
            raise SuiteError(f"{where}: expect_rules must be a list of rule names")
        expectations.append(ExpectExactRules(frozenset(rules)))
    if not expectations:
        raise SuiteError(f"{where}: give `expect` or `expect_rules`")

    if "output_contains" in doc:
        needles = doc["output_contains"]
        needles = [needles] if isinstance(needles, str) else needles
        if not isinstance(needles, list) or not all(isinstance(n, str) for n in needles):
            raise SuiteError(f"{where}: output_contains must be text or a list of text")
        if not _expects_fire(expectations, rule):
            raise SuiteError(f"{where}: output_contains needs the case to expect `{rule}` to fire")
        expectations.append(ExpectOutput(tuple(needles)))

    event = {**defaults, **_event(doc.get("event", {}), f"{where}: event")}
    if len(event.get("evt.type", ())) != 1:
        raise SuiteError(f"{where}: needs exactly one evt.type; set it in `defaults` or the case event")
    return Case(f"{display}::{name}", name, derive(event), tuple(expectations))


def _expects_fire(expectations: list[Expectation], rule: str) -> bool:
    return any(
        (isinstance(e, ExpectFires) and e.fires) or (isinstance(e, ExpectExactRules) and rule in e.rules)
        for e in expectations
    )


def _event(raw: Any, where: str) -> dict[str, tuple[str, ...]]:
    if not isinstance(raw, dict):
        raise SuiteError(f"{where}: expected a mapping of field to value")
    return {str(field): _values(value, f"{where}.{field}") for field, value in raw.items()}


def _values(value: Any, where: str) -> tuple[str, ...]:
    items = value if isinstance(value, list) else [value]
    out = []
    for item in items:
        if isinstance(item, bool):
            out.append("true" if item else "false")
        elif isinstance(item, str | int | float):
            out.append(str(item))
        else:
            raise SuiteError(f"{where}: values must be scalars or lists of scalars")
    return tuple(out)


def _mapping(raw: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SuiteError(f"{where}: expected a mapping")
    unknown = set(raw) - allowed
    if unknown:
        raise SuiteError(f"{where}: unknown keys {sorted(unknown)}; allowed: {sorted(allowed)}")
    return raw
