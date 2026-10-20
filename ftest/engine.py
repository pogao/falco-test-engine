"""Adapter for `falco-test-engine` (docs/engine-protocol.md): build a job, run it, parse the result."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ftest import cond
from ftest.config import PluginSpec
from ftest.suite import Case


class EngineError(Exception):
    pass


@dataclass(frozen=True)
class Versions:
    falco: str
    engine: str
    libs: str
    plugins: Mapping[str, str]


@dataclass(frozen=True)
class LoadMessage:
    code: str
    description: str
    message: str
    item_type: str
    item_name: str
    file: str
    line: int | None
    snippet: str = ""


@dataclass(frozen=True)
class FileLoad:
    name: str
    successful: bool
    errors: tuple[LoadMessage, ...]
    warnings: tuple[LoadMessage, ...]


@dataclass(frozen=True)
class Load:
    successful: bool
    files: tuple[FileLoad, ...]
    plugin_error: str | None

    @property
    def ok(self) -> bool:
        return self.successful and self.plugin_error is None

    @property
    def warnings(self) -> tuple[LoadMessage, ...]:
        return tuple(w for f in self.files for w in f.warnings)

    @property
    def errors(self) -> tuple[LoadMessage, ...]:
        return tuple(e for f in self.files for e in f.errors)


@dataclass(frozen=True)
class Rule:
    name: str
    source: str
    enabled: bool
    priority: str
    evttypes: tuple[str, ...]
    raw: cond.Node | None
    compiled: cond.Node
    leaf_count: int
    description: str = ""
    condition: str = ""
    output: str = ""
    tags: tuple[str, ...] = ()
    macros: tuple[str, ...] = ()
    lists: tuple[str, ...] = ()
    condition_fields: tuple[str, ...] = ()
    output_fields: tuple[str, ...] = ()
    exception_names: tuple[str, ...] = ()
    exception_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class Macro:
    name: str
    condition: str
    used: bool
    lists: tuple[str, ...]
    condition_fields: tuple[str, ...]


@dataclass(frozen=True)
class ListDef:
    name: str
    items: tuple[str, ...]
    used: bool


@dataclass(frozen=True)
class Trace:
    result: bool
    leaves: tuple[bool, ...]
    missing_fields: tuple[str, ...]


@dataclass(frozen=True)
class Alert:
    rule: str
    priority: str
    output: str


@dataclass(frozen=True)
class CaseError:
    id: str
    error: str
    unknown_fields: tuple[str, ...]


@dataclass(frozen=True)
class CaseRun:
    id: str
    alerts: tuple[Alert, ...]
    traces: Mapping[str, Trace]

    def alert_for(self, rule: str) -> Alert | None:
        return next((a for a in self.alerts if a.rule == rule), None)


type CaseResult = CaseError | CaseRun


@dataclass(frozen=True)
class EngineResult:
    versions: Versions
    load: Load
    rules: Mapping[str, Rule]
    macros: Mapping[str, Macro] = field(default_factory=dict)
    lists: Mapping[str, ListDef] = field(default_factory=dict)
    cases: Mapping[str, CaseResult] = field(default_factory=dict)

    @property
    def known_fields(self) -> frozenset[str]:
        fields = {f for r in self.rules.values() for f in r.condition_fields}
        fields.update(f for m in self.macros.values() for f in m.condition_fields)
        return frozenset(fields)


@dataclass(frozen=True)
class JobCase:
    case: Case
    rule: str | None


def build_job(rules_files: Sequence[Path], plugins: Sequence[PluginSpec], cases: Sequence[JobCase]) -> dict:
    return {
        "rules_files": [str(p) for p in rules_files],
        "plugins": [
            {"name": p.name, "library_path": p.library_path, "init_config": p.init_config} for p in plugins
        ],
        "describe": True,
        "cases": [
            {
                "id": c.case.id,
                "source": "syscall",
                "fields": {k: list(v) for k, v in c.case.event.items()},
                "trace_rules": [c.rule] if c.rule else [],
            }
            for c in cases
        ],
    }


def run_engine(binary: str, job: dict, timeout: float = 600) -> EngineResult:
    executable = shutil.which(binary)
    if executable is None:
        raise EngineError(f"engine binary not found: {binary}")
    fd, job_path = tempfile.mkstemp(prefix="ftest-job-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(job, f)
        try:
            proc = subprocess.run(
                [executable, "--job", job_path], capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired as e:
            raise EngineError(f"engine timed out after {timeout:.0f}s") from e
    finally:
        os.unlink(job_path)
    if proc.returncode == 2:
        try:
            message = json.loads(proc.stdout)["fatal"]
        except (ValueError, KeyError, TypeError):
            message = _tail(proc.stderr or proc.stdout)
        raise EngineError(f"engine failed: {message}")
    if proc.returncode != 0:
        raise EngineError(f"engine exited with code {proc.returncode}: {_tail(proc.stderr)}")
    try:
        doc = json.loads(proc.stdout)
    except ValueError as e:
        raise EngineError(f"engine wrote invalid JSON: {e}") from e
    return parse_result(doc)


def _tail(text: str, lines: int = 20) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def parse_result(doc: Any) -> EngineResult:
    try:
        return _parse_result(doc)
    except (KeyError, TypeError, ValueError, cond.AstError) as e:
        raise EngineError(f"engine result does not follow the protocol: {e!r}") from e


def _parse_result(doc: dict) -> EngineResult:
    v = doc["versions"]
    versions = Versions(v["falco"], v["engine"], v["libs"], dict(v.get("plugins", {})))
    plugin_req = doc.get("plugin_requirements", {"ok": True})
    load = Load(
        successful=bool(doc["load"]["successful"]),
        files=tuple(_file_load(r) for r in doc["load"]["results"]),
        plugin_error=None if plugin_req.get("ok", True) else (plugin_req.get("error") or "unmet"),
    )
    describe = doc.get("describe") or {}
    details = {d["info"]["name"]: d for d in describe.get("rules", [])}
    rules = {r["name"]: _rule(r, details.get(r["name"])) for r in doc.get("rules", [])}
    macros = {
        m["info"]["name"]: Macro(
            name=m["info"]["name"],
            condition=_oneline(m["info"]["condition"]),
            used=bool(m["details"].get("used", True)),
            lists=tuple(m["details"].get("lists", [])),
            condition_fields=tuple(m["details"].get("condition_fields", [])),
        )
        for m in describe.get("macros", [])
    }
    lists = {
        item["info"]["name"]: ListDef(
            name=item["info"]["name"],
            items=tuple(item["details"].get("items_compiled", item["info"].get("items", []))),
            used=bool(item["details"].get("used", True)),
        )
        for item in describe.get("lists", [])
    }
    for rule in rules.values():
        ids = sorted(c.id for c in cond.checks(rule.compiled) if c.id is not None)
        if ids != list(range(rule.leaf_count)):
            raise ValueError(f"rule {rule.name!r}: condition_ast leaf ids are not 0..{rule.leaf_count - 1}")
    cases = {c["id"]: _case(c) for c in doc.get("cases", [])}
    for case in cases.values():
        for name, trace in case.traces.items() if isinstance(case, CaseRun) else ():
            if name in rules and len(trace.leaves) != rules[name].leaf_count:
                raise ValueError(
                    f"case {case.id!r}: {len(trace.leaves)} leaves for {name!r}, expected "
                    f"{rules[name].leaf_count}"
                )
    return EngineResult(versions, load, rules, macros, lists, cases)


def _file_load(r: dict) -> FileLoad:
    return FileLoad(
        name=r.get("name", ""),
        successful=bool(r["successful"]),
        errors=tuple(_message(m) for m in r.get("errors", [])),
        warnings=tuple(_message(m) for m in r.get("warnings", [])),
    )


def _message(m: dict) -> LoadMessage:
    context = m.get("context", {})
    locations = context.get("locations", [])
    # Falco nests locations from the file down to the condition expression; the innermost ones name
    # an in-memory string, so take the file and item from the deepest locations that have them.
    in_file = [loc for loc in locations if not loc.get("position", {}).get("name", "").startswith('"')]
    position = in_file[-1].get("position", {}) if in_file else {}
    named = [loc for loc in locations if loc.get("item_name")]
    item = named[-1] if named else (locations[-1] if locations else {})
    line = position.get("line")
    return LoadMessage(
        code=m.get("code", ""),
        description=m.get("codedesc", ""),
        message=m.get("message", ""),
        item_type=item.get("item_type", ""),
        item_name=item.get("item_name", ""),
        file=position.get("name", ""),
        line=None if line is None else line + 1,
        snippet=context.get("snippet", ""),
    )


def _rule(r: dict, described: dict | None) -> Rule:
    info = (described or {}).get("info", {})
    details = (described or {}).get("details", {})
    return Rule(
        name=r["name"],
        source=r["source"],
        enabled=bool(r["enabled"]),
        priority=str(r["priority"]).upper(),
        evttypes=tuple(r["evttypes"]),
        raw=None
        if r.get("condition_raw_ast") is None
        else cond.parse(r["condition_raw_ast"], f"{r['name']}.condition_raw_ast"),
        compiled=cond.parse(r["condition_ast"], f"{r['name']}.condition_ast"),
        leaf_count=int(r["leaf_count"]),
        description=_oneline(info.get("description", "")),
        condition=_oneline(info.get("condition", "")),
        output=details.get("output_compiled") or info.get("output", ""),
        tags=tuple(info.get("tags", [])),
        macros=tuple(details.get("macros", [])),
        lists=tuple(details.get("lists", [])),
        condition_fields=tuple(details.get("condition_fields", [])),
        output_fields=tuple(details.get("output_fields", [])),
        exception_names=tuple(details.get("exception_names", [])),
        exception_fields=tuple(details.get("exception_fields", [])),
    )


def _case(c: dict) -> CaseResult:
    if c.get("error") is not None:
        return CaseError(c["id"], str(c["error"]), tuple(c.get("unknown_fields", [])))
    return CaseRun(
        id=c["id"],
        alerts=tuple(
            Alert(a["name"], str(a.get("priority", "")).upper(), a.get("output", ""))
            for a in c.get("matched_rules", [])
        ),
        traces={
            name: Trace(bool(t["result"]), tuple(bool(x) for x in t["leaves"]), tuple(t["missing_fields"]))
            for name, t in c.get("traces", {}).items()
        },
    )


def _oneline(text: str) -> str:
    return " ".join(text.split())
