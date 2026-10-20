"""Hand-built engine-protocol JSON for tests. `ast_json` turns condition text into contract AST JSON."""

from __future__ import annotations

import copy
import re

_OPS = (
    "exists",
    "==",
    "=",
    "!=",
    "<=",
    "<",
    ">=",
    ">",
    "in",
    "intersects",
    "pmatch",
    "contains",
    "icontains",
    "bcontains",
    "startswith",
    "bstartswith",
    "endswith",
    "glob",
    "iglob",
    "regex",
)
_TOKEN = re.compile(r'\s*(\(|\)|,|"(?:[^"\\]|\\.)*"|[^\s(),"]+)')


def _tokens(text: str) -> list[str]:
    out, pos = [], 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise ValueError(f"cannot tokenize at {text[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def _value(tok: str) -> str:
    if tok.startswith('"'):
        return tok[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return tok


class _Parser:
    def __init__(self, text: str):
        self.toks = _tokens(text)
        self.i = 0

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def expr(self) -> dict:
        node = self.conj()
        children = [node]
        while self.peek() == "or":
            self.take()
            children.append(self.conj())
        return node if len(children) == 1 else {"type": "or", "children": children}

    def conj(self) -> dict:
        children = [self.neg()]
        while self.peek() == "and":
            self.take()
            children.append(self.neg())
        return children[0] if len(children) == 1 else {"type": "and", "children": children}

    def neg(self) -> dict:
        if self.peek() == "not":
            self.take()
            return {"type": "not", "child": self.neg()}
        return self.atom()

    def atom(self) -> dict:
        tok = self.take()
        if tok == "(":
            node = self.expr()
            assert self.take() == ")"
            return node
        if "." not in tok:
            return {"type": "identifier", "name": tok}
        m = re.fullmatch(r"([\w.]+)(?:\[(.*)\])?", tok)
        lhs = {"type": "field", "field": m.group(1), "arg": m.group(2)}
        op = self.take()
        assert op in _OPS, op
        if self.peek() in ("anyof", "allof", "oneof"):
            op = f"{op} {self.take()}"
        if op == "exists":
            return {"type": "check", "op": op, "lhs": lhs}
        if self.peek() == "(":
            self.take()
            values = []
            while self.peek() != ")":
                tok = self.take()
                if tok != ",":
                    values.append(_value(tok))
            self.take()
            rhs = {"type": "list", "values": values}
        else:
            rhs = {"type": "value", "value": _value(self.take())}
        return {"type": "check", "op": op, "lhs": lhs, "rhs": rhs}


def ast_json(text: str, ids: bool = False) -> dict:
    node = _Parser(text).expr()
    if ids:
        counter = iter(range(10_000))
        _number(node, counter)
    return node


def _number(node: dict, counter) -> None:
    if node["type"] == "check":
        node["id"] = next(counter)
    for child in node.get("children", []):
        _number(child, counter)
    if "child" in node:
        _number(node["child"], counter)


def leaf_count(compiled: dict) -> int:
    n = 1 if compiled["type"] == "check" else 0
    return (
        n
        + sum(leaf_count(c) for c in compiled.get("children", []))
        + (leaf_count(compiled["child"]) if "child" in compiled else 0)
    )


def rule_entry(
    name: str, raw: str, compiled: str, *, evttypes=("execve", "execveat"), enabled=True, priority="NOTICE"
) -> dict:
    compiled_json = ast_json(compiled, ids=True)
    return {
        "name": name,
        "source": "syscall",
        "enabled": enabled,
        "priority": priority,
        "evttypes": list(evttypes),
        "condition_raw_ast": ast_json(raw),
        "condition_ast": compiled_json,
        "leaf_count": leaf_count(compiled_json),
    }


def describe_rule(
    name: str,
    condition: str,
    *,
    desc="",
    output="",
    priority="Notice",
    macros=(),
    lists=(),
    condition_fields=(),
    output_fields=(),
    exception_names=(),
    exception_fields=(),
    enabled=True,
    tags=(),
) -> dict:
    return {
        "info": {
            "name": name,
            "condition": condition,
            "priority": priority,
            "output": output,
            "description": desc,
            "enabled": enabled,
            "source": "syscall",
            "tags": list(tags),
        },
        "details": {
            "macros": list(macros),
            "lists": list(lists),
            "condition_operators": [],
            "condition_fields": list(condition_fields),
            "output_fields": list(output_fields),
            "exception_fields": list(exception_fields),
            "exception_names": list(exception_names),
            "exception_operators": [],
            "events": [],
            "condition_compiled": "",
            "output_compiled": output,
            "plugins": [],
        },
    }


def describe_macro(name: str, condition: str, *, used=True, fields=(), lists=()) -> dict:
    return {
        "info": {"name": name, "condition": condition},
        "details": {
            "used": used,
            "macros": [],
            "lists": list(lists),
            "condition_operators": [],
            "condition_fields": list(fields),
            "events": [],
            "condition_compiled": "",
            "plugins": [],
        },
    }


def describe_list(name: str, items, *, used=True) -> dict:
    return {
        "info": {"name": name, "items": list(items)},
        "details": {"used": used, "lists": [], "items_compiled": list(items), "plugins": []},
    }


def load_ok(files=("/etc/falco/falco_rules.yaml",), warnings=()) -> dict:
    results = [{"name": f, "successful": True, "errors": [], "warnings": []} for f in files]
    if warnings:
        results[-1]["warnings"] = list(warnings)
    return {"successful": True, "results": results}


def warning(code: str, item_name: str, message="", item_type="macro", codedesc="") -> dict:
    return {
        "context": {
            "locations": [
                {
                    "item_type": item_type,
                    "item_name": item_name,
                    "position": {"name": "/rules.yaml", "line": 3, "column": 1, "offset": 10},
                }
            ],
            "snippet": "",
        },
        "code": code,
        "codedesc": codedesc or code,
        "message": message,
    }


def result(rules=(), describe_rules=(), macros=(), lists=(), cases=(), load=None) -> dict:
    return {
        "versions": {
            "falco": "0.45.1",
            "engine": "0.65.0",
            "libs": "0.26.1",
            "plugins": {"container": "0.7.5"},
        },
        "load": load or load_ok(),
        "plugin_requirements": {"ok": True, "error": ""},
        "describe": {
            "required_engine_version": "0.65.0",
            "required_plugin_versions": [],
            "rules": list(describe_rules),
            "macros": list(macros),
            "lists": list(lists),
        },
        "rules": list(rules),
        "cases": list(cases),
    }


def case_run(case_id: str, alerts=(), traces=None) -> dict:
    return {
        "id": case_id,
        "error": None,
        "unknown_fields": [],
        "matched_rules": [dict(a) for a in alerts],
        "traces": copy.deepcopy(traces or {}),
    }


def trace(result: bool, leaves, missing=()) -> dict:
    return {"result": result, "leaves": list(leaves), "missing_fields": list(missing)}


FAKE_ENGINE = """#!{python}
import json, pathlib, sys
here = pathlib.Path({state!r})
job = json.loads(pathlib.Path(sys.argv[sys.argv.index("--job") + 1]).read_text())
n = len(list(here.glob("job-*.json")))
(here / f"job-{{n}}.json").write_text(json.dumps(job))
for entry in json.loads((here / "responses.json").read_text()):
    if entry["rules_files"] in (None, job["rules_files"]):
        if "exit" in entry:
            sys.stdout.write(entry.get("stdout", ""))
            sys.stderr.write(entry.get("stderr", ""))
            sys.exit(entry["exit"])
        out = dict(entry["result"])
        by_id = out.pop("cases_by_id", {{}})
        out["cases"] = [by_id[c["id"]] for c in job["cases"] if c["id"] in by_id]
        print(json.dumps(out))
        sys.exit(0)
sys.exit("fake engine: no response for " + repr(job["rules_files"]))
"""


def install_fake_engine(bin_dir, state_dir, responses, name="falco-test-engine"):
    """A stand-in engine on PATH. Each response is {"rules_files": [...] | None, "result": {...}}
    with cases given as "cases_by_id", or {"exit": n, "stdout": ...}. Jobs land in state_dir."""
    import json
    import os
    import sys

    bin_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "responses.json").write_text(json.dumps(list(responses)))
    script = bin_dir / name
    script.write_text(FAKE_ENGINE.format(python=sys.executable, state=str(state_dir)))
    os.chmod(script, 0o755)
    return script


def received_jobs(state_dir):
    import json

    return [json.loads(p.read_text()) for p in sorted(state_dir.glob("job-*.json"))]
