"""A small Falco world (stock macros plus the examples/ overrides) that produces contract-shaped
engine results. It compiles and evaluates conditions the way the protocol describes, so canned
results stay consistent with their conditions. It is a test double, not Falco."""

from __future__ import annotations

import copy
import fnmatch
import re

from builders import (
    ast_json,
    describe_list,
    describe_macro,
    describe_rule,
    leaf_count,
    load_ok,
    result,
)

STOCK_FILE = "/etc/falco/falco_rules.yaml"
CUSTOM_FILE = "rules/custom_rules.yaml"

SHELL = "Terminal shell in container"
PKG = "Package manager run in container"
META = "Cloud metadata access from container"
SENSITIVE = "Read sensitive file untrusted"

STOCK_MACROS = {
    "never_true": "(evt.num = 0)",
    "spawned_process": "(evt.type in (execve, execveat))",
    "container": "(container.id != host)",
    "shell_procs": "(proc.name in (shell_binaries))",
    "container_entrypoint": (
        "(not proc.pname exists or proc.pname in (runc:[0:PARENT], runc:[1:CHILD], runc, docker-runc, "
        "exe, docker-runc-cur, containerd-shim, systemd, crio, conmon))"
    ),
    "user_expected_terminal_shell_in_container_conditions": "(never_true)",
    "open_read": "(evt.type in (open, openat))",
}
CUSTOM_MACROS = {
    "user_expected_terminal_shell_in_container_conditions": (
        "(container.image.repository = ghcr.io/acme/ci-runner or k8s.ns.name = break-glass)"
    ),
    "cloud_metadata_endpoint": "(fd.sip = 169.254.169.254 or fd.sip = 169.254.170.2)",
}
STOCK_LISTS = {"shell_binaries": ["ash", "bash", "csh", "ksh", "sh", "tcsh", "zsh", "dash"]}
CUSTOM_LISTS = {
    "package_managers": ["apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "apk", "pip", "pip3"],
    "metadata_allowed_images": [
        "ghcr.io/acme/node-agent",
        "public.ecr.aws/eks/aws-node",
        "ghcr.io/acme/node-agent",
    ],
}

STOCK_RULES = {
    SHELL: dict(
        condition=(
            "spawned_process and container and shell_procs and proc.tty != 0 and container_entrypoint "
            "and not user_expected_terminal_shell_in_container_conditions"
        ),
        desc="A shell was used as the entrypoint/exec point into a container with an attached terminal.",
        output=(
            "A shell was spawned in a container with an attached terminal | user=%user.name "
            "process=%proc.name parent=%proc.pname command=%proc.cmdline terminal=%proc.tty "
            "image=%container.image.repository ns=%k8s.ns.name"
        ),
        priority="NOTICE",
        evttypes=["execve", "execveat"],
    ),
    SENSITIVE: dict(
        condition="open_read and fd.name startswith /etc/shadow",
        desc="Read a sensitive file.",
        output="Sensitive file opened (file=%fd.name process=%proc.name)",
        priority="WARNING",
        evttypes=["open", "openat"],
    ),
}
CUSTOM_RULES = {
    PKG: dict(
        condition=(
            "spawned_process and proc.aname in (sh, bash) and container and proc.name in (package_managers) "
            "and not container.image.repository = ghcr.io/acme/ci-runner"
        ),
        desc=(
            "A package manager ran inside a container. Containers are immutable, so installing software "
            "at runtime means drift or an intruder."
        ),
        output=(
            "Package manager in container (proc=%proc.name cmdline=%proc.cmdline parent=%proc.pname "
            "image=%container.image.repository ns=%k8s.ns.name pod=%k8s.pod.name)"
        ),
        priority="WARNING",
        evttypes=["execve", "execveat"],
    ),
    META: dict(
        condition=(
            "evt.type = connect and container and cloud_metadata_endpoint and not proc.exepath = "
            "/usr/bin/aws-node and not container.image.repository in (metadata_allowed_images)"
        ),
        desc="A containerized process connected to the cloud instance metadata service.",
        output=(
            "Metadata service contacted from container (proc=%proc.name cmdline=%proc.cmdline "
            "dest=%fd.sip:%fd.sport image=%container.image.repository ns=%k8s.ns.name pod=%k8s.pod.name)"
        ),
        priority="WARNING",
        evttypes=["connect"],
    ),
}

ANY_OF = {
    "proc.aname",
    "proc.apid",
    "proc.aexe",
    "proc.aexepath",
    "proc.acmdline",
    "fd.ip",
    "fd.port",
    "fd.net",
    "fd.proto",
}
_KNOWN_PREFIX = re.compile(r"^(evt|proc|thread|fd|fs|user|group|container|k8s)\.")
_OUTPUT_FIELD = re.compile(r"%(\()?([A-Za-z_][\w.]*(?:\[[^\]]*\])?)(?(1)\))")


class World:
    def __init__(self, macros, lists, rules, files):
        self.macros, self.lists, self.rules, self.files = macros, lists, rules, files

    @classmethod
    def stock(cls):
        return cls(dict(STOCK_MACROS), dict(STOCK_LISTS), copy.deepcopy(STOCK_RULES), [STOCK_FILE])

    @classmethod
    def full(cls, custom_file=CUSTOM_FILE):
        return cls(
            {**STOCK_MACROS, **CUSTOM_MACROS},
            {**STOCK_LISTS, **CUSTOM_LISTS},
            {**copy.deepcopy(STOCK_RULES), **copy.deepcopy(CUSTOM_RULES)},
            [STOCK_FILE, custom_file],
        )

    def spec(self):
        return {"macros": self.macros, "lists": self.lists, "rules": self.rules, "files": self.files}

    def compile(self, name):
        spec = self.rules[name]
        node = self._expand(ast_json(spec["condition"]))
        for exc in spec.get("exceptions", []):
            node = {"type": "and", "children": [node, {"type": "not", "child": ast_json(exc)}]}
        counter = iter(range(10_000))
        _number(node, counter)
        return node

    def _expand(self, node):
        node = copy.deepcopy(node)
        if node["type"] == "identifier":
            return self._expand(ast_json(self.macros[node["name"]]))
        if node["type"] == "check" and node.get("rhs", {}).get("type") == "list":
            values = []
            for v in node["rhs"]["values"]:
                values.extend(self.lists.get(v, [v]))
            node["rhs"]["values"] = values
        for key in ("children",):
            if key in node:
                node[key] = [self._expand(c) for c in node[key]]
        if "child" in node:
            node["child"] = self._expand(node["child"])
        return node

    def result(self, cases=(), load=None):
        rules, described = [], []
        for name, spec in self.rules.items():
            compiled = self.compile(name)
            raw = ast_json(spec["condition"])
            rules.append(
                {
                    "name": name,
                    "source": "syscall",
                    "enabled": spec.get("enabled", True),
                    "priority": spec["priority"],
                    "evttypes": spec["evttypes"],
                    "condition_raw_ast": raw,
                    "condition_ast": compiled,
                    "leaf_count": leaf_count(compiled),
                }
            )
            described.append(
                describe_rule(
                    name,
                    spec["condition"],
                    desc=spec["desc"],
                    output=spec["output"],
                    priority=spec["priority"].title(),
                    macros=_identifiers(raw),
                    lists=[v for v in _list_values(raw) if v in self.lists],
                    condition_fields=sorted(_fields(compiled)),
                    output_fields=[m.group(2) for m in _OUTPUT_FIELD.finditer(spec["output"])],
                    exception_names=spec.get("exception_names", []),
                    exception_fields=sorted(
                        {f for e in spec.get("exceptions", []) for f in _fields(ast_json(e))}
                    ),
                    enabled=spec.get("enabled", True),
                )
            )
        macros = [
            describe_macro(m, c, fields=sorted(_fields(self._expand(ast_json(c)))))
            for m, c in self.macros.items()
        ]
        lists = [describe_list(n, items) for n, items in self.lists.items()]
        out = result(
            rules=rules,
            describe_rules=described,
            macros=macros,
            lists=lists,
            load=load or load_ok(self.files),
        )
        out["cases"] = [self.run_case(c) for c in cases]
        return out

    def run_case(self, job_case):
        fields = job_case["fields"]
        unknown = [f for f in fields if not _KNOWN_PREFIX.match(f)]
        if unknown:
            return {"id": job_case["id"], "error": "unknown fields", "unknown_fields": unknown}
        alerts, traces = [], {}
        for name, spec in self.rules.items():
            compiled = self.compile(name)
            leaves, missing = [], set()
            _leaves(compiled, fields, leaves, missing)
            fired = _eval(compiled, leaves)
            if fired and spec.get("enabled", True):
                alerts.append(
                    {
                        "name": name,
                        "priority": spec["priority"].title(),
                        "output": _format(spec["output"], fields),
                    }
                )
            if name in job_case.get("trace_rules", []):
                traces[name] = {"result": fired, "leaves": leaves, "missing_fields": sorted(missing)}
        return {
            "id": job_case["id"],
            "error": None,
            "unknown_fields": [],
            "matched_rules": alerts,
            "traces": traces,
        }


def _number(node, counter):
    if node["type"] == "check":
        node["id"] = next(counter)
    for c in node.get("children", []):
        _number(c, counter)
    if "child" in node:
        _number(node["child"], counter)


def _walk(node):
    yield node
    for c in node.get("children", []):
        yield from _walk(c)
    if "child" in node:
        yield from _walk(node["child"])


def _identifiers(node):
    return list(dict.fromkeys(n["name"] for n in _walk(node) if n["type"] == "identifier"))


def _list_values(node):
    return [
        v
        for n in _walk(node)
        if n["type"] == "check" and n.get("rhs", {}).get("type") == "list"
        for v in n["rhs"]["values"]
    ]


def _key(lhs):
    return lhs["field"] if lhs.get("arg") is None else f"{lhs['field']}[{lhs['arg']}]"


def _fields(node):
    return {_key(n["lhs"]) for n in _walk(node) if n["type"] == "check"}


def _leaves(node, fields, out, missing):
    if node["type"] == "check":
        out.append(_check(node, fields, missing))
    for c in node.get("children", []):
        _leaves(c, fields, out, missing)
    if "child" in node:
        _leaves(node["child"], fields, out, missing)


def _check(node, fields, missing):
    key = _key(node["lhs"])
    op = node["op"]
    if op == "exists":
        return key in fields
    if key not in fields:
        missing.add(key)
        return False
    values = (
        fields[key] if node["lhs"]["field"] in ANY_OF and node["lhs"].get("arg") is None else fields[key][:1]
    )
    rhs = node["rhs"]
    targets = rhs["values"] if rhs["type"] == "list" else [rhs["value"]]
    base = op.split(" ")[0]
    tests = {
        "=": lambda v, t: v == t,
        "==": lambda v, t: v == t,
        "!=": lambda v, t: v != t,
        "in": lambda v, t: v == t,
        "contains": lambda v, t: t in v,
        "icontains": lambda v, t: t.lower() in v.lower(),
        "startswith": lambda v, t: v.startswith(t),
        "endswith": lambda v, t: v.endswith(t),
        "glob": lambda v, t: fnmatch.fnmatchcase(v, t),
        "regex": lambda v, t: re.fullmatch(t, v) is not None,
    }[base]
    return any(any(tests(v, t) for t in targets) for v in values)


def _eval(node, leaves):
    kind = node["type"]
    if kind == "check":
        return leaves[node["id"]]
    if kind == "not":
        return not _eval(node["child"], leaves)
    results = [_eval(c, leaves) for c in node["children"]]
    return all(results) if kind == "and" else any(results)


def _format(template, fields):
    return _OUTPUT_FIELD.sub(lambda m: fields.get(m.group(2), ["<NA>"])[0], template)


def engine_result(world, suites):
    """Typed engine result for the given suites, as ftest would request it."""
    from ftest.engine import JobCase, build_job, parse_result

    job = build_job([], [], [JobCase(c, s.rule) for s in suites for c in s.cases])
    return parse_result(world.result(job["cases"]))


def broken_world():
    world = World.full("broken/custom_rules.yaml")
    world.rules[PKG]["condition"] = (
        "spawned_process and container and proc.name = apt or proc.name = yum "
        "and not container.image.repository = ghcr.io/acme/ci-runner"
    )
    world.macros["user_expected_terminal_shell_in_container_conditions"] = (
        "(container.image.repository startswith ghcr.io/acme or k8s.ns.name = break-glass)"
    )
    return world
