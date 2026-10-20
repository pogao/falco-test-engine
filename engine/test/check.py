import json
import pathlib
import subprocess
import sys

engine, here = sys.argv[1], pathlib.Path(sys.argv[2])
failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def run(job):
    """Runs a job fixture by name, or a job dict over stdin."""
    args, stdin = (["--job", f"jobs/{job}.json"], None) if isinstance(job, str) else ([], json.dumps(job))
    p = subprocess.run([engine, *args], cwd=here, input=stdin, capture_output=True, text=True)
    return p.returncode, json.loads(p.stdout)


def evaluate(node, leaves):
    t = node["type"]
    if t == "and":
        return all(evaluate(c, leaves) for c in node["children"])
    if t == "or":
        return any(evaluate(c, leaves) for c in node["children"])
    if t == "not":
        return not evaluate(node["child"], leaves)
    if t == "check":
        return leaves[node["id"]]
    raise ValueError(f"unexpected {t} node in a condition")


def check_nodes(node):
    if node["type"] == "check":
        return [node]
    children = node.get("children", []) + ([node["child"]] if "child" in node else [])
    return [n for c in children for n in check_nodes(c)]


code, r = run("stock")
rules = {x["name"]: x for x in r["rules"]}
cases = {c["id"]: c for c in r["cases"]}
shell = "Terminal shell in container"

check(code == 0, "stock job exits 0")
check(r["load"]["successful"] and all(x["successful"] for x in r["load"]["results"]),
      "stock rules and ancestors.yaml load")
check(r["plugin_requirements"] == {"ok": True, "error": ""}, "stock plugin requirements are met")
check({k: r["versions"][k] for k in ("falco", "engine", "libs")}
      == {"falco": "0.45.1", "engine": "0.65.0", "libs": "0.26.1"}, "versions are Falco's")
check("container" in r["versions"]["plugins"], "container plugin version is reported")
check(shell in {x["info"]["name"] for x in r["describe"]["rules"]}, "describe covers the stock rules")

tty = cases["shell with tty"]
matched = {m["name"]: m for m in tty["matched_rules"]}
check(tty["error"] is None and shell in matched, "shell with a tty in a container matches")
output = matched.get(shell, {}).get("output", "")
check(all(s in output for s in ("process=bash", "command=bash -i", "terminal=34816", "user=root")),
      "output shows the case's values")
check("user_uid=<NA>" in output, "output shows <NA> for fields the case omits")
check("proc.pname" in tty["traces"][shell]["missing_fields"],
      "proc.pname, read but not supplied, is reported missing")

notty = cases["shell without tty"]
check(shell not in {m["name"] for m in notty["matched_rules"]}, "shell without a tty does not match")
check(notty["traces"][shell]["result"] is False, "trace result is false without a tty")
flipped = [i for i, (a, b) in enumerate(zip(tty["traces"][shell]["leaves"], notty["traces"][shell]["leaves"]))
           if a != b]
leaf_fields = [n["lhs"].get("field") for n in check_nodes(rules[shell]["condition_ast"])]
check(len(flipped) == 1 and leaf_fields[flipped[0]] == "proc.tty",
      f"exactly the proc.tty leaf flipped (flipped={flipped})")

anc = cases["bash among ancestors"]
names = {m["name"] for m in anc["matched_rules"]}
check("Ancestor is bash" in names, "proc.aname [sshd, bash] matches proc.aname = bash")
check("Ancestor is zsh" not in names, "proc.aname [sshd, bash] does not match proc.aname = zsh")

typo = cases["misspelled field"]
check(typo["error"] is not None and typo["unknown_fields"] == ["proc.nmae"],
      "proc.nmae is an error listing the unknown field")
check(typo["matched_rules"] == [] and typo["traces"] == {}, "an erroring case has no other results")

every = json.loads((here / "jobs/stock.json").read_text())
every["describe"] = False
every["cases"] = [dict(c, trace_rules=list(rules)) for c in every["cases"] if c["id"] != "misspelled field"]
code, r = run(every)
check(code == 0 and len(r["cases"]) == len(every["cases"]), "tracing every rule over stdin runs")
for c in r["cases"]:
    leaf_counts = [n for n, t in c["traces"].items()
                   if not len(t["leaves"]) == rules[n]["leaf_count"] == len(check_nodes(rules[n]["condition_ast"]))]
    check(not leaf_counts, f"{c['id']}: one leaf per check in all {len(c['traces'])} rules {leaf_counts}")
    wrong = [n for n, t in c["traces"].items() if evaluate(rules[n]["condition_ast"], t["leaves"]) != t["result"]]
    check(not wrong, f"{c['id']}: leaves recompute result in all {len(c['traces'])} rules {wrong}")

for job, err in (("yaml_error", "LOAD_ERR_YAML_PARSE"), ("condition_error", "LOAD_ERR_COMPILE_CONDITION")):
    code, r = run(job)
    errors = r["load"]["results"][0]["errors"]
    check(code == 0 and r["load"]["successful"] is False, f"{job}: exits 0 with load.successful=false")
    check(errors[0]["code"] == err and errors[0]["message"] != "", f"{job}: carries Falco's {err} error")

code, r = run("missing_plugin")
check(code == 2 and "fatal" in r, "a plugin that fails to load exits 2 with fatal")

print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)
