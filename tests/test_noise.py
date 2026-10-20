"""The noise check, end to end through `ftest run` against the sample world."""

import json

import yaml
from samples import PKG, SHELL, World
from test_cli import engine, reading_intents_as_the_cases_do, repo, report  # noqa: F401
from test_jev import Stub, answering

from ftest.cli import main
from ftest.corpus import builtin
from ftest.noise import Hit, sample
from ftest.oracle import MAX_TRIAGED

PKG_TERMS = (
    "spawned_process and proc.aname in (sh, bash) and container and proc.name in (package_managers) "
    "and not container.image.repository = ghcr.io/acme/ci-runner"
)
EXECS = sum(1 for e in builtin() if e.event["evt.type"] == ("execve",))


def inverted(world: World) -> World:
    world.rules[PKG]["condition"] = PKG_TERMS.replace("and proc.name in", "and not proc.name in")
    return world


def with_python(world: World) -> World:
    """PKG also fires on python3, so it fires on the two `manage.py migrate` runs in the corpus."""
    world.lists["package_managers"] = [*world.lists["package_managers"], "python3"]
    return world


MIGRATE_1 = "checkout-worker#1 (container shop/checkout-worker) runs python3 manage.py migrate --noinput"
MIGRATE_2 = "checkout-worker#2 (container shop/checkout-worker) runs python3 manage.py migrate --noinput"


def hits_read_by(root, call):
    """A Stub responder: suite and generated events are read the way their cases expect, and each noise
    hit gets `call(intent, event)`, None for unsure. Only corpus events carry `evt.num`."""
    cases = reading_intents_as_the_cases_do(root)

    def judge(state):
        found = call(state["intent"], state["event"])
        return (0.5, 0.5) if found is None else (0.9, 0.1) if found else (0.1, 0.1)

    hits = answering(judge)
    return lambda body: hits(body) if "evt.num" in body["state"].get("event", {}) else cases(body)


def noise_hits(stub):
    return [r["body"]["state"] for r in stub.requests if "evt.num" in r["body"]["state"].get("event", {})]


def use_jev(monkeypatch, stub):
    monkeypatch.setenv("JEV_API_KEY", "sk-test")
    monkeypatch.setenv("JEV_BASE_URL", stub.url)


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
    doc = json.loads((repo / "falco-test-report.json").read_text())
    assert doc["exit_code"] == 1
    noise = next(r for r in doc["rules"] if r["name"] == PKG)["noise"]
    assert set(noise) == {"fired", "total", "budget", "base_fired", "base_total", "examples"}
    assert noise["fired"] > len(noise["examples"]) == len(examples)
    assert all(set(e) == {"label", "fields"} for e in noise["examples"])


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


def test_a_sample_shows_each_event_type_then_spreads_over_the_rest():
    def hits(evt_type, ids):
        return [Hit(str(i), str(i), "", {"evt.type": (evt_type,)}) for i in ids]

    fired = hits("execve", range(10)) + hits("open", [10]) + hits("connect", [11])
    assert [h.id for h in sample(fired, 2)] == ["0", "10"]
    assert [h.id for h in sample(fired, 3)] == ["0", "10", "11"]
    assert [h.id for h in sample(fired, 5)] == ["0", "10", "11", "1", "5"]
    assert [h.id for h in sample(fired, 20)] == ["0", "10", "11", *map(str, range(1, 10))]


def test_jev_reads_each_noise_hit_against_each_intent_and_never_gates(repo, monkeypatch, capsys):  # noqa: F811
    (repo / "tests" / "python_in_container.yaml").write_text(
        yaml.safe_dump(
            {
                "rule": PKG,
                "intent": "Alert when python3 runs a migration in the first checkout-worker replica.",
                "defaults": {
                    "evt.type": "execve",
                    "container.id": "51901fa55c3b",
                    "proc.aname": ["bash", "runc"],
                },
                "cases": [
                    {"name": "python3 from bash", "expect": "match", "event": {"proc.name": "python3"}}
                ],
            }
        )
    )

    def first_replica(intent, event):
        return "python3" in intent and event["container.id"] == "51901fa55c3b"

    stub = Stub(hits_read_by(repo, first_replica))
    try:
        use_jev(monkeypatch, stub)
        engine(repo, with_python(World.full()), World.stock())
        assert main(["run"]) == 0
        read = noise_hits(stub)
        assert len(read) == 2 * 2
        assert {(s["event"]["container.id"], "python3" in s["intent"]) for s in read} == {
            ("51901fa55c3b", True),
            ("51901fa55c3b", False),
            ("aae427f223bf", True),
            ("aae427f223bf", False),
        }
        assert all(s["event"]["evt.type"] == "execve" and "proc.aname[2]" not in s["event"] for s in read)

        md = report(repo)
        assert (
            f"- Noise: 3 rules checked on {len(builtin())} ordinary events; none over budget; "
            "Jev read 2 hits: 1 false positive, 1 intended." in md
        )
        assert (
            f"**Noise.** Fired on 2 of the {EXECS} ordinary events of its event types (2.1%); budget 5%. "
            "Jev read 2 hits: 1 false positive, 1 intended." in md
        )
        suites = ("tests/package_manager_in_container.yaml", "tests/python_in_container.yaml")
        no, yes = "in scope p=0.10, exception p=0.10", "in scope p=0.90, exception p=0.10"
        fp = next(line for line in md.splitlines() if line.startswith(f"- false positive: {MIGRATE_2}: `"))
        assert fp.endswith(f"` ({suites[0]}: {no}; {suites[1]}: {no}).")
        intended = next(line for line in md.splitlines() if line.startswith(f"- intended: {MIGRATE_1}: `"))
        assert intended.endswith(f"` ({suites[0]}: {no}; {suites[1]}: {yes}).")
        assert (
            f"{PKG}: 7/7 cases; noise 2/{EXECS} (2.1%; Jev: 1 false positive, 1 intended)"
            in capsys.readouterr().out
        )

        doc = json.loads((repo / "falco-test-report.json").read_text())
        pkg = next(r for r in doc["rules"] if r["name"] == PKG)
        assert {j["origin"] for r in doc["rules"] for j in r["judgments"]} == {"suite", "generated"}
        assert [(t["event"], t["origin"], t["reading"]) for t in pkg["triage"]] == [
            ("ordinary::helper/checkout-worker#1/0", "ordinary", "intended"),
            ("ordinary::helper/checkout-worker#2/0", "ordinary", "false_positive"),
        ]
        assert pkg["triage"][0]["calls"][1] == {
            "suite": suites[1],
            "jev_says": "match",
            "in_scope": 0.9,
            "exception": 0.1,
            "model": "jev-1.13",
            "request_id": "req-1",
        }
        judged = sum(len(r["judgments"]) for r in doc["rules"])
        assert f"3 rules reviewed and {judged} events judged with model jev-latest (advisory)." in md

        cfg = yaml.safe_load((repo / "falco-test.yaml").read_text())
        cfg["jev"] = {"gate": True}
        (repo / "falco-test.yaml").write_text(yaml.safe_dump(cfg))
        stub.script = hits_read_by(repo, lambda intent, event: False)
        assert main(["run"]) == 0
        md = report(repo)
        assert "Jev read 2 hits: 2 false positives." in md
        assert "Jev gate" not in md
    finally:
        stub.close()


def test_jev_reads_at_most_eight_hits_and_names_a_suite_without_intent(repo, monkeypatch):  # noqa: F811
    suite_path = repo / "tests" / "package_manager_in_container.yaml"
    suite = yaml.safe_load(suite_path.read_text())
    suite["cases"] = [{"name": "any shell child", "expect": "match", "event": {"proc.name": "envsubst"}}]
    suite["max_fire_rate"] = 0.5
    suite_path.write_text(yaml.safe_dump(suite))
    stub = Stub(hits_read_by(repo, lambda intent, event: False))
    try:
        use_jev(monkeypatch, stub)
        engine(repo, inverted(World.full()), World.stock())
        assert main(["run"]) == 0
        fired = json.loads((repo / "falco-test-report.json").read_text())
        fired = next(r for r in fired["rules"] if r["name"] == PKG)["noise"]["fired"]
        assert fired > MAX_TRIAGED
        first = [s["event"]["evt.num"] for s in noise_hits(stub)]
        assert len(first) == len(set(first)) == MAX_TRIAGED
        assert f"Jev read 8 of the {fired} hits: 8 false positives." in report(repo)

        assert main(["run"]) == 0
        assert sorted(s["event"]["evt.num"] for s in noise_hits(stub)[MAX_TRIAGED:]) == sorted(first)

        del suite["intent"]
        suite_path.write_text(yaml.safe_dump(suite))
        sent = len(noise_hits(stub))
        assert main(["run"]) == 0
        assert len(noise_hits(stub)) == sent
        md = report(repo)
        assert (
            "- Jev did not read the hits: `tests/package_manager_in_container.yaml` states no `intent`." in md
        )
        assert "Jev read" not in md
    finally:
        stub.close()
