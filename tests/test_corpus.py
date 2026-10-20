from pathlib import Path

import pytest
import yaml

from ftest.corpus import builtin, load_corpus, values_by_field
from ftest.suite import SuiteError

COMMON = ("evt.type", "proc.name", "proc.exepath", "proc.cmdline", "user.name", "user.uid", "container.id")
IN_CONTAINER = ("container.image.repository", "k8s.ns.name", "k8s.pod.name")
BY_TYPE = {
    "openat": ("evt.is_open_read", "evt.is_open_write", "fd.typechar", "fd.name", "fd.num"),
    "connect": ("fd.typechar", "fd.sip", "fd.sport", "fd.cip", "fd.l4proto"),
    "execve": (),
}


def test_the_builtin_corpus_is_the_same_on_every_call():
    first, second = builtin(), builtin()
    assert [(e.id, dict(e.event)) for e in first] == [(e.id, dict(e.event)) for e in second]
    assert len({e.id for e in first}) == len(first)


def test_the_corpus_covers_hosts_containers_and_the_common_event_types():
    events = builtin()
    assert 200 <= len(events) <= 600
    contexts = {"host" if e.event["container.id"] == ("host",) else "container" for e in events}
    assert contexts == {"host", "container"}
    assert {e.event["evt.type"][0] for e in events} == set(BY_TYPE)


def test_every_event_sets_the_fields_rules_read_the_way_libsinsp_does():
    for e in builtin():
        kind = e.event["evt.type"][0]
        expected = COMMON + BY_TYPE[kind] + ((IN_CONTAINER) if e.event["container.id"] != ("host",) else ())
        assert [f for f in expected if f not in e.event] == [], e.id
        assert e.event["proc.tty"] == ("0",), e.id
        if kind == "openat":
            assert e.event["fd.typechar"] == ("f",)
            assert "true" in (e.event["evt.is_open_read"][0], e.event["evt.is_open_write"][0]), e.id


def test_events_go_through_the_fixture_derivations():
    child = next(e for e in builtin() if e.event.get("proc.aname", ())[:1] == ("sh",))
    assert child.event["proc.pname"] == ("sh",)
    assert child.event["proc.aname[1]"] == ("sh",)
    opened = next(e for e in builtin() if e.event["evt.type"] == ("openat",))
    assert opened.event["fd.directory"] == (str(Path(opened.event["fd.name"][0]).parent),)


def test_container_shells_come_from_scripts_and_probes_not_terminals():
    shells = [e for e in builtin() if e.event["proc.name"][0] in ("sh", "bash")]
    assert shells, "the corpus should start shells the way entrypoints and exec probes do"
    for e in shells:
        assert e.event["proc.cmdline"][0].split(" ")[1] == "-c", e.id
        assert e.event["proc.tty"] == ("0",), e.id


def test_user_corpus_files_are_lists_of_suite_events(tmp_path):
    path = tmp_path / "ordinary.yaml"
    path.write_text(
        yaml.safe_dump(
            [
                {"evt.type": "execve", "proc.name": "apt-get", "proc.aname": ["sh", "runc"]},
                {"evt.type": "openat", "fd.name": "/etc/app.yaml", "fd.num": 3},
            ]
        )
    )
    events = load_corpus([path], tmp_path)
    assert [e.id for e in events] == ["ordinary::ordinary.yaml#1", "ordinary::ordinary.yaml#2"]
    assert events[0].event["proc.pname"] == ("sh",)
    assert events[1].event["fd.num"] == ("3",)


@pytest.mark.parametrize(
    ("doc", "error"),
    [
        ({"evt.type": "execve"}, "non-empty YAML list"),
        ([{"proc.name": "bash"}], "needs exactly one evt.type"),
        ([{"evt.type": "execve", "proc.name": {"nested": 1}}], "scalars"),
    ],
)
def test_bad_corpus_files_are_rejected(tmp_path, doc, error):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(doc))
    with pytest.raises(SuiteError, match=error):
        load_corpus([path], tmp_path)


def test_field_values_are_the_distinct_values_the_corpus_uses():
    events = builtin()
    pool = values_by_field(events)
    assert sorted(pool["evt.type"]) == ["connect", "execve", "openat"]
    names = pool["proc.name"]
    assert len(names) == len(set(names)) and set(names) == {e.event["proc.name"][0] for e in events}
