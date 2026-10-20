from ftest.fixtures import derive


def test_ancestor_list_gives_indexed_ancestors_and_parent():
    event = derive({"proc.name": ("apt",), "proc.aname": ("bash", "containerd-shim", "systemd")})
    assert event["proc.pname"] == ("bash",)
    assert event["proc.aname[0]"] == ("apt",)
    assert event["proc.aname[1]"] == ("bash",)
    assert event["proc.aname[3]"] == ("systemd",)


def test_parent_alone_gives_one_level_of_ancestry():
    event = derive({"proc.pname": ("bash",)})
    assert event["proc.aname"] == ("bash",)
    assert event["proc.aname[1]"] == ("bash",)


def test_every_lineage_family_derives():
    event = derive(
        {
            "proc.ppid": ("1",),
            "proc.pexe": ("/bin/sh",),
            "proc.pexepath": ("/bin/sh",),
            "proc.acmdline": ("bash -i",),
            "proc.pid": ("42",),
        }
    )
    assert event["proc.apid"] == ("1",)
    assert event["proc.apid[0]"] == ("42",)
    assert event["proc.aexe[1]"] == ("/bin/sh",)
    assert event["proc.aexepath"] == ("/bin/sh",)
    assert event["proc.pcmdline"] == ("bash -i",)


def test_explicit_values_are_never_overridden():
    event = derive({"proc.aname": ("bash", "init"), "proc.pname": ("zsh",), "proc.aname[2]": ("x",)})
    assert event["proc.pname"] == ("zsh",)
    assert event["proc.aname[2]"] == ("x",)
    assert event["proc.aname[1]"] == ("bash",)


def test_fd_client_and_server_fields_union():
    event = derive(
        {"fd.cip": ("10.0.0.1",), "fd.sip": ("169.254.169.254",), "fd.sport": ("80",), "fd.cproto": ("tcp",)}
    )
    assert event["fd.ip"] == ("10.0.0.1", "169.254.169.254")
    assert event["fd.net"] == event["fd.ip"]
    assert event["fd.port"] == ("80",)
    assert event["fd.proto"] == ("tcp",)


def test_fd_name_splits_only_absolute_paths():
    assert derive({"fd.name": ("/etc/shadow",)})["fd.directory"] == ("/etc",)
    assert derive({"fd.name": ("/etc/shadow",)})["fd.filename"] == ("shadow",)
    assert "fd.directory" not in derive({"fd.name": ("10.0.0.1:80->1.2.3.4:443",)})


def test_no_inputs_derive_nothing():
    assert derive({"evt.type": ("execve",)}) == {"evt.type": ("execve",)}
