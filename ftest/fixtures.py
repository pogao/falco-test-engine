"""Fields a test case implies but rarely spells out, derived from the ones it does.

DERIVATIONS is the single place these rules live. Each derivation reads the event
built so far and proposes values; a proposal never replaces a value already present.
"""

from __future__ import annotations

import posixpath
from collections.abc import Callable, Mapping

type Event = Mapping[str, tuple[str, ...]]
type Derivation = Callable[[Event], dict[str, tuple[str, ...]]]


def _lineage(ancestors: str, parent: str, own: str) -> Derivation:
    """`proc.aname` lists ancestors nearest first; `proc.aname[0]` is the process itself."""

    def derive(event: Event) -> dict[str, tuple[str, ...]]:
        out: dict[str, tuple[str, ...]] = {}
        chain = event.get(ancestors) or event.get(parent, ())
        if chain:
            out[ancestors] = chain
            out[parent] = chain[:1]
            out.update({f"{ancestors}[{i}]": (v,) for i, v in enumerate(chain, 1)})
        if own in event:
            out[f"{ancestors}[0]"] = event[own]
        return out

    return derive


def _union(target: str, *sources: str) -> Derivation:
    def derive(event: Event) -> dict[str, tuple[str, ...]]:
        values = tuple(v for s in sources for v in event.get(s, ()))
        return {target: values} if values else {}

    return derive


def _path_parts(event: Event) -> dict[str, tuple[str, ...]]:
    paths = tuple(p for p in event.get("fd.name", ()) if p.startswith("/"))
    if not paths:
        return {}
    return {
        "fd.directory": tuple(posixpath.dirname(p) for p in paths),
        "fd.filename": tuple(posixpath.basename(p) for p in paths),
    }


DERIVATIONS: tuple[Derivation, ...] = (
    _lineage("proc.aname", "proc.pname", "proc.name"),
    _lineage("proc.apid", "proc.ppid", "proc.pid"),
    _lineage("proc.aexe", "proc.pexe", "proc.exe"),
    _lineage("proc.aexepath", "proc.pexepath", "proc.exepath"),
    _lineage("proc.acmdline", "proc.pcmdline", "proc.cmdline"),
    _union("fd.ip", "fd.cip", "fd.sip"),
    _union("fd.port", "fd.cport", "fd.sport"),
    _union("fd.proto", "fd.cproto", "fd.sproto"),
    _union("fd.net", "fd.ip"),
    _path_parts,
)


def derive(explicit: Event) -> dict[str, tuple[str, ...]]:
    event = dict(explicit)
    for derivation in DERIVATIONS:
        for field, values in derivation(event).items():
            event.setdefault(field, values)
    return event
