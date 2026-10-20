"""What the custom rules change relative to a baseline rule set."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Literal

from ftest.cond import render
from ftest.engine import Macro, Rule
from ftest.findings import Finding, Severity


@dataclass(frozen=True)
class RuleChange:
    name: str
    kind: Literal["added", "removed", "changed"]
    details: tuple[str, ...] = ()


def diff_rules(base: Mapping[str, Rule], full: Mapping[str, Rule]) -> tuple[RuleChange, ...]:
    changes = []
    for name, rule in full.items():
        before = base.get(name)
        if before is None:
            changes.append(RuleChange(name, "added"))
        elif details := _details(before, rule):
            changes.append(RuleChange(name, "changed", details))
    changes.extend(RuleChange(name, "removed") for name in base if name not in full)
    return tuple(changes)


def changed_macros(base: Mapping[str, Macro], full: Mapping[str, Macro]) -> frozenset[str]:
    """Macros the user's files define or redefine: the ones whose insides are theirs to test."""
    return frozenset(n for n, m in full.items() if n not in base or base[n].condition != m.condition)


def _details(before: Rule, after: Rule) -> tuple[str, ...]:
    details = []
    if before.enabled != after.enabled:
        details.append("enabled" if after.enabled else "disabled")
    if before.priority != after.priority:
        details.append(f"priority {before.priority} -> {after.priority}")
    if render(before.compiled) != render(after.compiled):
        details.append("condition changed")
    if before.output != after.output:
        details.append("output changed")
    if before.evttypes != after.evttypes:
        added = sorted(set(after.evttypes) - set(before.evttypes))
        removed = sorted(set(before.evttypes) - set(after.evttypes))
        parts = [f"+{', '.join(added)}" if added else "", f"-{', '.join(removed)}" if removed else ""]
        details.append("event types " + " ".join(p for p in parts if p))
    return tuple(details)


def untested(changes: tuple[RuleChange, ...], tested: Collection[str]) -> list[Finding]:
    return [
        Finding(
            "FTE011",
            Severity.WARNING,
            c.name,
            "modified stock rule has no tests" if c.kind == "changed" else "new rule has no tests",
            "Add a suite with `rule: " + c.name + "` (`ftest scaffold` writes a skeleton).",
        )
        for c in changes
        if c.kind != "removed" and c.name not in tested
    ]
