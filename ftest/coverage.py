"""Which parts of a rule's condition its test cases actually exercised."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ftest.cond import Node, checks, evaluate
from ftest.engine import Rule, Trace
from ftest.findings import Finding, Severity
from ftest.shape import Shape


@dataclass(frozen=True)
class Gap:
    text: str
    never: str


@dataclass(frozen=True)
class Coverage:
    cases: int
    both: int
    total: int
    leaves: tuple[Gap, ...]
    parts: tuple[Gap, ...]

    @property
    def summary(self) -> str:
        if not self.cases:
            return "no test case traced this rule"
        return f"{self.both} of {self.total} conditions seen both true and false across {self.cases} cases"


def consistency(rule: Rule, traces: Sequence[tuple[str, Trace]]) -> list[Finding]:
    findings = []
    for case_id, trace in traces:
        recomputed = evaluate(rule.compiled, trace.leaves)
        if recomputed != trace.result:
            findings.append(
                Finding(
                    "FTE900",
                    Severity.ERROR,
                    rule.name,
                    f"internal error in case `{case_id}`: the engine reported result={trace.result} "
                    f"but its leaf values give {recomputed}",
                )
            )
    return findings


def coverage(shape: Shape, compiled: Node, traces: Sequence[Trace]) -> Coverage:
    leaves = list(checks(compiled))
    seen = {leaf.id: set() for leaf in leaves}
    for trace in traces:
        for leaf in leaves:
            seen[leaf.id].add(trace.leaves[leaf.id])

    leaf_gaps: dict[tuple[str, str], Gap] = {}
    if traces:
        for leaf in leaves:
            if len(seen[leaf.id]) < 2:
                gap = Gap(shape.display(leaf), "never true" if True not in seen[leaf.id] else "never false")
                leaf_gaps.setdefault((gap.text, gap.never), gap)

    parts: dict[tuple[str, str], Gap] = {}
    if traces:
        for use in shape.macros:
            values = {evaluate(use.node, t.leaves) for t in traces}
            if len(values) < 2:
                gap = Gap(f"macro `{use.name}`", "never true" if True not in values else "never false")
                parts.setdefault((gap.text, gap.never), gap)
        for clause in shape.exceptions:
            values = {evaluate(clause.node, t.leaves) for t in traces}
            if len(values) < 2:
                never = "never triggered" if True not in values else "triggered on every case"
                parts.setdefault((clause.label, never), Gap(clause.label, never))

    both = sum(1 for leaf in leaves if len(seen[leaf.id]) == 2)
    return Coverage(len(traces), both, len(leaves), tuple(leaf_gaps.values()), tuple(parts.values()))
