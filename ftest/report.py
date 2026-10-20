"""The run model and its renderings: Markdown report, JSON dump, console summary, exit code."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path

from ftest.coverage import Coverage
from ftest.diff import RuleChange
from ftest.engine import Load, Versions
from ftest.findings import Finding, Severity
from ftest.jev import JevFailure, JevReview, Verdict
from ftest.lint import Work
from ftest.outcomes import CaseOutcome
from ftest.startup import StartupFailed, StartupPassed, StartupResult, StartupSkipped

PERFORMANCE_CODES = frozenset({"FTE001", "FTE002", "FTE003", "FTE004", "FTE005", "FTE006", "FTE007"})


@dataclass(frozen=True)
class RuleSection:
    name: str
    priority: str
    enabled: bool
    loaded: bool
    change: RuleChange | None
    what_it_does: tuple[str, ...]
    outcomes: tuple[CaseOutcome, ...]
    coverage: Coverage | None
    findings: tuple[Finding, ...]
    work: Work | None
    jev: JevReview | JevFailure | None = None

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if not o.passed)

    @property
    def needs_optimizing(self) -> str:
        perf = [f for f in self.findings if f.code in PERFORMANCE_CODES]
        serious = sorted({f.code for f in perf if f.severity is not Severity.INFO})
        if serious:
            return f"Needs optimizing: yes ({', '.join(serious)})"
        return (
            f"Needs optimizing: minor ({_plural(len(perf), 'info finding')})"
            if perf
            else "Needs optimizing: no"
        )


@dataclass(frozen=True)
class RunReport:
    versions: Versions | None
    startup: StartupResult
    load: Load | None
    engine_error: str | None
    base: str
    changes: tuple[RuleChange, ...]
    sections: tuple[RuleSection, ...]
    findings: tuple[Finding, ...]
    jev: str
    other_rules: int
    strict: bool = False
    jev_gate: bool = False

    @property
    def outcomes(self) -> tuple[CaseOutcome, ...]:
        return tuple(o for s in self.sections for o in s.outcomes)

    @property
    def all_findings(self) -> tuple[Finding, ...]:
        return tuple(f for s in self.sections for f in s.findings) + self.findings


def failures(report: RunReport) -> list[str]:
    reasons = []
    if isinstance(report.startup, StartupFailed):
        reasons.append(f"Falco did not start ({report.startup.reason})")
    if report.engine_error:
        reasons.append(report.engine_error)
    if report.load is not None and not report.load.successful:
        reasons.append("rules failed to load")
    if report.load is not None and report.load.plugin_error:
        reasons.append(f"plugin requirements not met: {report.load.plugin_error}")
    if failed := sum(1 for o in report.outcomes if not o.passed):
        reasons.append(f"{failed} test case{'s' if failed != 1 else ''} failed")
    errors = sum(1 for f in report.all_findings if f.severity is Severity.ERROR)
    if report.strict and errors:
        reasons.append(f"{errors} error finding{'s' if errors != 1 else ''} (--strict)")
    if report.jev_gate:
        jev_findings = sum(
            1
            for s in report.sections
            if isinstance(s.jev, JevReview)
            for n in s.jev.notes
            if n.verdict is Verdict.FINDING
        )
        jev_errors = sum(1 for s in report.sections if isinstance(s.jev, JevFailure))
        if jev_findings or jev_errors:
            reasons.append(f"Jev gate: {jev_findings} findings, {jev_errors} failed requests")
    return reasons


def exit_code(report: RunReport) -> int:
    return 1 if failures(report) else 0


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _versions(v: Versions | None) -> str:
    if v is None:
        return "Engine did not run."
    plugins = ", ".join(f"{name} {ver}" for name, ver in v.plugins.items())
    return f"Falco {v.falco}, engine {v.engine}, libs {v.libs}" + (
        f", plugins: {plugins}." if plugins else "."
    )


def _startup_line(s: StartupResult) -> str:
    match s:
        case StartupPassed(command):
            return f"passed (`{command}`)"
        case StartupFailed(command, reason, _):
            return f"**failed**: {reason} (`{command}`)"
        case StartupSkipped(reason):
            return f"skipped: {reason}"


def _load_line(report: RunReport) -> str:
    if report.engine_error:
        return f"**not run**: {report.engine_error}"
    load = report.load
    failed = [f.name for f in load.files if not f.successful]
    if failed:
        names = ", ".join(f"`{n}`" for n in failed)
        status = f"{len(failed)} of {_plural(len(load.files), 'rules file')} **failed to load** ({names})"
    else:
        status = f"{_plural(len(load.files), 'rules file')} loaded"
    text = f"{status}, {_plural(len(load.errors), 'error')}, {_plural(len(load.warnings), 'warning')}"
    if load.plugin_error:
        text += f"; plugin requirements not met: {load.plugin_error}"
    return text


def _tests_line(report: RunReport) -> str:
    outcomes = report.outcomes
    if not outcomes:
        return "no test cases ran" if report.load is None or report.load.ok else "not run: rules did not load"
    passed = sum(1 for o in outcomes if o.passed)
    rules = sum(1 for s in report.sections if s.outcomes)
    return f"{passed} of {len(outcomes)} cases passed across {_plural(rules, 'rule')}"


def _changes_line(report: RunReport) -> str:
    if not report.changes:
        return "no differences" if report.base.startswith("compared") else report.base
    counts = {k: sum(1 for c in report.changes if c.kind == k) for k in ("changed", "added", "removed")}
    removed = [c.name for c in report.changes if c.kind == "removed"]
    text = f"{counts['changed']} changed, {counts['added']} added, {counts['removed']} removed"
    return text + (f" ({', '.join(f'`{r}`' for r in removed)})" if removed else "")


def _severity_counts(findings) -> str:
    counts = [(s, sum(1 for f in findings if f.severity is s)) for s in reversed(Severity)]
    return (
        ", ".join(f"{n} info" if s is Severity.INFO else _plural(n, s.value) for s, n in counts if n)
        or "none"
    )


def markdown(report: RunReport) -> str:
    verdict = failures(report)
    out = [
        "# Falco rule test report",
        "",
        _versions(report.versions),
        "",
        f"**{'FAIL' if verdict else 'PASS'}**" + (f": {'; '.join(verdict)}." if verdict else "."),
        "",
        f"- Startup: {_startup_line(report.startup)}.",
        f"- Load: {_load_line(report)}.",
        f"- Tests: {_tests_line(report)}.",
        f"- Changes vs base: {_changes_line(report)}.",
        f"- Findings: {_severity_counts(report.all_findings)}.",
        f"- Jev: {report.jev}.",
    ]
    if report.other_rules:
        out.append(
            f"- {_plural(report.other_rules, 'other loaded rule')} unchanged and untested; not analyzed."
        )
    if isinstance(report.startup, StartupFailed) and report.startup.tail:
        out += ["", "Falco startup output (tail):", "", "```", report.startup.tail, "```"]
    if report.load is not None and report.load.errors:
        out += ["", "## Load errors", ""]
        for e in report.load.errors:
            where = f"{e.file}:{e.line}" if e.line is not None else e.file
            item = f" {e.item_type} `{e.item_name}`" if e.item_name else ""
            out.append(f"- `{e.code}` {where}{item}: {e.message}")
            if e.snippet:
                out += ["", "  ```", *(f"  {line}" for line in e.snippet.rstrip("\n").split("\n")), "  ```"]
    for section in report.sections:
        out += ["", *_section(section)]
    if report.findings:
        out += ["", "## Other findings", ""]
        out += [f"- {f.code} ({f.severity.value}): {f.message}" for f in report.findings]
    return "\n".join(out) + "\n"


def _section(s: RuleSection) -> list[str]:
    status = "enabled" if s.enabled else "disabled"
    head = [f"## {s.name}", ""]
    if not s.loaded:
        return head + ["Not loaded.", *_tests(s)]
    change = ""
    if s.change:
        change = (
            " Added." if s.change.kind == "added" else f" Changed vs base: {', '.join(s.change.details)}."
        )
    tests = (
        f" Tests: {sum(o.passed for o in s.outcomes)} of {len(s.outcomes)} passed."
        if s.outcomes
        else " No tests."
    )
    lines = head + [
        f"{s.priority}, {status}.{change}{tests} {s.needs_optimizing}.",
        "",
        "**What it does.**",
        "",
    ]
    lines += [f"- {line}" if not line.startswith("  ") else line for line in s.what_it_does]
    lines += _tests(s)
    if s.coverage and s.coverage.cases:
        lines += ["", f"**Coverage.** {s.coverage.summary}."]
        for never in ("never true", "never false"):
            texts = [g.text for g in s.coverage.leaves if g.never == never]
            if texts:
                lines.append(f"- {never.capitalize()}: " + ", ".join(f"`{t}`" for t in texts) + ".")
        if s.coverage.parts:
            lines.append(
                "- Not fully exercised: " + "; ".join(f"{g.text} {g.never}" for g in s.coverage.parts) + "."
            )
    if s.findings or s.work:
        lines += ["", "**Optimization and lint.**", ""]
        for f in s.findings:
            lines.append(f"- {f.code} ({f.severity.value}): {f.message}.")
            if f.suggestion:
                lines.append(f"  Suggestion: {f.suggestion}")
        if s.work:
            lines.append(f"- Work: {s.work.summary}.")
    if s.jev is not None:
        lines.append("")
        if isinstance(s.jev, JevFailure):
            lines.append(f"**Jev.** Request failed: {s.jev.error}.")
        else:
            rid = f", request {s.jev.request_id}" if s.jev.request_id else ""
            lines += [f"**Jev** (advisory; model {s.jev.model}{rid}).", ""]
            lines += [f"- {n.verdict.value}: {n.text}." for n in s.jev.notes]
    return lines


_MAX_WARNINGS = 3


def _tests(s: RuleSection) -> list[str]:
    if not s.outcomes:
        return []
    lines = ["", f"**Tests.** {sum(o.passed for o in s.outcomes)} of {len(s.outcomes)} passed."]
    for o in s.outcomes:
        for failure in o.failures:
            lines.append(f"- FAIL `{o.name}`: {failure}.")
    warned = [o for o in s.outcomes if o.warnings]
    for o in warned[:_MAX_WARNINGS]:
        lines.append(f"- warn `{o.name}`: {o.warnings[0]}.")
    if len(warned) > _MAX_WARNINGS:
        lines.append(f"- warn: {len(warned) - _MAX_WARNINGS} more cases left fields the rule reads unset.")
    return lines


def console(report: RunReport, written: list[Path]) -> str:
    verdict = failures(report)
    lines = [f"ftest: {'FAIL' if verdict else 'PASS'}" + (f" ({'; '.join(verdict)})" if verdict else "")]
    lines.append(f"  startup  {_startup_line(report.startup).replace('**', '')}")
    lines.append(f"  load     {_load_line(report).replace('**', '')}")
    lines.append(f"  tests    {_tests_line(report)}")
    for s in report.sections:
        mark = "FAIL" if s.failed or not s.loaded else "ok  "
        cases = f"{sum(o.passed for o in s.outcomes)}/{len(s.outcomes)} cases" if s.outcomes else "no tests"
        lines.append(
            f"  {mark}     {s.name}: {cases}; {s.needs_optimizing[0].lower()}{s.needs_optimizing[1:]}"
        )
    lines.append(f"  jev      {report.jev}")
    for path in written:
        lines.append(f"  report   {path}")
    return "\n".join(lines)


def _default(obj):
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path | set | frozenset):
        return sorted(obj) if isinstance(obj, set | frozenset) else str(obj)
    raise TypeError(f"not JSON serializable: {type(obj).__name__}")


def to_json(report: RunReport) -> str:
    sections = []
    for s in report.sections:
        doc = asdict(s)
        for outcome, raw in zip(s.outcomes, doc["outcomes"]):
            raw["passed"] = outcome.passed
        doc["jev_status"] = (
            None if s.jev is None else ("failed" if isinstance(s.jev, JevFailure) else "reviewed")
        )
        sections.append(doc)
    startup_status = {StartupPassed: "passed", StartupFailed: "failed", StartupSkipped: "skipped"}
    doc = {
        "result": "fail" if failures(report) else "pass",
        "exit_code": exit_code(report),
        "failures": failures(report),
        "versions": asdict(report.versions) if report.versions else None,
        "startup": {"status": startup_status[type(report.startup)], **asdict(report.startup)},
        "load": asdict(report.load) if report.load else None,
        "engine_error": report.engine_error,
        "base": report.base,
        "changes": [asdict(c) for c in report.changes],
        "rules": sections,
        "findings": [asdict(f) for f in report.findings],
        "jev": report.jev,
        "other_rules": report.other_rules,
    }
    return json.dumps(doc, indent=2, default=_default)
