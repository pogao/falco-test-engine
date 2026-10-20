"""The run model and its renderings: Markdown report, JSON dump, console summary, exit code."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path

from ftest.cond import render
from ftest.coverage import Coverage
from ftest.diff import RuleChange
from ftest.engine import Load, Versions
from ftest.findings import Finding, Severity
from ftest.jev import JevFailure, JevReview, Verdict
from ftest.lint import Work
from ftest.noise import Noise, percent
from ftest.oracle import EventBrief, Judgment, Stance, Unjudged, word
from ftest.outcomes import CaseOutcome
from ftest.startup import StartupFailed, StartupPassed, StartupResult, StartupSkipped
from ftest.strength import Generated, Strength

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
    noise: Noise | None = None
    strength: Strength | None = None
    judgments: tuple[Judgment | Unjudged, ...] = ()
    no_intent: tuple[str, ...] = ()

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if not o.passed)

    @property
    def jev_findings(self) -> int:
        """What `jev.gate` fails on: a priority two or more levels off, or a disputed rule verdict."""
        priority = isinstance(self.jev, JevReview) and self.jev.verdict is Verdict.FINDING
        return priority + sum(
            1 for j in self.judgments if isinstance(j, Judgment) and j.verdict is Verdict.FINDING
        )

    @property
    def jev_failed(self) -> int:
        return isinstance(self.jev, JevFailure) + sum(1 for j in self.judgments if isinstance(j, Unjudged))

    @property
    def noisy(self) -> bool:
        return self.noise is not None and self.noise.over

    @property
    def weak(self) -> bool:
        return self.strength is not None and self.strength.below_min

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
    noise: str
    mutation: str
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
    if noisy := sum(1 for s in report.sections if s.noisy):
        reasons.append(f"{_plural(noisy, 'rule')} over the noise budget")
    if weak := sum(1 for s in report.sections if s.weak):
        reasons.append(f"{_plural(weak, 'rule')} below the test-strength minimum")
    errors = sum(1 for f in report.all_findings if f.severity is Severity.ERROR)
    if report.strict and errors:
        reasons.append(f"{errors} error finding{'s' if errors != 1 else ''} (--strict)")
    if report.jev_gate:
        jev_findings = sum(s.jev_findings for s in report.sections)
        jev_failed = sum(s.jev_failed for s in report.sections)
        if jev_findings or jev_failed:
            reasons.append(f"Jev gate: {jev_findings} findings, {jev_failed} failed requests")
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


def _noise_line(report: RunReport) -> str:
    checked = [s for s in report.sections if s.noise is not None]
    if not checked:
        return report.noise
    noisy = [s for s in checked if s.noisy]
    text = f"{_plural(len(checked), 'rule')} checked on {report.noise}; "
    if not noisy:
        return text + "none over budget"
    worst = ", ".join(f"`{s.name}` fired on {percent(s.noise.rate)}" for s in noisy)
    return text + f"**{len(noisy)} over budget** ({worst})"


def _strength_line(report: RunReport) -> str:
    scored = [s.strength for s in report.sections if s.strength is not None]
    if not scored:
        return "no rule has test cases to score" if report.mutation == "on" else report.mutation
    killed, total = sum(x.killed for x in scored), sum(x.total for x in scored)
    survived = total - killed
    generated = sum(1 for x in scored for v in x.survivors if v.example is not None)
    text = f"{killed} of {total} mutants killed across {_plural(len(scored), 'rule')}"
    text += f"; {survived} survived, {generated} with a generated case" if survived else "; none survived"
    if weak := sum(1 for s in report.sections if s.weak):
        text += f"; **{_plural(weak, 'rule')} below the minimum**"
    return text


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
        f"- Noise: {_noise_line(report)}.",
        f"- Test strength: {_strength_line(report)}.",
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
        out += ["", *_section(section, report.jev_gate)]
    if report.findings:
        out += ["", "## Other findings", ""]
        out += [f"- {f.code} ({f.severity.value}): {f.message}" for f in report.findings]
    return "\n".join(out) + "\n"


def _section(s: RuleSection, gate: bool) -> list[str]:
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
    lines += _noise(s)
    lines += _strength(s)
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
    lint = [f for f in s.findings if f.code not in OWN_SECTION_CODES]
    if lint or s.work:
        lines += ["", "**Optimization and lint.**", ""]
        for f in lint:
            lines.append(f"- {f.code} ({f.severity.value}): {f.message}.")
            if f.suggestion:
                lines.append(f"  Suggestion: {f.suggestion}")
        if s.work:
            lines.append(f"- Work: {s.work.summary}.")
    return lines + _jev(s, gate)


def _jev(s: RuleSection, gate: bool) -> list[str]:
    """The priority note, a one-line tally of the judged events, and only the events to look at."""
    if s.jev is None and not s.judgments and not s.no_intent:
        return []
    models = [r.model for r in (s.jev, *s.judgments) if isinstance(r, JevReview | Judgment)]
    model = f"; model {models[0]}" if models else ""
    lines = ["", f"**Jev** ({'gating' if gate else 'advisory'}{model}).", ""]
    if isinstance(s.jev, JevReview):
        lines.append(f"- {s.jev.verdict.value}: {s.jev.text}.")
    judged = [j for j in s.judgments if isinstance(j, Judgment)]
    if judged:
        counts = Counter(j.stance for j in judged)
        parts = (
            ("agrees with the rule on", counts[Stance.AGREES] + counts[Stance.DISPUTES_EXPECT]),
            ("disputes it on", counts[Stance.DISPUTES_RULE]),
            ("is unsure on", counts[Stance.UNSURE]),
        )
        said = ", ".join(f"{words} {n}" for words, n in parts if n)
        lines.append(f"- Jev judged {_plural(len(judged), 'event')} against their suite's intent: it {said}.")
        if not s.enabled:
            lines.append("- The rule is disabled; Jev is compared with what its condition matched.")
    lines += [f"- {j.verdict.value}: {_dispute(j)}" for j in judged if j.verdict is not Verdict.OK]
    lines += [f"- Cases in `{suite}` were not judged: it states no `intent`." for suite in s.no_intent]
    errors = [s.jev.error] if isinstance(s.jev, JevFailure) else []
    errors += [j.error for j in s.judgments if isinstance(j, Unjudged)]
    lines += [f"- {_plural(n, 'request')} failed: {error}." for error, n in Counter(errors).items()]
    return lines


def _dispute(j: Judgment) -> str:
    b, rule, jev = j.brief, word(j.brief.matched), word(j.call)
    if j.stance is Stance.DISPUTES_EXPECT:
        return (
            f"`{b.name}` fails, and Jev sides with the rule: it reads the intent as {jev} ({j.why}). "
            "Check the case's `expect`."
        )
    if b.generated:
        return (
            f"generated case `{b.name}`: the rule says {rule}; Jev reads the intent as {jev} ({j.why}). "
            f"Its `expect` only copies the rule, so this may be a rule bug: if Jev is right, set "
            f"`expect: {jev}` and fix the rule."
        )
    if b.expect == b.matched:
        return (
            f"`{b.name}`: the rule and the case say {rule}; Jev reads the intent as {jev} ({j.why}). "
            "The intent may be vague, or the case and the rule may both be wrong."
        )
    return (
        f"`{b.name}` fails, and Jev sides with the case: it reads the intent as {jev} ({j.why}). "
        "The rule is the likely culprit."
    )


_MAX_WARNINGS = 3
OWN_SECTION_CODES = frozenset({"FTE012", "FTE013"})


def _strength(s: RuleSection) -> list[str]:
    if s.strength is None:
        return []
    summary = s.strength.summary[0].upper() + s.strength.summary[1:]
    lines = ["", f"**Test strength.** {'FAIL. ' if s.weak else ''}{summary}."]
    for survivor in s.strength.survivors:
        lines.append(f"- FTE012 (warning): your tests would not catch {survivor.mutant.description}.")
        lines += _generated(survivor.example, s.strength.unchecked)
    return lines


def _generated(g: Generated | None, unchecked: str | None) -> list[str]:
    if unchecked is not None:
        return [f"  Generated events were not checked: {unchecked}."]
    if g is None:
        return ["  No distinguishing event found; this mutant may mean the same as the rule."]
    return [
        f"  The current rule says {g.verdict} here; confirm that is what you want, then add it to your "
        f"suite. This case extends `{g.extends}` in {g.suite.display} and changes {g.changed}. "
        "The engine evaluated it: the rule and this mutant disagree.",
        "",
        "  ```yaml",
        *(f"  {line}" for line in g.yaml().splitlines()),
        "  ```",
    ]


def _noise(s: RuleSection) -> list[str]:
    if s.noise is None:
        return []
    summary = s.noise.summary[0].upper() + s.noise.summary[1:]
    lines = ["", f"**Noise.** {'FAIL. ' if s.noisy else ''}{summary}."]
    for f in s.findings:
        if f.code == "FTE013":
            lines.append(f"- {f.code} ({f.severity.value}): {f.message}.")
            if f.suggestion:
                lines.append(f"  Suggestion: {f.suggestion}")
    if s.noisy:
        lines += [f"- Fired on {e.label}: `{e.fields}`" for e in s.noise.examples]
    return lines


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
    lines.append(f"  noise    {_noise_line(report).replace('**', '')}")
    lines.append(f"  strength {_strength_line(report).replace('**', '')}")
    for s in report.sections:
        mark = "FAIL" if s.failed or not s.loaded or s.noisy or s.weak else "ok  "
        cases = f"{sum(o.passed for o in s.outcomes)}/{len(s.outcomes)} cases" if s.outcomes else "no tests"
        noisy = f"; noise {s.noise.fired}/{s.noise.total} ({percent(s.noise.rate)})" if s.noise else ""
        strong = f"; strength {s.strength.killed}/{s.strength.total}" if s.strength else ""
        optimizing = s.needs_optimizing[0].lower() + s.needs_optimizing[1:]
        lines.append(f"  {mark}     {s.name}: {cases}{noisy}{strong}; {optimizing}")
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


def _strength_json(strength: Strength) -> dict:
    """Mutants as condition text and generated cases as suite cases; no ASTs or whole suites."""
    survivors = []
    for v in strength.survivors:
        g = v.example
        survivors.append(
            {
                "kind": v.mutant.kind.value,
                "description": v.mutant.description,
                "condition": render(v.mutant.ast),
                "generated": None
                if g is None
                else {"suite": g.suite.display, "extends": g.extends, "changes": g.changed, "case": g.case()},
            }
        )
    return {
        "killed": strength.killed,
        "total": strength.total,
        "generated": strength.generated,
        "score": strength.score,
        "min_score": strength.min_score,
        "unchecked": strength.unchecked,
        "survivors": survivors,
    }


def _event_json(b: EventBrief) -> dict:
    """The event and intent are already in the suites and in the strength section's generated cases."""
    return {"case": b.name, "suite": b.suite, "origin": "generated" if b.generated else "suite"}


def _judgment_json(j: Judgment) -> dict:
    return {
        **_event_json(j.brief),
        "rule_says": word(j.brief.matched),
        "expect": None if j.brief.expect is None else word(j.brief.expect),
        "jev_says": None if j.call is None else word(j.call),
        "stance": j.stance.value,
        "verdict": j.verdict.value,
        "in_scope": j.in_scope,
        "exception": j.exception,
        "model": j.model,
        "request_id": j.request_id,
    }


def to_json(report: RunReport) -> str:
    sections = []
    for s in report.sections:
        doc = asdict(s)
        for outcome, raw in zip(s.outcomes, doc["outcomes"]):
            raw["passed"] = outcome.passed
        doc["jev_status"] = (
            None if s.jev is None else ("failed" if isinstance(s.jev, JevFailure) else "reviewed")
        )
        doc["strength"] = None if s.strength is None else _strength_json(s.strength)
        doc["judgments"] = [_judgment_json(j) for j in s.judgments if isinstance(j, Judgment)]
        doc["unjudged"] = [
            {**_event_json(j.brief), "error": j.error} for j in s.judgments if isinstance(j, Unjudged)
        ]
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
        "noise": report.noise,
        "mutation": report.mutation,
        "other_rules": report.other_rules,
    }
    return json.dumps(doc, indent=2, default=_default)
