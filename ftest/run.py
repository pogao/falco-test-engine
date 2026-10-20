"""`ftest run`: parse inputs, run Falco and the engine, analyze, and build the run model."""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Mapping
from pathlib import Path

from ftest import mutate, noise, strength, synth
from ftest.config import Config, JevMode
from ftest.corpus import builtin, load_corpus, values_by_field
from ftest.coverage import consistency, coverage
from ftest.diff import RuleChange, changed_macros, diff_rules, untested
from ftest.engine import CaseError, EngineError, EngineResult, JobCase, build_job, run_engine
from ftest.engine import CaseRun as EngineCaseRun
from ftest.explain import explain
from ftest.jev import JevClient, RuleBrief, credentials, review
from ftest.lint import CaseRun, RuleView, lint_rule, load_warnings, work
from ftest.outcomes import CaseOutcome, judge
from ftest.report import RuleSection, RunReport, markdown, to_json
from ftest.shape import shape_of
from ftest.startup import check_startup
from ftest.suite import Case, Suite, load_suites


def run(
    cfg: Config, strict: bool = False, use_jev: bool = True, env: Mapping[str, str] = os.environ
) -> RunReport:
    suites = load_suites(cfg.tests, cfg.root)
    ordinary = builtin() + load_corpus(cfg.noise.corpus, cfg.root) if cfg.noise.enabled else ()
    startup = check_startup(cfg.startup.enabled, cfg.startup.falco_config, cfg.rules_files)
    cases = [JobCase(c, s.rule) for s in suites for c in s.cases] + [JobCase(e, None) for e in ordinary]
    job = build_job(cfg.rules_files, cfg.plugins, cases)
    common = dict(startup=startup, strict=strict, jev_gate=cfg.jev.gate)
    try:
        full = run_engine(cfg.engine_binary, job)
    except EngineError as e:
        return RunReport(
            None,
            load=None,
            engine_error=str(e),
            base="not compared",
            changes=(),
            sections=(),
            findings=(),
            jev="not run",
            other_rules=0,
            noise="not run",
            mutation="not run",
            **common,
        )

    base_line, changes, base = _compare(cfg, full, ordinary)
    sections = analyze(full, suites, changes, cfg.lint_disable) if full.load.ok else ()
    noise_line, sections = _noise(cfg, suites, sections, ordinary, full, base)
    if cfg.mutation.enabled:
        changed = changed_macros(base.macros, full.macros) if base is not None else frozenset()
        sections = _strength(cfg, suites, sections, full, changed)
        sections = _generate(cfg, suites, sections, full)
    jev_line, sections = _jev(cfg, use_jev, env, suites, sections, full)
    return RunReport(
        versions=full.versions,
        load=full.load,
        engine_error=None,
        base=base_line,
        changes=changes,
        sections=sections,
        findings=tuple(load_warnings(full.load, cfg.lint_disable)),
        jev=jev_line,
        other_rules=max(len(full.rules) - sum(1 for s in sections if s.loaded), 0),
        noise=noise_line,
        mutation=("on" if full.load.ok else "not run: rules did not load") if cfg.mutation.enabled else "off",
        **common,
    )


def _compare(
    cfg: Config, full: EngineResult, ordinary: tuple[Case, ...]
) -> tuple[str, tuple[RuleChange, ...], EngineResult | None]:
    """The base rules see the same ordinary events, so the noise check can compare before and after."""
    if not cfg.base_rules_files:
        return "no base_rules_files configured", (), None
    job = build_job(cfg.base_rules_files, cfg.plugins, [JobCase(e, None) for e in ordinary])
    try:
        base = run_engine(cfg.engine_binary, job)
    except EngineError as e:
        return f"base run failed ({e}); not compared", (), None
    if not base.load.ok:
        return "base rules failed to load; not compared", (), None
    if not full.load.ok:
        return "rules failed to load; not compared", (), base
    return f"compared with {len(base.rules)} base rules", diff_rules(base.rules, full.rules), base


def _noise(cfg, suites, sections, ordinary, full, base) -> tuple[str, tuple[RuleSection, ...]]:
    if not cfg.noise.enabled:
        return "off", sections
    if not full.load.ok:
        return "not run: rules did not load", sections
    usable = tuple(e for e in ordinary if isinstance(full.cases.get(e.id), EngineCaseRun))
    rejected = [r for e in ordinary if isinstance(r := full.cases.get(e.id), CaseError)]
    checked = []
    for section in sections:
        rule = full.rules.get(section.name)
        if rule is not None:
            before = None
            if base is not None and section.name in base.rules:
                before = (base.rules[section.name], base.cases)
            limit = noise.budget(section.name, suites, cfg.noise.max_fire_rate)
            measured = noise.measure(rule, usable, full.cases, before, limit)
            found = noise.finding(section.name, measured)
            findings = section.findings + ((found,) if found else ())
            section = dataclasses.replace(section, noise=measured, findings=findings)
        checked.append(section)
    line = f"{len(usable)} ordinary events"
    if rejected:
        line += f"; the engine rejected {len(rejected)} (first: {rejected[0].id}: {rejected[0].error})"
    return line, tuple(checked)


def _strength(cfg, suites, sections, full, changed) -> tuple[RuleSection, ...]:
    scored = []
    for section in sections:
        rule = full.rules.get(section.name)
        runs = _runs(full, suites, section.name)
        if rule is not None and rule.enabled and runs:
            measured = strength.measure(
                rule, mutate.mutants(rule, shape_of(rule), changed), runs, cfg.mutation.min_score
            )
            findings = section.findings + tuple(strength.findings(section.name, measured))
            section = dataclasses.replace(section, strength=measured, findings=findings)
        scored.append(section)
    return tuple(scored)


def _generate(cfg, suites, sections, full) -> tuple[RuleSection, ...]:
    """Search for an event that tells each survivor from its rule, then let the engine judge."""
    pool = values_by_field(builtin())
    pending: dict[str, tuple[str, int, synth.Candidate]] = {}
    cases = []
    for section in sections:
        if section.strength is None:
            continue
        rule, runs = full.rules[section.name], _runs(full, suites, section.name)
        for si, survivor in enumerate(section.strength.survivors):
            for ci, candidate in enumerate(synth.search(rule, survivor.mutant, runs, pool)):
                case = synth.job_case(candidate, section.name, f"{si}::{ci}")
                pending[case.id] = (section.name, si, candidate)
                cases.append(JobCase(case, section.name))
    if not cases:
        return sections
    try:
        checked = run_engine(cfg.engine_binary, build_job(cfg.rules_files, cfg.plugins, cases))
    except EngineError as e:
        return tuple(
            dataclasses.replace(s, strength=dataclasses.replace(s.strength, unchecked=str(e)))
            if s.strength is not None
            else s
            for s in sections
        )
    by_name = {s.name: s for s in sections}
    examples: dict[tuple[str, int], strength.Generated] = {}
    for case_id, (name, si, candidate) in pending.items():
        mutant = by_name[name].strength.survivors[si].mutant
        if (name, si) not in examples:
            found = synth.verified(candidate, full.rules[name], mutant, checked.cases.get(case_id))
            if found is not None:
                examples[(name, si)] = found
    return tuple(_with_examples(s, examples) for s in sections)


def _with_examples(section: RuleSection, examples) -> RuleSection:
    if section.strength is None:
        return section
    survivors = tuple(
        dataclasses.replace(s, example=examples.get((section.name, i)))
        for i, s in enumerate(section.strength.survivors)
    )
    return dataclasses.replace(section, strength=dataclasses.replace(section.strength, survivors=survivors))


def _runs(full: EngineResult, suites: tuple[Suite, ...], name: str) -> list[strength.Run]:
    runs = []
    for suite, case in ((s, c) for s in suites if s.rule == name for c in s.cases):
        result = full.cases.get(case.id)
        if isinstance(result, EngineCaseRun) and name in result.traces:
            runs.append(strength.Run(suite, case, result.traces[name], result.alert_for(name) is not None))
    return runs


def analyze(
    full: EngineResult, suites: tuple[Suite, ...], changes: tuple[RuleChange, ...], disabled: frozenset[str]
) -> tuple[RuleSection, ...]:
    tested = {s.rule for s in suites}
    by_change = {c.name: c for c in changes}
    unproven = {f.rule: f for f in untested(changes, tested)}
    names = dict.fromkeys([s.rule for s in suites] + [c.name for c in changes if c.kind != "removed"])
    sections = []
    for name in names:
        cases = [c for s in suites if s.rule == name for c in s.cases]
        outcomes = tuple(judge_case(full, c, name) for c in cases)
        rule = full.rules.get(name)
        if rule is None:
            sections.append(
                RuleSection(name, "", False, False, by_change.get(name), (), outcomes, None, (), None)
            )
            continue
        shape = shape_of(rule)
        runs = []
        for c in cases:
            result = full.cases.get(c.id)
            if isinstance(result, EngineCaseRun):
                runs.append(CaseRun(c.name, result.traces.get(name), result.alert_for(name)))
        view = RuleView(rule, shape, full.macros, full.lists, tuple(runs))
        traces = [
            (c.id, r.traces[name])
            for c in cases
            if isinstance(r := full.cases.get(c.id), EngineCaseRun) and name in r.traces
        ]
        findings = consistency(rule, traces) + lint_rule(view, disabled)
        if name in unproven:
            findings.append(unproven[name])
        sections.append(
            RuleSection(
                name=name,
                priority=rule.priority,
                enabled=rule.enabled,
                loaded=True,
                change=by_change.get(name),
                what_it_does=explain(rule, full.macros),
                outcomes=outcomes,
                coverage=coverage(shape, rule.compiled, [t for _, t in traces]) if cases else None,
                findings=tuple(findings),
                work=work(view),
            )
        )
    return tuple(sections)


def judge_case(full: EngineResult, case: Case, rule: str) -> CaseOutcome:
    return judge(case, rule, full.cases.get(case.id), full.rules, full.known_fields)


def _jev(cfg, use_jev, env, suites, sections, full) -> tuple[str, tuple[RuleSection, ...]]:
    if not use_jev or cfg.jev.mode is JevMode.OFF:
        return "off", sections
    creds = credentials(env)
    if creds is None:
        if cfg.jev.mode is JevMode.ON:
            return (
                "skipped: jev.enabled is true but neither JEV_API_KEY nor TYPESAFE_API_KEY is set",
                sections,
            )
        return "skipped (set JEV_API_KEY or TYPESAFE_API_KEY to enable)", sections
    client = JevClient(creds)
    reviewed = []
    for section in sections:
        if section.loaded and section.outcomes:
            rule = full.rules[section.name]
            brief = RuleBrief(rule.name, rule.description, rule.priority, section.what_it_does)
            section = dataclasses.replace(section, jev=review(client, cfg.jev.model, brief))
        reviewed.append(section)
    count = sum(1 for s in reviewed if s.jev is not None)
    mode = "gating" if cfg.jev.gate else "advisory"
    return f"{count} rules reviewed with model {cfg.jev.model} ({mode})", tuple(reviewed)


def write_reports(report: RunReport, cfg: Config, env: Mapping[str, str] = os.environ) -> list[Path]:
    written = []
    text = markdown(report)
    for path, content in ((cfg.report.markdown, text), (cfg.report.json, to_json(report))):
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            written.append(path)
    if summary := env.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as f:
            f.write(text)
    return written
