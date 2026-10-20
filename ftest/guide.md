# ftest guide

ftest tests Falco rules with the real Falco engine. A test case is a set of Falco field values. The engine evaluates every loaded rule on those values, with lists, macros, exceptions, overrides, and appends resolved, and ftest compares what fired with what the case expects.

This guide writes commands as `ftest <command>`. Through Docker, run them from the rules repo root:

```sh
docker run --rm -v "$PWD:/work" ghcr.io/pogao/falco-test-engine <command> [args]
```

The image mounts the repo root at `/work`. A path the image prints, such as `/work/falco-test-report.md`, is that path relative to the repo root. Every command except `ftest guide` reads `falco-test.yaml` from the current directory. Pass `-c <path>` to use another config.

## Commands

- `ftest describe "<rule>"` prints what the loaded rule does after all overrides and appends (event types, each condition term, exceptions, output fields, macros, lists) and its lint findings. Read it before you write cases.
- `ftest scaffold "<rule>" [-o tests/x.yaml]` writes a suite skeleton. It lists every field the rule reads under `defaults`, with a value taken from the condition where one exists and `TODO` elsewhere. It refuses to overwrite a file.
- `ftest run [--strict] [--no-jev]` runs every suite, prints a summary, and writes the Markdown and JSON reports.
- `ftest generate "<rule>" [-o file] [--no-jev]` writes a suite named after the rule, ending in `_generated.yaml`, with one case for each mutant of the rule that the current suites miss. It needs at least one existing suite for the rule. It refuses to overwrite a file.
- `ftest guide` prints this guide.

## Work loop

1. Run `ftest describe "<rule>"`. Note each field the condition reads, each exception, and each `not`.
2. Run `ftest scaffold "<rule>" -o tests/<name>.yaml`.
3. Replace every `TODO`. Write `intent` as you would explain the rule to a reviewer: what it must catch, where, and each exception. A `TODO` value is a real string, so a comparison on it is false.
4. Write cases. For each `and` term, write one `match` case and one `no_match` case that differs from it only in the field that term reads. For each exception and each `not`, write one `no_match` case that sets the excluded value.
5. Run `ftest run`. Read `falco-test-report.md`, or `falco-test-report.json` for structured data.
6. Fix each failing case and each `warn` line (see "Fix a failure"). Run again until the run passes.
7. Read the "Test strength" section. For each FTE012 survivor, run `ftest generate "<rule>"`. Confirm each generated `expect` against the intent before you keep the case (see "Generated cases").
8. Run `ftest run` again. Stop when it exits 0 and no `warn` line remains for the rule.

## Suite format

One suite file tests one rule. Several suite files can test the same rule. `ftest run` reads every `.yaml` and `.yml` file under the `tests` paths in `falco-test.yaml`.

```yaml
rule: Package manager run in container      # exact rule name
intent: >                                   # optional; Jev judges events against it
  Alert when a shell inside a container starts a package manager. The CI runner image is excluded.
defaults:                                   # merged under every case's event
  evt.type: execve
  container.id: 9f2c51b0a1d4
  container.image.repository: docker.io/library/nginx
  proc.aname: [bash, runc]                  # process tree, nearest first
cases:
  - name: apt-get from bash in nginx        # unique within the file
    expect: match
    event: {proc.name: apt-get, proc.cmdline: apt-get install -y curl}
    output_contains: ["apt-get install -y curl"]
  - name: CI runner image is excluded
    expect: no_match
    event: {proc.name: apt, container.image.repository: ghcr.io/acme/ci-runner}
  - name: no other rule fires
    expect_rules: [Package manager run in container]
    event: {proc.name: apt-get}
```

Top-level keys:

- `rule` (required) names the rule under test.
- `intent` (optional) states what the rule must catch and ignore. An intent that starts with `TODO` counts as none.
- `defaults` (optional) holds fields set in every case.
- `cases` (required) is a non-empty list.
- `max_fire_rate` (optional) is a number from 0 to 1. It raises the noise budget for this rule. Use it only for a rule meant to fire on routine activity. The largest value across suites applies.

Case keys:

- `name` (required).
- `event` (optional) holds the case's fields. Each key replaces the same key from `defaults` whole. Lists are not merged.
- `expect`, `expect_rules`, and `output_contains` are described under "Expectations".

## How event fields work

- Keys are Falco field names, including indexed fields such as `proc.aname[2]`.
- A value is a scalar or a list of scalars. ftest turns `true` into `"true"` and `12` into `"12"`.
- Each case needs exactly one `evt.type`, from `defaults` or `event`. Set the syscall the rule's event-type filter expects, such as `execve` for `spawned_process`.
- A field the case does not set is unavailable, as when Falco cannot extract it. A comparison on it is false. `not` over that comparison is true. So `not proc.pname in (sshd)` passes when `proc.pname` is unset, and a `no_match` case can pass without testing the exception it names.
- The report adds a `warn` line to each case that left a field the rule reads unset. Treat each `warn` line as a bug in the case.
- A misspelled field fails the case with `unknown field` and the closest real name.

ftest derives fields that a case implies. A value you set yourself always wins.

| You set | ftest also sets |
| --- | --- |
| `proc.aname: [bash, runc]` (nearest ancestor first) | `proc.pname`, `proc.aname[N]` for each ancestor (`proc.aname[1]` is `bash`), and `proc.aname[0]` from `proc.name`. `proc.aname` matches any ancestor. |
| `proc.apid`, `proc.aexe`, `proc.aexepath`, `proc.acmdline` | the same way: `proc.ppid`, `proc.pexe`, `proc.pexepath`, `proc.pcmdline`, and `proc.apid[N]`, `proc.aexe[N]`, `proc.aexepath[N]`, `proc.acmdline[N]` |
| `proc.pname` and the other parent fields, with no ancestor list | the ancestor list with that one entry, and its `[1]` form |
| `fd.cip`, `fd.sip` | `fd.ip` (both values) and `fd.net` |
| `fd.cport`, `fd.sport` | `fd.port` |
| `fd.cproto`, `fd.sproto` | `fd.proto` |
| `fd.name` with an absolute path | `fd.directory`, `fd.filename` |

Set the process tree with one `proc.aname` list. If you also set `proc.pname`, it wins for `proc.pname` only, and `proc.aname[1]` still comes from the list.

## Expectations

A case needs `expect`, `expect_rules`, or both.

- `expect: match` passes when `rule` fires. `expect: no_match` passes when it does not.
- `expect_rules: [A, B]` passes when exactly that set of enabled rules fires. `expect_rules: []` means no rule fires. Use it to catch another loaded rule that overlaps.
- `output_contains: "text"` or a list of strings passes when the rule's alert output contains each string. The case must expect `rule` to fire.

## Read the report

`ftest run` prints one summary line per area and one `ok` or `FAIL` line per rule under test, then the report paths. `falco-test-report.md` has one section per rule:

- **What it does.** The same text `ftest describe` prints.
- **Tests.** One `FAIL` line per failed expectation, then up to three `warn` lines for cases that left fields unset.
- **Noise.** How many ordinary events of the rule's event types it fired on (315 built in, plus `noise.corpus`), against the budget (default 5%). Over budget fails the run with FTE013 and lists the events.
- **Test strength.** Mutants killed out of total. Each FTE012 line names a mutant no case catches and shows a generated case for it.
- **Coverage.** Condition parts that were never true or never false across the cases. Each one needs a case.
- **Optimization and lint.** Findings with suggested rewrites.
- **Readiness** scores a passing rule from 0 to 100. **Jev** is an advisory model that judges events against `intent`.

Under a case that fired when it should not, or did not fire when it should, the report lists the checks that decided the verdict:

```
- FAIL `apt-get from bash in nginx`: expected `Package manager run in container` to fire; it did not.
  - `proc.aname in (sh, bash)` was false, in the rule condition. The case does not set `proc.aname`.
```

Fix the event or the rule from that list. Do not change `expect` to make the case pass.

`falco-test-report.json` has these top-level keys: `result` (`pass` or `fail`), `exit_code`, `failures` (the reasons), `readiness`, `versions`, `startup`, `load`, `engine_error`, `base`, `changes`, `rules`, `findings`, `jev`, `noise`, `mutation`, and `other_rules`. Each entry of `rules` has `name`, `outcomes`, `coverage`, `findings`, `noise`, and `strength`. Each outcome has `name`, `expected`, `actual`, `passed`, `failures`, `warnings`, and `why`. `why` is a list of `{check, value, where, unset}`. `check` is the check's condition text. `value` is `true` or `false` on this case. `where` is `in the rule condition`, `in macro <name>`, or `in exception <name>`. `unset` lists the fields the check reads that the case does not set. To list the failed cases:

```sh
jq '.rules[].outcomes[] | select(.passed | not) | {name, failures, why}' falco-test-report.json
```

## Fix a failure

Decide whether the case or the rule is wrong from the suite's `intent`, never from what the rule does now.

- `unknown field`: use the suggested name.
- `expected ... to fire; it did not`: read `why`. If a deciding check reads a field the case does not set, set that field. If a set value makes the check false and the intent says the event must alert, fix the rule.
- `expected ... not to fire; it fired`: read `why`. The checks listed `in exception` or under a `not` were false, so they did not stop the rule. If the case leaves the excluded field unset, set it. If the case sets it and the rule still fires, the exception or `not` in the rule is wrong.
- `its condition matched but the rule is disabled`: the rule has `enabled: false` in the loaded rules files.
- `expected rule set differs`: another rule also fired, or one did not. Narrow the event or the other rule, or list the extra rule if both should fire.
- `output lacks`: the alert output did not contain the string. The report prints the actual output.
- `warn ... does not set`: set each named field to a value from the intent, in `defaults` or in the case.

## Generated cases

`ftest generate` and the FTE012 lines build each case from an existing case. Each changes as few fields as it can, so that the current rule and one mutant disagree on it, and the engine evaluates every one. Each `expect` is the current rule's verdict on that event, not a checked intent. For each case:

1. Read the event and decide from `intent` whether it must alert.
2. If the rule's verdict is right, keep the case.
3. If it is wrong, set `expect` to the correct value and fix the rule.

A comment above each generated case names the case it extends and the mutant it catches. With an API key set, it also gives Jev's call. If Jev disputes the rule, check that case first.

## Exit codes

- `0`: the run passed, or the command finished.
- `1`: `ftest run` failed. Falco did not start, rules or plugins failed to load, the engine failed, a case failed, or the run found a rule over its noise budget, a rule below `mutation.min_score`, an error-severity finding with `--strict`, or a Jev finding with `jev.gate: true`. The `failures` key of the JSON report lists which. `ftest scaffold` and `ftest generate` also exit 1 when the output file exists or no suite tests the rule.
- `2`: a bad `falco-test.yaml`, suite, or corpus file. For `describe`, `scaffold`, and `generate`, also a rule that is not loaded, rules that fail to load, or an engine error. The message is on stderr.

## Configuration

`falco-test.yaml` resolves relative paths from its own directory.

| Key | Default | Meaning |
| --- | --- | --- |
| `rules_files` | required | Rules files in load order, as in `falco.yaml`. `/etc/falco/falco_rules.yaml` holds the stock rules in the image. |
| `tests` | required | Suite files or directories. |
| `base_rules_files` | none | Baseline rules. The report lists what your files change, and FTE011 flags changed rules without a suite. |
| `plugins` | the container plugin | `name`, `library_path`, `init_config` for each plugin. |
| `startup.enabled`, `startup.falco_config` | `true`, `/etc/falco/falco.yaml` | Run `falco --dry-run` with these rules. |
| `lint.disable` | `[]` | Finding codes to skip. |
| `jev.enabled`, `jev.model`, `jev.gate` | `auto`, `jev-latest`, `false` | Jev review. `auto` runs it when `JEV_API_KEY` or `TYPESAFE_API_KEY` is set. |
| `report.markdown`, `report.json` | `falco-test-report.md`, `falco-test-report.json` | Report paths. `null` skips one. |
| `noise.enabled`, `noise.max_fire_rate`, `noise.corpus` | `true`, `0.05`, `[]` | Ordinary-activity check. `corpus` adds YAML files, each a list of events in the suite event format. |
| `mutation.enabled`, `mutation.min_score` | `true`, none | Mutation testing, and an optional minimum share of mutants killed, such as `0.9`. |
| `engine.binary` | `falco-test-engine` | The engine binary. Leave it unset in the image. |

## Findings

| Code | Finds |
| --- | --- |
| FTE001 | No event-type restriction, or more than 100 event types. |
| FTE002 | A top-level negative event type such as `evt.type != open`. |
| FTE003 | `f = a or f = b` that can be `f in (a, b)`. |
| FTE004 | `f contains a or f contains b` that can be `f contains anyof (a, b)`. |
| FTE005 | A costly check (ancestor walk, regex, plugin field) before cheaper ones in the same `and` or `or`. |
| FTE006 | A `regex` or `glob` that is a plain string test. Falco regexes match the whole value. |
| FTE007 | A repeated list item or predicate. |
| FTE008 | A condition that can never be true. |
| FTE009 | Output fields that rendered `<NA>` on matching cases. Set those fields in the cases. |
| FTE010 | Falco's own load warnings. |
| FTE011 | A rule your files add or change that no suite tests. |
| FTE012 | A mutant no case catches, with a generated case that would. |
| FTE013 | A rule over its noise budget. It fails the run. |
| FTE900 | An internal consistency error between the engine and the analysis. Report it. |

Each suggestion says whether the rewrite is equivalent. Apply only equivalent rewrites unless the intent calls for the change.

## Pitfalls

- An unset field makes every `not` over it true. A `no_match` case for an exception passes only by accident unless it sets the excluded value.
- A case without the right `evt.type` never reaches the rule. Copy the event type from `ftest describe`.
- A misspelled field fails the case. Do not delete the field. Fix its name.
- A `TODO` left from `ftest scaffold` is a literal value.
- An `event` key replaces the default whole. `proc.aname: [sh]` in a case drops `runc` from the default list.
- A generated `expect` copies the rule. Confirm it against `intent` before you commit it.
