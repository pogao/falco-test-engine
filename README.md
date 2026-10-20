# falco-test-engine

Test Falco rules in CI before they reach your clusters. `ftest` answers four questions about a rules change:

1. **Does Falco start with these rules?** It runs the real `falco --dry-run` and loads the rules with Falco's own rule loader.
2. **Does each rule do what you expect?** You write test cases as Falco field values. The real Falco engine evaluates every rule against them, with all lists, macros, exceptions, overrides, and appends resolved.
3. **Would a backwards rule get through?** Every rule you test, add, or change runs over 315 generated events of ordinary node activity. A rule that fires on many of them fails the run, even if it has no tests. Then `ftest` inverts parts of each rule and checks that your tests notice. For each inversion they miss, it writes the test case that would catch it.
4. **Can the rules be cheaper?** A linter reads each compiled condition and suggests rewrites. It also says whether each rewrite means exactly the same thing.

After each run you get a short Markdown report. For each rule under test it says what the rule does, which test cases passed, how often it fired on ordinary activity, which inversions the tests would miss, which conditions no test exercised, and what to optimize.

Built on Falco 0.45.1 (engine 0.65.0, libs 0.26.1, container plugin 0.7.5).

## How it works

`falco-test-engine` is a small C++ program built inside Falco's source tree and linked against Falco's `falco_engine` and libsinsp. It loads your rules exactly as Falco does. One thing changes: each field's value comes from your test case instead of the kernel. Parsing, operators, list and macro resolution, exceptions, transformers, comparison semantics, and the event-type index all stay Falco's.

So the tests check rule logic, which is where rule changes go wrong. They do not check how libsinsp turns a syscall into `proc.name`; Falco's own test suite covers that. [docs/how-it-works.md](docs/how-it-works.md) explains this choice and its limits.

The Python CLI `ftest` does everything else: it reads suites, runs the engine, analyzes the results, calls Jev, and writes the report. The two halves talk JSON, specified in [docs/engine-protocol.md](docs/engine-protocol.md).

## Run it on the examples

[`examples/`](examples) is a small rules repo. It overrides a stock macro, adds two custom rules, and has 18 test cases.

```sh
docker build -t falco-test-engine:dev .
docker run --rm -v "$PWD/examples:/work" falco-test-engine:dev run -c falco-test.yaml
```

The first build compiles libsinsp and takes about 15 minutes. Later builds take seconds.

You should see:

```
ftest: PASS
  startup  passed (`falco -c /etc/falco/falco.yaml --dry-run -r /etc/falco/falco_rules.yaml -r /work/rules/custom_rules.yaml`)
  load     2 rules files loaded, 0 errors, 0 warnings
  tests    18 of 18 cases passed across 3 rules
  noise    3 rules checked on 315 ordinary events; none over budget
  strength 42 of 48 mutants killed across 3 rules; 6 survived, 6 with a generated case
  ok       Cloud metadata access from container: 6/6 cases; noise 0/72 (0%); strength 16/17; needs optimizing: minor (2 info findings)
  ok       Package manager run in container: 6/6 cases; noise 0/97 (0%); strength 10/12; needs optimizing: yes (FTE005)
  ok       Terminal shell in container: 6/6 cases; noise 0/97 (0%); strength 16/19; needs optimizing: no
```

The full report is in `examples/falco-test-report.md`.

`examples/broken/` holds the same rules with three bugs that pass `falco --validate`:

- An `and`/`or` precedence mistake.
- An exception that matches too much.
- A `regex` that only matches one exact string.

Run `-c falco-test.broken.yaml` and the report names each bug through the cases it breaks:

```
ftest: FAIL (7 test cases failed)
  tests    11 of 18 cases passed across 3 rules
  FAIL     Cloud metadata access from container: 5/6 cases; noise 0/72 (0%); strength 15/17; needs optimizing: yes (FTE006)
  FAIL     Package manager run in container: 1/6 cases; noise 0/315 (0%); strength 9/18; needs optimizing: yes (FTE001)
  FAIL     Terminal shell in container: 5/6 cases; noise 0/97 (0%); strength 16/19; needs optimizing: no
```

## Test your own rules

1. Add `falco-test.yaml` to your rules repo:

   ```yaml
   rules_files:                     # load order, like rules_files in falco.yaml
     - /etc/falco/falco_rules.yaml  # stock rules shipped in the image
     - rules/custom_rules.yaml
   base_rules_files:                # optional: report what your files change in the stock rules
     - /etc/falco/falco_rules.yaml
   tests: [tests/]
   ```

2. Generate a suite skeleton for a rule. It lists every field the rule reads:

   ```sh
   docker run --rm -v "$PWD:/work" ghcr.io/pogao/falco-test-engine scaffold "Terminal shell in container" -o tests/terminal_shell.yaml
   ```

3. Fill in the cases, then run `run`.

To see what a rule does and how to optimize it without writing tests, run `describe "<rule name>"`. To write cases for the inversions a rule's tests miss, run `generate "<rule name>"`.

## Suite files

One suite tests one rule. Several suites can test the same rule.

```yaml
rule: Terminal shell in container
intent: >                        # optional; Jev judges each case's event against it
  Alert on an interactive shell in any container except our CI runner image.
defaults:                        # merged under every case's event
  evt.type: execve
  container.id: 3ad7b26ded6d
  proc.tty: 34816
cases:
  - name: kubectl exec bash into nginx
    expect: match                # match | no_match, for `rule`
    event: {proc.name: bash, container.image.repository: docker.io/library/nginx}
    output_contains: [bash, "terminal=34816"]
  - name: CI runner image is allowed
    expect: no_match
    event: {proc.name: bash, container.image.repository: ghcr.io/acme/ci-runner}
  - name: no other rule fires
    expect_rules: [Terminal shell in container]   # exact set of enabled rules that fire
    event: {proc.name: bash}
```

Event keys are Falco field names, including arguments such as `proc.aname[2]`. A misspelled field fails the case and suggests the closest real one. Syscall cases must set `evt.type`.

A field that a rule reads but the case leaves out is unavailable, as when Falco cannot extract it. The comparison is false, so `not` over it is true. The report lists these fields so a forgotten field doesn't pass by accident.

Give a list to set several values. For ancestor fields the list is the process tree, nearest first. `proc.aname: [bash, runc]` sets `proc.pname`, `proc.aname[1]`, `proc.aname[2]`, and `proc.aname` (which matches any ancestor). Other derived fields:

| You set | ftest also sets |
| --- | --- |
| `proc.aname`, `proc.apid`, `proc.aexe`, `proc.aexepath`, `proc.acmdline` | the indexed forms and `proc.pname`, `proc.ppid`, `proc.pexe`, `proc.pexepath`, `proc.pcmdline` |
| `proc.pname` (and the other parent fields) | `proc.aname[1]` and `proc.aname` |
| `fd.cip` and `fd.sip` | `fd.ip`, `fd.net` |
| `fd.cport` and `fd.sport` | `fd.port` |
| `fd.cproto` and `fd.sproto` | `fd.proto` |
| `fd.name` (absolute path) | `fd.directory`, `fd.filename` |

A value you set yourself always wins.

A suite can raise the noise budget for its rule with `max_fire_rate: 0.5` at the top level. Use it for a rule that is meant to fire on routine activity. When several suites set it, the largest value applies.

## Configuration reference

| Key | Default | Meaning |
| --- | --- | --- |
| `rules_files` | required | Rules files in load order. Relative paths resolve from the config file. |
| `base_rules_files` | none | Baseline for the "changes vs base" diff. |
| `tests` | required | Suite files or directories. |
| `plugins` | the container plugin | `name`, `library_path`, `init_config` for each plugin to load. |
| `startup.enabled` | `true` | Run `falco -c <falco_config> --dry-run -r <each rules file>`. |
| `startup.falco_config` | `/etc/falco/falco.yaml` | Your `falco.yaml`, to test your real configuration. |
| `lint.disable` | `[]` | Finding codes to skip. |
| `jev.enabled` | `auto` | `auto` runs Jev only when an API key is set. |
| `jev.model` | `jev-latest` | Jev model name. |
| `jev.gate` | `false` | Fail the run on Jev findings and failed Jev requests. |
| `report.markdown`, `report.json` | `falco-test-report.md`, `.json` | Report paths. |
| `noise.enabled` | `true` | Run each analyzed rule over the ordinary-activity corpus. |
| `noise.max_fire_rate` | `0.05` | Largest share of the ordinary events of a rule's event types that the rule may fire on. A suite's `max_fire_rate` overrides it for that rule. |
| `noise.corpus` | `[]` | Extra corpus files, each a YAML list of events in the suite event format. They join the built-in events. |
| `mutation.enabled` | `true` | Score each tested rule's suites against inversion mutants and generate cases for the survivors. |
| `mutation.min_score` | none | Fail the run when a rule's suites kill a smaller share of its mutants, such as `0.9`. |

`ftest run` exits 1 when Falco fails to start, rules fail to load, a case fails, a rule fires on more ordinary events than its noise budget, or a score is below `mutation.min_score`. With `--strict` it also exits 1 on error-severity findings. It exits 2 on a bad config, suite, or corpus file. When `GITHUB_STEP_SUMMARY` is set, the report is also appended to the job summary.

## Findings

The linter runs on rules under test and on rules that your files add or change compared with `base_rules_files`. Each suggestion says whether it is an equivalent rewrite.

| Code | Finds |
| --- | --- |
| FTE001 | No event-type restriction, or more than 100 event types. Falco evaluates the rule on nearly every event. |
| FTE002 | A top-level negative event type such as `evt.type != open`. |
| FTE003 | `f = a or f = b` that can be one `f in (a, b)` set lookup. |
| FTE004 | `f contains a or f contains b` that can be `f contains anyof (a, b)`. |
| FTE005 | A costly check (ancestor walk, regex, plugin field) evaluated before cheaper ones in the same `and`/`or`. |
| FTE006 | A `regex` or `glob` that is a plain string test. Falco regexes must match the whole value, so `^/usr/bin/x` matches only `/usr/bin/x`. |
| FTE007 | A repeated list item or a repeated predicate. |
| FTE008 | A condition that can never be true. |
| FTE009 | Output fields that rendered `<NA>` on matching cases. |
| FTE010 | Falco's own load warnings. |
| FTE011 | A rule your files add or change that no suite tests. |
| FTE012 | A mutant of the rule that no test case would catch, with a generated case that would. |
| FTE013 | A rule that fires on more ordinary events than its noise budget. It fails the run. |
| FTE900 | An internal consistency error between the engine and the analysis. Please report it. |

Each rule also gets a work metric: the number of predicates evaluated on the test cases, weighted by cost, for the current order and the suggested one. It shows the effect of a reorder on your cases. It is not a production timing.

## Generated events

ftest generates two kinds of events. Neither needs an engine change, and the real engine evaluates both.

**Ordinary activity.** The built-in corpus has 315 benign events from a Kubernetes node. It covers app containers that their runtime or an entrypoint script starts, `sh -c` health checks that curl or wget localhost, config and library reads, log and data writes, DNS and kube-API connects, and host daemons such as the kubelet, containerd, systemd, and journald. None of the 25 stock rules fires on any of them. ftest runs each rule it analyzes over the corpus and reports a share: the events the rule fired on, out of the ordinary events of its event types. Above `noise.max_fire_rate`, the run fails with FTE013 and lists up to three events the rule fired on. For a rule your files change, the line also gives the base version's count.

The check catches a rule that fires broadly. When `proc.name in (package_managers)` in the example rule becomes `not proc.name in (package_managers)`, the rule fires on 15 of the 97 ordinary process starts. When the whole condition is negated, it fires on all 315 events. It does not catch an inversion that matters on few ordinary events, such as a dropped `container` check. Mutation testing covers those.

To add activity your clusters see, list corpus files under `noise.corpus`. Each file is a YAML list of events:

```yaml
- {evt.type: execve, proc.name: apt-get, proc.aname: [sh, containerd-shim], container.id: 1f2e3d4c5b6a, container.image.repository: ghcr.io/acme/ci-runner}
```

**Cases that catch inversions.** For each tested rule, ftest makes mutants of the compiled condition. A mutant inverts one part or removes its `not`, swaps `and` and `or`, or drops one part. ftest also inverts and drops each exception. A stock macro is one part. A macro your files define or change is mutated inside too. A mutant is killed when one of the rule's test cases would fail under it. The engine's per-check values for each case decide this, so scoring costs no extra engine run.

For each surviving mutant, ftest searches for an event on which the rule and the mutant disagree. It starts from a test case and changes as few fields as it can. It sends every candidate to the engine and keeps one only when the engine's values separate the rule from the mutant. The report shows it as a case ready to paste. With the "yum on the host is out of scope" case deleted from the example suite, the report says:

```
- FTE012 (warning): your tests would not catch dropping macro `container`.
  The current rule says no_match here; confirm that is what you want, then add it to your suite. ...

  - name: apt-get from bash in nginx, with container.id=host
    expect: no_match
    event: {proc.name: apt-get, proc.cmdline: apt-get install -y curl, container.id: host}
```

The `expect` value is what the current rule does on the event. ftest cannot know what you meant the rule to do, so confirm each one. If the rule is wrong, fix the rule and keep the case with the corrected `expect`. To write all of a rule's generated cases to a suite file:

```sh
docker run --rm -v "$PWD:/work" ghcr.io/pogao/falco-test-engine generate "Package manager run in container" -o tests/package_manager_generated.yaml
```

## Jev review

[Jev](https://docs.typesafe.ai) is TypeSafe's decision model. It answers typed yes/no and choice questions about a document. Jev is weak at negation and boolean logic, so it never reads a rule's condition. The engine evaluates conditions. Jev judges the events instead.

**Does the suite's `intent` call for an alert on this event?** For each test case and each generated case, ftest sends Jev the suite's `intent` and the event's fields as the suite writes them. It sends nothing else: not the case name, not its `expect`, and not the rule. Jev answers two questions. Is the event the activity the intent asks to alert on? Does it match an exception the intent names? An event in scope with no exception calls for an alert. A clear no to the first or a clear yes to the second calls for none. Anything between is unsure. ftest compares the call with what the rule's condition matched. The report counts the events and lists only those that need a look:

- A case where Jev disputes the rule. If the case passes, the rule and the case may both be wrong, or the intent may be vague. If the case fails, Jev sides with the case, and the rule is the likely culprit.
- A failing case where Jev sides with the rule. Check the case's `expect`.
- A generated case where Jev disputes the rule. Its `expect` only copies the rule, so the rule may have a bug there:

```
- finding: generated case `kubectl exec bash into nginx, with proc.pname=sh`: the rule says no_match; Jev reads the intent as match (in scope p=0.92, exception p=0.04). Its `expect` only copies the rule, so this may be a rule bug: if Jev is right, set `expect: match` and fix the rule.
```

Jev judges only events whose suite states an `intent`. An intent that starts with `TODO`, as `ftest scaffold` writes it, counts as none. The report names each suite it skipped. Write the intent the way you would explain the rule to a reviewer: what it must catch, where, and each exception.

`ftest generate` writes Jev's call as a comment above each case it writes, and prints each case where Jev disputes the rule. Pass `--no-jev` to skip it.

**Which priority fits the rule?** Jev judges this from the rule's `desc` and what it does, without seeing the declared priority. ftest then compares the answer with the declared one.

Each event is its own request, so no other event sits in Jev's state. A run sends one request per rule under test and one per judged event: 27 on the examples. ftest sends four at a time. A failed request costs only its own answer.

The review is advisory. With `jev.gate: true`, the run fails when Jev disputes a rule's verdict on any event, when a priority is two or more levels off, or when a request fails. Set the key in `JEV_API_KEY` (or TypeSafe's own `TYPESAFE_API_KEY`). `JEV_BASE_URL` overrides `https://api.typesafe.ai`. With no key, the report says Jev was skipped.

## Use it in CI

This repo publishes `ghcr.io/pogao/falco-test-engine` from `main`. To test a rules repo on every pull request, call the reusable workflow:

```yaml
# .github/workflows/falco-rules.yml in your rules repo
on: [pull_request]
jobs:
  falco-rules:
    uses: pogao/falco-test-engine/.github/workflows/test-rules.yml@main
    permissions: {contents: read, packages: read, pull-requests: write}
    secrets: inherit
```

The workflow runs `ftest`, uploads the report, posts it as a pull request comment (updating the comment on later pushes), and fails the check on failures.

Both this repo and its image are private. To use them from another repo:

1. In this repo, open **Settings > Actions > General > Access** and allow access from your repositories.
2. In the package settings for `falco-test-engine`, add the rules repo under **Manage Actions access**.

## Upgrade Falco

Change `ARG FALCO_VERSION` in the `Dockerfile` and rebuild. The engine refuses to start if libsinsp's filter checks change shape, and CI runs `engine/test/run.sh` against the new stock rules. Fix what they report, then update the version numbers in this README.

## Develop

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest                                   # Python unit and CLI tests
docker build --target builder -t fte-builder .
docker run --rm fte-builder /src/falco/userspace/falco-test-engine/test/run.sh   # engine tests
docker build -t falco-test-engine:dev . && scripts/e2e.sh                         # image against the examples
```

After a change to `ftest/corpus.py`, check that the corpus stays benign. This prints every loaded rule's fire count on the corpus, from the real engine:

```sh
docker run --rm -v "$PWD/examples:/work" -v "$PWD/scripts:/scripts" -e PYTHONPATH=/opt/ftest \
	--entrypoint python3 falco-test-engine:dev /scripts/noise_calibration.py -c falco-test.yaml
```
