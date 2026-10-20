# About testing rules with field values

A Falco rule fails in production for one of two reasons. Either libsinsp computes a field differently than the author assumed, or the rule's logic is wrong. Logic covers precedence, an exception that is too broad, a macro override that changed meaning, or a list the rule no longer uses. Rule changes go wrong in their logic far more often, and logic is what this project tests.

## Why field values and not syscalls

There are three ways to feed a rule an event without a running cluster:

| Approach | What a test author writes | What it proves |
| --- | --- | --- |
| Replay a `.scap` capture through Falco | Nothing; they record a capture on a real host | Everything, for the one capture you have |
| Build synthetic syscall events for libsinsp | Syscall numbers, parameters, fd tables, process trees | Extraction and logic, at a high authoring cost |
| Inject field values into Falco's filter checks | The field values the rule reads | Logic, exactly as Falco evaluates it |

Rule authors think in fields. They write `proc.name in (shell_binaries) and container.id != host`, not "an `execve` exit event whose thread has comm `bash` and a cgroup with a container ID". A test that speaks the rule's language is one that people write and keep up to date. Captures are worth adding later for a handful of high-value rules. They are hard to produce for the "should not fire" cases that catch over-broad exceptions.

## What stays real

The engine wraps each libsinsp filter check class, `fixture_check<Real>`, and overrides only extraction. Everything else is Falco 0.45.1:

- The rule loader: YAML schema, `required_engine_version`, `required_plugin_versions`, `override`, `append`, and `exceptions`.
- List substitution, macro resolution, and the compiled condition AST.
- Field name parsing, including arguments and transformers, and type checks on constants.
- Operators and comparison code, including `in` set lookups, `pmatch`, RE2 full-match `regex`, `glob`, and the `anyof`/`allof` modifiers.
- The event-type index that decides which rules see which event, and output formatting.

The field schema is real too. The engine loads the container plugin, so `container.*` and `k8s.*` rules compile against the same fields as in production. At startup the engine checks that its wrapped filter checks match libsinsp's field list, so a libs upgrade cannot drift silently.

On top of that, `ftest` runs the real `falco` binary with `--dry-run` against the same rules files. That catches startup failures that live outside the rule engine, such as configuration errors and plugin loading.

## What is not tested

- **Extraction itself.** If a case says `proc.pname: runc`, the rule sees `runc`. Whether a real container start produces `runc` is Falco's concern. Write cases from real alerts: copy the field values from an alert's output.
- **Consistency between fields.** Nothing stops a case from setting `proc.pname: runc` and `proc.aname[1]: bash`. The derivation table fills related fields from one source to make this rare.
- **Event-derived fields.** `evt.dir`, `evt.num`, `evt.time`, and `evt.category` exist only if the case sets them.
- **Plugin event-type gates.** A real plugin extracts only for the event types it declares. A case value applies to any event type.
- **Non-syscall sources.** Cases run on the `syscall` source only. Rules for plugin sources such as `k8s_audit` load and lint when you list their plugin in `plugins`, but they cannot have cases yet.

## Why every leaf is evaluated

For each traced rule, the engine also compiles every leaf of the compiled condition into its own filter and records its truth value. Two things depend on this. First, `ftest` recomputes the rule's result from the leaves and the AST. A mismatch is reported as FTE900, so the analysis cannot drift from the engine unnoticed. Second, the leaf values drive coverage ("this exception was never true in any case") and the work metric, which replays short-circuit evaluation in any order without running the engine again.

## Why rules also run on ordinary activity

A test case proves a rule right on the events someone thought to write down. An inverted rule passes every test that nobody wrote. Picture a `not` added in the wrong place. The rule ignores what it should catch and fires on everything else, and the suite passes when it only checks the attack. A rule with no suite passes trivially. Ordinary activity needs no one to have anticipated the mistake, so ftest runs every rule it analyzes over a corpus of benign events.

The built-in corpus (`ftest/corpus.py`) crosses activity templates with a table of workloads. The templates are process starts, entrypoint helpers, exec probes, file reads, file writes, and connects. The workloads are app pods, kube-system add-ons, and host daemons. Each event sets the fields libsinsp always has for a syscall event, such as `proc.name`, `proc.aname`, `user.uid`, `container.id`, and `fd.typechar`. That matters because a field the event leaves out makes every check on it false, so `not` over it is true. An event without `proc.name` would make `not proc.name in (...)` fire for a reason that never happens in production.

The share ftest reports counts only the ordinary events of the rule's event types, which are the events Falco would evaluate the rule on. A share of the whole corpus would mostly measure the corpus's mix: 146 of its 315 events are file opens. An inverted process rule would then look quiet next to them.

The default budget, 5%, comes from running every loaded rule over the corpus with the real engine (`scripts/noise_calibration.py`). All 25 stock rules and the example rules fire on no ordinary event. Inversions that make a rule fire broadly land between 14.4% and 100%. One benign false positive costs between 0.7% and 1.4%, depending on the event type, so 5% lets a correct but untuned rule have three or four of them. The budget sits three times below the smallest broad inversion measured.

The check has limits, and they follow from what it measures:

- It counts kinds of activity, not their volume. A health check appears once per pod here and runs every ten seconds in production, so a rule that fires on it looks rare here and is loud there.
- It covers `execve`, `openat`, and `connect` only. Seven stock rules watch event types the corpus lacks, such as `ptrace` and `symlink`, so their 0 says nothing. Add corpus files for the activity your rules watch.
- It misses an inversion that only matters for a few ordinary events. Dropping `container` from the example package-manager rule fires on 2 of the 97 process starts, the host's security patching. Test cases have to catch that, which is the next section.

## Why ftest mutates rules

A suite that passes may still miss the bug the next change introduces. Mutation testing measures that directly. ftest makes small inversions of the rule, called mutants, and asks whether some test case would fail under each one. A suite that kills every mutant notices each of those single changes to the rule's own logic.

Mutants only restructure the compiled condition. They negate a part, swap `and` and `or`, or drop a part, and they never add a check. The engine already reports the truth value of every check for every case, so ftest evaluates each mutant in Python with no extra engine run. This is the same arithmetic the FTE900 consistency check uses to recompute the rule's own result.

ftest mutates what you wrote, not what you inherited. Each stock macro your rule uses is one part, negated or dropped as a whole. A macro your files define or change is mutated inside too, because its insides are yours to test.

## Who decides what a generated case expects

For a surviving mutant, ftest searches for an event on which the rule and the mutant disagree. It starts from a test case's real check values, flips one check, then two, then three, and turns the flipped checks back into field values. The operator model behind that step only guides the search. Falco's comparisons have details the model does not reproduce, and checks with `regex`, transformers, or `val()` are never flipped. So the engine evaluates every candidate, and ftest keeps one only when the engine's own check values separate the rule from the mutant.

The engine proves that the event tells the two apart. It cannot say which of the two is right. The generated case's `expect` is what the current rule does, and the report asks you to confirm it. If the rule is wrong on that event, the generated case is wrong in the same way, and confirming it is how you find out. ftest never presents a generated expectation as your intent. When no candidate separates the two, the report says so. The mutant may then mean the same as the rule, as when one check implies another.
