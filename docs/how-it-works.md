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
