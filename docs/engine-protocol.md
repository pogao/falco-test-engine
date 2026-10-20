# Engine protocol

`falco-test-engine` is a thin adapter around Falco's own `falco_engine` and libsinsp. It reads one job as JSON and writes one result as JSON. The Python CLI (`ftest`) builds jobs and interprets results. Everything that needs Falco semantics happens in the engine. Everything else (suites, analysis, reports, Jev) happens in Python.

```
falco-test-engine --job job.json      # or job on stdin
```

Exit code 0 means the job was processed, even if the rules failed to load (load errors are data). Exit code 2 means the harness itself failed (unreadable or malformed job, unreadable rules file, plugin failed to load or init). On exit code 2 stdout is `{"fatal": "<message>"}`.

## How evaluation works

Rules are loaded, resolved, and compiled by the unmodified Falco 0.45.1 rule loader against the real field schema: the libsinsp syscall filterchecks plus the filterchecks of each loaded plugin (the container plugin supplies `container.*` and `k8s.*`). Each filtercheck is wrapped so that field extraction reads values from the test case instead of the kernel. Parsing, operators, list and macro resolution, exceptions, overrides, transformers, comparison semantics, and the event-type index are all Falco's.

Two fields get special handling because libsinsp gives them "any of" semantics: the unindexed ancestor fields (`proc.aname`, `proc.apid`, `proc.aexe`, `proc.aexepath`, `proc.acmdline`) and the client-or-server fd fields (`fd.ip`, `fd.port`, `fd.net`, `fd.proto`). When a case supplies several values for one of these non-list fields, the check is true if it is true for any one value, as libsinsp does. The engine applies the same rule to every non-list field. For the other fields Falco extracts at most one value, so several values describe an event Falco never produces. Several values for a field that is compared against another field (`val(...)`) are a case error.

A field the rule reads but the case does not supply is unavailable, as when Falco cannot extract it. The comparison is false, so `not` over it is true. Such fields are reported in `missing_fields`.

## Job

```json
{
  "rules_files": ["/etc/falco/falco_rules.yaml", "/work/rules/custom.yaml"],
  "plugins": [
    {"name": "container", "library_path": "/usr/share/falco/plugins/libcontainer.so", "init_config": "{}"}
  ],
  "describe": true,
  "cases": [
    {
      "id": "tests/shell.yaml::bash in nginx",
      "source": "syscall",
      "fields": {
        "evt.type": ["execve"],
        "proc.name": ["bash"],
        "proc.aname": ["containerd-shim", "systemd"]
      },
      "trace_rules": ["Terminal shell in container"]
    }
  ]
}
```

- `rules_files` load in order into one engine, as Falco does with `rules_files`.
- Every field value is a list of strings. A single value is a one-element list.
- `source` is `syscall`. The event code comes from `evt.type`, which syscall cases must set.
- `trace_rules` names the rules whose leaf-level evaluation the engine reports for this case.
- Optional keys and their defaults: `plugins` `[]`, `init_config` `""`, `describe` `false`, `cases` `[]`, `source` `"syscall"`, `trace_rules` `[]`.

## Result

```json
{
  "versions": {"falco": "0.45.1", "engine": "0.65.0", "libs": "0.26.1", "plugins": {"container": "0.7.5"}},
  "load": {
    "successful": true,
    "results": ["<falco::load_result::as_json for each file, in load order>"]
  },
  "plugin_requirements": {"ok": true, "error": ""},
  "describe": "<falco_engine::describe_rule(nullptr, plugins) output; omitted unless load succeeded and describe=true>",
  "rules": [
    {
      "name": "Terminal shell in container",
      "source": "syscall",
      "enabled": true,
      "priority": "NOTICE",
      "evttypes": ["execve", "execveat"],
      "condition_raw_ast": "<AST of the rule's condition as written, macros kept as identifiers>",
      "condition_ast": "<AST of the compiled condition: macros, lists, and exceptions resolved; checks carry leaf ids>",
      "leaf_count": 11
    }
  ],
  "cases": [
    {
      "id": "tests/shell.yaml::bash in nginx",
      "error": null,
      "unknown_fields": [],
      "matched_rules": [
        {"name": "Terminal shell in container", "priority": "NOTICE", "output": "<output formatted with the case's values>"}
      ],
      "traces": {
        "Terminal shell in container": {
          "result": true,
          "leaves": [true, false, true],
          "missing_fields": ["proc.pname"]
        }
      }
    }
  ]
}
```

- `load.results` stops at the first file that fails, as Falco does. When load fails, `rules` and `cases` are empty and `describe` is omitted.
- `plugin_requirements` is reported but does not gate evaluation.
- `rules` lists every loaded rule, enabled or not, when load succeeded. `condition_raw_ast` is null when the raw condition only parses after Falco substitutes its lists.
- `evttypes` is the set of syscall event names the rule's compiled condition can match, sorted, from libsinsp's `event_set_to_names` (a generic event expands to every generic syscall name). An empty list means the condition can never match.
- `matched_rules` is every enabled rule that fires on the case, from `falco_engine::process_event` over the default ruleset with the all-matches strategy. `output` is the rule's message as Falco formats it, without the time and priority prefix. A field the case omits prints as `<NA>`. A non-list field with several values prints its first value.
- `traces[rule].result` is the rule's compiled filter run on the case. `leaves[i]` is the truth value of compiled-AST check `i`, evaluated on its own, without short-circuiting. The Python side recomputes `result` from `leaves` and the AST and flags any disagreement. `missing_fields` is every field the compiled condition reads that the case does not supply, sorted.
- `unknown_fields` lists case field names Falco does not know. A case has a non-null `error` when it has unknown fields, an unparseable value, a `source` other than `syscall`, or an unknown rule in `trace_rules`. It also has one when `evt.type` is missing, is not an event name, or has more than one value. Such a case has empty `matched_rules` and `traces` and no other results.

## AST

Nodes are JSON objects with a `type`:

| type | members |
| --- | --- |
| `and`, `or` | `children`: nodes |
| `not` | `child`: node |
| `identifier` | `name`: macro name (raw AST only) |
| `check` | `id` (compiled AST only, depth-first order from 0), `op`, `lhs`, and `rhs` unless `op` is `exists` |
| `field` | `field`, `arg` (string or null) |
| `transformer` | `name` (`tolower`, `val`, ...), `args`: nodes, `arg` (string or null) |
| `transformer_list` | `children`: nodes (a parenthesized list of fields or values inside a transformer) |
| `value` | `value`: string |
| `list` | `values`: strings |

Example check: `proc.name in (bash, sh)` is

```json
{"type": "check", "id": 3, "op": "in",
 "lhs": {"type": "field", "field": "proc.name", "arg": null},
 "rhs": {"type": "list", "values": ["bash", "sh"]}}
```
