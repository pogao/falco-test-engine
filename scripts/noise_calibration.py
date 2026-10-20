"""Fire count of every loaded rule on the built-in ordinary-activity corpus, from the real engine.

Run it in the image, from a rules repo mounted at /work:

    docker run --rm -v "$PWD/examples:/work" -v "$PWD/scripts:/scripts" -e PYTHONPATH=/opt/ftest \
      --entrypoint python3 falco-test-engine:dev /scripts/noise_calibration.py -c falco-test.yaml

Use it to check that a corpus change keeps benign events benign, and to re-derive the default
noise budget (ftest/config.py, DEFAULT_MAX_FIRE_RATE).
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

from ftest.config import load_config
from ftest.corpus import builtin, load_corpus
from ftest.engine import CaseError, JobCase, build_job, run_engine


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("falco-test.yaml"))
    parser.add_argument("--examples", type=int, default=0, help="print this many fired events per rule")
    args = parser.parse_args()
    cfg = load_config(args.config)
    events = builtin() + load_corpus(cfg.noise.corpus, cfg.root)
    result = run_engine(
        cfg.engine_binary, build_job(cfg.rules_files, cfg.plugins, [JobCase(e, None) for e in events])
    )
    if not result.load.ok:
        print("rules failed to load", file=sys.stderr)
        return 1
    rejected = [r for r in result.cases.values() if isinstance(r, CaseError)]
    for r in rejected:
        print(f"rejected {r.id}: {r.error}", file=sys.stderr)
    usable = [e for e in events if not isinstance(result.cases.get(e.id), CaseError)]
    counts = Counter(a.rule for e in usable for a in result.cases[e.id].alerts)
    print(f"{len(usable)} ordinary events, {len(rejected)} rejected")
    print(f"{'fired':>5}  {'seen':>4}  {'share':>6}  rule (seen: ordinary events of the rule's event types)")
    for name, rule in sorted(result.rules.items(), key=lambda kv: (-counts[kv[0]], kv[0])):
        seen = sum(1 for e in usable if e.event["evt.type"][0] in rule.evttypes)
        share = f"{counts[name] / seen:.1%}" if seen else "-"
        state = "" if rule.enabled else "  (disabled)"
        print(f"{counts[name]:>5}  {seen:>4}  {share:>6}  {name}{state}")
        shown = 0
        for e in events:
            run = result.cases.get(e.id)
            if shown < args.examples and not isinstance(run, CaseError) and run.alert_for(name):
                print(f"         {e.name}")
                shown += 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
