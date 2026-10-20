#!/usr/bin/env bash
# Runs the published image against examples/ and asserts on the real engine's verdicts.
set -uo pipefail

IMAGE=${1:-falco-test-engine:dev}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp -R "$ROOT/examples/." "$WORK/"
failures=0

check() {
	if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; failures=$((failures + 1)); fi
}

ftest() {
	docker run --rm -v "$WORK:/work" "$IMAGE" "$@"
}

ftest run -c falco-test.yaml --no-jev > "$WORK/good.out" 2>&1
check "good rules pass" "[ $? -eq 0 ]"
good="$WORK/falco-test-report.md"
check "real falco --dry-run passed" "grep -q '^- Startup: passed' $good"
check "all good cases pass" "grep -q '^- Tests: 18 of 18 cases passed' $good"
check "stock override shows as a change" "grep -q 'Changed vs base: condition changed' $good"
check "ancestor walk before cheap checks is flagged" "grep -q 'FTE005 (warning): \`proc.aname in (sh, bash)\`' $good"
check "or-chain on fd.sip folds into in" "grep -q 'fd.sip in (169.254.169.254, 169.254.170.2)' $good"
check "duplicate list item is flagged" "grep -q 'FTE007 (info): list \`metadata_allowed_images\`' $good"
cp "$good" "$WORK/good-report.md"

ftest run -c falco-test.broken.yaml --no-jev > "$WORK/broken.out" 2>&1
check "broken rules fail the run" "[ $? -eq 1 ]"
bad="$WORK/falco-test-report.md"
check "and/or precedence bug: yum on the host fires" "grep -q 'FAIL \`yum on the host is out of scope\`' $bad"
check "and/or precedence bug: rule matches every event type" "grep -q 'FTE001 (warning): matches 465 event types' $bad"
check "broad exception: other acme images stop alerting" "grep -q 'FAIL \`other acme images still alert\`' $bad"
check "full-match regex: aws-node with args still fires" "grep -q 'FAIL \`aws-node binary in a sidecar image is allowed\`' $bad"
check "full-match regex is explained" "grep -q 'FTE006 (warning): \`proc.cmdline regex ^/usr/bin/aws-node\` only matches the exact value' $bad"

printf -- '- rule: Broken\n  desc: x\n  condition: evt.type = execve and proc.nmae = bash\n  output: x\n  priority: WARNING\n' > "$WORK/rules/bad_field.yaml"
printf 'rules_files: [/etc/falco/falco_rules.yaml, rules/bad_field.yaml]\ntests: [tests/]\n' > "$WORK/falco-test.badfield.yaml"
ftest run -c falco-test.badfield.yaml --no-jev > "$WORK/badfield.out" 2>&1
check "unknown field fails startup and load" "[ $? -eq 1 ] && grep -q 'proc.nmae' $WORK/falco-test-report.md"

ftest scaffold "Terminal shell in container" -c falco-test.yaml -o tests/scaffolded.yaml > /dev/null 2>&1
check "scaffold lists the fields the rule reads" "grep -q 'proc.tty' $WORK/tests/scaffolded.yaml"

if [ "$failures" -ne 0 ]; then
	echo "--- good run"; cat "$WORK/good.out"; echo "--- broken run"; cat "$WORK/broken.out"
fi
echo "$failures failure(s)"
exit $((failures > 0))
