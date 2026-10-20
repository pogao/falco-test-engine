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

good="$WORK/good-report.md"
check "the example rules fire on no ordinary event" "grep -q '^- Noise: 3 rules checked on 315 ordinary events; none over budget.' $good"
check "the example suites kill 42 of 48 mutants" "grep -q '^- Test strength: 42 of 48 mutants killed across 3 rules; 6 survived, 6 with a generated case.' $good"

# A fresh copy of examples/ in $WORK/$1, run with the remaining arguments.
variant() {
	rm -rf "${WORK:?}/$1"
	cp -R "$ROOT/examples/." "$WORK/$1/"
}
run_variant() {
	docker run --rm -v "$WORK/$1:/work" "$IMAGE" run -c falco-test.yaml --no-jev > "$WORK/$1.out" 2>&1
}
PKG_RULES=rules/custom_rules.yaml
PKG_SUITE=tests/package_manager_in_container.yaml

for tests in with without; do
	variant "inverted-list-$tests"
	perl -pi -e 's/^    and proc\.name in \(package_managers\)/    and not proc.name in (package_managers)/' "$WORK/inverted-list-$tests/$PKG_RULES"
	variant "inverted-whole-$tests"
	perl -0pi -e 's/(condition: >\n)    (spawned_process\n    and proc\.aname in \(sh, bash\)\n(?:    .*\n)*?    and not container\.image\.repository = ghcr\.io\/acme\/ci-runner)\n/$1    not ($2)\n/' "$WORK/inverted-whole-$tests/$PKG_RULES"
	if [ $tests = without ]; then rm "$WORK/inverted-list-$tests/$PKG_SUITE" "$WORK/inverted-whole-$tests/$PKG_SUITE"; fi
done
check "variant setup: package_managers is negated" "grep -q '    and not proc.name in (package_managers)' $WORK/inverted-list-with/$PKG_RULES"
check "variant setup: the whole condition is negated" "grep -q '^    not (spawned_process' $WORK/inverted-whole-with/$PKG_RULES"
for v in inverted-list inverted-whole; do
	run_variant "$v-with"
	check "$v with its suite fails" "[ $? -eq 1 ] && grep -q 'test cases\{0,1\} failed' $WORK/$v-with/falco-test-report.md"
	run_variant "$v-without"
	check "$v without tests fails through the noise check" "[ $? -eq 1 ] && grep -q '^\*\*FAIL\*\*: 1 rule over the noise budget.' $WORK/$v-without/falco-test-report.md"
done
check "the inverted list fires on 15.5% of ordinary execs" "grep -q '^\*\*Noise.\*\* FAIL. Fired on 15 of the 97 ordinary events of its event types (15.5%), over the 5% budget.' $WORK/inverted-list-without/falco-test-report.md"
check "the inverted condition fires on every ordinary event" "grep -q '^\*\*Noise.\*\* FAIL. Fired on 315 of the 315 ordinary events of its event types (100%), over the 5% budget.' $WORK/inverted-whole-without/falco-test-report.md"
check "the noise finding says the rule is likely inverted" "grep -q 'FTE013 (error): fires on 100% of ordinary activity.*likely inverted' $WORK/inverted-whole-without/falco-test-report.md"

variant weakened
perl -0pi -e 's/  - name: yum on the host is out of scope\n    expect: no_match\n    event: \{proc\.name: yum, container\.id: host\}\n//' "$WORK/weakened/$PKG_SUITE"
check "weakened setup: the host case is gone" "! grep -q 'yum on the host' $WORK/weakened/$PKG_SUITE"
run_variant weakened
weak="$WORK/weakened/falco-test-report.md"
check "without the host case, dropping container survives" "grep -qF -- '- FTE012 (warning): your tests would not catch dropping macro \`container\`.' $weak"
check "its generated case moves the event to the host" "grep -qF -- '  - name: apt-get from bash in nginx, with container.id=host' $weak && grep -qF 'changes \`container.id\` from \`9f2c51b0a1d4\` to \`host\`' $weak"
check "with the host case, dropping container is killed" "! grep -qF 'not catch dropping macro \`container\`.' $good"
docker run --rm -v "$WORK/weakened:/work" "$IMAGE" generate "Package manager run in container" -c falco-test.yaml > "$WORK/generate.out" 2>&1
run_variant weakened
check "the generated suite kills every mutant of the rule" "grep -qF '**Test strength.** 12 of 12 mutants killed (100%).' $weak"

if [ "$failures" -ne 0 ]; then
	echo "--- good run"; cat "$WORK/good.out"; echo "--- broken run"; cat "$WORK/broken.out"
fi
echo "$failures failure(s)"
exit $((failures > 0))
