#!/bin/bash
# Runs inside the builder image, which carries the stock rules and container plugin in /opt/falco:
#   docker run --rm -v "$PWD/engine:/src/falco/userspace/falco-test-engine" fte-builder bash -c \
#     'cd /src/falco/build && make falco-test-engine >/dev/null && ../userspace/falco-test-engine/test/run.sh'
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
engine=${1:-/src/falco/build/userspace/falco-test-engine/falco-test-engine}
exec python3 -I "$here/check.py" "$engine" "$here"
