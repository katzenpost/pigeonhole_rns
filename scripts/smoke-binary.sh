#!/bin/sh
# Smoke test a built replica_rns executable: help, new-cap, and the two-replica
# end to end test with the executable as both replicas.
#     scripts/smoke-binary.sh dist/replica_rns-VERSION-linux-x86_64 SCRATCH_DIR
set -eu
bin=$(realpath "$1")
run=$2
rm -rf "$run" && mkdir -p "$run"

timeout 60 "$bin" --help | grep -q "Pigeonhole storage replica"
timeout 60 "$bin" new-cap | grep -q "^writecap [0-9a-f]"
timeout 900 python "$(dirname "$0")/../tests/e2e_two_replicas.py" --run-dir "$run/e2e" --replica-bin "$bin"
echo "smoke: ok"
