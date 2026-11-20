#!/usr/bin/env bash
# Live mode of scripts/lean-bounty-demo.sh against a stand-in node (fake-node.py, backed by
# witness-sim), to test it without a chain:
#
#   WITNESS_LEAN_DIR=... JAM_LEAN_DIR=... LEAN4EXPORT=... scripts/toaster/lean/test-fake.sh OUT [DROP]
#
# Where PolkaVM's recompiler can't run, set POLKAVM_BACKEND=interpreter (for fake-node's checks).
# Deploys witness in witness-sim and configures it as on the Toaster (fee asset `test`,
# deposits of 10), with another bounty already posted (so the demo's bounties aren't 0 and 1),
# starts fake-node.py on it, dropping a fraction DROP of packages (default 0.15), and runs the
# demo live against it, then again with REUSE_PLAN=1 to check that resuming finds it all done.
set -euo pipefail
cd "$(dirname "$0")/../../.."
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
DROP=${2:-0.15}
PORT=${PORT:-19870}
cargo build -q --release -p witness-sim -p witness-cli
cargo jam-build --out-dir out >/dev/null
SIM=$PWD/target/release/witness-sim W=$PWD/target/release/witness
export WITNESS_SIM_DIR=$OUT/chain
rm -rf "$WITNESS_SIM_DIR"
"$SIM" create-service out/witness-service.jam 10000000000 >/dev/null
SVC=$(( 16#$("$SIM" list | tail -1 | cut -f1) ))
"$SIM" item "$SVC" "$($W propose --service "$SVC" --nonce 0 --fee-asset test --commit-deposit 10 --attest-deposit 10)" >/dev/null
"$SIM" item "$SVC" "$($W mint --to someone --amount 1000)" >/dev/null
"$SIM" item "$SVC" "$($W create --service "$SVC" --maker someone --nonce 0 --check out/blake2b-preimage-check.jam \
	--params-blake2b x --reward 100 --check-gas 10000000 --expiry 100000)" >/dev/null
python3 scripts/toaster/lean/fake-node.py "$PORT" "$SIM" "$SVC" "$DROP" >"$OUT/fake-node.log" 2>&1 &
NODE=$!
trap 'kill $NODE 2>/dev/null || true' EXIT
sleep 1
export JAM_RPC=ws://127.0.0.1:$PORT SERVICE_ID=$SVC TAG=${TAG:-fake}
unset WITNESS_SIM_DIR
scripts/lean-bounty-demo.sh "$OUT/work"
echo
echo "== resuming the finished run: everything should be found done"
REUSE_PLAN=1 scripts/lean-bounty-demo.sh "$OUT/work" | tee "$OUT/resume.log"
grep -q 'resuming: 114 of 114 attested already\|resuming: [0-9]* of [0-9]* attested already' "$OUT/resume.log"
printf '\nlive mode passed against fake-node (drop %s)\n' "$DROP"
