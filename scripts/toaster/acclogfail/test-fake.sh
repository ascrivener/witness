#!/usr/bin/env bash
# Live mode of scripts/toaster/acclogfail/post.sh against a stand-in node (scripts/toaster/lean/
# fake-node.py, backed by witness-sim), to test it without a chain:
#
#   WITNESS_LEAN_DIR=... JAM_LEAN_DIR=... LEAN4EXPORT=... scripts/toaster/acclogfail/test-fake.sh OUT [DROP]
#
# Where PolkaVM's recompiler can't run, set POLKAVM_BACKEND=interpreter. Deploys witness in
# witness-sim and configures it as on the Toaster, with another bounty already posted (so this one
# isn't bounty 0), starts fake-node.py on it, dropping a fraction DROP of packages (default 0.15),
# and posts the bounty live against it; then runs again, which must find it all done.
set -euo pipefail
cd "$(dirname "$0")/../../.."
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
DROP=${2:-0.15}
PORT=${PORT:-19871}
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
scripts/toaster/acclogfail/post.sh "$OUT/work"
grep -q '^bounty=1$' "$OUT/work/state" || { echo "FAIL: the bounty should be bounty 1"; exit 1; }
echo
echo "== running again: everything should be found done"
scripts/toaster/acclogfail/post.sh "$OUT/work" | tee "$OUT/resume.log"
grep -q 'resuming: [0-9]* of [0-9]* attested already' "$OUT/resume.log"
grep -q '(bounty 1, posted in an earlier run)' "$OUT/resume.log"
printf '\nAccLogFail posting passed against fake-node (drop %s)\n' "$DROP"
