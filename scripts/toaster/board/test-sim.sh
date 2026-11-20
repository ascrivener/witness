#!/usr/bin/env bash
# Test the bounty board's snapshot (snapshot.py) without a chain: deploys witness in witness-sim,
# configured as on the Toaster (fee asset `test`, deposits of 10), with a bounty in each status
# (Claimed, Open, Revealing, Reclaimed, one Open past its expiry, and one citing blobs) and a pending proposal; serves
# it through scripts/toaster/lean/fake-node.py and runs snapshot.py against that. Then checks every
# value snapshot.py decoded against `witness decode`'s, and the storage keys it reads against
# `witness key`'s.
#
#   scripts/toaster/board/test-sim.sh OUT
#
# Needs cargo-jam-build 0.1.29 (for the service and the Blake2b check). Where PolkaVM's recompiler
# can't run, set POLKAVM_BACKEND=interpreter.
set -euo pipefail
cd "$(dirname "$0")/../../.."
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
PORT=${PORT:-19871}
cargo build -q --release --locked -p witness-sim -p witness-cli
cargo jam-build --out-dir out -- --locked >/dev/null
SIM=$PWD/target/release/witness-sim W=$PWD/target/release/witness
CHECK=out/blake2b-preimage-check.jam
GAS=10000000
export WITNESS_SIM_DIR=$OUT/chain
rm -rf "$WITNESS_SIM_DIR"
"$SIM" create-service out/witness-service.jam 10000000000 >/dev/null
SVC=$(( 16#$("$SIM" list | tail -1 | cut -f1) ))
item() { "$SIM" item "$SVC" "$@" | tail -1; }
slot() { "$SIM" inspect slot; }
wait_slot() { while [ "$(slot)" -lt "$1" ]; do :; done; }
create() { # NONCE SECRET REWARD EXPIRY [ARGS...]
	local nonce=$1 secret=$2 reward=$3 expiry=$4; shift 4
	item "$($W create --service "$SVC" --maker maker --nonce "$nonce" --check $CHECK --params-blake2b "$secret" \
		--reward "$reward" --check-gas $GAS --expiry "$expiry" "$@")"
}
commit_reveal() { # BOUNTY SECRET HUNTER NONCE
	local x payload; x=$(mktemp -d)
	item "$($W commit --service "$SVC" --bounty "$1" --hunter "$3" --nonce "$4" --salt 0x5a17 --witness-str "$2" 2>/dev/null)"
	wait_slot $(( $(slot) + 2 ))
	# The payload first: its extrinsic files must exist before the glob is expanded.
	payload=$($W reveal --bounty "$1" --check $CHECK --params-blake2b "$2" --check-gas $GAS --hunter "$3" \
		--salt 0x5a17 --witness-str "$2" --extrinsics "$x")
	item "$payload" "$x"/*
	rm -rf "$x"
}

item "$($W propose --service "$SVC" --nonce 0 --fee-asset test --commit-deposit 10 --attest-deposit 10)"
item "$($W mint --to maker --amount 1000000)"
item "$($W mint --to maker --amount 1000000)"
item "$($W mint --to hunter --amount 1000)"
# 0: claimed.
create 0 "secret 0" 100 $(( $(slot) + 500 ))
commit_reveal 0 "secret 0" hunter 0
wait_slot $(( $(slot) + 32 ))
item "$($W finalize --bounty 0)"
# 1: open, with a claim window and disclosure window of its own.
create 1 "secret 1" 250 $(( $(slot) + 100000 )) --claim-window 40 --disclosure-window 7
# 2: revealing.
create 2 "secret 2" 300 $(( $(slot) + 100000 ))
commit_reveal 2 "secret 2" hunter 1
# 3: reclaimed, once its reveal window has passed (expiry + REVEAL_GRACE, 20).
create 3 "secret 3" 400 $(( $(slot) + 3 ))
wait_slot $(( $(slot) + 25 ))
item "$($W reclaim --service "$SVC" --bounty 3 --maker maker --nonce 4)"
# 4: open, past its expiry.
create 5 "secret 4" 1000000 $(( $(slot) + 5 ))
wait_slot $(( $(slot) + 8 ))
# 5: open, citing an attested blob and a plain one, with params too long to inline (300 bytes).
W_CHECK=out/sorted-words-check.jam X=$OUT/x VOL=$OUT/volume.bin CLAIM=$OUT/volume.claim
mkdir -p "$X" && rm -f "$X"/*
printf '%-16s' apple banana cherry >"$VOL"
item "$($W mint --to attester --amount 100)"
payload=$($W attest --service "$SVC" --attester attester --nonce 0 --check $W_CHECK --check-gas $GAS --extrinsics "$X" \
	--subjects "$VOL" --claim-out "$CLAIM" 2>/dev/null)
item "$payload" "$X"/*
item "$($W create --service "$SVC" --maker maker --nonce 6 --check $W_CHECK --params "0x$(printf '%0600d' 7)" \
	--blobs "$CLAIM:0,$VOL" --reward 5 --check-gas $GAS --expiry $(( $(slot) + 1000 )) --bind-claim)"
# A pending proposal.
item "$($W propose --service "$SVC" --nonce 1 --set-admin someone)"

python3 scripts/toaster/lean/fake-node.py "$PORT" "$SIM" "$SVC" >"$OUT/fake-node.log" 2>&1 &
NODE=$!
trap 'kill $NODE 2>/dev/null || true' EXIT
sleep 1
JAM_RPC=ws://127.0.0.1:$PORT python3 scripts/toaster/board/snapshot.py "$SVC" "$OUT/snapshot.json"
kill $NODE

# Each bounty's, the config's and the proposal's raw value, and witness decode's view of it.
raw() { "$SIM" inspect storage --raw "$SVC" "$1"; }
{
	for id in 0 1 2 3 4 5; do
		v=$(raw "$($W key --bounty $id)")
		printf 'bounty\t%s\t%s\t%s\n' "$id" "$v" "$($W decode --bounty "$v")"
	done
	v=$(raw "$($W key --config)"); printf 'config\t-\t%s\t%s\n' "$v" "$($W decode --config "$v")"
	v=$(raw "$($W key --proposal 0)"); printf 'proposal\t0\t%s\t%s\n' "$v" "$($W decode --proposal "$v")"
	printf 'keys\t-\t%s %s %s %s\t-\n' "$($W key --bounty 258)" "$($W key --next)" "$($W key --config)" "$($W key --proposal 3)"
	printf 'admin\t-\t%s\t-\n' "$($W account --seed someone)"
} >"$OUT/decoded.tsv"
python3 scripts/toaster/board/check-sim.py "$OUT/snapshot.json" "$OUT/decoded.tsv" "$(slot)"
printf '\nsnapshot passed against witness-sim\n'
