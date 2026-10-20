#!/usr/bin/env bash
# End-to-end test against a local PolkaJam testnet (v0.1.29).
#
#   POLKAJAM_DIR=../polkajam-releases/polkajam-v0.1.29-macos-aarch64 scripts/e2e.sh
#
# Starts a testnet (unless JAM_RPC is set, in which case it uses that one), builds and deploys
# the service and both sample checks, then runs:
#   bounty 0 (factor check):   Bob commits; Mallory copies x, commits later and reveals first;
#                              Bob reveals inside the claim window and wins.
#   bounty 1 (preimage check): Dave commits but never reveals; an early reclaim is refused, a
#                              later one refunds Alice; Dave's dead commitment is released.
#   bounty 2 (preimage check): shares bounty 1's check blob; Carol reveals and wins.
# checking the chain state after each step. Takes about 8 minutes, mostly claim windows.
set -euo pipefail

cd "$(dirname "$0")/.."
JAMT=${POLKAJAM_DIR:+$POLKAJAM_DIR/}jamt
TESTNET=${POLKAJAM_DIR:+$POLKAJAM_DIR/}polkajam-testnet
W=./target/debug/witness
LOG=$(mktemp -d)/testnet.log

N=9903520302753827148829556741 # (2^61 - 1) * 4294967291
FACTOR=4294967291
SECRET="open sesame"
GAS=10000000

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

slot() { "$JAMT" inspect slot; }
wait_slot() { while [ "$(slot)" -lt "$1" ]; do sleep 2; done; }

# Raw storage value for `witness key` flags, or empty.
storage() {
	local v
	v=$("$JAMT" inspect storage --raw "$SVC" "$($W key "$@")" 2>/dev/null || true)
	case $v in 0x*) echo "$v" ;; *) echo "" ;; esac
}

# `witness decode --KIND` of the value at `witness key ARGS...`, or "none".
show() {
	local kind=$1; shift
	local v; v=$(storage "$@")
	if [ -n "$v" ]; then $W decode "--$kind" "$v"; else echo none; fi
}

# Wait until `show KIND ARGS...` matches PATTERN.
expect() {
	local what=$1 pattern=$2; shift 2
	local out=
	for _ in $(seq 1 40); do
		out=$(show "$@")
		if grep -qE "$pattern" <<<"$out"; then echo "ok: $what"; return; fi
		sleep 3
	done
	fail "$what: wanted /$pattern/, got: $out"
}

# Something that should not happen: give it time to (wrongly) happen, then check.
expect_still() {
	sleep 18
	expect "$@"
}

# One item per slot: the testnet silently drops some packages submitted together in one slot.
item() { "$JAMT" item "$SVC" "$1" >/dev/null; wait_slot $(( $(slot) + 1 )); }

# Print the commitment for `witness commit ARGS...` (the CLI reports it on stderr).
commitment_of() { $W commit "$@" 2>&1 >/dev/null | awk '{print $2}'; }

window_end() { show bounty --bounty "$1" | sed -nE 's/.*window_end: ([0-9]+).*/\1/p'; }

if [ -z "${JAM_RPC:-}" ]; then
	step "starting testnet (log: $LOG)"
	"$TESTNET" >"$LOG" 2>&1 &
	TESTNET_PID=$!
	trap 'pkill -P $TESTNET_PID 2>/dev/null; kill $TESTNET_PID 2>/dev/null || true' EXIT
	for _ in $(seq 1 60); do "$JAMT" list >/dev/null 2>&1 && break; sleep 2; done
fi

step "building"
command -v cargo-jam-build >/dev/null || fail "needs cargo-jam-build: cargo install cargo-jam-build --version 0.1.29 --locked"
cargo build -q
cargo jam-build --out-dir out >/dev/null
FACTOR_CHECK=out/factor-check.jam
PREIMAGE_CHECK=out/blake2b-preimage-check.jam
FACTOR_HASH=$($W hash --check $FACTOR_CHECK)
PREIMAGE_HASH=$($W hash --check $PREIMAGE_CHECK)

step "deploying"
before=$("$JAMT" list | wc -l)
"$JAMT" create-service out/witness-service.jam 10000000000 >/dev/null
for _ in $(seq 1 40); do [ "$("$JAMT" list | wc -l)" -gt "$before" ] && break; sleep 3; done
SVC=$((16#$("$JAMT" list | tail -1 | cut -f1)))
echo "service $SVC"
# Work packages anchored before the service existed cannot see its code, and anchors trail the
# best block, so wait until the service is in the finalized state, plus a margin.
for _ in $(seq 1 40); do "$JAMT" inspect final service "$SVC" >/dev/null 2>&1 && break; sleep 3; done
wait_slot $(( $(slot) + 3 ))

step "minting"
item "$($W mint --to alice --amount 1000)"
for who in bob carol mallory dave; do item "$($W mint --to $who --amount 100)"; done
expect "alice has 1000" 'balance: 1000, nonce: 0' account --account alice
for who in bob carol mallory dave; do expect "$who has 100" 'balance: 100, nonce: 0' account --account $who; done

step "creating bounties"
now=$(slot)
item "$($W create --service "$SVC" --maker alice --nonce 0 --check $FACTOR_CHECK --params-u128 $N \
	--reward 500 --check-gas $GAS --expiry $((now + 100)))"
expect "bounty 0 open" 'status: Open' bounty --bounty 0
item "$($W create --service "$SVC" --maker alice --nonce 1 --check $PREIMAGE_CHECK \
	--params-blake2b "$SECRET" --reward 100 --check-gas $GAS --expiry $((now + 25)))"
expect "bounty 1 open" 'status: Open' bounty --bounty 1
item "$($W create --service "$SVC" --maker alice --nonce 2 --check $PREIMAGE_CHECK \
	--params-blake2b "$SECRET" --reward 200 --check-gas $GAS --expiry $((now + 100)))"
expect "bounty 2 open" 'status: Open' bounty --bounty 2
expect "alice paid 800" 'balance: 200, nonce: 3' account --account alice
"$JAMT" provide "$SVC" $FACTOR_CHECK >/dev/null
"$JAMT" provide "$SVC" $PREIMAGE_CHECK >/dev/null

step "bounty 1: a commitment that is never revealed, and an early reclaim"
DAVE_C=$(commitment_of --service "$SVC" --bounty 1 --hunter dave --nonce 0 --salt 0xda --witness-str "$SECRET")
item "$($W commit --service "$SVC" --bounty 1 --hunter dave --nonce 0 --salt 0xda --witness-str "$SECRET" 2>/dev/null)"
expect "dave committed, deposit taken" 'balance: 90, nonce: 1' account --account dave
item "$($W reclaim --service "$SVC" --bounty 1 --maker alice --nonce 3)"
expect_still "early reclaim refused" 'status: Open' bounty --bounty 1
expect "alice unchanged" 'balance: 200, nonce: 3' account --account alice

step "committing"
BOB_C=$(commitment_of --service "$SVC" --bounty 0 --hunter bob --nonce 0 --salt 0x0b0b --witness-u64 $FACTOR)
item "$($W commit --service "$SVC" --bounty 0 --hunter bob --nonce 0 --salt 0x0b0b --witness-u64 $FACTOR 2>/dev/null)"
expect "bob committed, deposit taken" 'balance: 90, nonce: 1' account --account bob
CAROL_C=$(commitment_of --service "$SVC" --bounty 2 --hunter carol --nonce 0 --salt 0xca --witness-str "$SECRET")
item "$($W commit --service "$SVC" --bounty 2 --hunter carol --nonce 0 --salt 0xca --witness-str "$SECRET" 2>/dev/null)"
expect "carol committed" 'balance: 90, nonce: 1' account --account carol
# Mallory has seen Bob's x (say, by withholding his reveal) and commits to it herself.
item "$($W commit --service "$SVC" --bounty 0 --hunter mallory --nonce 0 --salt 0x0bad --witness-u64 $FACTOR 2>/dev/null)"
expect "mallory committed" 'balance: 90, nonce: 1' account --account mallory
wait_slot $(( $(slot) + 1 ))

step "revealing"
# A witness the check rejects: refine reports CheckFailed(False) and nothing changes.
item "$($W reveal --bounty 2 --check $PREIMAGE_CHECK --params-blake2b "$SECRET" --check-gas $GAS \
	--hunter carol --salt 0xca --witness-str "wrong")"
item "$($W reveal --bounty 0 --check $FACTOR_CHECK --params-u128 $N --check-gas $GAS \
	--hunter mallory --salt 0x0bad --witness-u64 $FACTOR)"
expect "mallory's reveal opens the window" 'Revealing' bounty --bounty 0
expect "mallory's deposit refunded" 'balance: 100, nonce: 1' account --account mallory
item "$($W reveal --bounty 0 --check $FACTOR_CHECK --params-u128 $N --check-gas $GAS \
	--hunter bob --salt 0x0b0b --witness-u64 $FACTOR)"
expect "bob's deposit refunded" 'balance: 100, nonce: 1' account --account bob
expect "bob's commitment consumed" '^none$' commitment --commitment "$BOB_C"
expect "carol's wrong witness changed nothing" 'Open' bounty --bounty 2
item "$($W reveal --bounty 2 --check $PREIMAGE_CHECK --params-blake2b "$SECRET" --check-gas $GAS \
	--hunter carol --salt 0xca --witness-str "$SECRET")"
expect "carol's reveal opens bounty 2's window" 'Revealing' bounty --bounty 2
expect "carol's commitment consumed" '^none$' commitment --commitment "$CAROL_C"

step "finalizing too early"
item "$($W finalize --bounty 0)"
expect_still "bounty 0 still revealing" 'Revealing' bounty --bounty 0

step "waiting out the claim windows and bounty 1's reveal grace"
wait_slot $((now + 25 + 20))
wait_slot "$(window_end 0)"
wait_slot "$(window_end 2)"

step "finalizing, reclaiming, releasing"
item "$($W finalize --bounty 0)"
item "$($W finalize --bounty 2)"
item "$($W reclaim --service "$SVC" --bounty 1 --maker alice --nonce 3)"
expect "bounty 0 claimed" 'Claimed' bounty --bounty 0
expect "bob won bounty 0" 'balance: 600, nonce: 1' account --account bob
expect "mallory won nothing" 'balance: 100, nonce: 1' account --account mallory
expect "bounty 2 claimed" 'Claimed' bounty --bounty 2
expect "carol won bounty 2" 'balance: 300, nonce: 1' account --account carol
expect "bounty 1 reclaimed" 'Reclaimed' bounty --bounty 1
expect "alice refunded bounty 1" 'balance: 300, nonce: 4' account --account alice
[ -z "$(storage --check-refs "$FACTOR_HASH")" ] || fail "factor check still referenced"
[ -z "$(storage --check-refs "$PREIMAGE_HASH")" ] || fail "preimage check still referenced"
echo "ok: both check blobs released"
item "$($W release --commitment "$DAVE_C")"
expect "dave's dead commitment deleted" '^none$' commitment --commitment "$DAVE_C"
expect "dave's deposit forfeit" 'balance: 90, nonce: 1' account --account dave

printf '\nall end-to-end checks passed\n'
