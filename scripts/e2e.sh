#!/usr/bin/env bash
# End-to-end test against a local PolkaJam testnet (v0.1.29).
#
#   POLKAJAM_DIR=../polkajam-releases/polkajam-v0.1.29-macos-aarch64 scripts/e2e.sh [--quick]
#
# Starts a testnet (unless JAM_RPC is set, in which case it uses that one), builds and deploys
# the service and the sample checks.
#
# --quick (about 4 minutes, a third of it starting the testnet) then mints, creates two bounties,
# provides their check blobs and the dictionary blob, commits, and reveals a wrong and a right
# witness on each. That covers everything that touches the node: deploy, refine and accumulate,
# the preimage lookups, the inner PVM and growing its heap. It skips the claim windows.
#
# The full run (about 8 minutes, mostly claim windows) instead does:
#   bounty 0 (factor check):     Bob commits; Mallory copies x, commits later and reveals first;
#                                Bob reveals inside the claim window and wins.
#   bounty 1 (preimage check):   Dave commits but never reveals; an early reclaim is refused, a
#                                later one refunds Alice; Dave's dead commitment is released.
#   bounty 2 (preimage check):   shares bounty 1's check blob; Carol reveals and wins.
#   bounty 3 (dictionary check): reads a dictionary blob and allocates; Erin reveals and wins.
# checking the chain state after each step.
set -euo pipefail

QUICK=
case "${1:-}" in
	--quick) QUICK=1 ;;
	"") ;;
	*) echo "usage: $0 [--quick]" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."
JAMT=${POLKAJAM_DIR:+$POLKAJAM_DIR/}jamt
TESTNET=${POLKAJAM_DIR:+$POLKAJAM_DIR/}polkajam-testnet
W=./target/debug/witness
TMP=$(mktemp -d)
LOG=$TMP/testnet.log
DICT=$TMP/dictionary.txt
printf 'open\nsesame\nsome\nwords\n' >"$DICT"
SENTENCE="open sesame some words"

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
DICT_CHECK=out/dictionary-check.jam
FACTOR_HASH=$($W hash --check $FACTOR_CHECK)
PREIMAGE_HASH=$($W hash --check $PREIMAGE_CHECK)
DICT_CHECK_HASH=$($W hash --check $DICT_CHECK)
DICT_HASH=$($W hash --check "$DICT")

# Create bounty $1 on the dictionary check (difficulty 0: any dictionary sentence), as Alice
# with nonce $2, and provide its check and dictionary.
create_dictionary_bounty() {
	item "$($W create --service "$SVC" --maker alice --nonce "$2" --check $DICT_CHECK --params 0x00 \
		--blobs "$DICT" --reward 100 --check-gas $GAS --expiry $(( $(slot) + 100 )))"
	expect "bounty $1 open" 'status: Open' bounty --bounty "$1"
	[ -n "$(storage --refs "$DICT_HASH")" ] || fail "dictionary not referenced"
	echo "ok: dictionary referenced"
	"$JAMT" provide "$SVC" $DICT_CHECK >/dev/null
	"$JAMT" provide "$SVC" "$DICT" >/dev/null
}

# Reveal on dictionary bounty $1 as hunter $2 with salt $3 and witness $4.
reveal_dictionary() {
	item "$($W reveal --bounty "$1" --check $DICT_CHECK --params 0x00 --blobs "$DICT" --check-gas $GAS \
		--hunter "$2" --salt "$3" --witness-str "$4")"
}

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

if [ -n "$QUICK" ]; then
	step "quick: mint, create, provide"
	item "$($W mint --to alice --amount 1000)"
	item "$($W mint --to bob --amount 100)"
	expect "alice has 1000" 'balance: 1000, nonce: 0' account --account alice
	expect "bob has 100" 'balance: 100, nonce: 0' account --account bob
	item "$($W create --service "$SVC" --maker alice --nonce 0 --check $PREIMAGE_CHECK \
		--params-blake2b "$SECRET" --reward 100 --check-gas $GAS --expiry $(( $(slot) + 100 )))"
	expect "bounty 0 open" 'status: Open' bounty --bounty 0
	expect "alice paid 100" 'balance: 900, nonce: 1' account --account alice
	"$JAMT" provide "$SVC" $PREIMAGE_CHECK >/dev/null

	step "quick: commit, reveal"
	BOB_C=$(commitment_of --service "$SVC" --bounty 0 --hunter bob --nonce 0 --salt 0x0b0b --witness-str "$SECRET")
	item "$($W commit --service "$SVC" --bounty 0 --hunter bob --nonce 0 --salt 0x0b0b --witness-str "$SECRET" 2>/dev/null)"
	expect "bob committed, deposit taken" 'balance: 90, nonce: 1' account --account bob
	wait_slot $(( $(slot) + 4 )) # MIN_COMMIT_AGE
	# A witness the check rejects: the inner PVM runs and returns false, and nothing changes.
	item "$($W reveal --bounty 0 --check $PREIMAGE_CHECK --params-blake2b "$SECRET" --check-gas $GAS \
		--hunter bob --salt 0x0b0b --witness-str "wrong")"
	expect_still "wrong witness changed nothing" 'status: Open' bounty --bounty 0
	item "$($W reveal --bounty 0 --check $PREIMAGE_CHECK --params-blake2b "$SECRET" --check-gas $GAS \
		--hunter bob --salt 0x0b0b --witness-str "$SECRET")"
	expect "bob's reveal opens the window" 'Revealing' bounty --bounty 0
	expect "bob's deposit refunded" 'balance: 100, nonce: 1' account --account bob
	expect "bob's commitment consumed" '^none$' commitment --bounty 0 --commitment "$BOB_C"

	step "quick: a check that reads a blob and grows its heap"
	create_dictionary_bounty 1 1
	item "$($W commit --service "$SVC" --bounty 1 --hunter bob --nonce 1 --salt 0x0b0b --witness-str "$SENTENCE" 2>/dev/null)"
	expect "bob committed to bounty 1" 'balance: 90, nonce: 2' account --account bob
	wait_slot $(( $(slot) + 4 )) # MIN_COMMIT_AGE
	reveal_dictionary 1 bob 0x0b0b "open sesame some word"
	expect_still "non-dictionary witness changed nothing" 'status: Open' bounty --bounty 1
	reveal_dictionary 1 bob 0x0b0b "$SENTENCE"
	expect "bob's dictionary reveal opens the window" 'Revealing' bounty --bounty 1
	printf '\nquick end-to-end checks passed (claim windows, finalize and reclaim not run)\n'
	exit 0
fi

step "minting"
item "$($W mint --to alice --amount 1000)"
for who in bob carol mallory dave erin; do item "$($W mint --to $who --amount 100)"; done
expect "alice has 1000" 'balance: 1000, nonce: 0' account --account alice
for who in bob carol mallory dave erin; do expect "$who has 100" 'balance: 100, nonce: 0' account --account $who; done

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
create_dictionary_bounty 3 3
expect "alice paid 900" 'balance: 100, nonce: 4' account --account alice
"$JAMT" provide "$SVC" $FACTOR_CHECK >/dev/null
"$JAMT" provide "$SVC" $PREIMAGE_CHECK >/dev/null

step "bounty 1: a commitment that is never revealed, and an early reclaim"
DAVE_C=$(commitment_of --service "$SVC" --bounty 1 --hunter dave --nonce 0 --salt 0xda --witness-str "$SECRET")
item "$($W commit --service "$SVC" --bounty 1 --hunter dave --nonce 0 --salt 0xda --witness-str "$SECRET" 2>/dev/null)"
expect "dave committed, deposit taken" 'balance: 90, nonce: 1' account --account dave
item "$($W reclaim --service "$SVC" --bounty 1 --maker alice --nonce 4)"
expect_still "early reclaim refused" 'status: Open' bounty --bounty 1
expect "alice unchanged" 'balance: 100, nonce: 4' account --account alice

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
ERIN_C=$(commitment_of --service "$SVC" --bounty 3 --hunter erin --nonce 0 --salt 0xe1 --witness-str "$SENTENCE")
item "$($W commit --service "$SVC" --bounty 3 --hunter erin --nonce 0 --salt 0xe1 --witness-str "$SENTENCE" 2>/dev/null)"
expect "erin committed" 'balance: 90, nonce: 1' account --account erin
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
expect "bob's commitment consumed" '^none$' commitment --bounty 0 --commitment "$BOB_C"
expect "carol's wrong witness changed nothing" 'Open' bounty --bounty 2
item "$($W reveal --bounty 2 --check $PREIMAGE_CHECK --params-blake2b "$SECRET" --check-gas $GAS \
	--hunter carol --salt 0xca --witness-str "$SECRET")"
expect "carol's reveal opens bounty 2's window" 'Revealing' bounty --bounty 2
expect "carol's commitment consumed" '^none$' commitment --bounty 2 --commitment "$CAROL_C"
reveal_dictionary 3 erin 0xe1 "open sesame some word"
reveal_dictionary 3 erin 0xe1 "$SENTENCE"
expect "erin's reveal opens bounty 3's window" 'Revealing' bounty --bounty 3
expect "erin's commitment consumed" '^none$' commitment --bounty 3 --commitment "$ERIN_C"

step "finalizing too early"
item "$($W finalize --bounty 0)"
expect_still "bounty 0 still revealing" 'Revealing' bounty --bounty 0

step "waiting out the claim windows and bounty 1's reveal grace"
wait_slot $((now + 25 + 20))
wait_slot "$(window_end 0)"
wait_slot "$(window_end 2)"
wait_slot "$(window_end 3)"

step "finalizing, reclaiming, releasing"
item "$($W finalize --bounty 0)"
item "$($W finalize --bounty 2)"
item "$($W finalize --bounty 3)"
item "$($W reclaim --service "$SVC" --bounty 1 --maker alice --nonce 4)"
expect "bounty 0 claimed" 'Claimed' bounty --bounty 0
expect "bob won bounty 0" 'balance: 600, nonce: 1' account --account bob
expect "mallory won nothing" 'balance: 100, nonce: 1' account --account mallory
expect "bounty 2 claimed" 'Claimed' bounty --bounty 2
expect "carol won bounty 2" 'balance: 300, nonce: 1' account --account carol
expect "bounty 3 claimed" 'Claimed' bounty --bounty 3
expect "erin won bounty 3" 'balance: 200, nonce: 1' account --account erin
expect "bounty 1 reclaimed" 'Reclaimed' bounty --bounty 1
expect "alice refunded bounty 1" 'balance: 200, nonce: 5' account --account alice
for h in "$FACTOR_HASH" "$PREIMAGE_HASH" "$DICT_CHECK_HASH" "$DICT_HASH"; do
	[ -z "$(storage --refs "$h")" ] || fail "preimage $h still referenced"
done
echo "ok: every check blob and the dictionary released"
item "$($W release --bounty 1 --commitment "$DAVE_C")"
expect "dave's dead commitment deleted" '^none$' commitment --bounty 1 --commitment "$DAVE_C"
expect "dave's deposit forfeit" 'balance: 90, nonce: 1' account --account dave

printf '\nall end-to-end checks passed\n'
