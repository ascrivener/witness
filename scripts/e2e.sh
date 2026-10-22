#!/usr/bin/env bash
# End-to-end test against a local PolkaJam testnet (v0.1.29).
#
#   POLKAJAM_DIR=../polkajam-releases/polkajam-v0.1.29-macos-aarch64 scripts/e2e.sh [--quick]
#
# Starts a testnet (unless JAM_RPC is set, in which case it uses that one), builds and deploys
# the service and the sample checks.
#
# With WITNESS_SIM=1 it runs against tools/witness-sim instead: the same ops through the same
# rules, with checks in PolkaVM, natively, in seconds. No PolkaJam needed. The testnet stays the
# judge of what fits a refine and of the node's behavior.
#
# --quick (about 6 minutes, a third of it starting the testnet) then mints, creates two bounties,
# provides their check blobs and the dictionary blob, commits, and reveals a wrong and a right
# witness on each. Then it attests a batch of two word volumes and a third on one of them,
# refuses a bad one, and reveals on a bounty that cites two of them, trusting the third as well.
# That covers everything that touches the node: deploy,
# refine and accumulate, pins and preimage lookups, the inner PVM in both modes and growing its
# heap. It skips the claim windows.
#
# The full run (about 8 minutes, mostly claim windows) instead does:
#   bounty 0 (factor check):     Bob commits; Mallory copies x, commits later and reveals first;
#                                Bob reveals inside the claim window and wins.
#   bounty 1 (preimage check):   Dave commits but never reveals; an early reclaim is refused, a
#                                later one refunds Alice; Dave's dead commitment is released.
#   bounty 2 (preimage check):   shares bounty 1's check blob; Carol reveals and wins.
#   bounty 3 (dictionary check): reads a dictionary blob and allocates; Erin reveals and wins.
#   bounty 4 (sorted-words check): the attestation steps above, with Erin revealing.
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
# Seconds between polls of the chain.
POLL=2
W=./target/debug/witness
TMP=$(mktemp -d)
LOG=$TMP/testnet.log
DICT=$TMP/dictionary.txt
printf 'open\nsesame\nsome\nwords\n' >"$DICT"
SENTENCE="open sesame some words"
# Word volumes for the sorted-words check: 16-byte records, padded with spaces.
VOL1=$TMP/volume1.bin VOL2=$TMP/volume2.bin VOL3=$TMP/volume3.bin BADVOL=$TMP/bad-volume.bin
printf '%-16s' apple banana cherry >"$VOL1"
printf '%-16s' grape lemon mango >"$VOL2"
printf '%-16s' peach plum >"$VOL3"
printf '%-16s' zebra yak >"$BADVOL" # not sorted
# Bundles: volumes 1 and 2 are attested as one batch, then volume 3, then the bad one.
BUNDLE_A=$TMP/batch-a.bundle BUNDLE_B=$TMP/batch-b.bundle BAD_BUNDLE=$TMP/bad.bundle
CLAIM_A=$TMP/batch-a.claim CLAIM_B=$TMP/batch-b.claim BADCLAIM=$TMP/bad.claim

N=9903520302753827148829556741 # (2^61 - 1) * 4294967291
FACTOR=4294967291
SECRET="open sesame"
GAS=10000000

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

slot() { "$JAMT" inspect slot; }
wait_slot() { while [ "$(slot)" -lt "$1" ]; do sleep $POLL; done; }

# Raw storage value for `witness key` flags, or empty.
storage() {
	local v
	# jamt cuts values over 1 KiB short; witness-sim doesn't.
	if [ "${JAM_RPC:-}" = sim ]; then
		v=$("$JAMT" inspect storage --raw "$SVC" "$($W key "$@")" 2>/dev/null || true)
	else
		v=$(python3 scripts/jam-storage.py "$SVC" "$($W key "$@")" 2>/dev/null || true)
	fi
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
		sleep $POLL
	done
	fail "$what: wanted /$pattern/, got: $out"
}

# Something that should not happen: give it time to (wrongly) happen, then check.
expect_still() {
	sleep $((POLL * 9))
	expect "$@"
}

# One item per slot: the testnet silently drops some packages submitted together in one slot.
item() { "$JAMT" item "$SVC" "$1" >/dev/null; wait_slot $(( $(slot) + 1 )); }

# Print the commitment for `witness commit ARGS...` (the CLI reports it on stderr).
commitment_of() { $W commit "$@" 2>&1 >/dev/null | awk '{print $2}'; }

window_end() { show bounty --bounty "$1" | sed -nE 's/.*window_end: ([0-9]+).*/\1/p'; }

if [ -n "${WITNESS_SIM:-}" ]; then
	step "using witness-sim (state: $TMP/sim)"
	cargo build -q -p witness-sim
	JAMT=$PWD/target/debug/witness-sim POLL=0 JAM_RPC=sim
	export WITNESS_SIM_DIR=$TMP/sim
	LOG=$WITNESS_SIM_DIR/log
elif [ -z "${JAM_RPC:-}" ]; then
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
WORDS_CHECK=out/sorted-words-check.jam
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

# Pat pins the sorted-words check and the bundles of volumes in one go. Pat attests volumes 1
# and 2 as a batch, then volume 3 trusting volume 2, and fails to attest the unsorted volume.
# Then bounty $1 (Alice, nonce $2) cites volumes 1 and 3, and hunter $3 (nonce $4) reveals a
# wrong witness and a right one that also trusts volume 2.
attestations() {
	local bounty=$1 alice_nonce=$2 hunter=$3 hunter_nonce=$4
	step "attesting word volumes"
	$W bundle --subjects "$VOL1,$VOL2" --out "$BUNDLE_A" >/dev/null
	$W bundle --subjects "$VOL3" --out "$BUNDLE_B" >/dev/null
	$W bundle --subjects "$BADVOL" --out "$BAD_BUNDLE" >/dev/null
	local files=($WORDS_CHECK "$BUNDLE_A" "$BUNDLE_B" "$BAD_BUNDLE")
	item "$($W mint --to pat --amount 200)"
	expect "pat has 200" 'balance: 200, nonce: 0' account --account pat
	item "$($W pin --service "$SVC" --owner pat --nonce 0 --blobs "$(IFS=,; echo "${files[*]}")")"
	expect "pat paid for four pins" 'balance: 160, nonce: 1' account --account pat
	for f in "${files[@]}"; do "$JAMT" provide "$SVC" "$f" >/dev/null; done
	wait_slot $(( $(slot) + 2 ))
	item "$($W attest --service "$SVC" --attester pat --nonce 1 --check $WORDS_CHECK --subjects "$BUNDLE_A" \
		--check-gas $GAS --claim-out "$CLAIM_A" 2>/dev/null)"
	expect "volumes 1 and 2 attested" 'Attestation \{ claim' attestation --attestation "$CLAIM_A"
	item "$($W attest --service "$SVC" --attester pat --nonce 2 --check $WORDS_CHECK --subjects "$BUNDLE_B" \
		--trust "$CLAIM_A:1" --check-gas $GAS --claim-out "$CLAIM_B" 2>/dev/null)"
	expect "volume 3 attested after volume 2" 'Attestation \{ claim' attestation --attestation "$CLAIM_B"
	item "$($W attest --service "$SVC" --attester pat --nonce 3 --check $WORDS_CHECK --subjects "$BAD_BUNDLE" \
		--trust "$CLAIM_A:1" --check-gas $GAS --claim-out "$BADCLAIM" 2>/dev/null)"
	expect_still "unsorted volume not attested" '^none$' attestation --attestation "$BADCLAIM"
	expect "pat paid for two attestations" 'balance: 140, nonce: 3' account --account pat

	step "a bounty citing attested volumes"
	local blobs="$CLAIM_A:0,$CLAIM_B:0"
	item "$($W create --service "$SVC" --maker alice --nonce "$alice_nonce" --check $WORDS_CHECK --params 0x00 \
		--blobs "$blobs" --reward 100 --check-gas $GAS --expiry $(( $(slot) + 100 )))"
	expect "bounty $bounty open" 'status: Open' bounty --bounty "$bounty"
	item "$($W commit --service "$SVC" --bounty "$bounty" --hunter "$hunter" --nonce "$hunter_nonce" --salt 0x77 \
		--witness-str "cherry lemon plum" 2>/dev/null)"
	expect "$hunter committed to bounty $bounty" "nonce: $((hunter_nonce + 1))" account --account "$hunter"
	wait_slot $(( $(slot) + 4 )) # MIN_COMMIT_AGE
	item "$($W reveal --bounty "$bounty" --check $WORDS_CHECK --params 0x00 --blobs "$blobs" --check-gas $GAS \
		--hunter "$hunter" --salt 0x77 --witness-str "cherry lemon plum")"
	expect_still "a word in a volume not given changed nothing" 'status: Open' bounty --bounty "$bounty"
	item "$($W reveal --bounty "$bounty" --check $WORDS_CHECK --params 0x00 --blobs "$blobs" --trust "$CLAIM_A:1" \
		--check-gas $GAS --hunter "$hunter" --salt 0x77 --witness-str "cherry lemon plum")"
	expect "$hunter's reveal on attested volumes opens the window" 'Revealing' bounty --bounty "$bounty"
}

# Reveal on dictionary bounty $1 as hunter $2 with salt $3 and witness $4.
reveal_dictionary() {
	item "$($W reveal --bounty "$1" --check $DICT_CHECK --params 0x00 --blobs "$DICT" --check-gas $GAS \
		--hunter "$2" --salt "$3" --witness-str "$4")"
}

step "deploying"
before=$("$JAMT" list | wc -l)
"$JAMT" create-service out/witness-service.jam 10000000000 >/dev/null
for _ in $(seq 1 40); do [ "$("$JAMT" list | wc -l)" -gt "$before" ] && break; sleep $POLL; done
SVC=$((16#$("$JAMT" list | tail -1 | cut -f1)))
echo "service $SVC"
# Work packages anchored before the service existed cannot see its code, and anchors trail the
# best block, so wait until the service is in the finalized state, plus a margin.
for _ in $(seq 1 40); do "$JAMT" inspect final service "$SVC" >/dev/null 2>&1 && break; sleep $POLL; done
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

	attestations 2 2 bob 2
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

attestations 4 5 erin 1

printf '\nall end-to-end checks passed\n'
