#!/usr/bin/env bash
# Witness on the JAM Toaster public testnet, through a local non-validating node at $JAM_RPC
# (default ws://localhost:19800). Run by .github/workflows/toaster.yml once the node has synced.
#
#   scripts/toaster/run.sh deploy
#   scripts/toaster/run.sh bounty SERVICE_ID
#   scripts/toaster/run.sh apply SERVICE_ID PROPOSAL_ID [EXPECTED_KEY_OR_CODE_HASH]
#
# Needs, from the environment:
#   JAMT        the polkajam release's jamt
#   W           the witness CLI built at the deployed commit
#   SERVICE_JAM the service blob to deploy (deploy)
#   CHECKS      the directory of check blobs built at that commit (bounty)
#   OUT         where to write summary.json and notes (default: .)
#   WITNESS_ADMIN_SEED  the seed of the admin to hand on to (deploy proposes it);
#                       deploy skips the rotation without it
#
# deploy: creates the service, proposes its first configuration (applied at once), then proposes
# handing the admin role from the build's public test key (seed "admin") to WITNESS_ADMIN_SEED's,
# which `apply` applies once ADMIN_DELAY (100,800 slots, about 7 days) has passed. `apply`
# applies any effective proposal (SetAdmin or Upgrade) and checks the admin or the code hash after.
# bounty: one bounty on the Blake2b preimage check, end to end: mint, create, commit, reveal a
# wrong witness and then the right one, finalize after the claim window. Its accounts are seeds
# unique to the run, so reruns and other users don't collide.
set -euo pipefail

cd "$(dirname "$0")/../.."
: "${JAMT:?}" "${W:?}"
OUT=${OUT:-.}
SUMMARY=$OUT/summary.json
POLL=6
GAS=10000000
ENDOWMENT=10000000000
DEPOSIT_GAS=300000 # witness_types::DEPOSIT_GAS
# StorageKey::Admin and StorageKey::NextProposalId, SCALE-encoded (variants 7 and 9).
ADMIN_KEY=0x07
NEXT_PROPOSAL_KEY=0x09

step() { printf '\n== %s (slot %s)\n' "$*" "$(slot 2>/dev/null || echo ?)"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
# Record KEY = VALUE (a JSON value) in the summary.
record() {
	python3 - "$SUMMARY" "$1" "$2" <<-'EOF'
	import json, os, sys
	path, key, value = sys.argv[1:]
	data = json.load(open(path)) if os.path.exists(path) else {}
	data[key] = json.loads(value)
	json.dump(data, open(path, "w"), indent=2)
	EOF
	echo "recorded $1 = $2"
}

slot() { "$JAMT" inspect slot; }
wait_slot() { while [ "$(slot)" -lt "$1" ]; do sleep $POLL; done; }

raw_storage() {
	local v
	if [ "${JAM_RPC:-}" = sim ]; then
		v=$("$JAMT" inspect storage --raw "$1" "$2" 2>/dev/null || true)
	else
		v=$(python3 scripts/jam-storage.py "$1" "$2" 2>/dev/null || true)
	fi
	case $v in 0x*) echo "$v" ;; *) echo "" ;; esac
}
storage() { raw_storage "$SVC" "$($W key "$@")"; }

# `witness decode --KIND` of the value at `witness key ARGS...`, or "none"; `account --account S`
# shows S's nonce and balance of the test asset.
show() {
	local kind=$1; shift
	local v
	if [ "$kind" = account ]; then
		local nonce balance
		v=$(storage "$@"); nonce=$([ -n "$v" ] && $W decode --account "$v" | sed -nE 's/.*nonce: ([0-9]+).*/\1/p')
		v=$(storage --balance "$2" --asset test); balance=$([ -n "$v" ] && $W decode --balance "$v")
		echo "balance: ${balance:-0}, nonce: ${nonce:-0}"
		return
	fi
	v=$(storage "$@")
	if [ -z "$v" ]; then echo none; else $W decode "--$kind" "$v"; fi
}

# Wait (up to about 6 minutes) until `show KIND ARGS...` matches PATTERN.
expect() {
	local what=$1 pattern=$2; shift 2
	local out=
	for _ in $(seq 1 60); do
		out=$(show "$@")
		if grep -qE "$pattern" <<<"$out"; then echo "ok: $what: $out"; return; fi
		sleep $POLL
	done
	fail "$what: wanted /$pattern/, got: $out"
}

# Something that should not happen: give it time to (wrongly) happen, then check.
expect_still() {
	sleep $((POLL * 10))
	expect "$@"
}

# One work item per slot. Any more arguments are extrinsic files.
item() { submit "$SVC" "$@"; wait_slot $(( $(slot) + 1 )); }
submit() { python3 scripts/jam-submit.py "$@"; }
# JAM_RPC=sim: against tools/witness-sim (JAMT=target/debug/witness-sim), to try this script out.
if [ "${JAM_RPC:-}" = sim ]; then
	POLL=0
	submit() { "$JAMT" item "$@"; }
fi

# The service's code hash, as the chain's service account records it.
code_hash() {
	[ "${JAM_RPC:-}" = sim ] && { echo; return; }
	python3 - "$1" <<-'EOF'
	import os, sys
	sys.path.insert(0, "scripts")
	from jamrpc import Rpc, unb64, url
	rpc = Rpc(url())
	best = rpc.call("bestBlock")["header_hash"]
	info = rpc.call("serviceData", best, int(sys.argv[1]))
	print("0x" + unb64(info)[1:33].hex() if info else "")
	EOF
}

deploy() {
	: "${SERVICE_JAM:?}"
	step "deploying $SERVICE_JAM"
	record blob_sha256 "\"$(sha256sum "$SERVICE_JAM" | cut -d' ' -f1)\""
	record blob_blake2b256 "\"$(b2sum -l 256 "$SERVICE_JAM" | cut -d' ' -f1)\""
	record blob_bytes "$(stat -c %s "$SERVICE_JAM")"
	"$JAMT" list | tee "$OUT/services-before.txt"
	"$JAMT" create-service "$SERVICE_JAM" $ENDOWMENT --min-memo-gas $DEPOSIT_GAS | tee "$OUT/create-service.txt"
	local new=
	for _ in $(seq 1 60); do
		"$JAMT" list >"$OUT/services-after.txt"
		new=$(comm -13 <(cut -f1 "$OUT/services-before.txt" | sort) <(cut -f1 "$OUT/services-after.txt" | sort))
		[ -n "$new" ] && break
		sleep $POLL
	done
	[ -n "$new" ] || fail "no new service appeared"
	[ "$(wc -l <<<"$new")" -eq 1 ] || fail "more than one new service: $new"
	SVC=$((16#$new))
	echo "service $SVC (0x$new)"
	record service_id "$SVC"
	for _ in $(seq 1 60); do "$JAMT" inspect final service "$SVC" >/dev/null 2>&1 && break; sleep $POLL; done
	"$JAMT" inspect final service "$SVC" | tee "$OUT/service.txt" || fail "service $SVC not finalized"
	record code_hash "\"$(code_hash "$SVC")\""
	record deployed_slot "$(slot)"

	# Waits a few slots: packages anchored before the service existed can't see its code.
	wait_slot $(( $(slot) + 3 ))
	step "first configuration (applies at once)"
	item "$($W propose --service "$SVC" --nonce 0 --fee-asset test --commit-deposit 10 --attest-deposit 10)"
	expect "witness configured" 'fee_asset: Some' config --config
	record configured_slot "$(slot)"

	if [ -z "${WITNESS_ADMIN_SEED:-}" ]; then
		echo "WITNESS_ADMIN_SEED is not set: skipping the admin rotation"
		record admin_rotation '"skipped: WITNESS_ADMIN_SEED not set"'
		return
	fi
	step "proposing the new admin"
	local admin; admin=$($W account --seed "$WITNESS_ADMIN_SEED")
	record new_admin "\"$admin\""
	local next; next=$(raw_storage "$SVC" "$NEXT_PROPOSAL_KEY")
	[ -z "$next" ] || fail "proposals already exist (next id $next): someone else used the test admin"
	item "$($W propose --service "$SVC" --nonce 1 --set-admin "$WITNESS_ADMIN_SEED")"
	expect "set-admin proposed" 'SetAdmin' proposal --proposal 0
	show proposal --proposal 0 | tee "$OUT/proposal-0.txt"
	record admin_proposal_id 0
	record admin_proposal_effective "$(sed -nE 's/.*effective: ([0-9]+).*/\1/p' "$OUT/proposal-0.txt")"
}


# Apply proposal $1 and check it took effect: a SetAdmin's key becomes the stored admin, an
# Upgrade's code hash the service's code hash. With $2 (hex), that key or code hash must also be
# $2. `apply` is unsigned: anyone can apply an effective proposal.
apply_proposal() {
	local id=$1 expect=${2:-}
	step "applying proposal $id"
	show proposal --proposal "$id" | tee "$OUT/proposal-$id.txt"
	local effective kind target
	effective=$(sed -nE 's/.*effective: ([0-9]+).*/\1/p' "$OUT/proposal-$id.txt")
	[ -n "$effective" ] || fail "no proposal $id"
	# The proposal's action: SetAdmin([..32 bytes..]) or Upgrade { code_hash: [..], code_len: N }.
	read -r kind target < <(python3 -c '
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r"SetAdmin\(\[([0-9, ]+)\]\)", text) or re.search(r"Upgrade \{ code_hash: \[([0-9, ]+)\]", text)
if not m:
    sys.exit("not a SetAdmin or an Upgrade: " + text)
kind = "set-admin" if m.group(0).startswith("SetAdmin") else "upgrade"
print(kind, "0x" + bytes(int(b) for b in m.group(1).split(",")).hex())
' "$OUT/proposal-$id.txt")
	# A failed decode leaves these empty (process substitution hides its exit status).
	[ -n "$kind" ] && [ -n "$target" ] || fail "couldn't decode proposal $id's action"
	echo "proposal $id: $kind $target, effective from slot $effective"
	record proposal "{\"id\": $id, \"action\": \"$kind\", \"target\": \"$target\", \"effective\": $effective}"
	if [ -n "$expect" ] && [ "${expect#0x}" != "${target#0x}" ]; then
		fail "proposal $id's target is $target, not the expected 0x${expect#0x}"
	fi
	[ "$(slot)" -ge "$effective" ] || fail "proposal $id is effective from slot $effective; it's slot $(slot)"
	local before; before=$(code_hash "$SVC")
	record code_hash_before "\"$before\""
	item "$($W apply --id "$id")"
	local now=
	for _ in $(seq 1 60); do
		case $kind in
			set-admin) now=$(raw_storage "$SVC" $ADMIN_KEY) ;;
			upgrade) now=$(code_hash "$SVC") ;;
		esac
		[ "$now" = "$target" ] && break
		sleep $POLL
	done
	[ "$now" = "$target" ] || fail "after applying proposal $id: $kind is $now, not $target"
	expect "proposal $id consumed" '^none$' proposal --proposal "$id"
	echo "ok: $kind is now $target"
	record "${kind/-/_}_applied" "\"$target\""
	record applied_slot "$(slot)"
	record code_hash_after "\"$(code_hash "$SVC")\""
}

bounty() {
	: "${CHECKS:?}"
	local check=$CHECKS/blake2b-preimage-check.jam
	local tag; tag=${GITHUB_RUN_ID:-$(date +%s)}
	local maker=toaster-maker-$tag hunter=toaster-hunter-$tag
	local secret="toaster secret $tag" salt=0x5a17
	local X payload; X=$(mktemp -d)
	record check_blob_blake2b256 "\"$(b2sum -l 256 "$check" | cut -d' ' -f1)\""

	step "minting"
	item "$($W mint --to "$maker" --amount 1000)"
	item "$($W mint --to "$hunter" --amount 100)"
	expect "maker has 1000" 'balance: 1000, nonce: 0' account --account "$maker"
	expect "hunter has 100" 'balance: 100, nonce: 0' account --account "$hunter"

	step "creating the bounty"
	local next id
	next=$(raw_storage "$SVC" "$($W key --next)")
	# A u64, little-endian; absent means 0.
	id=$([ -n "$next" ] && python3 -c "import sys; print(int.from_bytes(bytes.fromhex(sys.argv[1][2:]), 'little'))" "$next" || echo 0)
	echo "bounty id $id"
	record bounty_id "$id"
	item "$($W create --service "$SVC" --maker "$maker" --nonce 0 --check "$check" \
		--params-blake2b "$secret" --reward 100 --check-gas $GAS --expiry $(( $(slot) + 200 )))"
	expect "bounty $id open" 'status: Open' bounty --bounty "$id"
	expect "maker escrowed 100" 'balance: 900, nonce: 1' account --account "$maker"
	show bounty --bounty "$id" | tee "$OUT/bounty-created.txt"

	step "committing"
	local c; c=$($W commit --service "$SVC" --bounty "$id" --hunter "$hunter" --nonce 0 --salt $salt \
		--witness-str "$secret" 2>&1 >/dev/null | awk '{print $2}')
	item "$($W commit --service "$SVC" --bounty "$id" --hunter "$hunter" --nonce 0 --salt $salt \
		--witness-str "$secret" 2>/dev/null)"
	expect "hunter committed, deposit taken" 'balance: 90, nonce: 1' account --account "$hunter"
	expect "commitment stored" 'CommitRecord|slot' commitment --bounty "$id" --commitment "$c"
	wait_slot $(( $(slot) + 2 )) # MIN_COMMIT_AGE

	step "revealing a wrong witness"
	rm -f "$X"/*
	payload=$($W reveal --bounty "$id" --check "$check" --params-blake2b "$secret" --check-gas $GAS \
		--hunter "$hunter" --salt $salt --witness-str "wrong" --extrinsics "$X")
	item "$payload" "$X"/*
	expect_still "the wrong witness changed nothing" 'status: Open' bounty --bounty "$id"
	expect "hunter's deposit still held" 'balance: 90, nonce: 1' account --account "$hunter"

	step "revealing the right witness"
	rm -f "$X"/*
	payload=$($W reveal --bounty "$id" --check "$check" --params-blake2b "$secret" --check-gas $GAS \
		--hunter "$hunter" --salt $salt --witness-str "$secret" --extrinsics "$X")
	item "$payload" "$X"/*
	expect "the reveal opens the claim window" 'Revealing' bounty --bounty "$id"
	expect "hunter's deposit refunded" 'balance: 100, nonce: 1' account --account "$hunter"
	expect "commitment consumed" '^none$' commitment --bounty "$id" --commitment "$c"
	show bounty --bounty "$id" | tee "$OUT/bounty-revealed.txt"
	record revealed_slot "$(slot)"

	step "finalizing too early"
	item "$($W finalize --bounty "$id")"
	expect_still "still revealing" 'Revealing' bounty --bounty "$id"

	local end; end=$(sed -nE 's/.*window_end: ([0-9]+).*/\1/p' "$OUT/bounty-revealed.txt")
	step "waiting for the claim window to end at slot $end"
	wait_slot "$end"
	wait_slot $(( $(slot) + 1 ))

	step "finalizing"
	item "$($W finalize --bounty "$id")"
	expect "bounty claimed" 'Claimed' bounty --bounty "$id"
	expect "hunter won the reward" 'balance: 200, nonce: 1' account --account "$hunter"
	expect "maker paid it" 'balance: 900, nonce: 1' account --account "$maker"
	show bounty --bounty "$id" | tee "$OUT/bounty-final.txt"
	record finalized_slot "$(slot)"
	record bounty_result '"claimed by the hunter"'
}

case "${1:-}" in
	deploy) deploy ;;
	bounty) SVC=${2:?service id}; record service_id "$SVC"; bounty ;;
	apply) SVC=${2:?service id}; record service_id "$SVC"; apply_proposal "${3:?proposal id}" "${4:-}" ;;
	*) echo "usage: $0 deploy | bounty SERVICE_ID | apply SERVICE_ID PROPOSAL_ID [EXPECTED_KEY_OR_CODE_HASH]" >&2; exit 2 ;;
esac
printf '\n%s done\n' "$1"
