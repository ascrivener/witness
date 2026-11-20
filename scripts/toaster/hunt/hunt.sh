#!/usr/bin/env bash
# Hunt a witness Lean bounty on the JAM Toaster (docs/HUNTING.md): commit to a proof, then reveal it.
#
#   HUNTER_SEED=... WITNESS_LEAN_DIR=... JAM_LEAN_DIR=... LEAN4EXPORT=... \
#     scripts/toaster/hunt/hunt.sh STEP SPEC PROOF OUT
#
# STEP     check | commit | reveal | finalize | status
# SPEC     the bounty's spec (site/bounties/N.json): its statement, pinned commits, check, the
#          attestation it cites and the release of its library's attestations
# PROOF    a Lean file proving the bounty's theorem, under exactly its name and type, built against
#          jam-lean at the spec's commit (JAM_LEAN_DIR, with the spec's module built)
# OUT      a work directory (kept between steps on one machine; rebuilt from PROOF otherwise)
#
# - check:    build the reveal and measure it, touching nothing on chain: the goal's statement node
#             must be the bounty's; the check, run in witness-sim (PolkaJam's gas), must accept it
#             within the bounty's check gas; the package must fit the chain's input limit.
# - commit:   check, then mint test funds if needed and commit (`witness commit`), unless this
#             commitment is on chain already. The witness is fixed now: the commitment hashes it.
# - reveal:   rebuild the same witness (the commitment must be on chain, at least MIN_COMMIT_AGE
#             old), attest your own lemmas first in attest mode, measure, reveal, and check the
#             bounty now has your commitment as its leader (or winner).
# - finalize: once the claim window has passed, finalize, and check you were paid.
# - status:   the bounty, your account, and your commitment if OUT knows it.
#
# LEMMAS (default witness) says where your own lemmas go, and must be the same at commit and reveal:
# `witness` carries every node of yours (the goal, your lemmas, anything else outside the library)
# in the reveal, with its proof; `attest` carries only the goal and its proof, and attests the rest
# first, in the reveal step, right before revealing (never before committing: once attested, a
# lemma is public, and an earlier commitment citing it by name and type would win). In attest mode
# every declaration of your file that gets attested must have a name with 16 or more hex digits in a
# row, and none may have the goal's type. A lemma whose own check is over MAX_ATTEST_GAS (default
# 3.5e9) can't be attested whole: witness-lean can split it into judgments, which this doesn't do.
#
# HUNTER_SEED is your account's seed (secret: it signs, and the salt derives from it). JAM_RPC is the
# node (default ws://localhost:19800). RELEASE_LOCAL is a directory holding the release's files, to
# use instead of downloading them. Needs the witness CLI and witness-sim built (`cargo build --release
# -p witness-cli -p witness-sim`) and witness-lean's lean-host (`cargo build --release -p lean-host`
# in WITNESS_LEAN_DIR). The check is the release's (its hash is the spec's), so it isn't rebuilt.
set -euo pipefail
STEP=${1:?usage: hunt.sh STEP SPEC PROOF OUT} SPEC=${2:?spec} PROOF=${3:-} OUT=${4:?work directory}
: "${HUNTER_SEED:?set HUNTER_SEED to the seed of your account}"
LEMMAS=${LEMMAS:-witness}
# The most check gas a batch of your lemmas may use, as witness-sim measures it (PolkaJam's gas):
# 70% of a refine's 5e9 by default, the margin the libraries were attested with; up to 4.8e9 fits.
MAX_ATTEST_GAS=${MAX_ATTEST_GAS:-3500000000}
case $LEMMAS in witness | attest) ;; *) echo "LEMMAS: witness or attest"; exit 1 ;; esac
cd "$(dirname "$0")/../../.."
WITNESS_DIR=$PWD
SPEC=$(cd "$(dirname "$SPEC")" && pwd)/$(basename "$SPEC")
OUT=$(mkdir -p "$OUT" && cd "$OUT" && pwd)
export JAM_RPC=${JAM_RPC:-ws://localhost:19800}
W=$WITNESS_DIR/target/release/witness
SIM=$WITNESS_DIR/target/release/witness-sim
HUNT="python3 $WITNESS_DIR/scripts/toaster/hunt/hunt.py"
REL=$OUT/release
X=$OUT/extrinsics OP=$OUT/op.hex POLL=3
STATE=$OUT/state
touch "$STATE"
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
get() { sed -n "s/^$1=//p" "$STATE" | tail -1; }
put() { echo "$1=$2" >>"$STATE"; }
spec() { python3 -I -c 'import json, sys; v = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v = v[k]
print(v)' "$SPEC" "$1"; }
SVC=$(spec service) BOUNTY=$(spec bounty) THEOREM=$(spec statement.theorem) GOAL=$(spec statement.node)
cp "$SPEC" "$OUT/spec.json"
SALT=$($HUNT salt "$HUNTER_SEED" "$SVC" "$BOUNTY")
ME=$($W account --seed "$HUNTER_SEED")

# The chain.
slot() {
	python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from jamrpc import Rpc, url; print(Rpc(url()).call("bestBlock")["slot"])' \
		"$WITNESS_DIR/scripts"
}
storage() {
	local v; v=$(python3 "$WITNESS_DIR/scripts/jam-storage.py" "$SVC" "$($W key "$@")" 2>/dev/null || true)
	case $v in 0x*) echo "$v" ;; *) echo "" ;; esac
}
show() {
	local kind=$1; shift
	local v; v=$(storage "$@")
	if [ -n "$v" ]; then $W decode "--$kind" "$v"; else echo none; fi
}
# The bounty, as JSON (snapshot.py's decoder), or nothing.
bounty_json() {
	local v; v=$(storage --bounty "$BOUNTY")
	[ -n "$v" ] && python3 "$WITNESS_DIR/scripts/toaster/board/snapshot.py" --decode bounty "$v"
}
bounty_field() { bounty_json | python3 -I -c 'import json, sys; v = json.load(sys.stdin)
for k in sys.argv[1].split("."): v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else v)' "$1"; }
nonce_of() { local n; n=$(show account --account "$HUNTER_SEED" | sed -nE 's/.*nonce: ([0-9]+).*/\1/p'); echo "${n:-0}"; }
balance_of() { local b; b=$(show balance --balance "$HUNTER_SEED" --asset test); [ "$b" = none ] && echo 0 || echo "$b"; }
max_input() {
	python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from jamrpc import Rpc, url
print(next(iter(Rpc(url()).call("parameters").values()))["max_input"])' "$WITNESS_DIR/scripts"
}
# Submit OP (with the extrinsics in X) until the command CHECK... succeeds: up to 4 tries of 12 slots.
deliver() { # NAME CHECK...
	local name=$1; shift
	local extrinsics=($(ls "$X"/* 2>/dev/null)) sent
	for try in 1 2 3 4; do
		sent=$(slot)
		python3 "$WITNESS_DIR/scripts/jam-submit.py" "$SVC" "@$OP" "${extrinsics[@]}" || echo "$name: not submitted (try $try)"
		while [ "$(slot)" -le $((sent + 12)) ]; do
			if "$@"; then echo "ok: $name (try $try, slot $(slot))"; rm -rf "$X"; return 0; fi
			sleep $POLL
		done
		echo "$name: no effect after try $try (sent at slot $sent)"
	done
	return 1
}
# Mint test funds until the hunter holds AMOUNT (the faucet is the test asset's; on a chain whose
# fee asset is another, fund the account yourself).
fund() { # AMOUNT
	[ "$(balance_of)" -ge "$1" ] && return
	show config --config | grep -q 'fee_asset: Some(Asset { service: 4294967295, id: 0 })' \
		|| fail "the fee asset isn't the test asset: fund $ME yourself"
	while [ "$(balance_of)" -lt "$1" ]; do
		local before; before=$(balance_of)
		printf '%s' "$($W mint --to "$HUNTER_SEED" --amount 1000)" >"$OP"
		deliver "mint 1000 test for you" eval '[ "$(balance_of)" -gt '"$before"' ]' || fail "minting never took effect"
	done
}
deposit_of() { show config --config | sed -nE "s/.*$1: ([0-9]+).*/\1/p"; }

# The reveal, built from the proof: the release, the export, the witness, what it trusts.
build() {
	: "${WITNESS_LEAN_DIR:?set WITNESS_LEAN_DIR to a witness-lean checkout at the commit the spec pins}"
	: "${JAM_LEAN_DIR:?set JAM_LEAN_DIR to a jam-lean checkout at the commit the spec pins, its module built}"
	: "${LEAN4EXPORT:?set LEAN4EXPORT to the lean4export binary}"
	[ -f "$PROOF" ] || fail "no proof file: $PROOF"
	HOST=$WITNESS_LEAN_DIR/target/release/lean-host
	CHECK=$REL/lean-check.jam
	step "the release of attestations for $(spec library)"
	if [ ! -f "$REL/$(spec library).json" ]; then $HUNT fetch "$SPEC" "$REL" ${RELEASE_LOCAL:-}; fi
	[ "$($W hash --check "$CHECK")" = "$(spec check.hash)" ] || fail "the release's check isn't the bounty's"
	[ "$(git -C "$JAM_LEAN_DIR" rev-parse HEAD)" = "$(spec pins.jam_lean)" ] || fail "JAM_LEAN_DIR isn't at jam-lean $(spec pins.jam_lean)"
	[ "$(git -C "$WITNESS_LEAN_DIR" rev-parse HEAD)" = "$(spec pins.witness_lean)" ] || fail "WITNESS_LEAN_DIR isn't at witness-lean $(spec pins.witness_lean)"
	# PolkaVM's recompiler needs a sandbox some machines can't give it; its interpreter charges the same gas.
	$HUNT probe "$OUT/probe.args"
	if [ -z "${POLKAVM_BACKEND:-}" ] && grep -q BadCheckBlob <<<"$("$SIM" check "$CHECK" "$OUT/probe.args" 100000000 2>&1 || true)"; then
		export POLKAVM_BACKEND=interpreter
		echo "(PolkaVM's recompiler doesn't run here: witness-sim uses its interpreter, which charges the same gas)"
	fi

	step "compiling your proof against jam-lean $(spec pins.jam_lean | cut -c1-7) and exporting $THEOREM"
	rm -rf "$OUT/proof" "$OUT/nodes"
	mkdir -p "$OUT/proof"
	cp "$PROOF" "$OUT/proof/HuntProof.lean"
	local lp; lp=$(cd "$JAM_LEAN_DIR" && lake env printenv LEAN_PATH)
	(cd "$JAM_LEAN_DIR" && lake env lean --root="$OUT/proof" -o "$OUT/proof/HuntProof.olean" "$OUT/proof/HuntProof.lean") \
		>"$OUT/proof/lean.log" 2>&1 || { cat "$OUT/proof/lean.log"; fail "your proof doesn't compile"; }
	# Lean's messages can quote your proof: only their count, unless it failed (or LEAN_LOG=1).
	if [ -n "${LEAN_LOG:-}" ]; then cat "$OUT/proof/lean.log"; else echo "compiled; Lean said $(grep -c . "$OUT/proof/lean.log") lines (LEAN_LOG=1 shows them)"; fi
	grep -q "declaration uses .sorry." "$OUT/proof/lean.log" && fail "your proof uses sorry"
	(cd "$JAM_LEAN_DIR" && LEAN_PATH="$lp:$OUT/proof" "$LEAN4EXPORT" HuntProof -- "$THEOREM") >"$OUT/proof/export.ndjson"
	"$HOST" convert "$OUT/proof/export.ndjson" "$OUT/nodes" >/dev/null
	$HUNT prepare "$SPEC" "$REL" "$OUT/nodes" "$OUT" "$LEMMAS"
	if [ "$LEMMAS" = attest ]; then
		# Your declarations: none of the goal's type, and every one to be attested with an unguessable name.
		cat >"$OUT/proof/Decls.lean" <<EOF
import Lean
import HuntProof
open Lean Meta

#eval show MetaM Unit from do
  let env ← getEnv
  let some idx := env.getModuleIdx? \`HuntProof | throwError "no module HuntProof"
  let some g := env.find? \`$THEOREM | throwError "no $THEOREM"
  let mut out : Array Json := #[]
  for (n, c) in env.constants.map₁.toList do
    if env.getModuleIdxFor? n == some idx && n != g.name then
      let same ← if c.type == g.type then pure true else
        try withTransparency .default (isDefEq c.type g.type) catch _ => pure false
      out := out.push (Json.mkObj [("name", toJson n.toString), ("same_type_as_goal", toJson same)])
  IO.println ("DECLS " ++ (Json.mkObj [("constants", Json.arr out)]).compress)
EOF
		(cd "$JAM_LEAN_DIR" && LEAN_PATH="$lp:$OUT/proof" lake env lean "$OUT/proof/Decls.lean") >"$OUT/proof/decls.log" 2>&1 \
			|| { cat "$OUT/proof/decls.log"; fail "couldn't list your declarations"; }
		sed -n 's/^DECLS //p' "$OUT/proof/decls.log" >"$OUT/proof/decls.json"
		$HUNT names "$SPEC" "$OUT" "$OUT/proof/decls.json"
	fi
	WITNESS_SHA=$(sha256sum "$OUT/witness.pack" | cut -d' ' -f1)
	COMMITMENT=$($W commitment --bounty "$BOUNTY" --hunter "$HUNTER_SEED" --salt "$SALT" --witness-file "$OUT/witness.pack")
	echo "witness sha256 $WITNESS_SHA; commitment $COMMITMENT"
	local committed; committed=$(get commitment)
	if [ -n "$committed" ] && [ "$committed" != "$COMMITMENT" ]; then
		fail "this proof gives commitment $COMMITMENT, but OUT committed to $committed: the proof (or LEMMAS) changed since"
	fi
}

# What the reveal trusts (traced: only what the kernel looks up), its check gas measured in
# witness-sim, and the package's size.
measure() {
	local trust_ok=1
	"$HOST" trace "$OUT/nodes" "$OUT/reveal-plan.json" "$OUT/reveal-traced.json" 100000000 >"$OUT/trace.log"
	$HUNT trust "$SPEC" "$REL" "$OUT" "$OUT/reveal-traced.json" || trust_ok=
	[ -n "$trust_ok" ] || [ "$LEMMAS" = attest ] || fail "the reveal trusts nodes that aren't attested"
	CHECK_GAS=$(spec check_gas)
	$HUNT args "$SPEC" "$REL" "$OUT/nodes" "$OUT" "$OUT/reveal.args"
	local r; r=$("$SIM" check "$CHECK" "$OUT/reveal.args" "$CHECK_GAS" 2>&1 || true)
	echo "witness-sim: $r"
	grep -q '^Ok(())' <<<"$r" || fail "the check doesn't accept your reveal within the bounty's $CHECK_GAS gas: $r"
	REVEAL_GAS=$(sed -nE 's/.*used ([0-9]+) gas.*/\1/p' <<<"$r")
	put measured "$REVEAL_GAS"
	if [ -z "$trust_ok" ]; then
		echo "the reveal's check: $REVEAL_GAS gas of $CHECK_GAS (attest mode: its size is measured once your lemmas are attested, in the reveal step)"
		return
	fi
	rm -rf "$X"
	$W reveal --bounty "$BOUNTY" --check "$CHECK" --params "$GOAL" --blobs "$(cat "$OUT/cite")" \
		--trust "$(cat "$OUT/reveal.trust")" --check-gas "$CHECK_GAS" --hunter "$HUNTER_SEED" --salt "$SALT" \
		--witness-file "$OUT/witness.pack" --extrinsics "$X" >"$OP"
	local size=$(( $(wc -c <"$OP") / 2 ))
	for x in "$X"/*; do size=$((size + $(stat -c %s "$x"))); done
	local limit=${MAX_INPUT:-13791360}
	echo "the reveal: check gas $REVEAL_GAS of $CHECK_GAS; $size bytes of payload and extrinsics, of the chain's $limit"
	[ "$size" -le $(( limit * 95 / 100 )) ] || fail "the reveal is $size bytes, over 95% of the chain's input limit $limit: attest your lemmas (LEMMAS=attest), or trust less"
}

# Does the bounty have COMMITMENT as its leader (Revealing) or winner (Claimed)?
mine() { bounty_json | python3 -I -c 'import json, sys
s = json.load(sys.stdin)["status"]
c = s.get("leader") or s.get("winner") or {}
sys.exit(0 if c.get("commitment") == sys.argv[1] else 1)' "$COMMITMENT"; }

commitment_slot() {
	show commitment --bounty "$BOUNTY" --commitment "$COMMITMENT" | sed -nE 's/.*slot: ([0-9]+).*/\1/p'
}

case $STEP in
check)
	build
	MAX_INPUT=${MAX_INPUT:-13791360} measure
	printf '\ncheck passed: commitment %s\n' "$COMMITMENT"
	;;
commit)
	build
	MAX_INPUT=$(max_input) measure
	step "committing (bounty $BOUNTY on service $SVC; you are $ME)"
	status=$(bounty_field status.kind)
	case $status in Open | Revealing) ;; *) fail "bounty $BOUNTY is ${status:-not on chain}" ;; esac
	if [ -n "$(commitment_slot)" ]; then
		echo "(committed already, at slot $(commitment_slot))"
	else
		fund "$(deposit_of commit_deposit)"
		N=$(nonce_of)
		printf '%s' "$($W commit --service "$SVC" --bounty "$BOUNTY" --hunter "$HUNTER_SEED" --nonce "$N" --salt "$SALT" \
			--witness-file "$OUT/witness.pack" 2>/dev/null)" >"$OP"
		deliver "commit" eval '[ -n "$(commitment_slot)" ]' || fail "the commitment never landed"
	fi
	put commitment "$COMMITMENT"
	put lemmas "$LEMMAS"
	put commit_slot "$(commitment_slot)"
	printf '\ncommitted: %s at slot %s (lemmas: %s). Reveal from slot %s on, with the same proof and LEMMAS.\n' \
		"$COMMITMENT" "$(commitment_slot)" "$LEMMAS" "$(( $(commitment_slot) + 1 ))"
	;;
reveal)
	build
	if mine; then
		echo "(revealed already: your commitment leads bounty $BOUNTY)"
		bounty_json
		exit 0
	fi
	CS=$(commitment_slot)
	[ -n "$CS" ] || fail "commitment $COMMITMENT isn't on chain: commit first (with this proof and LEMMAS=$LEMMAS)"
	while [ "$(slot)" -le "$CS" ]; do sleep $POLL; done # MIN_COMMIT_AGE (1 slot)
	status=$(bounty_field status.kind)
	case $status in Open | Revealing) ;; *) fail "bounty $BOUNTY is ${status:-not on chain}" ;; esac
	if [ "$LEMMAS" = attest ] && [ ! -f "$OUT/lemmas-attested" ]; then
		step "attesting your lemmas, right before revealing"
		$HUNT lemmas "$SPEC" "$REL" "$OUT/nodes" "$OUT" 0
		CHECK=$REL/lean-check.jam
		GAS_PER_MS=${GAS_PER_MS:-$(python3 "$WITNESS_LEAN_DIR/tools/lean/gas_per_ms.py" "$HOST" "$SIM" "$CHECK" "$OUT/nodes" "$OUT/lemma-plan.json")}
		echo "$GAS_PER_MS" >"$OUT/gas_per_ms"
		"$HOST" trace "$OUT/nodes" "$OUT/lemma-plan.json" "$OUT/lemma-traced.json" $(( 2900000000 / GAS_PER_MS )) | tee "$OUT/lemma-trace.log"
		$HUNT batches "$REL" "$OUT/nodes" "$OUT"
		n=$(ls "$OUT"/own/batch-*.subjects | wc -l)
		for ((i = 0; i < n; i++)); do
			"$HOST" args "$OUT/nodes" "$OUT/lemma-traced.json" "$i" "$OUT/own/probe.args" >/dev/null
			r=$("$SIM" check "$CHECK" "$OUT/own/probe.args" "$MAX_ATTEST_GAS" 2>&1 || true)
			grep -q '^Ok(())' <<<"$r" || fail "your lemma batch $i doesn't attest within $MAX_ATTEST_GAS gas (MAX_ATTEST_GAS): $r"
			echo "lemma batch $i: $r"
		done
		fund $(( $(deposit_of attest_deposit) * n + 10 ))
		python3 "$WITNESS_DIR/scripts/attest-batches.py" "$OUT/own" --witness "$W" --service "$SVC" --check "$CHECK" \
			--check-gas 5000000000 --attesters "$HUNTER_SEED" ${PACKAGE_GAS:+--package-gas "$PACKAGE_GAS"} \
			${PACKAGE_ITEMS:+--package-items "$PACKAGE_ITEMS"} --log "$OUT/attest.jsonl"
		touch "$OUT/lemmas-attested"
	fi
	MAX_INPUT=$(max_input) measure
	step "revealing your proof to bounty $BOUNTY"
	[ -s "$OP" ] || fail "no reveal built"
	deliver "reveal" mine || fail "the reveal had no effect: rejected or dropped. The bounty: $(bounty_json)"
	bounty_json | tee "$OUT/bounty-revealed.json"
	put revealed 1
	printf '\nrevealed: your commitment leads bounty %s; finalize after slot %s\n' "$BOUNTY" "$(bounty_field status.window_end)"
	;;
finalize)
	status=$(bounty_field status.kind)
	if [ "$status" = Revealing ]; then
		END=$(bounty_field status.window_end)
		echo "the claim window ends at slot $END (now $(slot))"
		while [ "$(slot)" -lt "$END" ]; do sleep $POLL; done
		printf '%s' "$($W finalize --bounty "$BOUNTY")" >"$OP"
		deliver "finalize" eval '[ "$(bounty_field status.kind)" = Claimed ]' || fail "finalize had no effect"
	fi
	[ "$(bounty_field status.kind)" = Claimed ] || fail "bounty $BOUNTY is ${status:-not on chain}, not Claimed"
	bounty_json | tee "$OUT/bounty-final.json"
	winner=$(bounty_field status.winner.hunter)
	[ "$winner" = "$ME" ] || fail "the winner is $winner, not you ($ME)"
	printf '\nclaimed: bounty %s paid you (%s); your balance of the test asset is %s\n' "$BOUNTY" "$ME" "$(balance_of)"
	;;
status)
	echo "bounty $BOUNTY on service $SVC: $(bounty_json || echo none)"
	echo "you: $ME, $(show account --account "$HUNTER_SEED"), balance $(balance_of) test"
	c=$(get commitment)
	if [ -n "$c" ]; then COMMITMENT=$c; echo "your commitment $c: $(show commitment --bounty "$BOUNTY" --commitment "$c")"; fi
	;;
*) fail "unknown step $STEP: check, commit, reveal, finalize or status" ;;
esac
