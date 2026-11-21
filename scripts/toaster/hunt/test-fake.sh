#!/usr/bin/env bash
# The hunt (scripts/toaster/hunt/hunt.sh), end to end, against a stand-in node (scripts/toaster/
# lean/fake-node.py over witness-sim): nothing on chain.
#
#   WITNESS_LEAN_DIR=... JAM_LEAN_DIR=... LEAN4EXPORT=... scripts/toaster/hunt/test-fake.sh OUT [RELEASE]
#
# JAM_LEAN_DIR is jam-lean at the Picoalloc library's commit (b8864bd), Services.Picoalloc.Alloc
# built. RELEASE is a directory holding the release's files (scripts/toaster/attestations/build.py's
# output); without it they're downloaded from the release toaster-attestations-v1.
#
# 1. A sim copy of service 7's Picoalloc library: alloc_wf's closure exported from jam-lean afresh,
#    its batches rebuilt from the release (hunt.py replay) and attested in witness-sim. Every claim
#    must be the release's, byte for byte: so the attestation ids are service 7's.
# 2. A maker posts two bounties for `theorem HuntTest.alloc_wf_copy : type_of% @Picoalloc.alloc_wf`
#    (a statement nobody attested), citing the release's cited attestation, and the test writes their
#    specs as site/bounties/N.json are written.
# 3. Rejected before anything is sent: a proof of another statement, and in attest mode a lemma whose
#    type is the goal's, and one with a guessable name.
# 4. Hunter one (witness mode: alloc_wf's own node and proof go in the reveal) checks, commits and
#    reveals to bounty A; hunter two (attest mode: an unguessably named lemma, and alloc_wf, are
#    attested in the reveal step first) commits and reveals to bounty B. Both finalize and are paid.
#    Rerunning a done step must find it done.
set -euo pipefail
: "${WITNESS_LEAN_DIR:?}" "${JAM_LEAN_DIR:?}" "${LEAN4EXPORT:?}"
cd "$(dirname "$0")/../../.."
WITNESS_DIR=$PWD
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
RELEASE=${2:-}
DROP=${DROP:-0.1}
PORT=${PORT:-19872}
JAM_LEAN_DIR=$(cd "$JAM_LEAN_DIR" && pwd) WITNESS_LEAN_DIR=$(cd "$WITNESS_LEAN_DIR" && pwd)
export JAM_LEAN_DIR WITNESS_LEAN_DIR
TAG=toaster-attestations-v1
BASE=https://github.com/ascrivener/witness/releases/download/$TAG
step() { printf '\n==== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
cargo build -q --release -p witness-sim -p witness-cli
cargo jam-build --out-dir out >/dev/null
SIM=$PWD/target/release/witness-sim W=$PWD/target/release/witness
HOST=$WITNESS_LEAN_DIR/target/release/lean-host
rm -rf "$OUT"/*

step "the release's Picoalloc files"
REL=$OUT/release
mkdir -p "$REL"
for f in manifest.json picoalloc.json picoalloc-claims.tar.gz lean-check.jam; do
	if [ -n "$RELEASE" ]; then cp "$RELEASE/$f" "$REL/"; else curl -fsSL -o "$REL/$f" "$BASE/$f"; fi
done
(cd "$REL" && tar xzf picoalloc-claims.tar.gz)
LIB=$REL/picoalloc.json
lib() { python3 -I -c 'import json, sys; v = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v = v[k]
print(v)' "$LIB" "$1"; }
[ "$(git -C "$JAM_LEAN_DIR" rev-parse HEAD)" = "$(lib jam_lean)" ] || fail "JAM_LEAN_DIR isn't at $(lib jam_lean)"
(cd "$JAM_LEAN_DIR" && lake build "$(lib module)" >/dev/null)

step "a sim copy of the library: exported afresh, rebuilt from the release, attested in witness-sim"
(cd "$JAM_LEAN_DIR" && lake env "$LEAN4EXPORT" "$(lib module)" -- "$(lib goal.theorem)") >"$OUT/lib.ndjson"
"$HOST" convert "$OUT/lib.ndjson" "$OUT/lib-nodes" >/dev/null
python3 scripts/toaster/hunt/hunt.py replay "$REL" picoalloc "$OUT/lib-nodes" "$OUT/lib-work"
export WITNESS_SIM_DIR=$OUT/chain
"$SIM" create-service out/witness-service.jam 10000000000 >/dev/null
SVC=$(( 16#$("$SIM" list | tail -1 | cut -f1) ))
item() { printf '%s' "$1" >"$OUT/op.hex"; "$SIM" item "$SVC" "@$OUT/op.hex" >/dev/null; }
item "$($W propose --service "$SVC" --nonce 0 --fee-asset test --commit-deposit 10 --attest-deposit 10)"
for who in hunt-test-maker hunt-test-pat hunt-test-quinn; do item "$($W mint --to "$who" --amount 1000000)"; done
# Not bounty 0, as on the Toaster.
item "$($W create --service "$SVC" --maker hunt-test-maker --nonce 0 --check out/blake2b-preimage-check.jam \
	--params-blake2b x --reward 100 --check-gas 10000000 --expiry 100000)"
python3 scripts/toaster/hunt/hunt.py probe "$OUT/probe.args"
if [ -z "${POLKAVM_BACKEND:-}" ] && grep -q BadCheckBlob <<<"$("$SIM" check out/blake2b-preimage-check.jam "$OUT/probe.args" 100000000 2>&1 || true)"; then
	export POLKAVM_BACKEND=interpreter
	echo "PolkaVM's recompiler is unavailable here: its interpreter (same gas)"
fi
(cd "$OUT/lib-work" && python3 "$WITNESS_DIR/scripts/attest-batches.py" . --witness "$W" --service "$SVC" --check "$REL/lean-check.jam" \
	--check-gas 5000000000 --attesters hunt-test-pat,hunt-test-quinn --sim "$SIM") | tail -3
n=$(lib batch_count)
for ((i = 0; i < n; i++)); do
	cmp -s "$OUT/lib-work/batch-$i.claim" "$REL/picoalloc/lib-$i.claim" || fail "batch $i's claim isn't the release's"
	[ -n "$("$SIM" inspect storage --raw "$SVC" "$($W key --attestation "$REL/picoalloc/lib-$i.claim")" 2>/dev/null)" ] \
		|| fail "the release's attestation $i isn't in witness-sim"
done
echo "all $n claims are the release's, byte for byte, and attested in witness-sim"

step "the maker posts two bounties for HuntTest.alloc_wf_copy"
THEOREM=HuntTest.alloc_wf_copy
mkdir -p "$OUT/maker"
cat >"$OUT/maker/HuntGoal.lean" <<EOF
import $(lib module)

theorem $THEOREM : type_of% @Picoalloc.alloc_wf := sorry
EOF
LP=$(cd "$JAM_LEAN_DIR" && lake env printenv LEAN_PATH)
(cd "$JAM_LEAN_DIR" && lake env lean --root="$OUT/maker" -o "$OUT/maker/HuntGoal.olean" "$OUT/maker/HuntGoal.lean" 2>&1 | grep -v sorry || true)
(cd "$JAM_LEAN_DIR" && LEAN_PATH="$LP:$OUT/maker" "$LEAN4EXPORT" HuntGoal -- "$THEOREM") >"$OUT/maker/goal.ndjson"
"$HOST" convert "$OUT/maker/goal.ndjson" "$OUT/maker/nodes" >/dev/null
GOAL=$(python3 -I -c 'import json, sys; print(next(e["hash"] for e in json.load(open(sys.argv[1])) if sys.argv[2] in e["names"]))' \
	"$OUT/maker/nodes/manifest.json" "$THEOREM")
CITE=$REL/picoalloc/$(lib cite.claim):$(lib cite.entry)
for k in 1 2; do
	item "$($W create --service "$SVC" --maker hunt-test-maker --nonce "$k" --check "$REL/lean-check.jam" --params "$GOAL" \
		--blobs "$CITE" --reward 500 --check-gas 5000000000 --expiry 100000)"
done
for id in 1 2; do
	"$W" decode --bounty "$("$SIM" inspect storage --raw "$SVC" "$($W key --bounty $id)")" | grep -q 'status: Open' || fail "bounty $id isn't open"
done
echo "bounties 1 and 2: prove $THEOREM ($GOAL)"
for id in 1 2; do
	python3 -I - "$OUT/spec-$id.json" "$LIB" "$SVC" "$id" "$THEOREM" "$GOAL" "$BASE" <<'PY'
import json, sys
out, lib_path, svc, bid, theorem, goal, base = sys.argv[1:]
lib = json.load(open(lib_path))
names = ["manifest.json", "picoalloc.json", "picoalloc-claims.tar.gz", "lean-check.jam"]
spec = {"format": 1, "service": int(svc), "bounty": int(bid), "title": "test: " + theorem,
        "statement": {"theorem": theorem, "type": "type_of% @Picoalloc.alloc_wf", "module": lib["module"],
                      "imports": [lib["module"]], "node": goal, "lean_toolchain": lib["lean_toolchain"]},
        "pins": {"jam_lean": lib["jam_lean"], "witness_lean": lib["witness_lean"], "lean4export": lib["lean4export"]},
        "check": {"hash": lib["check_hash"], "sha256": lib["check_sha256"]}, "check_gas": 5000000000,
        "library": "picoalloc", "cite": {**lib["cite"], "library": "picoalloc"},
        "reward": "500", "asset": {"service": 4294967295, "id": 0, "name": "test"}, "claim_window": 30,
        "release": {"tag": "toaster-attestations-v1", "manifest": f"{base}/manifest.json",
                    "assets": {n: f"{base}/{n}" for n in names}}}
json.dump(spec, open(out, "w"), indent=1)
PY
done

python3 scripts/toaster/lean/fake-node.py "$PORT" "$SIM" "$SVC" "$DROP" >"$OUT/fake-node.log" 2>&1 &
NODE=$!
trap 'kill $NODE 2>/dev/null || true' EXIT
sleep 1
export JAM_RPC=ws://127.0.0.1:$PORT RELEASE_LOCAL=$REL
unset WITNESS_SIM_DIR
HUNT=scripts/toaster/hunt/hunt.sh
expect_fail() { # WHAT PATTERN COMMAND...
	local what=$1 pattern=$2; shift 2
	if "$@" >"$OUT/neg.log" 2>&1; then fail "$what was accepted"; fi
	grep -q "$pattern" "$OUT/neg.log" || { tail -20 "$OUT/neg.log"; fail "$what failed, but not with /$pattern/"; }
	echo "ok: refused $what"
}

step "refused before sending: another statement, a lemma of the goal's type, a guessable name"
mkdir -p "$OUT/proofs"
cat >"$OUT/proofs/other.lean" <<EOF
import $(lib module)

theorem $THEOREM : True := trivial
EOF
cat >"$OUT/proofs/sametype.lean" <<EOF
import $(lib module)

theorem HuntTest.step_0123456789abcdef : type_of% @Picoalloc.alloc_wf := @Picoalloc.alloc_wf
theorem $THEOREM : type_of% @Picoalloc.alloc_wf := @HuntTest.step_0123456789abcdef
EOF
cat >"$OUT/proofs/guessable.lean" <<EOF
import $(lib module)

theorem HuntTest.step : True ∧ type_of% @Picoalloc.alloc_wf := ⟨trivial, @Picoalloc.alloc_wf⟩
theorem $THEOREM : type_of% @Picoalloc.alloc_wf := HuntTest.step.2
EOF
expect_fail "a proof of another statement" "isn't exactly the bounty's" \
	env HUNTER_SEED=hunt-test-x "$HUNT" check "$OUT/spec-1.json" "$OUT/proofs/other.lean" "$OUT/neg"
expect_fail "attesting a lemma of the goal's type" "its type is the goal's" \
	env HUNTER_SEED=hunt-test-x LEMMAS=attest "$HUNT" check "$OUT/spec-1.json" "$OUT/proofs/sametype.lean" "$OUT/neg"
expect_fail "attesting a lemma with a guessable name" "nobody would guess" \
	env HUNTER_SEED=hunt-test-x LEMMAS=attest "$HUNT" check "$OUT/spec-1.json" "$OUT/proofs/guessable.lean" "$OUT/neg"

step "hunter one, witness mode, bounty 1: check, commit, reveal"
cat >"$OUT/proofs/one.lean" <<EOF
import $(lib module)

theorem $THEOREM : type_of% @Picoalloc.alloc_wf := @Picoalloc.alloc_wf
EOF
export HUNTER_SEED=hunt-test-one-$RANDOM
"$HUNT" check "$OUT/spec-1.json" "$OUT/proofs/one.lean" "$OUT/one"
"$HUNT" commit "$OUT/spec-1.json" "$OUT/proofs/one.lean" "$OUT/one"
# The reveal on another machine: a fresh work directory, rebuilt from the proof.
"$HUNT" reveal "$OUT/spec-1.json" "$OUT/proofs/one.lean" "$OUT/one-again"
"$HUNT" reveal "$OUT/spec-1.json" "$OUT/proofs/one.lean" "$OUT/one-again" | tee "$OUT/again.log"
grep -q "(revealed already" "$OUT/again.log" || fail "a second reveal should find it done"
ONE=$HUNTER_SEED

step "hunter two, attest mode, bounty 2: commit, then attest the lemmas and reveal"
TOKEN=$(openssl rand -hex 8)
cat >"$OUT/proofs/two.lean" <<EOF
import $(lib module)

theorem HuntTest.step_$TOKEN : True ∧ type_of% @Picoalloc.alloc_wf := ⟨trivial, @Picoalloc.alloc_wf⟩
theorem $THEOREM : type_of% @Picoalloc.alloc_wf := (HuntTest.step_$TOKEN).2
EOF
cat "$OUT/proofs/two.lean"
export HUNTER_SEED=hunt-test-two-$RANDOM LEMMAS=attest
"$HUNT" commit "$OUT/spec-2.json" "$OUT/proofs/two.lean" "$OUT/two"
"$HUNT" reveal "$OUT/spec-2.json" "$OUT/proofs/two.lean" "$OUT/two-again"
[ -s "$OUT/two-again/attest.jsonl" ] || fail "no lemmas attested"
TWO=$HUNTER_SEED
unset LEMMAS

step "both finalize after the claim window, and are paid"
HUNTER_SEED=$ONE "$HUNT" finalize "$OUT/spec-1.json" "" "$OUT/one-again"
HUNTER_SEED=$TWO "$HUNT" finalize "$OUT/spec-2.json" "" "$OUT/two-again"
HUNTER_SEED=$ONE "$HUNT" status "$OUT/spec-1.json" "" "$OUT/one-again"
# finalize checked each was the winner; their balances, for the log.
for who in $ONE $TWO; do
	echo "$who: $($W decode --balance "$(python3 scripts/jam-storage.py "$SVC" "$($W key --balance "$who" --asset test)")") test"
done
printf '\nhunt passed against fake-node: commit, reveal (witness and attest modes) and finalize\n'
