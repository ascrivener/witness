#!/usr/bin/env bash
# A witness bounty paid out for a Lean proof of a jam-lean theorem, end to end, in witness-sim:
#
#   WITNESS_LEAN_DIR=../witness-lean JAM_LEAN_DIR=../jam-lean \
#     LEAN4EXPORT=../lean4export/.lake/build/bin/lean4export scripts/lean-bounty-demo.sh [OUT]
#
# The target is Picoalloc.alloc_wf (jam-lean's Services/Picoalloc/Alloc.lean: an alignment-1
# alloc keeps the heap invariant), over Lean core only. MODULE and THEOREM pick another;
# OTHER (in OTHER_MODULE) is "a different statement" for the negative case: one no one has
# attested, so outside THEOREM's closure. WRONG is a theorem of THEOREM's closure whose proof the
# wrong-proof case pairs with THEOREM's statement. See docs/demo-lean-bounty.md for what it shows and the numbers it measured.
#
# 1. Export THEOREM's closure from jam-lean (lean4export) and convert it to content-addressed
#    nodes (witness-lean's `lean-host convert`).
# 2. Plan the library (everything but THEOREM, core included) into batches by dependency depth,
#    trusting only what the kernel touches (`lean-host trace`), and attest every batch in
#    witness-sim, several attesters a round (scripts/attest-batches.py).
# 3. Alice posts a bounty whose check is witness-lean's Lean check, with params the hash of
#    THEOREM's statement node (its name and type: no proof), citing one attested node.
#    She also posts a second bounty for OTHER's statement (hashed from its own export).
# 4. Carol commits to a wrong proof (THEOREM's statement with WRONG's proof); Bob commits to the
#    real one. Carol's reveal is rejected; Bob's real proof is rejected by the OTHER bounty
#    (a proof of a different statement); Bob's reveal to the THEOREM bounty is accepted.
# 5. After the claim window, Finalize pays Bob the reward.
#
# Everything is measured: the gas each check used (witness-sim charges PolkaJam v0.1.29's gas for
# the check in PolkaVM), the batches, blob sizes and wall-clock times. OUT (default a temporary
# directory) keeps the work, the simulated chain and its log, and report.md / report.json.
#
# Needs: elan with jam-lean's toolchain (v4.36.0-rc1), a lean4export built for it, cargo-jam-build
# 0.1.29 (see README), and Python 3.
set -euo pipefail
: "${WITNESS_LEAN_DIR:?set WITNESS_LEAN_DIR to a witness-lean checkout}"
: "${JAM_LEAN_DIR:?set JAM_LEAN_DIR to a jam-lean checkout}"
: "${LEAN4EXPORT:?set LEAN4EXPORT to the lean4export binary}"
MODULE=${MODULE:-Services.Picoalloc.Alloc}
THEOREM=${THEOREM:-Picoalloc.alloc_wf}
OTHER=${OTHER:-Picoalloc.free_wf}
OTHER_MODULE=${OTHER_MODULE:-Services.Picoalloc.Free}
WRONG=${WRONG:-Picoalloc.allocPost_wf}
# The bounty's check gas: witness_types::MAX_CHECK_GAS, all a check may have.
GAS=${GAS:-5000000000}
MAX_CHECK_GAS=5000000000
REWARD=500

cd "$(dirname "$0")/.."
WITNESS_DIR=$PWD
WITNESS_LEAN_DIR=$(cd "$WITNESS_LEAN_DIR" && pwd)
JAM_LEAN_DIR=$(cd "$JAM_LEAN_DIR" && pwd)
OUT=${1:-$(mktemp -d)}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
rm -rf "$OUT/nodes" "$OUT/w" "$OUT/sim" "$OUT/extrinsics"
W=$WITNESS_DIR/target/release/witness
SIM=$WITNESS_DIR/target/release/witness-sim
HOST=$WITNESS_LEAN_DIR/target/release/lean-host
LEANTOOLS=$WITNESS_LEAN_DIR/tools/lean
CHECK=$OUT/lean-check.jam
X=$OUT/extrinsics OP=$OUT/op.hex
export WITNESS_SIM_DIR=$OUT/sim
LOG=$WITNESS_SIM_DIR/log
TIMES=$OUT/times.tsv
: >"$TIMES"

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
now() { date +%s.%N; }
# Time a phase: `phase NAME` starts it (and ends the one before), `phase` alone ends the last.
PHASE= PHASE_START= PHASE_LOG=0
phase() {
	local t; t=$(now)
	local lines=0; [ -f "$LOG" ] && lines=$(wc -l <"$LOG")
	[ -n "$PHASE" ] && printf '%s\t%s\t%s\t%s\n' "$PHASE" "$(echo "$t - $PHASE_START" | bc)" "$PHASE_LOG" "$lines" >>"$TIMES"
	PHASE=${1:-} PHASE_START=$t PHASE_LOG=$lines
}
slot() { "$SIM" inspect slot; }
wait_slot() { while [ "$(slot)" -lt "$1" ]; do :; done; }
storage() {
	local v; v=$("$SIM" inspect storage --raw "$SVC" "$($W key "$@")" 2>/dev/null || true)
	case $v in 0x*) echo "$v" ;; *) echo "" ;; esac
}
show() {
	local kind=$1; shift
	local v; v=$(storage "$@")
	if [ -n "$v" ]; then $W decode "--$kind" "$v"; else echo none; fi
}
expect() {
	local what=$1 pattern=$2; shift 2
	local out; out=$(show "$@")
	grep -qE "$pattern" <<<"$out" || fail "$what: wanted /$pattern/, got: $out"
	echo "ok: $what"
}
# Submit PAYLOAD with the extrinsics the CLI last wrote, if any; print what refine said.
item() {
	[ -n "$1" ] || fail "no payload"
	printf '%s' "$1" >"$OP"
	"$SIM" item "$SVC" "@$OP" $(ls "$X"/* 2>/dev/null) >/dev/null
	rm -rf "$X"
}
last_refine() { grep 'refine:' "$LOG" | tail -1 | sed 's/.*refine: //' | cut -c1-160; }
last_check_gas() { grep 'check used' "$LOG" | tail -1 | grep -oE 'used [0-9]+' | cut -d' ' -f2; }
declare -A NONCE=([alice]=0 [bob]=0 [carol]=0)
take() { N=${NONCE[$1]}; NONCE[$1]=$((N + 1)); }
DEMO_START=$(now)

step "building witness (service, CLI, simulator) and witness-lean (check, lean-host)"
phase build
(cargo build -q --release -p witness-sim -p witness-cli && cargo jam-build --out-dir out -p witness-service >/dev/null)
(cd "$WITNESS_LEAN_DIR" && cargo build -q --release -p lean-host && cargo jam-build --out-dir out >/dev/null)
cp "$WITNESS_LEAN_DIR/out/lean-check.jam" "$CHECK"
(cd "$JAM_LEAN_DIR" && lake build "$MODULE" "$OTHER_MODULE" >/dev/null)

step "exporting $THEOREM from jam-lean ($MODULE) and converting it to nodes"
phase export
(cd "$JAM_LEAN_DIR" && lake env "$LEAN4EXPORT" "$MODULE" -- "$THEOREM") >"$OUT/export.ndjson"
# The maker of the OTHER bounty hashes its statement from an export of their own: nodes are
# content-addressed, so it's the hash any export of it would give.
(cd "$JAM_LEAN_DIR" && lake env "$LEAN4EXPORT" "$OTHER_MODULE" -- "$OTHER") >"$OUT/other.ndjson"
phase convert
"$HOST" convert "$OUT/export.ndjson" "$OUT/nodes" >/dev/null
rm -rf "$OUT/other-nodes"
"$HOST" convert "$OUT/other.ndjson" "$OUT/other-nodes" >/dev/null
node_of() { # DIR NAME
	python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); print(next(e["hash"] for e in m if sys.argv[2] in e["names"]))' \
		"$1/manifest.json" "$2"
}
GOAL_NODE=$(node_of "$OUT/nodes" "$THEOREM")
WRONG_NODE=$(node_of "$OUT/nodes" "$WRONG")
OTHER_NODE=$(node_of "$OUT/other-nodes" "$OTHER")
[ -e "$OUT/nodes/nodes/$OTHER_NODE" ] && fail "$OTHER is in $THEOREM's closure, so it will be attested: pick another OTHER"
echo "$(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$OUT/nodes/manifest.json") nodes; $THEOREM is $GOAL_NODE"

step "planning the library into batches"
phase plan
python3 "$LEANTOOLS/lean_plan.py" "$OUT/nodes" --goal "$THEOREM" >"$OUT/plan.json"
# PolkaVM's recompiler needs a Linux sandbox some containers can't give it (witness-sim then reports
# BadCheckBlob for every check). Its interpreter charges the same gas (both price a basic block
# with the same cost model), only slower: fall back to it.
"$HOST" args "$OUT/nodes" "$OUT/plan.json" 0 "$OUT/probe.args" >/dev/null
if [ -z "${POLKAVM_BACKEND:-}" ] && ! "$SIM" check "$CHECK" "$OUT/probe.args" "$GAS" >/dev/null 2>&1; then
	POLKAVM_BACKEND=interpreter "$SIM" check "$CHECK" "$OUT/probe.args" "$GAS" >/dev/null \
		|| fail "the Lean check doesn't run in witness-sim, recompiled or interpreted"
	echo "PolkaVM's recompiler is unavailable here: running checks in its interpreter (same gas)"
	export POLKAVM_BACKEND=interpreter
fi
echo "polkavm backend: ${POLKAVM_BACKEND:-default}" >"$OUT/backend"
# What a native millisecond of the check costs in gas on this machine, so batches are cut to fit
# a refine (as witness-lean's lean-e2e.sh): TRACE_GAS a batch, by default 2.9×10⁹.
GAS_PER_MS=${GAS_PER_MS:-$(python3 "$LEANTOOLS/gas_per_ms.py" "$HOST" "$SIM" "$CHECK" "$OUT/nodes" "$OUT/plan.json")}
TRACE_MS=${TRACE_MS:-$(( ${TRACE_GAS:-2900000000} / GAS_PER_MS ))}
echo "$(( GAS_PER_MS / 1000000 ))M gas per native ms: batches up to $TRACE_MS ms"
"$HOST" trace "$OUT/nodes" "$OUT/plan.json" "$OUT/plan-traced.json" "$TRACE_MS" | tee "$OUT/trace.log"
mv "$OUT/plan-traced.json" "$OUT/plan.json"
if grep -q '^over ' "$OUT/trace.log"; then
	fail "a declaration alone is over a batch's budget (see $OUT/trace.log): pick a lighter target, or split it with witness-lean's lean_split.py"
fi
BATCHES=$(python3 "$LEANTOOLS/lean_batches.py" "$OUT/nodes" "$OUT/plan.json" "$OUT/w" --gas-per-ms "$GAS_PER_MS")
PINS=$(cat "$OUT/w/pins")
for ((i = 0; i < ${#PINS}; i += 64)); do
	grep -q "^${PINS:i:64} " "$WITNESS_LEAN_DIR/check/pins.txt" || fail "pinned node ${PINS:i:64} isn't among the check's pins: another toolchain?"
done
[ "$(cat "$OUT/w/goal.hash")" = "$GOAL_NODE" ] || fail "the plan's goal isn't $THEOREM"
CITE=$(cat "$OUT/w/goal.cite")
echo "$BATCHES batches"

step "deploying witness in witness-sim and configuring it"
phase deploy
"$SIM" create-service out/witness-service.jam 10000000000 >/dev/null
SVC=$(( 16#$("$SIM" list | tail -1 | cut -f1) ))
item "$($W propose --service "$SVC" --nonce 0 --fee-asset test --commit-deposit 10 --attest-deposit 10)"
expect "witness configured" 'fee_asset: Some' config --config
ATTESTERS=${ATTESTERS:-pat,quinn,rene,sam}
for who in alice bob carol ${ATTESTERS//,/ }; do item "$($W mint --to "$who" --amount 1000000)"; done

step "attesters ($ATTESTERS) attest the library: $BATCHES batches"
phase attest
python3 "$WITNESS_DIR/scripts/attest-batches.py" "$OUT/w" --witness "$W" --service "$SVC" --check "$CHECK" \
	--check-gas "$GAS" --attesters "$ATTESTERS" --sim "$SIM"

step "alice posts the bounties"
phase bounty
take alice
item "$($W create --service "$SVC" --maker alice --nonce $N --check "$CHECK" --params "$GOAL_NODE" \
	--blobs "$CITE" --reward $REWARD --check-gas "$GAS" --expiry $(( $(slot) + 2000 )))"
expect "bounty 0 open: prove $THEOREM ($GOAL_NODE)" 'status: Open' bounty --bounty 0
take alice
item "$($W create --service "$SVC" --maker alice --nonce $N --check "$CHECK" --params "$OTHER_NODE" \
	--blobs "$CITE" --reward $REWARD --check-gas "$GAS" --expiry $(( $(slot) + 2000 )))"
expect "bounty 1 open: prove $OTHER ($OTHER_NODE)" 'status: Open' bounty --bounty 1
expect "alice escrowed both rewards" "^$((1000000 - 2 * REWARD))\$" balance --balance alice --asset test

# A wrong proof: THEOREM's statement, with WRONG's proof (a real proof, of something else).
python3 -I -c '
import sys
def uvar(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: out.append(b | 0x80)
        else: out.append(b); return bytes(out)
items = [open(p, "rb").read() for p in sys.argv[2:]]
open(sys.argv[1], "wb").write(uvar(len(items)) + b"".join(uvar(len(i)) + i for i in items))
' "$OUT/wrong.pack" "$OUT/nodes/nodes/$GOAL_NODE" "$OUT/nodes/proofs/$WRONG_NODE"

step "hunters commit"
phase commit
take carol
item "$($W commit --service "$SVC" --bounty 0 --hunter carol --nonce $N --salt 0x0c0c --witness-file "$OUT/wrong.pack" 2>/dev/null)"
take bob
item "$($W commit --service "$SVC" --bounty 0 --hunter bob --nonce $N --salt 0x0b0b --witness-file "$OUT/w/goal.pack" 2>/dev/null)"
take bob
item "$($W commit --service "$SVC" --bounty 1 --hunter bob --nonce $N --salt 0x0b0b --witness-file "$OUT/w/goal.pack" 2>/dev/null)"
expect "bob committed twice" "nonce: 2" account --account bob
expect "bob's commit deposits taken" "^$((1000000 - 20))\$" balance --balance bob --asset test
wait_slot $(( $(slot) + 2 ))

TRUST=$(cat "$OUT/w/goal.trust")
reveal() { # BOUNTY PARAMS HUNTER SALT PACK
	item "$($W reveal --bounty "$1" --check "$CHECK" --params "$2" --blobs "$CITE" --trust "$TRUST" \
		--check-gas "$GAS" --hunter "$3" --salt "$4" --witness-file "$5" --extrinsics "$X")"
}

step "carol reveals a wrong proof ($THEOREM's statement, $WRONG's proof)"
phase reveal-wrong-proof
reveal 0 "$GOAL_NODE" carol 0x0c0c "$OUT/wrong.pack"
WRONG_REFINE=$(last_refine) WRONG_GAS=$(last_check_gas)
echo "refine: $WRONG_REFINE"
grep -q 'Rejected' <<<"$WRONG_REFINE" || fail "the wrong proof wasn't rejected"
expect "the wrong proof changed nothing" 'status: Open' bounty --bounty 0

step "bob reveals his proof of $THEOREM to the bounty for $OTHER (a different statement)"
phase reveal-other-statement
reveal 1 "$OTHER_NODE" bob 0x0b0b "$OUT/w/goal.pack"
OTHER_REFINE=$(last_refine) OTHER_GAS=$(last_check_gas)
echo "refine: $OTHER_REFINE"
grep -q 'Rejected' <<<"$OTHER_REFINE" || fail "a proof of another statement wasn't rejected"
expect "bounty 1 unchanged" 'status: Open' bounty --bounty 1

step "bob reveals his proof of $THEOREM"
phase reveal
REVEAL_START=$(now)
reveal 0 "$GOAL_NODE" bob 0x0b0b "$OUT/w/goal.pack"
REVEAL_SECS=$(echo "$(now) - $REVEAL_START" | bc)
REVEAL_REFINE=$(last_refine) REVEAL_GAS=$(last_check_gas)
echo "refine: $REVEAL_REFINE"
expect "bob's proof opens the claim window" 'Revealing' bounty --bounty 0

step "the claim window passes; finalize pays bob"
phase finalize
item "$($W finalize --bounty 0)"
expect "finalizing early changes nothing" 'Revealing' bounty --bounty 0
END=$(show bounty --bounty 0 | sed -nE 's/.*window_end: ([0-9]+).*/\1/p')
[ -n "$END" ] || fail "no window_end in bounty 0"
wait_slot "$END"
item "$($W finalize --bounty 0)"
expect "bounty 0 claimed" 'Claimed' bounty --bounty 0
# Bob's deposit for bounty 0 came back at his reveal; bounty 1's stays locked until he releases it.
expect "bob was paid $REWARD" "^$((1000000 - 10 + REWARD))\$" balance --balance bob --asset test
phase
TOTAL_SECS=$(echo "$(now) - $DEMO_START" | bc)

step "report"
python3 -I - "$OUT" "$BATCHES" "$GAS" "$MAX_CHECK_GAS" "$TOTAL_SECS" "$REVEAL_SECS" "$REVEAL_GAS" "$WRONG_GAS" "$OTHER_GAS" \
	"$WRONG_REFINE" "$OTHER_REFINE" "$THEOREM" "$OTHER" "$GOAL_NODE" "$WRONG" "$GAS_PER_MS" "$WITNESS_DIR/out/witness-service.jam" <<'EOF'
import json, os, re, statistics, sys
(out, batches, gas, max_gas, total, reveal_secs, reveal_gas, wrong_gas, other_gas, wrong_refine,
 other_refine, theorem, other, goal, wrong, gas_per_ms, service) = sys.argv[1:]
log = open(f"{out}/sim/log").read().splitlines()
phases = [l.split("\t") for l in open(f"{out}/times.tsv").read().splitlines()]
times = {p[0]: float(p[1]) for p in phases}
# Every check run during attesting is a batch's attest-mode check.
a0, a1 = next((int(p[2]), int(p[3])) for p in phases if p[0] == "attest")
attest = [int(m.group(1)) for l in log[a0:a1] if (m := re.search(r"check used (\d+) gas", l))]
manifest = json.load(open(f"{out}/nodes/manifest.json"))
sizes = lambda d: [os.path.getsize(f"{out}/nodes/{d}/{f}") for f in os.listdir(f"{out}/nodes/{d}")]
subjects = []
for n in range(int(batches)):
    paths = open(f"{out}/w/batch-{n}.subjects").read().strip().split(",")
    subjects.append(sum(os.path.getsize(p) for p in paths) + os.path.getsize(f"{out}/w/batch-{n}.witness"))
plan = json.load(open(f"{out}/plan.json"))
depths = len({b["depth"] for b in plan if "depth" in b})
goal_trust = next(b for b in plan if "goal" in b)["trusted"]
r = {
    "theorem": theorem, "statement_node": goal, "other_statement": other,
    "nodes": len(manifest), "statement_bytes": sum(sizes("nodes")), "proof_bytes": sum(sizes("proofs")),
    "batches": int(batches), "depths": depths, "attest_checks": len(attest),
    "attest_gas": {"min": min(attest), "median": int(statistics.median(attest)), "max": max(attest), "total": sum(attest)},
    "attest_gas_each": attest,
    "batch_bytes": {"min": min(subjects), "median": int(statistics.median(subjects)), "max": max(subjects)},
    "reveal_gas": int(reveal_gas), "reveal_trusts": len(goal_trust),
    "goal_pack_bytes": os.path.getsize(f"{out}/w/goal.pack"),
    "wrong_proof": {"proof_of": wrong, "gas": int(wrong_gas or 0), "refine": wrong_refine},
    "other_statement_reveal": {"gas": int(other_gas or 0), "refine": other_refine},
    "check_blob_bytes": os.path.getsize(f"{out}/lean-check.jam"), "service_blob_bytes": os.path.getsize(service),
    "export_bytes": os.path.getsize(f"{out}/export.ndjson"),
    "check_gas": int(gas), "max_check_gas": int(max_gas), "gas_per_native_ms": int(gas_per_ms),
    "seconds": {**times, "reveal_item": float(reveal_secs), "total": float(total)},
}
json.dump(r, open(f"{out}/report.json", "w"), indent=1)
pct = lambda g: f"{100 * g / int(max_gas):.1f}%"
a = r["attest_gas"]
lines = [
    f"# {theorem}: a Lean bounty in witness-sim", "",
    f"- {r['nodes']} nodes ({r['statement_bytes']:,} B of statements, {r['proof_bytes']:,} B of proofs), from a {r['export_bytes']:,} B export",
    f"- {r['batches']} attest batches over {depths} depths; a batch's subjects and witness {r['batch_bytes']['min']:,}–{r['batch_bytes']['max']:,} B (median {r['batch_bytes']['median']:,})",
    f"- attest gas: min {a['min']:.3g}, median {a['median']:.3g}, max {a['max']:.3g} ({pct(a['max'])} of MAX_CHECK_GAS), total {a['total']:.3g}",
    f"- reveal gas: {r['reveal_gas']:.3g} ({pct(r['reveal_gas'])} of MAX_CHECK_GAS), trusting {r['reveal_trusts']} nodes; witness {r['goal_pack_bytes']:,} B",
    f"- wrong proof ({theorem}'s statement, {wrong}'s proof): {wrong_refine} after {r['wrong_proof']['gas']:.3g} gas",
    f"- {theorem}'s proof revealed to a bounty for {other}: {other_refine} after {r['other_statement_reveal']['gas']:.3g} gas",
    f"- check blob {r['check_blob_bytes']:,} B, service blob {r['service_blob_bytes']:,} B; {int(gas_per_ms)/1e6:.0f}M gas per native ms here",
    "", "| phase | seconds |", "|---|---|",
] + [f"| {k} | {v:.1f} |" for k, v in r["seconds"].items()]
open(f"{out}/report.md", "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
EOF
printf '\nLean bounty demo passed: %s (work in %s)\n' "$THEOREM" "$OUT"
