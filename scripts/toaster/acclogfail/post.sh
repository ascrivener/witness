#!/usr/bin/env bash
# Post a witness bounty for jam-lean's AccLogFail (T2's named hypothesis, as AccLogFailGoal in
# jam-lean's Services/Bootstrap/Acc/Final/Bounty.lean), with witness-lean's Lean check:
#
#   WITNESS_LEAN_DIR=../witness-lean JAM_LEAN_DIR=../jam-lean \
#     LEAN4EXPORT=../lean4export/.lake/build/bin/lean4export scripts/toaster/acclogfail/post.sh OUT
#
# JAM_LEAN_DIR must have Services.Bootstrap.Acc.Final.Bounty built. The bounty is for
#
#   theorem Services.Bootstrap.Acc.Final.accLogFail_bounty : AccLogFailGoal
#
# and its params are the hash of that theorem's statement node (its name and type, no proof).
# See docs/toaster-acclogfail.md.
#
# 1. Export and convert the statement. The theorem is stated with `sorry` only to be hashed: the
#    library is the statement's closure (what its type uses, and what their proofs use), never the
#    goal or its proof, so `sorryAx` is in neither.
# 2. Plan the library, trace it (each batch trusts only what the kernel touches) and split any
#    batch of more than MAX_SUBJECTS subjects (its subjects travel as one command-line argument;
#    subjects of one depth are independent, and each part keeps the batch's trust).
# 3. Dry run, always: attest every batch in witness-sim, PolkaVM charging PolkaJam's gas, and stop
#    unless every batch is accepted using at most MAX_ATTEST_GAS (default 3.5e9, 70% of a refine's
#    5e9). Then post the bounty there too, as a check of the post itself.
# 4. Live, with SERVICE_ID and TAG set: on the chain at JAM_RPC (default ws://localhost:19800),
#    against witness deployed as SERVICE_ID with the test asset (the Toaster's service 7): mint for
#    the run's accounts, attest the batches (scripts/attest-batches.py, resuming from the chain),
#    then the maker posts the bounty: REWARD (default 1,000,000) of the test asset, check gas 5e9,
#    expiry EXPIRY_SLOTS (default 1,296,000, about 90 days) after posting, citing the attestation of
#    AccLogFailGoal. OUT/state records what's done, so a rerun resumes.
#
# Accounts are seeds: MAKER (default bounty-acclogfail-maker) posts; bounty-acclogfail-TAG-pat,
# -quinn, -rene and -sam attest. PACKAGE_GAS, PACKAGE_ITEMS, SETTLE_SLOTS and LAND_SLOTS go to
# attest-batches.py. Writes OUT/report.md and OUT/report.json.
set -euo pipefail
: "${WITNESS_LEAN_DIR:?set WITNESS_LEAN_DIR to a witness-lean checkout}"
: "${JAM_LEAN_DIR:?set JAM_LEAN_DIR to a jam-lean checkout with the Bounty module built}"
: "${LEAN4EXPORT:?set LEAN4EXPORT to the lean4export binary}"
NS=Services.Bootstrap.Acc.Final
MODULE=$NS.Bounty
STATEMENT=$NS.AccLogFailGoal
THEOREM=$NS.accLogFail_bounty
GAS=5000000000                 # the bounty's and each attestation's check gas: MAX_CHECK_GAS
MAX_ATTEST_GAS=${MAX_ATTEST_GAS:-3500000000}
MAX_SUBJECTS=${MAX_SUBJECTS:-800}
REWARD=${REWARD:-1000000}
EXPIRY_SLOTS=${EXPIRY_SLOTS:-1296000}
MAKER=${MAKER:-bounty-acclogfail-maker}
# --bind-claim (BIND_CLAIM=1) limits a reveal to trusting one attestation beyond the bounty's, which
# a library attested in hundreds of batches can't meet: off by default (docs/toaster-acclogfail.md).
BIND=${BIND_CLAIM:+--bind-claim}

cd "$(dirname "$0")/../../.."
WITNESS_DIR=$PWD
WITNESS_LEAN_DIR=$(cd "$WITNESS_LEAN_DIR" && pwd)
JAM_LEAN_DIR=$(cd "$JAM_LEAN_DIR" && pwd)
OUT=$(mkdir -p "${1:?usage: post.sh OUT}" && cd "$1" && pwd)
SERVICE_ID=${SERVICE_ID:-}
if [ -n "$SERVICE_ID" ]; then
	: "${TAG:?live mode (SERVICE_ID) needs TAG, to name the attesters}"
	export JAM_RPC=${JAM_RPC:-ws://localhost:19800}
fi
TAG=${TAG:-sim}
ATTESTERS=${ATTESTERS:-bounty-acclogfail-$TAG-pat,bounty-acclogfail-$TAG-quinn,bounty-acclogfail-$TAG-rene,bounty-acclogfail-$TAG-sam}
W=$WITNESS_DIR/target/release/witness
SIM=$WITNESS_DIR/target/release/witness-sim
HOST=$WITNESS_LEAN_DIR/target/release/lean-host
LEANTOOLS=$WITNESS_LEAN_DIR/tools/lean
CHECK=$OUT/lean-check.jam
STATE=$OUT/state
touch "$STATE"
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
get() { sed -n "s/^$1=//p" "$STATE" | tail -1; }
put() { echo "$1=$2" >>"$STATE"; }

step "building witness (CLI, simulator, service) and witness-lean (check, lean-host)"
(cargo build -q --release -p witness-sim -p witness-cli && cargo jam-build --out-dir out -p witness-service >/dev/null)
(cd "$WITNESS_LEAN_DIR" && cargo build -q --release -p lean-host && cargo jam-build --out-dir out >/dev/null)
# A resumed run keeps the check its attestations name.
if [ -f "$CHECK" ]; then
	cmp -s "$WITNESS_LEAN_DIR/out/lean-check.jam" "$CHECK" || fail "the check built now differs from $CHECK, which earlier attestations name"
else
	cp "$WITNESS_LEAN_DIR/out/lean-check.jam" "$CHECK"
fi
(cd "$JAM_LEAN_DIR" && lake build "$MODULE" >/dev/null)
put check_hash "$($W hash --check "$CHECK")"

# From here on, in OUT: the batches name their files and claims by paths relative to it, which keeps
# each command-line argument they become (a batch's subjects, its trust) under Linux's 128 KiB.
cd "$OUT"
if [ -f "$OUT/w/goal.hash" ] && [ -n "$(get planned)" ]; then
	step "reusing the plan in $OUT"
else
	rm -rf "$OUT/goal" "$OUT/all" "$OUT/nodes" "$OUT/w" "$OUT/dry"
	step "exporting $THEOREM's statement and converting it to nodes"
	mkdir -p "$OUT/goal"
	cat >"$OUT/goal/AccLogFailBountyGoal.lean" <<EOF
import $MODULE

/-- The bounty's statement, stated only to hash its node: the bounty pays for a proof of it. -/
theorem $THEOREM : $STATEMENT := sorry
EOF
	LEAN_PATH_JAM=$(cd "$JAM_LEAN_DIR" && lake env printenv LEAN_PATH)
	(cd "$JAM_LEAN_DIR" && lake env lean --root="$OUT/goal" -o "$OUT/goal/AccLogFailBountyGoal.olean" \
		"$OUT/goal/AccLogFailBountyGoal.lean" 2>&1 | grep -v "declaration uses 'sorry'\|declaration uses \`sorry\`" || true)
	[ -f "$OUT/goal/AccLogFailBountyGoal.olean" ] || fail "the goal module didn't compile"
	(cd "$JAM_LEAN_DIR" && LEAN_PATH="$LEAN_PATH_JAM:$OUT/goal" "$LEAN4EXPORT" AccLogFailBountyGoal -- "$THEOREM") >"$OUT/export.ndjson"
	"$HOST" convert "$OUT/export.ndjson" "$OUT/all" >/dev/null
	# The library: the goal's statement closure. Every node the goal's type imports, recursively,
	# with what their proofs import; not the goal, and not what only its proof (sorry) imports.
	python3 -I - "$OUT/all" "$OUT/nodes" "$THEOREM" "$STATEMENT" <<'PY'
import json, os, sys
src, dst, theorem, statement = sys.argv[1:]
manifest = json.load(open(f"{src}/manifest.json"))
by_hash = {e["hash"]: e for e in manifest}
goal = next(e for e in manifest if theorem in e["names"])
stmt = next(e for e in manifest if statement in e["names"])
assert goal["imports"] == [stmt["hash"]], f"the goal's type should use only {statement}: {goal['imports']}"
keep, todo = set(), list(goal["imports"])
while todo:
    h = todo.pop()
    if h not in keep:
        keep.add(h)
        todo += by_hash[h]["imports"] + by_hash[h].get("proof_imports", [])
assert not any(n == "sorryAx" for h in keep for n in by_hash[h]["names"]), "sorryAx in the library"
keep.add(goal["hash"])  # planned as the goal: left out of the batches
os.makedirs(f"{dst}/nodes"); os.makedirs(f"{dst}/proofs")
for h in keep:
    for d in ("nodes", "proofs"):
        if os.path.exists(f"{src}/{d}/{h}"):
            os.link(f"{src}/{d}/{h}", f"{dst}/{d}/{h}")
# The goal as a statement alone: what only its proof (sorry) imports isn't the library's.
entries = [dict(e) for e in manifest if e["hash"] in keep]
for e in entries:
    if e["hash"] == goal["hash"]:
        e.pop("proof_imports", None)
json.dump(entries, open(f"{dst}/manifest.json", "w"))
print(f"{len(keep) - 1} library nodes, of {len(manifest)} in the export")
PY

	step "planning the library into batches"
	python3 "$LEANTOOLS/lean_plan.py" "$OUT/nodes" --goal "$THEOREM" >"$OUT/plan.json"
	"$HOST" args "$OUT/nodes" "$OUT/plan.json" 0 "$OUT/probe.args" >/dev/null
	if [ -z "${POLKAVM_BACKEND:-}" ] && ! "$SIM" check "$CHECK" "$OUT/probe.args" "$GAS" >/dev/null 2>&1; then
		POLKAVM_BACKEND=interpreter "$SIM" check "$CHECK" "$OUT/probe.args" "$GAS" >/dev/null \
			|| fail "the Lean check doesn't run in witness-sim, recompiled or interpreted"
		echo "PolkaVM's recompiler is unavailable here: running checks in its interpreter (same gas)"
		export POLKAVM_BACKEND=interpreter
	fi
	put polkavm_backend "${POLKAVM_BACKEND:-default}"
	GAS_PER_MS=${GAS_PER_MS:-$(python3 "$LEANTOOLS/gas_per_ms.py" "$HOST" "$SIM" "$CHECK" "$OUT/nodes" "$OUT/plan.json")}
	put gas_per_ms "$GAS_PER_MS"
	TRACE_MS=${TRACE_MS:-$(( ${TRACE_GAS:-2900000000} / GAS_PER_MS ))}
	echo "$(( GAS_PER_MS / 1000000 ))M gas per native ms: batches up to $TRACE_MS ms"
	# The trace checks each entry, the goal's (sorry) proof included: trace the batches alone, and put
	# the goal back after.
	python3 -I -c 'import json, sys; p = json.load(open(sys.argv[1])); json.dump([b for b in p if "goal" not in b], open(sys.argv[2], "w")); json.dump([b for b in p if "goal" in b], open(sys.argv[3], "w"))' \
		"$OUT/plan.json" "$OUT/plan-batches.json" "$OUT/plan-goal.json"
	"$HOST" trace "$OUT/nodes" "$OUT/plan-batches.json" "$OUT/plan-traced.json" "$TRACE_MS" | tee "$OUT/trace.log"
	python3 -I -c 'import json, sys; json.dump(json.load(open(sys.argv[1])) + json.load(open(sys.argv[2])), open(sys.argv[1], "w"))' \
		"$OUT/plan-traced.json" "$OUT/plan-goal.json"
	# A declaration over budget on its own stays a batch of its own; native timing is noisy, and the
	# dry run below measures every batch in PolkaVM, which decides.
	grep '^over ' "$OUT/trace.log" || true
	python3 -I - "$OUT/plan-traced.json" "$OUT/plan.json" "$MAX_SUBJECTS" <<'PY'
import json, sys
src, dst, most = sys.argv[1], sys.argv[2], int(sys.argv[3])
plan, out = json.load(open(src)), []
for b in plan:
    s = b.get("subjects")
    if s and len(s) > most:
        out += [{**b, "subjects": s[i:i + most]} for i in range(0, len(s), most)]
    else:
        out.append(b)
json.dump(out, open(dst, "w"))
print(f"{len(out) - len(plan)} batches added by splitting batches of over {most} subjects")
PY
	BATCHES=$(python3 "$LEANTOOLS/lean_batches.py" nodes plan.json w --gas-per-ms "$GAS_PER_MS")
	for f in w/batch-*.subjects w/batch-*.trust; do
		[ "$(wc -c <"$f")" -le 120000 ] || fail "$f is over 120 KB, too long for one command-line argument: lower MAX_SUBJECTS"
	done
	PINS=$(cat "$OUT/w/pins")
	for ((i = 0; i < ${#PINS}; i += 64)); do
		grep -q "^${PINS:i:64} " "$WITNESS_LEAN_DIR/check/pins.txt" || fail "pinned node ${PINS:i:64} isn't among the check's pins: another toolchain?"
	done
	echo "$BATCHES batches"
	put planned 1
fi
[ "$(get polkavm_backend)" = default ] || export POLKAVM_BACKEND=$(get polkavm_backend)
GOAL_NODE=$(cat "$OUT/w/goal.hash")
CITE=$(cat "$OUT/w/goal.cite")
BATCHES=$(ls "$OUT"/w/batch-*.subjects | wc -l)
put goal_node "$GOAL_NODE"
echo "$THEOREM's statement node: $GOAL_NODE; the bounty cites $CITE"

# The dry run, in witness-sim: every batch attested, and the bounty posted.
if [ "$(get dry_run)" != 1 ]; then
	step "dry run in witness-sim: attesting $BATCHES batches"
	export WITNESS_SIM_DIR=$OUT/dry
	rm -rf "$WITNESS_SIM_DIR"
	OP=$OUT/op.hex
	simitem() { printf '%s' "$1" >"$OP"; "$SIM" item "$DSVC" "@$OP" >/dev/null; }
	"$SIM" create-service "$WITNESS_DIR/out/witness-service.jam" 10000000000 >/dev/null
	DSVC=$(( 16#$("$SIM" list | tail -1 | cut -f1) ))
	simitem "$($W propose --service "$DSVC" --nonce 0 --fee-asset test --commit-deposit 10 --attest-deposit 10)"
	for who in "$MAKER" ${ATTESTERS//,/ }; do simitem "$($W mint --to "$who" --amount 1000000)"; done
	# The work dir's claims are the dry run's: keep the batches, start the claims afresh.
	rm -f "$OUT"/w/batch-*.claim "$OUT"/w/estimates
	python3 "$WITNESS_DIR/scripts/attest-batches.py" w --witness "$W" --service "$DSVC" --check "$CHECK" \
		--check-gas "$GAS" --attesters "$ATTESTERS" --sim "$SIM" | tee "$OUT/dry-attest.log"
	python3 -I - "$WITNESS_SIM_DIR/log" "$BATCHES" "$MAX_ATTEST_GAS" "$OUT/dry-gas.json" <<'PY'
import json, re, statistics, sys
log, batches, most, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
lines = open(log).read().splitlines()
gas = [int(m.group(1)) for l in lines if (m := re.search(r"check used (\d+) gas", l))]
refused = [l for l in lines if "Rejected" in l]
r = {"checks": len(gas), "min": min(gas), "median": int(statistics.median(gas)), "max": max(gas),
     "total": sum(gas), "over_1e9": sum(g > 10**9 for g in gas), "rejected": len(refused)}
json.dump(r, open(out, "w"), indent=1)
print(f"dry run: {len(gas)} checks; gas min {r['min']:.3g}, median {r['median']:.3g}, max {r['max']:.3g}, total {r['total']:.3g}; {len(refused)} rejected")
assert not refused, refused[:3]
assert len(gas) >= batches, f"only {len(gas)} checks for {batches} batches"
assert max(gas) <= most, f"a batch used {max(gas)} gas, over {most}"
PY
	step "dry run in witness-sim: posting the bounty"
	printf '%s' "$($W create --service "$DSVC" --maker "$MAKER" --nonce 0 --check "$CHECK" --params "$GOAL_NODE" \
		--blobs "$CITE" --reward "$REWARD" --check-gas "$GAS" --expiry $(( $("$SIM" inspect slot) + EXPIRY_SLOTS )) $BIND)" >"$OP"
	"$SIM" item "$DSVC" "@$OP" >/dev/null
	v=$("$SIM" inspect storage --raw "$DSVC" "$($W key --bounty 0)")
	$W decode --bounty "$v" | tee "$OUT/dry-bounty.txt" | grep -q 'status: Open' || fail "the dry run's bounty isn't open"
	unset WITNESS_SIM_DIR
	rm -f "$OUT"/w/batch-*.claim "$OUT"/w/estimates
	put dry_run 1
fi

if [ -z "$SERVICE_ID" ]; then
	printf '\ndry run passed: %s batches attest, and the bounty posts (statement node %s)\n' "$BATCHES" "$GOAL_NODE"
	exit
fi

# Live.
SVC=$SERVICE_ID OP=$OUT/op.hex X=$OUT/extrinsics POLL=3
put tag "$TAG"
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
nonce_of() { local n; n=$(show account --account "$1" | sed -nE 's/.*nonce: ([0-9]+).*/\1/p'); echo "${n:-0}"; }
balance_of() { local b; b=$(show balance --balance "$1" --asset test); [ "$b" = none ] && echo 0 || echo "$b"; }
# Submit OP (with the extrinsics in X) until the command CHECK... succeeds: up to 4 tries of 12 slots.
deliver() { # NAME CHECK...
	local name=$1; shift
	local extrinsics=($(ls "$X"/* 2>/dev/null)) sent
	for try in 1 2 3 4; do
		sent=$(slot)
		python3 "$WITNESS_DIR/scripts/jam-submit.py" "$SVC" "@$OP" "${extrinsics[@]}" || echo "$name: not submitted (try $try)"
		while [ "$(slot)" -le $((sent + 12)) ]; do
			if "$@"; then echo "ok: $name (try $try, slot $(slot))"; rm -rf "$X"; return; fi
			sleep $POLL
		done
		echo "$name: no effect after try $try (sent at slot $sent)"
	done
	fail "$name never took effect"
}
bytes_list() { python3 -I -c 'import sys; print("[" + ", ".join(str(b) for b in bytes.fromhex(sys.argv[1].removeprefix("0x"))) + "]")' "$1"; }
next_bounty() {
	local v; v=$(storage --next)
	[ -n "$v" ] && python3 -I -c 'import sys; print(int.from_bytes(bytes.fromhex(sys.argv[1][2:]), "little"))' "$v" || echo 0
}
makers() { # ID: is bounty ID the maker's, for the goal?
	local b; b=$(show bounty --bounty "$1")
	grep -qF "maker: $(bytes_list "$($W account --seed "$MAKER")")" <<<"$b" && grep -qF "params: $(bytes_list "$GOAL_NODE")" <<<"$b"
}

step "witness is service $SVC; minting for the maker ($MAKER) and the attesters"
show config --config | tee "$OUT/config.txt" | grep -q 'fee_asset: Some' || fail "service $SVC isn't a configured witness"
for who in ${ATTESTERS//,/ }; do
	[ "$(balance_of "$who")" -gt 0 ] && { echo "($who has $(balance_of "$who"))"; continue; }
	printf '%s' "$($W mint --to "$who" --amount 1000000)" >"$OP"
	deliver "mint $who" eval '[ "$(balance_of '"$who"')" -gt 0 ]'
done
if [ -z "$(get bounty)" ]; then
	while [ "$(balance_of "$MAKER")" -lt "$REWARD" ]; do
		before=$(balance_of "$MAKER")
		printf '%s' "$($W mint --to "$MAKER" --amount 1000000)" >"$OP"
		deliver "mint $MAKER" eval '[ "$(balance_of '"$MAKER"')" -gt '"$before"' ]'
	done
fi

step "attesters ($ATTESTERS) attest the library: $BATCHES batches"
[ -n "$(get attest_slot)" ] || put attest_slot "$(slot)"
python3 "$WITNESS_DIR/scripts/attest-batches.py" w --witness "$W" --service "$SVC" --check "$CHECK" \
	--check-gas "$GAS" --attesters "$ATTESTERS" ${PACKAGE_GAS:+--package-gas "$PACKAGE_GAS"} \
	${PACKAGE_ITEMS:+--package-items "$PACKAGE_ITEMS"} ${SETTLE_SLOTS:+--settle "$SETTLE_SLOTS"} \
	${LAND_SLOTS:+--land-slots "$LAND_SLOTS"} --log "$OUT/attest.jsonl" | tee -a "$OUT/attest.log"
[ -n "$(get attest_end_slot)" ] || put attest_end_slot "$(slot)"

step "the maker ($MAKER) posts the bounty for $THEOREM"
ID=$(get bounty)
if [ -n "$ID" ]; then
	echo "(bounty $ID, posted in an earlier run)"
else
	ID=$(get bounty_sent)
	if [ -n "$ID" ] && makers "$ID"; then
		echo "(bounty $ID, sent by an earlier run)"
	else
		# Its id is the service's next when it lands: read just before, and checked after.
		ID=$(next_bounty) N=$(nonce_of "$MAKER")
		put bounty_sent "$ID"
		EXPIRY=$(( $(slot) + EXPIRY_SLOTS ))
		put expiry "$EXPIRY"
		printf '%s' "$($W create --service "$SVC" --maker "$MAKER" --nonce "$N" --check "$CHECK" --params "$GOAL_NODE" \
			--blobs "$CITE" --reward "$REWARD" --check-gas "$GAS" --expiry "$EXPIRY" $BIND)" >"$OP"
		deliver "create the bounty" eval '[ "$(nonce_of '"$MAKER"')" -gt '"$N"' ]'
		makers "$ID" || fail "bounty $ID isn't the maker's (another bounty raced it?): look it up by the maker's"
	fi
	put bounty "$ID"
	put bounty_slot "$(slot)"
fi
show bounty --bounty "$ID" | tee "$OUT/bounty.txt"
grep -qE 'status: (Open|Revealing|Claimed)' "$OUT/bounty.txt" || fail "bounty $ID isn't posted"

python3 -I - "$OUT" "$ID" "$SVC" "$GOAL_NODE" "$THEOREM" "$MAKER" "$REWARD" "$BATCHES" <<'EOF'
import json, os, sys
out, bounty, svc, goal, theorem, maker, reward, batches = sys.argv[1:]
state = dict(l.split("=", 1) for l in open(f"{out}/state").read().splitlines() if "=" in l)
manifest = json.load(open(f"{out}/nodes/manifest.json"))
size = lambda d: sum(os.path.getsize(f"{out}/nodes/{d}/{f}") for f in os.listdir(f"{out}/nodes/{d}"))
dry = json.load(open(f"{out}/dry-gas.json"))
r = {"service": int(svc), "bounty": int(bounty), "theorem": theorem, "statement_node": goal, "maker_seed": maker,
     "reward": int(reward), "expiry": int(state.get("expiry", 0)), "check_hash": state.get("check_hash"),
     "cite": open(f"{out}/w/goal.cite").read().strip(), "library_nodes": len(manifest) - 1,
     "statement_bytes": size("nodes"), "proof_bytes": size("proofs"), "batches": int(batches), "dry_run_gas": dry,
     "attest_slots": [int(state.get("attest_slot", 0)), int(state.get("attest_end_slot", 0))],
     "bounty_slot": int(state.get("bounty_slot", 0))}
json.dump(r, open(f"{out}/report.json", "w"), indent=1)
lines = [f"# AccLogFail bounty: bounty {bounty} on service {svc}", "",
         f"- statement: `{theorem} : AccLogFailGoal`, node `{goal}`",
         f"- maker `{maker}`, reward {int(reward):,} test, check gas 5e9, expiry slot {r['expiry']:,}" + (", --bind-claim" if os.environ.get("BIND_CLAIM") else ""),
         f"- library: {r['library_nodes']:,} nodes ({r['statement_bytes']:,} B of statements, {r['proof_bytes']:,} B of proofs), {batches} batches",
         f"- dry-run attest gas: median {dry['median']:.3g}, max {dry['max']:.3g}, total {dry['total']:.3g}",
         f"- attested in slots {r['attest_slots'][0]:,}–{r['attest_slots'][1]:,}; posted at slot {r['bounty_slot']:,}"]
open(f"{out}/report.md", "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
EOF
printf '\nAccLogFail bounty posted: bounty %s on service %s\n' "$ID" "$SVC"
