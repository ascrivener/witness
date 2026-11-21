#!/usr/bin/env bash
# Attest jam-lean's proof-side library for AccLogFail on top of the attested acclogfail library
# (docs/toaster-proof-library.md): what jam-lean's proofs of the first log line's region
# (6501 … 6630) use that the statement's library doesn't hold.
#
#   WITNESS_LEAN_DIR=... JAM_LEAN_DIR=... LEAN4EXPORT=... REL=release-dir \
#     scripts/toaster/library/build.sh OUT
#
# JAM_LEAN_DIR is jam-lean at the release's commit (c22c197), built. REL holds the release's
# acclogfail.json and acclogfail/lib-N.claim (unpacked). Then:
#
# 1. Export: every declaration of the modules in acclogfail-proofs.modules (the proved success
#    branch `acc_log_lineK`, `acc_log_line`, the abort and trap lemmas), with AccLogFailGoal, and
#    convert. The library is what their proofs reach outside acclogfail (plan.py set).
# 2. Plan by dependency depth, trace (each batch trusts only what the kernel looks up; TRACE_GAS a
#    batch, default 2.9e9), and split each declaration too heavy alone into judgment ops
#    (heavy.py, witness-lean's machinery, every op measured in PolkaVM: at most MAX_ATTEST_GAS).
#    Lay it out for attest-batches.py (layout.py), trusting acclogfail through its claims.
# 3. Dry run, always: in witness-sim, acclogfail's batches rebuilt from this export and attested
#    (their claims must be the release's, byte for byte), then every batch of the new library; the
#    run stops unless each is accepted using at most MAX_ATTEST_GAS (default 3.5e9, 70% of 5e9).
# 4. Live, with SERVICE_ID and TAG: mint the attesters (proofs-TAG-a … -d, ATTESTERS) the test
#    asset, attest every batch (attest-batches.py, resuming from the chain). It never runs during
#    a quiet window (QUIET, default the service upgrade's, 2026-11-27 11:45–12:45 UTC): it stops
#    attesting QUIET_MARGIN (10 minutes) before one, waits it out, and resumes.
#
# OUT/state records what's done, so a rerun resumes. PACKAGE_GAS, PACKAGE_ITEMS, SETTLE_SLOTS and
# LAND_SLOTS go to attest-batches.py. Writes OUT/report.json and OUT/report.md.
set -euo pipefail
: "${WITNESS_LEAN_DIR:?set WITNESS_LEAN_DIR to a witness-lean checkout}"
: "${JAM_LEAN_DIR:?set JAM_LEAN_DIR to a jam-lean checkout, built}"
: "${LEAN4EXPORT:?set LEAN4EXPORT to the lean4export binary}"
: "${REL:?set REL to the release directory (acclogfail.json, acclogfail/lib-N.claim)}"
BASE=acclogfail
NAME=acclogfail-proofs
GOAL_TYPE=Services.Bootstrap.Acc.Final.AccLogFailGoal
GAS=5000000000
MAX_ATTEST_GAS=${MAX_ATTEST_GAS:-3500000000}
TRACE_GAS=${TRACE_GAS:-2900000000}
QUIET=${QUIET:-2026-11-27T11:45:00Z/2026-11-27T12:45:00Z}
QUIET_MARGIN=${QUIET_MARGIN:-600}

cd "$(dirname "$0")/../../.."
WITNESS_DIR=$PWD
HERE=$WITNESS_DIR/scripts/toaster/library
WITNESS_LEAN_DIR=$(cd "$WITNESS_LEAN_DIR" && pwd)
JAM_LEAN_DIR=$(cd "$JAM_LEAN_DIR" && pwd)
REL=$(cd "$REL" && pwd)
OUT=$(mkdir -p "${1:?usage: build.sh OUT}" && cd "$1" && pwd)
SERVICE_ID=${SERVICE_ID:-}
if [ -n "$SERVICE_ID" ]; then
	: "${TAG:?live mode (SERVICE_ID) needs TAG, to name the attesters}"
	export JAM_RPC=${JAM_RPC:-ws://localhost:19800}
fi
TAG=${TAG:-sim}
ATTESTERS=${ATTESTERS:-$(printf "proofs-$TAG-%s," a b c d | sed 's/,$//')}
W=$WITNESS_DIR/target/release/witness
SIM=$WITNESS_DIR/target/release/witness-sim
HOST=$WITNESS_LEAN_DIR/target/release/lean-host
CHECK=$REL/lean-check.jam
STATE=$OUT/state
touch "$STATE"
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
get() { sed -n "s/^$1=//p" "$STATE" | tail -1; }
put() { echo "$1=$2" >>"$STATE"; }

step "building witness (CLI, simulator, service) and lean-host"
(cargo build -q --release -p witness-sim -p witness-cli && cargo jam-build --out-dir out -p witness-service >/dev/null)
(cd "$WITNESS_LEAN_DIR" && cargo build -q --release -p lean-host)
[ "$($W hash --check "$CHECK")" = "$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["check_hash"])' "$REL/$BASE.json")" ] \
	|| fail "the release's check isn't $BASE's"
[ "$(git -C "$JAM_LEAN_DIR" rev-parse HEAD)" = "$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["jam_lean"])' "$REL/$BASE.json")" ] \
	|| fail "JAM_LEAN_DIR isn't at $BASE's jam-lean commit"
python3 "$WITNESS_DIR/scripts/toaster/hunt/hunt.py" probe "$OUT/probe.args"
if [ -z "${POLKAVM_BACKEND:-}" ] && grep -q BadCheckBlob <<<"$("$SIM" check "$CHECK" "$OUT/probe.args" 100000000 2>&1 || true)"; then
	export POLKAVM_BACKEND=interpreter
	echo "PolkaVM's recompiler is unavailable here: its interpreter (same gas)"
fi

cd "$OUT"
if [ "$(get planned)" != 1 ]; then
	step "exporting the roots: every declaration of $(paste -sd' ' "$HERE/$NAME.modules")"
	rm -rf roots nodes pack heavy w plan*.json traced.json set.json
	mkdir -p roots
	{ sed 's/^/import /' "$HERE/$NAME.modules"; echo "import Services.Bootstrap.Acc.Final.Bounty"; } >roots/Roots.lean
	{ echo "import Lean"; echo "import Roots"; echo "open Lean"
	  echo "#eval show CoreM Unit from do"
	  echo "  let env ← getEnv"
	  echo "  for m in #[$(sed 's/^/`/' "$HERE/$NAME.modules" | paste -sd,)] do"
	  echo "    let some idx := env.getModuleIdx? m | throwError \"no module {m}\""
	  echo "    for n in env.header.moduleData[idx.toNat]!.constNames do"
	  echo "      if !n.isInternal then IO.println s!\"ROOT {n}\""; } >roots/List.lean
	LP=$(cd "$JAM_LEAN_DIR" && lake env printenv LEAN_PATH)
	(cd "$JAM_LEAN_DIR" && lake env lean --root="$OUT/roots" -o "$OUT/roots/Roots.olean" "$OUT/roots/Roots.lean")
	(cd "$JAM_LEAN_DIR" && LEAN_PATH="$LP:$OUT/roots" lake env lean "$OUT/roots/List.lean") | sed -n 's/^ROOT //p' >roots/roots.txt
	echo "$(wc -l <roots/roots.txt) declarations"
	# AccLogFailGoal too, so that the export holds acclogfail (rebuilt in the dry run).
	(cd "$JAM_LEAN_DIR" && LEAN_PATH="$LP:$OUT/roots" "$LEAN4EXPORT" Roots -- $(cat "$OUT/roots/roots.txt") "$GOAL_TYPE") >export.ndjson
	"$HOST" convert export.ndjson nodes >/dev/null
	"$HOST" convert export.ndjson pack --pack >/dev/null
	rm -f export.ndjson

	step "planning: the library, its batches, the trace, the heavy declarations"
	python3 "$HERE/plan.py" set nodes "$REL" "$BASE" roots/roots.txt set.json
	python3 "$HERE/plan.py" batches nodes set.json plan.json
	GAS_PER_MS=${GAS_PER_MS:-$(python3 "$WITNESS_LEAN_DIR/tools/lean/gas_per_ms.py" "$HOST" "$SIM" "$CHECK" nodes plan.json)}
	put gas_per_ms "$GAS_PER_MS"
	TRACE_MS=$(( TRACE_GAS / GAS_PER_MS ))
	echo "$(( GAS_PER_MS / 1000000 ))M gas per native ms: batches up to $TRACE_MS ms"
	put trace_ms "$TRACE_MS"
	"$HOST" trace nodes plan.json traced.json "$TRACE_MS" | tee trace.log | tail -1
	MAX_OP_GAS=$MAX_ATTEST_GAS python3 "$HERE/heavy.py" "$WITNESS_LEAN_DIR" nodes pack traced.json "$TRACE_MS" "$SIM" "$CHECK" heavy "${HEAVY_JOBS:-4}"
	python3 "$HERE/layout.py" nodes traced.json heavy "$REL/$BASE" "$WITNESS_LEAN_DIR/check/pins.txt" "$GAS_PER_MS" w | tee layout.count
	put planned 1
fi
BATCHES=$(cat layout.count)
echo "$BATCHES batches in $OUT/w"

if [ "$(get dry_run)" != 1 ]; then
	step "dry run in witness-sim: $BASE rebuilt and attested, then $BATCHES batches"
	export WITNESS_SIM_DIR=$OUT/dry
	rm -rf "$WITNESS_SIM_DIR" "$OUT/base-work"
	"$SIM" create-service "$WITNESS_DIR/out/witness-service.jam" 10000000000 >/dev/null
	DSVC=$(( 16#$("$SIM" list | tail -1 | cut -f1) ))
	simitem() { printf '%s' "$1" >"$OUT/op.hex"; "$SIM" item "$DSVC" "@$OUT/op.hex" >/dev/null; }
	simitem "$($W propose --service "$DSVC" --nonce 0 --fee-asset test --commit-deposit 10 --attest-deposit 10)"
	for who in ${ATTESTERS//,/ }; do simitem "$($W mint --to "$who" --amount 1000000)"; done
	python3 "$WITNESS_DIR/scripts/toaster/hunt/hunt.py" replay "$REL" "$BASE" nodes "$OUT/base-work"
	(cd "$OUT/base-work" && python3 "$WITNESS_DIR/scripts/attest-batches.py" . --witness "$W" --service "$DSVC" --check "$CHECK" \
		--check-gas "$GAS" --attesters "$ATTESTERS" --sim "$SIM") | tail -2
	n=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["batch_count"])' "$REL/$BASE.json")
	for ((i = 0; i < n; i++)); do
		cmp -s "$OUT/base-work/batch-$i.claim" "$REL/$BASE/lib-$i.claim" || fail "$BASE's batch $i rebuilt isn't the release's claim"
	done
	echo "$BASE: all $n claims rebuilt byte for byte"
	from=$(wc -l <"$WITNESS_SIM_DIR/log")
	rm -f w/batch-*.claim w/estimates
	(cd w && python3 "$WITNESS_DIR/scripts/attest-batches.py" . --witness "$W" --service "$DSVC" --check "$CHECK" \
		--check-gas "$GAS" --attesters "$ATTESTERS" --sim "$SIM") | tee dry-attest.log | tail -3
	tail -n +"$((from + 1))" "$WITNESS_SIM_DIR/log" >dry.log
	python3 -I - dry.log "$BATCHES" "$MAX_ATTEST_GAS" dry-gas.json <<'PY'
import json, re, statistics, sys
log, batches, most, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
lines = open(log).read().splitlines()
gas = [int(m.group(1)) for l in lines if (m := re.search(r"check used (\d+) gas", l))]
refused = [l for l in lines if "Rejected" in l]
r = {"checks": len(gas), "min": min(gas), "median": int(statistics.median(gas)), "max": max(gas), "total": sum(gas),
     "over_1e9": sum(g > 10**9 for g in gas), "over_limit": sum(g > most for g in gas), "rejected": len(refused)}
json.dump(r, open(out, "w"), indent=1)
print(f"dry run: {len(gas)} checks; gas min {r['min']:.3g}, median {r['median']:.3g}, max {r['max']:.3g}, total {r['total']:.3g}; "
      f"{r['over_limit']} over {most:.3g}; {len(refused)} rejected")
assert not refused, refused[:3]
assert len(gas) >= batches, f"only {len(gas)} checks for {batches} batches"
assert max(gas) <= most, f"a batch used {max(gas)} gas, over {most}"
PY
	unset WITNESS_SIM_DIR
	rm -f w/batch-*.claim w/estimates
	put dry_run 1
fi

if [ -z "$SERVICE_ID" ]; then
	printf '\ndry run passed: %s batches attest (%s)\n' "$BATCHES" "$(cat dry-gas.json | tr -d '\n ')"
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
balance_of() { local v; v=$(storage --balance "$1" --asset test); if [ -n "$v" ]; then $W decode --balance "$v"; else echo 0; fi; }
deliver() { # NAME CHECK...
	local name=$1; shift
	for try in 1 2 3 4; do
		local sent; sent=$(slot)
		python3 "$WITNESS_DIR/scripts/jam-submit.py" "$SVC" "@$OP" || echo "$name: not submitted (try $try)"
		while [ "$(slot)" -le $((sent + 12)) ]; do
			if "$@"; then echo "ok: $name (try $try)"; return; fi
			sleep $POLL
		done
	done
	fail "$name never took effect"
}
# Seconds until the quiet window starts (negative while in it), and until it ends.
quiet() { python3 -I -c 'import datetime as d, sys
a, b = (d.datetime.fromisoformat(x.replace("Z", "+00:00")) for x in sys.argv[1].split("/"))
now = d.datetime.now(d.timezone.utc)
print(int((a - now).total_seconds()), int((b - now).total_seconds()))' "$QUIET"; }

step "service $SVC: minting for the attesters ($ATTESTERS)"
$W decode --config "$(storage --config)" | grep -q 'fee_asset: Some' || fail "service $SVC isn't a configured witness"
for who in ${ATTESTERS//,/ }; do
	[ "$(balance_of "$who")" -ge 10000 ] && continue
	printf '%s' "$($W mint --to "$who" --amount 1000000)" >"$OP"
	deliver "mint $who" eval '[ "$(balance_of '"$who"')" -ge 10000 ]'
done

step "attesting $BATCHES batches"
[ -n "$(get attest_slot)" ] || put attest_slot "$(slot)"
# Every block's activity by service (scripts/toaster/lean/stats.py), into the logs: whether others
# are squeezed out while we attest (raise SETTLE_SLOTS or lower the attesters if so).
STATS=${LOGS:-$OUT}/stats-all.csv
run_start=$(slot)
python3 "$WITNESS_DIR/scripts/toaster/lean/stats.py" watch all "$STATS" >/dev/null 2>>"${LOGS:-$OUT}/stats.log" &
stats_pid=$!
# Not left holding the step's pipe to tee: killed on exit, and on the run's timeout (TERM).
trap 'kill "$stats_pid" 2>/dev/null || true' EXIT
trap 'kill "$stats_pid" 2>/dev/null; exit 124' TERM
share() { python3 "$WITNESS_DIR/scripts/toaster/lean/stats.py" share "$STATS" "$run_start" 2>/dev/null | tee -a "${LOGS:-$OUT}/stats-share.jsonl" || true; }
while :; do
	read -r to_start to_end <<<"$(quiet)"
	if [ "$to_start" -le "$QUIET_MARGIN" ] && [ "$to_end" -gt 0 ]; then
		echo "quiet window $QUIET: waiting $to_end s"
		sleep "$to_end"
		continue
	fi
	limit=$(( to_start > 0 ? to_start - QUIET_MARGIN : 86400 * 365 ))
	set +e
	(cd w && timeout "$limit" python3 "$WITNESS_DIR/scripts/attest-batches.py" . --witness "$W" --service "$SVC" --check "$CHECK" \
		--check-gas "$GAS" --attesters "$ATTESTERS" ${PACKAGE_GAS:+--package-gas "$PACKAGE_GAS"} \
		${PACKAGE_ITEMS:+--package-items "$PACKAGE_ITEMS"} ${SETTLE_SLOTS:+--settle "$SETTLE_SLOTS"} \
		${LAND_SLOTS:+--land-slots "$LAND_SLOTS"} --log "$OUT/attest.jsonl") 2>&1 | tee -a attest.log
	status=${PIPESTATUS[0]}
	set -e
	share
	[ "$status" = 0 ] && break
	[ "$status" = 124 ] || fail "attest-batches.py failed ($status)"
	echo "stopped before the quiet window; resuming after it"
done
[ -n "$(get attest_end_slot)" ] || put attest_end_slot "$(slot)"

python3 -I - "$OUT" "$BATCHES" "$SVC" "$NAME" <<'EOF'
import json, sys
out, batches, svc, name = sys.argv[1:]
state = dict(l.split("=", 1) for l in open(f"{out}/state").read().splitlines() if "=" in l)
s = json.load(open(f"{out}/set.json"))
layout = json.load(open(f"{out}/w/layout.json"))
r = {"service": int(svc), "library": name, "nodes": len(s["nodes"]), "roots": len(s["roots"]), "batches": int(batches),
     "heavy_declarations": sum(e["kind"] == "final" for e in layout), "judgment_ops": sum(e["kind"] == "op" for e in layout),
     "dry_run_gas": json.load(open(f"{out}/dry-gas.json")),
     "attest_slots": [int(state.get("attest_slot", 0)), int(state.get("attest_end_slot", 0))]}
json.dump(r, open(f"{out}/report.json", "w"), indent=1)
md = [f"# {name}: attested on service {svc}", "", f"- {r['nodes']:,} nodes from {r['roots']} roots, {r['batches']:,} batches "
      f"({r['heavy_declarations']} heavy declarations as {r['judgment_ops']} judgment ops)",
      f"- dry-run gas: median {r['dry_run_gas']['median']:.3g}, max {r['dry_run_gas']['max']:.3g}, total {r['dry_run_gas']['total']:.3g}",
      f"- attested in slots {r['attest_slots'][0]:,}–{r['attest_slots'][1]:,}"]
open(f"{out}/report.md", "w").write("\n".join(md) + "\n")
print("\n".join(md))
EOF
