# Steps 3 to 5 of scripts/lean-bounty-demo.sh on a JAM chain: sourced by it when SERVICE_ID is set,
# once the library is exported and planned. The service SERVICE_ID must be witness, configured
# with the test faucet's asset (as on the JAM Toaster, docs/toaster.md); the node at JAM_RPC must
# be synced and able to submit work packages.
#
# - Accounts are seeds of this run's TAG: lean-TAG-alice posts, lean-TAG-bob and lean-TAG-carol
#   hunt, lean-TAG-pat, -quinn, -rene and -sam attest. Each is minted 1,000,000 of the test asset.
# - Every op goes through scripts/jam-submit.py, and is resubmitted until the chain shows its
#   effect: a signed op's nonce, a bounty's status, or for a reveal that must be rejected, a
#   refinement of the service in the chain's statistics, after which the state must be unchanged.
# - scripts/toaster/lean/stats.py follows the chain's statistics for the service (OUT/stats.csv):
#   the refine and accumulate gas of every block's work on it. A non-validating node doesn't
#   refine, so these are the gas figures there are. Each op is logged to OUT/live.jsonl.
# - OUT/state records what's done (bounty ids, steps), so a rerun with REUSE_PLAN=1 resumes.
#   Attestations resume from the chain (attest-batches.py), nonces are read from it.
# PACKAGE_GAS, PACKAGE_ITEMS, SETTLE_SLOTS and LAND_SLOTS go to attest-batches.py.
# Writes OUT/report.md and OUT/report.json.

STATE=$OUT/state STATS=$OUT/stats.csv EVENTS=$OUT/live.jsonl
LEANLIVE=$WITNESS_DIR/scripts/toaster/lean
touch "$STATE" "$EVENTS"
POLL=3
ALICE=lean-$TAG-alice BOB=lean-$TAG-bob CAROL=lean-$TAG-carol
ATTESTERS=${ATTESTERS:-lean-$TAG-pat,lean-$TAG-quinn,lean-$TAG-rene,lean-$TAG-sam}
MINT=1000000
SVC=$SERVICE_ID

get() { sed -n "s/^$1=//p" "$STATE" | tail -1; }
put() { echo "$1=$2" >>"$STATE"; }
done_already() { [ "$(get "done_$1")" = 1 ] && echo "($1: done in an earlier run)"; }
mark() { put "done_$1" 1; }

slot() {
	python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from jamrpc import Rpc, url; print(Rpc(url()).call("bestBlock")["slot"])' \
		"$WITNESS_DIR/scripts"
}
wait_slot() { while [ "$(slot)" -lt "$1" ]; do sleep $POLL; done; }
storage() {
	local v; v=$(python3 "$WITNESS_DIR/scripts/jam-storage.py" "$SVC" "$($W key "$@")" 2>/dev/null || true)
	case $v in 0x*) echo "$v" ;; *) echo "" ;; esac
}
show() {
	local kind=$1; shift
	local v; v=$(storage "$@")
	if [ -n "$v" ]; then $W decode "--$kind" "$v"; else echo none; fi
}
# Wait (up to about 6 minutes) for the state to match.
expect() {
	local what=$1 pattern=$2; shift 2
	local out=
	for _ in $(seq 1 120); do
		out=$(show "$@")
		grep -qE "$pattern" <<<"$out" && { echo "ok: $what"; return; }
		sleep $POLL
	done
	fail "$what: wanted /$pattern/, got: $out"
}
nonce_of() { local n; n=$(show account --account "$1" | sed -nE 's/.*nonce: ([0-9]+).*/\1/p'); echo "${n:-0}"; }
balance_of() { local b; b=$(show balance --balance "$1" --asset test); [ "$b" = none ] && echo 0 || echo "$b"; }
# The service's statistics from slot $1 on, summed (JSON).
stats_since() { python3 "$LEANLIVE/stats.py" since "$STATS" "$1" 2>/dev/null || echo null; }
refined_since() { stats_since "$1" | python3 -I -c 'import json, sys; s = json.load(sys.stdin); sys.exit(0 if s and s["refinements"] else 1)'; }

# Log an op: NAME, the slot it was first sent at, the bytes it sent (payload and extrinsics), the
# tries it took, the seconds until its effect showed; with the service's statistics since.
event() {
	python3 -I -c 'import json, sys
n, sent, landed, size, tries, secs, stats = sys.argv[1:]
s = json.loads(stats)
if s:
    s = {"refinements": s["refinements"], "refine_gas": s["refine_gas"], "accumulations": s["accumulations"],
         "accumulate_gas": s["accumulate_gas"], "busy_slots": [b["slot"] for b in s["blocks"]]}
print(json.dumps({"op": n, "sent_slot": int(sent), "landed_slot": int(landed), "bytes": int(size),
                  "tries": int(tries), "seconds": round(float(secs), 1), "stats": s}))' \
		"$1" "$2" "$(slot)" "$3" "$4" "$5" "$(stats_since "$2")" | tee -a "$EVENTS"
}

# deliver NAME CHECK...: submit OP (with the extrinsics in X) until the command CHECK... succeeds,
# up to 4 times, giving each try 12 slots (72 s).
deliver() {
	local name=$1; shift
	local extrinsics=($(ls "$X"/* 2>/dev/null)) start t0 size sent
	size=$(( $(wc -c <"$OP") / 2 ))
	for x in "${extrinsics[@]}"; do size=$((size + $(stat -c %s "$x"))); done
	start=$(slot) t0=$(now)
	for try in 1 2 3 4; do
		sent=$(slot)
		python3 "$WITNESS_DIR/scripts/jam-submit.py" "$SVC" "@$OP" "${extrinsics[@]}" || echo "$name: not submitted (try $try)"
		while [ "$(slot)" -le $((sent + 12)) ]; do
			if "$@"; then
				event "$name" "$start" "$size" "$try" "$(echo "$(now) - $t0" | bc)"
				rm -rf "$X"
				return
			fi
			sleep $POLL
		done
		echo "$name: no effect after try $try (sent at slot $sent)"
	done
	fail "$name never took effect"
}
nonce_above() { [ "$(nonce_of "$1")" -gt "$2" ]; }
status_is() { show bounty --bounty "$1" | grep -qE "$2"; }
# A signed op by WHO, made with nonce N: done once WHO's nonce passes N.
signed() { # NAME WHO PAYLOAD
	[ -n "$3" ] || fail "no payload"
	printf '%s' "$3" >"$OP"
	deliver "$1" nonce_above "$2" "$N"
}
unsigned() { # NAME PAYLOAD CHECK...
	[ -n "$2" ] || fail "no payload"
	local name=$1; printf '%s' "$2" >"$OP"; shift 2
	deliver "$name" "$@"
}
# A reveal that must be rejected: sent until the chain's statistics show the service refined
# something after it was sent, then the bounty must still be Open.
rejected() { # NAME BOUNTY PAYLOAD
	local since; since=$(slot)
	unsigned "$1" "$3" refined_since "$since"
	# Give a wrongly accepted reveal time to show, too.
	wait_slot $(( $(slot) + 3 ))
	expect "$1 changed nothing" 'status: Open' bounty --bounty "$2"
}

step "following service $SVC's statistics (stats.csv)"
python3 "$LEANLIVE/stats.py" watch "$SVC" "$STATS" "$OUT/stats-raw" 2>>"$OUT/stats.log" &
STATS_PID=$!
trap 'kill $STATS_PID 2>/dev/null || true' EXIT
stats_rows() { [ -f "$STATS" ] && wc -l <"$STATS" || echo 0; }
for _ in $(seq 1 20); do [ "$(stats_rows)" -gt 1 ] && break; sleep $POLL; done
tail -3 "$STATS" 2>/dev/null || true
# Without them a rejected reveal can't be told from a dropped one: stop before sending anything.
[ "$(stats_rows)" -gt 1 ] || fail "no statistics decoded after a minute (see $OUT/stats.log)"

step "witness is service $SVC; minting for this run's accounts (tag $TAG)"
phase setup
expect "witness configured" 'fee_asset: Some' config --config
show config --config | tee "$OUT/config.txt"
put tag "$TAG"
for who in $ALICE $BOB $CAROL ${ATTESTERS//,/ }; do
	[ "$(balance_of "$who")" -gt 0 ] && { echo "($who has $(balance_of "$who"))"; continue; }
	unsigned "mint $who" "$($W mint --to "$who" --amount $MINT)" eval '[ "$(balance_of '"$who"')" -gt 0 ]'
done

step "attesters ($ATTESTERS) attest the library: $BATCHES batches"
phase attest
ATTEST_SLOT=$(get attest_slot); [ -n "$ATTEST_SLOT" ] || { ATTEST_SLOT=$(slot); put attest_slot "$ATTEST_SLOT"; }
ATTEST_T0=$(now)
python3 "$WITNESS_DIR/scripts/attest-batches.py" "$OUT/w" --witness "$W" --service "$SVC" --check "$CHECK" \
	--check-gas "$GAS" --attesters "$ATTESTERS" ${PACKAGE_GAS:+--package-gas "$PACKAGE_GAS"} \
	${PACKAGE_ITEMS:+--package-items "$PACKAGE_ITEMS"} ${SETTLE_SLOTS:+--settle "$SETTLE_SLOTS"} \
	${LAND_SLOTS:+--land-slots "$LAND_SLOTS"} \
	--log "$OUT/attest.jsonl" | tee -a "$OUT/attest.log"
put attest_end_slot "$(slot)"
echo "attest: $(stats_since "$ATTEST_SLOT" | python3 -I -c 'import json, sys; s = json.load(sys.stdin); print({k: s[k] for k in ("refinements", "refine_gas", "accumulations", "accumulate_gas")} if s else "no statistics")')"

declare -A NONCE
for who in $ALICE $BOB $CAROL; do NONCE[$who]=$(nonce_of "$who"); done
take() { N=${NONCE[$1]}; NONCE[$1]=$((N + 1)); }
bytes_list() { python3 -I -c 'import sys; print("[" + ", ".join(str(b) for b in bytes.fromhex(sys.argv[1].removeprefix("0x"))) + "]")' "$1"; }
next_bounty() {
	local v; v=$(storage --next)
	[ -n "$v" ] && python3 -I -c 'import sys; print(int.from_bytes(bytes.fromhex(sys.argv[1][2:]), "little"))' "$v" || echo 0
}

step "alice ($ALICE) posts the bounties"
phase bounty
# Each bounty's id is the service's next id when it lands; with nobody else posting, the one read
# just before sending. Checked after: it must be alice's, for these params.
# Is bounty ID alice's, for PARAMS? (Its maker and params, as `witness decode` prints them: lists of bytes.)
alices() { # ID PARAMS
	local b; b=$(show bounty --bounty "$1")
	grep -qF "maker: $(bytes_list "$($W account --seed "$ALICE")")" <<<"$b" && grep -qF "params: $(bytes_list "$2")" <<<"$b"
}
post() { # KEY PARAMS
	local id; id=$(get "$1")
	if [ -n "$id" ]; then echo "($1 is bounty $id, posted in an earlier run)"; return; fi
	# Sent by an earlier run that stopped before it could record it?
	id=$(get "$1_sent")
	if [ -n "$id" ] && alices "$id" "$2"; then echo "($1 is bounty $id, sent by an earlier run)"; put "$1" "$id"; return; fi
	id=$(next_bounty)
	put "$1_sent" "$id"
	take "$ALICE"
	signed "create $1" "$ALICE" "$($W create --service "$SVC" --maker "$ALICE" --nonce $N --check "$CHECK" --params "$2" \
		--blobs "$CITE" --reward $REWARD --check-gas "$GAS" --expiry $(( $(slot) + 3000 )))"
	show bounty --bounty "$id" | tee "$OUT/$1-created.txt"
	alices "$id" "$2" || fail "bounty $id isn't the one alice posted (another poster raced it?)"
	put "$1" "$id"
}
post goal_bounty "$GOAL_NODE"
post other_bounty "$OTHER_NODE"
B0=$(get goal_bounty) B1=$(get other_bounty)
echo "bounty $B0: prove $THEOREM ($GOAL_NODE); bounty $B1: prove $OTHER ($OTHER_NODE)"
expect "bounty $B0 posted" 'status: (Open|Revealing|Claimed)' bounty --bounty "$B0"
expect "bounty $B1 posted" 'status: (Open|Revealing|Claimed)' bounty --bounty "$B1"

step "hunters commit"
phase commit
commit() { # KEY WHO BOUNTY SALT PACK
	done_already "$1" && return
	take "$2"
	signed "$1" "$2" "$($W commit --service "$SVC" --bounty "$3" --hunter "$2" --nonce $N --salt "$4" --witness-file "$5" 2>/dev/null)"
	mark "$1"
}
commit commit_wrong "$CAROL" "$B0" 0x0c0c "$OUT/wrong.pack"
commit commit_forged "$CAROL" "$B0" 0x0c0d "$OUT/forged.pack"
commit commit_goal "$BOB" "$B0" 0x0b0b "$OUT/w/goal.pack"
commit commit_other "$BOB" "$B1" 0x0b0b "$OUT/w/goal.pack"
wait_slot $(( $(slot) + 2 ))

TRUST=$(cat "$OUT/w/goal.trust")
reveal_op() { # BOUNTY PARAMS HUNTER SALT PACK [TRUST]
	rm -rf "$X"
	$W reveal --bounty "$1" --check "$CHECK" --params "$2" --blobs "$CITE" --trust "${6:-$TRUST}" \
		--check-gas "$GAS" --hunter "$3" --salt "$4" --witness-file "$5" --extrinsics "$X"
}

step "carol reveals a wrong proof ($THEOREM's statement, $WRONG's proof)"
phase reveal-wrong-proof
done_already reveal_wrong || { rejected "reveal wrong proof" "$B0" "$(reveal_op "$B0" "$GOAL_NODE" "$CAROL" 0x0c0c "$OUT/wrong.pack")"; mark reveal_wrong; }

step "carol reveals a forged proof ($WRONG's proof term, relabelled as a proof of $THEOREM)"
phase reveal-forged-proof
done_already reveal_forged || { rejected "reveal forged proof" "$B0" \
	"$(reveal_op "$B0" "$GOAL_NODE" "$CAROL" 0x0c0d "$OUT/forged.pack" "$(cat "$OUT/forged.trust")")"; mark reveal_forged; }

step "bob reveals his proof of $THEOREM to the bounty for $OTHER (a different statement)"
phase reveal-other-statement
done_already reveal_other || { rejected "reveal to the other bounty" "$B1" "$(reveal_op "$B1" "$OTHER_NODE" "$BOB" 0x0b0b "$OUT/w/goal.pack")"; mark reveal_other; }

step "bob reveals his proof of $THEOREM"
phase reveal
if ! status_is "$B0" 'Revealing|Claimed'; then
	unsigned "reveal proof" "$(reveal_op "$B0" "$GOAL_NODE" "$BOB" 0x0b0b "$OUT/w/goal.pack")" status_is "$B0" 'Revealing|Claimed'
fi
show bounty --bounty "$B0" | tee "$OUT/bounty-revealed.txt"

step "the claim window passes; finalize pays bob"
phase finalize
if ! status_is "$B0" Claimed; then
	if ! done_already finalize_early; then
		since=$(slot)
		unsigned "finalize too early" "$($W finalize --bounty "$B0")" refined_since "$since"
		wait_slot $(( $(slot) + 3 ))
		expect "finalizing early changes nothing" 'Revealing' bounty --bounty "$B0"
		mark finalize_early
	fi
	END=$(sed -nE 's/.*window_end: ([0-9]+).*/\1/p' "$OUT/bounty-revealed.txt")
	[ -n "$END" ] || fail "no window_end in bounty $B0"
	echo "waiting for slot $END (now $(slot))"
	wait_slot $(( END + 1 ))
	unsigned "finalize" "$($W finalize --bounty "$B0")" status_is "$B0" Claimed
fi
show bounty --bounty "$B0" | tee "$OUT/bounty-final.txt"
# Bob's deposit for bounty B0 came back at his reveal; B1's stays locked until he releases it.
expect "bob was paid $REWARD" "^$((MINT - 10 + REWARD))\$" balance --balance "$BOB" --asset test
phase
TOTAL_SECS=$(echo "$(now) - $DEMO_START" | bc)
kill $STATS_PID 2>/dev/null || true

step "report"
python3 -I - "$OUT" "$BATCHES" "$THEOREM" "$OTHER" "$WRONG" "$GOAL_NODE" "$SVC" "$TAG" "$B0" "$B1" "$TOTAL_SECS" \
	"$(get attest_slot)" "$(get attest_end_slot)" "$GAS_PER_MS" <<'EOF'
import json, os, statistics, sys
(out, batches, theorem, other, wrong, goal, svc, tag, b0, b1, total, a0, a1, gas_per_ms) = sys.argv[1:]
events = [json.loads(l) for l in open(f"{out}/live.jsonl") if l.strip()]
last = {e["op"]: e for e in events}
rows = []
for line in open(f"{out}/stats.csv").read().splitlines()[1:]:
    slot, _, r, rg, a, ag = line.split(",")
    rows.append((int(slot), int(r), int(rg), int(a), int(ag)))
attest_rows = [x for x in rows if int(a0) <= x[0] <= int(a1)]
attest = {"refinements": sum(x[1] for x in attest_rows), "refine_gas": sum(x[2] for x in attest_rows),
          "accumulations": sum(x[3] for x in attest_rows), "accumulate_gas": sum(x[4] for x in attest_rows),
          "slots": int(a1) - int(a0), "blocks_with_work": sum(1 for x in attest_rows if x[1] or x[3])}
per_block = [x[2] for x in attest_rows if x[1]]
attest["refine_gas_per_block"] = ({"min": min(per_block), "median": int(statistics.median(per_block)),
                                   "max": max(per_block)} if per_block else None)
rounds = [json.loads(l) for l in open(f"{out}/attest.jsonl")] if os.path.exists(f"{out}/attest.jsonl") else []
packages = [p for r in rounds for p in r.get("packages", [])]
phases = [l.split("\t") for l in open(f"{out}/times.tsv").read().splitlines()]
times = {p[0]: float(p[1]) for p in phases}
r = {
    "chain": "live", "service": int(svc), "tag": tag, "theorem": theorem, "statement_node": goal,
    "other_statement": other, "goal_bounty": int(b0), "other_bounty": int(b1), "batches": int(batches),
    "attest": attest, "attest_rounds": len(rounds), "attest_packages": len(packages),
    "package_bytes": ({"min": min(p["bytes"] for p in packages), "max": max(p["bytes"] for p in packages)} if packages else None),
    "package_items": ({"min": min(p["items"] for p in packages), "max": max(p["items"] for p in packages)} if packages else None),
    "ops": events, "check_blob_bytes": os.path.getsize(f"{out}/lean-check.jam"),
    "goal_pack_bytes": os.path.getsize(f"{out}/w/goal.pack"), "gas_per_native_ms": int(gas_per_ms),
    "seconds": {**times, "total": float(total)},
}
json.dump(r, open(f"{out}/report.json", "w"), indent=1)
def op(name):
    e = last.get(name)
    if not e:
        return "not run"
    s = e["stats"] or {}
    return (f"slot {e['sent_slot']} → {e['landed_slot']}, {e['seconds']:.0f} s, {e['tries']} tr{'ies' if e['tries'] > 1 else 'y'}, "
            f"{e['bytes']:,} B; refine gas {s.get('refine_gas', 0):.3g}, accumulate gas {s.get('accumulate_gas', 0):.3g}")
lines = [
    f"# {theorem}: a Lean bounty on a live chain (service {svc}, tag {tag})", "",
    f"- bounty {b0}: prove {theorem} ({goal}); bounty {b1}: prove {other}",
    f"- {batches} attest batches in {len(rounds)} rounds, {len(packages)} packages"
    + (f" of {r['package_items']['min']}–{r['package_items']['max']} items, {r['package_bytes']['min']:,}–{r['package_bytes']['max']:,} B" if packages else ""),
    f"- attest, slots {a0}–{a1} ({attest['slots']} slots): {attest['refinements']} refinements, refine gas {attest['refine_gas']:.3g}, "
    f"{attest['accumulations']} accumulations, accumulate gas {attest['accumulate_gas']:.3g}",
]
for name in ("create goal_bounty", "create other_bounty", "commit_goal", "reveal wrong proof", "reveal forged proof",
             "reveal to the other bounty", "reveal proof", "finalize too early", "finalize"):
    lines.append(f"- {name}: {op(name)}")
lines += ["", "| phase | seconds |", "|---|---|"] + [f"| {k} | {v:.0f} |" for k, v in r["seconds"].items()]
open(f"{out}/report.md", "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
EOF
printf '\nLean bounty demo passed on service %s: %s (bounty %s; work in %s)\n' "$SVC" "$THEOREM" "$B0" "$OUT"
