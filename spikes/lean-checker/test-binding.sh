#!/usr/bin/env bash
# Build the statement environments and submissions, make deltas, and check that every honest
# proof is accepted and every attack rejected. Needs elan, a built lean4export (LEAN4EXPORT=path),
# and ./setup.sh to have been run.
set -euo pipefail
cd "$(dirname "$0")"
: "${LEAN4EXPORT:?set LEAN4EXPORT to the lean4export binary}"
B=host-check/target/release/host-check
(cd host-check && cargo build -q --release)
cd proofs
lake build >/dev/null && lake build Proofs.Redefine >/dev/null
mkdir -p exports
# `lake env` must run from the project root.
for g in GoalTwo GoalAddComm GoalGcd GoalF; do lake env "$LEAN4EXPORT" Proofs.Statements -- $g > exports/env-$g.ndjson; done
for t in goal_two goal_add_comm goal_gcd goal_f goal_wrong goal_def goal_axiom goal_sorry; do
	lake env "$LEAN4EXPORT" Proofs.Solutions -- $t > exports/full-$t.ndjson
done
lake env "$LEAN4EXPORT" Proofs.Redefine -- goal_f > exports/full-redefine.ndjson
cd exports
delta() { python3 ../../delta/lean_delta.py "env-$1.ndjson" "full-$2.ndjson" > "delta-$2.ndjson"; }
delta GoalTwo goal_two; delta GoalAddComm goal_add_comm; delta GoalGcd goal_gcd; delta GoalF goal_f
delta GoalTwo goal_wrong; delta GoalTwo goal_def; delta GoalGcd goal_axiom; delta GoalGcd goal_sorry
delta GoalF redefine
for f in env-*.ndjson delta-*.ndjson; do python3 ../../delta/lean_bin.py "$f" > "${f%.ndjson}.bin"; done

failures=0
case_() { # EXPECTED LABEL ENV DELTA STATEMENT THEOREM; uses $EXT (ndjson or bin)
	local expected=$1 label=$2; shift 2
	local out; out=$(../../$B bind "env-$1.$EXT" "delta-$2.$EXT" "$3" "$4" || true)
	printf '%-8s %-6s %-30s %s\n' "$([[ $out == $expected* ]] && echo ok || echo FAIL)" "$EXT" "$label" "${out:0:140}"
	[[ $out == $expected* ]] || failures=$((failures + 1))
}
for EXT in ndjson bin; do
case_ ACCEPTED "2 + 2 = 4" GoalTwo goal_two GoalTwo goal_two
case_ ACCEPTED "a + b = b + a" GoalAddComm goal_add_comm GoalAddComm goal_add_comm
case_ ACCEPTED "gcd a b = gcd b a" GoalGcd goal_gcd GoalGcd goal_gcd
case_ ACCEPTED "poster's own vocabulary" GoalF goal_f GoalF goal_f
case_ REJECTED "proves True instead" GoalTwo goal_wrong GoalTwo goal_wrong
case_ REJECTED "proof is a def" GoalTwo goal_def GoalTwo goal_def
case_ REJECTED "extra axiom" GoalGcd goal_axiom GoalGcd goal_axiom
case_ REJECTED "sorry" GoalGcd goal_sorry GoalGcd goal_sorry
case_ REJECTED "redefines myF" GoalF redefine GoalF goal_f
case_ REJECTED "theorem missing" GoalTwo goal_two GoalTwo nonexistent
case_ REJECTED "statement not a Prop" GoalF goal_f myF goal_f
case_ REJECTED "delta for another bounty" GoalAddComm goal_two GoalAddComm goal_two
done
echo
[ $failures -eq 0 ] && echo "all binding cases behave as expected" || { echo "$failures case(s) failed"; exit 1; }
