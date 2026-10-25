#!/usr/bin/env bash
# A settled bug bounty, start to finish, in witness-sim:
#
#   scripts/evm-bounty-demo.sh
#
# A protocol posts a bounty on its toy trading pair (tools/evm-report/contracts/Toys.sol): a
# report that breaks the pair's invariant (its reserves' product never falls) on block N's state
# earns 5000. The bounty's check is checks/evm-bounty; its params commit to block N's state root
# and the invariant. Three hunters' reports, written by `evm-report demo`, come in:
#
#   mallory  a fair swap: the invariant still holds, so the check says no
#   carol    the exploit on forged state (the pair's reserves claimed tiny): a proof fails
#   bob      the exploit: 1 wei in, 99.8% of a reserve out. The check accepts; bob is paid
#
# Each hunter commits first and reveals later. A real hunter would, in between, disclose the bug
# privately and wait for the patch: the check replays block N's state, so the report still wins
# after the protocol has fixed its contracts.
#
# Reports are tens of KB of Merkle proofs, so they travel as extrinsics. witness-sim runs the
# check in PolkaVM (whose recompiler needs userfaultfd: in a container, run
# `sysctl -w vm.unprivileged_userfaultfd=1` first).
set -euo pipefail
cd "$(dirname "$0")/.."

W=./target/debug/witness
SIM=$PWD/target/debug/witness-sim
TMP=$(mktemp -d)
export WITNESS_SIM_DIR=$TMP/sim
LOG=$WITNESS_SIM_DIR/log
X=$TMP/extrinsics
DEMO=$TMP/demo
CHECK=out/evm-bounty-check.jam
GAS=1000000000
REWARD=5000

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
slot() { "$SIM" inspect slot; }
# witness-sim passes a slot with every item and every `inspect slot`.
wait_slot() { while [ "$(slot)" -lt "$1" ]; do :; done; }

storage() {
	local v; v=$("$SIM" inspect storage --raw "$SVC" "$($W key "$@")" 2>/dev/null || true)
	case $v in 0x*) echo "$v" ;; *) echo "" ;; esac
}
# `witness decode` of a bounty, or WHO's test-asset balance.
bounty() { local v; v=$(storage --bounty 0); [ -n "$v" ] && $W decode --bounty "$v" || echo none; }
balance() { local v; v=$(storage --balance "$1" --asset test); [ -n "$v" ] && $W decode --balance "$v" || echo 0; }
expect() { # WHAT PATTERN VALUE
	grep -qE "$2" <<<"$3" || fail "$1: wanted /$2/, got: $3"
	echo "ok: $1"
}

item() { "$SIM" item "$SVC" "$@" >/dev/null; }
itemx() { item "$1" "$X"/*; }
# The gas the last check took, from witness-sim's log.
check_gas() { grep -o 'check used [0-9]* gas' "$LOG" | tail -1 | awk '{print $3}'; }

step "building"
cargo build -q -p witness-cli -p witness-sim -p evm-report
cargo jam-build --out-dir out -p witness-service -p evm-bounty-check >/dev/null
./target/debug/evm-report demo "$DEMO"
PARAMS=$(cat "$DEMO/bounty.params")
echo "check blob: $(wc -c <"$CHECK") bytes; params: $(( (${#PARAMS} - 2) / 2 )) bytes"
for r in fair forged exploit; do echo "$r report: $(wc -c <"$DEMO/$r.report") bytes"; done

step "deploying witness"
"$SIM" create-service out/witness-service.jam 10000000000 >/dev/null
SVC=$((16#$("$SIM" list | tail -1 | cut -f1)))
item "$($W propose --service "$SVC" --nonce 0 --fee-asset test --commit-deposit 10 --attest-deposit 10)"
item "$($W mint --to protocol --amount 10000)"
for who in bob carol mallory; do item "$($W mint --to $who --amount 100)"; done
expect "the protocol has 10000" '^10000$' "$(balance protocol)"

step "the protocol posts the bounty"
item "$($W create --service "$SVC" --maker protocol --nonce 0 --check $CHECK --params "$PARAMS" \
	--reward $REWARD --check-gas $GAS --expiry $(( $(slot) + 100 )))"
expect "bounty 0 open" 'status: Open' "$(bounty)"
expect "the reward is escrowed" "^$((10000 - REWARD))\$" "$(balance protocol)"

step "hunters commit"
commit() { # HUNTER NONCE SALT REPORT
	item "$($W commit --service "$SVC" --bounty 0 --hunter "$1" --nonce "$2" --salt "$3" \
		--witness-file "$DEMO/$4.report" 2>/dev/null)"
}
commit mallory 0 0x01 fair
commit carol 0 0x02 forged
commit bob 0 0x03 exploit
for who in bob carol mallory; do expect "$who committed, deposit taken" '^90$' "$(balance $who)"; done
wait_slot $(( $(slot) + 2 )) # MIN_COMMIT_AGE

step "hunters reveal"
reveal() { # HUNTER SALT REPORT
	itemx "$($W reveal --bounty 0 --check $CHECK --params "$PARAMS" --check-gas $GAS --hunter "$1" \
		--salt "$2" --witness-file "$DEMO/$3.report" --extrinsics "$X")"
}
reveal mallory 0x01 fair
expect "the check says no to a fair swap" '^1$' "$(grep -c 'refine: Rejected(CheckFailed(False))' "$LOG")"
expect "a fair swap breaks nothing (check: $(check_gas) gas)" 'status: Open' "$(bounty)"
reveal carol 0x02 forged
expect "forged state fails its proof" '^2$' "$(grep -c 'refine: Rejected(CheckFailed(False))' "$LOG")"
expect "and changes nothing" 'status: Open' "$(bounty)"
reveal bob 0x03 exploit
expect "the exploit breaks the invariant (check: $(check_gas) gas) and opens the claim window" 'Revealing' "$(bounty)"
expect "bob's deposit refunded" '^100$' "$(balance bob)"

step "waiting out the claim window, then finalizing"
wait_slot "$($W decode --bounty "$(storage --bounty 0)" | sed -nE 's/.*window_end: ([0-9]+).*/\1/p')"
item "$($W finalize --bounty 0)"
expect "bounty 0 claimed" 'Claimed' "$(bounty)"
expect "bob is paid the reward" "^$((100 + REWARD))\$" "$(balance bob)"
for who in carol mallory; do expect "$who lost the commit deposit" '^90$' "$(balance $who)"; done

printf '\nthe settled bug bounty demo passed\n'
