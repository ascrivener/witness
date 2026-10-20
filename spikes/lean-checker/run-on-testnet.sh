#!/usr/bin/env bash
# usage: run-on-testnet.sh SERVICE_ID LOG NAME...
#
# For each proofs/NAME.ndjson: solicit it as a preimage of the lean-spike service, provide it,
# then ask refine to parse and check it, and print node0's report from the testnet log LOG.
# Needs jamt on PATH and the witness CLI built (for `witness hash`).
set -euo pipefail
cd "$(dirname "$0")"
H=../../target/debug/witness
SVC=$1 L=$2; shift 2
slot() { jamt inspect slot; }
wait_slots() { local t=$(( $(slot) + $1 )); while [ "$(slot)" -lt "$t" ]; do sleep 2; done; }
for n in "$@"; do
	f=proofs/$n.ndjson
	h=$($H hash --check "$f"); h=${h#0x}
	len=$(wc -c < "$f" | tr -d ' ')
	lenhex=$(printf '%08x' "$len" | sed -E 's/(..)(..)(..)(..)/\4\3\2\1/')
	jamt item "$SVC" "0x00$h$lenhex" >/dev/null; wait_slots 3
	jamt provide "$SVC" "$f" >/dev/null; wait_slots 3
	n0=$(( $(wc -l < "$L" | tr -d ' ') + 1 ))
	jamt item "$SVC" "0x01$h" >/dev/null
	for _ in $(seq 1 30); do tail -n +$n0 "$L" | grep node0 | grep -q "lean.*\(accumulate\|refine failed\)" && break; sleep 3; done
	printf '%-16s ' "$n"; tail -n +$n0 "$L" | grep node0 | grep -E "lean.*(accumulate|refine failed)" | head -1 | sed 's/.*INFO lean  //'
done
