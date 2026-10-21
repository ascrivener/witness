#!/usr/bin/env bash
# Drive the lean-spike service on a testnet and print node0's report for each run.
#
#   run-on-testnet.sh SERVICE_ID LOG check FILE
#   run-on-testnet.sh SERVICE_ID LOG bind ENV DELTA STATEMENT THEOREM
#   run-on-testnet.sh SERVICE_ID LOG bind-prechecked ENV DELTA STATEMENT THEOREM   (skips checking ENV)
#
# Files (exports, NDJSON or binary) are solicited as preimages and provided first. LOG is the
# testnet's log. Needs jamt on PATH and the witness CLI built (for `witness hash`).
set -euo pipefail
cd "$(dirname "$0")"
H=../../target/debug/witness
SVC=$1 L=$2 MODE=$3; shift 3

slot() { jamt inspect slot; }
wait_slots() { local t=$(( $(slot) + $1 )); while [ "$(slot)" -lt "$t" ]; do sleep 2; done; }
hash_of() { local h; h=$($H hash --check "$1"); echo "${h#0x}"; }
le32() { printf '%08x' "$1" | sed -E 's/(..)(..)(..)(..)/\4\3\2\1/'; }
# jam-codec string: the length as a JAM natural (one byte below 128), then the bytes.
str() { [ ${#1} -lt 128 ] || exit 1; printf '%02x' ${#1}; printf '%s' "$1" | xxd -p | tr -d '\n'; }

provide() {
	local f=$1 h; h=$(hash_of "$f")
	jamt item "$SVC" "0x00$h$(le32 "$(wc -c < "$f" | tr -d ' ')")" >/dev/null; wait_slots 3
	jamt provide "$SVC" "$f" >/dev/null; wait_slots 3
}

report() { # PAYLOAD LABEL
	local n0=$(( $(wc -l < "$L" | tr -d ' ') + 1 ))
	jamt item "$SVC" "$1" >/dev/null
	for _ in $(seq 1 40); do tail -n +$n0 "$L" | grep node0 | grep -q "lean.*\(accumulate\|refine failed\)" && break; sleep 3; done
	printf '%s\n' "$2"
	tail -n +$n0 "$L" | grep node0 | grep -E "lean.*(bind:|parsed|accumulate|refine failed)" | sed 's/.*INFO lean  /  /' | awk '!seen[$0]++'
}

case $MODE in
	check)
		provide "$1"
		report "0x01$(hash_of "$1")" "check $1" ;;
	bind|bind-prechecked)
		provide "$1"; provide "$2"
		tag=$([ "$MODE" = bind ] && echo 02 || echo 03)
		report "0x$tag$(hash_of "$1")$(hash_of "$2")$(str "$3")$(str "$4")" "$MODE $1 + $2 ($3 / $4)" ;;
	*) echo "usage: $0 SERVICE_ID LOG (check FILE | bind[-prechecked] ENV DELTA STATEMENT THEOREM)" >&2; exit 2 ;;
esac
