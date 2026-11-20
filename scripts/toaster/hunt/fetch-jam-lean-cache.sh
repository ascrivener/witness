#!/usr/bin/env bash
# Unpack jam-lean's build (.lake) for exactly COMMIT into JAM_LEAN_DIR, from witness's release
# jam-lean-lake-<first 7 of COMMIT> (.github/workflows/jam-lean-cache.yml copied it from jam-lean's
# lake-cache release, which follows jam-lean's main): `lake build` then has nothing, or little, to
# rebuild, wherever jam-lean's main has gone since.
#
#   scripts/toaster/hunt/fetch-jam-lean-cache.sh JAM_LEAN_DIR COMMIT
#
# Each part is checked against the release's SHA256SUMS. Exits 2 if there's no such release (then
# use jam-lean's own scripts/fetch-lake.sh, or build cold). Needs curl, zstd and tar; the disk holds
# one part (under 2 GiB) next to the growing .lake (about 12 GB).
set -euo pipefail
DIR=${1:?usage: fetch-jam-lean-cache.sh JAM_LEAN_DIR COMMIT} COMMIT=${2:?commit}
BASE=${JAM_LEAN_CACHE_BASE:-https://github.com/ascrivener/witness/releases/download}/jam-lean-lake-${COMMIT:0:7}
cd "$DIR"
[ "$(git rev-parse HEAD)" = "$COMMIT" ] || { echo "$DIR isn't at $COMMIT" >&2; exit 1; }
sums=$(curl -sSfL --retry 5 "$BASE/SHA256SUMS") || { echo "no release jam-lean-lake-${COMMIT:0:7}" >&2; exit 2; }
grep -q "lake-$COMMIT\.tar\.zst\." <<<"$sums" || { echo "SHA256SUMS isn't for $COMMIT" >&2; exit 1; }
rm -rf .lake.partial .lake.dl && mkdir .lake.partial
while read -r sum name; do
	for i in $(seq 1 30); do
		curl -sSfL --retry 5 -C - -o .lake.dl "$BASE/$name" && break
		echo "resuming $name ($i)" >&2; sleep 2
	done
	echo "$sum  .lake.dl" | sha256sum -c --quiet - >&2 || { echo "$name: sha256 mismatch" >&2; exit 1; }
	cat .lake.dl
	rm -f .lake.dl
done <<<"$sums" | zstd -dc | tar -x -C .lake.partial
rm -rf .lake && mv .lake.partial/.lake .lake && rmdir .lake.partial
echo "unpacked jam-lean ${COMMIT:0:7}'s .lake ($(du -sh .lake | cut -f1)) from $BASE"
