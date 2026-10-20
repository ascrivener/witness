#!/usr/bin/env bash
# Fetch nanoda_lib at the commit the spike was made against and apply the no_std port.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf nanoda
git clone -q https://github.com/ammkrn/nanoda_lib nanoda
git -C nanoda checkout -q 9d6964f
rm -rf nanoda/.git
patch -s -p1 -d nanoda < nanoda-no_std.patch
# The CLI needs std; the port is the library only.
rm -f nanoda/src/main.rs
echo "nanoda (no_std) ready in $(pwd)/nanoda"
