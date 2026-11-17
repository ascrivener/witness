#!/usr/bin/env python3
"""Wait for a JAM node to sync with its chain, logging its progress.

    sync.py TIMEOUT_MINUTES CSV [STATUS_JSON]

Polls the node at $JAM_RPC (default ws://localhost:19800) every 15 s and appends a CSV row each
time: wall-clock seconds since start, the wall-clock slot, the node's best and finalized slots,
and what `syncState` reports (JIP-2; blank if the node doesn't answer it). The wall-clock slot is
(now - JAM common era) / 6 s, the JAM common era being 2025-01-01 12:00:00 UTC (GP section 4.4).

The node counts as synced once its best slot is within 3 of the wall-clock slot and has been
advancing for a minute. Exits 0 when synced, 1 on timeout, and 1 early if after
$SYNC_STALL_MINUTES (default 20) the node still has no block past genesis. Either way it writes STATUS_JSON (if
given): the node's view of the chain at the end, and how long syncing took.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from jamrpc import Rpc, url  # noqa: E402

JCE = 1735732800  # 2025-01-01 12:00:00 UTC
SLOT_SECONDS = 6
POLL = int(os.environ.get("SYNC_POLL", 15))


def wall_slot():
    return int(time.time() - JCE) // SLOT_SECONDS


def call(rpc, method, *params):
    """`rpc.call`, but None where the node errors (jamrpc exits on an RPC error)."""
    try:
        return rpc.call(method, *params)
    except SystemExit:
        return None


def snapshot():
    rpc = Rpc(url())
    best = call(rpc, "bestBlock")
    final = call(rpc, "finalizedBlock")
    sync = call(rpc, "syncState")
    return best, final, sync


def main(timeout_min, csv_path, status_path=None):
    start = time.time()
    deadline = start + 60 * float(timeout_min)
    stall = 60 * float(os.environ.get("SYNC_STALL_MINUTES") or 20)
    stalled = False
    first_block = None
    synced_at = None
    near_since = None
    best = final = sync = None
    with open(csv_path, "a") as csv:
        csv.write("elapsed_s,wall_slot,best_slot,finalized_slot,sync_state\n")
        while time.time() < deadline:
            if first_block is None and time.time() - start >= stall:
                stalled = True
                break
            try:
                best, final, sync = snapshot()
            except (OSError, SystemExit) as e:
                csv.write(f"{int(time.time() - start)},{wall_slot()},,,rpc down: {e}\n")
                csv.flush()
                time.sleep(POLL)
                continue
            now = wall_slot()
            b = best["slot"] if best else None
            f = final["slot"] if final else None
            elapsed = int(time.time() - start)
            row = f"{elapsed},{now},{b if b is not None else ''},{f if f is not None else ''},{json.dumps(sync) if sync is not None else ''}"
            csv.write(row.replace("\n", " ") + "\n")
            csv.flush()
            print(row, flush=True)
            if b and first_block is None:
                first_block = elapsed
            if b is not None and b >= now - 3:
                near_since = near_since if near_since is not None else time.time()
                if time.time() - near_since >= 60:
                    synced_at = elapsed
                    break
            else:
                near_since = None
            time.sleep(POLL)
    status = {
        "synced": synced_at is not None,
        "stalled_at_genesis": stalled,
        "sync_seconds": synced_at,
        "first_block_seconds": first_block,
        "wall_slot": wall_slot(),
        "best": best,
        "finalized": final,
        "sync_state": sync,
    }
    if status_path:
        with open(status_path, "w") as out:
            json.dump(status, out, indent=2)
    print(json.dumps(status, indent=2))
    return 0 if status["synced"] else 1


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
