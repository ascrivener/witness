#!/usr/bin/env python3
"""Follow a JAM chain's per-block activity statistics for one service.

    stats.py watch SERVICE CSV [RAW_DIR]   follow the best chain, a row per block, until killed
                                           (SERVICE `all`: a row per block and active service)
    stats.py share CSV SLOT                of an `all` CSV, each service's totals from SLOT on
    stats.py since CSV SLOT                print the CSV's rows from SLOT on, summed
    stats.py decode FILE                   decode a raw statistics blob (for testing)

A non-validating node never refines, so its log can't say what a package's refine did, or used.
The chain's statistics (GP 0.8.0, π, JIP-2 `statistics`) can: for every block, each service's
refinement count and gas (of the work reports the block guarantees) and its accumulation count
and gas. `watch` asks the node at $JAM_RPC for every new block's statistics and appends
SERVICE's row to CSV: slot, header hash, refinements, refine gas, accumulations, accumulate gas
(zeros when the service did nothing in that block). With RAW_DIR it also keeps the first few raw
blobs, to check the decoding against.

π, as PolkaJam 0.1.29 serves it on the Toaster: the validators' records twice (this epoch's and
the last's), each a length-prefixed list of 6 u32s per validator; the cores' (C records of 8
naturals, C from the chain's parameters); then a dictionary of services': a u32 id and 11
naturals. Of those, the 3rd and 4th are the refinement count and gas, and the 9th and 11th the
accumulation count and gas: the Toaster's blobs (5 kept from the first live run) decode exactly
so, with corevm's services refining about 5.2×10⁸ gas and accumulating about 3.9×10⁵ a block.
The 10th has been 0 throughout and is kept unnamed. A blob that doesn't decode exactly, with
service ids in order, is reported, not guessed at.
"""

import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from jamrpc import Rpc, unb64, url  # noqa: E402

SERVICE_FIELDS = ("provided_count", "provided_size", "refinements", "refine_gas", "imports",
                  "extrinsic_count", "extrinsic_size", "exports", "accumulations", "field_10",
                  "accumulate_gas")
CORE_FIELDS = 8


def natural(b, i):
    """GP appendix C's variable-length natural at b[i]: (value, next index)."""
    first = b[i]
    if first < 0x80:
        return first, i + 1
    if first == 0xFF:
        return int.from_bytes(b[i + 1:i + 9], "little"), i + 9
    n = 0
    while first & (0x80 >> n):
        n += 1
    rest = int.from_bytes(b[i + 1:i + 1 + n], "little")
    high = first & ((1 << (8 - n - 1)) - 1)
    return rest + (high << (8 * n)), i + 1 + n


def services_at(b, i):
    """The service dictionary from b[i]: {id: {field: value}}, or None if it isn't one that ends
    exactly at the end of b."""
    try:
        count, i = natural(b, i)
        out, last = {}, -1
        for _ in range(count):
            sid = int.from_bytes(b[i:i + 4], "little")
            if sid <= last or i + 4 > len(b):
                return None
            i += 4
            rec = {}
            for f in SERVICE_FIELDS:
                rec[f], i = natural(b, i)
            out[sid], last = rec, sid
        return out if i == len(b) else None
    except IndexError:
        return None


def decode(blob, cores, validators=None):
    """(validator count, services) of a statistics blob, or (None, None)."""
    try:
        i, v = 0, None
        for _ in range(2):
            v, i = natural(blob, i)
            i += 24 * v
        for _ in range(cores * CORE_FIELDS):
            _, i = natural(blob, i)
    except IndexError:
        return None, None
    s = services_at(blob, i)
    return (v, s) if s is not None else (None, None)


def watch(service, csv_path, raw_dir=None):
    rpc = Rpc(url())
    params = next(iter(rpc.call("parameters").values()))
    cores = params["core_count"]
    validators, seen, kept = None, {}, 0
    new = not os.path.exists(csv_path)
    out = open(csv_path, "a")
    if new:
        out.write(("slot,header,service," if service == "all" else "slot,header,")
                  + "refinements,refine_gas,accumulations,accumulate_gas\n")
        out.flush()
    if raw_dir:
        os.makedirs(raw_dir, exist_ok=True)
    last_slot = None
    while True:
        try:
            best = rpc.call("bestBlock")
        except (OSError, SystemExit):
            time.sleep(3)
            rpc = Rpc(url())
            continue
        # Walk back to the last block written (at most 50), so no block is missed.
        chain, head = [], best
        while head and head["header_hash"] not in seen and len(chain) < 50:
            if last_slot is not None and head["slot"] <= last_slot:
                break
            chain.append(head)
            try:
                head = rpc.call("parent", head["header_hash"])
            except SystemExit:
                break
        for block in reversed(chain):
            try:
                blob = unb64(rpc.call("statistics", block["header_hash"]))
            except SystemExit as e:
                print(f"stats.py: no statistics at {block['slot']}: {e}", file=sys.stderr, flush=True)
                continue
            if raw_dir and kept < 5:
                open(f"{raw_dir}/stats-{block['slot']}.bin", "wb").write(blob)
                kept += 1
            v, svcs = decode(blob, cores)
            if v is None:
                print(f"stats.py: can't decode the statistics at {block['slot']} ({len(blob)} B)",
                      file=sys.stderr, flush=True)
                continue
            validators = v
            if service == "all":
                # Every service with activity in the block: who else the chain carried, for backing off.
                h = base64.b64decode(block["header_hash"]).hex()
                for sid, r in svcs.items():
                    if r["refinements"] or r["accumulations"]:
                        out.write(f"{block['slot']},{h},{sid},{r['refinements']},{r['refine_gas']},"
                                  f"{r['accumulations']},{r['accumulate_gas']}\n")
                out.flush()
                seen[block["header_hash"]] = True
                last_slot = block["slot"]
                continue
            r = svcs.get(int(service), {})
            out.write(f"{block['slot']},{base64.b64decode(block['header_hash']).hex()},"
                      f"{r.get('refinements', 0)},{r.get('refine_gas', 0)},"
                      f"{r.get('accumulations', 0)},{r.get('accumulate_gas', 0)}\n")
            out.flush()
            seen[block["header_hash"]] = True
            last_slot = block["slot"]
        time.sleep(2)


def rows(csv_path, since):
    lines = open(csv_path).read().splitlines()[1:]
    out = []
    for line in lines:
        slot, header, r, rg, a, ag = line.split(",")
        if int(slot) >= since:
            out.append({"slot": int(slot), "refinements": int(r), "refine_gas": int(rg),
                        "accumulations": int(a), "accumulate_gas": int(ag)})
    return out


def share(csv_path, slot):
    """Each service's totals in an `all` CSV from SLOT on, and how many blocks it was active in."""
    tot, blocks = {}, set()
    for line in open(csv_path).read().splitlines()[1:]:
        sl, _, sid, r, rg, a, ag = line.split(",")
        if int(sl) < int(slot):
            continue
        blocks.add(int(sl))
        t = tot.setdefault(sid, {"blocks": 0, "refinements": 0, "refine_gas": 0, "accumulations": 0, "accumulate_gas": 0})
        t["blocks"] += 1
        for k, v in (("refinements", r), ("refine_gas", rg), ("accumulations", a), ("accumulate_gas", ag)):
            t[k] += int(v)
    print(json.dumps({"from": int(slot), "active_blocks": len(blocks), "services": tot}))


def since(csv_path, slot):
    rs = rows(csv_path, int(slot))
    busy = [r for r in rs if r["refinements"] or r["accumulations"]]
    total = {k: sum(r[k] for r in rs) for k in ("refinements", "refine_gas", "accumulations", "accumulate_gas")}
    print(json.dumps({"from": int(slot), "to": rs[-1]["slot"] if rs else None, **total, "blocks": busy}))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "watch" and len(sys.argv) in (4, 5):
        watch(*sys.argv[2:])
    elif cmd == "share" and len(sys.argv) == 4:
        share(*sys.argv[2:])
    elif cmd == "since" and len(sys.argv) == 4:
        since(*sys.argv[2:])
    elif cmd == "decode" and len(sys.argv) in (4, 5):
        v, s = decode(open(sys.argv[2], "rb").read(), int(sys.argv[3]), int(sys.argv[4]) if len(sys.argv) > 4 else None)
        print(json.dumps({"validators": v, "services": s}, indent=1))
    else:
        sys.exit(__doc__)
