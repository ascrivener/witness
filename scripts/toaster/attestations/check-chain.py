#!/usr/bin/env python3
"""Check a release's libraries against witness's state on chain, and write what was found.

    check-chain.py SERVICE RELEASE_DIR OUT_JSON

For each library of RELEASE_DIR's manifest.json (its NAME.json, from build.py): every batch's attestation must be
recorded in service SERVICE's storage (StorageKey::Attestation), with the library's check hash and
empty attest params, and every bounty the library was attested for must be posted with the
library's goal as its params, its check, and the library's cited attestation as its one blob.
Reads the node at $JAM_RPC (default ws://localhost:19800, or a stand-in such as scripts/toaster/
lean/fake-node.py) at its best block. Exits 1, listing what's wrong, unless everything matches.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(HERE, "..", "board"))
from jamrpc import Rpc, b64, unb64, url  # noqa: E402
import snapshot  # noqa: E402

KEY_ATTESTATION = 4  # witness_types::StorageKey::Attestation's index
EMPTY_PARAMS = "0x" + hashlib.blake2b(b"", digest_size=32).hexdigest()


def main(service, release, out):
    rpc = Rpc(url())
    best = rpc.call("bestBlock")
    get = lambda key: (lambda v: unb64(v) if v is not None else None)(
        rpc.call("serviceValue", best["header_hash"], service, b64(key)))
    problems, libraries = [], []
    names = [l["library"] for l in json.load(open(f"{release}/manifest.json"))["libraries"]]
    for name in names:
        lib = json.load(open(f"{release}/{name}.json"))
        slots, missing = [], []
        for b in lib["batches"]:
            v = get(bytes([KEY_ATTESTATION]) + bytes.fromhex(b["attestation"][2:]))
            if v is None:
                missing.append(b["attestation"])
                continue
            r = snapshot.Reader(v)
            check, params, slot, attester = r.hash(), r.hash(), r.u32(), r.hash()
            r.end()
            if check != lib["check_hash"] or params != EMPTY_PARAMS:
                problems.append(f"{name}: attestation {b['attestation']} is by check {check}, params {params}")
            slots.append(slot)
        if missing:
            problems.append(f"{name}: {len(missing)} of {len(lib['batches'])} attestations not on chain, e.g. {missing[:3]}")
        bounties = []
        # A library with no goal (one on top of another, scripts/toaster/library/release.py) backs no bounty itself.
        for bid in (lib["goal"]["bounties"] if lib["goal"] else []):
            v = get(snapshot.key_bounty(bid))
            if v is None:
                problems.append(f"{name}: bounty {bid} isn't on chain")
                continue
            r = snapshot.Reader(v)
            bounty = snapshot.bounty(r)
            t = bounty["terms"]
            want = [{"kind": "attested", "attestation": lib["cite"]["attestation"], "entry": lib["cite"]["entry"]}]
            if t.get("params") != "0x" + lib["goal"]["node"] or t["check_hash"] != lib["check_hash"] or t["blobs"] != want:
                problems.append(f"{name}: bounty {bid} isn't for the goal {lib['goal']['node']} citing {want}: {t}")
            bounties.append({"id": bid, "status": bounty["status"]["kind"], "expiry": t["expiry"],
                             "reward": t["reward"], "asset": t["asset"], "claim_window": t["claim_window"]})
        libraries.append({"library": name, "attestations_found": len(slots), "attestations": len(lib["batches"]),
                          "attested_slots": [min(slots), max(slots)] if slots else None, "bounties": bounties})
        print(f"{name}: {len(slots)} of {len(lib['batches'])} attestations on chain"
              + (f", accumulated in slots {min(slots)}–{max(slots)}" if slots else "")
              + "".join(f"; bounty {b['id']} {b['status']}" for b in bounties))
    result = {"service": service, "best_block": {"slot": best["slot"], "header_hash": best["header_hash"]},
              "libraries": libraries, "ok": not problems}
    json.dump(result, open(out, "w"), indent=1)
    for p in problems:
        print("FAIL:", p, file=sys.stderr)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(int(sys.argv[1]), sys.argv[2], sys.argv[3])
