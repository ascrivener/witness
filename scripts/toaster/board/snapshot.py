#!/usr/bin/env python3
"""Read witness's bounties and admin state from a JAM node and write them as JSON, for the bounty
board (site/index.html).

    snapshot.py SERVICE OUT_JSON

Reads service SERVICE's storage at the node's best block, over its JSON-RPC (JIP-2) at $JAM_RPC
(default ws://localhost:19800), through scripts/jamrpc.py, and decodes it here (jam-codec, as
witness_types encodes it: SCALE's layout, with lengths as the Gray Paper's naturals): every bounty from 0 up to NextBountyId, the configuration, the stored
admin, every proposal from 0 up to NextProposalId, and the service's code hash. Submits nothing.

Not read: commitments and attestations. Both are keyed by hash with no counter, so they can't be
listed without scanning storage. Amounts are strings (they're u128s, past what JSON numbers hold
exactly).

`decode` (`snapshot.py --decode KIND HEX`, KIND bounty, config or proposal) prints one stored value
as JSON, for checking this decoder against `witness decode`.
"""

import datetime
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from jamrpc import Rpc, b64, unb64, url  # noqa: E402

JCE = 1735732800  # the JAM common era, 2025-01-01 12:00:00 UTC
SLOT_SECONDS = 6
TEST_ASSET = (0xFFFFFFFF, 0)
# Params longer than this are given by length and hash only.
PARAMS_INLINE = 256


# witness_types::StorageKey, encoded: the variant's index, then its fields.
def key_bounty(i):
    return bytes([1]) + i.to_bytes(8, "little")


KEY_NEXT_BOUNTY = bytes([3])
KEY_CONFIG = bytes([6])
KEY_ADMIN = bytes([7])


def key_proposal(i):
    return bytes([8]) + i.to_bytes(8, "little")


KEY_NEXT_PROPOSAL = bytes([9])


class Reader:
    def __init__(self, data):
        self.data, self.i = data, 0

    def take(self, n):
        if self.i + n > len(self.data):
            raise ValueError(f"truncated: need {n} bytes at {self.i} of {len(self.data)}")
        out = self.data[self.i : self.i + n]
        self.i += n
        return out

    def uint(self, n):
        return int.from_bytes(self.take(n), "little")

    def u8(self):
        return self.uint(1)

    def u32(self):
        return self.uint(4)

    def u64(self):
        return self.uint(8)

    def u128(self):
        return self.uint(16)

    def hash(self):
        return "0x" + self.take(32).hex()

    def boolean(self):
        b = self.u8()
        if b > 1:
            raise ValueError(f"bad bool {b}")
        return b == 1

    def compact(self):
        """A length: jam-codec's compact integer, the Gray Paper's variable-length natural."""
        b = self.u8()
        if b == 0xFF:
            return self.u64()
        n = 0
        while b & (0x80 >> n):
            n += 1
        return self.uint(n) + ((b & ((1 << (7 - n)) - 1)) << (8 * n))

    def bytes_(self):
        return self.take(self.compact())

    def vec(self, item):
        return [item() for _ in range(self.compact())]

    def end(self):
        if self.i != len(self.data):
            raise ValueError(f"{len(self.data) - self.i} bytes left over")


def asset(r):
    service, id_ = r.u32(), r.u32()
    out = {"service": service, "id": id_}
    if (service, id_) == TEST_ASSET:
        out["name"] = "test"
    return out


def claim(r):
    return {"committed": r.u32(), "commitment": r.hash(), "hunter": r.hash(), "witness_hash": r.hash()}


def blob_ref(r):
    v = r.u8()
    if v == 0:
        return {"kind": "blob", "hash": r.hash(), "len": r.u32()}
    if v == 1:
        return {"kind": "attested", "attestation": r.hash(), "entry": r.u32()}
    raise ValueError(f"bad BlobRef variant {v}")


def bounty(r):
    maker = r.hash()
    check_hash, check_len = r.hash(), r.u32()
    params = r.bytes_()
    terms = {
        "check_hash": check_hash,
        "check_len": check_len,
        "params_len": len(params),
        "params_blake2b": "0x" + hashlib.blake2b(params, digest_size=32).hexdigest(),
        "blobs": r.vec(lambda: blob_ref(r)),
        "asset": asset(r),
        "reward": str(r.u128()),
        "check_gas": r.u64(),
        "expiry": r.u32(),
        "claim_window": r.u32(),
        "disclosure_window": r.u32(),
        "bind_claim": r.boolean(),
    }
    if len(params) <= PARAMS_INLINE:
        terms["params"] = "0x" + params.hex()
    v = r.u8()
    if v == 0:
        status = {"kind": "Open"}
    elif v == 1:
        status = {"kind": "Revealing", "window_end": r.u32(), "leader": claim(r)}
    elif v == 2:
        status = {"kind": "Claimed", "winner": claim(r), "slot": r.u32()}
    elif v == 3:
        status = {"kind": "Reclaimed"}
    else:
        raise ValueError(f"bad BountyStatus variant {v}")
    return {"maker": maker, "terms": terms, "status": status}


def config(r):
    token_services = r.vec(r.u32)
    fee = asset(r) if r.u8() else None
    return {
        "token_services": token_services,
        "fee_asset": fee,
        "commit_deposit": str(r.u128()),
        "attest_deposit": str(r.u128()),
    }


def proposal(r):
    v = r.u8()
    if v == 0:
        action = {"kind": "Configure", "config": config(r)}
    elif v == 1:
        action = {"kind": "SetAdmin", "admin": r.hash()}
    elif v == 2:
        action = {"kind": "Upgrade", "code_hash": r.hash(), "code_len": r.u32()}
    else:
        raise ValueError(f"bad AdminAction variant {v}")
    return {"action": action, "effective": r.u32()}


def decode(kind, data):
    r = Reader(data)
    out = {"bounty": bounty, "config": config, "proposal": proposal}[kind](r)
    r.end()
    return out


def slot_time(slot):
    t = datetime.datetime.fromtimestamp(JCE + slot * SLOT_SECONDS, datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def snapshot(service):
    rpc = Rpc(url())
    best = rpc.call("bestBlock")
    final = rpc.call("finalizedBlock")
    head = best["header_hash"]

    def value(key):
        v = rpc.call("serviceValue", head, service, b64(key))
        return None if v is None else unb64(v)

    def counter(key):
        v = value(key)
        return 0 if v is None else int.from_bytes(v, "little")

    info = rpc.call("serviceData", head, service)
    if info is None:
        sys.exit(f"snapshot: no service {service} at the best block (slot {best['slot']})")
    code_hash = "0x" + unb64(info)[1:33].hex()

    bounties = []
    next_bounty = counter(KEY_NEXT_BOUNTY)
    for i in range(next_bounty):
        v = value(key_bounty(i))
        entry = {"id": i}
        if v is None:
            entry["missing"] = True
        else:
            entry.update(decode("bounty", v))
        bounties.append(entry)

    proposals = []
    next_proposal = counter(KEY_NEXT_PROPOSAL)
    for i in range(next_proposal):
        v = value(key_proposal(i))
        if v is not None:  # applied or cancelled proposals are deleted
            p = decode("proposal", v)
            p["id"] = i
            p["effective_time"] = slot_time(p["effective"])
            proposals.append(p)

    cfg = value(KEY_CONFIG)
    admin = value(KEY_ADMIN)
    return {
        "service": service,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "best_block": {"slot": best["slot"], "hash": "0x" + unb64(head).hex()},
        "finalized_slot": final["slot"] if final else None,
        "slot_time": slot_time(best["slot"]),
        "code_hash": code_hash,
        "config": decode("config", cfg) if cfg is not None else None,
        "admin_stored": "0x" + admin.hex() if admin is not None else None,
        "next_bounty_id": next_bounty,
        "next_proposal_id": next_proposal,
        "proposals": proposals,
        "bounties": bounties,
    }


def main(argv):
    if len(argv) == 4 and argv[1] == "--decode":
        print(json.dumps(decode(argv[2], bytes.fromhex(argv[3].removeprefix("0x"))), indent=2))
        return
    if len(argv) != 3 or not argv[1].isdigit():
        sys.exit(__doc__)
    snap = snapshot(int(argv[1]))
    with open(argv[2], "w") as f:
        json.dump(snap, f, indent=2)
        f.write("\n")
    print(f"service {snap['service']} at slot {snap['best_block']['slot']}: "
          f"{len(snap['bounties'])} bounties, {len(snap['proposals'])} pending proposals")
    for b in snap["bounties"]:
        if b.get("missing"):
            print(f"  bounty {b['id']}: missing")
        else:
            t = b["terms"]
            print(f"  bounty {b['id']}: {b['status']['kind']}, reward {t['reward']}, expiry {t['expiry']}")


if __name__ == "__main__":
    main(sys.argv)
