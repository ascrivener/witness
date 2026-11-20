#!/usr/bin/env python3
"""test-sim.sh's checks on a snapshot (snapshot.py's output) of witness-sim's chain.

    check-sim.py SNAPSHOT_JSON DECODED_TSV SLOT

DECODED_TSV has a line per stored value (kind, id, raw hex, `witness decode`'s output), plus the
storage keys `witness key` gives for bounty 258, NextBountyId, Config and proposal 3, and the
account of the seed `someone`. Every number and bool in `witness decode`'s output must be
snapshot.py's, in order, and the snapshot must show what test-sim.sh did.
"""

import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import snapshot  # noqa: E402

failures = []


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def debug_values(text):
    """The numbers and bools of a Rust Debug string, in order."""
    return [t == "true" if t in ("true", "false") else int(t) for t in re.findall(r"\b(?:\d+|true|false)\b", text)]


def hx(h):
    return list(bytes.fromhex(h[2:]))


def claim_values(c):
    return [c["committed"], *hx(c["commitment"]), *hx(c["hunter"]), *hx(c["witness_hash"])]


def asset_values(a):
    return [a["service"], a["id"]]


def bounty_values(b, params):
    t, s = b["terms"], b["status"]
    out = [*hx(b["maker"]), *hx(t["check_hash"]), t["check_len"], *params]
    for blob in t["blobs"]:
        out += [*hx(blob["hash"]), blob["len"]] if blob["kind"] == "blob" else [*hx(blob["attestation"]), blob["entry"]]
    out += [*asset_values(t["asset"]), int(t["reward"]), t["check_gas"], t["expiry"], t["claim_window"],
            t["disclosure_window"], t["bind_claim"]]
    if s["kind"] == "Revealing":
        out += [s["window_end"], *claim_values(s["leader"])]
    elif s["kind"] == "Claimed":
        out += [*claim_values(s["winner"]), s["slot"]]
    return out


def config_values(c):
    out = list(c["token_services"])
    if c["fee_asset"]:
        out += asset_values(c["fee_asset"])
    return out + [int(c["commit_deposit"]), int(c["attest_deposit"])]


def proposal_values(p):
    a = p["action"]
    if a["kind"] == "SetAdmin":
        out = hx(a["admin"])
    elif a["kind"] == "Upgrade":
        out = [*hx(a["code_hash"]), a["code_len"]]
    else:
        out = config_values(a["config"])
    return out + [p["effective"]]


def main(snap_path, tsv_path, slot):
    snap = json.load(open(snap_path))
    rows = [line.rstrip("\n").split("\t") for line in open(tsv_path)]
    extra = {r[0]: r[2] for r in rows if r[0] in ("keys", "admin")}

    for kind, id_, raw, text in (r for r in rows if r[0] in ("bounty", "config", "proposal")):
        data = bytes.fromhex(raw[2:])
        if kind == "bounty":
            b = snap["bounties"][int(id_)]
            check(f"bounty {id_}: the snapshot's is the stored value's decoding",
                  {k: v for k, v in b.items() if k != "id"} == snapshot.decode("bounty", data))
            p = data[32 + 32 + 4:]  # the params, after the maker, check hash and check length
            p = p[1:1 + p[0]] if p[0] < 0x80 else p[2:2 + ((p[0] & 0x3F) << 8) + p[1]]
            check(f"bounty {id_}: params inline only when short",
                  b["terms"].get("params") == ("0x" + p.hex() if len(p) <= snapshot.PARAMS_INLINE else None))
            mine = bounty_values(b, list(p))
            check(f"bounty {id_}: status {b['status']['kind']}, as witness decode's",
                  re.search(r"status: (\w+)", text).group(1) == b["status"]["kind"])
            check(f"bounty {id_}: params hash and length",
                  b["terms"]["params_len"] == len(p)
                  and b["terms"]["params_blake2b"] == "0x" + hashlib.blake2b(p, digest_size=32).hexdigest())
        elif kind == "config":
            mine = config_values(snap["config"])
        else:
            [p] = [p for p in snap["proposals"] if p["id"] == int(id_)]
            mine = proposal_values(p)
            check(f"proposal {id_}: SetAdmin", re.search(r"action: (\w+)", text).group(1) == p["action"]["kind"])
        theirs = debug_values(text)
        check(f"{kind} {id_}: all {len(theirs)} values as witness decode's", mine == theirs)

    keys = extra["keys"].split()
    mine = ["0x" + k.hex() for k in (snapshot.key_bounty(258), snapshot.KEY_NEXT_BOUNTY, snapshot.KEY_CONFIG,
                                     snapshot.key_proposal(3))]
    check("storage keys as witness key's", mine == keys)

    bs = snap["bounties"]
    check("6 bounties", snap["next_bounty_id"] == 6 and [b["id"] for b in bs] == [0, 1, 2, 3, 4, 5])
    check("statuses Claimed, Open, Revealing, Reclaimed, Open, Open",
          [b["status"]["kind"] for b in bs] == ["Claimed", "Open", "Revealing", "Reclaimed", "Open", "Open"])
    check("rewards", [b["terms"]["reward"] for b in bs] == ["100", "250", "300", "400", "1000000", "5"])
    check("bounty 5: an attested blob then a plain one, 300 bytes of params, bind_claim",
          [x["kind"] for x in bs[5]["terms"]["blobs"]] == ["attested", "blob"] and bs[5]["terms"]["blobs"][1]["len"] == 48
          and bs[5]["terms"]["params_len"] == 300 and bs[5]["terms"]["bind_claim"])
    check("rewards in the test asset", all(b["terms"]["asset"].get("name") == "test" for b in bs))
    check("bounty 1's windows", (bs[1]["terms"]["claim_window"], bs[1]["terms"]["disclosure_window"]) == (40, 7))
    check("bounty 4 is past its expiry", bs[4]["terms"]["expiry"] <= snap["best_block"]["slot"] <= int(slot))
    check("bounty 0's winner is bounty 2's leader's hunter",
          bs[0]["status"]["winner"]["hunter"] == bs[2]["status"]["leader"]["hunter"])
    check("config: fee asset test, deposits 10",
          snap["config"]["fee_asset"].get("name") == "test"
          and (snap["config"]["commit_deposit"], snap["config"]["attest_deposit"]) == ("10", "10"))
    # The first configuration applies at once, taking no id: the set-admin is proposal 0.
    check("one pending proposal: id 0, SetAdmin to someone",
          snap["next_proposal_id"] == 1 and len(snap["proposals"]) == 1 and snap["proposals"][0]["id"] == 0
          and snap["proposals"][0]["action"] == {"kind": "SetAdmin", "admin": extra["admin"]})
    check("no stored admin", snap["admin_stored"] is None)
    if failures:
        sys.exit(f"{len(failures)} check(s) failed")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
