#!/usr/bin/env python3
"""Submit a work package of work items, with extrinsics, to a JAM node.

    jam-submit.py SERVICE PAYLOAD [EXTRINSIC...] [-- PAYLOAD [EXTRINSIC...]]...

PAYLOAD is hex (an optional 0x prefix), or @FILE for a file holding the hex (an op too big for one
command-line argument, which Linux caps at 128 KiB); each EXTRINSIC is a file. Each `--` starts
another item for SERVICE, in the same package; accumulate applies them in order. Like `jamt item`,
which can't attach extrinsics: the package is anchored at the finalized block, its lookup anchor
is that block's parent, and the items share the chain's full refine and accumulate gas equally.
It's submitted with `submitWorkPackage` to the node at $JAM_RPC (default ws://localhost:19800) on
core $JAM_CORE (default 0), and authorized by $JAM_AUTHORIZER (default: the PolkaJam testnet's, as
`jamt` uses). Prints the package hash. Scripts can call `submit` instead, giving each item its own
gas.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jamrpc import Rpc, b64, unb64, url  # noqa: E402

# The most bytes a work package's encoding (its items' payloads, but not their extrinsics) may
# take: PolkaJam v0.1.29's nodes refuse a bigger one ("Failed to submit work-package to even a
# single proxy/guarantor"), though it's no chain parameter. Measured on a testnet: 203,750 bytes
# went through, 205,000 didn't.
MAX_PACKAGE = 200 * 1024

# The authorizer `jamt` v0.1.29 names on the testnet, hosted by the Bootstrap service (0).
TESTNET_AUTHORIZER = "f8d86b97d65319a078e5840f1614c296a5254217794dcc910e72ca174e3c2e86"
AUTH_CODE_HOST = 0


def blake2b(data):
    return hashlib.blake2b(data, digest_size=32).digest()


def natural(x):
    """JAM's variable-length encoding of a natural number (GP appendix C)."""
    if x < 1 << 7:
        return bytes([x])
    for n in range(1, 8):
        if x < 1 << (7 * (n + 1)):
            prefix = 256 - (1 << (8 - n)) + (x >> (8 * n))
            return bytes([prefix]) + (x % (1 << (8 * n))).to_bytes(n, "little")
    return b"\xff" + x.to_bytes(8, "little")


def blob(data):
    return natural(len(data)) + data


def u16(x):
    return x.to_bytes(2, "little")


def u32(x):
    return x.to_bytes(4, "little")


def u64(x):
    return x.to_bytes(8, "little")


def work_item(service, code_hash, refine_gas, accumulate_gas, payload, extrinsics):
    return (
        u32(service)
        + code_hash
        + u64(refine_gas)
        + u64(accumulate_gas)
        + u16(0)  # exports
        + blob(payload)
        + natural(0)  # imports
        + natural(len(extrinsics))
        + b"".join(blake2b(x) + u32(len(x)) for x in extrinsics)
    )


def work_package(authorizer, context, items):
    """`context` is (anchor, anchor_slot, state_root, beefy_root, lookup_anchor,
    lookup_anchor_slot, lookup_anchor_state_root), with no prerequisites."""
    anchor, anchor_slot, state_root, beefy_root, lookup, lookup_slot, lookup_root = context
    return (
        u32(AUTH_CODE_HOST)
        + authorizer
        + anchor
        + u32(anchor_slot)
        + state_root
        + beefy_root
        + lookup
        + u32(lookup_slot)
        + lookup_root
        + natural(0)  # prerequisites
        + blob(b"")  # authorization
        + blob(b"")  # authorizer config
        + natural(len(items))
        + b"".join(items)
    )


def submit(rpc, service, items, core=None):
    """Submit `items`, each (payload, extrinsics, refine gas, accumulate gas), all bytes and ints,
    as one work package for `service` on `core` (default $JAM_CORE, else 0). Returns its hash."""
    params = next(iter(rpc.call("parameters").values()))
    extrinsics = [x for _, xs, _, _ in items for x in xs]
    if len(extrinsics) > params["max_extrinsics"]:
        sys.exit(f"jam-submit: {len(extrinsics)} extrinsics, at most {params['max_extrinsics']}")
    if len(items) > params["max_work_items"]:
        sys.exit(f"jam-submit: {len(items)} items, at most {params['max_work_items']}")
    for name, i, limit in (("refine", 2, "max_refine_gas"), ("accumulate", 3, "max_accumulate_gas")):
        if sum(item[i] for item in items) > params[limit]:
            sys.exit(f"jam-submit: the items' {name} gas is over the package's {params[limit]}")
    final = rpc.call("finalizedBlock")
    lookup = rpc.call("parent", final["header_hash"])
    context = (
        unb64(final["header_hash"]),
        final["slot"],
        unb64(rpc.call("stateRoot", final["header_hash"])),
        unb64(rpc.call("beefyRoot", final["header_hash"])),
        unb64(lookup["header_hash"]),
        lookup["slot"],
        unb64(rpc.call("stateRoot", lookup["header_hash"])),
    )
    info = rpc.call("serviceData", final["header_hash"], int(service))
    if info is None:
        sys.exit(f"jam-submit: no service {service} at the finalized block")
    code_hash = unb64(info)[1:33]  # after the version byte
    authorizer = bytes.fromhex(os.environ.get("JAM_AUTHORIZER", TESTNET_AUTHORIZER))
    package = work_package(
        authorizer, context, [work_item(int(service), code_hash, r, a, p, xs) for p, xs, r, a in items]
    )
    if len(package) > MAX_PACKAGE:
        sys.exit(f"jam-submit: the package is {len(package)} bytes (extrinsics aside), at most {MAX_PACKAGE}")
    size = len(package) + sum(map(len, extrinsics))
    if size > params["max_input"]:
        sys.exit(f"jam-submit: package and extrinsics are {size} bytes, at most {params['max_input']}")
    core = int(os.environ.get("JAM_CORE", "0")) if core is None else core
    rpc.call("submitWorkPackage", core, b64(package), [b64(x) for x in extrinsics])
    return blake2b(package), final["slot"]


def main(service, args):
    rpc = Rpc(url())
    params = next(iter(rpc.call("parameters").values()))
    specs = [[]]
    for arg in args:
        if arg == "--":
            specs.append([])
        else:
            specs[-1].append(arg)
    if [] in specs:
        sys.exit(__doc__)
    items = []
    for payload, *files in specs:
        if payload.startswith("@"):
            payload = open(payload[1:]).read().strip()
        payload = bytes.fromhex(payload.removeprefix("0x"))
        extrinsics = [open(f, "rb").read() for f in files]
        n = len(specs)
        items.append((payload, extrinsics, params["max_refine_gas"] // n, params["max_accumulate_gas"] // n))
    package, anchor = submit(rpc, service, items)
    print(f"{len(items)} item{'s' * (len(items) > 1)} submitted in package 0x{package.hex()} with anchor at #{anchor}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2:])
