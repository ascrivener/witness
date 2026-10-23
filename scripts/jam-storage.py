#!/usr/bin/env python3
"""Print a service's storage value as of the best block, in full.

    jam-storage.py SERVICE KEY

KEY is hex (an optional 0x prefix). Prints the value as 0x-prefixed hex, or nothing if there is
none. `jamt inspect storage --raw` cuts values over 1 KiB short, so the e2e scripts read storage
with this instead: the node's JSON-RPC (JIP-2 `bestBlock` and `serviceValue`) at $JAM_RPC
(default ws://localhost:19800), through jamrpc.py.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jamrpc import Rpc, b64, unb64, url  # noqa: E402


def main(service, key):
    rpc = Rpc(url())
    best = rpc.call("bestBlock")["header_hash"]
    value = rpc.call("serviceValue", best, int(service), b64(bytes.fromhex(key.removeprefix("0x"))))
    if value is not None:
        print("0x" + unb64(value).hex())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
