#!/usr/bin/env python3
"""A stand-in JAM node for testing live mode without a chain: the subset of JIP-2 the live scripts
use, over a WebSocket, backed by tools/witness-sim.

    fake-node.py PORT WITNESS_SIM SERVICE [DROP]

WITNESS_SIM runs with this process's WITNESS_SIM_DIR (create and configure the service first).
`submitWorkPackage` decodes the package (as scripts/jam-submit.py encodes it), and refines and
accumulates its items in witness-sim (`items`), a second after it's submitted, as a block would; a
fraction DROP (default 0) of packages is silently dropped, to exercise resubmitting. The slot is
witness-sim's, passed every half second. `statistics` gives each block's service statistics as
GP 0.8.0 encodes them (6 validators, the parameters' cores), with the check gas the items' refines
used and the items applied, so scripts/toaster/lean/stats.py can follow them. Storage and service
data come from witness-sim.
"""

import base64
import hashlib
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

PARAMS = {"core_count": 10, "max_accumulate_gas": 10_000_000, "max_refine_gas": 5_000_000_000,
          "block_gas_limit": 3_500_000_000, "max_work_items": 16, "max_extrinsics": 128,
          "max_input": 13_791_360, "slot_period_sec": 6}
VALIDATORS = 6

lock = threading.Lock()
slot = 0
stats = {}  # slot -> [refinements, refine gas, accumulations, accumulate gas, extrinsic count, bytes]


def b64(b):
    return base64.b64encode(b).decode()


def natural(x):
    if x < 1 << 7:
        return bytes([x])
    for n in range(1, 8):
        if x < 1 << (7 * (n + 1)):
            return bytes([256 - (1 << (8 - n)) + (x >> (8 * n))]) + (x % (1 << (8 * n))).to_bytes(n, "little")
    return b"\xff" + x.to_bytes(8, "little")


def read_natural(b, i):
    first = b[i]
    if first < 0x80:
        return first, i + 1
    if first == 0xFF:
        return int.from_bytes(b[i + 1:i + 9], "little"), i + 9
    n = 0
    while first & (0x80 >> n):
        n += 1
    return int.from_bytes(b[i + 1:i + 1 + n], "little") + ((first & ((1 << (7 - n)) - 1)) << (8 * n)), i + 1 + n


def header(s):
    return b64(s.to_bytes(4, "little") + bytes(28))


def block(s):
    return {"header_hash": header(s), "slot": s}


def sim(*args):
    return subprocess.run([SIM, *args], capture_output=True, text=True).stdout.strip()


def ticker():
    global slot
    while True:
        with lock:
            slot = int(sim("inspect", "slot"))
        time.sleep(0.5)


def decode_package(pkg):
    i = 4 + 32 + 32 + 4 + 32 + 32 + 32 + 4 + 32
    n, i = read_natural(pkg, i)
    assert n == 0, "prerequisites"
    for _ in range(2):  # authorization, authorizer config
        n, i = read_natural(pkg, i)
        i += n
    count, i = read_natural(pkg, i)
    items = []
    for _ in range(count):
        service = int.from_bytes(pkg[i:i + 4], "little")
        i += 4 + 32
        refine, accumulate = struct.unpack("<QQ", pkg[i:i + 16])
        i += 16 + 2
        n, i = read_natural(pkg, i)
        payload = pkg[i:i + n]
        i += n
        _, i = read_natural(pkg, i)
        nx, i = read_natural(pkg, i)
        hashes = []
        for _ in range(nx):
            hashes.append((pkg[i:i + 32], int.from_bytes(pkg[i + 32:i + 36], "little")))
            i += 36
        items.append((service, refine, accumulate, payload, hashes))
    assert i == len(pkg), "trailing bytes"
    return items


def land(pkg, extrinsics):
    time.sleep(1)
    items = decode_package(pkg)
    xs = iter(extrinsics)
    with tempfile.TemporaryDirectory() as tmp, lock:
        lines = []
        for k, (service, _, _, payload, hashes) in enumerate(items):
            assert service == SERVICE
            files = []
            for j, (h, n) in enumerate(hashes):
                x = next(xs)
                assert hashlib.blake2b(x, digest_size=32).digest() == h and len(x) == n, "extrinsic hash"
                files.append(f"{tmp}/{k}-{j}")
                open(files[-1], "wb").write(x)
            open(f"{tmp}/{k}.op", "w").write(payload.hex())
            lines.append(" ".join([f"{tmp}/{k}.op", *files]))
        open(f"{tmp}/list", "w").write("\n".join(lines) + "\n")
        log = os.path.join(os.environ.get("WITNESS_SIM_DIR", ".witness-sim"), "log")
        before = os.path.getsize(log) if os.path.exists(log) else 0
        out = sim("items", str(SERVICE), f"{tmp}/list")
        with open(log) as f:
            f.seek(before)
            gas = sum(int(m) for m in re.findall(r"check used (\d+) gas", f.read()))
        s = int(sim("inspect", "slot"))
        applied = sum(1 for l in out.splitlines() if l.endswith(": applied"))
        st = stats.setdefault(s, [0] * 6)
        st[0] += len(items)
        st[1] += gas
        st[2] += applied
        st[3] += 50_000 * applied
        st[4] += len(extrinsics)
        st[5] += sum(map(len, extrinsics))
        print(f"fake-node: slot {s}: {len(items)} items, {applied} applied, check gas {gas}", flush=True)


def statistics(s):
    out = bytes(2 * 24 * VALIDATORS)
    out += b"".join(natural(random.randint(0, 99)) for _ in range(PARAMS["core_count"] * 8))
    svcs = {0: [1] * 10}
    if s in stats:
        r, rg, a, ag, xc, xs = stats[s]
        svcs[SERVICE] = [0, 0, r, rg, 0, xc, xs, 0, a, ag]
    out += natural(len(svcs))
    for sid in sorted(svcs):
        out += sid.to_bytes(4, "little") + b"".join(natural(v) for v in svcs[sid])
    return out


def call(method, params):
    if method == "parameters":
        return {"V1": PARAMS}
    if method in ("bestBlock", "finalizedBlock"):
        return block(slot)
    if method == "parent":
        s = int.from_bytes(base64.b64decode(params[0])[:4], "little")
        return block(s - 1) if s > 0 else None
    if method in ("stateRoot", "beefyRoot"):
        return b64(bytes(32))
    if method == "serviceData":
        return b64(bytes(1) + hashlib.blake2b(b"witness", digest_size=32).digest() + bytes(64)) if params[1] == SERVICE else None
    if method == "serviceValue":
        with lock:
            v = sim("inspect", "storage", "--raw", str(params[1]), "0x" + base64.b64decode(params[2]).hex())
        return b64(bytes.fromhex(v[2:])) if v.startswith("0x") else None
    if method == "statistics":
        return b64(statistics(int.from_bytes(base64.b64decode(params[0])[:4], "little")))
    if method == "submitWorkPackage":
        pkg = base64.b64decode(params[1])
        xs = [base64.b64decode(x) for x in params[2]]
        if random.random() < DROP:
            print(f"fake-node: dropping a package of {len(pkg)} B", flush=True)
        else:
            threading.Thread(target=land, args=(pkg, xs), daemon=True).start()
        return None
    raise KeyError(method)


def frame(text):
    data = text.encode()
    n = len(data)
    if n < 126:
        head = bytes([0x81, n])
    elif n < 1 << 16:
        head = bytes([0x81, 126]) + struct.pack(">H", n)
    else:
        head = bytes([0x81, 127]) + struct.pack(">Q", n)
    return head + data


def serve(conn):
    buf = b""
    def need(k):
        nonlocal buf
        while len(buf) < k:
            chunk = conn.recv(1 << 20)
            if not chunk:
                raise EOFError
            buf += chunk
    try:
        while b"\r\n\r\n" not in buf:
            need(len(buf) + 1)
        head, buf = buf.split(b"\r\n\r\n", 1)
        key = re.search(rb"Sec-WebSocket-Key: (\S+)", head).group(1)
        accept = b64(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        conn.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     f"Sec-WebSocket-Accept: {accept}\r\n\r\n".encode())
        while True:
            need(2)
            opcode, n, off = buf[0] & 0x0F, buf[1] & 0x7F, 2
            if n == 126:
                need(4)
                n, off = struct.unpack(">H", buf[2:4])[0], 4
            elif n == 127:
                need(10)
                n, off = struct.unpack(">Q", buf[2:10])[0], 10
            need(off + 4 + n)
            mask = buf[off:off + 4]
            data = buf[off + 4:off + 4 + n]
            buf = buf[off + 4 + n:]
            if opcode == 0x8:
                return
            key = (mask * (n // 4 + 1))[:n]
            text = (int.from_bytes(data, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big") if n else b""
            req = json.loads(text)
            try:
                reply = {"jsonrpc": "2.0", "id": req["id"], "result": call(req["method"], req.get("params", []))}
            except Exception as e:  # noqa: BLE001
                reply = {"jsonrpc": "2.0", "id": req["id"], "error": {"code": -1, "message": repr(e)}}
            conn.sendall(frame(json.dumps(reply)))
    except EOFError:
        pass
    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) not in (4, 5):
        sys.exit(__doc__)
    PORT, SIM, SERVICE = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    DROP = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
    threading.Thread(target=ticker, daemon=True).start()
    srv = socket.create_server(("127.0.0.1", PORT))
    print(f"fake-node: listening on {PORT}", flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
