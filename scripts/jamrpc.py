"""A minimal JSON-RPC client for a JAM node (JIP-2), over a WebSocket, using only the standard
library. Shared by jam-storage.py and jam-submit.py."""

import base64
import json
import os
import socket
import struct
import sys
from urllib.parse import urlparse


def url():
    return os.environ.get("JAM_RPC", "ws://localhost:19800")


def b64(data):
    return base64.b64encode(data).decode()


def unb64(text):
    return base64.b64decode(text)


class Rpc:
    def __init__(self, url):
        u = urlparse(url)
        if u.scheme != "ws":
            sys.exit(f"jamrpc: only ws:// RPC URLs are supported, not {url}")
        host, port = u.hostname, u.port or 80
        self.sock = socket.create_connection((host, port))
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            f"GET {u.path or '/'} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            self.read()
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            sys.exit(f"jamrpc: WebSocket handshake failed: {head.splitlines()[0]!r}")
        self.id = 0

    def read(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            sys.exit("jamrpc: RPC connection closed")
        self.buf += chunk

    def need(self, n):
        while len(self.buf) < n:
            self.read()

    def send(self, text):
        data, mask = text.encode(), os.urandom(4)
        n = len(data)
        if n < 126:
            head = bytes([0x81, 0x80 | n])
        elif n < 1 << 16:
            head = bytes([0x81, 0x80 | 126]) + struct.pack(">H", n)
        else:
            head = bytes([0x81, 0x80 | 127]) + struct.pack(">Q", n)
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def message(self):
        out = b""
        while True:
            self.need(2)
            fin, opcode, n, off = self.buf[0] & 0x80, self.buf[0] & 0x0F, self.buf[1] & 0x7F, 2
            if n == 126:
                self.need(4)
                n, off = struct.unpack(">H", self.buf[2:4])[0], 4
            elif n == 127:
                self.need(10)
                n, off = struct.unpack(">Q", self.buf[2:10])[0], 10
            self.need(off + n)
            payload, self.buf = self.buf[off : off + n], self.buf[off + n :]
            if opcode in (0x9, 0xA):  # ping, pong: not part of the message
                continue
            out += payload
            if fin:
                return out.decode()

    def call(self, method, *params):
        self.id += 1
        self.send(json.dumps({"jsonrpc": "2.0", "id": self.id, "method": method, "params": list(params)}))
        while True:
            reply = json.loads(self.message())
            if reply.get("id") == self.id:
                break
        if "error" in reply:
            sys.exit(f"jamrpc: {method}: {reply['error']}")
        return reply["result"]
