#!/usr/bin/env python3
"""Convert a lean4export NDJSON export (or a delta from lean_delta.py) to the binary format.

    lean_bin.py IN.ndjson > OUT.bin

The format is described in binary_format.md. In short: an 8-byte magic, then one item after
another, each a tag byte followed by its fields in a fixed order. Integers are unsigned LEB128,
strings and byte strings are length-prefixed, and big number literals are little-endian bytes.
Name, level and expression items carry no index: each one's index is its position among the items
of its kind, so the input must number them consecutively, which lean4export and lean_delta.py do.
"""

import json
import sys

MAGIC = b"LEANBIN\x01"
BINDERS = {"default": 0, "implicit": 1, "strictImplicit": 2, "instImplicit": 3}
SAFETY = {"safe": 0, "unsafe": 1, "partial": 2}
QUOT = {"type": 0, "ctor": 1, "lift": 2, "ind": 3}


class Writer:
    def __init__(self):
        self.out = bytearray(MAGIC)

    def byte(self, b):
        self.out.append(b)

    def uvar(self, n):
        if n < 0:
            raise ValueError(f"negative integer {n}")
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                self.out.append(b | 0x80)
            else:
                self.out.append(b)
                return

    def boolean(self, b):
        self.byte(1 if b else 0)

    def raw(self, data):
        self.uvar(len(data))
        self.out += data

    def string(self, s):
        self.raw(s.encode())

    def ints(self, xs):
        self.uvar(len(xs))
        for x in xs:
            self.uvar(x)


def encode(lines):
    w = Writer()
    # Each kind's indices must be consecutive, since the binary format leaves them implicit.
    last = {}

    def indexed(kind, line):
        i = line[kind]
        if kind in last and i != last[kind] + 1:
            raise ValueError(f"{kind} index {i} does not follow {last[kind]}")
        last[kind] = i

    for line in lines:
        for kind in ("in", "il", "ie"):
            if kind in line:
                indexed(kind, line)
        if "meta" in line:
            m = line["meta"]
            w.byte(0)
            w.string(m["exporter"]["name"]); w.string(m["exporter"]["version"])
            w.string(m["lean"]["githash"]); w.string(m["lean"]["version"])
            w.string(m["format"]["version"])
        elif "str" in line and "in" in line:
            w.byte(1); w.uvar(line["str"]["pre"]); w.string(line["str"]["str"])
        elif "num" in line:
            w.byte(2); w.uvar(line["num"]["pre"]); w.uvar(line["num"]["i"])
        elif "succ" in line:
            w.byte(3); w.uvar(line["succ"])
        elif "max" in line:
            w.byte(4); w.uvar(line["max"][0]); w.uvar(line["max"][1])
        elif "imax" in line:
            w.byte(5); w.uvar(line["imax"][0]); w.uvar(line["imax"][1])
        elif "param" in line:
            w.byte(6); w.uvar(line["param"])
        elif "natVal" in line:
            n = int(line["natVal"])
            w.byte(7); w.raw(n.to_bytes((n.bit_length() + 7) // 8, "little"))
        elif "strVal" in line:
            w.byte(8); w.string(line["strVal"])
        elif "letE" in line:
            e = line["letE"]
            w.byte(9); w.uvar(e["name"]); w.uvar(e["type"]); w.uvar(e["value"]); w.uvar(e["body"]); w.boolean(e["nondep"])
        elif "const" in line:
            w.byte(10); w.uvar(line["const"]["name"]); w.ints(line["const"]["us"])
        elif "app" in line:
            w.byte(11); w.uvar(line["app"]["fn"]); w.uvar(line["app"]["arg"])
        elif "forallE" in line or "lam" in line:
            tag, e = (12, line["forallE"]) if "forallE" in line else (13, line["lam"])
            w.byte(tag); w.uvar(e["name"]); w.uvar(e["type"]); w.uvar(e["body"]); w.byte(BINDERS[e["binderInfo"]])
        elif "proj" in line:
            e = line["proj"]
            w.byte(14); w.uvar(e["typeName"]); w.uvar(e["idx"]); w.uvar(e["struct"])
        elif "sort" in line:
            w.byte(15); w.uvar(line["sort"])
        elif "bvar" in line:
            w.byte(16); w.uvar(line["bvar"])
        elif "mdata" in line:
            raise ValueError("mdata is not supported (lean4export omits it unless asked)")
        elif "axiom" in line:
            d = line["axiom"]
            w.byte(17); w.uvar(d["name"]); w.ints(d["levelParams"]); w.uvar(d["type"]); w.boolean(d["isUnsafe"])
        elif "thm" in line:
            d = line["thm"]
            w.byte(18); w.uvar(d["name"]); w.ints(d["levelParams"]); w.uvar(d["type"]); w.uvar(d["value"])
        elif "def" in line:
            d = line["def"]
            w.byte(19); w.uvar(d["name"]); w.ints(d["levelParams"]); w.uvar(d["type"]); w.uvar(d["value"])
            hints = d["hints"]
            if hints == "opaque":
                w.byte(0)
            elif hints == "abbrev":
                w.byte(1)
            else:
                w.byte(2); w.uvar(hints["regular"])
            w.byte(SAFETY[d["safety"]])
        elif "opaque" in line:
            d = line["opaque"]
            w.byte(20); w.uvar(d["name"]); w.ints(d["levelParams"]); w.uvar(d["type"]); w.uvar(d["value"]); w.boolean(d["isUnsafe"])
        elif "quot" in line:
            d = line["quot"]
            w.byte(21); w.uvar(d["name"]); w.ints(d["levelParams"]); w.uvar(d["type"]); w.byte(QUOT[d["kind"]])
        elif "inductive" in line:
            d = line["inductive"]
            w.byte(22)
            w.uvar(len(d["types"]))
            for t in d["types"]:
                w.uvar(t["name"]); w.ints(t["levelParams"]); w.uvar(t["type"]); w.ints(t["all"]); w.ints(t["ctors"])
                w.boolean(t["isRec"]); w.boolean(t["isReflexive"])
                w.uvar(t["numIndices"]); w.uvar(t["numNested"]); w.uvar(t["numParams"]); w.boolean(t["isUnsafe"])
            w.uvar(len(d["ctors"]))
            for c in d["ctors"]:
                w.uvar(c["name"]); w.ints(c["levelParams"]); w.uvar(c["type"]); w.boolean(c["isUnsafe"])
                w.uvar(c["cidx"]); w.uvar(c["numParams"]); w.uvar(c["numFields"]); w.uvar(c["induct"])
            w.uvar(len(d["recs"]))
            for r in d["recs"]:
                w.uvar(r["name"]); w.ints(r["levelParams"]); w.uvar(r["type"]); w.boolean(r["isUnsafe"])
                w.uvar(r["numParams"]); w.uvar(r["numIndices"]); w.uvar(r["numMotives"]); w.uvar(r["numMinors"])
                w.uvar(len(r["rules"]))
                for rule in r["rules"]:
                    w.uvar(rule["ctor"]); w.uvar(rule["nfields"]); w.uvar(rule["rhs"])
                w.ints(r["all"]); w.boolean(r["k"])
        else:
            raise ValueError(f"unknown export item: {json.dumps(line)[:100]}")
    return bytes(w.out)


def main(path):
    with open(path) as f:
        lines = [json.loads(l) for l in f if l.strip()]
    sys.stdout.buffer.write(encode(lines))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
