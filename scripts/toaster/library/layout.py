#!/usr/bin/env python3
"""Lay out a library planned on top of an attested one (plan.py) for scripts/attest-batches.py,
heavy declarations as witness-lean's judgment ops.

    layout.py NODES TRACED HEAVY BASE PINS GAS_PER_MS WORK

NODES is the export's `lean-host convert` directory, TRACED the plan after `lean-host trace` (each
batch trusting only what the kernel looks up), HEAVY a directory holding, for each declaration too
slow for a batch alone, HEAVY/HASH/ops.json (witness-lean's mathlib_work.py heavy_job: its
judgment ops, each with the nodes and earlier ops it trusts, and the theorem's own `final`). BASE is
the attested library under it, as a directory of its claims (lib-N.claim) next to its index
(BASE.json, build.py's). PINS is witness-lean's check/pins.txt.

Writes, in WORK, attest-batches.py's layout with paths relative to WORK (run it there; WORK/base
links to BASE, WORK/nodes to NODES, WORK/heavy to HEAVY, so each argument stays short):
batch-N.subjects, batch-N.trust (`batch-M.claim:E` for this library's, `base/lib-M.claim:E` for
BASE's), batch-N.witness, batch-N.gas; and layout.json, what each batch is: `batch` (nodes and
their proofs), `op` (judgments of a heavy declaration) or `final` (the heavy declaration itself,
citing its judgments). Every heavy op also trusts the check's pinned nodes (BASE holds them),
as mathlib_work.py has it: nanoda takes its literal shortcuts only if they're loaded. A batch of
more than MAX_SUBJECTS subjects is split (each part keeps the batch's trust), and the run stops if
any argument would be over 120 KB. Prints the number of batches.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attestations"))
from build import pack  # noqa: E402

MAX_WITNESS = 60000  # under witness's MAX_WITNESS_LEN of 64 KiB, as lean_batches.py
MAX_SUBJECTS = 800
MAX_ARG = 120_000
OP_GAS = 4_000_000_000  # a heavy op's or final's estimate, as mathlib_work.py prices them


def link(src, dst):
    if os.path.islink(dst):
        os.remove(dst)
    os.symlink(os.path.abspath(src), dst)


def main(nodes, traced, heavy, base, pins, gas_per_ms, work):
    gas_per_ms = float(gas_per_ms)
    os.makedirs(work, exist_ok=True)
    link(nodes, f"{work}/nodes")
    link(heavy, f"{work}/heavy")
    link(base, f"{work}/base")
    base_index = json.load(open(f"{base}.json"))["nodes"]
    by = {e["hash"]: e for e in json.load(open(f"{nodes}/manifest.json"))}
    pinned = [l.split()[0] for l in open(pins) if l.strip() and not l.startswith("#")]
    pinned = [h for h in pinned if h in base_index]
    plan = json.load(open(traced))
    heavy_nodes = {h for h in os.listdir(heavy) if os.path.exists(f"{heavy}/{h}/ops.json")}
    heavy_nodes &= {b["subjects"][0] for b in plan if len(b.get("subjects", [])) == 1}

    # Batches of nodes first, split where over MAX_SUBJECTS, then each heavy node's ops.
    entries = []
    for b in plan:
        s = b["subjects"]
        if len(s) == 1 and s[0] in heavy_nodes:
            entries.append({"kind": "final", "node": s[0]})
            continue
        for i in range(0, len(s), MAX_SUBJECTS):
            entries.append({"kind": "batch", "subjects": s[i:i + MAX_SUBJECTS], "trusted": b["trusted"],
                            "gas": int(b.get("ms", 0) * gas_per_ms * len(s[i:i + MAX_SUBJECTS]) / len(s))})
    home = {}
    for n, e in enumerate(entries):
        for i, h in enumerate(e["subjects"] if e["kind"] == "batch" else [e["node"]]):
            home[h] = f"batch-{n}.claim:{i}"
    for h in sorted(heavy_nodes - set(home)):
        sys.exit(f"heavy node {h} isn't in the plan")
    ops = []  # (heavy node, op) in order, numbered after the batches
    op_number = {}
    for e in entries:
        if e["kind"] == "final":
            o = json.load(open(f"{heavy}/{e['node']}/ops.json"))
            for op in o["ops"]:
                op_number[(e["node"], op["name"])] = len(entries) + len(ops)
                ops.append((e["node"], op))
            e["ops"] = o

    def node_ref(h):
        if h in home:
            return home[h]
        if h in base_index:
            n, i = base_index[h]
            return f"base/lib-{n}.claim:{i}"
        sys.exit(f"{by[h]['names'][0]} is trusted but neither attested below nor in this library")

    def op_refs(node, trust_ops):
        out = []
        for r in trust_ops:
            name, k = (r, 0) if isinstance(r, str) else (r[0], r[1])
            out.append(f"batch-{op_number[(node, name)]}.claim:{k}")
        return out

    def write(n, subjects, refs, proofs, gas):
        items = [open(f"{work}/{p}", "rb").read() for p in proofs]
        if len(pack(items)) > MAX_WITNESS:
            subjects, items = subjects + proofs, []
        subj, trust = ",".join(subjects), ",".join(refs)
        for what, v in (("subjects", subj), ("trust", trust)):
            if len(v) > MAX_ARG:
                sys.exit(f"batch {n}'s {what} is {len(v)} bytes, over {MAX_ARG} for one argument")
        open(f"{work}/batch-{n}.subjects", "w").write(subj)
        open(f"{work}/batch-{n}.trust", "w").write(trust)
        open(f"{work}/batch-{n}.witness", "wb").write(pack(items))
        open(f"{work}/batch-{n}.gas", "w").write(str(int(gas)))

    proof_of = lambda h: [f"nodes/proofs/{h}"] if os.path.exists(f"{nodes}/proofs/{h}") else []
    layout = []
    for n, e in enumerate(entries):
        if e["kind"] == "batch":
            write(n, [f"nodes/nodes/{h}" for h in e["subjects"]], [node_ref(h) for h in e["trusted"]],
                  [p for h in e["subjects"] for p in proof_of(h)], e["gas"] or OP_GAS)
            layout.append({"batch": n, "kind": "batch", "nodes": e["subjects"]})
        else:
            h, f = e["node"], e["ops"]["final"]
            refs = [node_ref(x) for x in sorted(set(f["trust_nodes"]) | set(pinned))] + op_refs(h, f["trust_ops"])
            write(n, [f"nodes/nodes/{h}"], refs, proof_of(h), OP_GAS)
            layout.append({"batch": n, "kind": "final", "nodes": [h], "ops": len(e["ops"]["ops"])})
    for k, (h, op) in enumerate(ops):
        n = len(entries) + k
        subjects = op["subjects"] if "subjects" in op else [op["subject"]]
        refs = [node_ref(x) for x in sorted(set(op["trust_nodes"]) | set(pinned))] + op_refs(h, op["trust_ops"])
        subj = ",".join(f"heavy/{h}/{s}" for s in subjects)
        trust = ",".join(refs)
        if len(subj) > MAX_ARG or len(trust) > MAX_ARG:
            sys.exit(f"heavy op {n} has an argument over {MAX_ARG} bytes")
        open(f"{work}/batch-{n}.subjects", "w").write(subj)
        open(f"{work}/batch-{n}.trust", "w").write(trust)
        open(f"{work}/batch-{n}.witness", "wb").write(open(f"{heavy}/{h}/{op['witness']}", "rb").read())
        open(f"{work}/batch-{n}.gas", "w").write(str(OP_GAS))
        layout.append({"batch": n, "kind": "op", "node": h, "name": op["name"]})
    json.dump(layout, open(f"{work}/layout.json", "w"))
    print(len(layout))


if __name__ == "__main__":
    if len(sys.argv) != 8:
        sys.exit(__doc__)
    main(*sys.argv[1:])
