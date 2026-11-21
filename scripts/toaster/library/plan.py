#!/usr/bin/env python3
"""Plan attesting a library on top of one already attested (a release's, scripts/toaster/
attestations/), for scripts/toaster/library/build.sh.

    plan.py set NODES REL BASE ROOTS OUT_SET      the new library: every node ROOTS' proofs reach
                                                  that BASE (a library of the release REL) doesn't hold
    plan.py batches NODES OUT_SET OUT_PLAN        its batches, by dependency depth, as lean_plan.py
                                                  plans (each trusts what it and its proofs import,
                                                  recursively, outside it)

NODES is a `lean-host convert` directory of an export holding ROOTS (a file, one name a line) and
everything they use. A batch's trusted nodes are either the base library's or earlier batches'.
"""
import json
import os
import sys

MAX_PROOF_BYTES = 36000  # lean_plan.py's: a batch's witness stays under witness's 64 KiB


def load(nodes):
    m = json.load(open(f"{nodes}/manifest.json"))
    return m, {e["hash"]: e for e in m}, {e["hash"]: i for i, e in enumerate(m)}


def cmd_set(nodes, rel, base, roots, out):
    m, by, order = load(nodes)
    attested = set(json.load(open(f"{rel}/{base}.json"))["nodes"])
    names = [l.strip() for l in open(roots) if l.strip()]
    by_name = {n: e["hash"] for e in m for n in e["names"]}
    missing = [n for n in names if n not in by_name]
    if missing:
        sys.exit(f"not in the export: {missing[:5]}")
    seen, todo = set(), [by_name[n] for n in names]
    while todo:
        h = todo.pop()
        if h in seen or h in attested:
            continue
        seen.add(h)
        todo += by[h]["imports"] + by[h].get("proof_imports", [])
    if any("sorryAx" in by[h]["names"] for h in seen):
        sys.exit("sorryAx in the set")
    size = lambda d: sum(os.path.getsize(f"{nodes}/{d}/{h}") for h in seen if os.path.exists(f"{nodes}/{d}/{h}"))
    s = sorted(seen, key=order.get)
    json.dump({"base": base, "roots": names, "nodes": s}, open(out, "w"))
    print(f"{len(s)} nodes outside {base}: {size('nodes'):,} B of statements, {size('proofs'):,} B of proofs")


def cmd_batches(nodes, set_path, out):
    m, by, order = load(nodes)
    todo = json.load(open(set_path))["nodes"]
    mine = set(todo)
    depth = {}
    for h in todo:
        e = by[h]
        depth[h] = 1 + max((depth[d] for d in e["imports"] + e.get("proof_imports", []) if d in depth), default=-1)
    memo = {}

    def closure(h):
        if h not in memo:
            out, stack = set(), [h]
            while stack:
                x = stack.pop()
                if x not in out:
                    out.add(x)
                    stack += by[x]["imports"]
            memo[h] = frozenset(out)
        return memo[h]

    plan = []
    for level in range(max(depth.values()) + 1):
        current, size = [], 0
        for h in (h for h in todo if depth[h] == level):
            s = by[h].get("proof_size", 0)
            if current and size + s > MAX_PROOF_BYTES:
                plan.append((level, current))
                current, size = [], 0
            current.append(h)
            size += s
        if current:
            plan.append((level, current))
    batches = []
    for level, subjects in plan:
        need = set()
        for h in subjects:
            for i in by[h]["imports"] + by[h].get("proof_imports", []):
                need |= closure(i)
        batches.append({"depth": level, "subjects": subjects, "trusted": sorted(need - set(subjects), key=order.get)})
    json.dump(batches, open(out, "w"))
    print(f"{len(batches)} batches over {max(depth.values()) + 1} depths ({len(mine)} nodes)")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["set"] and len(a) == 6:
        cmd_set(*a[1:])
    elif a[:1] == ["batches"] and len(a) == 4:
        cmd_batches(*a[1:])
    else:
        sys.exit(__doc__)
