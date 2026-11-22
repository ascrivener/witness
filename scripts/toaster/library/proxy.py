#!/usr/bin/env python3
"""The bounty-3 proxy reveal (docs/HUNTING.md, Limits): how a reveal of a proof like jam-lean's
`acc_log_lineK` (the success branch of the same code, 6501 … 6630) would look against the attested
libraries a hunter trusts.

    proxy.py SPEC REL NODES WORK THEOREM

SPEC is the bounty's spec (site/bounties/3.json, or one listing the libraries to trust), REL a
directory with their release files (hunt.py fetch), NODES the export of THEOREM converted by
`lean-host convert`. THEOREM is attested itself (it's a root of acclogfail-proofs), so this treats
its node and proof as the hunter's: the reveal carries them, and the walk counts what else its
proof reaches outside every library (with both libraries, expected none). Writes WORK/witness.pack,
WORK/reveal-plan.json (for `lean-host trace`), WORK/spec.json (SPEC with THEOREM's node as the
statement, for hunt.py trust and args) and WORK/proxy.json (the counts).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "hunt"))
import hunt  # noqa: E402


def main(spec_path, rel, nodes, work, theorem):
    spec = hunt.load(spec_path)
    os.makedirs(work, exist_ok=True)
    _, index = hunt.library_index(spec, rel)
    manifest, by_hash = hunt.nodes_manifest(nodes)
    goal = next((e for e in manifest if theorem in e["names"]), None)
    assert goal is not None and "proof_size" in goal, f"no {theorem} with a proof in {nodes}"
    g = goal["hash"]
    index.pop(g, None)  # carried, as a hunter's proof would be
    seen, todo = set(), [g]
    while todo:
        h = todo.pop()
        if h in seen or h in index:
            continue
        seen.add(h)
        todo += by_hash[h]["imports"] + by_hash[h].get("proof_imports", [])
    outside = sorted(seen - {g})
    closure = hunt.closure_fn(by_hash)
    trusted = sorted(hunt.needs(by_hash, closure, [g] + outside))
    missing = [h for h in trusted if h not in index]
    assert not missing, f"untrusted nodes outside the witness: {missing[:3]}"
    subjects = [g] + outside
    items = [open(f"{nodes}/nodes/{h}", "rb").read() for h in subjects]
    items += [open(f"{nodes}/proofs/{h}", "rb").read() for h in subjects if "proof_size" in by_hash[h]]
    w = hunt.pack(items)
    open(f"{work}/witness.pack", "wb").write(w)
    hunt.dump([{"depth": 0, "subjects": subjects, "trusted": trusted}], f"{work}/reveal-plan.json")
    # The reveal's first trusted blob is the bounty's cited node (its statement), which THEOREM's
    # export doesn't hold: take its bytes from the cited claim, as a real reveal's would be.
    cite = spec["cite"]
    _, cited = hunt.read_claim(f"{rel}/{spec['library']}/{cite['claim']}")
    node = cited[cite["entry"]]
    assert hunt.blake2b(node).hex() == cite["node"], "the cited claim's entry isn't the cited node"
    if not os.path.exists(f"{nodes}/nodes/{cite['node']}"):
        open(f"{nodes}/nodes/{cite['node']}", "wb").write(node)
    proxy_spec = {**spec, "statement": {**spec["statement"], "theorem": theorem, "node": g}}
    hunt.dump(proxy_spec, f"{work}/spec.json")
    size = lambda d: sum(os.path.getsize(f"{nodes}/{d}/{h}") for h in outside if os.path.exists(f"{nodes}/{d}/{h}"))
    r = {"theorem": theorem, "node": g, "libraries": spec.get("libraries") or [spec["library"]],
         "outside": len(outside), "outside_statement_bytes": size("nodes"), "outside_proof_bytes": size("proofs"),
         "carried": len(subjects), "witness_bytes": len(w), "untraced_trust": len(trusted)}
    hunt.dump(r, f"{work}/proxy.json")
    print(json.dumps(r))


if __name__ == "__main__":
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    main(*sys.argv[1:])
