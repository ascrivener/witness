#!/usr/bin/env python3
"""Release assets for a library attested on top of another (scripts/toaster/library/build.sh), in
the format scripts/toaster/attestations/build.py writes for the others.

    release.py LIBRARIES_JSON NAME WORK OUT WITNESS_CLI

WORK is build.sh's work directory (its w/batch-N.claim from the live run, w/layout.json, set.json,
nodes/). Writes OUT/NAME-claims.tar.gz (NAME/lib-N.claim, deterministic) and OUT/NAME.json: as a
library's, with `base` (the library it rests on), no goal or cite, and every batch's `kind`
(`batch`, `op`: a heavy declaration's judgments, `final`: the declaration citing them), its
subjects (`n:HASH` a node, `p:HASH` a proof, `j:SHA256` a judgment blob) and what it trusted
(`[batch, entry]` here, `[BASE, batch, entry]` in the base). `nodes` maps each node attested here
to [batch, entry]. Every claim's subjects are checked against the files they came from.
"""
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attestations"))
from build import blake2b, read_claim, sha256  # noqa: E402


def subject_path(work, p):
    """A batch's subject path (relative to WORK/w). layout.py links WORK/w/nodes and WORK/w/heavy to
    WORK/nodes and WORK/heavy by absolute path, which dangles once the work is unpacked elsewhere
    (the release workflow): read those from WORK itself."""
    top = p.split("/", 1)[0]
    return f"{work}/{p}" if top in ("nodes", "heavy") else f"{work}/w/{p}"


def main(conf_path, name, work, out, w):
    conf = json.load(open(conf_path))
    lib = next(l for l in conf["libraries"] if l["name"] == name)
    base = lib["base"]
    os.makedirs(f"{out}/{name}", exist_ok=True)
    layout = json.load(open(f"{work}/w/layout.json"))
    s = json.load(open(f"{work}/set.json"))
    check = f"{out}/lean-check.jam"  # the base library's, written there by build.py first
    assert os.path.exists(check), f"no {check}: build the base library's assets first"
    check_hash = subprocess.run([w, "hash", "--check", check], check=True, capture_output=True, text=True).stdout.strip()
    nodes, batches = {}, []
    for n, e in enumerate(layout):
        assert e["batch"] == n
        claim_path = f"{work}/w/batch-{n}.claim"
        claim, subjects = read_claim(claim_path)
        assert claim[:32].hex() == check_hash.removeprefix("0x"), f"batch {n}: another check"
        paths = open(f"{work}/w/batch-{n}.subjects").read().strip().split(",")
        assert len(paths) == len(subjects), f"batch {n}: {len(paths)} paths, {len(subjects)} subjects"
        listed = []
        for i, (p, data) in enumerate(zip(paths, subjects)):
            assert open(subject_path(work, p), "rb").read() == data, f"batch {n} entry {i}: not {p}"
            if p.startswith("nodes/nodes/"):
                h = p.rsplit("/", 1)[1]
                assert blake2b(data).hex() == h, f"batch {n} entry {i}: hash"
                nodes.setdefault(h, [n, i])
                listed.append(f"n:{h}")
            elif p.startswith("nodes/proofs/"):
                listed.append(f"p:{p.rsplit('/', 1)[1]}")
            else:
                listed.append(f"j:{hashlib.sha256(data).hexdigest()}")
        trust = []
        for r in filter(None, open(f"{work}/w/batch-{n}.trust").read().strip().split(",")):
            m = re.fullmatch(r"batch-(\d+)\.claim:(\d+)", r) or re.fullmatch(r"base/lib-(\d+)\.claim:(\d+)", r)
            assert m, f"batch {n}: trust reference {r}"
            trust.append([int(m[1]), int(m[2])] if r.startswith("batch-") else [base, int(m[1]), int(m[2])])
        witness = open(f"{work}/w/batch-{n}.witness", "rb").read()
        attestation = subprocess.run([w, "claim-id", "--claim", claim_path], check=True, capture_output=True, text=True).stdout.strip()
        shutil.copy(claim_path, f"{out}/{name}/lib-{n}.claim")
        batches.append({"claim": f"lib-{n}.claim", "attestation": attestation, "kind": e["kind"], "subjects": listed,
                        "witness_sha256": hashlib.sha256(witness).hexdigest(), "trust": trust})
    missing = [h for h in s["nodes"] if h not in nodes]
    assert not missing, f"{len(missing)} of the library's nodes aren't attested by any batch, e.g. {missing[:3]}"
    doc = {
        "format": 1, "library": name, "about": lib["about"], "service": conf["service"], "base": base,
        "run": lib["run"], "same_as_runs": lib["same_as_runs"], "attest_slots": lib["attest_slots"],
        "jam_lean": lib["jam_lean"], "witness_lean": lib["witness_lean"], "lean4export": lib["lean4export"],
        "lean_toolchain": lib["lean_toolchain"], "module": lib["module"], "roots": s["roots"],
        "check_hash": check_hash, "check_sha256": sha256(check), "check_bytes": os.path.getsize(check),
        "goal": None, "cite": None, "claims": f"{name}-claims.tar.gz",
        "batch_count": len(batches), "node_count": len(nodes), "batches": batches, "nodes": nodes,
    }
    json.dump(doc, open(f"{out}/{name}.json", "w"), indent=0)
    with open(f"{out}/{name}-claims.tar.gz", "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for n in range(len(batches)):
            data = open(f"{out}/{name}/lib-{n}.claim", "rb").read()
            info = tarfile.TarInfo(f"{name}/lib-{n}.claim")
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            t.addfile(info, io.BytesIO(data))
    print(f"{name}: {len(batches)} batches ({sum(b['kind'] == 'op' for b in batches)} judgment ops), "
          f"{len(nodes)} nodes, on {base}; check {check_hash}")


if __name__ == "__main__":
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    main(*sys.argv[1:])
