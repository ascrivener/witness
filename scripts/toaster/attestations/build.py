#!/usr/bin/env python3
"""Build the release assets for a library attested on the JAM Toaster, from the work directory of
the run that attested it (the run's artifact, `lean-work.tgz`, unpacked).

    build.py library LIBRARIES_JSON NAME WORK OUT WITNESS_CLI
    build.py manifest LIBRARIES_JSON OUT

`library` writes, in OUT:

- NAME-claims.tar.gz: NAME/lib-N.claim, the claim file `witness attest --claim-out` wrote for batch
  N (the attestation's claim and its subjects). A reveal trusts an attested node by giving
  `--trust NAME/lib-N.claim:ENTRY`; a bounty's cited blob is one too. (`lib-`, not `batch-`:
  scripts/attest-batches.py reads `batch-M.claim` in a trust reference as one of its own batches.)
- NAME.json: the library. Its commits (jam-lean, witness-lean, lean4export), the check's hash, the
  goal it was attested for and the attestation that goal's bounty cites; every batch, in order,
  with its claim file, attestation id, subjects (`n:HASH` a node, `p:HASH` a proof carried as a
  subject), the proofs packed in its witness, the batches and entries it trusted, and the sha256
  of its witness; and `nodes`, every attested node's hash to [batch, entry]. With these and an
  export of the same nodes, the batches can be rebuilt byte for byte (scripts/toaster/hunt/
  library.py `replay`), so the claims can be checked, or attested again in witness-sim.
- lean-check.jam: the check the claims name, once (every library must have the same one).

Every claim's subjects are checked against the work's nodes (a node's hash is the blake2b-256 of
its bytes), and every witness against its proofs, before anything is written.

`manifest` writes OUT/manifest.json: per library, its commits, check hash, attestation ids, and
the sha256 and size of each of its files. Everything here is deterministic (the tarballs carry no
times or owners), so anyone can rebuild the release from the runs' artifacts and compare.
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


def blake2b(data):
    return hashlib.blake2b(data, digest_size=32).digest()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def natural(b, i):
    """The Gray Paper's variable-length natural (jam-codec's lengths), at b[i]: (value, next i)."""
    first = b[i]
    if first == 0xFF:
        return int.from_bytes(b[i + 1:i + 9], "little"), i + 9
    n = 0
    while first & (0x80 >> n):
        n += 1
    rest = int.from_bytes(b[i + 1:i + 1 + n], "little")
    top = first & ((1 << (8 - n)) - 1) if n < 8 else 0
    return rest + (top << (8 * n)), i + 1 + n


def read_claim(path):
    """A claim file: (AttestationClaim's 132 bytes, its subjects)."""
    b = open(path, "rb").read()
    claim, i = b[:132], 132
    count, i = natural(b, i)
    subjects = []
    for _ in range(count):
        n, i = natural(b, i)
        subjects.append(b[i:i + n])
        i += n
    if i != len(b):
        raise ValueError(f"{path}: {len(b) - i} trailing bytes")
    if int.from_bytes(claim[96:100], "little") != count:
        raise ValueError(f"{path}: the claim's subject count isn't its subjects'")
    return claim, subjects


def uvar(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def pack(items):
    """witness-lean's lean_pack.pack: a count, then each item's length and bytes (LEB128)."""
    return uvar(len(items)) + b"".join(uvar(len(i)) + i for i in items)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def library(conf_path, name, work, out, w):
    conf = json.load(open(conf_path))
    lib = next(l for l in conf["libraries"] if l["name"] == name)
    os.makedirs(f"{out}/{name}", exist_ok=True)
    manifest = {e["hash"]: e for e in json.load(open(f"{work}/nodes/manifest.json"))}
    plan = json.load(open(f"{work}/plan.json"))
    goal = next(b for b in plan if "goal" in b)
    assert plan[-1] is goal, "the goal must be the plan's last entry"
    batches = [b for b in plan if "subjects" in b]
    count = len([f for f in os.listdir(f"{work}/w") if re.fullmatch(r"batch-\d+\.claim", f)])
    assert count == len(batches), f"{count} claims for {len(batches)} batches"
    check = f"{work}/lean-check.jam"
    check_hash = run(w, "hash", "--check", check)
    if os.path.exists(f"{out}/lean-check.jam"):
        assert open(check, "rb").read() == open(f"{out}/lean-check.jam", "rb").read(), "another check"
    else:
        shutil.copy(check, f"{out}/lean-check.jam")
    goal_hash = open(f"{work}/w/goal.hash").read().strip()
    assert goal_hash == goal["goal"] and lib["goal"] in manifest[goal_hash]["names"], "the goal isn't the library's"

    nodes, out_batches = {}, []
    for n, b in enumerate(batches):
        claim_path = f"{work}/w/batch-{n}.claim"
        claim, subjects = read_claim(claim_path)
        assert claim[:32].hex() == check_hash.removeprefix("0x"), f"batch {n}: another check"
        paths = open(f"{work}/w/batch-{n}.subjects").read().strip().split(",")
        assert len(paths) == len(subjects), f"batch {n}: {len(paths)} paths, {len(subjects)} subjects"
        listed = []
        for e, (p, data) in enumerate(zip(paths, subjects)):
            kind, h = p.split("/")[-2], p.split("/")[-1]
            assert kind in ("nodes", "proofs"), p
            assert open(f"{work}/nodes/{kind}/{h}", "rb").read() == data, f"batch {n} entry {e}: not {p}"
            if kind == "nodes":
                assert blake2b(data).hex() == h, f"batch {n} entry {e}: hash"
                nodes.setdefault(h, [n, e])
                listed.append(f"n:{h}")
            else:
                listed.append(f"p:{h}")
        node_subjects = [s[2:] for s in listed if s.startswith("n:")]
        assert node_subjects == b["subjects"], f"batch {n}: not the plan's subjects"
        bundled = any(s.startswith("p:") for s in listed)
        proven = [] if bundled else [h for h in node_subjects if os.path.exists(f"{work}/nodes/proofs/{h}")]
        witness = open(f"{work}/w/batch-{n}.witness", "rb").read()
        assert pack([open(f"{work}/nodes/proofs/{h}", "rb").read() for h in proven]) == witness, f"batch {n}: witness"
        trust_text = open(f"{work}/w/batch-{n}.trust").read().strip()
        trust = [[int(m), int(e)] for m, e in re.findall(r"batch-(\d+)\.claim:(\d+)", trust_text)]
        assert len(trust) == (trust_text.count(",") + 1 if trust_text else 0), f"batch {n}: a trust reference isn't batch-M.claim:E"
        attestation = run(w, "claim-id", "--claim", claim_path)
        shutil.copy(claim_path, f"{out}/{name}/lib-{n}.claim")
        out_batches.append({"claim": f"lib-{n}.claim", "attestation": attestation, "depth": b.get("depth"),
                            "subjects": listed, "witness": proven, "witness_sha256": hashlib.sha256(witness).hexdigest(),
                            "trust": trust})
    cite_text = open(f"{work}/w/goal.cite").read().strip()
    cm, ce = map(int, re.fullmatch(r".*batch-(\d+)\.claim:(\d+)", cite_text).groups())
    cite_node = out_batches[cm]["subjects"][ce][2:]
    assert cite_node in manifest[goal_hash]["imports"], "the cited node isn't one the goal imports"
    doc = {
        "format": 1, "library": name, "about": lib["about"], "service": conf["service"],
        "run": lib["run"], "same_as_runs": lib["same_as_runs"], "attest_slots": lib["attest_slots"],
        "jam_lean": lib["jam_lean"], "witness_lean": lib["witness_lean"], "lean4export": lib["lean4export"],
        "lean_toolchain": lib["lean_toolchain"], "module": lib["module"],
        "check_hash": check_hash, "check_sha256": sha256(check), "check_bytes": os.path.getsize(check),
        "goal": {"theorem": lib["goal"], "node": goal_hash, "statement": lib.get("statement"), "bounties": lib["bounties"]},
        "cite": {"claim": f"lib-{cm}.claim", "entry": ce, "node": cite_node, "attestation": out_batches[cm]["attestation"]},
        "claims": f"{name}-claims.tar.gz",
        "batch_count": len(out_batches), "node_count": len(nodes),
        "batches": out_batches, "nodes": nodes,
    }
    json.dump(doc, open(f"{out}/{name}.json", "w"), indent=0, sort_keys=False)
    # Deterministic: no times or owners, so the same work gives the same bytes.
    with open(f"{out}/{name}-claims.tar.gz", "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for n in range(len(out_batches)):
            data = open(f"{out}/{name}/lib-{n}.claim", "rb").read()
            info = tarfile.TarInfo(f"{name}/lib-{n}.claim")
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            t.addfile(info, io.BytesIO(data))
    print(f"{name}: {len(out_batches)} batches, {len(nodes)} nodes; the bounty cites {doc['cite']['claim']}:{ce} "
          f"({doc['cite']['attestation']}); check {check_hash}")


def manifest(conf_path, out):
    conf = json.load(open(conf_path))
    libs = []
    for lib in conf["libraries"]:
        doc = json.load(open(f"{out}/{lib['name']}.json"))
        files = [f"{lib['name']}.json", doc["claims"], "lean-check.jam"]
        libs.append({
            "library": lib["name"], "about": lib["about"], "doc": lib["doc"],
            "jam_lean": doc["jam_lean"], "witness_lean": doc["witness_lean"], "lean4export": doc["lean4export"],
            "lean_toolchain": doc["lean_toolchain"], "module": doc["module"],
            "check_hash": doc["check_hash"], "goal": doc["goal"], "cite": doc["cite"],
            "run": doc["run"], "same_as_runs": doc["same_as_runs"], "attest_slots": doc["attest_slots"],
            "batch_count": doc["batch_count"], "node_count": doc["node_count"],
            "attestations": [b["attestation"] for b in doc["batches"]],
            "files": {f: {"sha256": sha256(f"{out}/{f}"), "bytes": os.path.getsize(f"{out}/{f}")} for f in files},
        })
    m = {"format": 1, "release": conf["release"], "service": conf["service"],
         "repo": "https://github.com/ascrivener/witness", "libraries": libs}
    json.dump(m, open(f"{out}/manifest.json", "w"), indent=1)
    print(f"manifest.json: {', '.join(f'{l['library']} ({l['batch_count']} attestations)' for l in libs)}")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["library"] and len(a) == 6:
        library(*a[1:])
    elif a[:1] == ["manifest"] and len(a) == 3:
        manifest(*a[1:])
    else:
        sys.exit(__doc__)
