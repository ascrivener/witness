#!/usr/bin/env python3
"""Helpers for scripts/toaster/hunt/hunt.sh: building a witness-lean reveal from a hunter's proof
and a release of attested libraries (scripts/toaster/attestations/build.py).

    hunt.py fetch SPEC REL [LOCAL_DIR]       the release's files for SPEC's library, into REL,
                                             each checked against the release's manifest.json
                                             (from LOCAL_DIR instead of the release URLs if given)
    hunt.py salt SEED SERVICE BOUNTY         the hunter's salt: secret, as the seed is
    hunt.py prepare SPEC REL NODES WORK MODE what the reveal must carry and may trust (below)
    hunt.py lemmas SPEC REL NODES WORK RATE  plan the hunter's own lemmas into batches (attest mode)
    hunt.py batches REL NODES WORK           lay out the traced lemma batches for attest-batches.py
    hunt.py trust SPEC REL WORK TRACED       the reveal's --trust, from a traced plan
    hunt.py args SPEC REL NODES WORK OUT     the check's arguments for the reveal, for witness-sim
    hunt.py names SPEC WORK DECLS            refuse lemmas that could be front-run (attest mode)
    hunt.py replay REL LIB NODES WORK        rebuild LIB's batches from an export, for witness-sim
    hunt.py probe OUT                        arguments for the Blake2b preimage check, to see
                                             whether PolkaVM's recompiler runs here

`prepare` (MODE `witness` or `attest`): the goal's node must be the bounty's statement node. The
hunter's nodes are the goal and everything its proof reaches that the library doesn't hold
(attested nodes stop the walk). In witness mode the reveal carries them all, nodes and proofs; in
attest mode it carries only the goal and its proof, and the rest (WORK/lemmas.json) are attested
first. Writes WORK/witness.pack and WORK/reveal-plan.json, for `lean-host trace` to cut down to
what the check looks up.
"""
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "attestations"))
from build import pack, read_claim, sha256  # noqa: E402

PINNED = {
    "eagerReduce", "Quot", "Quot.mk", "Quot.lift", "Quot.ind", "String", "String.ofList", "Nat",
    "Nat.zero", "Nat.succ", "Nat.add", "Nat.sub", "Nat.mul", "Nat.pow", "Nat.mod", "Nat.div",
    "Nat.beq", "Nat.ble", "Nat.gcd", "Nat.xor", "Nat.land", "Nat.lor", "Nat.shiftLeft",
    "Nat.shiftRight", "Bool.true", "Bool.false", "Char", "Char.ofNat", "List", "List.nil",
    "List.cons", "propext", "Classical.choice", "Quot.sound",
}  # witness-lean's lean_batches.py: nanoda_lib::nodes::PINNED_NAMES
# A batch's proofs packed in its witness, at most (witness-lean's lean_plan.py default).
MAX_PROOF_BYTES = 36000
# A hunter's own lemma must have a name with at least this many hex digits in a row.
TOKEN = re.compile(r"[0-9a-f]{16,}")


def blake2b(data):
    return hashlib.blake2b(data, digest_size=32).digest()


def load(path):
    return json.load(open(path))


def dump(obj, path):
    json.dump(obj, open(path, "w"), indent=1)


def fetch(spec_path, rel, local=None):
    spec = load(spec_path)
    r = spec["release"]
    os.makedirs(rel, exist_ok=True)

    def get(name, url):
        dst = f"{rel}/{name}"
        if local:
            shutil.copy(f"{local}/{name}", dst)
        else:
            with urllib.request.urlopen(url) as resp, open(dst, "wb") as f:
                shutil.copyfileobj(resp, f)
        return dst

    m = get("manifest.json", r["manifest"])
    if r.get("manifest_sha256") and sha256(m) != r["manifest_sha256"]:
        sys.exit(f"manifest.json's sha256 isn't the spec's {r['manifest_sha256']}")
    manifest = load(m)
    lib = next(l for l in manifest["libraries"] if l["library"] == spec["library"])
    for name, meta in lib["files"].items():
        dst = get(name, r["assets"][name])
        if sha256(dst) != meta["sha256"]:
            sys.exit(f"{name}: sha256 {sha256(dst)}, the manifest says {meta['sha256']}")
    with tarfile.open(f"{rel}/{spec['library']}-claims.tar.gz") as t:
        for m in t.getmembers():
            if not re.fullmatch(rf"{spec['library']}/lib-\d+\.claim", m.name) or not m.isfile():
                sys.exit(f"unexpected {m.name} in the claims")
        t.extractall(rel, filter="data")
    doc = load(f"{rel}/{spec['library']}.json")
    for k, want in (("check_hash", spec["check"]["hash"]), ("jam_lean", spec["pins"]["jam_lean"]),
                    ("witness_lean", spec["pins"]["witness_lean"]), ("cite", spec["cite"])):
        if (doc[k] if k != "cite" else {**doc["cite"], "library": spec["library"]}) != want:
            sys.exit(f"the release's {k} isn't the spec's")
    print(f"release {manifest['release']}: {spec['library']}, {doc['batch_count']} attestations, {doc['node_count']} nodes")


def salt(seed, service, bounty):
    print(blake2b(b"witness-hunt/salt\0" + seed.encode() + b"\0" + f"{service}/{bounty}".encode()).hex())


def library_index(spec, rel):
    """Every attested node the hunter may trust: its hash -> CLAIM:ENTRY."""
    lib = spec["library"]
    doc = load(f"{rel}/{lib}.json")
    index = {h: f"{rel}/{lib}/lib-{n}.claim:{e}" for h, (n, e) in doc["nodes"].items()}
    own = f"{rel}/own-index.json"
    if os.path.exists(own):
        index.update(load(own))
    return doc, index


def nodes_manifest(nodes):
    m = load(f"{nodes}/manifest.json")
    return m, {e["hash"]: e for e in m}


def closure_fn(by_hash):
    memo = {}

    def closure(h):
        """h and everything its node imports, recursively."""
        if h not in memo:
            out, todo = set(), [h]
            while todo:
                x = todo.pop()
                if x not in out:
                    out.add(x)
                    todo += by_hash[x]["imports"]
            memo[h] = frozenset(out)
        return memo[h]
    return closure


def needs(by_hash, closure, subjects):
    """What checking subjects (with their proofs) needs loaded, outside them (lean_plan.py's)."""
    need = set()
    for h in subjects:
        e = by_hash[h]
        for i in e["imports"] + e.get("proof_imports", []):
            need |= closure(i)
    return need - set(subjects)


def prepare(spec_path, rel, nodes, work, mode):
    spec = load(spec_path)
    os.makedirs(work, exist_ok=True)
    doc, index = library_index(spec, rel)
    manifest, by_hash = nodes_manifest(nodes)
    theorem, want = spec["statement"]["theorem"], spec["statement"]["node"]
    goal = next((e for e in manifest if theorem in e["names"]), None)
    if goal is None:
        sys.exit(f"your export has no {theorem}: the theorem must have exactly this name")
    if goal["hash"] != want:
        sys.exit(f"{theorem}'s statement node is {goal['hash']}, the bounty's is {want}: your theorem's type "
                 f"isn't exactly the bounty's (or another toolchain or jam-lean commit made it)")
    if "proof_size" not in goal:
        sys.exit(f"{theorem} has no proof in your export")
    if goal["hash"] in index:
        sys.exit("the goal is attested: the check would count it proved without your proof; this bounty can't be hunted this way")
    # The hunter's nodes: the goal and what its proof reaches that isn't attested.
    mine, todo = [], [goal["hash"]]
    seen = set()
    while todo:
        h = todo.pop()
        if h in seen or h in index:
            continue
        seen.add(h)
        e = by_hash[h]
        if PINNED & set(e["names"]):
            sys.exit(f"{e['names'][0]} is a pinned node the library doesn't hold: another Lean toolchain?")
        todo += e["imports"] + e.get("proof_imports", [])
    order = {e["hash"]: i for i, e in enumerate(manifest)}
    mine = sorted(seen, key=order.get)
    for h in mine:
        if "sorryAx" in by_hash[h]["names"]:
            sys.exit("your proof uses sorry")
    lemmas = [h for h in mine if h != goal["hash"]]
    subjects = mine if mode == "witness" else [goal["hash"]]
    closure = closure_fn(by_hash)
    trusted = sorted(needs(by_hash, closure, subjects), key=order.get)
    if mode == "witness":
        missing = [h for h in trusted if h not in index]
        assert not missing, f"untrusted nodes outside the witness: {missing[:3]}"
    proof = lambda h: open(f"{nodes}/proofs/{h}", "rb").read()
    items = [open(f"{nodes}/nodes/{h}", "rb").read() for h in subjects]
    items += [proof(h) for h in subjects if "proof_size" in by_hash[h]]
    w = pack(items)
    open(f"{work}/witness.pack", "wb").write(w)
    dump([{"depth": 0, "subjects": subjects, "trusted": trusted}], f"{work}/reveal-plan.json")
    dump({"goal": goal["hash"], "mode": mode, "carried": subjects, "lemmas": lemmas,
          "lemma_names": {h: by_hash[h]["names"] for h in lemmas}}, f"{work}/prepared.json")
    print(f"goal {theorem} = {goal['hash']} (the bounty's); your nodes: {len(mine)} "
          f"({len(lemmas)} besides the goal); the reveal carries {len(subjects)} with their proofs, "
          f"a {len(w):,}-byte witness ({mode} mode)")


def lemmas(spec_path, rel, nodes, work, rate):
    """Plan the hunter's lemmas (attest mode) by dependency depth, as lean_plan.py plans a library:
    a batch trusts the library and earlier batches."""
    spec = load(spec_path)
    _, index = library_index(spec, rel)
    manifest, by_hash = nodes_manifest(nodes)
    prepared = load(f"{work}/prepared.json")
    todo = set(prepared["lemmas"])
    order = {e["hash"]: i for i, e in enumerate(manifest)}
    depth = {}
    for h in sorted(todo, key=order.get):
        e = by_hash[h]
        depth[h] = 1 + max((depth[d] for d in e["imports"] + e.get("proof_imports", []) if d in depth), default=-1)
    closure = closure_fn(by_hash)
    plan = []
    for level in range(max(depth.values(), default=-1) + 1):
        current, size = [], 0
        for h in sorted((h for h in todo if depth[h] == level), key=order.get):
            s = by_hash[h].get("proof_size", 0)
            if current and size + s > MAX_PROOF_BYTES:
                plan.append(current)
                current, size = [], 0
            current.append(h)
            size += s
        if current:
            plan.append(current)
    plan = [{"depth": n, "subjects": s, "trusted": sorted(needs(by_hash, closure, s), key=order.get)} for n, s in enumerate(plan)]
    dump(plan, f"{work}/lemma-plan.json")
    print(f"{len(todo)} lemmas in {len(plan)} batches")


def batches(rel, nodes, work):
    """The traced lemma plan as attest-batches.py's layout, in WORK/own."""
    spec = load(f"{work}/spec.json")
    _, index = library_index(spec, rel)
    _, by_hash = nodes_manifest(nodes)
    plan = load(f"{work}/lemma-traced.json")
    own = f"{work}/own"
    os.makedirs(own, exist_ok=True)
    home = {}
    for n, b in enumerate(plan):
        for i, h in enumerate(b["subjects"]):
            home[h] = f"{own}/batch-{n}.claim:{i}"
    rate = float(open(f"{work}/gas_per_ms").read())
    for n, b in enumerate(plan):
        refs = []
        for h in b["trusted"]:
            ref = home.get(h) or index.get(h)
            if ref is None:
                sys.exit(f"batch {n} trusts {by_hash[h]['names'][0]}, which is neither attested nor yours")
            refs.append(ref)
        proven = [h for h in b["subjects"] if "proof_size" in by_hash[h]]
        proofs = pack([open(f"{nodes}/proofs/{h}", "rb").read() for h in proven])
        subjects = [f"{nodes}/nodes/{h}" for h in b["subjects"]]
        if len(proofs) > 60000:
            subjects += [f"{nodes}/proofs/{h}" for h in proven]
            proofs = pack([])
        open(f"{own}/batch-{n}.subjects", "w").write(",".join(subjects))
        open(f"{own}/batch-{n}.trust", "w").write(",".join(refs))
        open(f"{own}/batch-{n}.witness", "wb").write(proofs)
        if "ms" in b:
            open(f"{own}/batch-{n}.gas", "w").write(str(int(b["ms"] * rate)))
    dump({h: ref for h, ref in home.items()}, f"{rel}/own-index.json")
    print(f"{len(plan)} batches of your lemmas in {own}")


def trust(spec_path, rel, work, traced):
    """WORK/reveal-keep.json: what the traced reveal trusts (hashes), and WORK/reveal.trust, its
    --trust references, if every one is attested (in attest mode, not before your lemmas are)."""
    spec = load(spec_path)
    _, index = library_index(spec, rel)
    plan = load(traced)
    assert len(plan) == 1, "one reveal"
    keep = plan[0]["trusted"]
    dump(keep, f"{work}/reveal-keep.json")
    cite = spec["cite"]
    open(f"{work}/cite", "w").write(f"{rel}/{spec['library']}/{cite['claim']}:{cite['entry']}")
    missing = [h for h in keep if h not in index]
    if os.path.exists(f"{work}/reveal.trust"):
        os.remove(f"{work}/reveal.trust")
    if missing:
        print(f"the reveal trusts {len(keep)} nodes; {len(missing)} of them aren't attested yet")
        sys.exit(1)
    open(f"{work}/reveal.trust", "w").write(",".join(index[h] for h in keep))
    print(f"the reveal trusts {len(keep)} attested nodes, and the bounty's cited one")


def args(spec_path, rel, nodes, work, out):
    """The check's arguments for the reveal (witness_types::check_args), as refine would give them:
    the bounty's cited node, then the trusted nodes, all trusted (the claims' subjects are these
    same bytes); the goal as params."""
    spec = load(spec_path)
    hashes = [spec["cite"]["node"]] + load(f"{work}/reveal-keep.json")
    blobs = [open(f"{nodes}/nodes/{h}", "rb").read() for h in hashes]
    a = bytearray([2, 0])  # CHECK_INTERFACE_VERSION, CheckMode::Reveal
    a += len(blobs).to_bytes(4, "little")
    for b in blobs:
        a += b"\x01" + blake2b(b) + len(b).to_bytes(4, "little") + b
    params = bytes.fromhex(spec["statement"]["node"])
    a += len(params).to_bytes(4, "little") + params
    a += open(f"{work}/witness.pack", "rb").read()
    open(out, "wb").write(a)
    print(f"check arguments: {len(blobs)} trusted blobs, {len(a):,} bytes")


def names(spec_path, work, decls):
    """In attest mode, refuse to attest a lemma of the hunter's own module unless its name holds
    16 or more hex digits in a row (unguessable), or one whose type is the goal's: someone who
    committed earlier to a proof citing it by name and type would win."""
    spec = load(spec_path)
    d = load(decls)
    prepared = load(f"{work}/prepared.json")
    attested = {n for names in prepared["lemma_names"].values() for n in names}
    bad = []
    for c in d["constants"]:
        if c["name"] not in attested:
            continue
        if c["same_type_as_goal"]:
            bad.append(f"{c['name']}: its type is the goal's (never attest it)")
        elif not TOKEN.search(c["name"]):
            bad.append(f"{c['name']}: give it a name nobody would guess, with 16 or more hex digits in a row, e.g. Hunt_{os.urandom(8).hex()}")
    if bad:
        sys.exit("refusing to attest:\n  " + "\n  ".join(bad))
    print(f"{sum(c['name'] in attested for c in d['constants'])} of your module's declarations will be attested; their names are unguessable")


def replay(rel, lib, nodes, work):
    """Rebuild LIB's batches (NAME.json) from an export of the same nodes, as attest-batches.py's
    layout in WORK: attesting them gives the same claims, so the same attestation ids."""
    doc = load(f"{rel}/{lib}.json")
    os.makedirs(work, exist_ok=True)
    for n, b in enumerate(doc["batches"]):
        paths = [f"{nodes}/{'nodes' if s[0] == 'n' else 'proofs'}/{s[2:]}" for s in b["subjects"]]
        w = pack([open(f"{nodes}/proofs/{h}", "rb").read() for h in b["witness"]])
        assert hashlib.sha256(w).hexdigest() == b["witness_sha256"], f"batch {n}: the witness differs"
        open(f"{work}/batch-{n}.subjects", "w").write(",".join(paths))
        open(f"{work}/batch-{n}.trust", "w").write(",".join(f"{work}/batch-{m}.claim:{e}" for m, e in b["trust"]))
        open(f"{work}/batch-{n}.witness", "wb").write(w)
    print(f"{lib}: {len(doc['batches'])} batches rebuilt in {work}")


def probe(out):
    """Some check arguments (a Blake2b preimage check's): where PolkaVM's recompiler can't run,
    witness-sim says BadCheckBlob for any check; its interpreter (the same gas) gives a verdict."""
    params = blake2b(b"x")
    open(out, "wb").write(bytes([2, 0]) + (0).to_bytes(4, "little") + len(params).to_bytes(4, "little") + params + b"x")


if __name__ == "__main__":
    a = sys.argv[1:]
    cmds = {"fetch": (fetch, (2, 3)), "salt": (salt, (3,)), "prepare": (prepare, (5,)), "lemmas": (lemmas, (5,)),
            "batches": (batches, (3,)), "trust": (trust, (4,)), "args": (args, (5,)), "names": (names, (3,)),
            "replay": (replay, (4,)), "probe": (probe, (1,))}
    if not a or a[0] not in cmds or len(a) - 1 not in cmds[a[0]][1]:
        sys.exit(__doc__)
    cmds[a[0]][0](*a[1:])
