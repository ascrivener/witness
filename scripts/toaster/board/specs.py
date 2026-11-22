#!/usr/bin/env python3
"""Write the machine-readable bounty specs the board serves: site/bounties/N.json for every bounty
of site/bounties-meta.json with a `spec`, and site/bounties/index.json listing them.

    specs.py [--release DIR] [--check]

A spec is everything a hunter (or their agent) needs: the statement (Lean name, type, its full
definition, the module to import, the statement node's hash), the pinned commits, the check, the
attestation the bounty cites, its terms (reward, asset, check gas, expiry slot and approximate
date, windows), the libraries a hunter trusts (`libraries`: the cited one, then any attested on top
of it), the release of their attestations (each asset's URL and sha256) and the
hunt workflow's commands (docs/HUNTING.md). The hand-kept source is bounties-meta.json; the rest
comes from the release's manifest.json (downloaded, or from DIR) and the statement's definition from
jam-lean at the pinned commit (raw.githubusercontent.com). The terms are what the chain holds:
scripts/toaster/attestations/check-chain.py checks the bounty's params and cited attestation, and
the board shows its live status (snapshot.json).

With --check, write nothing and exit 1 if the files in site/bounties differ from what would be
written.
"""
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.normpath(os.path.join(HERE, "..", "..", "..", "site"))
JCE = 1735732800  # slot 0: 2025-01-01 12:00:00 UTC
BOARD = "https://ascrivener.github.io/witness"


def fetch(url):
    with urllib.request.urlopen(url) as r:
        return r.read()


def definition(jam_lean, path, name):
    """The `def NAME …` block of jam-lean's PATH at commit jam_lean, with its doc comment."""
    text = fetch(f"https://raw.githubusercontent.com/ascrivener/jam-lean/{jam_lean}/{path}").decode()
    short = name.split(".")[-1]
    m = re.search(rf"(/--(?:(?!-/).)*-/\n)?def {re.escape(short)}\b.*?(?=\n\n)", text, re.S)
    if not m:
        sys.exit(f"no def {short} in {path} at {jam_lean}")
    return m.group(0)


def main(release_dir=None, check=False):
    meta = json.load(open(f"{SITE}/bounties-meta.json"))
    repo, tag = meta["repo"], meta["release"]["tag"]
    base = f"{repo}/releases/download/{tag}"
    raw = open(f"{release_dir}/manifest.json", "rb").read() if release_dir else fetch(f"{base}/manifest.json")
    manifest = json.loads(raw)
    out, index = {}, []
    for bid, b in sorted(meta["bounties"].items(), key=lambda kv: int(kv[0])):
        s = b.get("spec")
        if not s:
            continue
        lib = next(l for l in manifest["libraries"] if l["library"] == s["library"])
        st, t = s["statement"], s["terms"]
        assert lib["goal"]["theorem"] == st["theorem"] and int(bid) in lib["goal"]["bounties"], f"bounty {bid}: not the library's goal"
        assert lib["goal"]["node"] == b["node"], f"bounty {bid}: the statement node isn't the library's goal"
        expiry_utc = datetime.datetime.fromtimestamp(JCE + 6 * t["expiry"], datetime.timezone.utc)
        # The libraries a hunter trusts: the cited one first, then any attested on top of it.
        libnames = [s["library"], *[n for n in s.get("libraries", []) if n != s["library"]]]
        libs = [next(l for l in manifest["libraries"] if l["library"] == n) for n in libnames]
        for l in libs[1:]:
            assert l["check_hash"] == lib["check_hash"] and l["jam_lean"] == lib["jam_lean"], f"bounty {bid}: {l['library']} has another check or jam-lean"
        files = {n: m for l in libs for n, m in l["files"].items()}
        names = ["manifest.json", *files]
        cmd = lambda step, extra="": (f"gh workflow run toaster-hunt.yml -R YOU/witness -f bounty={bid} -f step={step}{extra}")
        spec = {
            "format": 1,
            "chain": meta["chain"], "service": meta["service"], "bounty": int(bid),
            "title": b["title"], "about": b["about"], "doc": f"{repo}/blob/main/{b['doc']}",
            "statement": {
                "theorem": st["theorem"], "type": st["type"],
                "lean": f"theorem {st['theorem']} : {st['type']}",
                "imports": [st["module"]], "module": st["module"],
                "definition": definition(lib["jam_lean"], st["definition"], st["type"]),
                "definition_url": f"https://github.com/ascrivener/jam-lean/blob/{lib['jam_lean']}/{st['definition']}",
                "node": lib["goal"]["node"], "lean_toolchain": lib["lean_toolchain"],
            },
            "pins": {"jam_lean": lib["jam_lean"], "witness_lean": lib["witness_lean"],
                     "lean4export": lib["lean4export"], "witness_service": s["witness_service"]},
            "check": {"hash": lib["check_hash"], "sha256": lib["files"]["lean-check.jam"]["sha256"],
                      "name": meta["checks"].get(lib["check_hash"][:10], {}).get("name")},
            "check_gas": t["check_gas"],
            "library": s["library"], **({"libraries": libnames} if s.get("libraries") else {}),
            "cite": {**lib["cite"], "library": s["library"]},
            "reward": t["reward"], "asset": t["asset"],
            "expiry": {"slot": t["expiry"], "approx_utc": expiry_utc.strftime("%Y-%m-%dT%H:%M:%SZ")},
            "claim_window": t["claim_window"], "disclosure_window": t["disclosure_window"], "bind_claim": t["bind_claim"],
            "posted_slot": t["posted_slot"], "maker": s["maker"],
            "status": f"{BOARD}/snapshot.json",
            "release": {
                "tag": tag, "url": f"{repo}/releases/tag/{tag}",
                "manifest": f"{base}/manifest.json", "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "assets": {n: f"{base}/{n}" for n in names},
                "sha256": {n: m["sha256"] for n, m in files.items()},
            },
            "hunt": {
                "guide": f"{repo}/blob/main/docs/HUNTING.md",
                "workflow": ".github/workflows/toaster-hunt.yml",
                "secrets": {"HUNTER_SEED": "your account's seed (any secret string)",
                            "HUNTER_PROOF": "your Lean file, if it isn't committed to the repository (a public fork)"},
                "commands": {
                    "test": cmd("test"),
                    "check": cmd("check", " -f proof=PATH_OR_EMPTY"),
                    "commit": cmd("commit", " -f proof=PATH_OR_EMPTY"),
                    "reveal": cmd("reveal", " -f proof=PATH_OR_EMPTY"),
                    "finalize": cmd("finalize"),
                    "status": cmd("status"),
                },
                "local": f"HUNTER_SEED=... scripts/toaster/hunt/hunt.sh STEP site/bounties/{bid}.json PROOF.lean WORK",
            },
        }
        out[f"{bid}.json"] = spec
        index.append({"bounty": int(bid), "title": b["title"], "theorem": st["theorem"], "node": lib["goal"]["node"],
                      "reward": t["reward"], "asset": t["asset"], "expiry": spec["expiry"], "spec": f"{BOARD}/bounties/{bid}.json"})
    out["index.json"] = {"format": 1, "service": meta["service"], "chain": meta["chain"]["name"],
                         "status": f"{BOARD}/snapshot.json", "guide": f"{repo}/blob/main/docs/HUNTING.md", "bounties": index}
    os.makedirs(f"{SITE}/bounties", exist_ok=True)
    differ = []
    for name, doc in out.items():
        text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
        path = f"{SITE}/bounties/{name}"
        if check:
            if not os.path.exists(path) or open(path).read() != text:
                differ.append(name)
        else:
            open(path, "w").write(text)
    if check and differ:
        sys.exit(f"site/bounties is out of date ({', '.join(differ)}): run scripts/toaster/board/specs.py")
    print(f"{'checked' if check else 'wrote'} site/bounties: {', '.join(out)}")


if __name__ == "__main__":
    a = sys.argv[1:]
    rel = None
    if "--release" in a:
        i = a.index("--release")
        rel = a[i + 1]
        del a[i:i + 2]
    chk = "--check" in a
    if [x for x in a if x != "--check"]:
        sys.exit(__doc__)
    main(rel, chk)
