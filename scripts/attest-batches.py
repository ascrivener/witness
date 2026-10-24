#!/usr/bin/env python3
"""Attest a DAG of batches in parallel: several attesters, several batches to a work package.

    attest-batches.py WORK --witness W --service SVC --check CHECK --check-gas G --attesters A,B,...
                      [--params HEX] [--package-gas G] [--settle SLOTS] [--sim WITNESS_SIM]

WORK holds the batches, numbered from 0, each as the arguments of `witness attest`:
batch-N.subjects (comma-separated subject files), batch-N.trust (comma-separated CLAIM:ENTRY
references, where a CLAIM named batch-M.claim is batch M's, which attesting batch M writes) and
batch-N.witness (the check's witness, a file). An optional batch-N.gas estimates the gas batch N's
check uses; without one, a batch is priced at the check gas G.

A batch needs the batches it trusts attested first; batches that don't depend on each other can
go in any order. So in each round, every attester fills a work package with batches whose
dependencies are attested (or earlier in that package: accumulate applies a package's items in
order), up to the package's refine gas (each batch's estimate, plus loading the check and hashing
what it's given), accumulate gas, size, extrinsics and items, and the package's own bytes (see
MAX_PACKAGE). Each attester signs with its own nonces and submits to its own core, so their
packages don't depend on each other. Then it waits for the round to land, and requeues whatever
didn't, from the chain's state: what's attested and each attester's nonce. A batch that keeps
failing goes alone with all the gas, and fails the run after a few tries.

--package-gas caps the refine gas a package is filled with. On a laptop testnet every guarantor
and auditor shares one machine, which can't refine a package of the chain's full 5×10⁹ inside the
guarantors' deadline: "Slow refine ... 5 s" in the node log, then "Not enough signatures", and the
package is dropped. A batch needing more still goes alone. --settle waits some slots after a round
lands, while the validators audit it: on one machine, a round sent straight after the last can find
them too busy to refine it in time. Both are off by default.

On a testnet (JAM_RPC, default ws://localhost:19800) it submits through jam-submit.py, next to
this script; with --sim, through witness-sim, a round at once (`witness-sim items`), which refines
its items in parallel and accumulates them in order, as a block lands many packages. Prints a line a round; the gas and bytes each item was given go to WORK/estimates.
"""

import argparse
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
# Refine gas beyond the check's: the service's reserve, hashing what it's given, and loading the
# check into its inner PVM before lending it gas, per byte (a 405 KB check took about 3×10⁷).
REFINE_RESERVE = 20_000_000
HASH_GAS_PER_BYTE = 61
LOAD_GAS_PER_BYTE = 100
# What an estimate is scaled by, for safety.
MARGIN = 1.3
# Accumulate gas for an attestation: a base, and a lookup per attestation it rests on (Lean FTA's
# first batches, citing up to 20, used at most 3.1×10⁵ in all).
ACCUMULATE_BASE = 400_000
ACCUMULATE_PER_PARENT = 15_000
# Rounds a batch may fail before it goes alone with all the gas, and before giving up.
ALONE_AFTER, GIVE_UP_AFTER = 1, 6
# The most bytes a package's encoding (payloads, not extrinsics) may take: jam-submit.py's
# MAX_PACKAGE, what PolkaJam v0.1.29's nodes accept. Witness-sim keeps to it too. An attestation's
# payload is small (its citations are an extrinsic): estimated, then measured once built.
MAX_PACKAGE = 200 * 1024
PACKAGE_PER_ITEM = 1024
# Bytes of Merkle path a trusted subject brings, at most (a claim of up to 2^48 subjects).
PATH_BYTES = 48 * 32
# Slots to wait for a round to land (a package that lands does in two or three), and seconds
# between polls of the chain.
LAND_SLOTS, POLL = 4, 2
# Threads building ops, at low priority: on a local testnet the validators share this machine,
# and a package they can't refine in time is dropped.
BUILDERS = 4


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def low_priority():
    os.nice(10)


class Chain:
    """The chain witness runs on: a testnet over RPC, or witness-sim."""

    def __init__(self, a):
        self.a, self.sim = a, a.sim
        if self.sim:
            self.params = {"max_refine_gas": 5 * 10**9, "max_accumulate_gas": 10**7, "max_input": 13_791_360,
                           "max_extrinsics": 128, "max_work_items": 16, "core_count": 1}
            return
        spec = importlib.util.spec_from_file_location("jam_submit", f"{HERE}/jam-submit.py")
        self.js = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.js)
        self.rpc = self.js.Rpc(self.js.url())
        self.params = next(iter(self.rpc.call("parameters").values()))

    def storage(self, key):
        if self.sim:
            v = subprocess.run([self.sim, "inspect", "storage", "--raw", self.a.service, key],
                               capture_output=True, text=True).stdout.strip()
            return v if v.startswith("0x") else None
        best = self.rpc.call("bestBlock")["header_hash"]
        v = self.rpc.call("serviceValue", best, int(self.a.service), self.js.b64(bytes.fromhex(key[2:])))
        return "0x" + self.js.unb64(v).hex() if v is not None else None

    def slot(self):
        return 0 if self.sim else self.rpc.call("bestBlock")["slot"]

    def submit_round(self, packages):
        """witness-sim: refine every package's (payload, extrinsics, ...) items at once, then
        accumulate them in order. Whether each item was applied, in order."""
        with tempfile.TemporaryDirectory() as tmp:
            lines = []
            for p, items in enumerate(packages):
                for i, (payload, extrinsics, _, _) in enumerate(items):
                    files = []
                    for j, x in enumerate(extrinsics):
                        files.append(f"{tmp}/{p}-{i}-{j}")
                        open(files[-1], "wb").write(x)
                    op = f"{tmp}/{p}-{i}.op"
                    open(op, "w").write(payload.hex())
                    lines.append(" ".join([op, *files]))
            open(f"{tmp}/list", "w").write("\n".join(lines) + "\n")
            out = run(self.sim, "items", self.a.service, f"{tmp}/list")
        return [line.endswith(": applied") for line in out.splitlines()]

    def submit(self, items, core):
        """Submit (payload, extrinsics, refine gas, accumulate gas) items as one package."""
        if self.sim:
            with tempfile.TemporaryDirectory() as tmp:
                for i, (payload, extrinsics, _, _) in enumerate(items):
                    files = []
                    for j, x in enumerate(extrinsics):
                        files.append(f"{tmp}/{i}-{j}")
                        open(files[-1], "wb").write(x)
                    open(f"{tmp}/op", "w").write(payload.hex())
                    run(self.sim, "item", self.a.service, f"@{tmp}/op", *files)
            return
        self.js.submit(self.rpc, int(self.a.service), items, core)


class Attester:
    def __init__(self, a, chain):
        self.a, self.chain = a, chain
        self.total = 0
        while os.path.exists(self.file(self.total, "subjects")):
            self.total += 1
        self.subjects = [self.read(n, "subjects").split(",") for n in range(self.total)]
        # Each batch's trust references, as (batch, entry) where they're another batch's.
        self.refs = []
        for n in range(self.total):
            refs = re.findall(r"batch-(\d+)\.claim:(\d+)", self.read(n, "trust"))
            self.refs.append([(int(m), int(e)) for m, e in refs])
        self.deps = [{m for m, _ in refs} for refs in self.refs]
        self.attested = set()
        self.tries = [0] * self.total
        self.keys = {}
        self.estimates = open(f"{a.work}/estimates", "w")

    def file(self, n, kind):
        return f"{self.a.work}/batch-{n}.{kind}"

    def read(self, n, kind):
        return open(self.file(n, kind)).read().strip()

    def w(self, *args):
        return run(self.a.witness, *args)

    def is_attested(self, n):
        claim = self.file(n, "claim")
        if not os.path.exists(claim):
            return False
        if n not in self.keys:
            self.keys[n] = self.w("key", "--attestation", claim)
        return self.chain.storage(self.keys[n]) is not None

    def nonce(self, who):
        v = self.chain.storage(self.w("key", "--account", who))
        return int(re.search(r"nonce: (\d+)", self.w("decode", "--account", v)).group(1)) if v else 0

    def build(self, n, who, nonce):
        """Batch n's op for `who` with `nonce`: its payload and extrinsics."""
        with tempfile.TemporaryDirectory() as x:
            trust = self.read(n, "trust")
            payload = subprocess.run([self.a.witness,
                "attest", "--service", self.a.service, "--attester", who, "--nonce", str(nonce),
                "--check", self.a.check, *(["--params", self.a.params] if self.a.params else []),
                "--subjects", self.read(n, "subjects"), *(["--trust", trust] if trust else []),
                "--witness-file", self.file(n, "witness"), "--check-gas", str(self.a.check_gas),
                "--claim-out", self.file(n, "claim"), "--extrinsics", x],
                check=True, capture_output=True, text=True, preexec_fn=low_priority).stdout.strip()
            extrinsics = [open(f"{x}/{i}", "rb").read() for i in range(len(os.listdir(x)))]
        return bytes.fromhex(payload.removeprefix("0x")), extrinsics

    def check_gas(self, n):
        """The gas batch n's check is estimated to use."""
        if os.path.exists(self.file(n, "gas")):
            return int(self.read(n, "gas"))
        return self.a.check_gas

    def gas(self, n, hashed, alone):
        """Refine and accumulate gas for batch n's item, which hashes `hashed` bytes."""
        p = self.chain.params
        if alone:
            return p["max_refine_gas"], p["max_accumulate_gas"]
        load = LOAD_GAS_PER_BYTE * os.path.getsize(self.a.check)
        refine = int(MARGIN * (self.check_gas(n) + HASH_GAS_PER_BYTE * hashed + load) + REFINE_RESERVE)
        accumulate = int(MARGIN * (ACCUMULATE_BASE + ACCUMULATE_PER_PARENT * len(self.deps[n])))
        return min(refine, p["max_refine_gas"]), min(accumulate, p["max_accumulate_gas"])

    def size(self, n):
        """About how many bytes batch n's item carries, before building it: the check, its
        subjects, and the subjects it trusts with their Merkle paths."""
        trusted = sum(os.path.getsize(self.subjects[m][e]) + PATH_BYTES for m, e in self.refs[n])
        return os.path.getsize(self.a.check) + sum(map(os.path.getsize, self.subjects[n])) + trusted

    def package(self, who, pending, taken):
        """Choose batches for who's next package, from pending in order, and build them."""
        with ThreadPoolExecutor(os.cpu_count() if self.chain.sim else BUILDERS) as pool:
            return self.assemble(who, self.choose(pending, taken), pool)

    def round(self, attesters, pending, taken):
        """witness-sim: every attester's package for a round, chosen in turn and built at once."""
        chosen = []
        for who in attesters:
            chosen.append(self.choose(pending, taken))
            taken = taken | set(chosen[-1])
        with ThreadPoolExecutor(os.cpu_count()) as pool, ThreadPoolExecutor(len(attesters)) as packages:
            done = [packages.submit(self.assemble, who, c, pool) for who, c in zip(attesters, chosen)]
            return [d.result() for d in done]

    def choose(self, pending, taken):
        """Batches for a package, from pending in order: as many as fit, by estimate."""
        p = self.chain.params
        room = {"refine": self.a.package_gas or p["max_refine_gas"], "accumulate": p["max_accumulate_gas"],
                "input": int(0.95 * p["max_input"]), "package": MAX_PACKAGE, "items": p["max_work_items"]}
        chosen, mine = [], set()
        for n in pending:
            if not room["items"]:
                break
            if n in taken or not all(m in self.attested or m in mine for m in self.deps[n]):
                continue
            alone = self.tries[n] > ALONE_AFTER
            if alone and chosen:
                continue
            # Estimated; the op's real size and gas are checked once built.
            size = self.size(n)
            refine, accumulate = self.gas(n, size, alone)
            fits = (refine <= room["refine"] and accumulate <= room["accumulate"] and size <= room["input"]
                    and PACKAGE_PER_ITEM <= room["package"])
            if chosen and not (fits and room["items"]):
                continue
            chosen.append(n)
            mine.add(n)
            room["refine"] -= refine
            room["accumulate"] -= accumulate
            room["input"] -= size
            room["package"] -= PACKAGE_PER_ITEM
            room["items"] -= 1
            if alone:
                break
        return chosen

    def assemble(self, who, chosen, pool):
        """Build who's package of the batches chosen, in pool: the longest prefix that fits."""
        if not chosen:
            return []
        p = self.chain.params
        # Build in parallel, but a batch only once those it trusts in this package are built: an
        # op cites their claims, which building writes.
        base, built = self.nonce(who), {}
        def build(i, n):
            for m in self.deps[n] & built.keys():
                built[m].result()
            return self.build(n, who, base + i)
        for i, n in enumerate(chosen):
            built[n] = pool.submit(build, i, n)
        ops = [built[n].result() for n in chosen]
        # Keep the longest prefix that fits as built: dropping from the end keeps nonces in order.
        refine_limit = self.a.package_gas or p["max_refine_gas"]
        items, refine, accumulate, size, package, count = [], 0, 0, 0, 512, 0
        for n, (payload, extrinsics) in zip(chosen, ops):
            # JAM hashes the check, extrinsic 0; the service hashes the rest.
            r, acc = self.gas(n, sum(map(len, extrinsics[1:])), self.tries[n] > ALONE_AFTER)
            s = len(payload) + sum(map(len, extrinsics))
            k = len(payload) + 128 + 40 * len(extrinsics)
            if not items and package + k > MAX_PACKAGE:
                sys.exit(f"attest-batches.py: batch {n}'s op alone is {len(payload)} bytes, over a package's {MAX_PACKAGE}")
            if items and (refine + r > refine_limit or accumulate + acc > p["max_accumulate_gas"]
                          or size + s > 0.95 * p["max_input"] or package + k > MAX_PACKAGE
                          or count + len(extrinsics) > p["max_extrinsics"]):
                break
            items.append((n, (payload, extrinsics, r, acc)))
            refine, accumulate, size, package = refine + r, accumulate + acc, size + s, package + k
            count += len(extrinsics)
            self.estimates.write(f"{n} {r} {acc} {s}\n")
        self.estimates.flush()
        return items

    def run(self):
        attesters = self.a.attesters.split(",")
        cores = max(1, self.chain.params.get("core_count", 1))
        start, rounds, failed = time.time(), 0, 0
        # A resumed run: what an earlier one attested (each has the claim it wrote).
        self.attested = {n for n in range(self.total) if self.is_attested(n)}
        if self.attested:
            print(f"resuming: {len(self.attested)} of {self.total} attested already", flush=True)
        while len(self.attested) < self.total:
            rounds += 1
            pending = [n for n in range(self.total) if n not in self.attested]
            taken, refused, sent = set(), set(), []
            packages = []
            if self.chain.sim:
                built = self.round(attesters, pending, taken | refused)
            for i, who in enumerate(attesters):
                items = built[i] if self.chain.sim else self.package(who, pending, taken | refused)
                if not items:
                    continue
                if self.chain.sim:
                    # Submitted with the round's other packages, below.
                    packages.append(items)
                    taken.update(n for n, _ in items)
                    sent.append([n for n, _ in items])
                    continue
                try:
                    self.chain.submit([item for _, item in items], i % cores)
                except SystemExit as e:
                    # The testnet sometimes can't reach a guarantor; the next round tries again.
                    print(f"{who}'s package of {len(items)} not submitted: {e}", flush=True)
                    refused.update(n for n, _ in items)
                    continue
                taken.update(n for n, _ in items)
                sent.append([n for n, _ in items])
            if not sent:
                failed += 1
                if failed > GIVE_UP_AFTER:
                    sys.exit(f"attest-batches.py: nothing attested in {failed} rounds, "
                             f"{self.total - len(self.attested)} to go")
                time.sleep(POLL)
                continue
            failed = 0
            if self.chain.sim:
                applied = self.chain.submit_round([[item for _, item in items] for items in packages])
                numbers = [n for items in packages for n, _ in items]
                landed = {n for n, ok in zip(numbers, applied) if ok}
                self.attested |= landed
                for n in taken - landed:
                    self.tries[n] += 1
                    if self.tries[n] > GIVE_UP_AFTER:
                        sys.exit(f"attest-batches.py: batch {n} wasn't attested after {self.tries[n]} tries")
                print(f"round {rounds}: {len(landed)} of {len(taken)} batches attested in {len(sent)} packages "
                      f"({', '.join(str(len(s)) for s in sent)} items); {len(self.attested)} of {self.total} attested, "
                      f"{time.time() - start:.0f} s", flush=True)
                continue
            # Wait for the round to land: everything sent attested, or the deadline.
            waiting = set(taken)
            deadline = self.chain.slot() + LAND_SLOTS
            while waiting:
                waiting = {n for n in waiting if not self.is_attested(n)}
                if not waiting or self.chain.sim or self.chain.slot() > deadline:
                    break
                time.sleep(POLL)
            landed = taken - waiting
            self.attested |= landed
            if landed and self.a.settle and not self.chain.sim:
                # Let the validators audit what landed before giving them more to refine.
                settle = self.chain.slot() + self.a.settle
                while self.chain.slot() < settle:
                    time.sleep(POLL)
            for n in waiting:
                self.tries[n] += 1
                if self.tries[n] > GIVE_UP_AFTER:
                    sys.exit(f"attest-batches.py: batch {n} wasn't attested after {self.tries[n]} tries")
            print(f"round {rounds}: {len(landed)} of {len(taken)} batches attested in {len(sent)} packages "
                  f"({', '.join(str(len(s)) for s in sent)} items); {len(self.attested)} of {self.total} attested, "
                  f"{time.time() - start:.0f} s", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("work")
    for flag in ("witness", "service", "check", "attesters"):
        p.add_argument(f"--{flag}", required=True)
    p.add_argument("--check-gas", type=int, required=True)
    p.add_argument("--params", help="the attest params, hex (default none)")
    p.add_argument("--package-gas", type=int, help="refine gas to fill a package with (default the chain's)")
    p.add_argument("--settle", type=int, default=0, help="slots to wait after a round lands (default 0)")
    p.add_argument("--sim", help="witness-sim, in place of a testnet")
    a = p.parse_args()
    a.work = os.path.abspath(a.work)
    Attester(a, Chain(a)).run()


if __name__ == "__main__":
    main()
