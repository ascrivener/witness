#!/usr/bin/env python3
"""Split the declarations too heavy for one batch into judgment ops, with witness-lean's own
machinery (tools/lean/mathlib_work.py's heavy_job: `lean-host judgments` and `judgments-ops`,
twice, every op near the limit run in PolkaVM and the declaration planned again while any is
over), for scripts/toaster/library/build.sh.

    heavy.py WITNESS_LEAN_DIR NODES PACK TRACED BUDGET_MS SIM CHECK HEAVY [JOBS]

A candidate is a single-subject batch of TRACED (`lean-host trace`'s plan) over BUDGET_MS; it is
heavy if its check, measured in PolkaVM (witness-sim), is over MAX_OP_GAS (HEAVY/measured.json).
Each goes in HEAVY/HASH: its closure (what its statement and proof import, recursively), then
ops.json. Done ones are skipped, so a rerun resumes. MAX_OP_GAS (default 3.5e9, 70% of a
refine's 5e9) is the most any op may use, measured: mathlib_work.py's limit, lowered.
"""
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import types


def main(wl, nodes, pack, traced, budget_ms, sim, check, heavy, jobs="4"):
    sys.path.insert(0, f"{wl}/tools/lean")
    import mathlib_work as mw
    limit = float(os.environ.get("MAX_OP_GAS", 3.5e9))
    mw.VERIFY_LIMIT = limit
    mw.MAX_CHECK_GAS = limit  # never pass an op over the limit, even "as small as planning makes it"
    by = {e["hash"]: e for e in json.load(open(f"{nodes}/manifest.json"))}
    plan = json.load(open(traced))
    candidates = [(n, b["subjects"][0]) for n, b in enumerate(plan)
                  if len(b.get("subjects", [])) == 1 and b.get("ms", 0) > float(budget_ms)]
    # Native time is noisy: a candidate is heavy only if its check, measured in PolkaVM, is over the limit.
    def gas(n):
        args = f"{heavy}/probe-{n}.args"
        subprocess.run([f"{wl}/target/release/lean-host", "args", nodes, traced, str(n), args], check=True, capture_output=True)
        out = subprocess.run([sim, "check", check, args, str(10**11)], capture_output=True, text=True)
        os.remove(args)
        m = re.search(r"used (\d+) gas", out.stdout)
        if not m:
            raise SystemExit(f"witness-sim: {out.stdout} {out.stderr}")
        return int(m.group(1))
    os.makedirs(heavy, exist_ok=True)
    measured = {}
    if os.path.exists(f"{heavy}/measured.json"):
        measured = json.load(open(f"{heavy}/measured.json"))
    with cf.ThreadPoolExecutor(int(jobs)) as pool:
        for (n, h), g in zip(candidates, pool.map(lambda c: measured.get(c[1]) or gas(c[0]), candidates)):
            measured[h] = g
    json.dump(measured, open(f"{heavy}/measured.json", "w"))
    todo = [h for _, h in candidates if measured[h] > limit]
    print(f"{len(candidates)} declarations over {budget_ms} ms alone; {len(todo)} over {limit:.3g} gas, measured", flush=True)
    a = types.SimpleNamespace(work=os.path.abspath(os.path.dirname(heavy.rstrip("/"))), lean_host=f"{wl}/target/release/lean-host",
                              pack=os.path.abspath(pack), budget_ms=float(budget_ms), sim=sim, check=os.path.abspath(check))
    os.makedirs(heavy, exist_ok=True)
    # mathlib_work.heavy_job works in a.work/heavy/HASH.
    if os.path.abspath(heavy) != os.path.join(a.work, "heavy"):
        sys.exit("HEAVY must be a directory named heavy")

    def job(h):
        d = f"{heavy}/{h}"
        if os.path.exists(f"{d}/ops.json"):
            return h, "done before"
        os.makedirs(d, exist_ok=True)
        seen, stack = set(), list(by[h]["imports"]) + list(by[h].get("proof_imports", []))
        while stack:
            x = stack.pop()
            if x not in seen:
                seen.add(x)
                stack += by[x]["imports"]
        seen.discard(h)
        open(f"{d}/closure", "w").write("\n".join([h] + sorted(seen)) + "\n")
        kind = "inductive" if by[h].get("kind") == "inductive" else "theorem"
        mw.heavy_job(a, h, kind, f"{d}/closure")
        return h, f"{len(json.load(open(f'{d}/ops.json'))['ops'])} ops"

    failed = 0
    with cf.ThreadPoolExecutor(int(jobs)) as pool:
        for f in cf.as_completed([pool.submit(job, h) for h in todo]):
            try:
                h, what = f.result()
                print(f"heavy {by[h]['names'][0]} ({h[:12]}): {what}", flush=True)
            except Exception as e:  # noqa: BLE001
                failed += 1
                print(f"heavy: failed: {str(e)[:400]}", flush=True)
    if failed:
        sys.exit(f"{failed} heavy declarations failed")


if __name__ == "__main__":
    if len(sys.argv) not in (9, 10):
        sys.exit(__doc__)
    main(*sys.argv[1:])
