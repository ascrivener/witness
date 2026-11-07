# Demo: a bounty paid for a Lean proof of a jam-lean theorem

[`scripts/lean-bounty-demo.sh`](../scripts/lean-bounty-demo.sh) runs a Lean proof bounty end to
end in `tools/witness-sim`. The theorem comes from
[jam-lean](https://github.com/ascrivener/jam-lean), and witness-lean's Lean check verifies it.

1. Export the theorem's closure, Lean core included, from jam-lean.
2. Attest that library in batches.
3. A maker posts a bounty for the theorem's statement.
4. A hunter commits, then reveals, the proof.
5. The bounty finalizes and pays the hunter.

Wrong proofs, and a proof of a different statement, are rejected along the way.

## The target: `Picoalloc.alloc_wf`

```lean
theorem alloc_wf {grow : Grow} {hb r p : Nat} {s s' : State} (hwf : WF s)
    (h : alloc grow hb 1 r s = some (p, s')) : WF s'
```

This is jam-lean's `Services/Picoalloc/Alloc.lean`: an alignment-1 `alloc` on a heap satisfying
picoalloc's invariant leaves a heap that satisfies it too. It was chosen because:

- The picoalloc model imports nothing outside Lean core, so the library to attest is core plus 12
  picoalloc files.
- `alloc_wf` is a real statement about allocator code, not a toy.
- Its closure is small enough to attest in about 15 rounds.

Nothing about it needed simplifying. The script takes `MODULE`, `THEOREM`, `OTHER` and `WRONG`,
so another target is a matter of setting them.

## What the run shows

| Step | What happens | Result |
|---|---|---|
| Export | `lean4export Services.Picoalloc.Alloc -- Picoalloc.alloc_wf` (Lean v4.36.0-rc1, core only) | 15.3 MB of NDJSON |
| Convert | `lean-host convert` to content-addressed nodes | 2,580 nodes: 1.40 MB of statements, 3.11 MB of proofs |
| Plan | `lean_plan.py --goal`, `lean-host trace` (each batch trusts only what the kernel touches), `lean_batches.py` | 114 batches over 56 depths |
| Attest | 4 attesters, `scripts/attest-batches.py --sim`, several batches to a package | all 114 accepted in 14–15 rounds |
| Bounty 0 | Alice posts: check = Lean check, params = hash of `alloc_wf`'s statement node, citing one attested node, reward 500 | `Open` |
| Bounty 1 | Alice posts a bounty for `Picoalloc.free_wf`, hashed from its own export (not in the attested library) | `Open` |
| Wrong proof | Carol reveals `alloc_wf`'s statement with `allocPost_wf`'s proof | `Rejected(CheckFailed(False))`: the proof names another statement |
| Forged proof | Carol reveals `allocPost_wf`'s proof term relabelled to claim `alloc_wf`, with every node it imports trusted | `Rejected(CheckFailed(Panic))`: the kernel's type check fails. Type errors panic in the check, which counts as false. |
| Different statement | Bob reveals his real `alloc_wf` proof to bounty 1 | `Rejected(CheckFailed(False))` |
| Reveal | Bob reveals his `alloc_wf` proof to bounty 0, trusting 78 attested nodes | accepted; claim window opens |
| Finalize | Too early: no change. After `window_end`: `Claimed` | Bob's balance is +500, and his deposit is refunded |

## Numbers

Measured in witness-sim. It runs the check in PolkaVM with the gas PolkaJam v0.1.29 charges (see
[Caveats](#caveats)). The machine had 4 cores, and `report.json` holds every batch's gas.

| | |
|---|---|
| Attest batches | 114 over 56 depths, in 14–15 rounds of up to 4 packages |
| Attest gas per batch | min 5.1×10⁶, median 2.7×10⁸, max 2.19×10⁹ (**43.7%** of `MAX_CHECK_GAS`); 27 batches over 10⁹ |
| Attest gas, total | 6.4×10¹⁰ |
| Batch size (subjects + witness) | 1.4 KB to 142 KB, median 35 KB; 6 subjects median, 255 max |
| Trusted per batch | median 344 nodes (123 KB), max 613 (232 KB), from up to 60 earlier batches |
| Reveal | **6.1×10⁷ gas (1.2% of `MAX_CHECK_GAS`)**, trusting 78 nodes; the witness (statement + proof) is 10 KB |
| Rejected reveals | wrong proof 2.8×10⁵ gas; forged proof 4.9×10⁸; different statement 6.1×10⁷ |
| Blobs | Lean check 516 KB (under `MAX_CHECK_LEN`, 2 MiB); witness service 223 KB |
| Gas per native ms | about 51M on this machine (`gas_per_ms.py`); batches cut at 56 ms (2.9×10⁹ gas) |

Wall-clock time for a whole run was 77–81 s, with the PolkaVM interpreter running every check:

| Phase | Seconds |
|---|---|
| Build (incremental), export, convert | 8 |
| Plan (calibration and kernel trace included) | 23 |
| Attest (114 batches) | 44–48 |
| Bounties, commits, 4 reveals, finalize | under 2 in all; the reveal itself 0.2 |

Every op fits a refine with room to spare. The heaviest attestation uses under half of
`MAX_CHECK_GAS`, and the reveal about 1%. Most of the reveal's cost is in its trusted nodes, not in
the proof: the library work was done once, by the attestations.

## Rerun it

```bash
# Toolchains: Lean v4.36.0-rc1 (elan), lean4export at the commit for it, cargo-jam-build 0.1.29
git clone https://github.com/leanprover/lean4export && (cd lean4export && git checkout df81913 && lake build lean4export)
cargo install cargo-jam-build --version 0.1.29 --locked
git clone https://github.com/ascrivener/witness-lean ../witness-lean
git clone https://github.com/ascrivener/jam-lean ../jam-lean

WITNESS_LEAN_DIR=../witness-lean JAM_LEAN_DIR=../jam-lean \
  LEAN4EXPORT=../lean4export/.lake/build/bin/lean4export scripts/lean-bounty-demo.sh /tmp/lean-demo
cat /tmp/lean-demo/report.md            # the numbers; report.json has every batch's gas
```

Variables:

- `MODULE`, `THEOREM`: the target. Defaults are `Services.Picoalloc.Alloc` and
  `Picoalloc.alloc_wf`.
- `OTHER`, `OTHER_MODULE`: the different statement. It must be outside the target's closure.
- `WRONG`: the theorem whose proof the wrong and forged proofs use.
- `ATTESTERS`: the attesters.
- `TRACE_GAS`: a batch's gas budget.
- `GAS_PER_MS`: skips the calibration.

## Caveats

- **The simulator, not a testnet.** witness-sim runs the service's real rules (`witness-rules`)
  and the check in PolkaVM. It doesn't model time, work-package limits, or the gas of refine and
  accumulate themselves. witness-lean's `scripts/lean-e2e.sh` has run Lean bounties, `gcd` and
  `primes`, on a local PolkaJam testnet the same way; this target hasn't been run on one.
- **PolkaVM's interpreter.** The recompiler couldn't start its sandbox in the container this ran in.
  Both the Linux and the generic sandbox failed, most likely for lack of `userfaultfd`
  (`vm.unprivileged_userfaultfd` was 0; see README, "Build and test"). witness-sim then reported
  `BadCheckBlob` for every check. The script falls back to `POLKAVM_BACKEND=interpreter` when it sees that. Both backends
  price each basic block with the same cost model (`polkavm` 0.37's `Simulator` under
  `CostModelKind::Full`), so the gas is identical; only the wall-clock time differs. On a machine
  where the recompiler runs, the attest phase should be faster.
- **The bounty's statement is a node hash.** Params are the hash of the theorem's statement node:
  its name, universe parameters and type, with the nodes it uses named by hash. The maker computes
  it from an export of the statement alone, with no proof. In this run, `alloc_wf`'s hash comes
  from the full export, which is the same thing because nodes are content-addressed (bounty 1
  shows this with `free_wf`'s).
- **Don't post a bounty for an attested statement.** A reveal may trust attested nodes, and the
  check counts the goal as proved if it's among them. An earlier version of this demo used
  `Picoalloc.allocPost_wf` as its "different statement". That theorem is in `alloc_wf`'s closure,
  so it was attested with the library, and a reveal of `alloc_wf`'s proof *was accepted* for it.
  That's sound, because the statement really was proved, but the bounty pays whoever reveals
  first, whatever they reveal. A maker should check that the goal isn't attested. A hunter's own
  attested work is guarded the same way as in [Bound claims](../README.md#bound-claims)
  (`--bind-claim`).
- **The chain needs the full spec's refine gas.** With batches capped at 9×10⁸ gas
  (`TRACE_GAS=900000000`, to fit PolkaJam's "tiny" 10⁹ limit), 16 declarations are over budget on
  their own. These are auxiliary proofs of `allocPost_wf`, `allocPost_chunks` and `toBin_lt`, and
  two from core's `Nat` bitwise lemmas, the heaviest about 1.8×10⁹ gas. witness-lean's
  `lean_split.py` might split some of them; the script stops and says so instead. With the full
  5×10⁹ every declaration fits whole.

## On a real JAM testnet

What running this on a testnet needs, beyond what ran here:

1. **A testnet with the full spec's refine gas.** PolkaJam's tiny config gives 10⁹, too little
   here (see above). `tools/full-gas-spec` raises a dev chain spec's limit to 5×10⁹ (see
   README, "Build and test").
2. **Submitting through `scripts/jam-submit.py` instead of witness-sim.** witness-lean's
   `scripts/lean-e2e.sh` already does this for its targets: the same ops, with every blob as an
   extrinsic. This script's flow (export, convert, plan, `attest-batches.py`, create, commit,
   reveal, finalize) maps onto it one to one. The parts left to port are the negative reveals and
   `finalize`, which `lean-e2e.sh` doesn't have, plus waiting out real slots in the claim window.
3. **Package budgets.** On one machine, `attest-batches.py --package-gas` and `--settle` keep
   guarantors within their deadline. 6.4×10¹⁰ gas in all is about 13 full packages, spread over
   15 dependency rounds.
4. **Data availability.** Every attest carries its trusted nodes, at most 232 KB here with Merkle
   paths, far under a package's limit. Nothing is stored on chain beyond records.
