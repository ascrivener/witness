# A Lean proof bounty on the JAM Toaster

The [Lean bounty demo](demo-lean-bounty.md) ran live on the JAM Toaster, against witness as
**service 7** ([docs/toaster.md](toaster.md)). It used jam-lean's `Picoalloc.alloc_wf`, checked by
witness-lean's Lean check. The steps were:

1. Attest the theorem's library on chain, batch by batch.
2. Post a bounty for the theorem's statement.
3. Reveal three wrong proofs, all rejected.
4. Reveal the real proof.
5. Finalize after the claim window, paying the hunter.

**Result: bounty 1 on service 7 was claimed by the hunter at slot 9,909,096 and paid 500.**

## How it ran

[`.github/workflows/toaster-lean.yml`](../.github/workflows/toaster-lean.yml) runs
`scripts/lean-bounty-demo.sh` in its live mode ([`scripts/toaster/lean/live.sh`](../scripts/toaster/lean/live.sh)).

### Setup

- **Node:** a non-validating PolkaJam 0.1.29 node on the runner, started as in `toaster.yml`.
- **Toolchain:** built while the node syncs, at pinned commits:

  | Component | Version |
  |---|---|
  | Lean | v4.36.0-rc1 |
  | lean4export | `df81913` |
  | jam-lean | `b8864bd` |
  | witness-lean | `77335db` (pins witness `71e585a`, the code service 7 runs) |
  | rustc | 1.97.0 |

- **The Lean check:** 515,712 bytes, sha256 `dfecff13…7103a`, blake2b-256 `cc419035…77e4`, the bounty's check hash.

### What the live script does

- **Accounts:** the run's accounts are seeds of its tag (`lean-alloc1-alice`, `-bob`, `-carol`, and four attesters), minted from the test faucet.
- **Submission:** every op goes through `scripts/jam-submit.py`. It is resubmitted until the chain shows its effect: the signer's nonce moving on, or the bounty's status changing.
- **Rejected reveals:** a rejected reveal leaves no state behind. So the script waits for the chain's statistics to show service 7 refined something after the reveal was sent, then checks the bounty is unchanged.
- **Gas:** refine and accumulate gas come from the same statistics ([`scripts/toaster/lean/stats.py`](../scripts/toaster/lean/stats.py)). A non-validating node never refines, so this is the only gas figure it can see.
- **Resuming:** the work (check blob, nodes, plan, batches, claims and progress) is uploaded with each run. A later run resumes from it and from the chain's state.

### The two runs

- **[Run 44751676237](https://github.com/ascrivener/witness/actions/runs/44751676237)**:
  - attested the library, posted both bounties and made the four commits;
  - then stopped at the first wrong-proof reveal, because its statistics decoder didn't match the Toaster's encoding;
  - it showed success anyway, because the script's exit status was lost in a pipe (fixed in #40).
- **[Run 44758884737](https://github.com/ascrivener/witness/actions/runs/44758884737)** resumed from it and did the rest.

Each run took about 4 minutes to build and sync, the node syncing in 60 s.

## Results

### Attest

The library is Lean core plus 12 picoalloc files.

| | |
|---|---|
| Export | 2,580 nodes (1.40 MB of statements, 3.11 MB of proofs), one goal |
| Plan | 114 batches over 56 depths (batch budget 3.5×10⁹ gas; slowest batch 41 ms native against 64 ms) |
| Attesters | 4 (`lean-alloc1-pat`, `-quinn`, `-rene`, `-sam`) |
| Packages | 46 in 24 rounds, each capped at 2.5×10⁹ refine gas and 6 items |
| Package size (payload and extrinsics) | 0.70 MB to 3.94 MB |
| Package contents | 1–6 items (each carries its own copy of the check) |
| Landing | every package on its first submission, each round in 2–3 slots; none dropped or requeued |
| Duration | slots 9,908,620–9,908,680: 6 minutes, 114 attestations |
| Heaviest batch | estimated at 2.2×10⁹ check gas; given 2.97×10⁹ refine gas, alone in its package |
| Check gas | estimated 6.46×10¹⁰ in all |

No chain-measured gas exists for the attest phase. The statistics were only decoded from the second run on.

### Bounties

Both posted by `lean-alloc1-alice`, reward 500 of the test asset, check gas 5×10⁹, claim window 30 slots.

| Bounty | Statement | Status |
|---|---|---|
| **1** | `Picoalloc.alloc_wf`, node `7ce01691db1fb346b84f37274809ff53fbab2cb72ff0b30850798325dd052a09`, citing one attested node | **Claimed** by `lean-alloc1-bob` at slot 9,909,096 |
| 2 | `Picoalloc.free_wf`, node `afb01982909759ee14f5b84d0426964d2d114bb0da6c7b80274d566c5d8b7514`, outside the attested library | Open until its expiry (slot 9,911,683); only here to show a proof of a different statement rejected |

Bounty 0 on service 7 is the simple bounty `toaster.yml` ran earlier.

### Reveals and finalize

Each op below landed on its first submission. The refine gas is the whole refine as the chain's statistics give it, not only the check. The accumulate gas is from the block after.

| Op | Sent → effect (slots) | Bytes sent | Refine gas | Accumulate gas | Outcome |
|---|---|---|---|---|---|
| carol: `alloc_wf`'s statement with `allocPost_wf`'s proof | 9,909,045 → 9,909,047 | 635,151 | 1.21×10⁷ | 33,658 | rejected, bounty 1 unchanged |
| carol: `allocPost_wf`'s proof term relabelled as `alloc_wf`'s, its imports trusted | 9,909,050 → 9,909,052 | 878,850 | 5.48×10⁸ | 33,658 | rejected, bounty 1 unchanged |
| bob: his `alloc_wf` proof, to bounty 2 (`free_wf`) | 9,909,055 → 9,909,057 | 582,467 | 7.28×10⁷ | 33,658 | rejected, bounty 2 unchanged |
| bob: his `alloc_wf` proof, to bounty 1, trusting 77 attested nodes | 9,909,060 → 9,909,063 | 582,467 | 7.54×10⁷ | 374,731 | accepted: Revealing, window ends 9,909,093 |
| finalize, too early | 9,909,063 → 9,909,064 | 10 | 22,572 | 60,372 | no change |
| finalize | 9,909,094 → 9,909,096 | 10 | 22,572 | | **Claimed**; bob +500, his deposit refunded |

A reveal took 13–16 s from sending to its effect showing, and finalize about 9 s. The resumed run took 319 s in all, 198 of them waiting out the claim window.

### Compared with witness-sim

[docs/demo-lean-bounty.md](demo-lean-bounty.md) measures only the check's gas. Its figures are:

| Reveal | witness-sim check gas | On chain (whole refine) |
|---|---|---|
| Wrong proof | 2.8×10⁵ | 1.21×10⁷ |
| Forged proof | 4.9×10⁸ | 5.48×10⁸ |
| Different statement | 6.1×10⁷ | 7.28×10⁷ |
| Real proof | 6.1×10⁷ | 7.54×10⁷ |

The difference is the refine work around the check: loading the 516 KB check into the inner PVM, and hashing and decoding what the op is given.

- **The three reveals that trust the 77 attested nodes:** 1.2–1.4×10⁷.
- **The forged proof:** 5.8×10⁷. It trusts every node its proof imports, so it carries more to hash.

## Rerun it

Actions → Toaster Lean bounty → Run workflow:

- **`target: fake` (the default):** the whole flow against `scripts/toaster/lean/fake-node.py`, witness-sim behind a stand-in RPC that drops some packages. Nothing goes on chain. It takes about 7 minutes.
- **`target: toaster`:** the live run. Inputs:
  - `service_id` (7);
  - `tag` (the accounts' names; default the run's id);
  - `package_gas` (2.5×10⁹) and `package_items` (6).

  Each live run creates 114 attestations and two bounties on the service.
- **Resume:** set `resume_run_id` to an earlier run and give its `tag`.

The same on your own machine, with a synced node at `JAM_RPC`:

```sh
SERVICE_ID=7 TAG=mine TRACE_GAS=3500000000 PACKAGE_GAS=2500000000 PACKAGE_ITEMS=6 \
  WITNESS_LEAN_DIR=../witness-lean JAM_LEAN_DIR=../jam-lean LEAN4EXPORT=... \
  scripts/lean-bounty-demo.sh OUT
```

## Caveats

- **The attest phase's gas wasn't measured on chain.** Only the second run decoded the statistics. A full rerun would measure it too.
- **Statistics attribute by block, not by package.** They are summed over the blocks between sending an op and its effect. That is exact only while nothing else uses service 7, which held here.
- **Service 7 will change code.** It is due to upgrade (proposal 1, see [docs/toaster.md](toaster.md#pending-upgrade)) to a build whose service code is unchanged, but which is no longer byte for byte the blob jam-lean's theorems are about. This run was on the jam-lean build.
- **The planner budgets batches by native time, which is noisy.** One local plan put a declaration over the default 2.9×10⁹ budget by chance, so the workflow plans with 3.5×10⁹. A batch near that goes alone in its package, under the 5×10⁹ refine limit.
