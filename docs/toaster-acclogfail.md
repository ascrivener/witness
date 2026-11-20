# The AccLogFail bounty on the JAM Toaster

A witness bounty on the JAM Toaster, against witness as **service 7** ([toaster.md](toaster.md)),
for a proof of one of jam-lean's open obligations: `AccLogFail`, a named hypothesis of T2
(bootstrap's accumulate implements its spec). witness-lean's Lean check verifies a proof.

**Status: posted.** The bounty is **bounty 3 on service 7**, posted at slot 9,910,138 (2026-11-20) by
[run 44773292559](https://github.com/ascrivener/witness/actions/runs/44773292559). Its library was
attested in slots 9,909,960–9,910,135, about 18 minutes. It expires at slot 11,206,135.

## The statement

The bounty pays for a proof of

```lean
theorem Services.Bootstrap.Acc.Final.accLogFail_bounty : AccLogFailGoal
```

`AccLogFailGoal` is in jam-lean's `Services/Bootstrap/Acc/Final/Bounty.lean`. It is `AccLogFail`
(`Final/Hyps.lean`) quantified exactly as `AccHyps` asks for its `logFail` field: for every code that
is bootstrap's (`IsBootstrapCode`), its PVM code with the code facts, and every environment with that
code and the full parameters, `AccLogFail` holds at the heap bound 1044430 and the stack
4278050816 … 4278059008.

`AccLogFail` is the first log line's failure tail (6501 … 6630). If accumulate's run reaches a failed
allocation while keeping the allocator's context, it then ends ☇ keeping the context.

jam-lean's kernel proves the bounty statement is exactly that obligation:

- `accLogFailGoal_iff`: it is equivalent to the ∀ in `AccHyps`;
- `AccLogFailGoal.logFail`: it gives `AccLogFail` under those premises;
- `AccLogFailGoal.of_accHyps`: `AccHyps` implies it.

So a winning proof discharges `AccLogFail` for `accumulate_spec`.

The bounty's params are the hash of the theorem's statement node: its name and type, with the nodes
it uses named by hash, and no proof. A proof must use that exact name and type.

| | |
|---|---|
| Service | 7 |
| Bounty id | **3** |
| Statement node | `00bb0133f3bbe98877af4c7d3d9d59e3eb3068a70a545ed999d10bc2dcb0f354` |
| Check | witness-lean `77335db`'s Lean check, the same as the [Picoalloc bounty](toaster-lean.md)'s |
| Reward | 1,000,000 of the test asset |
| Check gas | 5×10⁹ (`MAX_CHECK_GAS`) |
| Expiry | slot 11,206,135: 1,296,000 slots (about 90 days) after posting |
| Claim window | 30 slots; no disclosure window |
| Maker | the seed `bounty-acclogfail-maker` |
| Cites | the attestation of `AccLogFailGoal` |
| jam-lean | `c22c197` (#241, which added `Bounty.lean`) |

## The library

The bounty can only be won by a reveal that trusts attested nodes, so the statement's library is
attested first: everything `AccLogFailGoal` uses, recursively, with what their proofs use. That is
Lean core, Std, jam-lean's PVM and JAM model, and bootstrap's code facts.

Sized in witness-sim before posting:

| | |
|---|---|
| Library | 25,795 nodes: 21.1 MB of statements (17.2 MB of them the code facts), 7.0 MB of proofs |
| Batches | 322 (303 by dependency depth, plus splits of the batches over 800 subjects), 46 rounds of 4 attesters |
| Gas per batch | median 3.4×10⁸, max 2.35×10⁹ (47% of `MAX_CHECK_GAS`); 76 over 10⁹ |
| Gas in all | 1.95×10¹¹, about 3× the Picoalloc library's |
| Per batch | up to 1.3 MB of subjects and 2.2 MB of trusted nodes |

The heaviest batches are Std's `DTreeMap` balancing proofs (`balanced_doubleR`, about 2.3×10⁹ each).

## How it's posted

[`.github/workflows/toaster-acclogfail.yml`](../.github/workflows/toaster-acclogfail.yml) runs
[`scripts/toaster/acclogfail/post.sh`](../scripts/toaster/acclogfail/post.sh) on a runner with a
non-validating node of its own, as the Picoalloc bounty's workflow does. jam-lean comes from its
published build (`scripts/fetch-lake.sh`).

1. **Export.** The goal theorem is stated with `sorry`, only to hash its statement node. The library
   is the statement's closure, so the goal, its proof and `sorryAx` are in none of it.
2. **Plan.** The library is planned by dependency depth, and each batch trusts only what the kernel
   touches (`lean-host trace`). A batch's subject paths and trust references each travel as one
   command-line argument, which Linux caps at 128 KiB. So any batch over 800 subjects is split
   (subjects of one depth are independent, and each part keeps the batch's trust), paths are relative
   to the work directory, and the run stops if any argument would still be over 120 KB.
3. **Dry run.** Every batch is attested in witness-sim, which charges PolkaJam v0.1.29's gas for the
   check in PolkaVM. The run stops unless every batch is accepted within 3.5×10⁹ gas, 70% of a
   refine's 5×10⁹. The bounty is posted there too.
4. **Live.** The attesters `bounty-acclogfail-TAG-pat`, `-quinn`, `-rene` and `-sam` are minted the
   test asset and attest every batch (`scripts/attest-batches.py`). Then the maker posts the bounty.
   A rerun resumes from the chain's state.

`target: fake` runs it all against `scripts/toaster/lean/fake-node.py` instead, with nothing on chain.

## For hunters

[HUNTING.md](HUNTING.md) is the step-by-step guide, with a workflow that commits, reveals and
finalizes from your own copy of this repository. The bounty's machine-readable spec is
[`site/bounties/3.json`](../site/bounties/3.json), served at
<https://ascrivener.github.io/witness/bounties/3.json>.

- **Your whole proof must be checked in one refine.** A reveal checks the goal's proof, and every
  node of yours that it carries, within the bounty's 5×10⁹ gas. A proof of `AccLogFail` runs through
  code steps 6501 … 6630, so it may not fit.
- **Attest your own lemmas first, if needed.** Attest them in batches as the library was, then reveal
  the goal's proof trusting them and the library.
- **Commit before you attest anything.** Your commitment fixes your witness: the goal's proof term,
  naming your lemmas by hash. Earliest commitment wins.
- **Don't attest a lemma whose type is `AccLogFailGoal`.** A node's hash depends only on its name and
  type. Someone who committed earlier to a one-line proof citing that lemma's name and type could
  reveal ahead of you. Give the lemmas you attest names nobody would guess, for example with a random
  suffix.
- **The bounty doesn't set `--bind-claim`.** That option lets a reveal trust at most one attestation
  beyond those the bounty cites. A library attested in hundreds of batches can't meet that limit.
- **Don't reveal against an attested goal.** The check counts the goal as proved if it is among the
  trusted nodes. Prove the goal itself in your witness.
