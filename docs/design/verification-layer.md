# Design: witness as a verification layer

Status: a reframing, plus proposals. The checks, the attestations and the open bounties described
here are implemented. **Assigned jobs**, **notifying other services**, a **stable read interface**
for other services, and every check named under "Markets" that isn't in `checks/` or
[witness-lean](https://github.com/ascrivener/witness-lean) are proposals. Each section says which
is which.

## Why reframe

The README has led with "a find-the-witness bounty market". But witness's operations already
separate into three things, and only one of them is a bounty:

1. **Checks.** A check is a PVM program, `check(params, blobs, x) -> bool`, which witness runs in
   refine, under JAM's consensus: guarantors run it, auditors re-run it, and a wrong result is
   slashable like any other refine.
2. **Verified claims.** `Attest` runs a check and records "check C, with params P, accepted the
   subjects with these hashes, trusting subjects of earlier attestations". It stands alone. No bounty is involved.
3. **Conditional payments.** A bounty escrows a reward and releases it when a reveal passes its
   check. Commit-reveal is there because a bounty is open to anyone, so reveals race.

The uses we want are all of the form "a check, and optionally a payment conditioned on it":

- **Formally verified software.** The check is a Lean kernel checking a proof. The useful product is
  a reusable fact ("this declaration type-checks", eventually "the program with hash H satisfies
  spec S"), with payment for producing it as an option.
- **Verifiable AI inference.** The check verifies a proof that a committed model produced an output.
  A buyer pays a named prover for an answer they can trust without re-running the model.
- **Machine-verifiable work markets.** Agents pay other agents for outputs a program can judge.

Agents paying agents mostly look like the last two: a buyer and a chosen worker, not a public
contest. Calling witness a bounty market hides the parts they'd use. So this doc describes witness
as a verification layer, with bounties as one product on it, and proposes the pieces it lacks.

### Two faces: the layer and the registry

The same mechanism has two faces:

- **The verification layer** is the verbs: run a check, record the result, condition a payment on
  it. It's how witness works, and what a buyer uses.
- **The registry of verified claims** is the noun: the attestations the layer accumulates. It's
  why witness compounds. Later checks trust earlier attestations instead of redoing them, so each
  one makes the next cheaper, and the registry is public, so anyone can rely on it or extend it.

The audiences differ. Buyers, agents among them, come for verify-then-pay. Ecosystem users and
funders care about the registry: a growing body of verified facts, such as an attested Mathlib,
that outlives any single bounty or job.

**Witness stores claims, not work.** An attestation records that a check accepted subjects
identified by hash, with given params and parents: its id covers the check hash, the params hash,
the root of a Merkle tree over the subjects' hashes, their count, and the parents' root. The
subjects themselves, and the proofs, binaries, datasets or other evidence behind them, live off
chain, content-addressed and rebuildable (for Lean, from source). They travel as extrinsics with
the ops that use them. Losing them costs liveness, never soundness, since refine checks every byte
it's given against the hashes.

## The layers

```
  other JAM services        read attestations and payment records (accumulate only)
        |
  conditional payments      open bounties (built)       assigned jobs (proposed)
        |
  verified claims           attestations, a DAG of them (built)
        |
  checks                    PVM programs run in refine, under consensus (built)
        |
  balances                  assets of token services, deposits, fees (built)
```

Balances sit underneath everything: payments escrow assets held for token services, and records
are paid for with deposits. They're described in [tokens.md](tokens.md) and not repeated here.

### 1. Checks

**What exists.** A check is a JAM standard program blob, run by refine in an inner PVM
([`service/src/check_vm.rs`](../../service/src/check_vm.rs),
[`types/src/program.rs`](../../types/src/program.rs)). It receives:

- **params:** up to `MAX_PARAMS_LEN` (4 KiB) of configuration fixed by whoever posts the work, so
  one check blob serves many uses (`checks/blake2b-preimage` takes the target hash as params);
- **blobs:** up to `MAX_BLOBS` (4,096) blobs and `MAX_BLOBS_LEN` (16 MiB), carried as extrinsics of
  the work item and checked against hashes or Merkle roots ([extrinsics.md](extrinsics.md));
- **trusted subjects:** blobs marked `trusted`, covered by attestations of this same check with
  the same params, which it may rely on without re-verifying;
- **a witness `x`:** the candidate answer, or in attest mode the attester's evidence;
- **gas:** up to `MAX_CHECK_GAS` (5×10⁹, the full spec's refine budget), and memory up to
  `MAX_CHECK_PAGES` (128 MiB) through `grow_heap`.

It has two modes, reveal (0) and attest (1), and no host calls but `grow_heap`, so it's a pure
function of its input. The check's hash, the params' hash and the blobs' hashes together say
exactly what was checked. `check/` provides `declare_check!` and `declare_full_check!`.

Checks are never run on their own today. Each run is inside an op that does something with the
result: `Attest` records it, `Reveal` pays on it.

**What's new.** Nothing in the code. The reframing is to treat checks as the product: a library
of standard checks that many buyers share, so that "what does this check accept?" is answered once
and reviewed once. See [standard-checks.md](standard-checks.md).

**Open questions.**

- **A dry run.** Should there be an op that runs a check and only reports the result in refine's
  output, recording nothing? It costs core time and proves nothing to anyone who doesn't follow
  the work report. Probably not worth an op: an attestation is the durable version.
- **Checks that trust other checks.** A check only trusts its own attestations (see below). Some
  compositions want more: a check over Lean proofs trusting a separate, simpler checker's attested
  parse of a file, say. That needs the check to learn which checker made each trusted blob. Not
  needed yet.
- **Gas limits as service parameters.** `MAX_CHECK_LEN`, `MAX_CHECK_PAGES`, `MAX_CHECK_GAS` and
  `MAX_BLOBS_LEN` are constants (see the README's known gaps).

### 2. Verified claims

**What exists.** `Attest` (see the README and [attestation-dag.md](attestation-dag.md)) runs a check
in attest mode over a list of subjects and records an `Attestation` under its id:

```
id = blake2b256(encode("witness/attest", AttestationClaim {
    check_hash, params_hash, subjects_root, subject_count, parents_root }))
```

The record (`types::Attestation`) holds the check hash, the params hash, the slot and the attester.
It's stored under `StorageKey::Attestation(id)` and kept for good. The attester pays the configured
attest deposit, which isn't refunded.

Attestations form a DAG: an attestation can trust subjects of any number of earlier ones, all by the
same check with the same params. Since one is only recorded once its parents were, a recorded
attestation means: every subject under `subjects_root` was accepted by this check, with these
params, given subjects that were themselves accepted. Anyone holding a subject and its Merkle path
can show it's covered.

Attestations are reusable: a bounty can cite attested subjects (`BlobRef::Attested`), and a reveal
or a later attestation can trust them, so work done once isn't redone. witness-lean attests a
library once and every proof after builds on it.

**What's new.** Nothing in the ops. Two proposals affect how others use them:

- **A stable read interface** for other services (see layer 4): fix the encoding of
  `StorageKey::Attestation` and `Attestation` as a versioned public format, so a service that reads
  them isn't broken by a witness upgrade.
- **Attestations as the main output.** In the formal-verification market the product is the
  attestation itself ("this lemma, this library, this program's spec, verified"), and a payment for
  producing it is optional. Bounties citing attestations already work this way in one direction.

**Open questions.**

- **Who pays for attesting.** Each attestation costs its attester a refine and a deposit, and helps
  everyone after. [lemma-rewards.md](lemma-rewards.md) notes the idea of rewarding it, and its
  problems.
- **Revocation.** A check found to be buggy can't revoke its attestations. They keep saying
  exactly what they said, about a check that's now known to be wrong. Consumers have to name the
  checks they trust and drop a check when it's found faulty (see "Check correctness" below).
- **Attestations by reveal.** A reveal that passes doesn't leave an attestation: it's a reveal-mode
  run, about a witness, and it records a claim on a bounty instead. Whether a paid reveal or job
  should also leave a reusable record is open (see assigned jobs).

### 3. Conditional payments

#### Open bounties (built)

`CreateBounty`, `Commit`, `Reveal`, `Finalize`, `Reclaim` and `Release`, described in the README. A
maker escrows a reward for anyone whose witness passes the check. Because anyone can answer, and
revealing publishes the answer, the bounty uses commit-reveal: the earliest commitment among
valid reveals in the claim window wins. Disclosure windows delay publication for reports that
mustn't go public at once, and `bind_claim` stops speculators from committing early to reveals that
trust work attested later.

Bounties fit when the buyer doesn't know who can do the work, or wants a public contest: a proof
nobody has found, a bug in a live contract, a preimage.

#### Assigned jobs (proposed)

Most agent-to-agent work isn't a contest. A buyer picks a worker (by price, reputation, or because
the worker offered), and wants a guarantee for each side: the worker is paid if their output
passes the check, and the buyer gets their money back if it doesn't arrive by a deadline.

An assigned job is a bounty with one possible winner. Since nobody else can be paid, copying a
worker's output is pointless, and there's nothing to race. So no commitment and no claim window:
the first passing submission pays at once. Commit-reveal only comes back if the output must stay
private, and then for a different reason (see "Private outputs").

The ops are sketched [below](#sketch-assigned-job-ops).

**Open questions** are listed with the sketch.

### 4. Consumption by other JAM services

What another service can do with witness's records is fixed by JAM's host calls. From the Gray
Paper (appendix B, the host functions) and the SDK witness builds on (`jam-pvm-common` 0.1.29,
whose `refine` and `accumulate` modules export the calls each entry point may use):

| | Refine (another service's) | Accumulate (another service's) |
|---|---|---|
| Read witness's storage (attestations, bounties) | **No.** Refine can't read any service's storage, its own included | **Yes**, with `read` naming witness's service id (`get_foreign_storage`). Read-only |
| Read witness's preimages | Yes, `historical_lookup` on witness's id, as of the package's lookup anchor. But witness holds almost nothing as preimages now: blobs travel as extrinsics | Yes, `lookup` on witness's id |
| Write to witness's storage | No | No. No service can write another's storage |
| Call witness | No | No synchronous calls. A service can only send witness a **transfer** (native balance, a gas limit and a 128-byte memo), which witness processes in a later accumulate |
| Be called by witness | — | Only by a transfer witness sends from its accumulate (proposed, below) |

So:

- **Possible now, without changing witness.** Another service, in its accumulate, can check that an
  attestation was recorded. Its work item carries the `AttestationClaim` (five fields, about 132
  bytes), and the subject it cares about with its Merkle path. Its accumulate recomputes the id
  from the claim, reads `StorageKey::Attestation(id)` from witness's storage, checks the record
  exists with the check hash and params hash it trusts, and checks the subject's Merkle path
  against `subjects_root` (`witness_types::merkle`). That's one storage read and some hashing:
  cheap. It's the same split witness uses itself: refine checks what it's given, accumulate checks
  it was recorded.
- **Possible now, with more trust.** It can likewise read a bounty's record (`StorageKey::Bounty`)
  and see that it was claimed, by whom and with which witness hash.
- **Not possible.** A consumer's refine can't confirm an attestation exists. It can only take the
  claim as given and leave the existence check to its accumulate. There's no way to call witness
  and get an answer in the same block, or for witness to write into another service.
- **Possibly delayed.** Services accumulate in parallel within a block, each against the state as
  it stood before. A consumer should assume an attestation recorded in a block is visible to it
  from a later block, not the same one.

What the consumer trusts:

- **The check.** An attestation means what its check's attest mode means. The consumer must pin the
  check hash and params hash it accepts, just as a bounty does.
- **Witness's code and admin.** The records are witness's storage, laid out by witness's code. While
  an admin key can upgrade witness (after `ADMIN_DELAY`), a consumer trusts that key not to rewrite
  or fake records. This is the same trust users already place in it for balances.
- **The storage format.** Today it's an internal SCALE encoding. Hence the proposal to freeze it.

**Example: an upgrade gate.** Service U only upgrades its code to binaries a verifier has
approved. JAM's `upgrade` host call can only be made by U itself, in its own accumulate, so the gate
lives in U:

1. U's configuration pins `check_hash` (a checker for "this code satisfies U's spec") and
   `params_hash` (U's spec).
2. Someone attests the new code: a witness `Attest` whose subject is the code blob, so the subject's
   hash is the code hash JAM uses.
3. U's admin submits `Upgrade { code_hash, claim, entry, path }` to U. U's accumulate reads the
   attestation from witness, checks check and params, checks `code_hash` is subject `entry` under
   the claim's root, and only then calls `solicit`, waits for the preimage, and `upgrade`.

The plumbing is all available today. The missing piece is the check: something that can relate
a PVM binary to a spec. A Lean proof about a source program also needs a verified path from source
to binary (a verified compiler, or a proof about the binary itself). That's research, not
engineering. A weaker gate works sooner, for instance a check that the binary is the reproducible
build of a source tree whose hash a governance vote approved, though even that needs the build to
fit in a refine.

**Notifications (proposed).** Witness could send a transfer to a service a payment or attestation
names, when it's settled. That would let a consumer react without polling. It costs witness gas
per transfer (the recipient's `min_memo_gas`) and adds a way for a payer to make witness spend
gas, so it would need its own deposit. Not needed until a consumer exists.

**Open questions.**

- **A separate attestation service.** [attestations.md](attestations.md) suggested splitting
  attestations into their own service once a second consumer exists. Reading witness's storage
  works without that, so it stays deferred.
- **Freezing the format** (layer 2) before any consumer reads it.

## How the target markets map onto the layers

### Formally verified software

| Layer | Use |
|---|---|
| Check | witness-lean: an independent Lean 4 kernel as a PVM program. Subjects are declarations; a reveal binds a proof to the bounty's statement |
| Verified claims | A library (Mathlib) attested in batches, as a DAG. Attested declarations are reusable facts |
| Payment | An open bounty for an unproved statement, or an assigned job ("prove this lemma, by Friday, for 50 USDC") |
| Consumers | A service gating its upgrades or its configuration on an attested property |

**Flow, open bounty (works today, on a testnet):** a maker posts a bounty whose check is the Lean
checker and whose blobs cite the attested statement's environment. A solver commits, attests the
library layers their proof uses that aren't attested yet, and reveals the proof trusting them.
witness-lean has proved "there are infinitely many primes" from Mathlib this way, in 66 attested
layers. [docs/demo-lean-bounty.md](../demo-lean-bounty.md) runs a bounty for a jam-lean theorem
(`Picoalloc.alloc_wf`) end to end in witness-sim.

**Flow, assigned job (proposed):** the buyer creates a job naming the worker, the Lean check, the
statement and a deadline. The worker submits a proof; the check passes; the worker is paid. If the
proof is reusable, the worker can also attest it, so later proofs can trust it.

### Verifiable AI inference

| Layer | Use |
|---|---|
| Check | A proof verifier (a zkML or other succinct-proof verifier, compiled to PVM): "proof π shows that the model with weights committed as M, on input I, produced output O". Params: M's commitment and the verifier key. No such check exists in this repo yet |
| Verified claims | Optional: attest the verifier key or a model's commitment once, if checking them is costly |
| Payment | Assigned job: the buyer pays a named prover for O, given I |
| Consumers | A service acting on a model's output (an oracle, an agent's on-chain action) only when it's proven |

**Flow (proposed):** the buyer creates a job with the verifier as check, `(M, I)` as params, and a
deadline. The prover runs the model, produces the proof off chain, and submits `(O, π)` as the
witness. The check verifies π, which pays the prover. The buyer reads O from the submission.

The hard part is outside witness: proving inference for a large model is very expensive today. And
verifying a succinct proof in a PVM refine is unmeasured here: a pairing-based or FRI-based
verifier should fit in the refine budget, but nobody has compiled one to PVM and measured it. For
small models, the check could simply re-run the model, with no proof, if it fits in 5×10⁹ gas.

### Machine-verifiable work markets

| Layer | Use |
|---|---|
| Check | Whatever the work is judged by: a test harness over a submitted program, a solver's certificate checker (SAT, ILP), a hash target, a data validator |
| Verified claims | Attest the expensive fixed parts once (a test suite's setup, a dataset), so each submission only pays for itself |
| Payment | Assigned job when the buyer has picked a worker; open bounty when anyone may answer |
| Consumers | Reputation: a service counting an agent's paid jobs by reading their records |

**Flow (proposed):** an agent wants a function that passes a test suite. It posts a job naming a
worker agent, the test-harness check, the suite as a plain blob (or attested, if it's large and
reused), and a deadline. The worker submits the function. The check runs the suite on it in the
inner PVM, which means the function must be compiled to PVM (or interpreted by the check). If it
passes, the worker is paid.

**Example checks that exist today:** `checks/factor` (x is a nontrivial factor of N),
`checks/blake2b-preimage`, `checks/dictionary` (words hashing to a difficulty target) and
witness-sat's refutation checker. They're demonstrations of the shape, not a market.

## Sketch: assigned-job ops

Proposed. Nothing below is implemented. It reuses the bounty machinery wherever it can: the
terms, the check run and the citations are a bounty's, minus commit-reveal.

### Terms

```rust
pub struct JobTerms {
    // As BountyTerms: what the check is, and what it's given.
    pub check_hash: Hash,
    pub check_len: u32,
    pub params: Vec<u8>,
    pub blobs: Vec<BlobRef>,
    pub check_gas: Gas,
    // The payment.
    pub asset: Asset,
    pub payment: Amount,
    // Who may be paid, and by when.
    pub worker: AccountId,
    /// A passing submission must be accumulated at or before this slot.
    pub deadline: Slot,
    /// What the worker locks on accepting, in the fee asset. 0 for no acceptance step.
    pub worker_bond: Amount,
}
```

### Ops

| Op | Refine (in-core, stateless) | Accumulate (on-chain) |
|---|---|---|
| `CreateJob` | verify the buyer's signature over the terms | check nonce, balance and limits, the asset is accepted, `deadline` is in the future and at most `MAX_JOB_DURATION` away, and cited attestations exist and are by the job's check with one set of params (as `CreateBounty`); escrow `payment`; take the job deposit; store the job as `Open` |
| `AcceptJob` | verify the worker's signature | only if `worker_bond` > 0: the job is `Open` and before its deadline; lock the bond; mark it `Accepted` |
| `Submit` | as `Reveal`: read the check, plain blobs and trusted subjects from the extrinsics and check them against the job's hashes; run the check in reveal mode with `params` and the witness, with the job's `check_gas` | the terms match, the cited attestations were recorded, the job is `Open` (bond 0) or `Accepted`, and `now ≤ deadline`; pay `payment` to `worker`, return the bond and the job deposit; mark it `Paid { slot, witness_hash }` |
| `ReclaimJob` | verify the buyer's signature | the job is `Open` with no bond required (any time: cancelling), `Open` past the deadline, or `Accepted` past the deadline; refund `payment` and the job deposit to the buyer, and pay them the worker's bond if there was one; mark it `Reclaimed` |

`Submit` needs no signature. The payee is fixed in the terms, so anyone who submits a passing
witness pays the worker, which is harmless: it lets a worker hand submission to a relayer. A
failing submission is rejected in refine and writes nothing, so a worker can retry until the
deadline. It wastes only the submitter's core time.

### State

```rust
pub enum JobStatus {
    Open,
    Accepted { slot: Slot },
    Paid { slot: Slot, witness_hash: Hash },
    Reclaimed,
}

pub struct Job { pub buyer: AccountId, pub terms: JobTerms, pub status: JobStatus }
```

Stored under a new `StorageKey::Job(JobId)`, numbered from `NextJobId` as bounties are. The
witness's hash in `Paid` lets the buyer, or another service, tell which output was paid for.

### Deposits

- **Escrow:** `payment` in the job's asset, from the buyer, at creation.
- **Job deposit:** a configured amount in the fee asset, from the buyer, for the record. Returned
  when the job closes either way, if closed records are deleted (see below); kept otherwise, as
  the attest deposit is.
- **Worker bond:** optional, set by the buyer. It makes a worker who accepts and then doesn't
  deliver pay the buyer for the wait. With a bond of 0 there's no acceptance step: the buyer can
  cancel any time before a passing submission lands, and the worker carries that risk.

### Failure and timeouts

- **The check fails:** nothing changes. The worker may submit again before the deadline.
- **The submission lands late:** a submission accumulated after `deadline` is rejected, even if
  refine passed. Workers should submit with a margin. A grace period, as bounties have, would
  only move the deadline.
- **Buyer cancels while a submission is in flight (bond 0):** whichever accumulates first wins.
  A worker who needs certainty asks for a bond, which removes the buyer's cancel.
- **The check needs more gas than set:** it fails as out of gas, like any check. The buyer set the
  gas, and the worker can see it before accepting.
- **The worker never submits:** the buyer reclaims after the deadline, with the bond if any.

### Private outputs

A submission's witness is in the work package, which JAM keeps available for weeks, so it's
public. Commit-reveal doesn't fix that, it only delays it. Options, none built:

- **Delay:** a job could take a disclosure window, as bounties do: the worker commits to the output
  before the deadline, gives it to the buyer privately, and reveals later. The output still goes
  public in the end.
- **Check a proof, not the output:** the witness is a commitment to the output plus a zero-knowledge
  proof that the committed output passes the real check. The buyer gets the output off chain and
  checks it against the commitment. This needs a ZK verifier as the check, and a prover for the
  real check: heavy, but it's the only option that keeps the output private for good.

### Open questions

- **Partial and staged payment.** Milestones, several workers, or pay-per-item (a batch of
  inferences) would each need more state. Start with one payment.
- **Disputes about the spec.** There are none to resolve: the check is the spec, fixed at creation.
  A buyer who wrote the wrong check pays for the wrong thing. That's the point, and the risk (see
  below).
- **Delete closed jobs?** A paid job is a payment record, not a reusable fact. Deleting it on close
  saves storage and lets the deposit be refunded. Keeping it lets reputation services read it.
  Either could be right; an `Attest` covers the reusable case.
- **Offers.** Should a worker be able to post an offer ("I'll do this check for this price") that a
  buyer takes in one op? That's a matching layer, and can live off chain until there's demand.

## Risks and limits

### The gas cost of heavy checks

Every check runs within one refine, and the full spec allows 5×10⁹ gas per refine (the testnet's
tiny parameters, 10⁹). The Lean measurements in [attestations.md](attestations.md), on PolkaJam
v0.1.29:

| Proof | Re-check everything | With the environment attested |
|---|---|---|
| Small (`2 + 2 = 4`, list and induction lemmas) | 50–110 M gas | ~1.6 M for `2 + 2 = 4` |
| Medium (`Nat.gcd_comm`) | ~1.42×10⁹ | 948 M |
| Mathlib-backed | the library alone exceeds any refine | ~3.4 M per new declaration |

Attestations are what make heavy checks feasible: expensive fixed work is attested once, in
parallel batches, and each later run pays only for what's new. That works when the work splits into
pieces that verify independently given earlier ones. A check that can't be split (one big model
inference, re-executed) is capped at one refine's gas, and needs a succinct proof instead.

Gas is also a cost: someone pays for every refine in core time. JAM's pricing of core time isn't
settled, so the price of a check is unknown.

### Check correctness

The check *is* the contract. A check that accepts a wrong answer pays for it, and an attestation by
it records a false fact, permanently, for everyone who trusts that check. Consensus makes sure the
check ran as written. It says nothing about whether it was written right. In order of how much
they help:

- **Shared, reviewed checks.** A small library of standard checks, each reviewed once and used many
  times, rather than one check per job. See [standard-checks.md](standard-checks.md).
- **Small trusted cores.** witness-lean is an independent kernel, not Lean's own, so a proof must
  pass a second implementation of the type theory. A smaller trusted base is easier to review.
- **Verify the checks.** A check is a program, so its correctness is a claim like any other: "check
  C accepts x only if P(x)". In the long run that claim should itself be proved, and attested. This
  is the same research as the upgrade gate above.
- **Pinning, not revocation.** A buggy check can't be fixed in place: the fix is a new check, with a
  new hash, and new attestations. Consumers and buyers name the checks they trust, and stop naming
  a broken one. Old attestations by it stay recorded, and keep meaning only what the broken check
  meant.

### Settlement latency

JAM blocks are 6 s. Refine runs on a core, then the work report is guaranteed, made available and
accumulated a few blocks later: a payment settles in tens of seconds at best. Open bounties then add
a claim window (at least 30 slots, three minutes) so that a front-run can't win, and disclosure
windows add up to 90 days. Assigned jobs settle in one submission, with no window. That's fine for
proofs and work measured in minutes or more, and too slow for per-request micro-payments (pay per
inference token, say). Those would need a payment channel off chain, settled through witness
occasionally.

### Demand

Unproven. Nobody pays for any of this on witness yet:

- witness can't hold real money before JAM mainnet, which has no date
  ([targets.md](../targets.md)), so every bounty and job is credit-only until then;
- formal verification markets are small, and people who need proofs now hire experts;
- verifiable inference depends on proving costs falling a long way;
- agent-to-agent work markets don't exist at scale anywhere, and those that appear may judge work
  by reputation rather than by checks, because most valuable work isn't machine-checkable.

The case for the layer is that it's general: if any of these markets appears, the same checks,
attestations and payments serve it. The case against building assigned jobs now is the same lack of
demand. They're small, though: one record type and four ops, most of their logic shared with
bounties.

## Suggested order

1. README and docs reframed (this change).
2. Freeze the attestation record and key as a versioned format, before anyone depends on them.
3. Assigned jobs, when there's a buyer for them: rules and unit tests first, then the service and
   `witness-sim`, then the CLI.
4. A consumer: an example service whose accumulate reads an attestation (an upgrade gate on a
   trivial check), to prove the read path end to end.
5. Standard checks, as markets ask for them.
