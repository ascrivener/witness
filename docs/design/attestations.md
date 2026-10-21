# Design: attestations and multi-blob checks

Status: phase 1 is partly implemented: extra blobs, check interface v2 and the check heap.
Extrinsic witnesses and limits as parameters are not done yet. Phase 2 is implemented for
bounties citing attestations and for chains of them; see "As built" below for where it differs
from this proposal. Reveals citing extra attestations of their own are not done.

## Summary

Today a check sees one blob (itself), the bounty's `params` (at most 4 KB) and the witness (at most
64 KB). It must do all its verification inside one refine, from scratch, on every reveal.

The [Lean checker spike](https://github.com/ascrivener/witness/blob/spike/lean-checker/spikes/lean-checker/README.md)
(on the unmerged `spike/lean-checker` branch) showed where that breaks:
- Real proof bounties need large supporting data, such as a statement environment or library
  layers.
- Much of the work is the same on every reveal (checking that data), and some of it is too big for
  any single refine.

This proposes two generic features, in two phases:
- **Phase 1, multi-blob checks.** A bounty names extra preimage blobs that refine hands to the
  check, alongside a larger witness. The check gets an allocator. Cheap, and useful on its own.
- **Phase 2, attestations.** A way to record, once, "check C has verified blob B, given earlier
  attestations P", and let later checks trust B instead of re-verifying it. This is what makes
  large, layered verification possible.

Witness never interprets what an attestation *means*: the check blob defines it. For the Lean
checker it would mean "every declaration in B type-checks, given the layers in P".

## Are attestations critical?

It depends on proof size, measured with the Lean checker on PolkaJam v0.1.29:

| Proof | Re-check everything per reveal | With the environment attested |
|---|---|---|
| Small (`2 + 2 = 4`, list and induction lemmas) | 50–110 M gas | the delta alone: ~1.6 M for `2 + 2 = 4` |
| Medium (`Nat.gcd_comm`) | ~1.42×10⁹ gas | 948 M gas |
| Mathlib-backed, professional | the library alone exceeds any single refine | pay per new declaration (~3.4 M gas each) |

The "environment attested" column is measured by having the spike service skip checking the
environment (its `BindPrechecked` op), since nothing can attest it yet. It's the per-reveal cost
attestations would give, not something witness can do today.

- **Not critical for a first version.** Small proofs fit easily. Medium ones fit in the full
  spec's 5×10⁹ refine budget, though not the testnet's 10⁹, assuming one work item can use most of
  a package's budget (unverified).
- **Critical for anything Mathlib-scale.** There's no other way for a reveal to rely on
  verification done in an earlier refine.

Hence the phasing. Phase 1 already reserves the check's "mode" and the "trusted" flag on blobs, so
phase 2 needs no further breaking change to check blobs.

## Phase 1: multi-blob checks

### Bounty terms

```rust
pub struct BountyTerms {
    pub check_hash: Hash,
    pub check_len: u32,
    pub params: Vec<u8>,
    /// New: extra preimages the check receives, in order.
    pub blobs: Vec<BlobRef>,
    // reward, check_gas, expiry, claim_window: unchanged
}

pub struct BlobRef { pub hash: Hash, pub len: u32 }
```

The blobs are solicited and reference-counted like check blobs: solicited when the first bounty
using them is created, forgotten when the last one closes. They're capped by number and total
size, so one reveal's lookups fit in refine.

### Witnesses

A reveal's witness can come from the work item's **extrinsic data** instead of the payload. This
raises the limit from 64 KB to about the package's input limit (about 13 MB at present). The
payload carries only the witness's hash. Refine fetches the extrinsic and checks the hash.

### Check interface, version 2

The arguments the check receives become:

```
E1(version = 2) ++ E1(mode) ++ E4(n) ++ [E1(trusted) ++ hash ++ E4(len) ++ bytes] × n ++ E4(len) ++ params ++ witness
```

Lengths are fixed 4-byte little-endian, as in version 1, so a check can parse them without a
codec.

- **`mode`:** `0` for reveal; `1` for attest (phase 2). In phase 1 it's always 0.
- **`trusted`:** always 0 in phase 1. In phase 2, 1 marks a blob covered by an attestation the
  caller relies on.

`witness-check` parses this into an `Input`, and gains `declare_full_check!`, which hands the check
the whole `Input`. `declare_check!` keeps today's `fn(params, x) -> bool` form on top of version 2,
and returns false in any mode but reveal, so a simple check can never attest anything.

The service sends only version 2. Witness only runs on test networks so far, so existing checks
are rebuilt rather than kept working. The version byte is for future changes.

### Memory

The service answers `grow_heap` from the inner VM by mapping more pages, up to a per-check page
cap, then resumes it. `witness-check` provides an allocator built on it. This makes ordinary `alloc`
Rust (`Vec`, `BTreeMap`, parsers) usable in checks.

As implemented, the heap grows from the end of the check's read-write data and may not reach its
stack, and the check pays `grow_heap`'s gas (275 plus 121 per page). Past `MAX_CHECK_PAGES`,
counting the arguments, the call returns the heap's current end, so the allocation fails and the
check panics.

### Limits

`MAX_CHECK_LEN`, `MAX_CHECK_PAGES` and `MAX_CHECK_GAS` become service parameters with higher
defaults. The Lean checker blob alone is 629 KB, and a medium proof uses most of a refine.

## Phase 2: attestations

### As built

What follows is the proposal. The implementation settled these differently:

- **A check only trusts its own attestations.** Parents must be by the same check with the same
  params, and a bounty may only cite attestations by its own check. Without this, an attester
  could name as a parent a layer "verified" by a check that accepts anything, or by this check
  with lenient params (say, more axioms allowed), and the strict check would trust it. A bounty's
  maker picks the attestations it cites, params included. With
  it, a trusted blob always means "my own attest mode accepted this", so checks don't need to
  recognize other checkers (the last security note below no longer applies).
- **The id covers the params too:** `blake2b256(encode("witness/attest", claim))`, where the
  claim is `(check_hash, params_hash, subject, parents)`. Params can change what a check accepts.
- **Subjects are pinned first.** Refine has to look the subject up before accumulate ever sees the
  attestation, so a new `Pin` op (signed, `PIN_DEPOSIT`) holds a preimage for good. The check
  blob needs a pin too unless a bounty holds it.
- **Pins and attestations are permanent,** with deposits that aren't refunded, so the preimages
  they hold are too. Children don't need to count references to their parents.
- **Refine gets the claims.** It can't read state, so `Attest` carries the parents' full claims,
  and a reveal carries the claims of the bounty's attested blobs. Refine runs the check on the
  claimed subjects. Accumulate then makes sure the claims were recorded: for `Attest` by looking
  up the parents' ids, for `Reveal` by matching the bounty's terms, whose attestations were
  checked when it was created.
- **In attest mode** the check gets the parents' subjects, trusted and in order, then the subject,
  untrusted, last. The witness is empty. `witness_check::Input::subject()` returns the subject.
- **Parents are listed in full.** An attestation names every layer it relies on, not only the
  one below it, since the check needs all their data. Nothing enforces that a parent's own
  parents are included. If they're missing, the check sees less data and most likely fails.

### What one is

An attestation records that check `C` returned true in attest mode on subject blob `B`, given the
parent attestations `P`:

```rust
pub struct Attestation {
    pub check_hash: Hash,
    pub subject: BlobRef,
    pub parents: Vec<AttestationId>,
    pub slot: Slot,
    pub attester: AccountId,
}

/// blake2b256(encode(check_hash, subject.hash, parents))
pub type AttestationId = Hash;
```

The ID covers the check, the subject and the parents, so the same blob verified by a different
checker version, or on a different foundation, is a different attestation.

### Operations

- **`Attest { check_hash, subject, parents, params }`:**
  - **Refine:** looks up `C`, `B` and the subjects of all parent attestations. It runs `C` in
    attest mode, with the parents' subjects marked trusted and `B` untrusted. If the check
    returns true, it outputs `Verified::Attested { id, check_hash, subject, parents }`.
  - **Accumulate:** requires every parent attestation to exist, then records the attestation and
    takes a storage deposit from the attester. It solicits `B` if it isn't already held. An
    attestation that already exists is a no-op.
- **Bounties cite attestations.** A `BlobRef` in the terms can name an attestation instead of a
  bare blob:

  ```rust
  pub enum BlobRef { Blob { hash: Hash, len: u32 }, Attested(AttestationId) }
  ```

  At reveal, refine passes attested blobs to the check with `trusted = 1`, and outputs the
  attestation IDs it relied on. Accumulate pays out only if they all exist. Refine can't read
  state, so this check happens there, as with the commitment rules.
- **A reveal may cite extra attestations of its own,** beyond the bounty's, such as chunks of a
  large proof attested earlier. Those must chain to the bounty's attestations, so the check knows
  what foundation they assume.

### Lifetime and cost

- **Records are small and kept.** Their deposit is paid by the attester. A shared library layer
  is paid for once, by whoever attests it, and benefits every bounty after.
- **Subject blobs must stay available** while anything depends on them. That means reference
  counts across bounties and child attestations, extending today's check-blob counts.
- **Each `Attest` costs one refine.** Large subjects are split into layers, each attested on top
  of the previous one.

### Security notes

- **Trust is the same as any refine.** Guarantors run the attest refine, and auditors re-run it.
  An attestation is exactly as trustworthy as a reveal.
- **The checker is part of the ID.** A bug fix in a checker means new attestations; old ones keep
  saying exactly what they said.
- **Attesting in chunks reveals work early.** A solver who attests chunks of their proof before
  the final reveal publishes them. The commitment rules still protect them, since the earliest
  commitment wins, but only if they **commit before attesting their first chunk**. Tooling and
  docs must say so.
- **A check must reject trusted blobs it doesn't recognize.** The trusted flag says the blob was
  attested by *some* attestation the reveal cited. The check is responsible for confirming that
  attestation was made by a compatible checker, for example by also receiving the attestation's
  `check_hash`.

## Uses beyond proof bounties

An attestation is a generic, reusable "JAM verified this, given that". Other uses:

- **Bug bounties with heavy targets:** attest the target program's build, or its state after an
  expensive setup, once. Crash reveals then run against the trusted artifact.
- **Cross-chain verification:** attest a segment of another chain's headers on top of the
  previous segment. Bridges and oracles then trust the latest attested checkpoint instead of
  re-verifying history.
- **Datasets and models:** attest that a dataset meets a schema or quality bar, or that a model
  scores at least N on a benchmark. Bounties and markets can then build on it.
- **Software supply chain:** attest that a reproducible build of a source tree produced a given
  binary, or that it passes its tests.
- **Checkpointed long computations:** split any computation larger than one refine into attested
  steps.

That breadth suggests attestations may eventually belong in **their own JAM service**, which
witness and others read. JAM services can read each other's storage in accumulate, and look up
each other's preimages in refine. Recommendation: build them inside witness first (one service,
simpler payments and storage), with types that don't depend on bounties, and split them out once a
second consumer exists.

## Suggested order

1. Phase 1: multi-blob bounty terms, extrinsic witnesses, check interface v2, heap support and
   limits as parameters. Then port the Lean checker to it and test without attestations, on small
   and medium proofs.
2. Phase 2: attestations, starting with the single-layer case (an attested statement environment)
   and then chains.
3. Tooling to attest a library in layers (for Lean: Mathlib, split by module).
4. Revisit a standalone attestation service.
