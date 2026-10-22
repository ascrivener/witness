# Design: attestations as a DAG, over sets of subjects

Status: proposal. Replaces the linear chains of witness#7.

## Why

Today an attestation names one parent, a check receives a subject's whole chain, and a subject is
trusted only right after its own chain. That fits positional formats, where a layer only means
something after its exact prefix, but it makes every refine load the whole chain before a
subject. A chain's total size is then bounded by what one refine can load and parse.

[witness-lean's measurements](https://github.com/ascrivener/witness-lean/blob/main/docs/design/content-addressed.md)
show what a content-addressed format gains instead, where each item names what it uses by hash:
for Mathlib's FLT for n = 4, a chain would have to parse 4.6 MB per refine (over the limit), while
any single declaration needs a median of 40 KB of other statements and at most 2.4 MB of NDJSON.
To use that, a check has to receive *just* the attested items it needs, from many attestations,
in any combination. That takes four changes, none specific to Lean.

## 1. An attestation covers a list of subjects

A **subject list** is a preimage listing `(hash, len)` entries. An attestation's claim names the
list, not a single blob:

```rust
pub struct AttestationClaim {
    pub check_hash: Hash,
    pub params_hash: Hash,
    /// A preimage listing the subjects, as (hash, len) entries.
    pub subjects: Preimage,
    /// Blake2b-256 of the sorted, deduplicated ids of the attestations this one relied on.
    pub parents_root: Hash,
}
```

It says: check `check_hash`, in attest mode with params hashing to `params_hash`, accepted every
subject in the list, trusting subjects of the parent attestations. Any single entry of the list
can later be trusted on its own.

The parents enter the id only through `parents_root`, so a claim stays four hashes long however
many parents it has. Ops carry claims, and a claim with 200 parent ids inline would be 6 KB.

## 2. Attestations form a DAG, and trust needs no context

Parents are a set: the attestations whose subjects the check was given as trusted. A trusted
subject means "some attestation by this check, with these params, accepted it, given subjects
that were themselves attested". By induction that holds for anything recorded, so witness only
has to check that each attestation an op cites was recorded. There's no chain to walk, no closure
to pass along, and no rule about what came before a subject.

The rules that stay:

- **A check only trusts its own attestations.** Every attestation an op cites, and every parent,
  is by the same check with the same attest params.
- **Records and the subjects they cover are kept for good.**

Positional formats lose the context rule witness#7 added. A check over such a format can enforce
it itself: it sees each blob's hash, so a layer can name the hash of the layer it follows, and the
check can require that layer among its trusted blobs.

## 3. Ops cite claims once and entries by index

A check may draw on hundreds or thousands of trusted subjects. In gas that's cheap (a `lookup`
is 600 gas plus 248 per KiB). In op size it isn't, if each carries a claim. So an op carries the
claims it uses once, and refers to subjects by index:

```rust
pub struct TrustedRef {
    /// Index into the op's claims.
    pub claim: u16,
    /// Entry in that claim's subject list.
    pub entry: u32,
}
```

Refine looks up each claim's subject list, takes the entry's hash, looks up the subject, and
passes it to the check with `trusted = 1`. For a check drawing 1,500 subjects from 200
attestations, that's about 27 KB of claims and 9 KB of references.

The ops:

- **`Pin { owner, nonce, blobs: Vec<Preimage>, signature }`**: hold many preimages at once,
  typically a subject list and its entries.
- **`Attest { attester, nonce, check_hash, params, subjects: Preimage, claims, trusted, witness,
  check_gas, signature }`**: refine resolves `trusted`, then runs the check in attest mode on the
  trusted subjects, then every subject in the list, untrusted, with `witness`. The witness is the
  attester's evidence (a batch's proofs, say). It isn't part of the claim: the attestation is about
  the subjects, however they were shown. The claim's parents are the claims `trusted` used.
  Accumulate checks every parent was recorded and records the claim.
- **Bounties cite subjects:** `BlobRef::Attested { attestation: AttestationId, entry: u32 }`, or a
  plain blob. Creating a bounty checks each cited attestation exists and is by the bounty's check.
- **`Reveal` carries `claims` and `trusted`.** Its `trusted` must include the bounty's cited
  subjects, and may add others (library a proof uses that the bounty didn't name). Accumulate
  checks every claim the reveal used was recorded.

The check receives, in order: the trusted subjects, in the order of `trusted`; then the plain
blobs; then, in attest mode, the subjects being attested.

## 4. Limits

- `MAX_BLOBS` (128) becomes a limit in the thousands: 4,096.
- `MAX_BLOBS_LEN` (4 MiB) rises to 16 MiB, and `MAX_CHECK_PAGES` (64 MiB) to 128 MiB, so a
  check can hold that many blobs plus its own heap.
- Ops get bigger: an attest or reveal drawing on 1,500 subjects is around 40 KB before the
  witness. Work-item payloads stay well under a work package's limit, but `jamt item` takes the
  payload as a command-line argument, which Linux caps at 128 KiB (64 KiB of bytes in hex). The
  CLI may have to submit through a file, or extrinsic data.

## What changes in the code

- **types:** the claim and `TrustedRef` above, `BlobRef::Attested { attestation, entry }`, new
  `Pin`, `Attest` and `Reveal` fields, `StorageKey::Attestation` unchanged.
- **rules:** resolving `TrustedRef`s (look up the subject list, then the entry), the same-check
  rule over all cited claims, existence checks for every cited claim in accumulate, and dropping
  the chain checks.
- **witness-check:** nothing new in the interface. Attest mode's subject becomes subjects: every
  untrusted blob after the trusted ones and the plain ones. `Input::subject()` gives way to
  `Input::subjects()`.
- **samples and tests:** `checks/sorted-words` attests a list of volumes; its reveal mode already
  treats any trusted volume on its own merits. The rules tests and `scripts/e2e.sh` move to sets.
- **CLI:** subject lists, `Pin` of many blobs, citing claims and entries, and submitting big
  payloads.

## Open questions

- **Holding many small preimages.** Every subject is a preimage the service holds, with a storage
  deposit per item. A library of hundreds of thousands of items is as many preimages. If that's
  too costly, a list's entries could be byte ranges of one shared blob instead, with the list
  giving (offset, length, hash) and refine slicing it.
- **Who attests a library, and pays.** One attester per batch, each paying `ATTEST_DEPOSIT`, and
  every later bounty reuses the work. Rewarding attesters is out of scope here.
