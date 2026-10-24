# Blobs as extrinsics, state as records

Status: steps 1 and 2 implemented (types, rules, service, witness-sim, CLI; the submitter).

## Why

Witness keeps every blob a check reads as a preimage of the service: check blobs, bounties' plain
blobs, and the bundles of attested subjects, which are held for good. On-chain state is the scarce
resource in JAM. A service locks a deposit for every item and byte it holds, and the proposed
JAMKB token meters exactly that: about 21 million, initially a kilobyte of state each. All of
Mathlib as attested nodes is about 1 GB, or about a million JAMKB: 5% of JAM's whole state supply.
A library that size can't live in state.

None of those bytes has to. Refine needs them only while it runs, and a work package can carry
them: a work item has up to 128 *extrinsics* (blobs the package supplies, which refine reads with
`fetch(OurExtrinsic(i))`), within the package's size limit (about 13.8 MB in the full parameters).
They're committed to by hash, and kept available for auditors for as long as the package can be
audited, like the rest of the package. So: blobs travel with the ops that use them, and state
keeps only records.

## Design

**Attestations commit to a Merkle root.** A claim's `subjects: Preimage` (a bundle's hash and
length) becomes `subjects_root: Hash` and `subject_count: u32`: the root of a binary Merkle tree
over the subjects. Leaves are `blake2b(0x00 ++ blake2b(subject))`, inner nodes `blake2b(0x01 ++
left ++ right)` (so a leaf can't pass as a node); an odd node at the end of a level is carried up
as it is. The count fixes the tree's shape, so an index means one thing. A leaf comes from its
subject's hash, which the check is given anyway, so refine hashes each subject once.

**Ops supply blobs as extrinsics.** An extrinsic is a SCALE `Vec<Vec<u8>>` of blobs, so 128
extrinsics hold any number. An op names a blob by `BlobAt { extrinsic: u8, index: u32 }`.

- `Attest` names its subjects: refine reads them, computes the root, and runs the check. Nothing
  is pinned.
- A `TrustedRef` becomes `{ claim, entry, blob: BlobAt, path: Vec<Hash> }`: subject `entry` of the
  cited claim, its bytes in the package, and its Merkle path. Refine checks the path against the
  claim's root, so it hashes only the subjects it uses. An FTA batch cites the attestations of
  about 270 batches, and those bundles are far bigger than the subjects it trusts.
- An op's citations (the claims it cites, and its `TrustedRef`s) travel as an extrinsic of their
  own too, whole: SCALE `Citations { claims, trusted }`, which the op names by its index (none if
  it cites nothing). They grow with what an op trusts, about 300 bytes a trusted subject with its
  path, and PolkaJam refuses a work package whose own bytes (its items' payloads, extrinsics
  aside) pass 200 KiB: a median FTA attestation's citations are about 100 KB, and its biggest
  250 KB. In an extrinsic they cost the package nothing, so several ops fit one package. The
  package commits to the extrinsic's hash, the signed claim's parents root binds the claims, and
  refine checks each reference against its claim, so nothing about them needs signing.
- A bounty's plain blobs are named the same way, and refine checks each against the hash the
  bounty records. The check blob travels as an extrinsic of its own, whole: the work package
  commits to each extrinsic's Blake2b-256 hash, so refine compares that with `check_hash` instead
  of hashing the blob. Hashing costs about 61 gas a byte in PVM (`blake2b_simd` and RustCrypto's
  `blake2` alike), and a Lean check is 416 KB: 3×10⁷ gas an op saved.

**The check's gas comes out of refine's.** A check runs in an inner PVM whose gas is charged to
refine as it goes, and invoking it with more than refine has left fails refine outright (out of
gas, so the op is lost rather than rejected). So the service lends the check at most what refine
can spare, keeping a reserve for its own work after the check; a check needing more runs out of
gas and is rejected. With the testnet's 10⁹ refine gas and a check limit of 9.5×10⁸, refine's
own work before the check (decoding, the signature, reading and hashing subjects: about 5×10⁷
for a Lean batch trusting 100 nodes) left too little before this.

**State is records.** Accumulate keeps attestations (`id → { slot, attester }`), bounties
(their terms name blobs by hash), commitments and accounts. The `Pin` op goes: nothing needs
holding. Bounties no longer solicit or release preimages. Accumulate's work no longer depends on
bundle sizes at all.

| | Today | With this |
|---|---|---|
| All of Mathlib's attestations in state | about 1 GB (bundles) | about 5 MB (49,670 records) |
| In JAMKB, at a KB each | about 1,000,000 | about 5,000 |

## Where the bytes live

Off chain, with whoever submits ops: an attester has the subjects it attests, and a hunter
assembles what a reveal trusts. For Lean they're reproducible: nodes are canonical, so anyone can
rebuild a library's nodes from its source (export, then `lean-host convert`) and get the same
hashes. Indexers and mirrors can serve them too. Losing them costs liveness only: an attestation
nobody can supply the subjects for can't be cited, but no false claim can pass, because refine
checks every byte against a root or hash recorded on chain.

## Soundness

Unchanged in kind. Refine checks a subject against the root its claim commits to, and the claim
against the attestation recorded in accumulate (as today, by id). Auditors re-run refine from the
package and its extrinsics, which JAM keeps available for audit. The rule that an op's claims are
all by its check with one set of params, and that a bounty citing no attestation takes no claims,
carries over.

## Limits

A package's extrinsics and payload must fit its size limit, so a batch can trust at most that
many bytes of subjects. Its payloads, outside the extrinsics, must also fit in 200 KiB on PolkaJam
v0.1.29, no chain parameter but what its nodes accept: so ops keep their payloads small (hence
citations as an extrinsic), and `jam-submit.py` checks it. The profiled plan of all of Mathlib has a median of about 250 KB trusted
per batch and a maximum of about 3 MB, against about 13.8 MB. Merkle paths add about
`32 × log2(subject_count)` bytes per trusted subject: for 1,400 trusted subjects from bundles of
a few hundred, about 400 KB.

## Deposits

With state just records, a deposit is per record: what JAM charges the service for an item of
that size. It's passed on to whoever creates the record (an attester, a bounty's maker, a
committer), in the unit JAM meters state in (JAMKB, as proposed). Attestations are permanent, so
their deposits are never refunded; a bounty's and a commitment's come back when they're removed.
Bounty rewards are a separate matter, paid in a token, not in JAMKB. Both come with moving witness
from points to native tokens.

## Tooling

`jamt item` can't attach extrinsics. Work packages with extrinsics go through the node's
`submitWorkPackage` RPC, so witness has its own submitter, `scripts/jam-submit.py`, which builds
the package (refine context, authorizer) as `jamt` does: for the same item it encodes the same
bytes. witness-sim supplies extrinsics directly.

## Plan

1. Types, rules and service, tested in witness-sim: claims with roots, `BlobAt`, trusted refs with
   paths, no `Pin`. The CLI writes an op's payload and its extrinsics.
2. The submitter, for PolkaJam testnets.
3. witness-lean: batches as subject lists, reveals with paths; the e2e scripts.
4. Deposits per record, and native tokens for deposits and rewards.
