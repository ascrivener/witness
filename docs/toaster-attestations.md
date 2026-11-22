# The Toaster's attestations, published

A witness-lean reveal trusts attested nodes by citing the exact attestations that hold them. Each
citation is a claim file (the attestation's claim and its subjects) and an entry in it. Which
attestation holds which node depends on how the library was batched. That batching followed the
planner's noisy native-time trace, so it can't be rebuilt from source. It exists only in the work
of the runs that attested each library, and their artifacts expire after 90 days.

So the release [`toaster-attestations-v2`](https://github.com/ascrivener/witness/releases/tag/toaster-attestations-v2)
publishes them for good. Hunters use it through [HUNTING.md](HUNTING.md). It holds v1's two
libraries unchanged (byte for byte; [`toaster-attestations-v1`](https://github.com/ascrivener/witness/releases/tag/toaster-attestations-v1)
stays as it was) and adds `acclogfail-proofs`.

## What's in it

| Asset | |
|---|---|
| `manifest.json` | per library: jam-lean, witness-lean and lean4export commits, the check's hash, the goal and the attestation its bounty cites, every attestation id, and the sha256 and size of each file |
| `NAME-claims.tar.gz` | `NAME/lib-N.claim` for each batch N: what `witness attest --claim-out` wrote. A reveal trusts a node with `--trust NAME/lib-N.claim:ENTRY` |
| `NAME.json` | the library: commits, check, goal, cited attestation; every batch (claim file, attestation id, subjects, the proofs in its witness and their sha256, the batches and entries it trusted); and `nodes`, each attested node's hash → [batch, entry] |
| `lean-check.jam` | the check every claim names (witness-lean `77335db`'s Lean check, blake2b `cc419035…`) |
| `chain-check.json` | what service 7 held when the release was made: every attestation found, and each bounty's status |

The claim files are named `lib-N.claim`, not `batch-N.claim`, because `scripts/attest-batches.py`
reads `batch-M.claim` in a trust reference as one of its own batches.

| Library | Runs | Attestations | Nodes | For |
|---|---|---|---|---|
| `picoalloc` | [44758884737](https://github.com/ascrivener/witness/actions/runs/44758884737) (resuming [44751676237](https://github.com/ascrivener/witness/actions/runs/44751676237), same claims) | 114 | 2,579 | bounty 1, `Picoalloc.alloc_wf` ([toaster-lean.md](toaster-lean.md)) |
| `acclogfail` | [44773292559](https://github.com/ascrivener/witness/actions/runs/44773292559) | 320 | 25,795 | bounty 3, `AccLogFailGoal` ([toaster-acclogfail.md](toaster-acclogfail.md)) |
| `acclogfail-proofs` | [44985391809](https://github.com/ascrivener/witness/actions/runs/44985391809) (the last of four live runs, each resuming the one before, from the dry run [44906071989](https://github.com/ascrivener/witness/actions/runs/44906071989)) | 6,428 | 21,911 | bounty 3, on top of `acclogfail`: what jam-lean's proofs of the region reach ([toaster-proof-library.md](toaster-proof-library.md)) |

A library on top of another (`acclogfail-proofs`, `"base": "acclogfail"`) has no goal or cited
attestation of its own: its batches trust the base's claims as `[BASE, batch, entry]`, and each
batch has a `kind` (`batch`, `op`: one judgment of a declaration too heavy for one refine, `final`:
the declaration citing its judgments; subjects `j:SHA256` are judgment blobs).

## How it's made

[`.github/workflows/toaster-attestations.yml`](../.github/workflows/toaster-attestations.yml)
(Actions → Toaster attestations → Run workflow; tick `publish` to create the release):

1. downloads the runs' artifacts (`scripts/toaster/attestations/libraries.json` names them), and
   checks that a resumed run's claims are the same as the run it resumed;
2. builds the assets with `scripts/toaster/attestations/build.py` (a library on top of another
   with `scripts/toaster/library/release.py`, after its base). It checks every claim's
   subjects against the run's nodes (a node's hash is the blake2b-256 of its bytes) and every
   witness against its proofs. The output is deterministic: the tarballs carry no times or
   owners, so a rerun gives the same bytes;
3. syncs a non-validating node, as `toaster.yml` does, and runs
   `scripts/toaster/attestations/check-chain.py`. Every attestation must be in service 7's
   storage, by the release's check, with empty attest params. Every bounty must be posted for its
   library's goal, citing the release's cited attestation (a library with no goal backs no
   bounty itself). Otherwise the run fails;
4. with `publish`, creates the release. It submits nothing to the chain.

## Checking it yourself

The batches can be rebuilt byte for byte from a fresh export of the same nodes:
`scripts/toaster/hunt/hunt.py replay RELEASE LIB NODES WORK` writes them in
`scripts/attest-batches.py`'s layout. Attesting them in witness-sim gives the release's claims,
and so service 7's attestation ids. `scripts/toaster/hunt/test-fake.sh` does this for `picoalloc`
before hunting a sim copy of its bounty.
