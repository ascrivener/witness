# witness

A "find the witness" bounty market as a JAM service. A maker posts `check(params, x) -> bool`
with a reward. Hunters commit to an `x` and then reveal it. Among the reveals that pass the
check, the one whose commitment reached the chain first wins.

Prototype: rewards are points from a faucet (`Mint`), not tokens.

## How it works

| Op | Refine (in-core, stateless) | Accumulate (on-chain) |
|---|---|---|
| `Mint` | — | credit points (faucet, at most `MAX_MINT`) |
| `CreateBounty` | verify the maker's Ed25519 signature | check nonce, balance and limits, and that cited attestations exist and are by the bounty's check; debit the reward; solicit the check blob and the bounty's plain blobs, except those already held; store the bounty |
| `Commit` | verify the committer's signature | the bounty takes commitments; debit `COMMIT_DEPOSIT`; record the slot of `blake2b(bounty_id, x, hunter, salt)` |
| `Reveal` | look up the check blob and the extra blobs; run the check on them (attested ones marked trusted), `params` and `x` in an inner PVM with the bounty's `check_gas` | the terms match and the commitment is older than this slot and made before expiry. The first valid reveal opens the claim window, and later ones replace the leader if their commitment is earlier. Refund the deposit |
| `Finalize` | — | once the claim window has closed, pay the leader and release the bounty's blobs |
| `Reclaim` | verify the maker's signature | if no one revealed by `expiry + REVEAL_GRACE`, refund the maker and release the bounty's blobs |
| `Release` | — | delete a commitment (named by bounty and hash) that can no longer be revealed; its deposit stays forfeit |
| `Pin` | verify the owner's signature | debit `PIN_DEPOSIT`; hold the preimage for good (solicit it unless already held) |
| `Attest` | verify the attester's signature; look up the check, the parents' subjects and the subject; run the check in attest mode | the parents were attested and this wasn't yet; debit `ATTEST_DEPOSIT`; hold the subject for good; record the attestation |

### Attestations

An attestation records that a check, run once in attest mode with some params, accepted a subject
blob given the subjects of its parent attestations: "check C verified B, given P". Its id hashes
all of that, so the same blob verified by another check, other params or other parents is another
attestation. Later work can then rely on B without verifying it again:

- **Bounties cite them.** A bounty's blob can be `Attested(id)` instead of a plain preimage. Its
  check receives the subject marked trusted, and can skip whatever its attest mode verified.
  For a Lean checker that means type-checking the statement environment once, instead of on
  every reveal.
- **Attestations build on each other.** An attestation names parents; the check receives their
  subjects trusted and verifies only the new layer. A large library can be attested layer by
  layer, each in one refine.

A check only ever trusts its own attestations. Parents must be by the same check with the same
params, and a bounty may only cite attestations by its own check. So a trusted blob always means
"my own attest mode accepted this", and an attester can't slip in a layer verified by a lenient
check, or by this check with lenient params. A bounty's maker chooses which attestations it cites,
and so which params they were made with.

Refine can't read state, so `Attest` and `Reveal` carry the claims of the attestations they rely
on (check, params hash, subject, parents). Refine runs the check on the claimed subjects, and
accumulate makes sure the claims' ids were really recorded: for `Attest` by looking the parents
up, for `Reveal` by matching the bounty's terms, which were checked when it was created.

The subject must be on chain before refine can look it up, so it's pinned first (`Pin`), and
the check blob too unless a bounty already holds it. Pins and attestations are permanent for now,
and so are the preimages they hold.
### Front-running

Revealing `x` publishes it, and guarantors see it first. Anyone who copies `x` can only commit
after seeing it, so the original commitment is always earlier. Getting your reveal on chain first
doesn't help either: every valid reveal during the claim window competes, and the earliest
commitment wins. Ties within a slot go to the lower commitment hash. The remaining assumption is
that the original reveal can't be kept off chain for the whole claim window (at least
`MIN_CLAIM_WINDOW` = 30 slots, set per bounty), which would take sustained censorship across
guarantor rotations. `rules/src/tests.rs` covers both cases.

Commitments are stored per bounty. A commitment hash hides which bounty it is for, so with one
global key someone could copy a hunter's in-flight commitment onto another bounty first and block
the real one. Keyed by bounty, the copy sits apart where no reveal can ever match it.

### Spam

Each commitment locks `COMMIT_DEPOSIT` points, and only a valid reveal gets them back.
Accumulate checks the service can pay the storage deposit for an operation before writing
anything. An operation it can't store is rejected whole, and the other work items in the same
batch still go through. Check blobs and extra blobs are reference-counted and forgotten when no
unfinished bounty uses them.

### Checks

Check blobs are JAM program blobs, as `cargo jam-build` writes them for an authorizer-type crate:
conventional metadata, then a standard program (GP appendix A.7). Refine skips the metadata and
builds the inner PVM's memory and registers exactly as `Y(p, args)` would
([service/src/check_vm.rs](service/src/check_vm.rs), [types/src/program.rs](types/src/program.rs)).
The arguments (interface version 2) are:

```
E1(2) ++ E1(mode) ++ E4(n) ++ [E1(trusted) ++ hash ++ E4(|data|) ++ data]^n ++ E4(|params|) ++ params ++ x
```

`mode` is 0 to reveal and 1 to attest. When revealing, the `n` blobs are the bounty's extra blobs,
in order, with `trusted` set on attested ones. When attesting, they are the parents' subjects,
trusted, then the subject, untrusted, and `x` is empty. At most `MAX_BLOBS` blobs and
`MAX_BLOBS_LEN` bytes in all. `witness_check` parses the arguments back. Halting with 1 in `φ7` means true. Anything else
(0, panic, page fault, out of gas, any host call but `grow_heap`) means false. `check_gas` is
capped at `MAX_CHECK_GAS` and passed to `invoke` as the inner VM's limit.

A check may call `grow_heap` (host call 1). Refine maps the pages it asks for, after the check's
read-write data and short of its stack, charges the check the gas `grow_heap` costs a service, and
resumes it. Everything the check uses, arguments included, must fit in `MAX_CHECK_PAGES` (16 MiB);
past that the call returns the heap's current end and the allocation fails.

Because the check gets the bounty's `params` and blobs, one check blob serves many bounties.
`checks/blake2b-preimage` takes the target hash as its params, so any number of "find the
preimage" bounties share one on-chain blob. `checks/dictionary` reads a dictionary blob and builds
a set of its words on the heap, so bounties at different difficulties share both blobs.
`checks/sorted-words` attests word volumes (sorted, after their parents' words) once, then
binary-searches trusted volumes on each reveal instead of checking them in full.

## Layout

```
types/                     protocol types, constants, standard-program parser/initializer (no_std)
rules/                     refine and accumulate rules, host-independent and unit-tested
service/                   the JAM service: host-call glue around `rules` (jam-pvm-common 0.1.29)
check/                     `declare_check!` and `declare_full_check!` for writing checks, and an allocator
checks/factor/             sample: x is a nontrivial factor of N (params: N)
checks/blake2b-preimage/   sample: x is a Blake2b-256 preimage of H (params: H)
checks/dictionary/         sample: x is dictionary words hashing to D leading zero bits (blob: the
                           dictionary; params: D)
checks/sorted-words/       sample that attests: as dictionary, over attested sorted word volumes
tools/witness-cli/         builds work-item payloads as hex, and reads state (`witness`)
scripts/e2e.sh             end-to-end test on a local PolkaJam testnet
```

## Build and test

Everything builds on stable Rust (1.86 or newer). PVM blobs are built with Parity's
[`cargo-jam-build`](https://crates.io/crates/cargo-jam-build), which needs `rust-src`:

```bash
rustup component add rust-src
```

```bash
cargo install cargo-jam-build --version 0.1.29 --locked
```

Unit tests cover the rules, the program layout and the checks:

```bash
cargo test
```

Build the service and the sample checks into `out/` (as `.jam` files):

```bash
cargo jam-build --out-dir out
```

`witness hash --check out/factor-check.jam` prints the check hash a bounty on that blob uses.

CI (`.github/workflows/ci.yml`) runs the unit tests and builds the blobs. The end-to-end script
needs a PolkaJam release, so run it locally. It starts its own testnet, deploys, and checks the
chain state at each step. It has two modes:

- **`--quick`** (about 4 minutes): two bounties, from create to a reveal, one of them on a check
  that reads a blob and grows its heap. It exercises everything that touches the node: deploy,
  refine and accumulate, the preimage lookups, the inner PVM and its heap. Run it before opening
  any PR that changes code.
- **Full** (about 10 minutes, mostly waiting out claim windows): four bounties, adding the
  front-run, finalize, reclaim, release, blob release and deposit checks. Run it when changing `service/`,
  `check_vm`, the build setup, or anything about timing (windows, expiry, grace), and before a
  release. The bounty logic itself is covered by the unit tests in `rules/`, so a rules-only
  change needs only those plus `--quick`.

```bash
POLKAJAM_DIR=../polkajam-releases/polkajam-v0.1.29-macos-aarch64 scripts/e2e.sh --quick
```

On Linux without IPv6 (some containers), the nodes need `--listen-ip 0.0.0.0 --external-ip
127.0.0.1`, and if the PVM recompiler can't run there, `--pvm-backend interpreter`. The testnet
doesn't pass node flags through, so put a wrapper script named `polkajam` that adds them next to
copies of `polkajam-testnet` and `jamt`, and point `POLKAJAM_DIR` at that directory.

## Writing a check

```rust
#![cfg_attr(not(test), no_std)]
fn check(params: &[u8], x: &[u8]) -> bool { /* ... */ }
witness_check::declare_check!(check);
```

The crate depends on `witness-check` and `polkavm-derive`, and declares
`[package.metadata.jam] type = "authorizer"` so `cargo jam-build` builds it with the single entry
point a check needs. A check declared this way ignores the bounty's blobs, and is false in any
mode but reveal.

A check that reads blobs takes the whole input instead:

```rust
fn check(input: &witness_check::Input) -> bool {
    let Some(environment) = input.blob(0) else { return false };
    /* ... input.mode, input.params, input.witness, environment.data ... */
}
witness_check::declare_full_check!(check);
```

It should return false for any mode it doesn't handle. A check that supports attest mode
verifies `input.subject()` (the last blob) given the others, which are trusted. In reveal mode it
can rely on trusted blobs, which its own attest mode accepted, and must verify untrusted ones. With `witness-check`'s `alloc` feature the check gets a global allocator, so `alloc`
types (`Vec`, `BTreeMap`) work. Checks get no other host calls, so no logging or I/O. The stack is
8 KiB unless the check raises it with `polkavm_derive::min_stack_size!`.

## Using it by hand

`scripts/e2e.sh` is the worked example. In short, with `W=./target/debug/witness` and `SVC` the
id `jamt create-service out/witness-service.jam 10000000000` produced:

```bash
jamt item $SVC $($W mint --to alice --amount 1000)
jamt item $SVC $($W create --service $SVC --maker alice --nonce 0 --check out/blake2b-preimage-check.jam --params-blake2b "open sesame" --reward 500 --check-gas 10000000 --expiry $(( $(jamt inspect slot) + 100 )))
jamt provide $SVC out/blake2b-preimage-check.jam
jamt item $SVC $($W mint --to bob --amount 100)
jamt item $SVC $($W commit --service $SVC --bounty 0 --hunter bob --nonce 0 --salt 0x0b0b --witness-str "open sesame")
jamt item $SVC $($W reveal --bounty 0 --check out/blake2b-preimage-check.jam --params-blake2b "open sesame" --check-gas 10000000 --hunter bob --salt 0x0b0b --witness-str "open sesame")
# a bounty with extra blobs names them, in order, on create and on every reveal; provide each one
printf 'open\nsesame\n' > words.txt
jamt item $SVC $($W create --service $SVC --maker alice --nonce 1 --check out/dictionary-check.jam --params 0x00 --blobs words.txt --reward 100 --check-gas 10000000 --expiry $(( $(jamt inspect slot) + 100 )))
jamt provide $SVC out/dictionary-check.jam
jamt provide $SVC words.txt
# attest a blob (pinned and provided first, as is the check), then cite the claim in a bounty
printf '%-16s' apple banana cherry > volume1.bin
jamt item $SVC $($W mint --to pat --amount 100)
jamt item $SVC $($W pin --service $SVC --owner pat --nonce 0 --blob out/sorted-words-check.jam)
jamt item $SVC $($W pin --service $SVC --owner pat --nonce 1 --blob volume1.bin)
jamt provide $SVC out/sorted-words-check.jam; jamt provide $SVC volume1.bin
jamt item $SVC $($W attest --service $SVC --attester pat --nonce 2 --check out/sorted-words-check.jam --subject volume1.bin --check-gas 10000000 --claim-out volume1.claim)
jamt item $SVC $($W create --service $SVC --maker alice --nonce 2 --check out/sorted-words-check.jam --params 0x00 --blobs claim:volume1.claim --reward 100 --check-gas 10000000 --expiry $(( $(jamt inspect slot) + 100 )))
# after the claim window (30 slots by default)
jamt item $SVC $($W finalize --bounty 0)
```

Wait a block (about 6 s) after deploying, and after `provide`, before sending items that depend on
it. Refine reads the chain as of the package's anchor block, so an anchor that's too early fails
with `CheckUnavailable`.

To read state, get the raw value with `jamt inspect storage --raw $SVC $($W key --account bob)`,
then decode it with `$W decode --account <value>`. The same works for `--bounty`, and for
commitments with `key --bounty ID --commitment HEX` and `decode --commitment <value>`, and for
attestations with `key --attestation CLAIM` and `decode --attestation <value>`. The node logs (target `witness`) show each refine result, and why accumulate did
or did not apply it.

## Known gaps

- Points are unbacked: anyone can `Mint`, so the commit deposit stops casual spam but not someone
  with a faucet. There are no withdrawals. Real value would come from service transfers.
- One op per work item, and no batching. Signed ops take sequential nonces, so one account can't
  have two signed ops in flight at once.
- The latest Gray Paper (0.8.0 on `main`) replaces `machine(code, pc)` with `compile` (which can
  load a preimage by hash directly) followed by `machine(handle, pc)`. SDK 0.1.29 still exposes
  `machine(code, pc)`, so the service follows the SDK. Revisit when the SDK moves.
- Witnesses come from the work-item payload, so they're limited to `MAX_WITNESS_LEN` (64 KiB).
  Taking them from extrinsic data would raise that to the package's input limit.
- The limits (`MAX_CHECK_LEN`, `MAX_CHECK_PAGES`, `MAX_CHECK_GAS`, `MAX_BLOBS_LEN`) are constants.
- Closed bounties stay in storage as a record. Only their commitments and check blobs are cleaned
  up.
- Pins and attestations, and the preimages they hold, are never released.
- A check only trusts its own attestations. Building on another checker's attested layers would
  need the check to learn which checker made each one.
