# witness

A "find the witness" bounty market as a JAM service. A maker posts `check(params, x) -> bool`
with a reward. Hunters commit to an `x` and then reveal it. Among the reveals that pass the
check, the one whose commitment reached the chain first wins.

Rewards are paid in stablecoins (or any asset) held by token services: users deposit them by a
transfer from the token service and withdraw them by a transfer back. Witness's own native
balance only pays for the records it stores. See [docs/design/tokens.md](docs/design/tokens.md).
Not yet deployed anywhere with real money: test builds also have a faucet (`Mint`).

## How it works

| Op | Refine (in-core, stateless) | Accumulate (on-chain) |
|---|---|---|
| deposit (a transfer in) | — | from an accepted token service, with a deposit memo: credit the account it names with that asset |
| `Withdraw` | verify the account's signature | debit the asset; send its token service a transfer whose memo pays the payee there |
| `Mint` | — | test builds: credit the test asset (a faucet, at most `MAX_MINT`) |
| `CreateBounty` | verify the maker's Ed25519 signature | check nonce, balance and limits, that the bounty's asset is accepted, and that cited attestations exist and are by the bounty's check with one set of params; escrow the reward; store the bounty |
| `Commit` | verify the committer's signature | the bounty takes commitments; lock the configured commit deposit (in the fee asset); record the slot of `blake2b(bounty_id, x, hunter, salt)` |
| `Reveal` | read the check blob, the plain blobs and the trusted subjects the reveal cites (the bounty's, and any more it adds) from the work item's extrinsics, checking each against the bounty's hashes or its claim's Merkle root; run the check on them (attested ones marked trusted), `params` and `x` in an inner PVM with the bounty's `check_gas` | the terms match, the cited attestations were recorded, and the commitment is older than this slot, by the bounty's disclosure window if it has one, and made before expiry. The first valid reveal opens the claim window, and later ones replace the leader if their commitment is earlier. Refund the deposit |
| `Finalize` | — | once the claim window has closed, pay the leader |
| `Reclaim` | verify the maker's signature | if no one revealed by `expiry + disclosure window + REVEAL_GRACE`, refund the maker |
| `Release` | — | delete a commitment (named by bounty and hash) that can no longer be revealed; its deposit stays forfeit |
| `Attest` | read the check, the subjects and the trusted subjects it cites from the extrinsics, and compute the subjects' Merkle root; verify the attester's signature over the claim; run the check in attest mode with the attester's witness | the parents were recorded and this wasn't yet; take the configured attest deposit (in the fee asset); record the attestation |
| `Propose` | verify the admin's signature | record an admin action (a configuration, a new admin, or an upgrade, whose code it solicits) to take effect after `ADMIN_DELAY`; the first configuration applies at once |
| `Apply` | — | carry out a proposal whose delay has passed |
| `Cancel` | verify the admin's signature | drop a proposal |

Blobs travel with the ops that use them: a work item's payload is the op, and its extrinsics
hold the blobs it names: the check blob as an extrinsic of its own (the work package commits to
its hash), and the rest in extrinsics that are each a SCALE `Vec<Vec<u8>>` of blobs, named as
`BlobAt { extrinsic, index }`.
So state holds only records: bounties, commitments, accounts, balances and attestations. See
[docs/design/extrinsics.md](docs/design/extrinsics.md).

### Attestations

An attestation records that a check, run once in attest mode with some params, accepted every
subject in a list, given trusted subjects of earlier attestations: "check C verified B₁…Bₙ, given
subjects of P₁…Pₖ". The claim commits to the subjects by the root of a binary Merkle tree over
them (`witness_types::merkle`) and their count; a subject's hash is that of its own bytes. The
attestation's id hashes the check, the params hash, the subjects' root and count, and
`parents_root`, the hash of its parents' ids (sorted and deduplicated). Later work can then rely on any one of B₁…Bₙ
without verifying it again:

- **Attestations form a DAG.** An attestation can trust subjects of any number of earlier ones,
  and they of others. A library is attested in batches, each batch trusting the subjects it
  uses, and independent batches in parallel.
- **Bounties cite subjects.** A bounty's blobs can be `Attested { attestation, entry }`, subject
  `entry` of an attestation, mixed with plain blobs. Its check receives the
  attested subjects marked trusted, and can skip whatever its attest mode verified. For a Lean
  checker that means type-checking the statement's environment once, instead of on every reveal.
- **Reveals can trust more.** A reveal must trust its bounty's attested subjects, and may add
  others its witness uses that the bounty didn't name (library a proof relies on, say).

Trust needs no context: an attestation is only recorded once its parents were, so by induction a
recorded attestation rests on subjects that were all checked. A check over a positional format,
where an item only means something after a given prefix, can still enforce that itself: it sees
each blob's hash, so an item can name the hash of the one it follows.

A check only ever trusts its own attestations. Every attestation an op cites is by the check being
run, all with one set of params (for `Attest`, its own params), and a bounty may only cite its own
check's attestations. So a trusted blob always means "my own attest mode accepted this", and an
attester can't slip in a subject verified by a lenient check, or by this check with lenient params.

Ops cite attestations compactly. Refine can't read state, so `Attest` and `Reveal` carry the
claims they rely on (check, params hash, subjects' root and count, parents root), each once, and
refer to trusted subjects as `TrustedRef { claim, entry, blob, path }`: subject `entry` of the
claim, its bytes at `blob` in the extrinsics, and its Merkle path. Refine checks the path against
the claim's root, so it hashes only the subjects it uses. Accumulate makes sure the claims were
really recorded, by id.

Accumulating an attestation stores one small record, however many subjects it has. The
subjects live off chain, with whoever cites them (for Lean, anyone can rebuild them from source);
losing them costs liveness, never soundness, since refine checks every byte it's given. The
attester's witness is the evidence (a batch's proofs, say) and is not part of the claim.
Attestations are permanent. See [docs/design/attestation-dag.md](docs/design/attestation-dag.md).

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

### Disclosure windows

Some witnesses shouldn't be published the moment they're found: a report of a bug in a live
protocol (see [witness-evm](https://github.com/ascrivener/witness-evm)) reveals how to exploit it,
and JAM's data availability keeps a work package's extrinsics fetchable for weeks. A bounty can
set a `disclosure_window` (up to `MAX_DISCLOSURE_WINDOW`, about 90 days) for them:

1. The hunter commits on chain, then shows the maker `x` (and the salt) privately. The maker can
   check it against the commitment and run the check off chain.
2. The maker has the window to fix the bug. No reveal of that commitment is accepted before the
   window has passed since it was committed.
3. The hunter reveals, and the bounty pays as any other. A check that judges `x` against a fixed
   snapshot (the state before the fix) still accepts it, so fixing the bug can't void the report.

Every commitment waits the same window, so an earlier commitment is always revealable first: if
the disclosure leaks, or the maker tries to claim the report themselves, their later commitment
still loses. The reward stays escrowed until `expiry + disclosure_window + REVEAL_GRACE`, so a
commitment made just before expiry still gets its window and the grace. With a window of 0 (the
default) a bounty works as before.

### Bound claims

A reveal can win by *trusting* attested work rather than carrying it: a refutation attested in
chunks pays out once a reveal trusts the attested empty clause (see
[witness-sat](https://github.com/ascrivener/witness-sat)), whatever its witness. That breaks
commit-reveal. The work goes public chunk by chunk as it's attested, and anyone who committed
earlier, to any witness, before the work existed, can reveal trusting it and win.

A bounty can set `bind_claim` (`witness create --bind-claim`). A reveal may then trust subjects of
at most one attestation its bounty doesn't cite, and its witness must begin with that
attestation's id (refine reports whether it does; accumulate holds the bounty to it). An
attestation's id covers its parents' ids, so it's fixed by the whole chain of work beneath it
and can't be known before that work exists:

1. The hunter builds their attestations' claims off chain (`witness attest` only builds the op),
   reads the id of the one their reveal will trust (`witness claim-id`), and commits to a
   witness beginning with it, before attesting anything.
2. They attest the work, then reveal trusting it.

Nobody who committed before the hunter can have committed to that id, and anyone who commits to
it after seeing it is later than the hunter. A reveal trusting no attestation beyond the
bounty's carries its work in its witness, which its commitment binds already, so it needs no
binding. The limit of one keeps a speculator from naming an attestation of their own, made in
advance, while trusting the hunter's too. Checks for such bounties take the id as part of the
witness (sat-check ignores the witness once the empty clause is trusted).

`rules/src/tests.rs` covers the attack without the option, and with it.

### Spam

Each commitment locks the configured commit deposit, and only a valid reveal gets it back. Each
attestation pays the attest deposit, for good. Both are in one fee asset the configuration
names: they exist because every record is storage witness's sponsor pays for.
Accumulate checks the service can pay the storage deposit for an operation before writing
anything. An operation it can't store is rejected whole, and the other work items in the same
batch still go through.

### Checks

Check blobs are JAM program blobs, as `cargo jam-build` writes them for an authorizer-type crate:
conventional metadata, then a standard program (GP appendix A.7). Refine skips the metadata and
builds the inner PVM's memory and registers exactly as `Y(p, args)` would
([service/src/check_vm.rs](service/src/check_vm.rs), [types/src/program.rs](types/src/program.rs)).
The arguments (interface version 2) are:

```
E1(2) ++ E1(mode) ++ E4(n) ++ [E1(trusted) ++ hash ++ E4(|data|) ++ data]^n ++ E4(|params|) ++ params ++ x
```

`mode` is 0 to reveal and 1 to attest. The `n` blobs are the trusted subjects, in the order the
op cites them, then, when revealing, the bounty's plain blobs, or, when attesting, the subjects to
attest, untrusted, with the attester's witness as `x`. At most `MAX_BLOBS` blobs and
`MAX_BLOBS_LEN` bytes in all. `witness_check` parses the arguments back. Halting with 1 in `φ7` means true. Anything else
(0, panic, page fault, out of gas, any host call but `grow_heap`) means false. `check_gas` is
capped at `MAX_CHECK_GAS` (5×10⁹, the full spec's refine gas), and refine lends the inner VM at
most what it can spare of it, keeping a reserve for its own work after.

A check may call `grow_heap` (host call 1). Refine maps the pages it asks for, after the check's
read-write data and short of its stack, charges the check the gas `grow_heap` costs a service, and
resumes it. Everything the check uses, arguments included, must fit in `MAX_CHECK_PAGES` (128 MiB);
past that the call returns the heap's current end and the allocation fails.

Because the check gets the bounty's `params` and blobs, one check blob serves many bounties.
`checks/blake2b-preimage` takes the target hash as its params, so any number of "find the
preimage" bounties share one on-chain blob. `checks/dictionary` reads a dictionary blob and builds
a set of its words on the heap, so bounties at different difficulties share both blobs.
`checks/sorted-words` attests batches of word volumes (sorted, after the words it trusts) once, then
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
tools/witness-sim/         runs ops natively in place of a testnet, checks in PolkaVM
tools/mock-token/          a test-only token service's rules: deposits into and withdrawals from
                           witness, as a real one would send and take them
tools/mock-token-service/  that, as a JAM service
tools/full-gas-spec/       raises a PolkaJam dev chain spec's refine limit to the full spec's
scripts/e2e.sh             end-to-end test on a local PolkaJam testnet
scripts/jam-submit.py      submits work packages with extrinsics, several items to one
scripts/attest-batches.py  attests a DAG of batches in parallel: several attesters, several batches
                           to a package
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

The end-to-end script runs in seconds against `tools/witness-sim`, which takes the `jamt`
commands the script uses and runs each op through the service's rules natively, with extrinsics
and storage in memory and checks in PolkaVM. It charges checks the gas PolkaJam v0.1.29 does
(PolkaVM's full cost model with L2 cache hits matched it exactly on the sample checks), but not
refine or accumulate themselves, and a slot passes with every op, so the testnet stays the judge
of what fits and of the node's behavior. Use it while iterating:

```bash
WITNESS_SIM=1 scripts/e2e.sh          # the full run, in about 7 seconds
```

CI (`.github/workflows/ci.yml`) runs the unit tests and builds the blobs. Against a testnet the
end-to-end script needs a PolkaJam release, so run it locally. It submits every item with
`scripts/jam-submit.py`, since `jamt item` can't attach the extrinsics reveals and attestations
carry. It starts its own testnet, deploys, and checks the
chain state at each step. It has two modes:

- **`--quick`** (about 4 minutes): two bounties, from create to a reveal, one of them on a check
  that reads a blob and grows its heap. It exercises everything that touches the node: deploy,
  refine and accumulate, extrinsics, the inner PVM and its heap. Run it before opening
  any PR that changes code.
- **Full** (about 10 minutes, mostly waiting out claim windows): four bounties, adding the
  front-run, finalize, reclaim, release and deposit checks. Run it when changing `service/`,
  `check_vm`, the build setup, or anything about timing (windows, expiry, grace), and before a
  release. The bounty logic itself is covered by the unit tests in `rules/`, so a rules-only
  change needs only those plus `--quick`.

```bash
POLKAJAM_DIR=../polkajam-releases/polkajam-v0.1.29-macos-aarch64 scripts/e2e.sh --quick
```

On Linux without IPv6 (some containers), the nodes need `--listen-ip 0.0.0.0 --external-ip
127.0.0.1`. The testnet doesn't pass node flags through, so put a wrapper script named `polkajam`
that adds them next to copies of `polkajam-testnet` and `jamt`, and point `POLKAJAM_DIR` at that
directory.

The PVM recompiler's sandbox needs `userfaultfd`. Where unprivileged processes may not create one
(work packages then fail with `AuthorizationInvalid`), allow it with
`sysctl vm.unprivileged_userfaultfd=1`. `--pvm-backend interpreter` also works, but it's too slow
for big refines: guarantors drop reports whose refine takes more than a few seconds, which the
interpreter reaches at under 10⁹ gas.

The testnet's dev chain uses PolkaJam's "tiny" protocol parameters, with a refine limit of 10⁹
gas; the full spec allows 5×10⁹. To test with the full limit, dump the dev spec, raise its limit
with `tools/full-gas-spec` (a standalone crate), and have the wrapper swap the testnet's
`--chain=dev:...` argument for the patched spec:

```bash
polkajam --chain dev:40000 dump-spec dev.json
(cd tools/full-gas-spec && cargo run --release -- ../../dev.json ../../full-gas.json)
# in the wrapper: replace an argument --chain=dev:* with --chain=/path/to/full-gas.json
```

## Checks built on witness

- **Lean 4 proofs:** [witness-lean](https://github.com/ascrivener/witness-lean) checks Lean proofs
  with an independent kernel, attesting library once (Mathlib's, say) and binding a
  solver's proof to the bounty's statement. It has proved "there are infinitely many primes" on
  a local testnet, from Mathlib, in 66 attested layers.

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
verifies `input.subjects()` (the untrusted blobs) given `input.trusted()`. In reveal mode it
can rely on trusted blobs, which its own attest mode accepted, and must verify untrusted ones. With `witness-check`'s `alloc` feature the check gets a global allocator, so `alloc`
types (`Vec`, `BTreeMap`) work. Checks get no other host calls, so no logging or I/O. The stack is
8 KiB unless the check raises it with `polkavm_derive::min_stack_size!`.

## Using it by hand

`scripts/e2e.sh` is the worked example. In short, with `W=./target/debug/witness`, `SVC` the
id `jamt create-service out/witness-service.jam 10000000000 --min-memo-gas 300000` produced
(the memo gas is `DEPOSIT_GAS`, what a deposit must carry), and
`SUBMIT="python3 scripts/jam-submit.py"`, which takes extrinsic files after the payload
(`jamt item` can't attach extrinsics; `witness-sim item` takes them the same way):

```bash
# configure first, as the admin (test builds: --seed admin): the first configuration applies at once
$SUBMIT $SVC $($W propose --service $SVC --nonce 0 --token-services $TOKEN_SVC --fee-asset test --commit-deposit 10 --attest-deposit 10)
$SUBMIT $SVC $($W mint --to alice --amount 1000)
$SUBMIT $SVC $($W create --service $SVC --maker alice --nonce 0 --check out/blake2b-preimage-check.jam --params-blake2b "open sesame" --reward 500 --check-gas 10000000 --expiry $(( $(jamt inspect slot) + 100 )))
$SUBMIT $SVC $($W mint --to bob --amount 100)
$SUBMIT $SVC $($W commit --service $SVC --bounty 0 --hunter bob --nonce 0 --salt 0x0b0b --witness-str "open sesame")
# a reveal writes its extrinsics (the check, the blobs) to a directory, to send with it
$SUBMIT $SVC $($W reveal --bounty 0 --check out/blake2b-preimage-check.jam --params-blake2b "open sesame" --check-gas 10000000 --hunter bob --salt 0x0b0b --witness-str "open sesame" --extrinsics x) x/*
# a bounty with extra blobs names them, in order, on create and on every reveal
printf 'open\nsesame\n' > words.txt
$SUBMIT $SVC $($W create --service $SVC --maker alice --nonce 1 --check out/dictionary-check.jam --params 0x00 --blobs words.txt --reward 100 --check-gas 10000000 --expiry $(( $(jamt inspect slot) + 100 )))
# attest a list of blobs, then cite its subjects in a bounty; the claim file keeps the subjects,
# which citing them needs
printf '%-16s' apple banana cherry > volume1.bin
printf '%-16s' grape lemon > volume2.bin
$SUBMIT $SVC $($W mint --to pat --amount 100)
$SUBMIT $SVC $($W attest --service $SVC --attester pat --nonce 0 --check out/sorted-words-check.jam --subjects volume1.bin,volume2.bin --check-gas 10000000 --claim-out batch.claim --extrinsics x) x/*
# a later attestation trusts subjects of earlier ones: --trust batch.claim:1 (entry 1, volume 2)
$SUBMIT $SVC $($W create --service $SVC --maker alice --nonce 2 --check out/sorted-words-check.jam --params 0x00 --blobs batch.claim:0,batch.claim:1 --reward 100 --check-gas 10000000 --expiry $(( $(jamt inspect slot) + 100 )))
# after the claim window (30 slots by default)
$SUBMIT $SVC $($W finalize --bounty 0)
# a library of many batches, each trusting earlier ones: lay them out as batch-N.subjects,
# batch-N.trust (citing batch-M.claim) and batch-N.witness, and attest them in parallel
python3 scripts/attest-batches.py batches/ --witness $W --service $SVC --check out/sorted-words-check.jam --check-gas 10000000 --attesters pat,quinn
# a stablecoin: the test token service ($TOKEN_SVC) mints alice some, she moves 600 into witness,
# and later withdraws 100 back out
$SUBMIT $TOKEN_SVC $($W token-faucet --to alice --asset 1 --amount 1000)
$SUBMIT $TOKEN_SVC $($W token-send --from alice --asset 1 --amount 600 --to-service $SVC --to alice)
$SUBMIT $SVC $($W create --service $SVC --maker alice --nonce 3 --check out/blake2b-preimage-check.jam --params-blake2b "open sesame" --asset $TOKEN_SVC:1 --reward 500 --check-gas 10000000 --expiry $(( $(jamt inspect slot) + 100 )))
$SUBMIT $SVC $($W withdraw --service $SVC --account alice --nonce 4 --asset $TOKEN_SVC:1 --amount 100 --to alice)
```

Wait a block (about 6 s) after deploying before sending items.

To read state, get the raw value with `jamt inspect storage --raw $SVC $($W key --account bob)`,
then decode it with `$W decode --account <value>`. The same works for `--bounty`, for balances
with `key --balance WHO --asset A` and `decode --balance`, for `--config` and `--proposal N`, and for
commitments with `key --bounty ID --commitment HEX` and `decode --commitment <value>`, and for
attestations with `key --attestation CLAIM` and `decode --attestation <value>`. The node logs (target `witness`) show each refine result, and why accumulate did
or did not apply it.

## Known gaps

- No real token service speaks witness's memos yet; `mock-token-service` stands in. One that
  doesn't (Asset Hub on JAM, say) would need a thin adapter service in front of it.
- Storage is sponsored: witness records native balance sent along with deposits as storage
  credit, but doesn't spend it yet.
- While a person holds the admin key, users trust them with the rules, and so with their
  balances; the timelock gives them time to withdraw. Test builds have a faucet: a deployment
  with real money builds witness-service without the `faucet` feature.
- One op per work item, and no batching. Signed ops take sequential nonces, so one account can't
  have two signed ops in flight at once.
- The latest Gray Paper (0.8.0 on `main`) replaces `machine(code, pc)` with `compile` (which can
  load a preimage by hash directly) followed by `machine(handle, pc)`. SDK 0.1.29 still exposes
  `machine(code, pc)`, so the service follows the SDK. Revisit when the SDK moves.
- A reveal's or attestation's witness in the work-item payload is limited to `MAX_WITNESS_LEN`
  (64 KiB). It can be an extrinsic instead (`Witness::Extrinsic`), limited only by the package's
  input; the CLI puts any over 1 KiB there.
- The limits (`MAX_CHECK_LEN`, `MAX_CHECK_PAGES`, `MAX_CHECK_GAS`, `MAX_BLOBS_LEN`) are constants.
- Closed bounties stay in storage as a record. Only their commitments are cleaned up.
- Attestations are never released.
- A check only trusts its own attestations. Building on another checker's attested layers would
  need the check to learn which checker made each one.
- Attestations form linear chains, and a check receives a subject's whole chain, so a refine must
  load (and typically parse) everything before the subject. A chain's total size is bounded by
  what one refine can process. Libraries too big for that need attestations that form a DAG, with
  each subject naming only what it uses.
