# witness

A "find the witness" bounty market as a JAM service. A maker posts `check(params, x) -> bool`
with a reward. Hunters commit to an `x` and then reveal it. Among the reveals that pass the
check, the one whose commitment reached the chain first wins.

Prototype: rewards are points from a faucet (`Mint`), not tokens.

## How it works

| Op | Refine (in-core, stateless) | Accumulate (on-chain) |
|---|---|---|
| `Mint` | — | credit points (faucet, at most `MAX_MINT`) |
| `CreateBounty` | verify the maker's Ed25519 signature | check nonce, balance and limits; debit the reward; solicit the check blob unless another bounty already uses it; store the bounty |
| `Commit` | verify the committer's signature | the bounty takes commitments; debit `COMMIT_DEPOSIT`; record the slot of `blake2b(bounty_id, x, hunter, salt)` |
| `Reveal` | look up the check blob; run `check(params, x)` in an inner PVM with the bounty's `check_gas` | the terms match and the commitment is older than this slot and made before expiry. The first valid reveal opens the claim window, and later ones replace the leader if their commitment is earlier. Refund the deposit |
| `Finalize` | — | once the claim window has closed, pay the leader and release the check blob |
| `Reclaim` | verify the maker's signature | if no one revealed by `expiry + REVEAL_GRACE`, refund the maker and release the check blob |
| `Release` | — | delete a commitment that can no longer be revealed; its deposit stays forfeit |

### Front-running

Revealing `x` publishes it, and guarantors see it first. Anyone who copies `x` can only commit
after seeing it, so the original commitment is always earlier. Getting your reveal on chain first
doesn't help either: every valid reveal during the claim window competes, and the earliest
commitment wins. Ties within a slot go to the lower commitment hash. The remaining assumption is
that the original reveal can't be kept off chain for the whole claim window (at least
`MIN_CLAIM_WINDOW` = 30 slots, set per bounty), which would take sustained censorship across
guarantor rotations. `rules/src/tests.rs` covers both cases.

### Spam

Each commitment locks `COMMIT_DEPOSIT` points, and only a valid reveal gets them back.
Accumulate checks the service can pay the storage deposit for an operation before writing
anything. An operation it can't store is rejected whole, and the other work items in the same
batch still go through. Check blobs are reference-counted and forgotten when no unfinished bounty
uses them.

### Checks

Check blobs are JAM program blobs, as `cargo jam-build` writes them for an authorizer-type crate:
conventional metadata, then a standard program (GP appendix A.7). Refine skips the metadata and
builds the inner PVM's memory and registers exactly as `Y(p, args)` would
([service/src/check_vm.rs](service/src/check_vm.rs), [types/src/program.rs](types/src/program.rs)).
The arguments are `E4(|params|) ++ params ++ x`, and `declare_check!` splits them back apart.
Halting with 1 in `φ7` means true. Anything else (0, panic, page fault, out of gas, any host call)
means false. `check_gas` is capped at `MAX_CHECK_GAS` and passed to `invoke` as the inner VM's
limit.

Because the check gets the bounty's `params`, one check blob serves many bounties.
`checks/blake2b-preimage` takes the target hash as its params, so any number of "find the
preimage" bounties share one on-chain blob.

## Layout

```
types/                     protocol types, constants, standard-program parser/initializer (no_std)
rules/                     refine and accumulate rules, host-independent and unit-tested
service/                   the JAM service: host-call glue around `rules` (jam-pvm-common 0.1.29)
check/                     `declare_check!` for writing checks as `fn(params, x) -> bool`
checks/factor/             sample: x is a nontrivial factor of N (params: N)
checks/blake2b-preimage/   sample: x is a Blake2b-256 preimage of H (params: H)
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

Build the service and both checks into `out/` (as `.jam` files):

```bash
cargo jam-build --out-dir out
```

`witness hash --check out/factor-check.jam` prints the check hash a bounty on that blob uses.

CI (`.github/workflows/ci.yml`) runs the unit tests and builds the blobs. The end-to-end script
needs a PolkaJam release, so run it locally. It starts its own testnet, deploys, and checks the
chain state at each step, in about 8 minutes:

```bash
POLKAJAM_DIR=../polkajam-releases/polkajam-v0.1.29-macos-aarch64 scripts/e2e.sh
```

## Writing a check

```rust
#![cfg_attr(not(test), no_std)]
fn check(params: &[u8], x: &[u8]) -> bool { /* ... */ }
witness_check::declare_check!(check);
```

The crate depends on `witness-check` and `polkavm-derive`, and declares
`[package.metadata.jam] type = "authorizer"` so `cargo jam-build` builds it with the single entry
point a check needs. Checks get no host calls, so there is
no allocator, logging or I/O. Constants and static tables are fine. The stack is 8 KiB unless
the check raises it with `polkavm_derive::min_stack_size!`.

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
# after the claim window (30 slots by default)
jamt item $SVC $($W finalize --bounty 0)
```

Wait a block (about 6 s) after deploying, and after `provide`, before sending items that depend on
it. Refine reads the chain as of the package's anchor block, so an anchor that's too early fails
with `CheckUnavailable`.

To read state, get the raw value with `jamt inspect storage --raw $SVC $($W key --account bob)`,
then decode it with `$W decode --account <value>`. The same works for `--bounty` and
`--commitment`. The node logs (target `witness`) show each refine result, and why accumulate did
or did not apply it.

## Known gaps

- Points are unbacked: anyone can `Mint`, so the commit deposit stops casual spam but not someone
  with a faucet. There are no withdrawals. Real value would come from service transfers.
- One op per work item, and no batching. Signed ops take sequential nonces, so one account can't
  have two signed ops in flight at once.
- The latest Gray Paper (0.8.0 on `main`) replaces `machine(code, pc)` with `compile` (which can
  load a preimage by hash directly) followed by `machine(handle, pc)`. SDK 0.1.29 still exposes
  `machine(code, pc)`, so the service follows the SDK. Revisit when the SDK moves.
- Checks can't allocate memory. Servicing `grow_heap` for the inner VM would allow it.
- Closed bounties stay in storage as a record. Only their commitments and check blobs are cleaned
  up.
