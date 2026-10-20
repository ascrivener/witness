# witness

A "find the witness" bounty market as a JAM service. A maker posts `check: X -> bool` with a
reward; the first hunter to reveal an `x` with `check(x) = true` gets the reward.

Prototype: rewards are points from a faucet (`Mint`), not tokens.

## How it works

| Op | Refine (in-core, stateless) | Accumulate (on-chain) |
|---|---|---|
| `Mint` | — | credit points (faucet, ≤ `MAX_MINT`) |
| `CreateBounty` | verify maker's Ed25519 signature | check nonce, balance and limits; debit reward; `solicit` the check blob; store bounty |
| `Commit` | — | record `slot` for `blake2b(bounty_id, x, hunter, salt)` (earliest wins) |
| `Reveal` | look up the check blob, run `check(x)` in an inner PVM with the bounty's `check_gas` | commitment ≥ `MIN_COMMIT_AGE` slots old, made before expiry, bounty open and terms match → pay hunter |
| `Reclaim` | verify maker's signature | after `expiry + REVEAL_GRACE`, refund an unclaimed bounty |

- **Front-running.** Revealing `x` publishes it. Commit-then-reveal, with the hunter's key inside
  the commitment, means a copier would need a commitment older than the reveal they copied.
- **Check blobs** are standard JAM programs (GP appendix A.7), without the metadata prefix. Refine
  builds the inner PVM's memory and registers exactly as `Y(p, x)` would
  ([service/src/check_vm.rs](service/src/check_vm.rs), [types/src/program.rs](types/src/program.rs)).
  Halting with 1 in `φ7` means true. Anything else (0, panic, page fault, out of gas, any host
  call) means false.
- **Gas.** `check_gas` is capped at `MAX_CHECK_GAS` when the bounty is created and passed to
  `invoke` as the inner VM's limit. The Reveal work item's refine gas must cover it.

## Layout

```
types/                 shared types, constants, standard-program parser/initializer (no_std)
service/               the JAM service (jam-pvm-common 0.1.29)
check/                 `declare_check!` for writing checks as `fn(&[u8]) -> bool`
checks/factor/         sample check: x is a nontrivial factor of a fixed N
tools/witness-build/   builds the service (.jam) and checks (.check)
tools/witness-cli/     builds work-item payloads as hex (`witness`)
```

## Build

Host tools build on stable Rust (1.86 or newer). PVM blobs need `nightly-2025-05-10` with
`rust-src`, which `witness-build` invokes itself:

```bash
rustup toolchain install nightly-2025-05-10 -c rust-src
```

```bash
cargo build
```

```bash
./target/debug/witness-build service
```

```bash
./target/debug/witness-build check checks/factor
```

Outputs go to `out/`, and the builder prints each blob's length and Blake2b-256 hash.

`witness-build` does what `jam-pvm-build` does, but links with polkavm-linker 0.37. The latest
`jam-pvm-build` on crates.io (0.1.28) links with 0.30, and PolkaJam 0.1.29 rejects its output
("module validation failed").

## Writing a check

```rust
#![cfg_attr(not(test), no_std)]
fn check(x: &[u8]) -> bool { /* ... */ }
witness_check::declare_check!(check);
```

The crate depends on `witness-check` and `polkavm-derive`. Checks get no host calls, so there is
no allocator, logging or I/O. Constants and static tables are fine. The stack is 8 KiB unless
the check raises it with `polkavm_derive::min_stack_size!`.

## Running it on a local testnet

Tested with PolkaJam v0.1.29 (GP 0.8.0) from
[polkajam-releases](https://github.com/paritytech/polkajam-releases). With `jamt` and
`polkajam-testnet` from that release on your `PATH`, start a testnet:

```bash
polkajam-testnet
```

In another terminal, deploy. `jamt list` shows the new service id; it is `1` on a fresh testnet.

```bash
jamt create-service out/witness-service.jam 10000000000
```

Then run the flow, with `W=./target/debug/witness` and `SVC` set to the service id. Wait a block
(~6 s) after deploying, and after `provide`, before items that depend on it: refine reads the
chain as of the package's anchor block, so earlier anchors fail with `CheckUnavailable`.

```bash
jamt item $SVC $($W mint --to alice --amount 1000)
jamt item $SVC $($W create --service $SVC --maker alice --nonce 0 --check out/factor-check.check --reward 500 --check-gas 10000000 --expiry $(( $(jamt inspect slot) + 300 )))
jamt provide $SVC out/factor-check.check
jamt item $SVC $($W commit --bounty 0 --witness-u64 4294967291 --hunter bob --salt 0x0b0b5a17)
# wait MIN_COMMIT_AGE (4) slots
jamt item $SVC $($W reveal --bounty 0 --check out/factor-check.check --check-gas 10000000 --witness-u64 4294967291 --hunter bob --salt 0x0b0b5a17)
```

Read state with `jamt inspect storage --raw $SVC $($W key --account bob)`, then
`$W decode --account <value>`. The same works for `--bounty`, and the node logs (target
`witness`) show each refine result and why accumulate did or did not apply it.

Tested on 2026-10-20, on-chain:

- Mint.
- CreateBounty, with its signature verified in refine.
- Solicit and provide of the check blob.
- A wrong witness, which gave `CheckFailed(False)`.
- A copied witness under another key, which gave "no commitment".
- A commit and reveal that paid out.
- A double claim, rejected with "bounty not open".
- A check given 10 gas, which gave `CheckFailed(OutOfGas)`.
- A reclaim before `expiry + REVEAL_GRACE`, which was refused.
- A reclaim after it, which refunded the reward, and a replay of that reclaim, which was rejected.

## Known gaps

- Points are unbacked: anyone can `Mint`. No withdrawals.
- One op per work item, and no batching.
- The latest Gray Paper (0.8.0 on `main`) replaces `machine(code, pc)` with `compile` (which can
  load a preimage by hash directly) followed by `machine(handle, pc)`. SDK 0.1.29 still exposes
  `machine(code, pc)`, so the service follows the SDK. Revisit when the SDK moves.
- Checks cannot allocate. Servicing `grow_heap` for the inner VM would allow it.
