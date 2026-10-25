# Design: settled bug bounties

Status: feasibility spike. `checks/evm-bounty` (the check), `tools/evm-report` (test cases) and
`scripts/evm-bounty-gas.sh` (the measurement) are on branch `spike/settled-bug-bounties-ozwfbj`.

## The question

A protocol funds a precise condition: *a transaction sequence that breaks invariant I of our
contracts, run on block N's state, earns R.* A hunter's report is the transactions plus
Merkle-Patricia proofs of every account and slot they touch. A witness check verifies the
proofs against block N's state root, replays the transactions in revm, and runs the invariant
before and after. If the invariant held and now fails, the bounty pays out, with no human judge.

Does verifying a report fit in one JAM refine, 5×10⁹ gas?

**Answer: yes, for the reports that matter, with room to spare.** The toy exploit costs
1.0×10⁷ gas, 0.2% of the budget. A large DeFi-shaped report (131 accounts, 449 slots, 3.1M EVM
gas) costs 3.9×10⁸, 8%. Execution is rarely the limit: about 30M EVM gas of pure compute fits,
more than any single transaction may use since Osaka (2²⁴, about 16.8M), and DeFi-style work,
mostly storage reads, is about 8× cheaper to replay than that. What grows with a big exploit is
its footprint, the accounts and slots it touches: proofs are about 3.5 KB an account, so report
size binds before gas does.
**Go**, with the open items in [What has to change](#what-has-to-change).

## How the check works

`checks/evm-bounty/src/lib.rs`, about 400 lines over revm 43 (no_std, unchanged) and alloy-trie.

- **Params** (the bounty's terms, RLP, under `MAX_PARAMS_LEN` = 4 KB): block N's state root, the
  hard fork, the environment of the block the transactions run in (number, timestamp, gas limit,
  base fee, coinbase, `prevrandao`), the hunters' starting `capital` in wei, and the invariant:
  EVM runtime code returning one word, nonzero while the invariant holds.
- **Witness** (the report, RLP): every account the replay reads, with its proof, its code and
  the storage slots read, each with its proof (absences proven too), and the transactions.
- **Flow:** decode; verify every proof and code hash, building the only state the replay can
  read (anything else, and `BLOCKHASH`, fails the check); run the invariant, which must hold;
  run the transactions in order on one journal (reverts are fine, invalid transactions fail);
  run the invariant again. The report wins iff it now returns zero.

### Who sends the transactions

Transactions are unsigned, so who they come from is the check's choice. The first version let a
report send from *any* proven account. That is unsound: a report could send as a protocol's
owner or admin key and "break" the invariant through a privileged function.

Now transactions come only from four **hunter accounts**, addresses derived from the next
block's `prevrandao` (`hunter(prevrandao, i)`), made up by the check, each holding the bounty's
`capital` in ETH and nothing else. Nobody could know these addresses at block N, so no contract
in N's state can single them out: a winning report shows that *anyone* could break the
invariant. Hunters get tokens as an attacker would, by trading or flash-borrowing them on chain.
The toy exploit wraps 1 wei of ETH, pays it into the pair and takes 99.8% of the other reserve.

Gas is free (gas price zero, base fee off) and nonces aren't checked, so a report needn't
account for fees. The invariant is called from a separate empty account (EIP-3607 forbids
sending from one with code, which made the first version's invariant call always fail) with
2²⁴ gas, Osaka's per-transaction cap.

## Test cases

All synthetic, from toy contracts written for this (`tools/evm-report/contracts/Toys.sol`):
a WETH-style token, a constant-product pair with a planted bug (its `swap` checks the
fee-adjusted product at the wrong scale), a router, a gas burner, and the pair's invariant
(pair 0's reserve product never falls below its value at block N). No real incidents are
replayed. Public Ethereum RPCs aren't reachable from the environment the spike ran in, so
nothing here uses mainnet state; that is a [next step](#milestones).

The state is synthetic but the proofs are mainnet-shaped. `evm-report` pads every trie so each
proven key has filler siblings at every level of its path: account proofs are 9 nodes (6 full
16-way branches), about 3.5 KB, as `eth_getProof` returns on mainnet; a big token's storage
proofs are 7 nodes, like WETH's. To build a case it replays the transactions with the check's
own `replay`, over a database that records every account and slot read, then proves exactly
those, as a hunter's tooling would with `eth_getProof`.

| Case | What | Outcome |
|---|---|---|
| `burn-1m`, `-10m`, `-30m` | keccak, arithmetic and memory in a loop, in transactions of ≤10M gas | holds |
| `proofs-AxS` | A big-token accounts with S slots each proven, no transactions | holds |
| `pair-swap` | wrap ETH, pay it in, take the fair amount out | holds |
| `pair-exploit` | the planted bug: 1 wei in, 99.8% of a reserve out | **violated: the check accepts** |
| `route-H` | the router swaps through H pairs: a pair and a token more each hop | holds |

The tool's tests also check that a report missing a proof, or with a wrong storage value, fails.

## Measurements

`scripts/evm-bounty-gas.sh` runs each case through `witness-sim check`: PolkaVM's recompiler
with PolkaJam v0.1.29's gas, the inner VM the service runs checks in. A phase's gas is the
difference between stopping after it and stopping before it (`Report::stop_after`).

| Case | EVM gas | Accounts | Slots | Report | Decode | Proofs | Invariant (before) | Transactions | Invariant (after) | **Total** | % of 5×10⁹ |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| burn-1m | 1.0M | 2 | 0 | 7.7 KB | 0.18M | 1.96M | 0.50M | 164M | 0.05M | **167M** | 3.3% |
| burn-10m | 10.0M | 2 | 0 | 7.7 KB | 0.18M | 1.96M | 0.50M | 1,671M | 0.05M | **1,674M** | 33% |
| burn-30m | 30.0M | 2 | 0 | 7.9 KB | 0.19M | 1.96M | 0.50M | 5,014M | 0.05M | **5,016M** | 100.3% |
| proofs-10x10 | 0 | 11 | 100 | 297 KB | 6.0M | 71M | 0.50M | 0 | 0.05M | **78M** | 1.6% |
| proofs-100x10 | 0 | 101 | 1,000 | 2.9 MB | 59M | 705M | 0.50M | 0 | 0.06M | **764M** | 15% |
| proofs-400x10 | 0 | 401 | 4,000 | 11.7 MB | 236M | 2,821M | 0.50M | 0 | 0.06M | **3,058M** | 61% |
| pair-swap | 0.15M | 4 | 9 | 32 KB | 0.69M | 7.9M | 0.61M | 0.94M | 0.13M | **10.3M** | 0.2% |
| **pair-exploit** | 0.15M | 4 | 9 | 32 KB | 0.69M | 7.9M | 0.61M | 0.94M | 0.13M | **10.3M** | 0.2% |
| route-4 | 0.22M | 11 | 29 | 91 KB | 1.9M | 22M | 0.61M | 3.9M | 0.13M | **29M** | 0.6% |
| route-16 | 0.80M | 35 | 113 | 318 KB | 6.7M | 77M | 0.61M | 15.5M | 0.13M | **100M** | 2.0% |
| route-64 | 3.1M | 131 | 449 | 1.2 MB | 26M | 298M | 0.60M | 62M | 0.14M | **387M** | 7.7% |

(M = 10⁶ gas. "Invariant (before)" includes building revm's context.)

### What dominates

- **Proof verification**, for anything that touches real state: **about 90,000 gas per proof
  node**, about 256 gas a byte (89k/node across `proofs-400x10`, 96k/node in `route-64`, where
  storage proofs are shallower). It is keccak over each node plus RLP decoding. Decoding the
  report adds about 20 gas a byte. A proven account with 10 big-token slots is 79 nodes, about
  7M gas.
- **EVM execution** costs **about 167 PVM gas per EVM gas on pure compute** (all three burns).
  On DeFi-shaped transactions it is about **20 PVM gas per EVM gas** (`route-*`), because their
  EVM gas is mostly cold `SLOAD`s and calls, priced for disk reads that cost the replay nothing.
  So compute-bound reports are bounded by EVM gas, state-bound ones by proofs.
- **Fixed costs** are small: the invariant's two runs and building revm's context take about
  0.6–0.75M gas.

At about 0.9×10⁹ gas a second, the worst case that fits (5×10⁹) is about 5.5 s of refine. The
same check natively takes 75 ms for `burn-30m` and 7 ms for `route-64`, so in PolkaVM the check
runs about 60–75× slower than natively.

### What fits

As a rough model, gas ≈ 1M + 90k × proof nodes + 20 × report bytes + k × EVM gas, with k
between 20 (state-bound) and 167 (compute-bound).

- **EVM compute:** about **30M EVM gas** of pure compute, nearly two transactions at Osaka's
  per-transaction cap. Storage-bound transactions replay about 8× cheaper per EVM gas, so far
  more of them fit, until their proofs hit the input limit below.
- **State:** about **50,000 proof nodes** fit the gas, about 1,700 accounts with 3 big-token
  slots each (30 nodes an account). But at about 350 bytes a node that is 17 MB of proofs, more than a work package's input (about 13.8 MB), so the
  input limit binds first: about **40,000 nodes** in a package.
- **A large real exploit**, say 100 accounts, 1,000 slots and 10M EVM gas: about 7,900 nodes
  (0.7×10⁹), a few MB of report and code (under 0.1×10⁹ to decode, plus hashing the code), and
  0.2–1.7×10⁹ to execute. **About 1–2.5×10⁹ in all**, half the budget or less.

Not measured here, and worth measuring next: real contract code. Mainnet contracts run up to
24 KB each, and the check hashes and analyzes every proven account's code; `route-64` proves 156 KB of
toy code. Hashing code should cost about what proof bytes do (keccak), so 1 MB of code is about
0.25×10⁹.

## What has to change

Blocking, for a real deployment:

1. **The check blob is 1,156,339 bytes, over `MAX_CHECK_LEN` (1 MiB).** It is almost all revm
   and its precompiles. Optimizing the check crate for size saves only 4% and costs 25% more gas.
   Options: drop precompiles the bounty's fork doesn't need (KZG point evaluation, BLS12-381) or
   build them in a lighter configuration; or raise `MAX_CHECK_LEN`, since check blobs travel as
   extrinsics and are attested once.
2. **Reports must travel as extrinsics.** A reveal's witness is inline, at most 64 KiB
   (`MAX_WITNESS_LEN`); even the toy exploit's report is 32 KB, and realistic ones are hundreds of
   KB to a few MB. `Attest` already takes `Witness::Extrinsic`; `Reveal` needs the same.

Soundness, before money depends on it:

3. **Adversarial review of the check.** The spike found two flaws in its own first draft (any
   sender; an invariant call that always failed). Still to review: which revm `cfg` relaxations
   are safe (nonce checks off is; balance checks stay on), how precompiles and `SELFDESTRUCT`
   behave on proven state, `CREATE` addresses that collide with proven-absent accounts, and the
   block environment, which the maker sets in the params.
4. **Invariants that revert.** If the invariant reverts or runs out of gas after the
   transactions, the report loses, rather than letting a hunter "break" an invariant by making
   it too expensive to evaluate. So invariants must be cheap and total; that is guidance for
   makers, and something invariant tooling should check.
5. **`BLOCKHASH`** fails the check. Supporting it means proving the last 256 headers (or the
   EIP-2935 history contract's storage), which a light client would provide.

Cheaper, not required:

6. **Deduplicate proof nodes.** Every account proof repeats the root and the top levels; a
   report could send each node once and refer to it by hash. An estimated 10% on `route-64`, more
   on wide reports.
7. **Faster keccak** in PolkaVM, since it is most of the proof cost.

## Scope beyond the spike

### Responsible disclosure

A reveal publishes the exploit. A bounty that has to be revealed against a live, unpatched
protocol would be a public 0-day. The check's design avoids that: it runs against **block N's
state, a snapshot**, so the exploit still verifies after the protocol has patched.

1. The hunter commits (witness's commit-reveal already does this: a hash, timestamped, that
   fixes priority).
2. The hunter discloses privately to the protocol, which patches.
3. After an agreed window, the hunter reveals against block N and is paid automatically. The
   protocol can't refuse to pay or quibble over severity: the escrow is locked and the check is
   the judge.

The bounty's terms need a window long enough to patch (expiry well after posting, and a minimum
time between commit and reveal), and protocols must re-post with a fresh N after upgrades, since
a bounty on old state pays for bugs that state had. JAM's data availability keeps reports
fetchable for weeks for anyone auditing a payout. Stronger privacy (revealing only that *some*
report wins) would take ZK proofs of the same replay or a TEE; both are much heavier than this,
and not needed for v1.

### Trusting the state root

v1: the protocol commits to block N's state root in its own bounty. It is the one paying, so it
has no reason to lie, and a wrong root only makes its own bounty unwinnable, which hunters can
check before working on it. Later: take roots from an Ethereum light client on JAM (Snowbridge's
beacon client on Polkadot is the obvious source), so a bounty can say "any recent block" and
reports can't be dodged by a stale root.

### Invariants

The invariant is ordinary EVM code, so makers write it in Solidity. Good ones are about value:
"the vault holds at least its total deposits", "no pair's k decreases", "the oracle's price stays
within X of the TWAP". Bounty terms have to fix the constants (here, k at block N). Oracle- and
token-dependent invariants need care, since hunters can move prices within the replay; that is
the point, but makers must decide which moves count as a bug. Writing and auditing invariants is
a service in itself: probably the business's main product, more than the check.

### Milestones

1. Make reports extrinsics; get the blob under the limit.
2. Adversarial hardening of the check (items 3–5 above), with a review by someone outside.
3. Bounty terms for disclosure: patch window, minimum commit-to-reveal delay.
4. A witness-sim demo of about a dozen cases, including measurements on real mainnet state
   (needs an RPC, and an archive node for older blocks), and real-size contract code.
5. State roots from a light client.
6. Invariant tooling: templates for common DeFi invariants, and a local harness (Foundry) to test
   them against the same replay.
7. Splitting reports too big for one refine (attest proofs in batches, as `sorted-words` attests
   word volumes, then reveal against attested state).

### Business

Immunefi, Sherlock, Cantina and Hats all have humans judge reports and protocols decide what to
pay. The edge here is **automatic settlement**: funds escrowed against a precise condition,
paid by a check, with nothing to negotiate. Risks:

- **Protocols may prefer discretion.** A pre-committed, automatically paid bounty removes
  their room to argue severity or scope; some will see that as the cost, not the feature.
- **Disclosure.** The flow above depends on hunters waiting out the patch window, and on
  protocols re-posting after upgrades.
- **State trust** until a light client exists.
- **JAM's timeline.** This needs JAM in production with real value on it.
- **Adam's employment agreement**, which should be checked before this becomes a business.

## Reproducing

```bash
cargo test -p evm-report            # the cases natively, including the exploit winning
scripts/evm-bounty-gas.sh           # build everything and print the table above
```

PolkaVM's recompiler needs `userfaultfd`. In a container that forbids it unprivileged, run
`sysctl -w vm.unprivileged_userfaultfd=1` first. `tools/evm-report/contracts/compile.js`
recompiles `Toys.sol` with solcjs (npm `solc@0.8.28`) if the contracts change.
