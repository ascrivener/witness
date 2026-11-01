# Break-it targets: where Polkadot's contract value is, and which VM it runs on

Survey, 2026-11-01. The question: should break-it start with EVM (witness-evm, which exists) or
with PolkaVM (a new check that runs the target's code in witness's inner PVM)?

**Answer: EVM, and specifically Ethereum's EVM, not a Polkadot-side one.** The largest value
the Polkadot ecosystem holds in contracts sits on Ethereum, in its bridges' contracts, and that
is also where its one contract exploit of 2026 happened. witness-evm already proves state
against Ethereum's state root and replays it in revm. PolkaVM contracts hold almost nothing:
on Polkadot Hub, 8 of 544 contracts are PVM code, holding 0.5 DOT between them. Defer the
PolkaVM check, with explicit triggers to revisit it ([below](#when-to-revisit-polkavm)).

> **Update, 2026-11-01, later the same day.** This survey's numbers stand, but two later
> findings change how to read its recommendation:
> - **Witness-evm judges a real exploit on real state.** Hyperbridge's April exploit, replayed
>   from a hunter account, breaks a supply invariant at 1.6% of a refine's gas. The rule that
>   came out of it, caps on bridged supply that allow for pending messages, is in witness-evm's
>   `docs/invariants.md`.
> - **For small checks, settling on Ethereum with a zk proof is viable.** One exploit replay or one reveal
>   costs cents to a few dollars to prove. JAM's edge is library-scale checking, because it
>   executes the check rather than proving it, and that's prove-it's core. So break-it on EVM
>   is not where JAM is needed most, and the long-run prove-it work comes first.

Two caveats shape everything after this:

1. **The amounts are small.** About $22M sits in Snowbridge on Ethereum and about $24M in
   Hydration's money market. The other contract platforms hold a few million at most. Polkadot
   has no large contract economy for break-it to protect, and DOT trades at about $0.95.
2. **witness can't escrow real money before JAM mainnet,** and JAM mainnet has no date (October
   2026 reports point to 2027 or later). Until then every break-it bounty is credit-only,
   whichever VM it targets. That makes the choice less urgent than it looks, and it gates the
   grant's funded-bounty milestone on JAM.

## Method

- TVL comes from DefiLlama's API (`api.llama.fi/v2/chains`, `/protocols`, `/protocol/*`), read
  today. DOT and ETH prices come from CoinGecko: DOT $0.95, ETH $2,263.
- Polkadot Hub contracts come from its Blockscout (`blockscout.polkadot.io`). I listed all 544
  contracts (`module=contract&action=listcontracts`), fetched each one's deployed code and native
  balance, and classified code by its first bytes. PVM blobs start with `PVM\0` (`0x50564d00`);
  EVM code starts with a push (`0x60…`).
- Snowbridge's holdings come from Ethplorer, for the addresses Snowbridge's docs list.
- Launch, shutdown and exploit facts come from the sources at the end. Where secondary
  sources disagree, I say so.

All figures are snapshots. DeFi TVL in this ecosystem fell steeply over 2025–26, so treat older
figures in the sources (Snowbridge's "over $75M", "Hydration and Bifrost about $300M by late
2025") as history, not the present.

## The platforms

| Platform | VM, and where its state lives | Value in contracts now | Notes |
|---|---|---:|---|
| **Snowbridge (Ethereum side)** | Ethereum EVM, Solidity. Ethereum MPT state | **≈ $22M** (≈ $19.5M in tokens and 1,076 ETH in the Asset Hub sovereign agent `0xd803…46a8`) | Polkadot's canonical Ethereum bridge, funded by the treasury. TRAC, tBTC, wstETH, WETH, PAXG, MYTH, USDC, AAVE, USDT. HackenProof bounty up to $75k. Upgrades go through OpenGov |
| **Hyperbridge (EVM side)** | EVM on Ethereum, Arbitrum, Base, BSC, Polygon and OP. Solidity | small (DefiLlama tracks none) | **Exploited 2026-04-13:** a missing `leaf_index < leafCount` check in its Solidity MMR verifier let a forged message through the Token Gateway, which minted 1B bridged DOT on Ethereum. About $237k was extracted at first, and later reports say about $2.5M across four chains (unconfirmed). It now has a $50k HackenProof bounty |
| **Hydration money market** | **EVM on Frontier** (`pallet_evm`), Solidity, a fork of Aave v3. State in Hydration's Substrate trie. It holds native assets through precompiles, and the runtime's `liquidation` pallet calls the pool contract | **$23.7M** supplied, $16.6M borrowed | Hydration is $47.9M in all. The rest (Omnipool, about $24M) is runtime pallets, not contracts. Immunefi bounty up to $222k, scoped to runtime pallets |
| **Polkadot Hub (Revive)** | pallet-revive: **REVM** for EVM bytecode and **PVM** for RISC-V, with contracts on either able to call each other. State in Asset Hub's Substrate trie. Assets and XCM through precompiles | **≈ 4,300 DOT (≈ $4k)** native in contracts, all of it in EVM code | Live since 2026-01-27. 544 contracts: 376 EVM, **8 PVM (0.5 DOT)**, 157 with no code (destroyed or not indexed). All 111 verified contracts were compiled with solc, none with resolc. 10,834 transactions in all. The docs call PVM-with-Ethereum-compatibility "early-stage". Stablecoins held by contracts through the assets precompile aren't indexed, but USDC has 26 holders on the EVM side |
| **Bifrost** | Runtime pallets (vDOT and friends), plus SLPx contracts on EVM chains | ≈ $14M (liquid staking $11.1M, DEX $3.4M), almost all in pallets | DefiLlama's "Bifrost Network" ($13.3M) is an unrelated chain, so don't mix them up |
| **Moonbeam / Moonriver** | EVM on Frontier | **≈ 0, shut down** | The Moonbeam parachain wound down on 2026-07-31. GLMR moved to Base as an ERC-20 and the team relaunched there. DefiLlama marks it deprecated |
| **Astar** | EVM on Frontier, plus Wasm (ink!) | $1.0M | ink! development effectively stopped in January 2026 for lack of funding |
| **Peaq, Acala, Karura** | EVM on Frontier (Acala's is EVM+) | $0.74M, $0.28M, $0.05M | |
| **JAM services** | PVM | **0, no mainnet** | Public testnet since January 2026. No mainnet date, and estimates now say 2027 or later. The mainnet referendum hasn't been held |

Outside contracts, most of the ecosystem's value (DOT itself, Asset Hub's USDT and USDC, Omnipool
liquidity, vDOT) lives in **runtime pallets**: Rust compiled to Wasm, upgraded by governance.
Neither check covers that. A break-it check for runtime logic would replay a runtime against a
Substrate state proof. That's a different and much larger project. It's noted here because it's
where the money is, not proposed.

## What each option would take

### EVM, Ethereum side (witness-evm as it is)

It fits Snowbridge, Hyperbridge and Bifrost's SLPx, and any Ethereum contract, with no
Polkadot-specific work. witness-evm's own [design doc](https://github.com/ascrivener/witness-evm/blob/main/docs/design.md)
lists what's left before real targets:

1. **Real mainnet state and real-size code.** All its cases so far are toy contracts in
   synthetic state. Next: a report built from `eth_getProof` on mainnet, against the deployed
   Snowbridge Gateway, Agent and BeefyClient (the Gateway alone is a proxy over a large
   implementation).
2. **An outside review of the check** before any money depends on it (its `docs/review.md` says
   so).
3. **Bridge invariants need care.** Relaying a valid message is permissionless, so a hunter
   relaying a real pending message would "break" a naive invariant like "the agent's balance
   doesn't fall". Either pick a block N with no deliverable messages, or make the invariant
   pending-aware (the balance falls only by messages under an MMR root the light client already
   accepted). Hyperbridge's bug, a forged message accepted below the light client, is exactly the
   class such an invariant catches: "no message is dispatched that isn't committed under an
   accepted root".
4. **Multi-block flows and `PREVRANDAO`.** Snowbridge's BeefyClient takes a commitment over
   several transactions, and samples which signatures to check using `PREVRANDAO` from a later
   block. witness-evm replays one block's environment, with `prevrandao` fixed by the bounty and
   so known to the hunter. A replay that lets the hunter know the randomness in advance is
   weaker than mainnet, so it would accept false wins. Bounties on the BeefyClient need either
   multi-block replay with randomness the hunter can't predict (hard), or a scope that holds
   the light client's state at N fixed and attacks everything downstream of it (the Gateway,
   message dispatch, agents, token handling). Start with the latter.

The bounty's state root is public and fixed when it's posted, so hunters can check it against
Ethereum before working. A maker who posts a wrong root to avoid paying would be visible up
front. A light-client proof of the root would still remove this trust.

### EVM on Frontier (Hydration, Astar, Peaq)

It's EVM, but witness-evm doesn't cover it yet. It would need:
- **Substrate state proofs** in place of Ethereum MPT proofs. Frontier keeps code and storage in
  `pallet_evm` maps in the parachain's trie: a 16-ary Patricia trie with Blake2/Twox keys and
  SCALE values. The parachain's state root is in its head, which the relay chain finalizes.
- **The chain's precompiles, reimplemented in the check.** That's the hard part. Hydration's
  money market holds native assets through an ERC-20 precompile over its multi-currency pallet,
  and reads prices from its oracle. A faithful replay has to model those pallets' effects, so
  part of the runtime goes into the check, and every runtime upgrade can change it. Getting it
  wrong gives false wins (unsound) or missed ones.

Worth it only with a committed payer (Hydration), and only after the Ethereum-side version
works. It's $24M of value, and it's the largest pool of contract value on a Polkadot chain.

### PolkaVM (Polkadot Hub's PVM backend, and later JAM services)

- **Polkadot Hub isn't a clean PVM target even for PVM contracts.** Any Hub contract runs under
  pallet-revive's semantics (its gas and storage-deposit model, precompiles into pallet-assets
  and XCM, calls between REVM and PVM contracts), against Asset Hub's Substrate trie. A Hub check
  would embed pallet-revive's execution, not just a PVM. Its cost is mostly that model and the
  Substrate proofs, which an EVM-on-Hub check would need too. So the "EVM or PolkaVM" choice is
  partly false on Hub: one Revive check would cover both backends. What makes it worth doing is
  value on Hub, and there is about $4k.
- **JAM services are the clean PVM target.** witness already runs PVM code in an inner VM, and a
  service's refine and accumulate are PVM programs with host calls. A check would run the
  target service's accumulate against a proven state snapshot with mocked host calls. It has
  nothing to protect until JAM mainnet, and it shares most of its engineering with pvm-lean
  (the host-call model, GP 0.8.0's PVM).

## Recommendation

1. **Start break-it with witness-evm on Ethereum-side contracts that hold Polkadot's assets:**
   Snowbridge's Gateway and agents first (≈ $22M, treasury-funded, and the biggest pool of
   contract value the ecosystem has), and Hyperbridge's gateways second (a live example of the
   bug class). The engineering is items 1–4 above, mostly real-state reports and invariants
   for bridges, not new VM work.
2. **Make Hydration's money market the second target,** on Frontier, if Hydration wants it.
   Treat the precompile model as the real cost, and scope it with them.
3. **Defer PolkaVM.** Fold the JAM-service check into the pvm-lean work, which needs the same
   host-call and 0.8.0 PVM semantics.

This also suits the grant's third milestone. Snowbridge is the ecosystem's own critical
contract, already paid for by the Polkadot treasury, and it already runs a $75k discretionary
bounty, so a treasury-funded, machine-judged bounty on it compares like with like.

Candidly: none of this validates demand. Snowbridge and Hyperbridge already have human-judged
bounties of $50–75k. The question to put to them, before engineering, is whether they would fund
a bounty that pays automatically on a stated invariant. Draft that ask before building item 1.

## When to revisit PolkaVM

Revisit when any of these holds:
- PVM contracts on Polkadot Hub hold more than about $1M, or any single PVM contract more than
  $250k. Re-run the Blockscout count: it takes a few minutes, and the script is in the
  method above.
- JAM mainnet has a scheduled referendum, and a service plans to custody value on it (a token
  service, a bridge).
- A payer asks for a Hub contract specifically. Then build the Revive check (both backends),
  not a PVM-only one.

## Sources

- Revive release on Polkadot, 2026-01-27: [Polkadot Forum](https://forum.polkadot.network/t/release-of-smart-contracts-on-polkadot/16848);
  dual VM: [docs.polkadot.com](https://docs.polkadot.com/smart-contracts/for-eth-devs/dual-vm-stack.md),
  [smart contracts overview](https://docs.polkadot.com/smart-contracts/overview/)
- First-week adoption (19 contracts) and ink!'s end: [DL News, 2026-02-04](https://www.dlnews.com/articles/defi/polkadot-adds-smart-contracts-to-entice-ethereum-developers/)
- Hub contract counts: [blockscout.polkadot.io](https://blockscout.polkadot.io), read 2026-11-01
- TVL: [DefiLlama](https://defillama.com/chains/polkadot) API, read 2026-11-01
- Snowbridge addresses: [docs.snowbridge.network](https://docs.snowbridge.network/llms-full.txt);
  bounty: [HackenProof](https://hackenproof.com/programs/snowbridge-on-chain-code);
  holdings: Ethplorer for `0xd803472c47a87D7B63E888DE53f03B4191B846a8`, read 2026-11-01
- Hyperbridge exploit: [Verichains root cause](https://blog.verichains.io/p/how-a-missing-bounds-check-led-to),
  [crypto.news](https://crypto.news/hyperbridge-exploit-mints-1-billion-fake-dot-on-ethereum-nets-just-237k/),
  [Hyperbridge's statement](https://x.com/hyperbridge/status/2043676775083803057)
- Hydration money market (Aave v3 fork, launched 2024-11-29): [Hydration](https://hydration.substack.com/p/borrowing-now-live);
  EVM integration: `pallets/liquidation` in [galacticcouncil/hydration-node](https://github.com/galacticcouncil/hydration-node);
  bounty: [Immunefi](https://immunefi.com/bug-bounty/hydration)
- Moonbeam wind-down: [Moonbeam forum](https://forum.moonbeam.network/t/multisig-maintenance-wind-down-moonbeam-moonriver-and-moonbase-july-2026/2512),
  [Tatum changelog](https://docs.tatum.io/changelog/moonbeam-networks-removal)
- JAM mainnet status: [TokenPost](https://www.tokenpost.com/news/technology/36995),
  [Coin Bureau](https://coinbureau.com/review/polkadot-dot) (secondary sources; no official date exists)
