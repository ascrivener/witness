# Stablecoin balances from token services

Status: proposed.

## Why

Witness's balances are points from a faucet (`Mint`). Real bounties need real money, and the
people posting and solving them should see a stablecoin, not DOT or JAMKB. JAM has no user
accounts: value lives in services and moves between them only by transfers, made in accumulate,
each carrying native balance, its sender's service id and a 128-byte memo. So money reaches
witness only from another service: a token service holding stablecoins, such as a multi-asset
service like Polkadot's Asset Hub, or a bridge to it.

Two kinds of money stay apart:

- **Users' money: assets of token services.** Rewards, escrow and deposits, kept in witness's
  ledger per account and per asset, and moved in and out by memo messages with the token service
  that issues the asset.
- **Witness's storage: its own native balance.** It only backs the records witness stores, which
  JAM charges per item and per byte. Users never see it. A sponsor funds it for now; a per-record
  fee, converted on chain, can come once JAM has an exchange (or a trusted operator to convert).

## Assets

An asset is `(service, id)`: a token service and an asset in it. A multi-asset service names
many assets under one service id; a single-asset service uses id 0. The services witness accepts
assets from are fixed at deployment (see Configuration): witness trusts each entirely for what it
says it deposited, so the list is short and doesn't change under anyone's feet.

## Messages

Memos are SCALE-encoded, starting with a version byte, and fit in 128 bytes.

**Deposit** (token service to witness): `{ asset_id: u32, amount: u128, to: AccountId }`. Witness
credits `amount` of `(sender, asset_id)` to `to`, if the sender is an accepted service. A deposit
from any other service, or that doesn't decode, is ignored (its native balance, if any, stays
with witness's storage).

**Withdrawal** (witness to token service): `{ asset_id: u32, amount: u128, to: [u8; 32] }`, where
`to` is the payee's account in the token service. Witness sends it from accumulate, with no native
balance, when it applies a signed `Withdraw { account, nonce, asset, amount, to, signature }`
after debiting the account. The token service pays `to` out of what witness holds with it.

The token service holds witness's total in each asset as one of its own accounts: deposits move
the user's funds to witness's account there, withdrawals move them back out. So the token
service's ledger always shows what witness owes its users, and witness's ledger who it owes.

## Ledger

- `Account(id)` keeps the account's nonce. `Balance(id, asset)` keeps a balance, deleted at zero.
- A bounty names its asset: its reward is escrowed in it, and commitments on it lock
  `COMMIT_DEPOSIT` of it, refunded on a valid reveal as now. Commit deposits and rewards scale
  differently across assets (a cent is not a satoshi), so the deposit becomes a term of the
  bounty, at least a per-asset minimum the deployment sets.
- `Attest` records no money, so attestations stay shared by every asset's bounties. Its deposit
  (spam protection for the sponsored storage) is paid in one fee asset the deployment names.
- `Mint` stays for testnets only, behind a build feature, crediting a test asset.

## Configuration

The accepted token services, the fee asset and the per-asset minimum deposits are constants in
the service build, set by environment variables when it's built. Each deployment's code then
commits to its configuration: anyone can check it from the code hash, nobody can change it after,
and there's no admin key or first-come configuration op to front-run. Witness's source stays
generic: a deployment is a build of it with its own list.

## Testing

A minimal mock token service (`tools/mock-token`, a JAM service): accounts per asset, a faucet for
tests, a signed transfer to another service with a deposit memo, and paying out a withdrawal memo
from an accepted caller. The e2e script deposits into witness, posts and wins a bounty paid in the
mock stablecoin, and withdraws the reward; witness-sim emulates the token service.

## Open

- Whether a token service on JAM will speak this memo format, or need a thin adapter service in
  front of it (likely for Asset Hub, whose form on JAM isn't settled).
- Withdrawals are fire-and-forget: witness debits, then sends. A token service that fails to pay
  out is a bug in the token service, which witness already trusts entirely.
