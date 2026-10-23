# Stablecoin balances from token services

Status: implemented (storage credit recorded, not yet spent).

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
  JAM charges per item and per byte. Users never see it. A sponsor funds it for now (see Storage).

## Assets

An asset is `(service, id)`: a token service and an asset in it. A multi-asset service names
many assets under one service id; a single-asset service uses id 0. Witness accepts assets only
from the token services its configuration lists, and trusts each entirely for what it says it
deposited, so the list is short and changes only under the timelock (see Administration).

## Messages

Memos are SCALE-encoded, fit in 128 bytes, and start with a version byte (now 2) and then the
kind of memo: `TokenMemo::Deposit` or `TokenMemo::Withdrawal`. The kind keeps one from being read
as the other, which matters for refunds (below).

**Deposit** (token service to witness): `{ asset_id: u32, amount: u128, to: AccountId,
refund_to: [u8; 32] }`. Witness credits `amount` of `(sender, asset_id)` to `to`, if the sender is
an accepted token service. The transfer's native balance, if any, is credited to `to` as storage
credit (see Storage).

**Refund.** A deposit witness can't credit goes back: from a service it doesn't accept (or before
it's configured at all), or one it can't store. Witness sends the sender a withdrawal paying
`amount` of `asset_id` to `refund_to`, the depositor's account with the token service, with the
deposit's native balance. Only a deposit is ever refunded, never a withdrawal, so two services
can't bounce a refund between them. A transfer that isn't a deposit credits nothing, and its native
balance stays with witness's storage.

A deposit must carry at least `DEPOSIT_GAS` (3×10⁵; crediting one used about 37,000 on PolkaJam): a transfer's gas limit is all the receiver
gets to process it, and a deposit witness can't process is lost after the token service has
moved the funds. So witness is deployed with that as its `min_memo_gas`, and JAM refuses
transfers to it that carry less. Likewise witness gives a withdrawal (or refund) the token
service's own `min_memo_gas`, which the token service must set to cover paying it out. A refund
comes out of the deposit's gas, after witness has tried to credit it, so a token service whose
deposits should be refundable asks for at most about 2×10⁵.

**Withdrawal** (witness to token service): `{ asset_id: u32, amount: u128, to: [u8; 32] }`, where
`to` is the payee's account in the token service. Witness sends it from accumulate, with no native
balance, when it applies a signed `Withdraw { account, nonce, asset, amount, to, signature }`,
after debiting the account. The token service pays `to` out of what witness holds with it.

The token service holds witness's total in each asset as one of its own accounts: deposits move a
user's funds to witness's account there, withdrawals move them back out. So the token service's
ledger shows what witness owes its users, and witness's ledger whom it owes.

## Ledger

- `Account(id)` keeps the account's nonce; `Balance(id, asset)` a balance, deleted at zero.
- A bounty names its asset: its reward is escrowed in it and paid out in it.
- Spam deposits are fixed amounts of one **fee asset** (a stablecoin, say), set in the
  configuration: `commit_deposit`, locked per commitment and refunded on a valid reveal as now,
  and `attest_deposit`, per attestation, kept. They exist because each commitment and
  attestation is a record in storage the sponsor pays for; attestations are permanent, and anyone
  can attest anything under a check of their own. A hunter on a bounty paid in another asset
  holds a little of the fee asset as well.
- Attestations record no money, so they stay shared by every asset's bounties.
- `Mint` stays for testnets only, behind a build feature, crediting a test asset.

## Storage

JAM charges witness's native balance for each record (`deposit_per_item` plus `deposit_per_byte`,
with overheads). A sponsor keeps that balance funded, by plain transfers to witness, until there
is an on-chain exchange (or a trusted operator) to convert fees into it.

Records can also be paid for by whoever creates them: native balance a deposit transfer carries
becomes the recipient's **storage credit**, and when an account's ops store records, accumulate
debits its credit by what JAM charges for them, refunding it when they're removed. An account with
no credit falls back to the sponsor. So once wallets can buy and hide a few cents of the storage
token (JAMKB, as proposed), people pay for their own state and the sponsor becomes optional,
without a redesign. Credit isn't withdrawable at first: it only ever backs storage. For now
witness records credit as it arrives but doesn't spend it: nobody holds the storage token yet,
and the sponsor pays. Spending it is the switch to flip later.

## Administration

An admin can change the configuration and upgrade the service's code, and hand the role on; both
are timelocked so nobody's funds change rules under them without notice.

- The first admin's key is compiled into the build, so nobody can claim the role by being first.
- `Propose { action, nonce, signature }`, signed by the admin, records an action to take effect
  after `ADMIN_DELAY` (about 7 days of slots); `Apply { id }`, by anyone, applies it after that;
  `Cancel`, by the admin, drops it. Actions: `Configure(Config)`, `SetAdmin(Admin)`, and
  `Upgrade { code_hash, code_len }`.
- `Upgrade` solicits the new code as a preimage when proposed; once it's provided and the delay
  has passed, `Apply` calls JAM's `upgrade`. The service keeps its id, state and balances.
- `Admin` is a key or a service (a governance service, eventually, whose transfers carry its
  proposals). While a person holds the role, users trust them with the rules, and so with their
  balances; the delay lets anyone who disagrees withdraw first.

`Config` holds the accepted token services, the fee asset and the two deposits.

## Testing

A minimal mock token service (`tools/mock-token`, a JAM service): balances per account and asset,
a faucet for tests, a signed transfer to another service with a deposit memo, and paying out a
withdrawal memo from a service holding a balance with it. witness-sim emulates it. The e2e script
sends a deposit before witness is configured and sees it refunded, deposits into witness, posts
and wins a bounty paid in the mock stablecoin, withdraws the reward, and changes the configuration
under the timelock.

## Open

- Whether token services on JAM will speak this memo format, or need a thin adapter in front of
  them (likely for Asset Hub, whose form on JAM isn't settled).
- Withdrawals are fire-and-forget: witness debits, then sends. A token service that fails to pay
  out is a bug in the token service, which witness already trusts entirely.
