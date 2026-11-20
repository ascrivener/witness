# Witness on the JAM Toaster

The [JAM Toaster](https://jamtoaster.network) is Parity's public JAM testnet: chain spec
[public.json](https://jamtoaster.network/chainspec/public.json) (id `public`, formerly
`public-30`: the id and bootnode have changed, the chain hasn't), genesis header hash
`0xb8100ea7c6c6f952bf2ad61192e17f5b788f510ae7d86603edbe9f792412087d`, 10 cores, 6-second slots,
GP 0.8.0, PolkaJam 0.1.29. It has no public RPC, so deploying and using witness there means
running a node of your own, non-validating, and talking to its RPC.

**Status: deployed; one bounty paid end to end.** Witness is **service 7**, created at slot
9,907,098 (2026-11-20) from a macOS node following the steps below, code hash
`0xf4c0a230ce9f4cd32cb55dc61d8127d5ae2fedb004ee352cdf1f0610bceac99b` (the blob's blake2b-256). Its
first configuration applied at slot 9,907,103, and the admin handover is proposal 0, effective
from slot 10,007,905. Bounty 0 then ran through mint, create, commit, a wrong reveal (rejected),
the right reveal, an early finalize (rejected) and finalize, and was claimed by the hunter at
slot 9,907,164. An upgrade to a build with its own admin key is pending (proposal 1,
[below](#pending-upgrade)).

The chain spec's bootnode is now `195.154.91.169:5556`; the GitHub Actions runs before this
couldn't reach the earlier one (`78.137.198.98:5556`). A node also needs `--proxy` (below) to
submit work packages.

## The build deployed

The service deployed is the one [jam-lean](https://github.com/ascrivener/jam-lean)'s theorems are
about, vendored there as `services/witness/witness-service.jam` (jam-lean at `98bc6aa`): witness
at `71e585a`, built with `cargo jam-build` 0.1.29 and rustc 1.97.0, default features (so with the
test faucet), and neither `WITNESS_ADMIN` nor `WITNESS_ADMIN_DELAY` set.

| | |
|---|---|
| bytes | 222,973 |
| sha256 | `408b5be2fde1ae49b64f7c1ee44d2660472f1c9545320bf7a65ee9281206e2e4` |
| blake2b-256 | `f4c0a230ce9f4cd32cb55dc61d8127d5ae2fedb004ee352cdf1f0610bceac99b` |

The workflow deploys jam-lean's file only if its sha256 is this one, and rebuilds `71e585a` to
compare: the rebuild is the same byte for byte with rustc 1.97.0 (a newer rustc gives other
bytes). The on-chain code hash is recorded at deploy, in the run's `summary.json`.

That build's admin is the public test key (seed `admin`), and its admin delay is 100,800 slots
(about 7 days); the first configuration applies at once. So the deploy configures the service
straight away (fee asset `test`, commit and attest deposits of 10, as in `scripts/e2e.sh`) and
proposes handing the admin role to the key of the `WITNESS_ADMIN_SEED` repository secret, which
the workflow's `apply` applies once the delay has passed. Until then anyone holding the test key can
propose or cancel too.

## Pending upgrade

Proposal 1 on service 7 upgrades its code. It was proposed at slot 9,907,281 with the test key, and
it is effective from slot **10,008,081**: the delay comes from the running build (100,800 slots),
not the new one. The new code was provided as a preimage at slot 9,907,283. Once the slot is
reached, anyone can apply it (`witness apply --id 1`). Until then, the test key can still cancel it.

The new build is witness at `42c3802` (`main`; `service/`, `rules/` and `types/` are unchanged
from `71e585a`), built with `cargo jam-build` 0.1.29 and rustc 1.97.0, with
`WITNESS_ADMIN=9981b72971f6a7282c86bf149082caac7e48d5a4737c57e81be0b25a88788bcf` (the
`WITNESS_ADMIN_SEED` key, the same one proposal 0 hands over to) and `WITNESS_ADMIN_DELAY=600`:

| | |
|---|---|
| bytes | 222,971 |
| sha256 | `f24c93c9b2892cb52e39b6a6567ab263226d025f553b04611749dbc06f80cf4f` |
| blake2b-256 | `2f25d04bbb212aa47ec4e3c57e81eccc31e196f4c9a90b2a56e9510fc7515d71` |

The service keeps its id and its storage. The admin is the one stored by a `SetAdmin`, or else the
build's `WITNESS_ADMIN`. Nothing is stored yet, so once the upgrade applies the admin is the
`WITNESS_ADMIN_SEED` key, whether or not proposal 0 has been applied, and later proposals wait 600
slots. **Once applied, service 7 no longer runs the build jam-lean vendors**, so jam-lean's theorems
about that blob no longer describe the code on chain.

To apply them from the workflow once effective: `action` `apply`, `service_id` 7, and
`proposal_id` 1 with `expect` `2f25d04bbb212aa47ec4e3c57e81eccc31e196f4c9a90b2a56e9510fc7515d71`
(from slot 10,008,081), or `proposal_id` 0 with `expect`
`9981b72971f6a7282c86bf149082caac7e48d5a4737c57e81be0b25a88788bcf` (from slot 10,007,905).

### Daily watch

Until then, `.github/workflows/toaster-watch.yml` checks service 7 every day at 04:37 UTC (and
on demand: Actions → Toaster watch → Run workflow). It syncs a node and reads, without submitting
anything: the proposals (exactly proposals 0 and 1, with the actions and effective slots above),
the test admin's nonce (3: a new proposal or a cancel by the test key would change it), the stored
admin (none yet) and the code hash (`f4c0a230…`). Any difference fails the run, which sends
GitHub's failure notice, and the run's summary lists each check. Once the proposals are applied it
fails by design: disable it then (Actions → Toaster watch → ⋯ → Disable workflow).

## The workflow

`.github/workflows/toaster.yml`, run by hand (Actions → Toaster → Run workflow). Each run
downloads PolkaJam 0.1.29, checks that the chain spec's genesis header hashes to `0xb8100ea7…`,
starts a node on it (`polkajam --chain public.json run --rpc-port 19800 --temp --proxy
<bootnode>`), checks the node's genesis is the same, builds the witness CLI and the checks at
`71e585a`, waits for the node to sync, then does `action`:

| `action` | does | inputs |
|---|---|---|
| `sync-only` (default) | records how long syncing took and the node's view of the chain | |
| `deploy` | creates the service, configures it, proposes the admin handover | |
| `bounty` | one bounty on the Blake2b preimage check: mint, create, commit, reveal a wrong witness and then the right one, finalize too early, finalize after the claim window, checking state after each step | `service_id` |
| `watch` | reads service `service_id`'s proposals, test-admin nonce, stored admin and code hash, and fails unless they are `watch_expect`'s (`EXPECT_*=` lines; see `toaster-watch.yml`). Submits nothing | `service_id`, `watch_expect` |
| `apply` | applies proposal `proposal_id` once it's effective (unsigned: no key needed), then checks it took: a SetAdmin's key is the stored admin, an Upgrade's code hash is the service's code hash, and the proposal is gone. With `expect`, that key or code hash must also be `expect` | `service_id`, `proposal_id` (0), `expect` |

The node counts as synced once its best slot is within 3 of the wall-clock slot for a minute.
A run gives up after `stall_minutes` (20) with no block past genesis, and after
`sync_timeout_minutes` (300) in any case. `node_args` adds arguments to `polkajam run`.
`cli_commit` builds the witness CLI and checks at another commit, to match the code the service
runs (default `71e585a`; the CLI is the same at the upgrade's `42c3802`). Logs
(the node's, the sync progress as CSV, the chain spec's head, help texts) and `summary.json` are
uploaded as the run's artifact.

## The same steps on your own machine

Anywhere a PolkaJam node can sync (Linux, or macOS with the macOS release):

```sh
# PolkaJam 0.1.29 from paritytech/polkajam-releases (tag v0.1.29), and the chain spec
curl -fsSLO https://jamtoaster.network/chainspec/public.json
# --proxy: without one an ordinary node can't hand work packages to guarantors ("Failed to
# submit work-package to even a single proxy/guarantor"); the chain spec's bootnode serves
polkajam --chain public.json run --rpc-port 19800 --temp \
  --proxy "$(python3 -c 'import json; print(json.load(open("public.json"))["bootnodes"][0])')"
# on Linux, first:
# sudo sysctl vm.unprivileged_userfaultfd=1 kernel.apparmor_restrict_unprivileged_userns=0

# in another shell, from this repository: the CLI and checks at the deployed commit
git worktree add ../witness-71e585a 71e585a
(cd ../witness-71e585a && cargo +1.97.0 build --locked -p witness-cli \
  && cargo +1.97.0 jam-build --out-dir out -- --locked)
curl -fsSLo witness-service.jam \
  https://raw.githubusercontent.com/ascrivener/jam-lean/98bc6aa6a44f81967024446bb9c53e8f1406b642/services/witness/witness-service.jam
echo "408b5be2fde1ae49b64f7c1ee44d2660472f1c9545320bf7a65ee9281206e2e4  witness-service.jam" | sha256sum -c
# (on macOS: `shasum -a 256 -c`; `cargo jam-build` needs `rustup component add rust-src
# --toolchain 1.97.0`; and run.sh uses GNU `stat`, so put coreutils' gstat first in PATH as stat)

# once the node has synced (scripts/toaster/sync.py 300 sync.csv waits for it)
export JAMT=/path/to/jamt W=../witness-71e585a/target/debug/witness CHECKS=../witness-71e585a/out
SERVICE_JAM=witness-service.jam WITNESS_ADMIN_SEED=... scripts/toaster/run.sh deploy
scripts/toaster/run.sh bounty SERVICE_ID
scripts/toaster/run.sh apply SERVICE_ID PROPOSAL_ID [EXPECTED_KEY_OR_CODE_HASH]   # once effective
```

`JAM_RPC` points the scripts and `jamt` at another node (default `ws://localhost:19800`); `OUT`
is where `summary.json` goes (default `.`). With `JAM_RPC=sim` and
`JAMT=target/debug/witness-sim` the script runs against `tools/witness-sim` instead, without a
node.
