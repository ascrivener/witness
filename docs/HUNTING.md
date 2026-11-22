# Hunting a witness bounty on the JAM Toaster

This guide takes you, or an AI agent working for you, from nothing to a claimed bounty. It needs
a GitHub account and a Lean proof of the bounty's theorem. The chain work runs in a GitHub
Actions workflow in your own copy of this repository, so you don't need a machine of your own.
Every step below is a command or a click, and each one says what success looks like.

The bounties are on witness, deployed as **service 7** on the [JAM Toaster](https://jamtoaster.network)
testnet. The live list is the board: <https://ascrivener.github.io/witness/>. Rewards are in the
Toaster's test asset, which has no value: what you win is the record on chain that your proof was
checked and paid.

## How a bounty is won

- The bounty names a **statement**: a Lean theorem's name and type, by the hash of its *statement
  node*. You must prove that theorem, under exactly that name and type.
- **Commit:** you post a commitment, a hash of your witness (your proof, packed as nodes), your
  account and a secret salt. Nobody can read your proof from it.
- **Reveal:** at least one slot later you reveal the witness. The service runs witness-lean's Lean
  kernel on it, and a valid proof opens a **claim window** of 30 slots (3 minutes).
- During the window, a later valid reveal can still win if its commitment is **earlier**. The
  earliest commitment among valid reveals wins.
- **Finalize:** after the window, anyone can finalize, which pays the winner.

Your proof is checked trusting the bounty's **attested libraries** (its spec's `libraries`): their
nodes were type-checked on chain earlier, in batches, and your reveal cites those attestations
instead of re-checking them. The citations come from a published release,
[`toaster-attestations-v2`](https://github.com/ascrivener/witness/releases/tag/toaster-attestations-v2)
([docs/toaster-attestations.md](toaster-attestations.md)). The workflow fetches them for you.

## 0. Pick a bounty and read its spec

```sh
curl -s https://ascrivener.github.io/witness/bounties/index.json
curl -s https://ascrivener.github.io/witness/bounties/3.json
```

The spec (also in this repository as `site/bounties/N.json`) has everything a hunt needs:

| Field | What it is |
|---|---|
| `statement.lean` | the exact theorem to prove, e.g. `theorem Services.Bootstrap.Acc.Final.accLogFail_bounty : Services.Bootstrap.Acc.Final.AccLogFailGoal` |
| `statement.imports`, `statement.definition` | the module to import, and the full Lean text of the type's definition |
| `statement.node` | the statement node's hash: the bounty's params. Your theorem must hash to it |
| `pins` | the commits everything is built at: jam-lean, witness-lean, lean4export (and the service's witness build) |
| `check`, `check_gas` | the check (witness-lean's Lean kernel) and the gas your reveal's check may use: 5×10⁹, one refine |
| `cite`, `library`, `libraries`, `release` | the attested library the bounty cites, every library you may trust (the cited one first), the attestation the bounty cites, and the release's asset URLs and sha256s |
| `reward`, `asset`, `expiry`, `claim_window` | the terms. Commit before `expiry.slot` (`expiry.approx_utc` is its date) |
| `hunt.commands` | the workflow commands below |
| `status` | the board's snapshot of the chain, about hourly: is the bounty still `Open`? |

**Bounty 3** asks for a proof of `AccLogFailGoal`, one of jam-lean's open obligations; see
[toaster-acclogfail.md](toaster-acclogfail.md) for what it means and why it matters.

## 1. Write the proof

The proof is **one Lean file** that imports the spec's module, may declare lemmas of its own, and
ends with the theorem under exactly the spec's name and type:

```lean
import Services.Bootstrap.Acc.Final.Bounty

namespace Services.Bootstrap.Acc.Final

-- your own lemmas, if any (see "Your own lemmas" for how to name them)

theorem accLogFail_bounty : AccLogFailGoal := by
  ...

end Services.Bootstrap.Acc.Final
```

Rules the check enforces:

- No `sorry`. The only axioms allowed are `propext`, `Classical.choice` and `Quot.sound`.
- Import only jam-lean's modules, and Lean core and Std through them; the file is compiled inside
  jam-lean at the pinned commit. Anything your proof uses that isn't in the attested libraries is
  carried in your reveal and checked there, which costs gas.
- The type must be the spec's exactly: the same constant (`AccLogFailGoal`), not an unfolded copy.
  The statement node hashes the type as written.

Work on it locally, in jam-lean at the pinned commit, with Lean's usual tools:

```sh
PIN=$(curl -s https://ascrivener.github.io/witness/bounties/3.json | jq -r .pins.jam_lean)
git clone https://github.com/ascrivener/jam-lean && git -C jam-lean checkout "$PIN"
# its build for exactly that commit (about 12 GB unpacked), from this repository's release
# jam-lean-lake-<first 7 of PIN>; without it, a cold build takes about 5 hours
witness/scripts/toaster/hunt/fetch-jam-lean-cache.sh jam-lean "$PIN"
cd jam-lean && lake build Services.Bootstrap.Acc.Final.Bounty
lake env lean MyProof.lean         # your file
```

You can also run the whole build-and-measure locally: see [Running it locally](#running-it-locally).

## 2. Make your copy of the repository

Your proof must stay secret until your commitment is on chain. Anyone who reads it before then
can commit to it first, and win. So choose one of these:

- **A private copy (recommended).** Create an empty **private** repository on GitHub (for example
  `YOU/witness-hunt`), then:

  ```sh
  git clone --bare https://github.com/ascrivener/witness.git
  git -C witness.git push --mirror https://github.com/YOU/witness-hunt.git
  ```

  Commit your proof file to it (say `proofs/accLogFail.lean`), and pass `proof=proofs/accLogFail.lean`.
  Private repositories use your Actions minutes: each run takes about 30–90 minutes.
- **A public fork.** Fork `ascrivener/witness`. A fork is public: its files, workflow inputs, logs
  and artifacts are readable by anyone. So **don't commit your proof** before your commitment has
  landed. Put the file's text in the `HUNTER_PROOF` secret instead, and leave `proof` empty. Secrets
  hold up to 48 KB; for a larger file use `gzip -c MyProof.lean | base64 -w0`.

Then:

1. **Actions → enable workflows.** In a fork, open the Actions tab and press "I understand my
   workflows, go ahead and enable them". Only `Toaster hunt` needs to run; the scheduled ones
   (board, watch) can stay disabled.
2. **Secrets** (Settings → Secrets and variables → Actions → New repository secret):
   - `HUNTER_SEED`: your account. Any secret string, e.g. `openssl rand -hex 32`. It signs your
     commit, and your salt derives from it. Keep it: you need the same seed for every step.
   - `HUNTER_PROOF` (public fork only): your Lean file, as above.
3. **Keep the copy current.** The bounty specs and the hunt workflow live in this repository.
   Before hunting, sync your copy (a fork: "Sync fork"; a private copy: `git pull
   https://github.com/ascrivener/witness main` and push).

With the GitHub CLI, every step below is one command. In the GitHub web UI it's Actions → Toaster
hunt → Run workflow, with the same inputs.

## 3. Optional: see it work on a test chain

```sh
gh workflow run toaster-hunt.yml -R YOU/REPO -f step=test
```

This runs the whole hunt (commit, reveal in both lemma modes, finalize) against a stand-in node
over witness-sim, on a sim copy of the Picoalloc bounty. Nothing goes on chain and no secrets are
needed. It succeeds when the log ends `hunt passed against fake-node`. About 20 minutes.

## 4. Check

```sh
gh workflow run toaster-hunt.yml -R YOU/REPO -f bounty=3 -f step=check -f proof=proofs/accLogFail.lean
gh run watch -R YOU/REPO "$(gh run list -R YOU/REPO -w toaster-hunt.yml -L1 --json databaseId -q '.[0].databaseId')"
```

(With the proof in a secret, drop `-f proof=...`.) This builds your reveal exactly as it will be
sent, without a node or anything on chain:

- it compiles your file against jam-lean at the pinned commit, exports it, and checks that your
  theorem's statement node is the bounty's;
- it fetches the release and verifies every file's sha256;
- it works out what your reveal must carry and which attested nodes it trusts, traced down to what
  the kernel looks up;
- it runs the check in witness-sim, which charges PolkaJam 0.1.29's gas, and checks the package
  fits the chain's input limit.

Success ends with `check passed: commitment 0x…`. The log also has the check's gas, of the
bounty's 5×10⁹, and the package's size.

## 5. Commit

```sh
gh workflow run toaster-hunt.yml -R YOU/REPO -f bounty=3 -f step=commit -f proof=proofs/accLogFail.lean
```

This does the check again, then syncs a node, mints test funds for your account if it needs the
commit deposit (10), and commits. Success ends with `committed: 0x… at slot S (lemmas: witness)`.

From here on, **don't change the proof file, the seed or `lemmas`**. The reveal rebuilds the
witness from them, and only the same bytes open your commitment.

## 6. Reveal

```sh
gh workflow run toaster-hunt.yml -R YOU/REPO -f bounty=3 -f step=reveal -f proof=proofs/accLogFail.lean
```

This rebuilds the witness, checks your commitment is on chain, measures the reveal again, sends it,
and checks that the bounty now has your commitment as its leader. Success ends with
`revealed: your commitment leads bounty 3; finalize after slot E`. Rerunning finds it done.

Reveal soon after committing: until you do, nobody knows you have a proof, but nothing stops
someone else committing to theirs meanwhile. Once the reveal lands your proof is public, and
copying it is useless: any copy's commitment is later than yours.

## 7. Finalize and verify

After the window (30 slots, 3 minutes):

```sh
gh workflow run toaster-hunt.yml -R YOU/REPO -f bounty=3 -f step=finalize
```

Success ends with `claimed: bounty 3 paid you (0x…)`: the bounty is `Claimed`, its winner is your
account, and the reward is in your balance. Anyone can finalize; if someone already did, this just
checks the outcome. To look any time:

```sh
gh workflow run toaster-hunt.yml -R YOU/REPO -f bounty=3 -f step=status
curl -s https://ascrivener.github.io/witness/snapshot.json | jq '.bounties[] | select(.id == 3) | .status'
```

## Your own lemmas

By default (`lemmas=witness`) your reveal carries every node of yours, with its proof: your
lemmas, and anything else you use that isn't in the attested libraries. That's simplest, but it all
has to be checked in the one refine, within the bounty's 5×10⁹ gas, and fit one work package.

If it doesn't fit (`check` says so), use `lemmas=attest`, at commit **and** reveal:

- **commit** commits to a witness of just your theorem and its proof, naming your lemmas by hash;
- **reveal** first attests your lemmas on chain, in batches by dependency depth, each measured in
  witness-sim first (`scripts/attest-batches.py`, 10 test a batch as deposit). Right after, it
  reveals, trusting them.

The order matters. Attesting a lemma makes it public: its name and type are then known. Someone
who committed *before you* to a one-line proof citing that lemma would win. So:

1. **Commit before attesting anything.** The workflow only attests in the reveal step, once your
   commitment is on chain, and immediately before revealing.
2. **Never attest a lemma whose type is the goal's.** If its type is the bounty's statement, a
   proof that just cites it wins, for whoever committed to that earliest. The workflow refuses,
   checking syntactic equality and definitional equality in Lean.
3. **Give every lemma of yours an unguessable name.** A node's hash depends only on its name and
   type, so someone could pre-commit to a guess. The workflow refuses to attest a declaration of
   your file unless its name contains 16 or more hex digits in a row, e.g.
   `theorem step_3f9a1c07e2b4d685 : ...` (`openssl rand -hex 8`). Lean's auxiliary declarations
   (`step_3f9a….match_1`) inherit it.
4. **Never reveal against an attested goal.** The workflow stops if the goal itself is attested.

The bounties don't set `--bind-claim`, so a reveal may trust any number of attestations.

## Limits

- **One refine.** Your reveal's check, with everything it carries, must use at most the bounty's
  check gas (5×10⁹). `check` measures it exactly.
- **One work package.** Your reveal carries the check (516 KB), every attested node it trusts, and
  your witness. All of it must fit the chain's input limit (13.8 MB on the Toaster); `check` says
  how big it is. AccLogFail's library holds 17 MB of code facts alone, so a proof whose kernel run
  looks up much of it won't fit. Attest lemmas that need those facts (`lemmas=attest`), so that
  your reveal trusts your lemmas instead of the facts.
- **What a proof of `AccLogFailGoal` likely needs.** Two attested libraries back bounty 3, and
  its spec lists both (`libraries`), so `hunt.sh` trusts either automatically:
  - `acclogfail`, the statement's closure: what `AccLogFailGoal` mentions;
  - `acclogfail-proofs`, what jam-lean's own proofs of the same code region reach on top of it
    (`acc_log_lineK`, `acc_log_line`, the allocation-failure traps, `AccAbort`, and the `Fmt`,
    `Alloc` and `memcpy` lemmas under them): 21,911 nodes, the 45 declarations too heavy for
    one refine (`Fmt.io_l`, `Fmt.dl_iter` …) attested as judgments ([toaster-proof-library.md](toaster-proof-library.md)).

  Measured with jam-lean's proved success branch, `acc_log_lineK` (the same code, 6501 … 6630),
  as if it were a hunter's proof: its proof reaches **nothing outside the two libraries**, so the
  reveal carries only its own node and proof (a 79 KB witness). The check trusts 249 attested nodes
  and uses 4.40×10⁸ gas of the bounty's 5×10⁹; the package is 822 KB, 6% of the chain's input
  limit. A proof built from jam-lean's lemmas the same way should look much the same: your own
  new lemmas are what's left to carry (`lemmas=witness`) or attest (`lemmas=attest`). A lemma of
  yours too heavy for one refine (over `MAX_ATTEST_GAS`, 3.5×10⁹) still can't be attested by the
  hunt workflow, which doesn't split judgments.

  (Exact PolkaJam gas, from witness-sim; `scripts/toaster/hunt/hunt.sh` does the same
  measurement for your own proof, and `scripts/toaster/library/proxy.py` repeats this one.)
- **Build time.** Each run unpacks jam-lean's build for exactly the pinned commit, from the
  release `jam-lean-lake-<commit>` (`.github/workflows/jam-lean-cache.yml` copied it from
  jam-lean's own cache), so little rebuilds. Without that release it falls back to jam-lean's
  latest published build (`main`'s), and the further `main` has moved the more rebuilds; the
  workflow allows 5 hours.
- **The test asset.** Rewards and deposits are the Toaster's test asset, minted free by its faucet.

## If something fails

| Message | What to do |
|---|---|
| `no seed: add a repository secret named HUNTER_SEED` | add the secret (step 2) |
| `no proof: give a path ...` | pass `proof=PATH`, or add `HUNTER_PROOF` |
| `your proof doesn't compile` | the log has Lean's errors; fix it locally first (in a public fork, the log is public) |
| `your export has no NAME` / `isn't exactly the bounty's` | the theorem's name or type differs from `statement.lean` |
| `your proof uses sorry` | finish it |
| `the check doesn't accept your reveal within ... gas` | it's over 5×10⁹, or the kernel rejects it: try `lemmas=attest`, or a lighter proof |
| `over 95% of the chain's input limit` | `lemmas=attest`, so your reveal trusts your lemmas instead of large library nodes |
| `refusing to attest: ...` | rename the lemma (16+ hex digits), or don't state the goal as a lemma |
| `commitment ... isn't on chain: commit first` | the proof file, seed or `lemmas` changed since you committed, or the commit didn't land |
| `the reveal had no effect` | it was dropped or rejected: rerun `reveal`; your commitment stays valid until the bounty is decided |
| `bounty N is Claimed` / `Reclaimed` | the bounty is over |
| the node never syncs | rerun; `sync_timeout_minutes` raises the wait |

## Running it locally

On Linux with a synced PolkaJam 0.1.29 node of your own ([toaster.md](toaster.md) has the steps):

```sh
# this repository, the CLI and simulator
cargo build --release -p witness-cli -p witness-sim
# witness-lean and lean4export at the spec's pins, jam-lean at its pin with the module built (step 1)
(cd ../witness-lean && cargo build --release -p lean-host)
(cd ../lean4export && lake build lean4export)
export HUNTER_SEED=... WITNESS_LEAN_DIR=../witness-lean JAM_LEAN_DIR=../jam-lean \
  LEAN4EXPORT=../lean4export/.lake/build/bin/lean4export JAM_RPC=ws://localhost:19800
scripts/toaster/hunt/hunt.sh check  site/bounties/3.json MyProof.lean work   # no node needed
scripts/toaster/hunt/hunt.sh commit site/bounties/3.json MyProof.lean work
scripts/toaster/hunt/hunt.sh reveal site/bounties/3.json MyProof.lean work
scripts/toaster/hunt/hunt.sh finalize site/bounties/3.json "" work
```

`LEMMAS=attest` picks attest mode, `LEAN_LOG=1` shows Lean's messages, and `RELEASE_LOCAL=DIR` uses
release files you already have. `scripts/toaster/hunt/test-fake.sh` is the `test` step.

## Not yet supported

- **A proof in several files.** Put it in one file; your lemmas can live there.
- **Resuming an attest-mode reveal on a fresh runner.** If a reveal run attests your lemmas and then
  fails before revealing, rerun `reveal`. It plans the same batches; any whose claims differ, from a
  different timing split, are attested again, which costs deposits but is safe.
- **Splitting a lemma too heavy for one refine** into judgments (witness-lean's `lean-host
  judgments`), so it can be attested in pieces.
- **`--bind-claim` bounties.** None are posted. Their witness must start with the id of the one
  attestation it trusts beyond the bounty's.
