# jam-lean's proof-side library for AccLogFail, attested on the Toaster

**Status: planned and in its dry run; not yet attested live.** Approved by Adam (option (b) of the
bounty-3 measurement in [HUNTING.md](HUNTING.md#limits)).

The [AccLogFail bounty](toaster-acclogfail.md)'s attested library is its statement's closure: what
`AccLogFailGoal` mentions. A proof of it would use much more. jam-lean's proved success branch of
the same code (`acc_log_lineK`, 6501 … 6630) reaches 21,585 nodes outside that library, and two of
its lemmas are too heavy for one refine. Few hunters would attest all of that themselves. So this
library attests it once, on service 7, as a public good, on top of the acclogfail library. Hunters
then trust both automatically.

## The set

The roots are every declaration of four jam-lean modules (c22c197) covering the first log line's
code region ([`scripts/toaster/library/acclogfail-proofs.modules`](../scripts/toaster/library/acclogfail-proofs.modules)):

| Module | What |
|---|---|
| `Services.Bootstrap.Acc.Final.LogLineK` | `acc_log_lineK`: the region's success branch, under accumulate's context |
| `Services.Bootstrap.Fmt.AccFmt` | `acc_log_line`: the same, frame-only |
| `Services.Bootstrap.Acc.Transfer.Trap` | the allocation-failure traps, and `aborts_of_exhaustsP` |
| `Services.Bootstrap.Acc.Abort` | `AccAbort`, heap exhaustion as T2's abort reason |

The library is every node those roots' proofs reach that acclogfail doesn't hold.

| | |
|---|---|
| Roots | 30 declarations |
| Library | 21,911 nodes: 20.8 MB of statements, 154 MB of proofs (jam-lean's `Fmt`, `Alloc`, `memcpy` lemmas and the roots) |
| Batches | 4,596 by dependency depth (32 depths), each traced to what the kernel looks up, at 2.9×10⁹ gas a batch |
| Over budget alone | 148 declarations; measured in witness-sim, 103 fit under 3.5×10⁹ and stay whole |
| Heavy | 45 declarations over 3.5×10⁹ (up to 9.0×10⁹), split into 1,819 judgment ops and 45 finals |
| In all | 6,460 attestations; about 6.8×10¹² gas, an upper bound (35× the acclogfail library) |

## How it's attested

[`scripts/toaster/library/build.sh`](../scripts/toaster/library/build.sh), run by
[`.github/workflows/toaster-library.yml`](../.github/workflows/toaster-library.yml):

1. **Export.** Every declaration of the modules, and `AccLogFailGoal`, from jam-lean at c22c197
   (its pinned build, `jam-lean-lake-c22c197`). Then `plan.py set` picks the nodes outside
   acclogfail.
2. **Plan.** `plan.py batches` plans by dependency depth, then `lean-host trace` runs at a
   2.9×10⁹-gas budget a batch. `heavy.py` measures every declaration over budget alone in
   PolkaVM and splits those over 3.5×10⁹ into judgments. It uses witness-lean's
   `lean-host judgments` / `judgments-ops`, driven by `mathlib_work.py`'s `heavy_job` with its op
   cap lowered to 3.5×10⁹, and every op near the cap is run in PolkaVM. `layout.py` writes the
   batches for `scripts/attest-batches.py`, trusting acclogfail through its release claims
   (`base/lib-N.claim:E`) and every heavy op trusting the check's pinned nodes.
3. **Dry run, always.** acclogfail's batches are rebuilt from the same export and attested in
   witness-sim; their claims must be the release's, byte for byte. Then every batch of the new
   library is attested. The run stops on any rejection or any check over 3.5×10⁹ gas (70% of
   `MAX_CHECK_GAS`).
4. **Live.** Eight attesters (`proofs-TAG-a` …) are minted the test asset and attest in
   parallel, resuming from the chain. A run stops after `attest_minutes` and uploads its work for
   the next to resume. It never attests within 10 minutes of, or during, the service upgrade
   (2026-11-27 11:45–12:45 UTC).

Then the claims go in the release `toaster-attestations-v2`, as `acclogfail-proofs`
(`scripts/toaster/library/release.py`). The bounty-3 spec lists both libraries, so
`scripts/toaster/hunt/hunt.sh` trusts either.
