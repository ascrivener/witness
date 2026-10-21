# Spike: a Lean 4 proof checker in JAM refine

**Question:** could witness pay bounties for Lean proofs, with refine running a Lean kernel checker
on the submitted proof?

**Answer:** yes for small, self-contained proofs, which check in 50–110 M gas, a tenth of
witness's current check-gas cap. Proofs that pull in more of the library don't fit yet: parsing
the JSON export is the main cost, and one export ran past the testnet's 1 billion-gas refine
limit. Bad proofs are rejected, both `sorry` and tampered statements.

Done 2026-10-20 against PolkaJam v0.1.29 (GP 0.8.0), `jam-pvm-common` 0.1.29, Lean
v4.36.0-rc1, lean4export at `main`, nanoda_lib `9d6964f`.

## What was built

- **`nanoda-no_std.patch`**: a `no_std` port of [nanoda_lib](https://github.com/ammkrn/nanoda_lib), an
  independent Lean 4 kernel checker in Rust (Apache-2.0). The changes:
  - `std` swapped for `core`/`alloc`, and `hashbrown` for `std` collections.
  - The parallel checker made serial, and file and stdout I/O removed.
  - Parsing from an in-memory string, plus a `Config::in_memory` constructor.
  - Process exits turned into panics.
- **`host-check/`**: a native harness for the port, used for baselines.
- **`lean-spike/`**: a JAM service.
  - `Solicit { hash, len }` makes accumulate solicit an export as a preimage.
  - `Check { hash }` makes refine look it up, parse it, type-check every declaration, and report
    the gas each phase used.
  - A bad proof panics, so refine fails.
- **`proofs/`**: a Lean project with the sample theorems, including `Bad.lean`, which uses `sorry`.
- **Binary export format** (added later): [`binary_format.md`](binary_format.md), the
  `delta/lean_bin.py` converter, and a decoder in the patched parser. The format is detected
  automatically.
- **Statement binding** (added later; see [the design](DESIGN-statement-binding.md)):
  - `nanoda/src/binding.rs` in the patch: the check.
  - `delta/lean_delta.py`: the solver's delta tool.
  - `test-binding.sh`: 4 honest proofs accepted, 8 attacks rejected.

## Results

### On the PVM

Measured on a local `polkajam-testnet`. It uses the "tiny" parameters, where refine's gas limit is
10⁹; the full spec allows 5×10⁹.

| Theorem | Export | Declarations | Parse gas | Check gas | Total |
|---|---|---|---|---|---|
| `2 + 2 = 4` (`rfl`) | 36 KB | 38 | 26.8 M | 23.3 M | **50 M** |
| `a + b = b + a` (cites `Nat.add_comm`) | 61 KB | 53 | 45.5 M | 64.6 M | **110 M** |
| own `MyNat`, `zero_add` by induction | 42 KB | 37 | 31.5 M | 26.4 M | **58 M** |
| `l.reverse.reverse = l` | 59 KB | 46 | 44.5 M | 44.8 M | **89 M** |
| `Nat.gcd_comm` | 1.1 MB | 509 | 803 M | out of gas | **> 10⁹** |

**Rejection tests:**
- `theorem cheat : 2 + 2 = 5 := sorry` is rejected, because `sorryAx` isn't a permitted axiom.
- The `2 + 2 = 4` export edited to say `5` is rejected (`def_eq` fails). On-chain, it parses, then
  refine fails.

### Native, for comparison

Small proofs take 0.9–1.8 ms to parse and check. `gcd_comm` takes 24 ms (7 ms parsing, 16 ms
checking). Peak memory is at most 7 MB.

### Size and memory

- The service blob, including nanoda, serde_json and num-bigint, is about **557 KB**, under
  witness's 1 MB `MAX_CHECK_LEN`.
- A 1 MB stack was enough for every proof that fit in the gas budget. Natively, nanoda asks for a
  16 MB stack for deep proofs. The standard program format stores the stack size in 3 bytes, so
  the maximum is just under 16 MB.

### Update: binary format and binding on the PVM (2026-10-21)

The [binary export format](binary_format.md) is about 11% of the JSON size. Measured on the same
v0.1.29 testnet (refine limit 10⁹ gas):

| `gcd a b = gcd b a`, bound (env 466 KB + delta 655 KB of JSON) | Parse | Binding | Check env | Check delta | Total |
|---|---|---|---|---|---|
| JSON | 773 M | — | — | — | out of gas after parsing |
| Binary (52 KB + 74 KB) | 102 M | — | 473 M | needed > 425 M | out of gas |
| **Binary, environment pre-checked** | **102 M** | **5.6 M** | — | **841 M** | **948 M: passes** |

- **Parsing is 7.6× cheaper** in binary. For the small `2 + 2 = 4` environment, it's 4.0 M gas
  instead of 25.3 M.
- **With the environment pre-checked, a medium proof fits** in one refine: `gcd_comm` reveals
  for 948 M gas. The one-off environment check (about 473 M) also fits on its own.
- **Checking the delta now dominates,** at 89% of a reveal. The delta is 247 declarations, mostly
  library lemmas the proof uses. Shrinking it means a shared, pre-checked library layer, not
  faster parsing.
- The service blob with the decoder and binding is 629 KB.

## What it means for witness

1. **Feasible today for small proofs.** Self-contained theorems over core `Nat` and `List` check
   in 5–11% of `MAX_CHECK_GAS`.
2. **Parsing dominates, and it's fixable.** It costs about 720 gas per byte, and for most exports
   it's at least half the total. A compact binary export, or a pre-parsed binary form of the
   environment, should cut it substantially (not measured).
3. **Dependencies dominate size.** Even `2 + 2 = 4` ships 38 declarations: `Nat`, `HAdd`, `OfNat`
   and so on. A shared, pre-checked environment blob (core `Init` by hash), with the solver
   supplying only the new declarations, would cut both size and gas. That needs a design for
   trusting a pre-checked environment.
4. **Medium proofs need more gas.** `gcd_comm` would need about 2.5×10⁹ in total, estimated from
   the native ratio of check to parse time. That's over the testnet's 10⁹, possibly within the full
   spec's 5×10⁹, and well over witness's `MAX_CHECK_GAS` (10⁹). Not verified.
5. **Mathlib-scale proofs are out of reach** without (2) and (3) together, and probably still out
   of reach.
6. **Not tested: binding the statement.** The spike checks every declaration but doesn't confirm
   that the proved theorem is *the bounty's* statement. A real check must:
   - fix the poster's definitions and statement (the solver can't redefine `Nat`),
   - confirm the named theorem's type equals the bounty's statement exactly,
   - allow only permitted axioms.

   This design is the main security risk.
7. **The witness repo changes needed, now confirmed:**
   - **Heap for checks:** service `grow_heap` for the inner VM. nanoda allocates heavily.
   - **Large inputs:** exports are 36 KB to 1 MB or more, against `MAX_WITNESS_LEN` of 64 KB.
     Take witnesses from extrinsics, and environments from preimage blobs.
   - **Memory:** `MAX_CHECK_PAGES` (16 MB) has to cover stack plus heap. That's enough for these
     proofs, tight for bigger ones.
   - **Gas:** possibly raise `MAX_CHECK_GAS` toward the refine limit.

## Suggested next steps

1. ~~Design statement binding (6).~~ Designed, and prototyped natively: see
   [the design](DESIGN-statement-binding.md).
2. ~~Cut parsing cost with a binary export format (2), then measure `gcd_comm` again.~~ Done:
   7.6× cheaper parsing, and `gcd_comm` reveals in 948 M gas with the environment pre-checked.
3. A shared, pre-checked library layer, to move common lemmas out of solver deltas. Delta
   checking is now 89% of a reveal.
4. In witness: heap support, environment blobs and large witnesses (7), then pre-verification.
5. Measure on a testnet with full-spec parameters, if `polkajam-testnet` can run one.

## Reproducing

Needs Lean (elan), lean4export built with `lake build`, `cargo-jam-build`, the witness CLI built,
and PolkaJam v0.1.29.

```bash
./setup.sh
```

```bash
cd host-check && cargo run --release -- ../proofs/two_add_two.ndjson
```

Build the exports from `proofs/`, with `lake build`, then
`lake env <lean4export> Proofs.Basic -- <theorem> > <theorem>.ndjson`. Then build the service
and run it against a testnet:

```bash
cd lean-spike && cargo jam-build --out-dir out
```

```bash
./run-on-testnet.sh <service id> <testnet log> two_add_two add_comm_ex
```
