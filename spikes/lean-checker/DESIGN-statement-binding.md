# Design: binding a Lean proof to the bounty's statement

Status: proposal, from the [checker spike](README.md). Not implemented.

## The problem

The spike's check confirms that every declaration in the submitted export type-checks, and that
only standard axioms are used. That isn't enough for a bounty, because the solver controls the
whole export:

1. **A different theorem.** `theorem goal : True := trivial` checks fine.
2. **Redefined vocabulary.** For a bounty on "every n reaches 1 under `collatz`", the solver ships
   their own `collatz` that returns 1 immediately. The statement reads the same but means
   something trivial. The same trick works on `Nat`, `+`, anything the statement mentions.
3. **Extra axioms**, e.g. `axiom cheat : False`. The spike already blocks this with nanoda's axiom
   allow-list.

Binding stops (1) and (2): the poster fixes what the statement means, and the check enforces that
the solver proved exactly that.

## The idea: the poster publishes the statement environment

The poster writes the statement as a **`Prop`-valued definition**, not a theorem:

```lean
def collatz : Nat → Nat := ...
def reachesOne (n : Nat) : Prop := ∃ k, collatz^[k] n = 1
def Goal : Prop := ∀ n, 0 < n → reachesOne n      -- the statement
```

The poster exports `Goal` with `lean4export ... -- Goal`. That gives `Goal` plus every definition
it depends on (`collatz`, `Nat`, `+`, ...). This export is the **statement environment E**. It
contains no `sorry`, and it's the poster's to check and publish.

A solver proves the statement as a theorem whose type is **literally the constant `Goal`**:

```lean
theorem goal : Goal := by
  unfold Goal reachesOne
  ...
```

Because `Goal` and everything it mentions come from E, "the type of `goal` is the constant `Goal`"
is a complete, purely syntactic binding. There's no need to compare large expressions, and no
room for reinterpretation.

## Submitting only what's new

The solver's full export of `goal` contains all of E again, plus the proof and any library lemmas
it used. Instead, the solver submits a **delta P**: only the items not already in E. It's
numbered as a continuation of E's names, levels and expressions, so the checker reads `E ++ P` as
one export.

A small tool does this. It parses E and the full export, drops everything already in E, and
renumbers the rest to follow E. The checker gets the security property for free: **P can only add
declarations, never change E's.** The rule is simply that P may not declare any name E declares.
Lean environments are append-only, so nothing P adds can alter what E's definitions mean.

## The check

Bounty terms:
- `check_hash`: the Lean checker blob (nanoda plus this logic).
- `params` (small, inline):
  - `env_hash`: the hash of E, stored as a preimage of the service like the check blob.
  - `statement`: the name of the `Prop` definition (`Goal`).
  - `theorem`: the name the solver must use (`goal`).
- The axiom allow-list is fixed in the checker: `propext`, `Classical.choice`, `Quot.sound`.
  `Lean.trustCompiler` isn't allowed, since a theorem should never need it.

On reveal, refine runs the check on `(E, P)`:
1. Parse E, then continue parsing with P as the rest of the same export.
2. Reject if P declares any name E declares.
3. Reject any axiom not on the allow-list.
4. Type-check every declaration.
5. Find `theorem` in P. Require it to be a theorem, with no universe parameters, whose type is
   exactly the constant `statement` (an `Expr::Const` with no universe arguments).
6. Return true.

Any failure is a panic, which witness already treats as `false`.

## Checking E once instead of every time

Steps 1 and 4 re-parse and re-check all of E on every reveal. For a statement over `Nat.gcd`,
that's most of the 1.1 MB that ran out of gas in the spike. Since E is fixed per bounty:
- **A `VerifyEnv` operation:** anyone can ask refine to check E alone. Accumulate then records
  `EnvChecked(check_hash, env_hash)`.
- **Reveal checks only P's declarations.** It still parses E to build the environment, but skips
  checking E's declarations. Refine can't read state, so it reports `env_hash`, and accumulate pays
  out only if `EnvChecked` exists. A bounty can't be revealed against until its environment has
  been verified.
- **Later, layered environments:** E could be a list of layers, such as a shared "core `Nat` and
  `List`" layer verified once for everyone, plus a small per-bounty layer. That also shrinks what
  posters upload.

What remains per reveal is parsing E plus parsing and checking P. Parsing is the cost the binary
format work would cut. With checking E moved out of the reveal, parsing becomes the dominant
remaining cost.

## What witness needs (generic, not Lean-specific)

- **Extra preimages per bounty:** terms carry a short list of blob hashes (here, E), solicited,
  reference-counted and forgotten like check blobs. Refine looks them up and passes them to the
  check.
- **Heap for checks:** the service handles `grow_heap` from the inner VM. nanoda allocates
  heavily.
- **Large witnesses:** P can exceed the 64 KB payload limit, so take it from the work package's
  extrinsic data.
- **Pre-verification:** a generic form of `VerifyEnv`, where a check blob can attest that one of a
  bounty's blobs has been checked, with the attestation recorded by accumulate. This needs its own
  design; v1 can skip it and check E on every reveal, at a higher gas cost.

## Risks and open questions

- **Checker soundness.** nanoda is an independent kernel, not Lean's own. A bug that accepts a
  false proof pays out a bounty. Mitigations: track nanoda's own bug bounties and audits,
  cross-check with a second checker (lean4lean), or cap rewards until there's confidence.
- **Statement fidelity.** Binding guarantees the solver proved the poster's *formal* statement,
  not that the statement matches the poster's intent. A misformalized statement can be "solved"
  through the gap. That's the poster's risk; a review period before funding helps.
- **Unsafe and partial definitions.** lean4export leaves out unsafe declarations by default. Need
  to confirm nanoda rejects safe declarations that depend on unsafe ones, and treats `partial`
  definitions as opaque.
- **Universe polymorphism.** v1 requires a monomorphic `Goal`, with no universe parameters.
  Polymorphic statements would need step 5 to compare universe arguments.
- **Building the delta.** The renumbering tool must produce exactly what the checker expects.
  A mismatch fails the check, which costs the solver gas but never pays wrongly.

## Suggested order

1. Prototype the check (steps 1–6) and the delta tool natively, against the spike's proofs. Add
   negative tests: a wrong theorem, a redefined vocabulary, an extra axiom, a name collision.
2. Measure E and P sizes and gas for `gcd_comm`, with and without checking E at reveal time.
3. Then decide whether the binary format is still needed, and how urgently.
4. The witness changes (extra preimages, heap, large witnesses), then pre-verification.
