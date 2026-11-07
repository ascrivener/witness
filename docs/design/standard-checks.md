# Standard checks

Status: a list. The checks in `checks/` and witness-lean exist; the rest are proposals.

A check is the whole contract between a buyer and a worker, so a market is only as sound as its
checks (see "Check correctness" in [verification-layer.md](verification-layer.md)). The aim is a
small library of checks that many buyers share, each reviewed once, with params doing the work of
telling one use from another. A buyer should be able to say "the Lean check, with these params, on
this statement" rather than write a program.

## Exists

| Check | Accepts | Params | Blobs | Attest mode | Where |
|---|---|---|---|---|---|
| `factor` | x is a nontrivial factor of N | N | none | no | [`checks/factor`](../../checks/factor) |
| `blake2b-preimage` | x hashes to H | H | none | no | [`checks/blake2b-preimage`](../../checks/blake2b-preimage) |
| `dictionary` | x is words from a dictionary whose hash has D leading zero bits | D | the dictionary | no | [`checks/dictionary`](../../checks/dictionary) |
| `sorted-words` | as `dictionary`, over word volumes | D | volumes, attested | yes: each volume is sorted, after the ones it trusts | [`checks/sorted-words`](../../checks/sorted-words) |
| Lean 4 kernel | x proves the bounty's statement | see its repo | the statement's environment and library, attested | yes: declarations type-check, given the ones they trust | [witness-lean](https://github.com/ascrivener/witness-lean) |
| SAT refutation | a formula is unsatisfiable: the reveal trusts an attested empty clause | see its repo | refutation chunks, attested | yes | [witness-sat](https://github.com/ascrivener/witness-sat) |
| EVM exploit | a replayed transaction breaks an invariant, on state proven against an Ethereum state root | see its repo | see its repo | see its repo | [witness-evm](https://github.com/ascrivener/witness-evm) |

The first four are samples, to show the interface. The last three are real checkers, still on test
networks. witness-evm says it needs an outside review before money depends on it.

## Worth having (proposed)

- **Inference-proof verifiers.** A verifier for a succinct proof that a committed model produced an
  output: params fix the model commitment and the verifying key. Likely one check per proof system
  (a pairing-based SNARK, a FRI-based STARK), not per model. Unmeasured: the first step is to
  compile one verifier to PVM and measure its gas. For small models, a check that re-runs the model
  directly may fit in a refine and needs no proof.
- **Test harnesses.** Run a submitted PVM program against a test suite given as a blob (or attested,
  if large and shared), with gas and memory limits per test. A harness for one calling convention
  serves any number of jobs. Its weakness is the usual one: tests accept wrong programs that pass
  them.
- **Certificate checkers.** Problems whose answers carry cheap certificates: SAT assignments and
  refutations (DRAT/LRAT), LP and ILP optimality certificates, primality certificates. Checking
  is far cheaper than solving, which is exactly what a check should be.
- **Reproducible builds.** "Source tree T builds to binary B" by re-running a deterministic build in
  the check. Only for builds that fit in a refine, or that split into attested steps.
- **Data validators.** A dataset meets a schema, or contains no item from a blocklist: attest once,
  cite in later jobs.
- **Signature and header checks.** Another chain's headers or signatures, attested segment by
  segment, for bridges and oracles (see "Uses beyond proof bounties" in
  [attestations.md](attestations.md)).

## What makes a check standard

- **Its params say everything a buyer chooses.** Two uses that differ only in params share a blob
  and its review.
- **It rejects what it doesn't handle.** False in any mode it doesn't support, and false on
  malformed input, never a panic that depends on gas.
- **Its attest mode is sound by itself.** It accepts subjects only if they're correct given its
  trusted subjects, since every later run will trust them.
- **It's reviewed, and its source builds reproducibly to its hash,** so anyone can confirm the blob
  a job names is the code that was reviewed.
