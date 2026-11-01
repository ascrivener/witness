# Idea: rewarding attested lemmas

Status: an idea, not planned. This records it and the problems with it, which so far look
fatal in its simple form.

## The idea

A proof too big for one reveal is attested in layers, and attested layers are public. A hunter who
attests some lemmas and then gets stuck has given them away: anyone can cite them and win with a
later commitment (see Front-running in the [README](../../README.md)). Nothing on chain rewards
that partial work.

The idea is to pay for it. When a bounty finalizes, part of the reward goes to the attesters of
the attestations the winning reveal cited, so attesting a useful lemma pays even if someone else
finishes the proof.

## Problems

**Copying evades payment.** This is the main one. A bundle is public once pinned, so a winner
who doesn't want to pay can attest the same lemmas themselves, or trivially reformatted ones,
under a new attestation, and cite that instead. Payment becomes voluntary in effect, for the
same reason an embargo couldn't protect attestations. Anything that fixes this has to tie credit
to content rather than to an attestation id, and the service doesn't interpret content.

**The attester isn't necessarily the author.** An attestation's id doesn't include the attester,
and the first `Attest` for a claim records it. A bundle is pinned before it's attested, so a
watcher can attest someone else's bundle first and take the credit. Front-running moves from
reveals to attestations. Fixing that needs commit-reveal for attestations too.

**The service can't tell which citations matter.**
- A reveal may cite attestations its bounty didn't name, and the check only returns a bool. So
  the winner can pad the reveal with citations of their own (or a sybil's) attestations and pay
  part of the reward back to themselves.
- Even honest citations don't separate novel lemmas from library layers. Whoever first attested
  Mathlib would collect on every bounty that uses it, for having run a known library through the
  checker.
- Fixing this needs the check to report which trusted subjects it used, which changes the check
  interface, and a way to tell novel from shared that nothing on chain has.

**Splitting is gameable.** Splitting per attestation rewards cutting one lemma into many
attestations. Splitting per subject does the same at the level of subjects. Splitting by attest
gas rewards padding the check's work. No unit is obviously the lemma's worth.

**Transitive credit is expensive.** Attestations form a DAG. Paying only direct citations shorts
the layers underneath. Paying transitively means walking the DAG in accumulate, which has 10M gas
per work report, and deciding how credit decays with depth.

**It dilutes the main reward.** Whatever goes to lemmas comes out of what the finisher gets,
unless the maker funds it separately. That weakens the incentive the bounty exists to create.

## Narrower variants

These avoid some of the problems, mostly by giving up on enforcement:
- **Maker-named contributions.** The maker lists attestations at bounty creation, or adds them
  later, with a share each. This is honest about being a judgment call, but it doesn't cover
  lemmas made after the bounty.
- **Voluntary splits.** The winner's reveal names recipients and shares. It's only enforceable as
  far as reputation goes, but it costs the service almost nothing.
- **Separate lemma bounties.** A maker who wants partial progress posts bounties for the lemmas
  themselves. This needs no new mechanism, and commit-reveal already protects each one.

The last needs no change, and is the thing to point people to until one of the others is worth
building.
