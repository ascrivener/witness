//! The witness service's rules, written against small traits instead of host calls so they run
//! (and are tested) natively.
//!
//! - [`refine`] verifies an [`Op`]: signatures, limits, and the bounty's check via
//!   [`RefineEnv::run_check`].
//! - [`accumulate`] applies a [`Verified`] to a read-only [`State`] and returns the [`Effects`]:
//!   storage writes plus the preimages to solicit or forget. Nothing is written unless the
//!   whole operation is valid, so the service can check it can afford the storage first and then
//!   apply everything, rather than failing halfway through.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests;

use alloc::{collections::BTreeMap, vec::Vec};
use codec::{Decode, Encode};
use witness_types::{
	ATTEST_DEPOSIT, Account, AccountId, Attestation, AttestationClaim, AttestationId, BlobRef,
	Bounty, BountyId, BountyStatus, BountyTerms, COMMIT_DEPOSIT, CheckBlob, CheckMode, Claim,
	CommitRecord, Gas, Hash, MAX_BLOBS, MAX_BLOBS_LEN, MAX_CHECK_GAS, MAX_CHECK_LEN,
	MAX_CLAIM_WINDOW, MAX_MINT, MAX_PARAMS_LEN, MAX_WITNESS_LEN, MIN_CLAIM_WINDOW, MIN_COMMIT_AGE,
	Op, PIN_DEPOSIT, Points, Preimage, REVEAL_GRACE, Rejection, Signature, Slot, StorageKey,
	SubjectList, TrustedRef, Verified, blake2b256,
};

/// What refine needs from the host.
pub trait RefineEnv {
	/// The service's preimage `hash`, as of the work package's lookup anchor.
	fn lookup(&self, hash: &Hash) -> Option<Vec<u8>>;
	/// Run check blob `blob` on `args` with at most `gas`; `Ok` iff it returned true.
	fn run_check(&self, blob: &[u8], args: &[u8], gas: Gas) -> core::result::Result<(), Rejection>;
}

/// Read access to the service's storage and preimages.
pub trait State {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
	/// The service's preimage `hash`, if it is available.
	fn lookup(&self, hash: &Hash) -> Option<Vec<u8>>;
}

/// What an accepted operation changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Effects {
	/// Encoded [`StorageKey`] to new value, or `None` to remove.
	pub writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
	/// Preimages to solicit (hash, length) before applying the writes.
	pub solicit: Vec<(Hash, u32)>,
	/// Preimages to forget (hash, length) after applying the writes.
	pub forget: Vec<(Hash, u32)>,
}

pub type Result<T> = core::result::Result<T, &'static str>;

fn verify_signature(key: &AccountId, message: &[u8], signature: &Signature) -> bool {
	let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(key) else { return false };
	key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature)).is_ok()
}

/// Look up each of `blobs` (with whether the check may trust it), stopping as soon as their total
/// length passes [`MAX_BLOBS_LEN`]: refine can't tell yet whether they are the ones it should be
/// given, so it must not copy unbounded data.
fn fetch_blobs(
	env: &impl RefineEnv,
	blobs: impl Iterator<Item = (Preimage, bool)>,
) -> core::result::Result<Vec<(Preimage, bool, Vec<u8>)>, Rejection> {
	let mut fetched = Vec::new();
	let mut total = 0;
	for (blob, trusted) in blobs {
		let data = env.lookup(&blob.hash).ok_or(Rejection::BlobUnavailable)?;
		total += data.len();
		if total > MAX_BLOBS_LEN as usize {
			return Err(Rejection::BlobsTooLarge);
		}
		fetched.push((blob, trusted, data));
	}
	Ok(fetched)
}

/// Look up and decode the subject list `list`.
fn lookup_subject_list(env: &impl RefineEnv, list: &Preimage) -> core::result::Result<SubjectList, Rejection> {
	let data = env.lookup(&list.hash).ok_or(Rejection::BlobUnavailable)?;
	witness_types::decode_subject_list(&data).ok_or(Rejection::BadSubjectList)
}

/// Check that an op's `claims` are all by `check_hash` with one set of params, `params_hash` if
/// given, and each cited once, and return their ids.
fn check_claims(
	check_hash: &Hash,
	params_hash: Option<Hash>,
	claims: &[AttestationClaim],
) -> core::result::Result<Vec<AttestationId>, Rejection> {
	// A check only trusts its own attestations, with the same params: otherwise a subject
	// attested with lenient params (or by a lenient check) would be trusted by a strict one.
	let params_hash = params_hash.or(claims.first().map(|c| c.params_hash));
	if claims.iter().any(|c| c.check_hash != *check_hash || Some(c.params_hash) != params_hash) {
		return Err(Rejection::ForeignAttestation);
	}
	let ids: Vec<AttestationId> = claims.iter().map(AttestationClaim::id).collect();
	let mut sorted = ids.clone();
	sorted.sort();
	sorted.dedup();
	if sorted.len() != ids.len() {
		return Err(Rejection::BadTrustedRef);
	}
	Ok(ids)
}

/// The subjects `trusted` cites, in its order. Every claim must be used. Each claim's subject
/// list is looked up once and dropped before the next, so refine holds one list at a time.
fn resolve_trusted(
	env: &impl RefineEnv,
	claims: &[AttestationClaim],
	trusted: &[TrustedRef],
) -> core::result::Result<Vec<Preimage>, Rejection> {
	let mut uses: Vec<Vec<usize>> = claims.iter().map(|_| Vec::new()).collect();
	for (i, r) in trusted.iter().enumerate() {
		uses.get_mut(r.claim as usize).ok_or(Rejection::BadTrustedRef)?.push(i);
	}
	let mut subjects = Vec::with_capacity(trusted.len());
	subjects.resize(trusted.len(), Preimage { hash: [0; 32], len: 0 });
	for (claim, uses) in claims.iter().zip(&uses) {
		if uses.is_empty() {
			return Err(Rejection::BadTrustedRef);
		}
		let list = lookup_subject_list(env, &claim.subjects)?;
		for &i in uses {
			subjects[i] = *list.get(trusted[i].entry as usize).ok_or(Rejection::BadTrustedRef)?;
		}
	}
	Ok(subjects)
}

/// Run check blob `check_hash` in `mode` on `blobs`, `params` and `witness`.
fn run(
	env: &impl RefineEnv,
	check_hash: &Hash,
	mode: CheckMode,
	blobs: &[(Preimage, bool, Vec<u8>)],
	params: &[u8],
	witness: &[u8],
	gas: Gas,
) -> core::result::Result<(), Rejection> {
	let check = env.lookup(check_hash).ok_or(Rejection::CheckUnavailable)?;
	let blobs: Vec<CheckBlob> = blobs
		.iter()
		.map(|(blob, trusted, data)| CheckBlob { trusted: *trusted, hash: blob.hash, data })
		.collect();
	env.run_check(&check, &witness_types::check_args(mode, &blobs, params, witness), gas)
}

/// Refine a reveal: everything but the signatures and the claim, which it has none of.
#[allow(clippy::too_many_arguments)]
fn refine_reveal(
	env: &impl RefineEnv,
	bounty_id: BountyId,
	check_hash: Hash,
	params: Vec<u8>,
	blobs: Vec<BlobRef>,
	claims: Vec<AttestationClaim>,
	trusted: Vec<TrustedRef>,
	check_gas: Gas,
	hunter: AccountId,
	salt: Hash,
	witness: Vec<u8>,
) -> core::result::Result<Verified, Rejection> {
	if check_gas > MAX_CHECK_GAS {
		return Err(Rejection::CheckGasTooHigh);
	}
	if witness.len() > MAX_WITNESS_LEN as usize {
		return Err(Rejection::WitnessTooLong);
	}
	if params.len() > MAX_PARAMS_LEN as usize {
		return Err(Rejection::ParamsTooLong);
	}
	let plain: Vec<Preimage> = blobs
		.iter()
		.filter_map(|b| match b {
			BlobRef::Blob(p) => Some(*p),
			BlobRef::Attested { .. } => None,
		})
		.collect();
	if trusted.len() + plain.len() > MAX_BLOBS as usize {
		return Err(Rejection::BlobsTooLarge);
	}
	// The attestations' own params are their attest params, not the bounty's.
	let ids = check_claims(&check_hash, None, &claims)?;
	// The reveal must trust every subject its bounty cites. Accumulate checks the blobs are the
	// bounty's and the claims were recorded.
	for blob in &blobs {
		if let BlobRef::Attested { attestation, entry } = blob {
			if !trusted.iter().any(|r| ids.get(r.claim as usize) == Some(attestation) && r.entry == *entry) {
				return Err(Rejection::BadTrustedRef);
			}
		}
	}
	let trusted = resolve_trusted(env, &claims, &trusted)?;
	let in_order = trusted.iter().map(|p| (*p, true)).chain(plain.iter().map(|p| (*p, false)));
	let fetched = fetch_blobs(env, in_order)?;
	run(env, &check_hash, CheckMode::Reveal, &fetched, &params, &witness, check_gas)?;
	Ok(Verified::Reveal {
		bounty_id,
		check_hash,
		params_hash: blake2b256(&params),
		blobs_hash: blake2b256(&blobs.encode()),
		attestations: ids,
		check_gas,
		commitment: witness_types::commitment(bounty_id, &witness, &hunter, &salt),
		hunter,
		witness_hash: blake2b256(&witness),
	})
}

/// Refine an attestation.
#[allow(clippy::too_many_arguments)]
fn refine_attest(
	env: &impl RefineEnv,
	service_id: u32,
	attester: AccountId,
	nonce: u64,
	check_hash: Hash,
	params: Vec<u8>,
	subjects: Preimage,
	claims: Vec<AttestationClaim>,
	trusted: Vec<TrustedRef>,
	witness: Vec<u8>,
	check_gas: Gas,
	signature: Signature,
) -> core::result::Result<Verified, Rejection> {
	if check_gas > MAX_CHECK_GAS {
		return Err(Rejection::CheckGasTooHigh);
	}
	if witness.len() > MAX_WITNESS_LEN as usize {
		return Err(Rejection::WitnessTooLong);
	}
	if params.len() > MAX_PARAMS_LEN as usize {
		return Err(Rejection::ParamsTooLong);
	}
	if trusted.len() > MAX_BLOBS as usize {
		return Err(Rejection::BlobsTooLarge);
	}
	let params_hash = blake2b256(&params);
	let parents = check_claims(&check_hash, Some(params_hash), &claims)?;
	let claim = AttestationClaim {
		check_hash,
		params_hash,
		subjects,
		parents_root: witness_types::parents_root(&parents),
	};
	let message = witness_types::attest_message(service_id, &attester, nonce, &claim.id());
	if !verify_signature(&attester, &message, &signature) {
		return Err(Rejection::BadSignature);
	}
	let trusted = resolve_trusted(env, &claims, &trusted)?;
	let list = lookup_subject_list(env, &subjects)?;
	if trusted.len() + list.len() > MAX_BLOBS as usize {
		return Err(Rejection::BlobsTooLarge);
	}
	// The trusted subjects, then the subjects to attest.
	let in_order = trusted.iter().map(|p| (*p, true)).chain(list.iter().map(|p| (*p, false)));
	let fetched = fetch_blobs(env, in_order)?;
	run(env, &check_hash, CheckMode::Attest, &fetched, &params, &witness, check_gas)?;
	Ok(Verified::Attest { attester, nonce, claim, parents })
}

/// Verify `op`, received by service `service_id`.
pub fn refine(env: &impl RefineEnv, service_id: u32, op: Op) -> Verified {
	let verified = match op {
		Op::Mint { to, amount } => Ok(Verified::Mint { to, amount }),
		Op::CreateBounty { maker, nonce, terms, signature } => {
			let message = witness_types::create_message(service_id, &maker, nonce, &terms);
			if verify_signature(&maker, &message, &signature) {
				Ok(Verified::CreateBounty { maker, nonce, terms })
			} else {
				Err(Rejection::BadSignature)
			}
		},
		Op::Commit { bounty_id, committer, nonce, commitment, signature } => {
			let message =
				witness_types::commit_message(service_id, bounty_id, &committer, nonce, &commitment);
			if verify_signature(&committer, &message, &signature) {
				Ok(Verified::Commit { bounty_id, committer, nonce, commitment })
			} else {
				Err(Rejection::BadSignature)
			}
		},
		Op::Reveal { bounty_id, check_hash, params, blobs, claims, trusted, check_gas, hunter, salt, witness } =>
			refine_reveal(
				env, bounty_id, check_hash, params, blobs, claims, trusted, check_gas, hunter, salt, witness,
			),
		Op::Finalize { bounty_id } => Ok(Verified::Finalize { bounty_id }),
		Op::Reclaim { bounty_id, maker, nonce, signature } => {
			let message = witness_types::reclaim_message(service_id, bounty_id, &maker, nonce);
			if verify_signature(&maker, &message, &signature) {
				Ok(Verified::Reclaim { bounty_id, maker, nonce })
			} else {
				Err(Rejection::BadSignature)
			}
		},
		Op::Release { bounty_id, commitment } => Ok(Verified::Release { bounty_id, commitment }),
		Op::Pin { owner, nonce, blobs, signature } => {
			let message = witness_types::pin_message(service_id, &owner, nonce, &blobs);
			if verify_signature(&owner, &message, &signature) {
				Ok(Verified::Pin { owner, nonce, blobs })
			} else {
				Err(Rejection::BadSignature)
			}
		},
		Op::Attest {
			attester,
			nonce,
			check_hash,
			params,
			subjects,
			claims,
			trusted,
			witness,
			check_gas,
			signature,
		} => refine_attest(
			env, service_id, attester, nonce, check_hash, params, subjects, claims, trusted, witness,
			check_gas, signature,
		),
	};
	verified.unwrap_or_else(Verified::Rejected)
}

/// Reads through to `state`, seeing this transaction's own writes.
struct Tx<'a, S> {
	state: &'a S,
	fx: Effects,
}

impl<S: State> Tx<'_, S> {
	fn get<T: Decode>(&self, key: &StorageKey) -> Option<T> {
		let key = key.encode();
		let value = match self.fx.writes.get(&key) {
			Some(value) => value.clone(),
			None => self.state.get(&key),
		}?;
		T::decode(&mut &value[..]).ok()
	}

	fn set(&mut self, key: &StorageKey, value: &impl Encode) {
		self.fx.writes.insert(key.encode(), Some(value.encode()));
	}

	fn remove(&mut self, key: &StorageKey) {
		self.fx.writes.insert(key.encode(), None);
	}

	fn account(&self, id: &AccountId) -> Account {
		self.get(&StorageKey::Account(*id)).unwrap_or_default()
	}

	fn credit(&mut self, id: &AccountId, amount: Points) {
		let mut acc = self.account(id);
		acc.balance = acc.balance.saturating_add(amount);
		self.set(&StorageKey::Account(*id), &acc);
	}

	/// Check and bump `id`'s nonce, and take `amount` from its balance.
	fn charge(&mut self, id: &AccountId, nonce: u64, amount: Points) -> Result<()> {
		let mut acc = self.account(id);
		if nonce != acc.nonce {
			return Err("bad nonce");
		}
		acc.balance = acc.balance.checked_sub(amount).ok_or("insufficient points")?;
		acc.nonce += 1;
		self.set(&StorageKey::Account(*id), &acc);
		Ok(())
	}

	fn bounty(&self, id: BountyId) -> Result<Bounty> {
		self.get(&StorageKey::Bounty(id)).ok_or("no such bounty")
	}

	fn attestation(&self, id: &AttestationId) -> Result<Attestation> {
		self.get(&StorageKey::Attestation(*id)).ok_or("no such attestation")
	}

	fn subject_list(&self, list: &Preimage) -> Result<SubjectList> {
		let data = self.state.lookup(&list.hash).ok_or("subject list unavailable")?;
		witness_types::decode_subject_list(&data).ok_or("bad subject list")
	}

	/// Record a use of preimage `blob`, soliciting it if nothing used it yet.
	fn acquire(&mut self, blob: Preimage) {
		let key = StorageKey::PreimageRefs(blob.hash);
		let refs: u32 = self.get(&key).unwrap_or(0);
		if refs == 0 {
			self.fx.solicit.push((blob.hash, blob.len));
		}
		self.set(&key, &(refs + 1));
	}

	/// Drop a use of preimage `blob`, forgetting it once nothing uses it.
	fn release(&mut self, blob: Preimage) {
		let key = StorageKey::PreimageRefs(blob.hash);
		match self.get::<u32>(&key).unwrap_or(0) {
			0 | 1 => {
				self.remove(&key);
				self.fx.forget.push((blob.hash, blob.len));
			},
			n => self.set(&key, &(n - 1)),
		}
	}

	/// Drop the uses of every preimage `bounty` needs, now that it is finished.
	fn release_preimages(&mut self, bounty: &Bounty) {
		for blob in preimages(&bounty.terms) {
			self.release(blob);
		}
	}
}

/// The preimages a bounty holds while unfinished: its check blob, then its plain blobs. Attested
/// blobs are held for good by their attestations.
fn preimages(terms: &BountyTerms) -> impl Iterator<Item = Preimage> + '_ {
	let check = Preimage { hash: terms.check_hash, len: terms.check_len };
	let plain = terms.blobs.iter().filter_map(|b| match b {
		BlobRef::Blob(p) => Some(*p),
		BlobRef::Attested { .. } => None,
	});
	core::iter::once(check).chain(plain)
}

/// Whether a reveal could still change `bounty`'s outcome at `now`.
fn revealable(bounty: &Bounty, now: Slot) -> bool {
	match &bounty.status {
		BountyStatus::Open => now < bounty.terms.expiry.saturating_add(REVEAL_GRACE),
		BountyStatus::Revealing { window_end, .. } => now < *window_end,
		BountyStatus::Claimed { .. } | BountyStatus::Reclaimed => false,
	}
}

/// Apply `verified` at slot `now`. Refine rejections should not be passed here.
pub fn accumulate(state: &impl State, verified: Verified, now: Slot) -> Result<Effects> {
	let mut tx = Tx { state, fx: Effects::default() };
	match verified {
		Verified::Rejected(_) => return Err("rejected in refine"),
		Verified::Mint { to, amount } => {
			if amount > MAX_MINT {
				return Err("mint too large");
			}
			tx.credit(&to, amount);
		},
		Verified::CreateBounty { maker, nonce, terms } => {
			if terms.check_gas > MAX_CHECK_GAS ||
				terms.check_len > MAX_CHECK_LEN ||
				terms.params.len() > MAX_PARAMS_LEN as usize
			{
				return Err("check too large");
			}
			// Attested blobs must be subjects of this bounty's check's attestations, all with
			// one set of attest params, as a reveal will only trust those.
			let mut blobs_len = 0u64;
			let mut params_hash = None;
			for blob in &terms.blobs {
				blobs_len += match blob {
					BlobRef::Blob(p) => p.len,
					BlobRef::Attested { attestation, entry } => {
						let claim = tx.attestation(attestation)?.claim;
						if claim.check_hash != terms.check_hash {
							return Err("attested by another check");
						}
						if *params_hash.get_or_insert(claim.params_hash) != claim.params_hash {
							return Err("attested with other params");
						}
						let list = tx.subject_list(&claim.subjects)?;
						list.get(*entry as usize).ok_or("no such subject")?.len
					},
				} as u64;
			}
			if terms.blobs.len() > MAX_BLOBS as usize || blobs_len > MAX_BLOBS_LEN as u64 {
				return Err("blobs too large");
			}
			if !(MIN_CLAIM_WINDOW..=MAX_CLAIM_WINDOW).contains(&terms.claim_window) {
				return Err("claim window out of range");
			}
			if terms.expiry <= now.saturating_add(MIN_COMMIT_AGE) {
				return Err("expiry too soon");
			}
			tx.charge(&maker, nonce, terms.reward)?;

			for blob in preimages(&terms) {
				tx.acquire(blob);
			}

			let id: BountyId = tx.get(&StorageKey::NextBountyId).unwrap_or(0);
			tx.set(&StorageKey::NextBountyId, &(id + 1));
			tx.set(&StorageKey::Bounty(id), &Bounty { maker, terms, status: BountyStatus::Open });
		},
		Verified::Commit { bounty_id, committer, nonce, commitment } => {
			let bounty = tx.bounty(bounty_id)?;
			if !revealable(&bounty, now) || now >= bounty.terms.expiry {
				return Err("bounty not accepting commitments");
			}
			let key = StorageKey::Commitment(bounty_id, commitment);
			if tx.get::<CommitRecord>(&key).is_some() {
				return Err("already committed");
			}
			tx.charge(&committer, nonce, COMMIT_DEPOSIT)?;
			let record = CommitRecord { slot: now, committer, deposit: COMMIT_DEPOSIT };
			tx.set(&key, &record);
		},
		Verified::Reveal {
			bounty_id,
			check_hash,
			params_hash,
			blobs_hash,
			attestations,
			check_gas,
			commitment,
			hunter,
			witness_hash,
		} => {
			let mut bounty = tx.bounty(bounty_id)?;
			// Refine ran the check on the subjects of the claims the reveal supplied. Their ids
			// bind the claims, so this makes sure they were really attested.
			for id in &attestations {
				tx.attestation(id)?;
			}
			if bounty.terms.check_hash != check_hash ||
				bounty.terms.check_gas != check_gas ||
				blake2b256(&bounty.terms.params) != params_hash ||
				blake2b256(&bounty.terms.blobs.encode()) != blobs_hash
			{
				return Err("revealed against different terms");
			}
			if !revealable(&bounty, now) {
				return Err("reveal window closed");
			}
			let key = StorageKey::Commitment(bounty_id, commitment);
			let record: CommitRecord = tx.get(&key).ok_or("no commitment")?;
			if record.slot.saturating_add(MIN_COMMIT_AGE) > now {
				return Err("commitment too recent");
			}
			if record.slot >= bounty.terms.expiry {
				return Err("committed after expiry");
			}

			let claim = Claim { committed: record.slot, commitment, hunter, witness_hash };
			bounty.status = match bounty.status {
				BountyStatus::Open => BountyStatus::Revealing {
					window_end: now.saturating_add(bounty.terms.claim_window),
					leader: claim,
				},
				BountyStatus::Revealing { window_end, leader } => BountyStatus::Revealing {
					window_end,
					leader: if claim.beats(&leader) { claim } else { leader },
				},
				// `revealable` rules these out.
				BountyStatus::Claimed { .. } | BountyStatus::Reclaimed => return Err("reveal window closed"),
			};
			tx.set(&StorageKey::Bounty(bounty_id), &bounty);
			// Any valid reveal gets its deposit back, winning or not.
			tx.credit(&record.committer, record.deposit);
			tx.remove(&key);
		},
		Verified::Finalize { bounty_id } => {
			let mut bounty = tx.bounty(bounty_id)?;
			let BountyStatus::Revealing { window_end, leader } = bounty.status.clone() else {
				return Err("bounty not revealing");
			};
			if now < window_end {
				return Err("claim window still open");
			}
			tx.credit(&leader.hunter, bounty.terms.reward);
			tx.release_preimages(&bounty);
			bounty.status = BountyStatus::Claimed { winner: leader, slot: now };
			tx.set(&StorageKey::Bounty(bounty_id), &bounty);
		},
		Verified::Reclaim { bounty_id, maker, nonce } => {
			let mut bounty = tx.bounty(bounty_id)?;
			if bounty.maker != maker {
				return Err("not the maker");
			}
			if bounty.status != BountyStatus::Open {
				return Err("bounty not open");
			}
			if revealable(&bounty, now) {
				return Err("reveal window still open");
			}
			tx.charge(&maker, nonce, 0)?;
			tx.credit(&maker, bounty.terms.reward);
			tx.release_preimages(&bounty);
			bounty.status = BountyStatus::Reclaimed;
			tx.set(&StorageKey::Bounty(bounty_id), &bounty);
		},
		Verified::Release { bounty_id, commitment } => {
			let key = StorageKey::Commitment(bounty_id, commitment);
			tx.get::<CommitRecord>(&key).ok_or("no commitment")?;
			if let Ok(bounty) = tx.bounty(bounty_id) {
				if revealable(&bounty, now) {
					return Err("commitment can still be revealed");
				}
			}
			tx.remove(&key);
		},
		Verified::Pin { owner, nonce, blobs } => {
			// A subject list and its subjects.
			if blobs.len() > MAX_BLOBS as usize + 1 {
				return Err("too many blobs");
			}
			if blobs.iter().any(|b| b.len > MAX_BLOBS_LEN.max(MAX_CHECK_LEN)) {
				return Err("blob too large");
			}
			tx.charge(&owner, nonce, PIN_DEPOSIT * blobs.len() as Points)?;
			for blob in blobs {
				tx.acquire(blob);
			}
		},
		Verified::Attest { attester, nonce, claim, parents } => {
			let id = claim.id();
			if tx.attestation(&id).is_ok() {
				return Err("already attested");
			}
			// Refine ran the check trusting the parents' claimed subjects. Their ids bind the
			// claims, and an attestation is only recorded once its parents were, so this makes
			// sure everything it rests on was really attested.
			for parent in &parents {
				tx.attestation(parent).map_err(|_| "no such parent attestation")?;
			}
			tx.charge(&attester, nonce, ATTEST_DEPOSIT)?;
			// Attestations are kept for good, so their subjects are too.
			let list = tx.subject_list(&claim.subjects)?;
			tx.acquire(claim.subjects);
			for subject in list {
				tx.acquire(subject);
			}
			tx.set(&StorageKey::Attestation(id), &Attestation { claim, slot: now, attester });
		},
	}
	Ok(tx.fx)
}
