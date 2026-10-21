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
	Op, PIN_DEPOSIT, Points, Preimage, REVEAL_GRACE, RevealBlob, Rejection, Signature, Slot,
	StorageKey, Verified, blake2b256,
};

/// What refine needs from the host.
pub trait RefineEnv {
	/// The service's preimage `hash`, as of the work package's lookup anchor.
	fn lookup(&self, hash: &Hash) -> Option<Vec<u8>>;
	/// Run check blob `blob` on `args` with at most `gas`; `Ok` iff it returned true.
	fn run_check(&self, blob: &[u8], args: &[u8], gas: Gas) -> core::result::Result<(), Rejection>;
}

/// Read access to the service's storage.
pub trait State {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
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

/// The preimage a reveal blob is, and whether the check may trust it.
fn reveal_blob(blob: &RevealBlob) -> (Preimage, bool) {
	match blob {
		RevealBlob::Blob(p) => (*p, false),
		RevealBlob::Attested(claim) => (claim.subject, true),
	}
}

/// Verify `op`, received by service `service_id`.
pub fn refine(env: &impl RefineEnv, service_id: u32, op: Op) -> Verified {
	match op {
		Op::Mint { to, amount } => Verified::Mint { to, amount },
		Op::CreateBounty { maker, nonce, terms, signature } => {
			let message = witness_types::create_message(service_id, &maker, nonce, &terms);
			if !verify_signature(&maker, &message, &signature) {
				return Verified::Rejected(Rejection::BadSignature);
			}
			Verified::CreateBounty { maker, nonce, terms }
		},
		Op::Commit { bounty_id, committer, nonce, commitment, signature } => {
			let message =
				witness_types::commit_message(service_id, bounty_id, &committer, nonce, &commitment);
			if !verify_signature(&committer, &message, &signature) {
				return Verified::Rejected(Rejection::BadSignature);
			}
			Verified::Commit { bounty_id, committer, nonce, commitment }
		},
		Op::Reveal { bounty_id, check_hash, params, blobs, check_gas, hunter, salt, witness } => {
			if check_gas > MAX_CHECK_GAS {
				return Verified::Rejected(Rejection::CheckGasTooHigh);
			}
			if witness.len() > MAX_WITNESS_LEN as usize {
				return Verified::Rejected(Rejection::WitnessTooLong);
			}
			if params.len() > MAX_PARAMS_LEN as usize {
				return Verified::Rejected(Rejection::ParamsTooLong);
			}
			if blobs.len() > MAX_BLOBS as usize {
				return Verified::Rejected(Rejection::BlobsTooLarge);
			}
			// Trust only this check's own attestations. Accumulate checks the claims are the
			// bounty's, and the bounty only cites attestations that were recorded.
			if blobs.iter().any(|b| matches!(b, RevealBlob::Attested(c) if c.check_hash != check_hash)) {
				return Verified::Rejected(Rejection::ForeignAttestation);
			}
			let result = fetch_blobs(env, blobs.iter().map(reveal_blob)).and_then(|fetched| {
				run(env, &check_hash, CheckMode::Reveal, &fetched, &params, &witness, check_gas)
			});
			if let Err(rejection) = result {
				return Verified::Rejected(rejection);
			}
			let refs: Vec<BlobRef> = blobs.iter().map(RevealBlob::blob_ref).collect();
			Verified::Reveal {
				bounty_id,
				check_hash,
				params_hash: blake2b256(&params),
				blobs_hash: blake2b256(&refs.encode()),
				check_gas,
				commitment: witness_types::commitment(bounty_id, &witness, &hunter, &salt),
				hunter,
				witness_hash: blake2b256(&witness),
			}
		},
		Op::Finalize { bounty_id } => Verified::Finalize { bounty_id },
		Op::Reclaim { bounty_id, maker, nonce, signature } => {
			let message = witness_types::reclaim_message(service_id, bounty_id, &maker, nonce);
			if !verify_signature(&maker, &message, &signature) {
				return Verified::Rejected(Rejection::BadSignature);
			}
			Verified::Reclaim { bounty_id, maker, nonce }
		},
		Op::Release { bounty_id, commitment } => Verified::Release { bounty_id, commitment },
		Op::Pin { owner, nonce, blob, signature } => {
			let message = witness_types::pin_message(service_id, &owner, nonce, &blob);
			if !verify_signature(&owner, &message, &signature) {
				return Verified::Rejected(Rejection::BadSignature);
			}
			Verified::Pin { owner, nonce, blob }
		},
		Op::Attest { attester, nonce, check_hash, params, subject, parents, check_gas, signature } => {
			let claim = AttestationClaim {
				check_hash,
				params_hash: blake2b256(&params),
				subject,
				parents: parents.iter().map(AttestationClaim::id).collect(),
			};
			let message = witness_types::attest_message(service_id, &attester, nonce, &claim.id());
			if !verify_signature(&attester, &message, &signature) {
				return Verified::Rejected(Rejection::BadSignature);
			}
			if check_gas > MAX_CHECK_GAS {
				return Verified::Rejected(Rejection::CheckGasTooHigh);
			}
			if params.len() > MAX_PARAMS_LEN as usize {
				return Verified::Rejected(Rejection::ParamsTooLong);
			}
			if parents.len() >= MAX_BLOBS as usize {
				return Verified::Rejected(Rejection::BlobsTooLarge);
			}
			// A chain is verified under one check and one set of params: otherwise a layer
			// attested with lenient params (or by a lenient check) would be trusted by a strict one.
			if parents.iter().any(|p| p.check_hash != check_hash || p.params_hash != claim.params_hash) {
				return Verified::Rejected(Rejection::ForeignAttestation);
			}
			// The parents' subjects, trusted, then the subject.
			let blobs = parents.iter().map(|p| (p.subject, true)).chain([(subject, false)]);
			let result = fetch_blobs(env, blobs).and_then(|fetched| {
				run(env, &check_hash, CheckMode::Attest, &fetched, &params, &[], check_gas)
			});
			if let Err(rejection) = result {
				return Verified::Rejected(rejection);
			}
			Verified::Attest { attester, nonce, claim }
		},
	}
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
		BlobRef::Attested(_) => None,
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
			let mut blobs_len = 0u64;
			for blob in &terms.blobs {
				blobs_len += match blob {
					BlobRef::Blob(p) => p.len,
					BlobRef::Attested(id) => {
						let attestation = tx.attestation(id)?;
						if attestation.claim.check_hash != terms.check_hash {
							return Err("attested by another check");
						}
						attestation.claim.subject.len
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
			check_gas,
			commitment,
			hunter,
			witness_hash,
		} => {
			let mut bounty = tx.bounty(bounty_id)?;
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
		Verified::Pin { owner, nonce, blob } => {
			if blob.len > MAX_BLOBS_LEN.max(MAX_CHECK_LEN) {
				return Err("blob too large");
			}
			tx.charge(&owner, nonce, PIN_DEPOSIT)?;
			tx.acquire(blob);
		},
		Verified::Attest { attester, nonce, claim } => {
			let id = claim.id();
			if tx.attestation(&id).is_ok() {
				return Err("already attested");
			}
			// Refine ran the check on the parents' claimed subjects; the ids bind those claims,
			// so this makes sure they were really attested.
			for parent in &claim.parents {
				tx.attestation(parent).map_err(|_| "no such parent attestation")?;
			}
			tx.charge(&attester, nonce, ATTEST_DEPOSIT)?;
			// Attestations are kept for good, so their subjects are too.
			tx.acquire(claim.subject);
			tx.set(&StorageKey::Attestation(id), &Attestation { claim, slot: now, attester });
		},
	}
	Ok(tx.fx)
}
