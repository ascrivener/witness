//! The witness service's rules, written against small traits instead of host calls so they run
//! (and are tested) natively.
//!
//! - [`refine`] verifies an [`Op`]: signatures, limits, and the bounty's check via
//!   [`RefineEnv::run_check`].
//! - [`on_transfer`] credits a deposit from a token service.
//! - [`accumulate`] applies a [`Verified`] to a read-only [`State`] and returns the [`Effects`]:
//!   storage writes. Nothing is written unless the whole operation is valid, so the service can
//!   check it can afford the storage first and then apply everything, rather than failing halfway
//!   through. Blobs come with the ops that use them (as extrinsics), so state is only records.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests;

use alloc::{collections::BTreeMap, vec::Vec};
use codec::{Decode, DecodeAll, Encode};
use witness_types::{
	ADMIN_DELAY, Account, AccountId, AdminAction, Amount, Asset, Attestation, AttestationClaim,
	AttestationId, BUILD_ADMIN, BlobAt, BlobHash, BlobRef, Bounty, BountyId, BountyStatus, CheckBlob,
	CheckMode, Citations, Claim, CommitRecord, Config, Gas, Hash, MAX_BLOBS, MAX_BLOBS_LEN, MAX_CHECK_GAS,
	MAX_CHECK_LEN, MAX_CLAIM_WINDOW, MAX_MINT, MAX_PARAMS_LEN, MAX_WITNESS_LEN, MEMO_LEN,
	MIN_CLAIM_WINDOW, MIN_COMMIT_AGE, Op, Proposal, REVEAL_GRACE, Rejection, Signature, Slot, StorageKey,
	TEST_ASSET, TokenMemo, TrustedRef, Verified, Witness, WithdrawalMemo, blake2b256, blobs_in, merkle,
};

/// Whether this build has the test faucet (`Mint`, crediting [`TEST_ASSET`]).
pub const FAUCET: bool = cfg!(any(test, feature = "faucet"));

/// What refine needs from the host.
pub trait RefineEnv {
	/// Extrinsic `index` of the work item being refined.
	fn extrinsic(&self, index: usize) -> Option<Vec<u8>>;
	/// The Blake2b-256 hash of extrinsic `index`, as the work package commits to it.
	fn extrinsic_hash(&self, index: usize) -> Option<Hash>;
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
	/// Transfers to send, with no native balance: (destination service, memo).
	pub transfers: Vec<(u32, [u8; MEMO_LEN])>,
	/// A preimage to solicit: (hash, length).
	pub solicit: Option<(Hash, u32)>,
	/// Replace the service's code with the preimage hashing to this.
	pub upgrade: Option<Hash>,
}

pub type Result<T> = core::result::Result<T, &'static str>;
type Refined<T> = core::result::Result<T, Rejection>;

fn verify_signature(key: &AccountId, message: &[u8], signature: &Signature) -> bool {
	let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(key) else { return false };
	key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature)).is_ok()
}

/// The work item's extrinsics, each fetched and decoded once.
struct Extrinsics<'e, E> {
	env: &'e E,
	/// An extrinsic's bytes, and where each of its blobs is in them.
	fetched: BTreeMap<u8, (Vec<u8>, Vec<core::ops::Range<usize>>)>,
}

impl<'e, E: RefineEnv> Extrinsics<'e, E> {
	fn new(env: &'e E) -> Self {
		Extrinsics { env, fetched: BTreeMap::new() }
	}

	fn fetch(&mut self, extrinsic: u8) -> Refined<&(Vec<u8>, Vec<core::ops::Range<usize>>)> {
		if !self.fetched.contains_key(&extrinsic) {
			let data = self.env.extrinsic(extrinsic as usize).ok_or(Rejection::BadBlob)?;
			let start = data.as_ptr() as usize;
			let ranges = blobs_in(&data)
				.ok_or(Rejection::BadExtrinsic)?
				.iter()
				.map(|b| b.as_ptr() as usize - start..b.as_ptr() as usize - start + b.len())
				.collect();
			self.fetched.insert(extrinsic, (data, ranges));
		}
		Ok(&self.fetched[&extrinsic])
	}

	/// The blob at `at`.
	fn blob(&mut self, at: BlobAt) -> Refined<Vec<u8>> {
		let (data, ranges) = self.fetch(at.extrinsic)?;
		let range = ranges.get(at.index as usize).ok_or(Rejection::BadBlob)?;
		Ok(data[range.clone()].to_vec())
	}

	/// Extrinsic `extrinsic`, whole, which must hash to `hash`. The work package commits to its
	/// hash, so refine doesn't hash it again: a check blob is the biggest an op carries, and
	/// hashing costs about 60 gas a byte in PVM.
	fn whole(&self, extrinsic: u8, hash: &Hash) -> Refined<Vec<u8>> {
		if self.env.extrinsic_hash(extrinsic as usize) != Some(*hash) {
			return Err(Rejection::BadBlob);
		}
		self.env.extrinsic(extrinsic as usize).ok_or(Rejection::BadBlob)
	}

	/// The blob at `at`, which must hash to `hash`.
	fn blob_hashing_to(&mut self, at: BlobAt, hash: &Hash) -> Refined<Vec<u8>> {
		let data = self.blob(at)?;
		if blake2b256(&data) != *hash {
			return Err(Rejection::BadBlob);
		}
		Ok(data)
	}

	/// Every blob of extrinsic `extrinsic`.
	fn all(&mut self, extrinsic: u8) -> Refined<Vec<Vec<u8>>> {
		let (data, ranges) = self.fetch(extrinsic)?;
		Ok(ranges.iter().map(|r| data[r.clone()].to_vec()).collect())
	}
}

/// An op's citations: none, or extrinsic `at`, whole, decoded. Its hash is the work package's to
/// commit to, and every reference in it is checked against its claim.
fn citations(env: &impl RefineEnv, at: Option<u8>) -> Refined<Citations> {
	let Some(at) = at else { return Ok(Citations::default()) };
	let data = env.extrinsic(at as usize).ok_or(Rejection::BadBlob)?;
	Citations::decode_all(&mut &data[..]).map_err(|_| Rejection::BadExtrinsic)
}

/// The blobs a check is given, as (hash, trusted, data), in order. Their count and total length
/// are checked as they're added: refine can't tell yet whether they are the ones it should be
/// given, so it must not copy unbounded data.
#[derive(Default)]
struct CheckBlobs {
	blobs: Vec<(Hash, bool, Vec<u8>)>,
	len: usize,
}

impl CheckBlobs {
	fn push(&mut self, hash: Hash, trusted: bool, data: Vec<u8>) -> Refined<()> {
		self.len += data.len();
		if self.blobs.len() >= MAX_BLOBS as usize || self.len > MAX_BLOBS_LEN as usize {
			return Err(Rejection::BlobsTooLarge);
		}
		self.blobs.push((hash, trusted, data));
		Ok(())
	}
}

/// Check that an op's `claims` are all by `check_hash` with one set of params, `params_hash` if
/// given, and each cited once, and return their ids.
fn check_claims(check_hash: &Hash, params_hash: Option<Hash>, claims: &[AttestationClaim]) -> Refined<Vec<AttestationId>> {
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

/// Add the subjects `trusted` cites to `blobs`, in its order, marked trusted: each read from the
/// extrinsics and checked against its claim's Merkle root. Every claim must be used.
fn push_trusted(
	ex: &mut Extrinsics<'_, impl RefineEnv>,
	blobs: &mut CheckBlobs,
	claims: &[AttestationClaim],
	trusted: &[TrustedRef],
) -> Refined<()> {
	let mut used = alloc::vec![false; claims.len()];
	for r in trusted {
		let claim = claims.get(r.claim as usize).ok_or(Rejection::BadTrustedRef)?;
		used[r.claim as usize] = true;
		let subject = ex.blob(r.blob)?;
		let hash = blake2b256(&subject);
		if !merkle::verify(&claim.subjects_root, claim.subject_count, r.entry, merkle::leaf(&hash), &r.path) {
			return Err(Rejection::BadBlob);
		}
		blobs.push(hash, true, subject)?;
	}
	if used.contains(&false) {
		return Err(Rejection::BadTrustedRef);
	}
	Ok(())
}

/// Run `check` in `mode` on `blobs`, `params` and `witness`.
fn run(
	env: &impl RefineEnv,
	check: &[u8],
	mode: CheckMode,
	blobs: &CheckBlobs,
	params: &[u8],
	witness: &[u8],
	gas: Gas,
) -> Refined<()> {
	if check.len() > MAX_CHECK_LEN as usize {
		return Err(Rejection::BadCheckBlob);
	}
	let blobs: Vec<CheckBlob> = blobs
		.blobs
		.iter()
		.map(|(hash, trusted, data)| CheckBlob { trusted: *trusted, hash: *hash, data })
		.collect();
	env.run_check(check, &witness_types::check_args(mode, &blobs, params, witness), gas)
}

/// Refine a reveal: everything but the signatures and the claim, which it has none of.
#[allow(clippy::too_many_arguments)]
fn refine_reveal(
	env: &impl RefineEnv,
	bounty_id: BountyId,
	check_hash: Hash,
	params: Vec<u8>,
	blobs: Vec<BlobRef>,
	check: u8,
	plain: Vec<BlobAt>,
	claims: Vec<AttestationClaim>,
	trusted: Vec<TrustedRef>,
	check_gas: Gas,
	hunter: AccountId,
	salt: Hash,
	witness: Witness,
) -> Refined<Verified> {
	if check_gas > MAX_CHECK_GAS {
		return Err(Rejection::CheckGasTooHigh);
	}
	let witness = witness_bytes(env, witness)?;
	if params.len() > MAX_PARAMS_LEN as usize {
		return Err(Rejection::ParamsTooLong);
	}
	let plain_hashes: Vec<BlobHash> = blobs
		.iter()
		.filter_map(|b| match b {
			BlobRef::Blob(p) => Some(*p),
			BlobRef::Attested { .. } => None,
		})
		.collect();
	if trusted.len() + plain_hashes.len() > MAX_BLOBS as usize {
		return Err(Rejection::BlobsTooLarge);
	}
	if plain.len() != plain_hashes.len() {
		return Err(Rejection::BadBlob);
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
	let mut ex = Extrinsics::new(env);
	let check = ex.whole(check, &check_hash)?;
	// The trusted subjects, then the plain blobs.
	let mut check_blobs = CheckBlobs::default();
	push_trusted(&mut ex, &mut check_blobs, &claims, &trusted)?;
	for (want, at) in plain_hashes.iter().zip(&plain) {
		let data = ex.blob_hashing_to(*at, &want.hash)?;
		if data.len() != want.len as usize {
			return Err(Rejection::BadBlob);
		}
		check_blobs.push(want.hash, false, data)?;
	}
	run(env, &check, CheckMode::Reveal, &check_blobs, &params, &witness, check_gas)?;
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

/// A witness's bytes, from the op or its extrinsic.
fn witness_bytes(env: &impl RefineEnv, witness: Witness) -> Refined<Vec<u8>> {
	match witness {
		Witness::Inline(w) if w.len() > MAX_WITNESS_LEN as usize => Err(Rejection::WitnessTooLong),
		Witness::Inline(w) => Ok(w),
		Witness::Extrinsic(at) => env.extrinsic(at as usize).ok_or(Rejection::BadBlob),
	}
}

/// Refine an attestation.
#[allow(clippy::too_many_arguments)]
fn refine_attest(
	env: &impl RefineEnv,
	service_id: u32,
	attester: AccountId,
	nonce: u64,
	check_hash: Hash,
	check: u8,
	params: Vec<u8>,
	subjects: u8,
	claims: Vec<AttestationClaim>,
	trusted: Vec<TrustedRef>,
	witness: Witness,
	check_gas: Gas,
	signature: Signature,
) -> Refined<Verified> {
	if check_gas > MAX_CHECK_GAS {
		return Err(Rejection::CheckGasTooHigh);
	}
	let witness = witness_bytes(env, witness)?;
	if params.len() > MAX_PARAMS_LEN as usize {
		return Err(Rejection::ParamsTooLong);
	}
	if trusted.len() > MAX_BLOBS as usize {
		return Err(Rejection::BlobsTooLarge);
	}
	let params_hash = blake2b256(&params);
	let parents = check_claims(&check_hash, Some(params_hash), &claims)?;
	let mut ex = Extrinsics::new(env);
	let subjects = ex.all(subjects)?;
	let hashes: Vec<Hash> = subjects.iter().map(|s| blake2b256(s)).collect();
	let leaves: Vec<Hash> = hashes.iter().map(merkle::leaf).collect();
	let claim = AttestationClaim {
		check_hash,
		params_hash,
		subjects_root: merkle::root(&leaves),
		subject_count: subjects.len() as u32,
		parents_root: witness_types::parents_root(&parents),
	};
	let message = witness_types::attest_message(service_id, &attester, nonce, &claim.id());
	if !verify_signature(&attester, &message, &signature) {
		return Err(Rejection::BadSignature);
	}
	let check = ex.whole(check, &check_hash)?;
	// The trusted subjects, then the subjects to attest.
	let mut check_blobs = CheckBlobs::default();
	push_trusted(&mut ex, &mut check_blobs, &claims, &trusted)?;
	for (hash, subject) in hashes.into_iter().zip(subjects) {
		check_blobs.push(hash, false, subject)?;
	}
	run(env, &check, CheckMode::Attest, &check_blobs, &params, &witness, check_gas)?;
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
		Op::Reveal {
			bounty_id,
			check_hash,
			params,
			blobs,
			check,
			plain,
			citations: at,
			check_gas,
			hunter,
			salt,
			witness,
		} => citations(env, at).and_then(|Citations { claims, trusted }| {
			refine_reveal(
				env, bounty_id, check_hash, params, blobs, check, plain, claims, trusted, check_gas, hunter, salt,
				witness,
			)
		}),
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
		Op::Withdraw { account, nonce, asset, amount, to, signature } => {
			let message = witness_types::withdraw_message(service_id, &account, nonce, &asset, amount, &to);
			if verify_signature(&account, &message, &signature) {
				Ok(Verified::Withdraw { account, nonce, asset, amount, to })
			} else {
				Err(Rejection::BadSignature)
			}
		},
		Op::Propose { admin, nonce, action, signature } => {
			let message = witness_types::propose_message(service_id, &admin, nonce, &action);
			if verify_signature(&admin, &message, &signature) {
				Ok(Verified::Propose { admin, nonce, action })
			} else {
				Err(Rejection::BadSignature)
			}
		},
		Op::Apply { id } => Ok(Verified::Apply { id }),
		Op::Cancel { admin, nonce, id, signature } => {
			let message = witness_types::cancel_message(service_id, &admin, nonce, id);
			if verify_signature(&admin, &message, &signature) {
				Ok(Verified::Cancel { admin, nonce, id })
			} else {
				Err(Rejection::BadSignature)
			}
		},
		Op::Attest {
			attester,
			nonce,
			check_hash,
			check,
			params,
			subjects,
			citations: at,
			witness,
			check_gas,
			signature,
		} => citations(env, at).and_then(|Citations { claims, trusted }| {
			refine_attest(
				env, service_id, attester, nonce, check_hash, check, params, subjects, claims, trusted, witness,
				check_gas, signature,
			)
		}),
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

	fn balance(&self, id: &AccountId, asset: Asset) -> Amount {
		self.get(&StorageKey::Balance(*id, asset)).unwrap_or(0)
	}

	fn set_balance(&mut self, id: &AccountId, asset: Asset, amount: Amount) {
		let key = StorageKey::Balance(*id, asset);
		if amount == 0 { self.remove(&key) } else { self.set(&key, &amount) }
	}

	fn credit(&mut self, id: &AccountId, asset: Asset, amount: Amount) -> Result<()> {
		let balance = self.balance(id, asset).checked_add(amount).ok_or("balance overflow")?;
		self.set_balance(id, asset, balance);
		Ok(())
	}

	fn debit(&mut self, id: &AccountId, asset: Asset, amount: Amount) -> Result<()> {
		let balance = self.balance(id, asset).checked_sub(amount).ok_or("insufficient balance")?;
		self.set_balance(id, asset, balance);
		Ok(())
	}

	/// Check and bump `id`'s nonce.
	fn use_nonce(&mut self, id: &AccountId, nonce: u64) -> Result<()> {
		let mut acc = self.account(id);
		if nonce != acc.nonce {
			return Err("bad nonce");
		}
		acc.nonce += 1;
		self.set(&StorageKey::Account(*id), &acc);
		Ok(())
	}

	/// Check and bump `id`'s nonce, and take `amount` of `asset` from it.
	fn charge(&mut self, id: &AccountId, nonce: u64, asset: Asset, amount: Amount) -> Result<()> {
		self.use_nonce(id, nonce)?;
		self.debit(id, asset, amount)
	}

	fn config(&self) -> Option<Config> {
		self.get(&StorageKey::Config)
	}

	/// The fee asset and the deposits paid in it.
	fn fees(&self) -> Result<(Asset, Config)> {
		let config = self.config().ok_or("witness is not configured")?;
		Ok((config.fee_asset.ok_or("no fee asset configured")?, config))
	}

	/// Whether bounties may pay in `asset`.
	fn accepted(&self, asset: Asset) -> bool {
		(FAUCET && asset == TEST_ASSET) || self.config().is_some_and(|c| c.token_services.contains(&asset.service))
	}

	fn admin(&self) -> AccountId {
		self.get(&StorageKey::Admin).unwrap_or(BUILD_ADMIN)
	}

	/// Check `who` is the admin, and use its nonce.
	fn as_admin(&mut self, who: &AccountId, nonce: u64) -> Result<()> {
		if *who != self.admin() {
			return Err("not the admin");
		}
		self.use_nonce(who, nonce)
	}

	fn act(&mut self, action: AdminAction) {
		match action {
			AdminAction::Configure(config) => self.set(&StorageKey::Config, &config),
			AdminAction::SetAdmin(admin) => self.set(&StorageKey::Admin, &admin),
			AdminAction::Upgrade { code_hash, .. } => self.fx.upgrade = Some(code_hash),
		}
	}

	fn bounty(&self, id: BountyId) -> Result<Bounty> {
		self.get(&StorageKey::Bounty(id)).ok_or("no such bounty")
	}

	fn attestation(&self, id: &AttestationId) -> Result<Attestation> {
		self.get(&StorageKey::Attestation(*id)).ok_or("no such attestation")
	}
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
			if !FAUCET {
				return Err("no faucet");
			}
			if amount > MAX_MINT {
				return Err("mint too large");
			}
			tx.credit(&to, TEST_ASSET, amount)?;
		},
		Verified::CreateBounty { maker, nonce, terms } => {
			if terms.check_gas > MAX_CHECK_GAS ||
				terms.check_len > MAX_CHECK_LEN ||
				terms.params.len() > MAX_PARAMS_LEN as usize
			{
				return Err("check too large");
			}
			// Attested blobs must be subjects of this bounty's check's attestations, all with
			// one set of attest params, as a reveal will only trust those. Accumulate doesn't
			// see subjects, so an entry past the end of a claim's, or attested blobs too big for
			// a check, only show at reveal, which then fails; the maker can reclaim.
			let mut plain_len = 0u64;
			let mut params_hash = None;
			for blob in &terms.blobs {
				match blob {
					BlobRef::Blob(p) => plain_len += p.len as u64,
					BlobRef::Attested { attestation, .. } => {
						let a = tx.attestation(attestation)?;
						if a.check_hash != terms.check_hash {
							return Err("attested by another check");
						}
						if *params_hash.get_or_insert(a.params_hash) != a.params_hash {
							return Err("attested with other params");
						}
					},
				}
			}
			if terms.blobs.len() > MAX_BLOBS as usize || plain_len > MAX_BLOBS_LEN as u64 {
				return Err("blobs too large");
			}
			if !(MIN_CLAIM_WINDOW..=MAX_CLAIM_WINDOW).contains(&terms.claim_window) {
				return Err("claim window out of range");
			}
			if terms.expiry <= now.saturating_add(MIN_COMMIT_AGE) {
				return Err("expiry too soon");
			}
			if !tx.accepted(terms.asset) {
				return Err("asset not accepted");
			}
			tx.charge(&maker, nonce, terms.asset, terms.reward)?;

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
			let (fee_asset, config) = tx.fees()?;
			tx.charge(&committer, nonce, fee_asset, config.commit_deposit)?;
			let record =
				CommitRecord { slot: now, committer, deposit_asset: fee_asset, deposit: config.commit_deposit };
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
			// Refine made the claims share one set of params, and include the bounty's attested
			// blobs, which share its attest params. A bounty citing none leaves the params free:
			// a hunter could cite attestations made with params of their choosing (for Lean,
			// pins under which anything is provable). So such a bounty takes no claims.
			let cites = bounty.terms.blobs.iter().any(|b| matches!(b, BlobRef::Attested { .. }));
			if !cites && !attestations.is_empty() {
				return Err("the bounty cites no attestation");
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
			tx.credit(&record.committer, record.deposit_asset, record.deposit)?;
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
			tx.credit(&leader.hunter, bounty.terms.asset, bounty.terms.reward)?;
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
			tx.use_nonce(&maker, nonce)?;
			tx.credit(&maker, bounty.terms.asset, bounty.terms.reward)?;
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
			let (fee_asset, config) = tx.fees()?;
			tx.charge(&attester, nonce, fee_asset, config.attest_deposit)?;
			let record = Attestation { check_hash: claim.check_hash, params_hash: claim.params_hash, slot: now, attester };
			tx.set(&StorageKey::Attestation(id), &record);
		},
		Verified::Withdraw { account, nonce, asset, amount, to } => {
			// Whatever the configuration now, a balance can always go back where it came from.
			if asset.service == TEST_ASSET.service {
				return Err("the test asset can't be withdrawn");
			}
			tx.charge(&account, nonce, asset, amount)?;
			let memo = TokenMemo::Withdrawal(WithdrawalMemo { asset_id: asset.id, amount, to });
			tx.fx.transfers.push((asset.service, memo.memo()));
		},
		Verified::Propose { admin, nonce, action } => {
			tx.as_admin(&admin, nonce)?;
			if matches!(action, AdminAction::Configure(_)) && tx.config().is_none() {
				// The first configuration: no funds are at stake yet.
				tx.act(action);
			} else {
				if let AdminAction::Upgrade { code_hash, code_len } = &action {
					tx.fx.solicit = Some((*code_hash, *code_len));
				}
				let id: u64 = tx.get(&StorageKey::NextProposalId).unwrap_or(0);
				tx.set(&StorageKey::NextProposalId, &(id + 1));
				tx.set(&StorageKey::Proposal(id), &Proposal { action, effective: now.saturating_add(ADMIN_DELAY) });
			}
		},
		Verified::Apply { id } => {
			let proposal: Proposal = tx.get(&StorageKey::Proposal(id)).ok_or("no such proposal")?;
			if now < proposal.effective {
				return Err("proposal not yet effective");
			}
			tx.remove(&StorageKey::Proposal(id));
			tx.act(proposal.action);
		},
		Verified::Cancel { admin, nonce, id } => {
			tx.as_admin(&admin, nonce)?;
			tx.get::<Proposal>(&StorageKey::Proposal(id)).ok_or("no such proposal")?;
			tx.remove(&StorageKey::Proposal(id));
		},
	}
	Ok(tx.fx)
}

/// Apply a transfer of `memo` and `native` balance to the service from service `source`: a
/// deposit, if `source` is an accepted token service and the memo is one. The native balance is
/// recorded as the recipient's storage credit. Anything else credits nothing: a deposit is then
/// sent back (see [`refund`]), and any other transfer's native balance stays with the service's
/// storage.
pub fn on_transfer(state: &impl State, source: u32, native: u64, memo: &[u8]) -> Result<Effects> {
	let mut tx = Tx { state, fx: Effects::default() };
	if !tx.config().is_some_and(|c| c.token_services.contains(&source)) {
		return Err("not from an accepted token service");
	}
	let TokenMemo::Deposit(deposit) = TokenMemo::parse(memo)? else { return Err("not a deposit") };
	tx.credit(&deposit.to, Asset { service: source, id: deposit.asset_id }, deposit.amount)?;
	if native > 0 {
		let key = StorageKey::StorageCredit(deposit.to);
		let credit: u64 = tx.get(&key).unwrap_or(0);
		tx.set(&key, &credit.saturating_add(native));
	}
	Ok(tx.fx)
}

/// What to send back to the token service that sent `memo`, when witness couldn't credit it: a
/// withdrawal paying the deposit to its `refund_to`, out of what witness now holds there. Only a
/// deposit is refunded, so a withdrawal can never come back as one.
pub fn refund(memo: &[u8]) -> Option<[u8; MEMO_LEN]> {
	let TokenMemo::Deposit(d) = TokenMemo::parse(memo).ok()? else { return None };
	Some(TokenMemo::Withdrawal(WithdrawalMemo { asset_id: d.asset_id, amount: d.amount, to: d.refund_to }).memo())
}
