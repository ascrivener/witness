//! Types shared by the witness service, check blobs and the host tooling.
//!
//! The protocol, in short:
//! - A maker posts a bounty: a check blob `check(params, x) -> bool` (stored as a preimage of the
//!   service), the `params` to run it with, any extra preimage blobs the check reads, a reward in
//!   points, a gas limit for the check, an expiry slot and a claim window.
//! - A hunter commits to `blake2b(bounty_id, x, hunter, salt)`, paying [`COMMIT_DEPOSIT`], then
//!   reveals `x` at least [`MIN_COMMIT_AGE`] slots later. Refine runs the check in an inner PVM.
//! - The first valid reveal opens the claim window. Every valid reveal before it closes competes,
//!   and the one whose commitment reached the chain earliest wins. Someone who copies `x` out of a
//!   reveal can only commit after seeing it, so they always lose to the original. Ties within a
//!   slot go to the lower commitment hash.
//! - `Finalize` after the window pays the winner. After `expiry + REVEAL_GRACE` a bounty no one
//!   revealed for can be reclaimed by its maker.
//! - A valid reveal refunds its commitment's deposit; unrevealed commitments forfeit theirs, which
//!   is what makes spamming commitments cost something.
//!
//! Attestations let checks reuse verification across refines (see docs/design/attestation-dag.md):
//! - `Pin` holds preimages for good, so refine can look them up.
//! - `Attest` runs a check in attest mode on a bundle of subjects (one preimage holding them all),
//!   trusting subjects of earlier attestations it cites. If the check returns true, accumulate
//!   records an [`Attestation`]: "check C, with these params, verified every subject in this
//!   bundle, given those parents' subjects". Any subject in the bundle can then be trusted on its
//!   own. A bundle is one preimage, so accumulate's work per attestation doesn't grow with it.
//! - Bounties cite attested subjects, and reveals can cite more. The check receives them marked
//!   trusted, and can skip re-verifying them.
//! - Attestations form a DAG. Trust needs no context: an attestation is only recorded once its
//!   parents were, so a cited attestation rests, by induction, on subjects that were all checked.
//! - A check only ever trusts its own attestations: everything an op cites is by the same check
//!   with the same attest params, and a bounty may only cite its own check's attestations.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};

pub mod program;

pub type Hash = [u8; 32];
/// An Ed25519 public key. Points balances are held per account.
pub type AccountId = [u8; 32];
pub type Signature = [u8; 64];
pub type BountyId = u64;
pub type Slot = u32;
pub type Points = u64;
pub type Gas = u64;
/// See [`AttestationClaim::id`].
pub type AttestationId = Hash;

/// Most gas a bounty may give its check. Must leave refine enough headroom for the rest of a
/// Reveal (lookup, hashing, setting up the inner PVM) within one work-item's refine gas: the full
/// spec allows 5×10⁹. On a network with less (PolkaJam's "tiny" parameters allow 10⁹), a check
/// given more than refine can spend just runs out of gas.
pub const MAX_CHECK_GAS: Gas = 4_500_000_000;
/// Largest check blob a bounty may solicit.
pub const MAX_CHECK_LEN: u32 = 1 << 20;
/// Largest check parameters a bounty may carry.
pub const MAX_PARAMS_LEN: u32 = 4096;
/// Most blobs a check may be given: trusted subjects, plain blobs and subjects to attest. A check
/// over a big library may draw on hundreds or thousands of attested items.
pub const MAX_BLOBS: u32 = 4096;
/// Largest total length of the blobs a check is given. They are copied into the check's memory,
/// so this must leave room within [`MAX_CHECK_PAGES`] for its own code, data, stack and heap.
pub const MAX_BLOBS_LEN: u32 = 16 << 20;
/// Most memory pages a check may use (128 MiB), counting its arguments and any heap it grows.
/// Real verifiers, such as proof checkers, want deep stacks and allocate heavily.
pub const MAX_CHECK_PAGES: u32 = 32768;
/// Largest witness accepted in a Reveal payload.
pub const MAX_WITNESS_LEN: u32 = 1 << 16;
/// A commitment must be on chain before its reveal, so a reveal can only use a commitment from an
/// earlier slot. With earliest-commitment-wins this is all the age needed: a copier learns `x`
/// from the reveal, after the original commitment is already on chain.
pub const MIN_COMMIT_AGE: Slot = 1;
/// Shortest claim window a bounty may have. The window is how long an attacker who saw `x` would
/// have to keep the original reveal off chain, so it should span several guarantor rotations.
pub const MIN_CLAIM_WINDOW: Slot = 30;
pub const MAX_CLAIM_WINDOW: Slot = 14_400;
/// Slots after expiry during which commitments made before expiry may still open the claim
/// window, and before which the maker may not reclaim.
pub const REVEAL_GRACE: Slot = 20;
/// Points a commitment locks up; refunded on a valid reveal, forfeited otherwise.
pub const COMMIT_DEPOSIT: Points = 10;
/// Most preimages one `Pin` may hold. Accumulate pays about 24k gas per preimage it holds, of
/// 10M per work report.
pub const MAX_PINS: u32 = 64;
/// Points a pin costs, per preimage. Pins are permanent, so this is never refunded.
pub const PIN_DEPOSIT: Points = 10;
/// Points an attestation costs. Attestations are permanent, so this is never refunded.
pub const ATTEST_DEPOSIT: Points = 10;
/// Largest single faucet mint.
pub const MAX_MINT: Points = 1_000_000;

pub fn blake2b256(data: &[u8]) -> Hash {
	let h = blake2b_simd::Params::new().hash_length(32).hash(data);
	let mut out = [0; 32];
	out.copy_from_slice(h.as_bytes());
	out
}

/// A preimage of the service, by hash and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Preimage {
	pub hash: Hash,
	pub len: u32,
}

/// A blob a bounty gives its check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum BlobRef {
	/// A plain preimage: the check must verify whatever it relies on in it.
	Blob(Preimage),
	/// Entry `entry` of the bundle of an attestation by the bounty's own check, passed to
	/// it as trusted.
	Attested { attestation: AttestationId, entry: u32 },
}

/// A bundle: the subjects an attestation covers, encoded as a `Vec<Vec<u8>>` and stored as one
/// preimage. A subject's hash is the Blake2b-256 of its own bytes.
///
/// Subjects are bundled rather than held as a preimage each because accumulate pays for every
/// preimage it holds (about 24k gas each, of 10M per work report), so an attestation holding
/// its subjects one by one could hold only a few hundred.
pub type Bundle = Vec<Vec<u8>>;

/// Largest bundle: [`MAX_BLOBS`] subjects of at most [`MAX_BLOBS_LEN`] bytes in all, and their
/// length prefixes.
pub const MAX_BUNDLE_LEN: u32 = MAX_BLOBS_LEN + 5 * (MAX_BLOBS + 1);

/// The subjects in an encoded [`Bundle`], without copying them; `None` unless `data` is exactly
/// one bundle of at most [`MAX_BLOBS`] subjects.
pub fn bundle_subjects(mut data: &[u8]) -> Option<Vec<&[u8]>> {
	let input = &mut data;
	let count = codec::Compact::<u32>::decode(input).ok()?.0;
	if count > MAX_BLOBS {
		return None;
	}
	let mut subjects = Vec::with_capacity(count as usize);
	for _ in 0..count {
		let len = codec::Compact::<u32>::decode(input).ok()?.0 as usize;
		let (subject, rest) = input.split_at_checked(len)?;
		subjects.push(subject);
		*input = rest;
	}
	input.is_empty().then_some(subjects)
}

/// What an attestation says: check `check_hash`, run in attest mode with params hashing to
/// `params_hash`, returned true for every subject in the list `subjects`, given trusted subjects
/// of the attestations whose ids `parents_root` commits to.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AttestationClaim {
	pub check_hash: Hash,
	pub params_hash: Hash,
	/// A preimage holding the [`Bundle`] of subjects.
	pub subjects: Preimage,
	/// See [`parents_root`]. Committing to the parents through a root keeps a claim four hashes
	/// long however many parents it has, since ops carry claims.
	pub parents_root: Hash,
}

impl AttestationClaim {
	/// The attestation's id. It covers the check, the params, the subjects and the parents, so
	/// the same subjects verified by another check version, or on other foundations, are another
	/// attestation.
	pub fn id(&self) -> AttestationId {
		blake2b256(&(b"witness/attest", self).encode())
	}
}

/// The root of a set of parent attestations: Blake2b-256 of their ids, sorted and deduplicated.
pub fn parents_root(parents: &[AttestationId]) -> Hash {
	let mut ids = parents.to_vec();
	ids.sort();
	ids.dedup();
	blake2b256(&(b"witness/parents", ids).encode())
}

/// A trusted subject, as an op cites it: entry `entry` of the bundle of the op's claim
/// number `claim`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TrustedRef {
	pub claim: u16,
	pub entry: u32,
}

/// A recorded attestation. Kept for good.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Attestation {
	pub claim: AttestationClaim,
	/// The slot it was accumulated.
	pub slot: Slot,
	pub attester: AccountId,
}

/// What a maker puts up, and what a hunter must reproduce exactly when revealing.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BountyTerms {
	/// Blake2b-256 of the check blob (standard PVM program format, see [`program`]).
	pub check_hash: Hash,
	pub check_len: u32,
	/// Passed to the check alongside the witness, so one check blob can serve many bounties.
	pub params: Vec<u8>,
	/// Blobs refine passes to the check, such as a statement environment or a library: attested
	/// subjects (trusted) and plain blobs. Plain blobs are solicited and released along with the
	/// check blob; attested ones are held for good.
	pub blobs: Vec<BlobRef>,
	pub reward: Points,
	pub check_gas: Gas,
	/// Commitments made at or after this slot are not accepted.
	pub expiry: Slot,
	/// Slots from the first valid reveal until the bounty can be finalized.
	pub claim_window: Slot,
}

/// A work-item payload: exactly one operation per work item.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Op {
	/// Prototype faucet: points have no backing value yet.
	Mint { to: AccountId, amount: Points },
	CreateBounty { maker: AccountId, nonce: u64, terms: BountyTerms, signature: Signature },
	/// `committer` pays the deposit and signs; the payout key is inside the commitment.
	Commit {
		bounty_id: BountyId,
		committer: AccountId,
		nonce: u64,
		commitment: Hash,
		signature: Signature,
	},
	Reveal {
		bounty_id: BountyId,
		/// Must match the bounty's terms; refine cannot read state, so the hunter supplies them
		/// and accumulate checks them.
		check_hash: Hash,
		params: Vec<u8>,
		blobs: Vec<BlobRef>,
		/// The attestations `trusted` cites, each once: all by the bounty's check, with one set of
		/// params, which the bounty's own attested blobs fix. A bounty citing no attestation takes
		/// none, as otherwise the hunter would choose those params.
		claims: Vec<AttestationClaim>,
		/// Every subject passed to the check as trusted: those of the bounty's blobs, and any
		/// more the reveal relies on (such as library a proof uses that the bounty didn't name).
		/// They come first, in this order, then the bounty's plain blobs.
		trusted: Vec<TrustedRef>,
		check_gas: Gas,
		hunter: AccountId,
		salt: Hash,
		witness: Vec<u8>,
	},
	/// Pay the winner once the claim window has closed. Anyone may send it.
	Finalize { bounty_id: BountyId },
	Reclaim { bounty_id: BountyId, maker: AccountId, nonce: u64, signature: Signature },
	/// Delete a commitment that can no longer be revealed. Anyone may send it; the deposit is
	/// already forfeit.
	Release { bounty_id: BountyId, commitment: Hash },
	/// Hold `blobs` as preimages for good, paying [`PIN_DEPOSIT`] for each, so attestations can
	/// use them: typically a check and bundles to attest.
	Pin { owner: AccountId, nonce: u64, blobs: Vec<Preimage>, signature: Signature },
	/// Attest that check `check_hash` accepts every subject in the bundle `subjects`, trusting
	/// the subjects `trusted` cites, paying [`ATTEST_DEPOSIT`]. The check and the bundle must
	/// already be held, by pins or bounties. Refine can't read state, so the attester
	/// supplies the claims cited; accumulate checks they were recorded.
	Attest {
		attester: AccountId,
		nonce: u64,
		check_hash: Hash,
		params: Vec<u8>,
		subjects: Preimage,
		/// The parent attestations, each once.
		claims: Vec<AttestationClaim>,
		trusted: Vec<TrustedRef>,
		/// The attester's evidence, passed to the check (a batch's proofs, say). Not part of the
		/// claim: the attestation is about the subjects, however they were shown.
		witness: Vec<u8>,
		check_gas: Gas,
		signature: Signature,
	},
}

/// Why a check did not return true.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum CheckFailure {
	/// Halted normally with a result other than 1.
	False,
	Panic,
	OutOfGas,
	PageFault,
	/// Checks get no host calls; any attempt fails the check.
	HostCall,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Rejection {
	BadPayload,
	BadSignature,
	CheckGasTooHigh,
	WitnessTooLong,
	ParamsTooLong,
	/// The check blob is not (yet) available as a preimage at the lookup anchor.
	CheckUnavailable,
	/// One of the bounty's blobs is not (yet) available as a preimage at the lookup anchor.
	BlobUnavailable,
	/// More than [`MAX_BLOBS`] blobs, or more than [`MAX_BLOBS_LEN`] bytes of them.
	BlobsTooLarge,
	/// An attestation by a check other than the one being run, or with other params.
	ForeignAttestation,
	/// A trusted reference to a claim or entry that doesn't exist, a claim cited twice or that no
	/// reference uses, or a reveal that doesn't trust its bounty's attested subjects.
	BadTrustedRef,
	/// A bundle that doesn't decode, or holds more than [`MAX_BLOBS`] subjects.
	BadBundle,
	/// The check blob is not a valid standard program, or needs more memory than allowed.
	BadCheckBlob,
	CheckFailed(CheckFailure),
}

/// Refine's output: an [`Op`] whose expensive parts (signatures, the check) have been verified.
/// Accumulate trusts these and only applies the state rules.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Verified {
	Mint { to: AccountId, amount: Points },
	CreateBounty { maker: AccountId, nonce: u64, terms: BountyTerms },
	Commit { bounty_id: BountyId, committer: AccountId, nonce: u64, commitment: Hash },
	/// The check returned true for a witness whose commitment is `commitment`.
	Reveal {
		bounty_id: BountyId,
		check_hash: Hash,
		params_hash: Hash,
		/// Blake2b-256 of the encoded blob references.
		blobs_hash: Hash,
		/// The attestations the reveal relied on, which accumulate must find recorded.
		attestations: Vec<AttestationId>,
		check_gas: Gas,
		commitment: Hash,
		hunter: AccountId,
		witness_hash: Hash,
	},
	Finalize { bounty_id: BountyId },
	Reclaim { bounty_id: BountyId, maker: AccountId, nonce: u64 },
	Release { bounty_id: BountyId, commitment: Hash },
	Pin { owner: AccountId, nonce: u64, blobs: Vec<Preimage> },
	/// The check returned true in attest mode; accumulate records `claim` if `parents` (whose
	/// root the claim covers) were.
	Attest { attester: AccountId, nonce: u64, claim: AttestationClaim, parents: Vec<AttestationId> },
	Rejected(Rejection),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Account {
	pub balance: Points,
	/// Next nonce expected on a signed operation (CreateBounty, Commit, Reclaim).
	pub nonce: u64,
}

/// The leading reveal while a bounty's claim window is open, or the winner once it has closed.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Claim {
	/// The slot the winning commitment reached the chain.
	pub committed: Slot,
	pub commitment: Hash,
	pub hunter: AccountId,
	pub witness_hash: Hash,
}

impl Claim {
	/// Whether `self` beats `other`: earlier commitment, then lower commitment hash.
	pub fn beats(&self, other: &Claim) -> bool {
		(self.committed, self.commitment) < (other.committed, other.commitment)
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum BountyStatus {
	Open,
	Revealing { window_end: Slot, leader: Claim },
	Claimed { winner: Claim, slot: Slot },
	Reclaimed,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Bounty {
	pub maker: AccountId,
	pub terms: BountyTerms,
	pub status: BountyStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CommitRecord {
	/// The slot at which the commitment was accumulated.
	pub slot: Slot,
	pub committer: AccountId,
	pub deposit: Points,
}

/// Service storage keys (encoded as the raw storage key).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum StorageKey {
	Account(AccountId),
	Bounty(BountyId),
	/// Keyed by bounty as well as hash: the hash hides which bounty it is for, so a global key
	/// would let anyone copy a commitment onto another bounty first and block the real one.
	Commitment(BountyId, Hash),
	NextBountyId,
	/// How many holders a preimage has: unfinished bounties using it as a check blob or a plain
	/// blob, pins, and attestations of it. The preimage is forgotten when it reaches zero.
	PreimageRefs(Hash),
	Attestation(AttestationId),
}

/// The commitment a hunter posts before revealing `witness`.
pub fn commitment(bounty_id: BountyId, witness: &[u8], hunter: &AccountId, salt: &Hash) -> Hash {
	blake2b256(&(b"witness/commit", bounty_id, witness, hunter, salt).encode())
}

/// The message a maker signs to create a bounty on service `service_id`.
pub fn create_message(service_id: u32, maker: &AccountId, nonce: u64, terms: &BountyTerms) -> Vec<u8> {
	(b"witness/create", service_id, maker, nonce, terms).encode()
}

/// The message a committer signs to post `commitment` on service `service_id`.
pub fn commit_message(
	service_id: u32,
	bounty_id: BountyId,
	committer: &AccountId,
	nonce: u64,
	commitment: &Hash,
) -> Vec<u8> {
	(b"witness/commit", service_id, bounty_id, committer, nonce, commitment).encode()
}

/// The message an owner signs to pin `blobs` on service `service_id`.
pub fn pin_message(service_id: u32, owner: &AccountId, nonce: u64, blobs: &[Preimage]) -> Vec<u8> {
	(b"witness/pin", service_id, owner, nonce, blobs).encode()
}

/// The message an attester signs to attest the claim with id `id` on service `service_id`.
pub fn attest_message(service_id: u32, attester: &AccountId, nonce: u64, id: &AttestationId) -> Vec<u8> {
	(b"witness/attest", service_id, attester, nonce, id).encode()
}

/// The message a maker signs to reclaim bounty `bounty_id` on service `service_id`.
pub fn reclaim_message(service_id: u32, bounty_id: BountyId, maker: &AccountId, nonce: u64) -> Vec<u8> {
	(b"witness/reclaim", service_id, bounty_id, maker, nonce).encode()
}

/// The version of the check arguments' layout, the first byte of [`check_args`].
pub const CHECK_INTERFACE_VERSION: u8 = 2;

/// Why a check is being run, the second byte of [`check_args`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CheckMode {
	/// Does the witness solve the bounty?
	Reveal = 0,
	/// Do the subjects, the untrusted blobs after the trusted ones, all verify given the trusted
	/// ones? The witness is the attester's evidence.
	Attest = 1,
}

/// A blob as a check receives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckBlob<'a> {
	/// The blob is a subject of an attestation by this same check, with the same attest params,
	/// so the check may rely on it.
	pub trusted: bool,
	pub hash: Hash,
	pub data: &'a [u8],
}

/// The arguments a check receives:
///
/// ```text
/// E1(version) ++ E1(mode) ++ E4(n) ++ [E1(trusted) ++ hash ++ E4(|data|) ++ data]^n
///     ++ E4(|params|) ++ params ++ witness
/// ```
///
/// `witness_check` parses them back.
pub fn check_args(mode: CheckMode, blobs: &[CheckBlob], params: &[u8], witness: &[u8]) -> Vec<u8> {
	let blobs_len: usize = blobs.iter().map(|b| 1 + 32 + 4 + b.data.len()).sum();
	let mut args = Vec::with_capacity(2 + 4 + blobs_len + 4 + params.len() + witness.len());
	args.extend_from_slice(&[CHECK_INTERFACE_VERSION, mode as u8]);
	args.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
	for blob in blobs {
		args.push(blob.trusted as u8);
		args.extend_from_slice(&blob.hash);
		args.extend_from_slice(&(blob.data.len() as u32).to_le_bytes());
		args.extend_from_slice(blob.data);
	}
	args.extend_from_slice(&(params.len() as u32).to_le_bytes());
	args.extend_from_slice(params);
	args.extend_from_slice(witness);
	args
}
