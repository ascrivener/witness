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
//! Attestations let checks reuse verification across refines:
//! - `Pin` holds a preimage for good, so refine can look it up.
//! - `Attest` runs a check in attest mode on a pinned subject blob, trusting the subjects of the
//!   attestation chain it extends. If the check returns true, accumulate records an
//!   [`Attestation`]: "check C, with these params, verified this blob following that chain".
//! - A bounty can cite a chain of attestations as its first blobs, and a reveal can extend it.
//!   The check receives the chain's subjects marked trusted, and can skip re-verifying them.
//! - A subject is only trusted where it was verified: right after the chain it was attested on.
//!   Formats like Lean exports number their items on from the layers before, so a layer checked
//!   after one prefix can mean something else after another.
//! - A check only ever trusts its own attestations: a chain is one check with one set of params,
//!   and a bounty may only cite chains by its own check.

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
/// Reveal (lookup, hashing, setting up the inner PVM) within one work-item's refine gas.
pub const MAX_CHECK_GAS: Gas = 1_000_000_000;
/// Largest check blob a bounty may solicit.
pub const MAX_CHECK_LEN: u32 = 1 << 20;
/// Largest check parameters a bounty may carry.
pub const MAX_PARAMS_LEN: u32 = 4096;
/// Most blobs a check may be given: a bounty's blobs plus a reveal's extra attested layers, or
/// an attested subject and its chain.
pub const MAX_BLOBS: u32 = 128;
/// Largest total length of a bounty's extra blobs. They are copied into the check's memory, so
/// this must leave room within [`MAX_CHECK_PAGES`] for the check's own code, data, stack and heap.
pub const MAX_BLOBS_LEN: u32 = 4 << 20;
/// Most memory pages a check may use (16 MiB), counting its arguments and any heap it grows.
pub const MAX_CHECK_PAGES: u32 = 4096;
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
/// Points a pin costs. Pins are permanent, so this is never refunded.
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
	/// The subject of an attestation by the bounty's own check, passed to it as trusted. A
	/// bounty's attested blobs come first and form one chain from its root, in order.
	Attested(AttestationId),
}

/// What an attestation says: check `check_hash`, run in attest mode with params hashing to
/// `params_hash`, returned true for `subject`, given the subjects of `parent`'s chain (trusted,
/// oldest first) before it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AttestationClaim {
	pub check_hash: Hash,
	pub params_hash: Hash,
	pub subject: Preimage,
	/// The attestation this one follows, by the same check with the same params; `None` for the
	/// root of a chain. Its id covers its own parent, so this commits to the whole chain.
	pub parent: Option<AttestationId>,
}

impl AttestationClaim {
	/// The attestation's id. It covers the check, the params, the subject and the parent (so the
	/// whole chain before it), so the same blob verified by another check version or after other
	/// layers is another attestation.
	pub fn id(&self) -> AttestationId {
		blake2b256(&(b"witness/attest", self).encode())
	}
}

/// Whether `chain` is a chain of attestations following `parent` (oldest first): each claim's
/// parent is the one before it, and all are by `check_hash` with `params_hash`.
pub fn is_chain(
	chain: &[AttestationClaim],
	parent: Option<AttestationId>,
	check_hash: &Hash,
	params_hash: &Hash,
) -> bool {
	let mut expected = parent;
	chain.iter().all(|claim| {
		let follows = claim.parent == expected &&
			claim.check_hash == *check_hash &&
			claim.params_hash == *params_hash;
		expected = Some(claim.id());
		follows
	})
}

/// A recorded attestation. Kept for good.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Attestation {
	pub claim: AttestationClaim,
	/// The slot it was accumulated.
	pub slot: Slot,
	pub attester: AccountId,
}

/// A blob as a reveal names it. Refine can't read state, so for an attested blob the hunter
/// supplies the claim; its id must match the bounty's.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum RevealBlob {
	Blob(Preimage),
	Attested(AttestationClaim),
}

impl RevealBlob {
	/// How the bounty's terms name this blob.
	pub fn blob_ref(&self) -> BlobRef {
		match self {
			RevealBlob::Blob(p) => BlobRef::Blob(*p),
			RevealBlob::Attested(claim) => BlobRef::Attested(claim.id()),
		}
	}
}

/// What a maker puts up, and what a hunter must reproduce exactly when revealing.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BountyTerms {
	/// Blake2b-256 of the check blob (standard PVM program format, see [`program`]).
	pub check_hash: Hash,
	pub check_len: u32,
	/// Passed to the check alongside the witness, so one check blob can serve many bounties.
	pub params: Vec<u8>,
	/// Blobs refine passes to the check, in order, such as a statement environment or a library.
	/// Plain blobs are solicited and released along with the check blob; attested ones are
	/// already held for good.
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
		blobs: Vec<RevealBlob>,
		/// Attested layers this reveal adds after the bounty's attested chain, continuing it,
		/// such as library layers the proof uses. Passed to the check as trusted, after the
		/// bounty's attested blobs and before its plain ones.
		extra: Vec<AttestationClaim>,
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
	/// Hold `blob` as a preimage for good, paying [`PIN_DEPOSIT`], so attestations can use it.
	Pin { owner: AccountId, nonce: u64, blob: Preimage, signature: Signature },
	/// Attest that check `check_hash` accepts `subject` after the chain `ancestors` (oldest
	/// first, empty for a new root), paying [`ATTEST_DEPOSIT`]. The check and every subject must
	/// already be held, by a pin or a bounty. Refine can't read state, so the attester supplies
	/// the chain's claims; accumulate checks its tip was recorded.
	Attest {
		attester: AccountId,
		nonce: u64,
		check_hash: Hash,
		params: Vec<u8>,
		subject: Preimage,
		ancestors: Vec<AttestationClaim>,
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
	/// Attested blobs that aren't one chain from its root, or extra layers that don't continue
	/// the bounty's chain.
	BrokenChain,
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
		/// The last of the reveal's extra layers, which accumulate must find recorded.
		extra_tip: Option<AttestationId>,
		check_gas: Gas,
		commitment: Hash,
		hunter: AccountId,
		witness_hash: Hash,
	},
	Finalize { bounty_id: BountyId },
	Reclaim { bounty_id: BountyId, maker: AccountId, nonce: u64 },
	Release { bounty_id: BountyId, commitment: Hash },
	Pin { owner: AccountId, nonce: u64, blob: Preimage },
	/// The check returned true in attest mode; accumulate records `claim` if its parent was.
	Attest { attester: AccountId, nonce: u64, claim: AttestationClaim },
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

/// The message an owner signs to pin `blob` on service `service_id`.
pub fn pin_message(service_id: u32, owner: &AccountId, nonce: u64, blob: &Preimage) -> Vec<u8> {
	(b"witness/pin", service_id, owner, nonce, blob).encode()
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
	/// Does the subject, the last blob, verify given the others? The witness is empty.
	Attest = 1,
}

/// A blob as a check receives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckBlob<'a> {
	/// The blob is the subject of an attestation by this same check, so the check may rely on it.
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
