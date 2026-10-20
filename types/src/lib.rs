//! Types shared by the witness service, check blobs and the host tooling.
//!
//! The protocol, in short:
//! - A maker posts a bounty: a check blob `check(params, x) -> bool` (stored as a preimage of the
//!   service), the `params` to run it with, a reward in points, a gas limit for the check, an
//!   expiry slot and a claim window.
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

/// Most gas a bounty may give its check. Must leave refine enough headroom for the rest of a
/// Reveal (lookup, hashing, setting up the inner PVM) within one work-item's refine gas.
pub const MAX_CHECK_GAS: Gas = 1_000_000_000;
/// Largest check blob a bounty may solicit.
pub const MAX_CHECK_LEN: u32 = 1 << 20;
/// Largest check parameters a bounty may carry.
pub const MAX_PARAMS_LEN: u32 = 4096;
/// Most memory pages a check may be given (16 MiB).
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
/// Largest single faucet mint.
pub const MAX_MINT: Points = 1_000_000;

pub fn blake2b256(data: &[u8]) -> Hash {
	let h = blake2b_simd::Params::new().hash_length(32).hash(data);
	let mut out = [0; 32];
	out.copy_from_slice(h.as_bytes());
	out
}

/// What a maker puts up, and what a hunter must reproduce exactly when revealing.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BountyTerms {
	/// Blake2b-256 of the check blob (standard PVM program format, see [`program`]).
	pub check_hash: Hash,
	pub check_len: u32,
	/// Passed to the check alongside the witness, so one check blob can serve many bounties.
	pub params: Vec<u8>,
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
	Release { commitment: Hash },
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
		check_gas: Gas,
		commitment: Hash,
		hunter: AccountId,
		witness_hash: Hash,
	},
	Finalize { bounty_id: BountyId },
	Reclaim { bounty_id: BountyId, maker: AccountId, nonce: u64 },
	Release { commitment: Hash },
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
	pub bounty_id: BountyId,
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
	Commitment(Hash),
	NextBountyId,
	/// How many unfinished bounties use a check blob; the blob is forgotten when it reaches zero.
	CheckRefs(Hash),
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

/// The message a maker signs to reclaim bounty `bounty_id` on service `service_id`.
pub fn reclaim_message(service_id: u32, bounty_id: BountyId, maker: &AccountId, nonce: u64) -> Vec<u8> {
	(b"witness/reclaim", service_id, bounty_id, maker, nonce).encode()
}

/// The arguments a check receives: `E4(|params|) ++ params ++ witness`.
/// `witness_check::declare_check!` splits them back apart.
pub fn check_args(params: &[u8], witness: &[u8]) -> Vec<u8> {
	let mut args = Vec::with_capacity(4 + params.len() + witness.len());
	args.extend_from_slice(&(params.len() as u32).to_le_bytes());
	args.extend_from_slice(params);
	args.extend_from_slice(witness);
	args
}
