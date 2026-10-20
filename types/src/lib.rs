//! Types shared by the witness service, check blobs and the host tooling.
//!
//! The protocol, in short:
//! - A maker posts a bounty: a check blob `check(x) -> bool` (stored as a preimage of the
//!   service), a reward in points, a gas limit for the check and an expiry slot.
//! - A hunter commits to `blake2b(bounty_id, x, hunter, salt)`, waits at least
//!   [`MIN_COMMIT_AGE`] slots, then reveals `x`. Refine runs the check in an inner PVM; accumulate
//!   pays the hunter if the commitment is old enough and the bounty is still open.
//! - After `expiry + REVEAL_GRACE` an unclaimed bounty can be reclaimed by its maker.

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
/// Most memory pages a check may be given (16 MiB).
pub const MAX_CHECK_PAGES: u32 = 4096;
/// Largest witness accepted in a Reveal payload.
pub const MAX_WITNESS_LEN: u32 = 1 << 16;
/// A commitment must be this many slots old before its reveal pays out. Large enough that anyone
/// who copies `x` out of a gossiped reveal cannot get their own commitment old enough before the
/// original reveal accumulates.
pub const MIN_COMMIT_AGE: Slot = 4;
/// Slots after expiry during which commitments made before expiry may still be revealed, and
/// before which the maker may not reclaim.
pub const REVEAL_GRACE: Slot = 20;
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
	pub reward: Points,
	pub check_gas: Gas,
	/// Commitments made at or after this slot are not accepted.
	pub expiry: Slot,
}

/// A work-item payload: exactly one operation per work item.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Op {
	/// Prototype faucet: points have no backing value yet.
	Mint { to: AccountId, amount: Points },
	CreateBounty { maker: AccountId, nonce: u64, terms: BountyTerms, signature: Signature },
	Commit { commitment: Hash },
	Reveal {
		bounty_id: BountyId,
		/// Must match the bounty's terms; refine cannot read state, so the hunter supplies them
		/// and accumulate checks them.
		check_hash: Hash,
		check_gas: Gas,
		hunter: AccountId,
		salt: Hash,
		witness: Vec<u8>,
	},
	Reclaim { bounty_id: BountyId, maker: AccountId, nonce: u64, signature: Signature },
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
	Commit { commitment: Hash },
	/// The check returned true for a witness whose commitment is `commitment`.
	Reveal {
		bounty_id: BountyId,
		check_hash: Hash,
		check_gas: Gas,
		commitment: Hash,
		hunter: AccountId,
		witness_hash: Hash,
	},
	Reclaim { bounty_id: BountyId, maker: AccountId, nonce: u64 },
	Rejected(Rejection),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Account {
	pub balance: Points,
	/// Next nonce expected on a signed operation (CreateBounty, Reclaim).
	pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum BountyStatus {
	Open,
	Claimed { hunter: AccountId, witness_hash: Hash, slot: Slot },
	Reclaimed,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Bounty {
	pub maker: AccountId,
	pub terms: BountyTerms,
	pub status: BountyStatus,
}

/// Service storage keys (encoded as the raw storage key).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum StorageKey {
	Account(AccountId),
	Bounty(BountyId),
	/// Value: the slot at which the commitment was first accumulated.
	Commitment(Hash),
	NextBountyId,
}

/// The commitment a hunter posts before revealing `witness`.
pub fn commitment(bounty_id: BountyId, witness: &[u8], hunter: &AccountId, salt: &Hash) -> Hash {
	blake2b256(&(b"witness/commit", bounty_id, witness, hunter, salt).encode())
}

/// The message a maker signs to create a bounty on service `service_id`.
pub fn create_message(service_id: u32, maker: &AccountId, nonce: u64, terms: &BountyTerms) -> Vec<u8> {
	(b"witness/create", service_id, maker, nonce, terms).encode()
}

/// The message a maker signs to reclaim bounty `bounty_id` on service `service_id`.
pub fn reclaim_message(service_id: u32, bounty_id: BountyId, maker: &AccountId, nonce: u64) -> Vec<u8> {
	(b"witness/reclaim", service_id, bounty_id, maker, nonce).encode()
}
