//! Types shared by the witness service, check blobs and the host tooling.
//!
//! The protocol, in short:
//! - A maker posts a bounty: a check blob `check(params, x) -> bool` (by hash), the `params` to
//!   run it with, any extra blobs the check reads (by hash), a reward in an asset, a gas limit for
//!   the check, an expiry slot and a claim window.
//! - A hunter commits to `blake2b(bounty_id, x, hunter, salt)`, paying the configured commit
//!   deposit, then reveals `x` at least [`MIN_COMMIT_AGE`] slots later. Refine runs the check in
//!   an inner PVM.
//! - The first valid reveal opens the claim window. Every valid reveal before it closes competes,
//!   and the one whose commitment reached the chain earliest wins. Someone who copies `x` out of a
//!   reveal can only commit after seeing it, so they always lose to the original. Ties within a
//!   slot go to the lower commitment hash.
//! - `Finalize` after the window pays the winner. After `expiry + REVEAL_GRACE` a bounty no one
//!   revealed for can be reclaimed by its maker.
//! - A valid reveal refunds its commitment's deposit; unrevealed commitments forfeit theirs, which
//!   is what makes spamming commitments cost something.
//!
//! Blobs are never stored (see docs/design/extrinsics.md): an op's work item carries the blobs it
//! uses as extrinsics, and refine checks each against a hash or Merkle root recorded on chain. So
//! state holds only records, whatever the size of the blobs.
//!
//! Attestations let checks reuse verification across refines (see docs/design/attestation-dag.md):
//! - `Attest` runs a check in attest mode on subjects (one extrinsic holding them all), trusting
//!   subjects of earlier attestations it cites. If the check returns true, accumulate records an
//!   [`Attestation`]: "check C, with these params, verified every subject under this Merkle root,
//!   given those parents' subjects". Any of them can then be trusted on its own, with its path.
//! - Bounties cite attested subjects, and reveals can cite more. The check receives them marked
//!   trusted, and can skip re-verifying them.
//! - Attestations form a DAG. Trust needs no context: an attestation is only recorded once its
//!   parents were, so a cited attestation rests, by induction, on subjects that were all checked.
//! - A check only ever trusts its own attestations: everything an op cites is by the same check
//!   with the same attest params, and a bounty may only cite its own check's attestations.
//!
//! Money is assets of token services (see docs/design/tokens.md): an account's balances are
//! credited by deposit transfers from accepted token services and paid out by withdrawal
//! transfers back. An admin configures which, under a timelock.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};

pub mod program;

pub type Hash = [u8; 32];
/// An Ed25519 public key. Balances are held per account and per asset.
pub type AccountId = [u8; 32];
pub type Signature = [u8; 64];
pub type BountyId = u64;
pub type Slot = u32;
/// An amount of an asset, in its smallest unit.
pub type Amount = u128;
pub type Gas = u64;
/// See [`AttestationClaim::id`].
pub type AttestationId = Hash;

/// Most gas a bounty may give its check. Must leave refine enough headroom for the rest of a
/// Reveal (lookup, hashing, setting up the inner PVM) within one work-item's refine gas: the full
/// spec allows 5×10⁹. On a network with less (PolkaJam's "tiny" parameters allow 10⁹), a check
/// given more than refine can spend just runs out of gas.
pub const MAX_CHECK_GAS: Gas = 4_500_000_000;
/// Largest check blob a bounty may name.
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
/// Largest single faucet mint.
pub const MAX_MINT: Amount = 1_000_000;
/// Slots between an admin proposing an action and its taking effect: about 7 days of 6-second
/// slots, time for anyone who disagrees to withdraw first. A test build can set it with
/// `WITNESS_ADMIN_DELAY`.
pub const ADMIN_DELAY: Slot = match option_env!("WITNESS_ADMIN_DELAY") {
	Some(slots) => parse_slots(slots),
	None => 100_800,
};

const fn parse_slots(digits: &str) -> Slot {
	let digits = digits.as_bytes();
	assert!(!digits.is_empty(), "WITNESS_ADMIN_DELAY must be a number of slots");
	let (mut n, mut i) = (0u32, 0);
	while i < digits.len() {
		assert!(digits[i].is_ascii_digit(), "WITNESS_ADMIN_DELAY must be a number of slots");
		n = n * 10 + (digits[i] - b'0') as u32;
		i += 1;
	}
	n
}

/// The admin until the role is handed on: the key in `WITNESS_ADMIN` (64 hex digits) when the
/// service is built, or else, for test builds, the witness CLI's `--seed admin`.
pub const BUILD_ADMIN: AccountId = match option_env!("WITNESS_ADMIN") {
	Some(hex) => parse_key(hex),
	None => parse_key("5402051ea9ef82b9a3e2e27e3a2a4b58f047c002ae6f3a0510f9849e720f253a"),
};

const fn parse_key(hex: &str) -> AccountId {
	const fn digit(c: u8) -> u8 {
		match c {
			b'0'..=b'9' => c - b'0',
			b'a'..=b'f' => c - b'a' + 10,
			b'A'..=b'F' => c - b'A' + 10,
			_ => panic!("WITNESS_ADMIN must be 64 hex digits"),
		}
	}
	let hex = hex.as_bytes();
	assert!(hex.len() == 64, "WITNESS_ADMIN must be 64 hex digits");
	let mut key = [0; 32];
	let mut i = 0;
	while i < 32 {
		key[i] = digit(hex[2 * i]) << 4 | digit(hex[2 * i + 1]);
		i += 1;
	}
	key
}

/// An asset: asset `id` of token service `service` (0 for a service with one asset).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Asset {
	pub service: u32,
	pub id: u32,
}

/// The faucet's asset, on test builds: no token service backs it, so it can't be withdrawn.
pub const TEST_ASSET: Asset = Asset { service: u32::MAX, id: 0 };

/// What the admin sets (see docs/design/tokens.md).
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Config {
	/// Token services whose deposits are credited, and whose assets bounties may pay in.
	pub token_services: Vec<u32>,
	/// The asset spam deposits are paid in.
	pub fee_asset: Option<Asset>,
	/// Locked per commitment, refunded on a valid reveal.
	pub commit_deposit: Amount,
	/// Paid per attestation, kept: attestations are permanent records.
	pub attest_deposit: Amount,
}

/// What an admin proposal does once its delay has passed.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum AdminAction {
	/// Replace the configuration. The first one, made before any, applies at once: nobody's
	/// funds are at stake yet.
	Configure(Config),
	/// Hand the admin role to another key.
	SetAdmin(AccountId),
	/// Replace the service's code with the blob hashing to `code_hash`, which proposing solicits.
	Upgrade { code_hash: Hash, code_len: u32 },
}

/// A pending admin proposal.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Proposal {
	pub action: AdminAction,
	/// The first slot it can be applied in.
	pub effective: Slot,
}

/// The version byte memos start with.
pub const MEMO_VERSION: u8 = 1;

/// A deposit transfer's memo, from a token service: credit `amount` of its asset `asset_id` to
/// witness account `to`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DepositMemo {
	pub version: u8,
	pub asset_id: u32,
	pub amount: Amount,
	pub to: AccountId,
}

/// A withdrawal transfer's memo, to a token service: pay `amount` of its asset `asset_id` to its
/// account `to`, out of witness's.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct WithdrawalMemo {
	pub version: u8,
	pub asset_id: u32,
	pub amount: Amount,
	pub to: [u8; 32],
}

/// The length of a JAM transfer memo.
pub const MEMO_LEN: usize = 128;

/// `value` as a memo: encoded, then zero-padded.
pub fn memo(value: &impl Encode) -> [u8; MEMO_LEN] {
	let mut memo = [0; MEMO_LEN];
	let data = value.encode();
	memo[..data.len()].copy_from_slice(&data);
	memo
}

pub fn blake2b256(data: &[u8]) -> Hash {
	let h = blake2b_simd::Params::new().hash_length(32).hash(data);
	let mut out = [0; 32];
	out.copy_from_slice(h.as_bytes());
	out
}

/// A blob, by hash and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BlobHash {
	pub hash: Hash,
	pub len: u32,
}

/// Where an op's blob is: entry `index` of extrinsic `extrinsic` of its work item. Each extrinsic
/// is a [`Blobs`], so an op can carry more blobs than a work item has extrinsics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BlobAt {
	pub extrinsic: u8,
	pub index: u32,
}

/// An extrinsic: blobs, encoded as a `Vec<Vec<u8>>`.
pub type Blobs = Vec<Vec<u8>>;

/// The blobs in an encoded [`Blobs`], without copying them; `None` unless `data` is exactly one
/// list of at most [`MAX_BLOBS`] blobs.
pub fn blobs_in(mut data: &[u8]) -> Option<Vec<&[u8]>> {
	let input = &mut data;
	let count = codec::Compact::<u32>::decode(input).ok()?.0;
	if count > MAX_BLOBS {
		return None;
	}
	let mut blobs = Vec::with_capacity(count as usize);
	for _ in 0..count {
		let len = codec::Compact::<u32>::decode(input).ok()?.0 as usize;
		let (blob, rest) = input.split_at_checked(len)?;
		blobs.push(blob);
		*input = rest;
	}
	input.is_empty().then_some(blobs)
}

/// A Merkle tree over an attestation's subjects. Leaves are `blake2b(0x00 ++ blake2b(subject))`
/// and inner nodes `blake2b(0x01 ++ left ++ right)`, so a leaf can't pass for a node. A leaf comes
/// from its subject's hash, which a check is given anyway, so each subject is hashed once. At each level, an odd
/// node at the end is carried up as it is. The number of subjects fixes the shape.
pub mod merkle {
	use super::{Hash, blake2b256};
	use alloc::vec::Vec;

	/// The leaf of the subject hashing to `subject_hash`.
	pub fn leaf(subject_hash: &Hash) -> Hash {
		let mut data = [0u8; 33];
		data[1..].copy_from_slice(subject_hash);
		blake2b256(&data)
	}

	fn node(left: &Hash, right: &Hash) -> Hash {
		blake2b256(&[&[1u8][..], left, right].concat())
	}

	fn up(level: &[Hash]) -> Vec<Hash> {
		level.chunks(2).map(|pair| if let [l, r] = pair { node(l, r) } else { pair[0] }).collect()
	}

	/// The root over `leaves` (all zeros for none).
	pub fn root(leaves: &[Hash]) -> Hash {
		let mut level = leaves.to_vec();
		while level.len() > 1 {
			level = up(&level);
		}
		level.first().copied().unwrap_or([0; 32])
	}

	/// The path proving leaf `index` of `leaves`: the sibling at each level that has one.
	pub fn path(leaves: &[Hash], mut index: usize) -> Vec<Hash> {
		let mut level = leaves.to_vec();
		let mut out = Vec::new();
		while level.len() > 1 {
			let sibling = index ^ 1;
			if sibling < level.len() {
				out.push(level[sibling]);
			}
			level = up(&level);
			index /= 2;
		}
		out
	}

	/// Whether `path` proves `leaf` is leaf `index` of `count` under `root`.
	pub fn verify(root: &Hash, count: u32, index: u32, leaf: Hash, path: &[Hash]) -> bool {
		if index >= count {
			return false;
		}
		let (mut index, mut width, mut hash, mut path) = (index as usize, count as usize, leaf, path.iter());
		while width > 1 {
			let sibling = index ^ 1;
			if sibling < width {
				let Some(s) = path.next() else { return false };
				hash = if index % 2 == 0 { node(&hash, s) } else { node(s, &hash) };
			}
			index /= 2;
			width = width.div_ceil(2);
		}
		path.next().is_none() && hash == *root
	}
}

/// A blob a bounty gives its check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum BlobRef {
	/// A plain blob: the check must verify whatever it relies on in it.
	Blob(BlobHash),
	/// Subject `entry` of an attestation by the bounty's own check, passed to it as trusted.
	Attested { attestation: AttestationId, entry: u32 },
}

/// What an attestation says: check `check_hash`, run in attest mode with params hashing to
/// `params_hash`, returned true for every one of the `subject_count` subjects under
/// `subjects_root`, given trusted subjects of the attestations whose ids `parents_root` commits
/// to.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AttestationClaim {
	pub check_hash: Hash,
	pub params_hash: Hash,
	/// See [`merkle`].
	pub subjects_root: Hash,
	pub subject_count: u32,
	/// See [`parents_root`]. Committing to the parents through a root keeps a claim a few hashes
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

/// A trusted subject, as an op cites it: subject `entry` of the op's claim number `claim`, whose
/// bytes are at `blob`, with its Merkle path.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TrustedRef {
	pub claim: u16,
	pub entry: u32,
	pub blob: BlobAt,
	pub path: Vec<Hash>,
}

/// A recorded attestation. Kept for good, so it holds only what accumulate needs: the claim is
/// its id.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Attestation {
	/// The claim's check and params, which a bounty citing it must match.
	pub check_hash: Hash,
	pub params_hash: Hash,
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
	/// subjects (trusted) and plain blobs. A reveal supplies them all.
	pub blobs: Vec<BlobRef>,
	/// The asset the reward is escrowed and paid in.
	pub asset: Asset,
	pub reward: Amount,
	pub check_gas: Gas,
	/// Commitments made at or after this slot are not accepted.
	pub expiry: Slot,
	/// Slots from the first valid reveal until the bounty can be finalized.
	pub claim_window: Slot,
}

/// A work-item payload: exactly one operation per work item.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Op {
	/// Test faucet, crediting [`TEST_ASSET`].
	Mint { to: AccountId, amount: Amount },
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
		/// The extrinsic holding the check blob, on its own: JAM commits to each extrinsic's
		/// Blake2b-256 hash, so refine needn't hash the blob itself.
		check: u8,
		/// The bounty's plain blobs, in order.
		plain: Vec<BlobAt>,
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
	/// Attest that check `check_hash` accepts every subject in extrinsic `subjects`, trusting the
	/// subjects `trusted` cites, paying [`ATTEST_DEPOSIT`]. Refine can't read state, so the
	/// attester supplies the claims cited; accumulate checks they were recorded.
	Attest {
		attester: AccountId,
		nonce: u64,
		check_hash: Hash,
		/// The extrinsic holding the check blob, on its own, as for `Reveal`.
		check: u8,
		params: Vec<u8>,
		subjects: u8,
		/// The parent attestations, each once.
		claims: Vec<AttestationClaim>,
		trusted: Vec<TrustedRef>,
		/// The attester's evidence, passed to the check (a batch's proofs, say). Not part of the
		/// claim: the attestation is about the subjects, however they were shown.
		witness: Vec<u8>,
		check_gas: Gas,
		signature: Signature,
	},
	/// Pay `amount` of `asset` out to `to`, the payee's account in the asset's token service.
	Withdraw { account: AccountId, nonce: u64, asset: Asset, amount: Amount, to: [u8; 32], signature: Signature },
	/// The admin proposes `action`, to take effect after [`ADMIN_DELAY`].
	Propose { admin: AccountId, nonce: u64, action: AdminAction, signature: Signature },
	/// Carry out proposal `id` once its delay has passed. Anyone may send it.
	Apply { id: u64 },
	/// The admin drops proposal `id`.
	Cancel { admin: AccountId, nonce: u64, id: u64, signature: Signature },
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
	/// A blob the op names isn't in its extrinsics, or isn't what the op says it is (its hash,
	/// or for a trusted subject its Merkle path, doesn't match).
	BadBlob,
	/// More than [`MAX_BLOBS`] blobs, or more than [`MAX_BLOBS_LEN`] bytes of them.
	BlobsTooLarge,
	/// An attestation by a check other than the one being run, or with other params.
	ForeignAttestation,
	/// A trusted reference to a claim or entry that doesn't exist, a claim cited twice or that no
	/// reference uses, or a reveal that doesn't trust its bounty's attested subjects.
	BadTrustedRef,
	/// An extrinsic that doesn't decode as [`Blobs`], or holds more than [`MAX_BLOBS`].
	BadExtrinsic,
	/// The check blob is not a valid standard program, or needs more memory than allowed.
	BadCheckBlob,
	CheckFailed(CheckFailure),
}

/// Refine's output: an [`Op`] whose expensive parts (signatures, the check) have been verified.
/// Accumulate trusts these and only applies the state rules.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Verified {
	Mint { to: AccountId, amount: Amount },
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
	/// The check returned true in attest mode; accumulate records `claim` if `parents` (whose
	/// root the claim covers) were.
	Attest { attester: AccountId, nonce: u64, claim: AttestationClaim, parents: Vec<AttestationId> },
	Withdraw { account: AccountId, nonce: u64, asset: Asset, amount: Amount, to: [u8; 32] },
	Propose { admin: AccountId, nonce: u64, action: AdminAction },
	Apply { id: u64 },
	Cancel { admin: AccountId, nonce: u64, id: u64 },
	Rejected(Rejection),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Account {
	/// Next nonce expected on a signed operation.
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
	/// What the committer locked: the fee asset and commit deposit of the time.
	pub deposit_asset: Asset,
	pub deposit: Amount,
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
	Attestation(AttestationId),
	/// An account's balance of an asset, absent at zero.
	Balance(AccountId, Asset),
	Config,
	/// The current admin, once it has been handed on from the build's.
	Admin,
	Proposal(u64),
	NextProposalId,
	/// Native balance an account has sent along with its deposits, for paying for its own
	/// storage (see docs/design/tokens.md). Recorded, not yet spent: the sponsor pays for now.
	StorageCredit(AccountId),
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

/// The message an attester signs to attest the claim with id `id` on service `service_id`.
pub fn attest_message(service_id: u32, attester: &AccountId, nonce: u64, id: &AttestationId) -> Vec<u8> {
	(b"witness/attest", service_id, attester, nonce, id).encode()
}

/// The message an account signs to withdraw on service `service_id`.
pub fn withdraw_message(
	service_id: u32,
	account: &AccountId,
	nonce: u64,
	asset: &Asset,
	amount: Amount,
	to: &[u8; 32],
) -> Vec<u8> {
	(b"witness/withdraw", service_id, account, nonce, asset, amount, to).encode()
}

/// The message the admin signs to propose `action` on service `service_id`.
pub fn propose_message(service_id: u32, admin: &AccountId, nonce: u64, action: &AdminAction) -> Vec<u8> {
	(b"witness/propose", service_id, admin, nonce, action).encode()
}

/// The message the admin signs to cancel proposal `id` on service `service_id`.
pub fn cancel_message(service_id: u32, admin: &AccountId, nonce: u64, id: u64) -> Vec<u8> {
	(b"witness/cancel", service_id, admin, nonce, id).encode()
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

#[cfg(test)]
mod tests {
	use super::{blake2b256, merkle};

	#[test]
	fn merkle_paths_prove_exactly_their_leaf() {
		for count in 1..=17u32 {
			let leaves: alloc::vec::Vec<_> = (0..count).map(|i| merkle::leaf(&blake2b256(&i.to_le_bytes()))).collect();
			let root = merkle::root(&leaves);
			for i in 0..count {
				let path = merkle::path(&leaves, i as usize);
				assert!(merkle::verify(&root, count, i, leaves[i as usize], &path), "{i} of {count}");
				let other = (i + 1) % count;
				if other != i {
					assert!(!merkle::verify(&root, count, other, leaves[i as usize], &path), "{i} as {other}");
					assert!(!merkle::verify(&root, count, i, leaves[other as usize], &path), "{other} at {i}");
				}
				assert!(!merkle::verify(&root, count, count, leaves[i as usize], &path));
			}
		}
		// A leaf can't pass for an inner node: its hash is domain-separated.
		assert_ne!(merkle::leaf(&[0; 32]), merkle::root(&[]));
	}
}
