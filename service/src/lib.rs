//! The witness bounty service.
//!
//! Each work item's payload is one encoded [`Op`]. Refine does the expensive, stateless work
//! (signature checks, running the bounty's check in an inner PVM) and outputs a [`Verified`].
//! Accumulate applies the state rules: balances, nonces, commitment ages and bounty status.
//! See `witness_types` for the protocol.

#![cfg_attr(any(target_arch = "riscv32", target_arch = "riscv64"), no_std)]

extern crate alloc;

mod check_vm;

use codec::{Decode, Encode};
use jam_pvm_common::{accumulate, debug, info, refine};
use jam_types::{
	AccumulateItem, CoreIndex, Hash, ServiceId, Slot, WorkItemRecord, WorkOutput, WorkPackageHash,
	WorkPayload,
};
use witness_types::{
	Account, AccountId, Bounty, BountyId, BountyStatus, MAX_CHECK_GAS, MAX_CHECK_LEN, MAX_MINT,
	MAX_WITNESS_LEN, MIN_COMMIT_AGE, Op, REVEAL_GRACE, Rejection, Signature, StorageKey, Verified,
	blake2b256,
};

pub struct Service;
jam_pvm_common::declare_service!(Service);

// The linker's default is 8 KiB, which Ed25519 verification overflows (a page fault, so refine
// dies without a panic message).
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
polkavm_derive::min_stack_size!(256 * 1024);

impl jam_pvm_common::Service for Service {
	fn refine(
		_core_index: CoreIndex,
		_item_index: usize,
		service_id: ServiceId,
		payload: WorkPayload,
		_package_hash: WorkPackageHash,
	) -> WorkOutput {
		let verified = match Op::decode(&mut &payload[..]) {
			Ok(op) => verify(service_id, op),
			Err(_) => Verified::Rejected(Rejection::BadPayload),
		};
		info!(target = "witness", "refine: {:?}", verified);
		verified.encode().into()
	}

	fn accumulate(now: Slot, _service_id: ServiceId, _item_count: usize) -> Option<Hash> {
		for item in accumulate::accumulate_items() {
			match item {
				AccumulateItem::WorkItem(record) => on_work_item(record, now),
				// Points are not backed by service balance yet, so transfers are just kept.
				AccumulateItem::Transfer(t) => debug!(target = "witness", "transfer of {}", t.amount),
			}
		}
		None
	}
}

fn verify_signature(key: &AccountId, message: &[u8], signature: &Signature) -> bool {
	let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(key) else { return false };
	key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature)).is_ok()
}

fn verify(service_id: ServiceId, op: Op) -> Verified {
	match op {
		Op::Mint { to, amount } => Verified::Mint { to, amount },
		Op::CreateBounty { maker, nonce, terms, signature } => {
			let message = witness_types::create_message(service_id, &maker, nonce, &terms);
			if !verify_signature(&maker, &message, &signature) {
				return Verified::Rejected(Rejection::BadSignature);
			}
			Verified::CreateBounty { maker, nonce, terms }
		},
		Op::Commit { commitment } => Verified::Commit { commitment },
		Op::Reveal { bounty_id, check_hash, check_gas, hunter, salt, witness } => {
			if check_gas > MAX_CHECK_GAS {
				return Verified::Rejected(Rejection::CheckGasTooHigh);
			}
			if witness.len() > MAX_WITNESS_LEN as usize {
				return Verified::Rejected(Rejection::WitnessTooLong);
			}
			let Some(blob) = refine::lookup(&check_hash) else {
				return Verified::Rejected(Rejection::CheckUnavailable);
			};
			if let Err(rejection) = check_vm::run_check(&blob, &witness, check_gas) {
				return Verified::Rejected(rejection);
			}
			Verified::Reveal {
				bounty_id,
				check_hash,
				check_gas,
				commitment: witness_types::commitment(bounty_id, &witness, &hunter, &salt),
				hunter,
				witness_hash: blake2b256(&witness),
			}
		},
		Op::Reclaim { bounty_id, maker, nonce, signature } => {
			let message = witness_types::reclaim_message(service_id, bounty_id, &maker, nonce);
			if !verify_signature(&maker, &message, &signature) {
				return Verified::Rejected(Rejection::BadSignature);
			}
			Verified::Reclaim { bounty_id, maker, nonce }
		},
	}
}

fn on_work_item(record: WorkItemRecord, now: Slot) {
	let Ok(output) = record.result else {
		info!(target = "witness", "refine failed for item in {}", record.package);
		return;
	};
	let Ok(verified) = Verified::decode(&mut &output[..]) else { return };
	match apply(verified, now) {
		Ok(()) => {
			accumulate::checkpoint();
		},
		Err(reason) => info!(target = "witness", "not applied: {reason}"),
	}
}

fn account(id: &AccountId) -> Account {
	accumulate::get(StorageKey::Account(*id)).unwrap_or_default()
}

fn set_account(id: &AccountId, account: &Account) {
	accumulate::set(StorageKey::Account(*id), account).expect("service balance too low for storage");
}

fn set_bounty(id: BountyId, bounty: &Bounty) {
	accumulate::set(StorageKey::Bounty(id), bounty).expect("service balance too low for storage");
}

fn apply(verified: Verified, now: Slot) -> Result<(), &'static str> {
	match verified {
		Verified::Rejected(rejection) => {
			info!(target = "witness", "rejected in refine: {:?}", rejection);
			Ok(())
		},
		Verified::Mint { to, amount } => {
			if amount > MAX_MINT {
				return Err("mint too large");
			}
			let mut acc = account(&to);
			acc.balance = acc.balance.saturating_add(amount);
			set_account(&to, &acc);
			Ok(())
		},
		Verified::CreateBounty { maker, nonce, terms } => {
			let mut acc = account(&maker);
			if nonce != acc.nonce {
				return Err("bad nonce");
			}
			if terms.check_gas > MAX_CHECK_GAS || terms.check_len > MAX_CHECK_LEN {
				return Err("check too large");
			}
			if terms.expiry <= now.saturating_add(MIN_COMMIT_AGE) {
				return Err("expiry too soon");
			}
			acc.balance = acc.balance.checked_sub(terms.reward).ok_or("insufficient points")?;
			acc.nonce += 1;

			// Several bounties may share one check; only the first solicit succeeds.
			match accumulate::solicit(&terms.check_hash, terms.check_len as usize) {
				Ok(()) | Err(jam_pvm_common::ApiError::ActionInvalid) => {},
				Err(_) => return Err("cannot solicit check blob"),
			}

			// All checks passed; from here on only writes, so a rejection never leaves partial
			// state behind.
			set_account(&maker, &acc);
			let id: BountyId = accumulate::get(StorageKey::NextBountyId).unwrap_or(0);
			accumulate::set(StorageKey::NextBountyId, id + 1).expect("service balance too low");
			info!(target = "witness", "bounty {id} created, reward {}", terms.reward);
			set_bounty(id, &Bounty { maker, terms, status: BountyStatus::Open });
			Ok(())
		},
		Verified::Commit { commitment } => {
			let key = StorageKey::Commitment(commitment);
			// Keep the earliest slot; recommitting must not reset the age.
			if accumulate::get::<Slot>(&key).is_none() {
				accumulate::set(&key, now).expect("service balance too low for storage");
			}
			Ok(())
		},
		Verified::Reveal { bounty_id, check_hash, check_gas, commitment, hunter, witness_hash } => {
			let mut bounty: Bounty =
				accumulate::get(StorageKey::Bounty(bounty_id)).ok_or("no such bounty")?;
			if bounty.status != BountyStatus::Open {
				return Err("bounty not open");
			}
			if bounty.terms.check_hash != check_hash || bounty.terms.check_gas != check_gas {
				return Err("revealed against different terms");
			}
			let key = StorageKey::Commitment(commitment);
			let committed: Slot = accumulate::get(&key).ok_or("no commitment")?;
			if committed.saturating_add(MIN_COMMIT_AGE) > now {
				return Err("commitment too recent");
			}
			if committed >= bounty.terms.expiry {
				return Err("committed after expiry");
			}
			if now >= bounty.terms.expiry.saturating_add(REVEAL_GRACE) {
				return Err("reveal window closed");
			}

			let mut acc = account(&hunter);
			acc.balance = acc.balance.saturating_add(bounty.terms.reward);
			set_account(&hunter, &acc);
			bounty.status = BountyStatus::Claimed { hunter, witness_hash, slot: now };
			set_bounty(bounty_id, &bounty);
			accumulate::remove(&key);
			info!(target = "witness", "bounty {bounty_id} claimed");
			Ok(())
		},
		Verified::Reclaim { bounty_id, maker, nonce } => {
			let mut bounty: Bounty =
				accumulate::get(StorageKey::Bounty(bounty_id)).ok_or("no such bounty")?;
			if bounty.maker != maker {
				return Err("not the maker");
			}
			if bounty.status != BountyStatus::Open {
				return Err("bounty not open");
			}
			if now < bounty.terms.expiry.saturating_add(REVEAL_GRACE) {
				return Err("reveal window still open");
			}
			let mut acc = account(&maker);
			if nonce != acc.nonce {
				return Err("bad nonce");
			}
			acc.nonce += 1;
			acc.balance = acc.balance.saturating_add(bounty.terms.reward);
			set_account(&maker, &acc);
			bounty.status = BountyStatus::Reclaimed;
			set_bounty(bounty_id, &bounty);
			Ok(())
		},
	}
}
