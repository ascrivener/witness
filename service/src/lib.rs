//! The witness bounty service.
//!
//! Each work item's payload is one encoded [`Op`], and its extrinsics hold the blobs the op names.
//! The rules live in `witness_rules`; this crate connects them to the host: extrinsics and the
//! inner-PVM check for refine; storage, transfers in and out, and code upgrades for accumulate.
//! See `witness_types` for the protocol.

#![cfg_attr(any(target_arch = "riscv32", target_arch = "riscv64"), no_std)]

extern crate alloc;

mod check_vm;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use jam_pvm_common::{accumulate, info, refine};
use jam_types::{
	AccumulateItem, Balance, CoreIndex, FOOTPRINT_PREIMAGE_OVERHEAD, FOOTPRINT_STORAGE_OVERHEAD, Hash, Memo, ServiceId,
	Slot, TransferRecord, WorkItemRecord, WorkOutput, WorkPackageHash, WorkPayload,
};
use witness_rules::Effects;
use witness_types::{Gas, Op, Rejection, Verified};

pub struct Service;
jam_pvm_common::declare_service!(Service);

// The linker's default is 8 KiB, which Ed25519 verification overflows (a page fault, so refine
// dies without a panic message).
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
polkavm_derive::min_stack_size!(256 * 1024);

struct Host;

/// Refine's host: the work item being refined is item `item` of its package.
struct RefineHost {
	item: usize,
}

impl witness_rules::RefineEnv for RefineHost {
	fn extrinsic(&self, index: usize) -> Option<Vec<u8>> {
		refine::extrinsic(index)
	}
	fn extrinsic_hash(&self, index: usize) -> Option<Hash> {
		let package = refine::work_package();
		Some(package.items.get(self.item)?.extrinsics.get(index)?.hash.0)
	}
	fn run_check(&self, blob: &[u8], args: &[u8], gas: Gas) -> Result<(), Rejection> {
		check_vm::run_check(blob, args, gas)
	}
}

impl witness_rules::State for Host {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		accumulate::get_storage(key)
	}
}

impl jam_pvm_common::Service for Service {
	fn refine(
		_core_index: CoreIndex,
		item_index: usize,
		service_id: ServiceId,
		payload: WorkPayload,
		_package_hash: WorkPackageHash,
	) -> WorkOutput {
		let verified = match Op::decode(&mut &payload[..]) {
			Ok(op) => witness_rules::refine(&RefineHost { item: item_index }, service_id, op),
			Err(_) => Verified::Rejected(Rejection::BadPayload),
		};
		info!(target = "witness", "refine: {:?}", verified);
		verified.encode().into()
	}

	fn accumulate(now: Slot, _service_id: ServiceId, _item_count: usize) -> Option<Hash> {
		for item in accumulate::accumulate_items() {
			match item {
				AccumulateItem::WorkItem(record) => on_work_item(record, now),
				AccumulateItem::Transfer(t) => on_transfer(t),
			}
		}
		None
	}
}

/// A deposit, if it's from an accepted token service; its native balance stays with the service
/// either way.
fn on_transfer(t: TransferRecord) {
	let start = accumulate::gas();
	match witness_rules::on_transfer(&Host, t.source, t.amount, &t.memo.0).and_then(apply) {
		Ok(()) => {
			accumulate::checkpoint();
			info!(target = "witness", "deposit from service {} used {} gas", t.source, start - accumulate::gas());
		},
		Err(reason) => info!(target = "witness", "transfer of {} from service {}: {reason}", t.amount, t.source),
	}
}

fn on_work_item(record: WorkItemRecord, now: Slot) {
	let start = accumulate::gas();
	on_work_item_inner(record, now);
	info!(target = "witness", "accumulate used {} gas", start - accumulate::gas());
}

fn on_work_item_inner(record: WorkItemRecord, now: Slot) {
	let output = match record.result {
		Ok(output) => output,
		Err(e) => {
			info!(target = "witness", "refine failed for item in {}: {:?}", record.package, e);
			return;
		},
	};
	let Ok(verified) = Verified::decode(&mut &output[..]) else { return };
	if let Verified::Rejected(rejection) = &verified {
		info!(target = "witness", "rejected in refine: {:?}", rejection);
		return;
	}
	let applied = witness_rules::accumulate(&Host, verified, now).and_then(apply);
	match applied {
		Ok(()) => {
			accumulate::checkpoint();
		},
		Err(reason) => {
			info!(target = "witness", "not applied: {reason}");
		},
	}
}

/// The most storage deposit `effects` could add, counting every write as a new item.
fn deposit_needed(effects: &Effects) -> Balance {
	let params = accumulate::protocol_parameters();
	let item = |bytes: u64| params.deposit_per_item + params.deposit_per_byte * bytes;
	let writes: Balance = effects
		.writes
		.iter()
		.filter_map(|(key, value)| value.as_ref().map(|v| (key.len() + v.len()) as u64))
		.map(|bytes| item(bytes + FOOTPRINT_STORAGE_OVERHEAD))
		.sum();
	let solicit = effects.solicit.map_or(0, |(_, len)| item(len as u64 + FOOTPRINT_PREIMAGE_OVERHEAD));
	writes + solicit
}

/// Gas for sending one transfer, beyond the gas it carries.
const TRANSFER_OVERHEAD: u64 = 20_000;

/// Apply `effects` in full, or not at all.
fn apply(effects: Effects) -> Result<(), &'static str> {
	// Every write below must succeed: a failure part-way would leave half an operation applied.
	// Storage writes only fail for want of balance, so make sure there is enough first.
	let info = accumulate::my_info();
	if info.balance < info.threshold.saturating_add(deposit_needed(&effects)) {
		return Err("service balance too low to store this");
	}
	// Likewise the transfers and the upgrade: check now what would make them fail later.
	let mut transfers = alloc::vec::Vec::new();
	for (destination, memo) in &effects.transfers {
		let to = accumulate::service_info(*destination).ok_or("no such token service")?;
		transfers.push((*destination, to.min_memo_gas, Memo(*memo)));
	}
	// Each transfer's gas comes out of this accumulate's, with a little for the host calls.
	let gas_needed: u64 = transfers.iter().map(|(_, gas, _)| gas.saturating_add(TRANSFER_OVERHEAD)).sum();
	if accumulate::gas() < gas_needed {
		return Err("not enough gas left to send the transfers");
	}
	if effects.upgrade.is_some_and(|code_hash| !accumulate::is_available(&code_hash)) {
		return Err("the new code hasn't been provided");
	}
	for (key, value) in &effects.writes {
		match value {
			Some(value) => {
				accumulate::set_storage(key, value).expect("balance checked above");
			},
			None => {
				accumulate::remove_storage(key);
			},
		}
	}
	for (destination, gas, memo) in &transfers {
		// No native balance moves: the memo carries the withdrawal.
		accumulate::transfer(*destination, 0, *gas, memo).expect("destination and gas checked above");
	}
	if let Some((hash, len)) = effects.solicit {
		// Already requested is fine: someone proposed the same code before.
		let _ = accumulate::solicit(&hash, len as usize);
	}
	if let Some(code_hash) = effects.upgrade {
		// The new code takes over from the next work item; the service keeps its id and state.
		accumulate::upgrade(&code_hash.into(), info.min_item_gas, info.min_memo_gas);
	}
	Ok(())
}
