//! The witness bounty service.
//!
//! Each work item's payload is one encoded [`Op`], and its extrinsics hold the blobs the op names.
//! The rules live in `witness_rules`; this crate connects them to the host: extrinsics and the
//! inner-PVM check for refine, storage for accumulate. See `witness_types` for the protocol.

#![cfg_attr(any(target_arch = "riscv32", target_arch = "riscv64"), no_std)]

extern crate alloc;

mod check_vm;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use jam_pvm_common::{accumulate, debug, info, refine};
use jam_types::{
	AccumulateItem, Balance, CoreIndex, FOOTPRINT_STORAGE_OVERHEAD, Hash, ServiceId, Slot, WorkItemRecord, WorkOutput, WorkPackageHash, WorkPayload,
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

impl witness_rules::RefineEnv for Host {
	fn extrinsic(&self, index: usize) -> Option<Vec<u8>> {
		refine::extrinsic(index)
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
		_item_index: usize,
		service_id: ServiceId,
		payload: WorkPayload,
		_package_hash: WorkPackageHash,
	) -> WorkOutput {
		let verified = match Op::decode(&mut &payload[..]) {
			Ok(op) => witness_rules::refine(&Host, service_id, op),
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
				AccumulateItem::Transfer(t) => {
					debug!(target = "witness", "transfer of {}", t.amount);
				},
			}
		}
		None
	}
}

fn on_work_item(record: WorkItemRecord, now: Slot) {
	let start = accumulate::gas();
	on_work_item_inner(record, now);
	info!(target = "witness", "accumulate used {} gas", start - accumulate::gas());
}

fn on_work_item_inner(record: WorkItemRecord, now: Slot) {
	let Ok(output) = record.result else {
		info!(target = "witness", "refine failed for item in {}", record.package);
		return;
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
	effects
		.writes
		.iter()
		.filter_map(|(key, value)| value.as_ref().map(|v| (key.len() + v.len()) as u64))
		.map(|bytes| params.deposit_per_item + params.deposit_per_byte * (bytes + FOOTPRINT_STORAGE_OVERHEAD))
		.sum()
}

/// Apply `effects` in full, or not at all.
fn apply(effects: Effects) -> Result<(), &'static str> {
	// Every write below must succeed: a failure part-way would leave half an operation applied.
	// Storage writes only fail for want of balance, so make sure there is enough first.
	let info = accumulate::my_info();
	if info.balance < info.threshold.saturating_add(deposit_needed(&effects)) {
		return Err("service balance too low to store this");
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
	Ok(())
}
