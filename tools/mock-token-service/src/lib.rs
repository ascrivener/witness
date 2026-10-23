//! A mock token service on JAM, for testing witness's deposits and withdrawals. **Test only:
//! anyone can mint and move anyone's tokens.** The rules are in `mock_token`; each work item's
//! payload is a [`TokenOp`], applied in accumulate.

#![cfg_attr(any(target_arch = "riscv32", target_arch = "riscv64"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::Decode;
use jam_pvm_common::{accumulate, info};
use jam_types::{AccumulateItem, CoreIndex, Hash, Memo, ServiceId, Slot, WorkOutput, WorkPackageHash, WorkPayload};
use mock_token::{Effects, TokenOp};

pub struct Service;
jam_pvm_common::declare_service!(Service);

struct Host;

impl mock_token::State for Host {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		accumulate::get_storage(key)
	}
}

impl jam_pvm_common::Service for Service {
	fn refine(_: CoreIndex, _: usize, _: ServiceId, payload: WorkPayload, _: WorkPackageHash) -> WorkOutput {
		// Nothing to verify: ops are unauthenticated.
		payload.take().into()
	}

	fn accumulate(_now: Slot, _service_id: ServiceId, _item_count: usize) -> Option<Hash> {
		for item in accumulate::accumulate_items() {
			let applied = match item {
				AccumulateItem::WorkItem(record) => match record.result {
					Ok(output) => TokenOp::decode(&mut &output[..])
						.map_err(|_| "not an op")
						.and_then(|op| mock_token::apply(&Host, op)),
					Err(_) => Err("refine failed"),
				},
				AccumulateItem::Transfer(t) => mock_token::on_transfer(&Host, t.source, &t.memo.0),
			};
			match applied.and_then(apply) {
				Ok(()) => {
					accumulate::checkpoint();
				},
				Err(reason) => info!(target = "mock-token", "not applied: {reason}"),
			}
		}
		None
	}
}

fn apply(fx: Effects) -> Result<(), &'static str> {
	for (key, value) in &fx.writes {
		match value {
			Some(value) => accumulate::set_storage(key, value).map_err(|_| "service balance too low")?,
			None => accumulate::remove_storage(key),
		};
	}
	for (destination, memo) in &fx.transfers {
		let gas = accumulate::service_info(*destination).ok_or("no such service")?.min_memo_gas;
		accumulate::transfer(*destination, 0, gas, &Memo(*memo)).map_err(|_| "transfer failed")?;
	}
	Ok(())
}
