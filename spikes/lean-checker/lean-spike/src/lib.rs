//! Spike: can nanoda (a Lean 4 kernel checker) run in a JAM refine, and at what gas cost?
//!
//! Payload `Solicit { hash, len }`: accumulate solicits a lean4export NDJSON file as a preimage.
//! Payload `Check { hash }`: refine looks the export up, parses it and type-checks every
//! declaration, and reports the gas each phase used. A bad proof panics, failing refine.

#![cfg_attr(any(target_arch = "riscv32", target_arch = "riscv64"), no_std)]

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use codec::{Decode, Encode};
use jam_pvm_common::{accumulate, info, refine};
use jam_types::*;

#[derive(Encode, Decode)]
enum Payload {
	Solicit { hash: [u8; 32], len: u32 },
	Check { hash: [u8; 32] },
}

#[derive(Encode, Decode, Debug)]
enum Report {
	Solicit { hash: [u8; 32], len: u32 },
	Checked { bytes: u32, declarations: u32, parse_gas: u64, check_gas: u64 },
	Missing,
}

pub struct Service;
jam_pvm_common::declare_service!(Service);

// nanoda recurses deeply while type checking; it asks for a 16 MiB stack natively.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
polkavm_derive::min_stack_size!(8 * 1024 * 1024);

impl jam_pvm_common::Service for Service {
	fn refine(_: CoreIndex, _: usize, _: ServiceId, payload: WorkPayload, _: WorkPackageHash) -> WorkOutput {
		let report = match Payload::decode(&mut &payload[..]).expect("bad payload") {
			Payload::Solicit { hash, len } => Report::Solicit { hash, len },
			Payload::Check { hash } => match refine::lookup(&hash) {
				None => Report::Missing,
				Some(export) => {
					let export = String::from_utf8(export).expect("export is not UTF-8");
					let axioms: Vec<String> =
						["propext", "Classical.choice", "Quot.sound", "Lean.trustCompiler"].map(String::from).into();
					let g0 = refine::gas();
					let (file, _skipped) = nanoda_lib::util::Config::in_memory(axioms)
						.parse_export(&export)
						.expect("export does not parse");
					let g1 = refine::gas();
					info!(target = "lean", "parsed {} bytes, {} declarations, parse_gas {}, gas left {}", export.len(), file.declars.len(), g0 - g1, g1);
					file.check_all_declars();
					let g2 = refine::gas();
					Report::Checked {
						bytes: export.len() as u32,
						declarations: file.declars.len() as u32,
						parse_gas: g0 - g1,
						check_gas: g1 - g2,
					}
				},
			},
		};
		info!(target = "lean", "refine: {:?}", report);
		report.encode().into()
	}

	fn accumulate(_: Slot, _: ServiceId, _: usize) -> Option<Hash> {
		for item in accumulate::accumulate_items() {
			if let AccumulateItem::WorkItem(w) = item {
				match w.result.map(|o| Report::decode(&mut &o[..])) {
					Ok(Ok(Report::Solicit { hash, len })) => {
						let r = accumulate::solicit(&hash, len as usize);
						info!(target = "lean", "solicit: {:?}", r.is_ok());
					},
					Ok(Ok(report)) => info!(target = "lean", "accumulate: {:?}", report),
					_ => info!(target = "lean", "refine failed"),
				}
			}
		}
		let _ = vec![0u8; 0];
		None
	}
}
