//! Runs witness ops natively, in place of a JAM testnet, for iterating in seconds instead of
//! minutes. It takes the subset of `jamt`'s commands the scripts use, so a script points `JAMT` at
//! it and runs unchanged:
//!
//!     witness-sim create-service SERVICE_BLOB BALANCE   start afresh, with the witness service;
//!                                                        or, for mock-token-service's blob, add
//!                                                        the test token service beside it
//!     witness-sim list                                   the services, as `jamt list` prints them
//!     witness-sim item SERVICE PAYLOAD [EXTRINSIC...]    refine and accumulate one op (hex, or
//!                                                        @FILE holding the hex), with its
//!                                                        extrinsics (files)
//!     witness-sim provide SERVICE FILE                   provide a preimage (logged; witness
//!                                                        stores none but upgrade code)
//!     witness-sim inspect slot                           the current slot (and pass one)
//!     witness-sim inspect storage --raw SERVICE KEY      a storage value, hex
//!     witness-sim inspect final service SERVICE          whether the service exists
//!     witness-sim check BLOB ARGS GAS                    run a check blob on arguments (a file,
//!                                                        see `witness_types::check_args`) with
//!                                                        up to GAS, and print the gas it used
//!
//! State lives in `$WITNESS_SIM_DIR` (default `.witness-sim`), and the log the testnet's nodes
//! would print (`refine: ...`, `check used N gas of L`) in its `log`.
//!
//! What's real: the service's rules (`witness-rules`), extrinsics as refine fetches them, and
//! check blobs run in PolkaVM with the JAM
//! instruction set, gas metering and the `grow_heap` host call, as the service runs them in an
//! inner PVM, with the gas PolkaJam v0.1.29 charges (PolkaVM's full cost model with L2 cache hits
//! matched it exactly on the sample checks; `POLKAVM_DEFAULT_COST_MODEL` overrides it). What
//! isn't: time (a slot passes with every item and every `inspect slot`), the service's storage
//! deposits, work-package limits, and the gas of refine and accumulate themselves, so a testnet
//! stays the judge of what fits.

use codec::{Decode, Encode};
use polkavm::{
	ArcBytes, CacheModel, Config, CostModelKind, Engine, GasMeteringKind, InterruptKind, MemoryProtection, Module, ModuleConfig, ProgramBlob,
	ProgramCounter, ProgramParts, Reg, program::InstructionSetKind,
};
use std::{
	collections::BTreeMap,
	io::Write,
	path::PathBuf,
	process::ExitCode,
};
use witness_types::{
	CheckFailure, Gas, MAX_CHECK_PAGES, Op, Rejection, Verified,
	program::{Access, Heap, PAGE_SIZE, StandardProgram, initialize},
};

/// Run check `blob` on `args` in windows of `window` gas, printing for each window the pages it
/// read and wrote: what pausing the check at that window's end, and resuming it elsewhere, would
/// carry. Pages are mapped only when touched: read-only at first, writable on the first write.
fn profile_pages(blob: &[u8], args: &[u8], window: Gas) -> Result<(), Rejection> {
	use std::collections::{BTreeMap as Map, BTreeSet as Set};
	fn bad<E>(_: E) -> Rejection {
		Rejection::BadCheckBlob
	}
	let program = StandardProgram::parse_jam_blob(blob).ok_or(Rejection::BadCheckBlob)?;
	let layout = initialize(&program, args).ok_or(Rejection::BadCheckBlob)?;
	let mut config = Config::from_env().map_err(bad)?;
	config.set_allow_dynamic_paging(true);
	if config.default_cost_model().is_none() {
		config.set_default_cost_model(Some(CostModelKind::Full(CacheModel::L2Hit)));
	}
	let engine = Engine::new(&config).map_err(bad)?;
	let mut module_config = ModuleConfig::new();
	module_config.set_page_size(PAGE_SIZE as u32);
	module_config.set_gas_metering(Some(GasMeteringKind::Sync));
	module_config.set_dynamic_paging(true);
	let mut parts = ProgramParts::empty(InstructionSetKind::JamV1);
	parts.code_and_jump_table = ArcBytes::from(layout.code.to_vec());
	let program_blob = ProgramBlob::from_parts(parts).map_err(bad)?;
	let module = Module::from_blob(&engine, &module_config, program_blob).map_err(bad)?;
	let mut vm = module.instantiate().map_err(bad)?;
	// Every page's contents, kept here between windows; and which pages may be mapped.
	let page_len = PAGE_SIZE as usize;
	let mut contents: Map<u64, Vec<u8>> = Map::new();
	let mut valid: Set<u64> = Set::new();
	for region in &layout.regions {
		for i in 0..region.pages {
			let page = region.first_page + i;
			valid.insert(page);
			let start = (i as usize * page_len).min(region.data.len());
			let end = ((i as usize + 1) * page_len).min(region.data.len());
			if start < end {
				let mut data = region.data[start..end].to_vec();
				data.resize(page_len, 0);
				contents.insert(page, data);
			}
		}
	}
	for (reg, value) in Reg::ALL.into_iter().zip(layout.registers) {
		vm.set_reg(reg, value);
	}
	vm.set_next_program_counter(ProgramCounter(0));
	let mut heap = Heap::new(&layout, MAX_CHECK_PAGES as u64);
	let (mut read, mut written): (Set<u64>, Set<u64>) = (Set::new(), Set::new());
	let (mut ever_read, mut ever_written): (Set<u64>, Set<u64>) = (Set::new(), Set::new());
	let (mut windows, mut used) = (0u64, 0u64);
	// Pages an earlier window wrote, and the window that last wrote each: a window that reads one
	// has to be given it. Those last written in the first window, while the check loads what it's
	// given, could be rebuilt each step instead; the rest are the check's own state.
	let mut carried: Set<u64> = Set::new();
	let mut last_write: Map<u64, u64> = Map::new();
	let report = |n: u64, read: &Set<u64>, written: &Set<u64>, carried: &Set<u64>, last_write: &Map<u64, u64>| {
		let given: Vec<u64> = read.intersection(carried).copied().collect();
		let early = given.iter().filter(|p| last_write.get(p) == Some(&1)).count();
		println!(
			"window {n}: {} pages read, {} carried ({} MiB): {early} last written in window 1 ({} MiB), {} since ({} MiB); {} written",
			read.len(),
			given.len(),
			given.len() * 4 / 1024,
			early * 4 / 1024,
			given.len() - early,
			(given.len() - early) * 4 / 1024,
			written.len()
		);
	};
	vm.set_gas(window as i64);
	let outcome = loop {
		match vm.run().map_err(bad)? {
			InterruptKind::Segfault(fault) => {
				let page = u64::from(fault.page_address) / PAGE_SIZE;
				if fault.is_write_protected {
					written.insert(page);
					ever_written.insert(page);
					vm.unprotect_memory(fault.page_address, PAGE_SIZE as u32).map_err(bad)?;
					continue;
				}
				if !valid.contains(&page) {
					break "page fault";
				}
				read.insert(page);
				ever_read.insert(page);
				vm.zero_memory_with_memory_protection(fault.page_address, PAGE_SIZE as u32, MemoryProtection::ReadWrite)
					.map_err(bad)?;
				if let Some(data) = contents.get(&page) {
					vm.write_memory(fault.page_address, data).map_err(bad)?;
				}
				vm.protect_memory(fault.page_address, PAGE_SIZE as u32).map_err(bad)?;
			},
			InterruptKind::NotEnoughGas => {
				// A pause: keep what this window wrote, unmap everything, and go on.
				windows += 1;
				used += window;
				report(windows, &read, &written, &carried, &last_write);
				carried.extend(written.iter().copied());
				for &page in &written {
					last_write.insert(page, windows);
				}
				for &page in &written {
					contents.insert(page, vm.read_memory((page * PAGE_SIZE) as u32, PAGE_SIZE as u32).map_err(bad)?);
				}
				for &page in &read {
					vm.free_pages((page * PAGE_SIZE) as u32, PAGE_SIZE as u32).map_err(bad)?;
				}
				read.clear();
				written.clear();
				vm.set_gas(window as i64);
			},
			InterruptKind::Ecalli(GROW_HEAP) => {
				if let Some((first, count)) = heap.grow(vm.reg(Reg::A0)) {
					valid.extend(first..first + count);
				}
				vm.set_reg(Reg::A0, heap.end_page);
			},
			InterruptKind::Finished => break if vm.reg(Reg::A0) == 1 { "true" } else { "false" },
			InterruptKind::Trap => break "panic",
			InterruptKind::Ecalli(_) => break "host call",
			InterruptKind::Step => continue,
		}
	};
	used += window - vm.gas().max(0) as u64;
	report(windows + 1, &read, &written, &carried, &last_write);
	println!(
		"{outcome} after {used} gas in {} windows; {} distinct pages read, {} written ({} MiB)",
		windows + 1,
		ever_read.len(),
		ever_written.len(),
		ever_written.len() * 4 / 1024
	);
	Ok(())
}

/// The one host call a check may make: grow its heap.
const GROW_HEAP: u32 = 1;
/// What `grow_heap` costs a service in PolkaJam v0.1.29 (`jam_types::gas_costs`).
const GROW_HEAP_BASE: u64 = 275;
const GROW_HEAP_LINEAR: u64 = 121;
/// The service ids `create-service` gives witness and the test token service.
const SERVICE: u32 = 1;
const TOKEN_SERVICE: u32 = 2;

#[derive(Default, Encode, Decode)]
struct State {
	slot: u32,
	service: bool,
	storage: BTreeMap<Vec<u8>, Vec<u8>>,
	token_service: bool,
	token_storage: BTreeMap<Vec<u8>, Vec<u8>>,
}

fn write(storage: &mut BTreeMap<Vec<u8>, Vec<u8>>, writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>) {
	for (key, value) in writes {
		match value {
			Some(v) => storage.insert(key, v),
			None => storage.remove(&key),
		};
	}
}

/// The test token service's storage, as mock_token reads it.
struct TokenState<'a>(&'a BTreeMap<Vec<u8>, Vec<u8>>);

impl mock_token::State for TokenState<'_> {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		self.0.get(key).cloned()
	}
}

struct Sim {
	dir: PathBuf,
	state: State,
	/// The extrinsics of the item being refined.
	extrinsics: Vec<Vec<u8>>,
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	if s.len() % 2 != 0 {
		return None;
	}
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

impl Sim {
	fn open() -> Sim {
		let dir = PathBuf::from(std::env::var("WITNESS_SIM_DIR").unwrap_or_else(|_| ".witness-sim".into()));
		let state = std::fs::read(dir.join("state"))
			.ok()
			.and_then(|b| State::decode(&mut &b[..]).ok())
			.unwrap_or_default();
		Sim { dir, state, extrinsics: Vec::new() }
	}

	fn save(&self) {
		std::fs::create_dir_all(&self.dir).unwrap();
		std::fs::write(self.dir.join("state"), self.state.encode()).unwrap();
	}

	fn log(&self, line: &str) {
		let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("log")).unwrap();
		writeln!(f, "sim: slot {} INFO witness  {line}", self.state.slot).unwrap();
	}

	fn item(&mut self, payload: &[u8], extrinsics: Vec<Vec<u8>>) {
		self.state.slot += 1;
		self.extrinsics = extrinsics;
		let verified = match Op::decode(&mut &payload[..]) {
			Ok(op) => witness_rules::refine(&*self, SERVICE, op),
			Err(_) => Verified::Rejected(Rejection::BadPayload),
		};
		self.log(&format!("refine: {verified:?}"));
		if let Verified::Rejected(_) = verified {
			return;
		}
		match witness_rules::accumulate(&*self, verified, self.state.slot) {
			Ok(effects) => self.apply(effects),
			Err(reason) => self.log(&format!("not applied: {reason}")),
		}
	}

	fn apply(&mut self, effects: witness_rules::Effects) {
		write(&mut self.state.storage, effects.writes);
		if let Some((hash, len)) = effects.solicit {
			self.log(&format!("solicited {} ({len} bytes)", hex(&hash)));
		}
		if let Some(hash) = effects.upgrade {
			self.log(&format!("upgraded to code {}", hex(&hash)));
		}
		for (destination, memo) in effects.transfers {
			self.log(&format!("transfer to service {destination}"));
			if destination == TOKEN_SERVICE && self.state.token_service {
				match mock_token::on_transfer(&TokenState(&self.state.token_storage), SERVICE, &memo) {
					Ok(fx) => write(&mut self.state.token_storage, fx.writes),
					Err(reason) => self.log(&format!("mock-token: not applied: {reason}")),
				}
			}
		}
	}

	/// An item for the test token service.
	fn token_item(&mut self, payload: &[u8]) {
		self.state.slot += 1;
		let applied = mock_token::TokenOp::decode(&mut &payload[..])
			.map_err(|_| "not an op")
			.and_then(|op| mock_token::apply(&TokenState(&self.state.token_storage), op));
		let fx = match applied {
			Ok(fx) => fx,
			Err(reason) => return self.log(&format!("mock-token: not applied: {reason}")),
		};
		write(&mut self.state.token_storage, fx.writes);
		for (destination, memo) in fx.transfers {
			if destination != SERVICE {
				continue;
			}
			match witness_rules::on_transfer(&*self, TOKEN_SERVICE, 0, &memo) {
				Ok(effects) => {
					self.log(&format!("deposit from service {TOKEN_SERVICE}"));
					self.apply(effects);
				},
				Err(reason) => {
					self.log(&format!("transfer from service {TOKEN_SERVICE}: {reason}"));
					if let Some(refund) = witness_rules::refund(&memo) {
						self.log(&format!("refunded the deposit to service {TOKEN_SERVICE}"));
						self.apply(witness_rules::Effects { transfers: vec![(TOKEN_SERVICE, refund)], ..Default::default() });
					}
				},
			}
		}
	}
}

impl witness_rules::State for Sim {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		self.state.storage.get(key).cloned()
	}
}

impl witness_rules::RefineEnv for Sim {
	fn extrinsic(&self, index: usize) -> Option<Vec<u8>> {
		self.extrinsics.get(index).cloned()
	}

	fn extrinsic_hash(&self, index: usize) -> Option<witness_types::Hash> {
		self.extrinsics.get(index).map(|x| witness_types::blake2b256(x))
	}

	fn run_check(&self, blob: &[u8], args: &[u8], gas: Gas) -> Result<(), Rejection> {
		let (result, used) = run_check(blob, args, gas)?;
		self.log(&format!("check used {used} gas of {gas}"));
		result
	}
}

/// Run check `blob` on `args` with at most `gas`, as the service's inner PVM does (see
/// `service/src/check_vm.rs`). Returns the outcome and the gas used.
fn run_check(blob: &[u8], args: &[u8], gas: Gas) -> Result<(Result<(), Rejection>, Gas), Rejection> {
	let bad = |_| Rejection::BadCheckBlob;
	let program = StandardProgram::parse_jam_blob(blob).ok_or(Rejection::BadCheckBlob)?;
	let layout = initialize(&program, args).ok_or(Rejection::BadCheckBlob)?;
	if layout.total_pages() > MAX_CHECK_PAGES as u64 {
		return Err(Rejection::BadCheckBlob);
	}

	let mut config = Config::from_env().map_err(|_| Rejection::BadCheckBlob)?;
	config.set_allow_dynamic_paging(true);
	if config.default_cost_model().is_none() {
		// Gives the same gas as PolkaJam v0.1.29's inner PVM, measured on the sample checks.
		config.set_default_cost_model(Some(CostModelKind::Full(CacheModel::L2Hit)));
	}
	let engine = Engine::new(&config).map_err(|_| Rejection::BadCheckBlob)?;
	let mut module_config = ModuleConfig::new();
	module_config.set_page_size(PAGE_SIZE as u32);
	module_config.set_gas_metering(Some(GasMeteringKind::Sync));
	module_config.set_dynamic_paging(true);
	let mut parts = ProgramParts::empty(InstructionSetKind::JamV1);
	parts.code_and_jump_table = ArcBytes::from(layout.code.to_vec());
	let program_blob = ProgramBlob::from_parts(parts).map_err(|_| Rejection::BadCheckBlob)?;
	let module = Module::from_blob(&engine, &module_config, program_blob).map_err(|_| Rejection::BadCheckBlob)?;
	let mut vm = module.instantiate().map_err(|_| Rejection::BadCheckBlob)?;

	let addr = |page: u64| u32::try_from(page * PAGE_SIZE).map_err(|_| Rejection::BadCheckBlob);
	for region in &layout.regions {
		let (start, len) = (addr(region.first_page)?, addr(region.pages)?);
		vm.zero_memory_with_memory_protection(start, len, MemoryProtection::ReadWrite).map_err(bad)?;
		vm.write_memory(start, region.data).map_err(bad)?;
		if region.access == Access::ReadOnly {
			vm.protect_memory(start, len).map_err(bad)?;
		}
	}
	for (reg, value) in Reg::ALL.into_iter().zip(layout.registers) {
		vm.set_reg(reg, value);
	}
	vm.set_next_program_counter(ProgramCounter(0));
	let limit = i64::try_from(gas).map_err(|_| Rejection::CheckGasTooHigh)?;
	vm.set_gas(limit);

	let mut heap = Heap::new(&layout, MAX_CHECK_PAGES as u64);
	let failure = loop {
		match vm.run().map_err(|_| Rejection::BadCheckBlob)? {
			InterruptKind::Finished if vm.reg(Reg::A0) == 1 => {
				return Ok((Ok(()), (limit - vm.gas().max(0)) as Gas));
			},
			InterruptKind::Finished => break CheckFailure::False,
			InterruptKind::Trap => break CheckFailure::Panic,
			InterruptKind::NotEnoughGas => break CheckFailure::OutOfGas,
			InterruptKind::Segfault(_) => break CheckFailure::PageFault,
			InterruptKind::Ecalli(GROW_HEAP) => {
				if let Some((first, count)) = heap.grow(vm.reg(Reg::A0)) {
					let left = vm.gas() - (GROW_HEAP_BASE + GROW_HEAP_LINEAR * count) as i64;
					if left < 0 {
						vm.set_gas(0);
						break CheckFailure::OutOfGas;
					}
					vm.set_gas(left);
					if count > 0 {
						vm.zero_memory_with_memory_protection(addr(first)?, addr(count)?, MemoryProtection::ReadWrite)
							.map_err(bad)?;
					}
				}
				vm.set_reg(Reg::A0, heap.end_page);
			},
			InterruptKind::Ecalli(_) => break CheckFailure::HostCall,
			InterruptKind::Step => continue,
		}
	};
	Ok((Err(Rejection::CheckFailed(failure)), (limit - vm.gas().max(0)) as Gas))
}

fn usage() -> ExitCode {
	eprintln!(
		"usage: witness-sim (create-service BLOB BALANCE | list | item SERVICE PAYLOAD [EXTRINSIC...] \
		 | inspect slot | inspect storage --raw SERVICE KEY | inspect final service SERVICE)"
	);
	ExitCode::from(2)
}

fn main() -> ExitCode {
	let args: Vec<String> = std::env::args().skip(1).collect();
	let args: Vec<&str> = args.iter().map(String::as_str).collect();
	let mut sim = Sim::open();
	let fail = |msg: &str| {
		eprintln!("{msg}");
		ExitCode::FAILURE
	};
	match args[..] {
		["create-service", blob, _balance, ..] => {
			let is_token = std::fs::read(blob).is_ok_and(|b| b.windows(10).any(|w| w == b"mock-token"));
			if is_token {
				sim.state.token_service = true;
			} else {
				let _ = std::fs::remove_dir_all(&sim.dir);
				sim.state = State { service: true, ..State::default() };
			}
		},
		["list"] => {
			println!("00000000\tjam-bootstrap-service\tsim");
			if sim.state.service {
				println!("{SERVICE:08x}\twitness-service\tsim");
			}
			if sim.state.token_service {
				println!("{TOKEN_SERVICE:08x}\tmock-token-service\tsim");
			}
			return ExitCode::SUCCESS;
		},
		["item", service, payload, ref files @ ..] => {
			let payload = match payload.strip_prefix('@') {
				Some(file) => std::fs::read_to_string(file).unwrap_or_default(),
				None => payload.to_string(),
			};
			let Some(payload) = from_hex(payload.trim()) else { return fail("payload is not hex") };
			let Ok(extrinsics) = files.iter().map(std::fs::read).collect::<Result<Vec<_>, _>>() else {
				return fail("cannot read an extrinsic");
			};
			if service.parse() == Ok(TOKEN_SERVICE) {
				sim.token_item(&payload);
			} else {
				sim.item(&payload, extrinsics);
			}
			println!("Item submitted at slot {}", sim.state.slot);
		},
		["provide", _service, file] => {
			let Ok(data) = std::fs::read(file) else { return fail("cannot read the preimage") };
			sim.log(&format!("provided {}", hex(&witness_types::blake2b256(&data))));
		},
		["inspect", "slot"] => {
			sim.state.slot += 1;
			println!("{}", sim.state.slot);
		},
		["inspect", "storage", "--raw", service, key] => {
			let storage = if service.parse() == Ok(TOKEN_SERVICE) { &sim.state.token_storage } else { &sim.state.storage };
			let value = from_hex(key).and_then(|k| storage.get(&k).cloned());
			let Some(value) = value else { return fail("no such key") };
			println!("0x{}", hex(&value));
			return ExitCode::SUCCESS;
		},
		["check", blob, args, gas] => {
			let (Ok(blob), Ok(args), Ok(gas)) = (std::fs::read(blob), std::fs::read(args), gas.parse::<Gas>()) else {
				return fail("check BLOB ARGS GAS: cannot read BLOB or ARGS, or GAS is not a number");
			};
			return match run_check(&blob, &args, gas) {
				Ok((result, used)) => {
					println!("{result:?}: used {used} gas of {gas}");
					ExitCode::SUCCESS
				},
				Err(rejection) => fail(&format!("{rejection:?}")),
			};
		},
		["pages", blob, args, window] => {
			let (Ok(blob), Ok(args), Ok(window)) = (std::fs::read(blob), std::fs::read(args), window.parse::<Gas>()) else {
				return fail("pages BLOB ARGS WINDOW: cannot read BLOB or ARGS, or WINDOW is not a number");
			};
			return match profile_pages(&blob, &args, window) {
				Ok(()) => ExitCode::SUCCESS,
				Err(rejection) => fail(&format!("{rejection:?}")),
			};
		},
		["inspect", "final", "service", _service] => {
			return if sim.state.service { ExitCode::SUCCESS } else { fail("no such service") };
		},
		_ => return usage(),
	}
	sim.save();
	ExitCode::SUCCESS
}
