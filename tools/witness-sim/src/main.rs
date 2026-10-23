//! Runs witness ops natively, in place of a JAM testnet, for iterating in seconds instead of
//! minutes. It takes the subset of `jamt`'s commands the scripts use, so a script points `JAMT` at
//! it and runs unchanged:
//!
//!     witness-sim create-service SERVICE_BLOB BALANCE   start afresh, with the witness service
//!     witness-sim list                                   the services, as `jamt list` prints them
//!     witness-sim item SERVICE PAYLOAD [EXTRINSIC...]    refine and accumulate one op (hex, or
//!                                                        @FILE holding the hex), with its
//!                                                        extrinsics (files)
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

/// The one host call a check may make: grow its heap.
const GROW_HEAP: u32 = 1;
/// What `grow_heap` costs a service in PolkaJam v0.1.29 (`jam_types::gas_costs`).
const GROW_HEAP_BASE: u64 = 275;
const GROW_HEAP_LINEAR: u64 = 121;
/// The service id `create-service` gives.
const SERVICE: u32 = 1;

#[derive(Default, Encode, Decode)]
struct State {
	slot: u32,
	service: bool,
	storage: BTreeMap<Vec<u8>, Vec<u8>>,
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
			Ok(effects) => {
				for (key, value) in effects.writes {
					match value {
						Some(v) => self.state.storage.insert(key, v),
						None => self.state.storage.remove(&key),
					};
				}
			},
			Err(reason) => self.log(&format!("not applied: {reason}")),
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
		["create-service", _blob, _balance] => {
			let _ = std::fs::remove_dir_all(&sim.dir);
			sim.state = State { service: true, ..State::default() };
		},
		["list"] => {
			println!("00000000\tjam-bootstrap-service\tsim");
			if sim.state.service {
				println!("{SERVICE:08x}\twitness-service\tsim");
			}
			return ExitCode::SUCCESS;
		},
		["item", _service, payload, ref files @ ..] => {
			let payload = match payload.strip_prefix('@') {
				Some(file) => std::fs::read_to_string(file).unwrap_or_default(),
				None => payload.to_string(),
			};
			let Some(payload) = from_hex(payload.trim()) else { return fail("payload is not hex") };
			let Ok(extrinsics) = files.iter().map(std::fs::read).collect::<Result<Vec<_>, _>>() else {
				return fail("cannot read an extrinsic");
			};
			sim.item(&payload, extrinsics);
			println!("Item submitted at slot {}", sim.state.slot);
		},
		["inspect", "slot"] => {
			sim.state.slot += 1;
			println!("{}", sim.state.slot);
		},
		["inspect", "storage", "--raw", _service, key] => {
			let value = from_hex(key).and_then(|k| sim.state.storage.get(&k).cloned());
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
		["inspect", "final", "service", _service] => {
			return if sim.state.service { ExitCode::SUCCESS } else { fail("no such service") };
		},
		_ => return usage(),
	}
	sim.save();
	ExitCode::SUCCESS
}
