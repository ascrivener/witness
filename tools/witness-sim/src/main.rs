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
//!     witness-sim items SERVICE LIST                     refine many witness ops at once, in
//!                                                        parallel, then accumulate them in
//!                                                        order: LIST has a line an op, its
//!                                                        payload file (hex) then its extrinsic
//!                                                        files; prints `item N: applied` or why
//!                                                        not, a line an op
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
//! `items` is how a block of many packages lands: refine sees the state before it (witness's refine
//! reads no state, only its item), so items refine independently, on as many threads as the
//! machine has (`WITNESS_SIM_THREADS` overrides), and accumulate applies them in order.
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

/// One item's refine environment, apart from the others: its extrinsics, and its log lines.
struct ItemEnv {
	extrinsics: Vec<Vec<u8>>,
	log: std::sync::Mutex<Vec<String>>,
}

impl witness_rules::RefineEnv for ItemEnv {
	fn extrinsic(&self, index: usize) -> Option<Vec<u8>> {
		self.extrinsics.get(index).cloned()
	}

	fn extrinsic_hash(&self, index: usize) -> Option<witness_types::Hash> {
		self.extrinsics.get(index).map(|x| witness_types::blake2b256(x))
	}

	fn run_check(&self, blob: &[u8], args: &[u8], gas: Gas) -> Result<(), Rejection> {
		let (result, used) = run_check(blob, args, gas)?;
		self.log.lock().unwrap().push(format!("check used {used} gas of {gas}"));
		result
	}
}

impl Sim {
	/// Refine `items` (payloads and extrinsics) in parallel, then accumulate them in order.
	/// Returns, for each, whether it was applied, or why not.
	fn items(&mut self, items: Vec<(Vec<u8>, Vec<Vec<u8>>)>) -> Vec<Result<(), String>> {
		let threads = std::env::var("WITNESS_SIM_THREADS")
			.ok()
			.and_then(|t| t.parse().ok())
			.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
		let envs: Vec<ItemEnv> = items.iter().map(|(_, x)| ItemEnv { extrinsics: x.clone(), log: Default::default() }).collect();
		let next = std::sync::atomic::AtomicUsize::new(0);
		let verified: Vec<std::sync::Mutex<Option<Verified>>> = items.iter().map(|_| Default::default()).collect();
		std::thread::scope(|scope| {
			for _ in 0..threads.min(items.len()).max(1) {
				scope.spawn(|| loop {
					let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
					let Some((payload, _)) = items.get(i) else { break };
					let v = match Op::decode(&mut &payload[..]) {
						Ok(op) => witness_rules::refine(&envs[i], SERVICE, op),
						Err(_) => Verified::Rejected(Rejection::BadPayload),
					};
					*verified[i].lock().unwrap() = Some(v);
				});
			}
		});
		let mut out = Vec::new();
		for (env, v) in envs.into_iter().zip(verified) {
			self.state.slot += 1;
			let verified = v.into_inner().unwrap().unwrap();
			for line in env.log.into_inner().unwrap() {
				self.log(&line);
			}
			self.log(&format!("refine: {verified:?}"));
			if let Verified::Rejected(r) = verified {
				out.push(Err(format!("rejected: {r:?}")));
				continue;
			}
			match witness_rules::accumulate(&*self, verified, self.state.slot) {
				Ok(effects) => {
					self.apply(effects);
					out.push(Ok(()));
				},
				Err(reason) => {
					self.log(&format!("not applied: {reason}"));
					out.push(Err(format!("not applied: {reason}")));
				},
			}
		}
		out
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
		["items", _service, list] => {
			let Ok(list) = std::fs::read_to_string(list) else { return fail("cannot read the list") };
			let mut items = Vec::new();
			for line in list.lines().filter(|l| !l.trim().is_empty()) {
				let mut files = line.split_whitespace();
				let payload = files.next().and_then(|f| std::fs::read_to_string(f).ok()).and_then(|h| from_hex(h.trim()));
				let Some(payload) = payload else { return fail("cannot read a payload") };
				let Ok(extrinsics) = files.map(std::fs::read).collect::<Result<Vec<_>, _>>() else {
					return fail("cannot read an extrinsic");
				};
				items.push((payload, extrinsics));
			}
			for (n, result) in sim.items(items).into_iter().enumerate() {
				match result {
					Ok(()) => println!("item {n}: applied"),
					Err(why) => println!("item {n}: {why}"),
				}
			}
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
		["inspect", "final", "service", _service] => {
			return if sim.state.service { ExitCode::SUCCESS } else { fail("no such service") };
		},
		_ => return usage(),
	}
	sim.save();
	ExitCode::SUCCESS
}
