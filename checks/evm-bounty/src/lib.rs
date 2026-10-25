//! Witness check for settled bug bounties: a report earns the reward if replaying its transactions
//! against an Ethereum state the bounty commits to breaks the bounty's invariant.
//!
//! - **Params** ([`Params`], RLP): the state root of block N, the environment of the block the
//!   transactions run in (N + 1, say), the hard fork, and the invariant: EVM runtime code that
//!   [`INVARIANT`] runs with empty calldata, returning one word, nonzero while the invariant holds.
//! - **Witness** ([`Report`], RLP): every account and storage slot the replay reads, each with
//!   its Merkle-Patricia proof against the state root (or its absence proven), the code of each
//!   account, and the transactions.
//!
//! The check verifies every proof, runs the invariant (it must hold), executes the transactions
//! in revm, and runs the invariant again: the report wins if it now returns zero. Reading
//! anything the report didn't prove fails the check, so the replay sees only proven state. This
//! is the stateless execution zkEVM provers do, without the zero knowledge.
//!
//! Transactions aren't signed, and they come only from [`HUNTERS`] fresh accounts, [`hunter`]
//! addresses derived from the next block's `prevrandao`, each starting with [`Params::capital`]
//! wei and nothing else. Nobody could know those addresses before block N's successor, so no
//! contract in block N's state can single them out: a report shows that *anyone* could break the
//! invariant, which is what a bounty pays for, and can't act as a protocol's owner or admin. A
//! hunter gets tokens the way an attacker would, by trading or borrowing them on chain. Gas costs
//! nothing (gas price zero, base fee off) and nonces aren't checked. `BLOCKHASH` is not supported
//! in this version: it fails the check.
//!
//! [`Report::stop_after`] lets a measurement stop the check after a phase. Stopping early always
//! returns false, so it can't make a report win; it only shows what each phase costs in gas.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use alloy_trie::{EMPTY_ROOT_HASH, Nibbles, proof::verify_proof};
use revm::{
	Context, Database, ExecuteEvm, MainBuilder, MainContext,
	bytecode::Bytecode,
	context::{
		TxEnv,
		result::{ExecutionResult, Output},
	},
	primitives::{Address, B256, Bytes, KECCAK_EMPTY, TxKind, U256, address, hardfork::SpecId, keccak256},
	state::AccountInfo,
};

/// Where the invariant's code runs. A report can't prove an account here.
pub const INVARIANT: Address = address!("00000000000000000000000000000000696e7631");

/// Who calls the invariant: an empty account, since EIP-3607 forbids sending from one with code.
pub const INVARIANT_CALLER: Address = address!("00000000000000000000000000000000696e7630");

/// How many hunter accounts a report may send from.
pub const HUNTERS: u8 = 4;

/// Hunter `i`'s address, for a block whose `prevrandao` is given.
pub fn hunter(prevrandao: B256, i: u8) -> Address {
	let mut preimage = [0u8; 58];
	preimage[..25].copy_from_slice(b"witness evm-bounty hunter");
	preimage[25..57].copy_from_slice(prevrandao.as_slice());
	preimage[57] = i;
	Address::from_word(keccak256(preimage))
}

/// Gas the invariant gets each time it runs: the most a transaction may have since Osaka (EIP-7825).
pub const INVARIANT_GAS: u64 = 1 << 24;

/// The bounty's terms.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Params {
	/// The state root the report's proofs are against: block N's.
	pub state_root: B256,
	/// `SpecId` as a byte: the hard fork the transactions run under.
	pub spec: u8,
	pub chain_id: u64,
	pub number: u64,
	pub timestamp: u64,
	pub gas_limit: u64,
	pub basefee: u64,
	pub coinbase: Address,
	pub prevrandao: B256,
	/// Wei each hunter starts with.
	pub capital: U256,
	/// Runtime code, run at [`INVARIANT`] with empty calldata before and after the transactions.
	pub invariant: Bytes,
}

/// An account as the state trie stores it.
#[derive(Clone, Debug, Default, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct TrieAccount {
	pub nonce: u64,
	pub balance: U256,
	pub storage_root: B256,
	pub code_hash: B256,
}

impl TrieAccount {
	/// What an account that doesn't exist looks like.
	pub fn empty() -> Self {
		Self { nonce: 0, balance: U256::ZERO, storage_root: EMPTY_ROOT_HASH, code_hash: KECCAK_EMPTY }
	}
}

/// A storage slot and its proof against the account's storage root. Zero means proven absent.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Slot {
	pub key: B256,
	pub value: U256,
	pub proof: Vec<Bytes>,
}

/// An account, its proof against the state root, its code, and the slots the replay reads.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct AccountWitness {
	pub address: Address,
	/// False if the proof shows there is no such account; `account` is then [`TrieAccount::empty`].
	pub exists: bool,
	pub account: TrieAccount,
	pub proof: Vec<Bytes>,
	pub code: Bytes,
	pub slots: Vec<Slot>,
}

/// A transaction to replay, unsigned, from hunter number `hunter` (less than [`HUNTERS`]).
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Tx {
	pub hunter: u8,
	/// Deploy `data` as init code instead of calling `to`.
	pub create: bool,
	pub to: Address,
	pub value: U256,
	pub data: Bytes,
	pub gas_limit: u64,
}

/// A researcher's report.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Report {
	pub accounts: Vec<AccountWitness>,
	pub txs: Vec<Tx>,
	/// 0 to run the whole check; otherwise return false after phase `stop_after` (see [`Phase`]).
	pub stop_after: u8,
}

/// The check's phases, in order, for [`Report::stop_after`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Phase {
	/// Decode params and report.
	Decode = 1,
	/// Verify every account and slot proof.
	Proofs = 2,
	/// Run the invariant on the proven state; it must hold.
	InvariantBefore = 3,
	/// Execute the transactions.
	Transactions = 4,
}

/// How a check ended, for host tools; the check itself only says whether the report won.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
	/// The invariant held, then the transactions broke it.
	Violated,
	/// The invariant still holds after the transactions.
	Holds,
	/// Stopped after this phase, as the report asked.
	Stopped(Phase),
	/// Params or report don't decode, prove an account the check makes up (the invariant's, its
	/// caller's or a hunter's), repeat an account or slot, or send from no hunter.
	Malformed,
	/// A proof doesn't verify, or code doesn't match its hash.
	BadProof,
	/// The invariant didn't hold on the proven state, or didn't return one word.
	BadInvariant,
	/// A transaction was invalid or read state the report didn't prove.
	TxFailed,
}

/// Replay read something the report didn't prove (or `BLOCKHASH`).
#[derive(Debug)]
pub struct Unproven;

impl core::fmt::Display for Unproven {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		f.write_str("state the report didn't prove")
	}
}

impl core::error::Error for Unproven {}
impl revm::database_interface::DBErrorMarker for Unproven {}

/// Proven state: the only thing the replay can read.
#[derive(Default)]
struct ProvenDb {
	/// `None` for an account proven absent.
	accounts: BTreeMap<Address, Option<AccountInfo>>,
	storage: BTreeMap<(Address, U256), U256>,
	/// The accounts the check makes up, whose storage is all zero.
	made_up: Vec<Address>,
}

impl Database for ProvenDb {
	type Error = Unproven;

	fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Unproven> {
		self.accounts.get(&address).cloned().ok_or(Unproven)
	}

	fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Unproven> {
		// Every proven account carries its code, so revm only asks for code it hasn't got: none.
		if code_hash == KECCAK_EMPTY { Ok(Bytecode::default()) } else { Err(Unproven) }
	}

	fn storage(&mut self, address: Address, index: U256) -> Result<U256, Unproven> {
		match self.storage.get(&(address, index)) {
			Some(value) => Ok(*value),
			None if self.made_up.contains(&address) => Ok(U256::ZERO),
			None => Err(Unproven),
		}
	}

	fn block_hash(&mut self, _number: u64) -> Result<B256, Unproven> {
		Err(Unproven)
	}
}

fn key(hashed: B256) -> Nibbles {
	Nibbles::unpack(hashed)
}

/// Verify `witness` against `state_root` and add what it proves to `db`.
fn prove(db: &mut ProvenDb, state_root: B256, witness: &AccountWitness) -> Result<(), Outcome> {
	let AccountWitness { address, exists, account, proof, code, slots } = witness;
	if db.accounts.contains_key(address) {
		return Err(Outcome::Malformed);
	}
	if !exists && *account != TrieAccount::empty() {
		return Err(Outcome::Malformed);
	}
	let leaf = exists.then(|| alloy_rlp::encode(account));
	verify_proof(state_root, key(keccak256(address)), leaf, proof).map_err(|_| Outcome::BadProof)?;
	if keccak256(code) != account.code_hash {
		return Err(Outcome::BadProof);
	}
	for Slot { key: slot, value, proof } in slots {
		let leaf = (!value.is_zero()).then(|| alloy_rlp::encode(value));
		verify_proof(account.storage_root, key(keccak256(slot)), leaf, proof).map_err(|_| Outcome::BadProof)?;
		if db.storage.insert((*address, (*slot).into()), *value).is_some() {
			return Err(Outcome::Malformed);
		}
	}
	let info = exists.then(|| AccountInfo {
		balance: account.balance,
		nonce: account.nonce,
		code_hash: account.code_hash,
		account_id: None,
		code: Some(Bytecode::new_raw(code.clone())),
	});
	db.accounts.insert(*address, info);
	Ok(())
}

fn invariant_call() -> TxEnv {
	TxEnv {
		caller: INVARIANT_CALLER,
		kind: TxKind::Call(INVARIANT),
		gas_limit: INVARIANT_GAS,
		..TxEnv::default()
	}
}

/// The invariant's answer: `Some(true)` if it holds, `Some(false)` if broken, `None` if it didn't
/// return exactly one word.
fn holds(result: &ExecutionResult) -> Option<bool> {
	match result {
		ExecutionResult::Success { output: Output::Call(word), .. } if word.len() == 32 =>
			Some(word.iter().any(|&b| b != 0)),
		_ => None,
	}
}

/// Run the whole check on encoded params and report.
pub fn run(params: &[u8], report: &[u8]) -> Outcome {
	run_measured(params, report).0
}

/// [`run`], also returning the EVM gas the report's transactions used, for host tools.
pub fn run_measured(params: &[u8], report: &[u8]) -> (Outcome, u64) {
	let mut evm_gas = 0;
	match run_phases(params, report, &mut evm_gas) {
		Ok(outcome) | Err(outcome) => (outcome, evm_gas),
	}
}

fn run_phases(mut params: &[u8], mut report: &[u8], evm_gas: &mut u64) -> Result<Outcome, Outcome> {
	let params = Params::decode(&mut params).map_err(|_| Outcome::Malformed)?;
	let report = Report::decode(&mut report).map_err(|_| Outcome::Malformed)?;
	stop(report.stop_after, Phase::Decode)?;

	// Made-up accounts go in first, so a report that proves one is malformed.
	let mut db = ProvenDb::default();
	for (address, info) in made_up(&params) {
		db.made_up.push(address);
		db.accounts.insert(address, Some(info));
	}
	for witness in &report.accounts {
		prove(&mut db, params.state_root, witness)?;
	}
	stop(report.stop_after, Phase::Proofs)?;

	replay(&params, db, report.txs, report.stop_after, evm_gas)
}

fn stop(stop_after: u8, phase: Phase) -> Result<(), Outcome> {
	if stop_after == phase as u8 { Err(Outcome::Stopped(phase)) } else { Ok(()) }
}

/// The accounts the check makes up rather than proves, all with zero storage: the invariant's,
/// holding its code, its caller, and the hunters, each holding [`Params::capital`].
pub fn made_up(params: &Params) -> Vec<(Address, AccountInfo)> {
	let code = Bytecode::new_raw(params.invariant.clone());
	let invariant = AccountInfo { balance: U256::ZERO, nonce: 1, code_hash: code.hash_slow(), account_id: None, code: Some(code) };
	let mut accounts = alloc::vec![(INVARIANT, invariant), (INVARIANT_CALLER, AccountInfo::default())];
	for i in 0..HUNTERS {
		accounts.push((hunter(params.prevrandao, i), AccountInfo { balance: params.capital, ..AccountInfo::default() }));
	}
	accounts
}

/// Run the invariant, the transactions and the invariant again on `db`, from phase
/// [`Phase::Proofs`] on, adding the transactions' EVM gas to `evm_gas`. The check runs it on proven
/// state; host tools run it on whatever state they have, to see what a report has to prove. `db`
/// must answer for the accounts [`made_up`] makes up as it says.
pub fn replay<DB: Database>(
	params: &Params,
	db: DB,
	txs: Vec<Tx>,
	stop_after: u8,
	evm_gas: &mut u64,
) -> Result<Outcome, Outcome> {
	let spec = SpecId::try_from_u8(params.spec).ok_or(Outcome::Malformed)?;
	let mut evm = Context::mainnet()
		.with_db(db)
		.modify_cfg_chained(|cfg| {
			cfg.set_spec_and_mainnet_gas_params(spec);
			cfg.chain_id = params.chain_id;
			cfg.disable_nonce_check = true;
			cfg.disable_base_fee = true;
		})
		.modify_block_chained(|block| {
			block.number = U256::from(params.number);
			block.timestamp = U256::from(params.timestamp);
			block.gas_limit = params.gas_limit;
			block.basefee = params.basefee;
			block.beneficiary = params.coinbase;
			block.prevrandao = Some(params.prevrandao);
		})
		.build_mainnet();

	// `transact` drops the journal after the invariant runs, so it can't change the state the
	// transactions start from.
	let before = evm.transact(invariant_call()).map_err(|_| Outcome::BadInvariant)?;
	if holds(&before.result) != Some(true) {
		return Err(Outcome::BadInvariant);
	}
	stop(stop_after, Phase::InvariantBefore)?;

	for tx in txs {
		if tx.hunter >= HUNTERS {
			return Err(Outcome::Malformed);
		}
		let kind = if tx.create { TxKind::Create } else { TxKind::Call(tx.to) };
		let env = TxEnv {
			caller: hunter(params.prevrandao, tx.hunter),
			kind,
			value: tx.value,
			data: tx.data,
			gas_limit: tx.gas_limit,
			chain_id: Some(params.chain_id),
			..TxEnv::default()
		};
		// A reverted transaction is fine; an invalid one, or one that read unproven state, isn't.
		// Each runs on the journal its predecessors left, as `transact_many` does.
		*evm_gas += evm.transact_one(env).map_err(|_| Outcome::TxFailed)?.tx_gas_used();
	}
	stop(stop_after, Phase::Transactions)?;

	let after = evm.transact_one(invariant_call()).map_err(|_| Outcome::BadInvariant)?;
	match holds(&after) {
		Some(true) => Ok(Outcome::Holds),
		Some(false) => Ok(Outcome::Violated),
		None => Err(Outcome::BadInvariant),
	}
}

fn check(params: &[u8], report: &[u8]) -> bool {
	run(params, report) == Outcome::Violated
}

witness_check::declare_check!(check);

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
polkavm_derive::min_stack_size!(1024 * 1024);
