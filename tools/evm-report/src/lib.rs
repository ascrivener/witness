//! Test cases for the evm-bounty check, built from synthetic state.
//!
//! A [`World`] holds accounts with code and storage, written straight in: the toy contracts in
//! `contracts/Toys.sol` (their runtime code, as `*.hex`), and EOAs. To build a case, the tool
//! replays its transactions on the world with [`evm_bounty_check::replay`], the code the check
//! runs, over a database that records every account and slot the replay reads. Only those go in
//! the report, each with its proof, as a hunter would fetch them with `eth_getProof`.
//!
//! The tries are padded so proofs are as deep as mainnet's ([`Shape`]): every key the report
//! proves gets filler siblings at each level of its path, so its proof has full 16-way branch
//! nodes (about 530 bytes each) where mainnet's do. Fillers are never read; they only shape the
//! tries and their roots.

use alloy_rlp::Encodable;
use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, Nibbles, proof::ProofRetainer};
use evm_bounty_check::{
	AccountWitness, Params, Report, Slot, TrieAccount, Tx, Unproven, made_up, replay,
};
use revm::{
	Database,
	bytecode::Bytecode,
	primitives::{Address, B256, Bytes, KECCAK_EMPTY, U256, hardfork::SpecId, keccak256},
	state::AccountInfo,
};
use std::collections::{BTreeMap, BTreeSet};

pub use evm_bounty_check::Outcome;

/// How deep a trie's proofs are: `full` levels of 16-way branches, then `sparse` levels of
/// branches with [`SPARSE_SIBLINGS`] siblings, then the leaf.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
	pub full: usize,
	pub sparse: usize,
}

const SPARSE_SIBLINGS: usize = 2;

/// Mainnet's state trie (about 3×10⁸ accounts): account proofs are 9 nodes, 6 of them full
/// branches, about 4 KB, as `eth_getProof` returns them for recent blocks.
pub const MAINNET_ACCOUNTS: Shape = Shape { full: 6, sparse: 2 };
/// A big token's storage (WETH's, say): 7-node proofs.
pub const BIG_STORAGE: Shape = Shape { full: 4, sparse: 2 };
/// A contract with a handful of slots: a branch, then the leaf.
pub const SMALL_STORAGE: Shape = Shape { full: 0, sparse: 1 };

#[derive(Clone, Debug)]
pub struct Account {
	pub nonce: u64,
	pub balance: U256,
	pub code: Bytes,
	pub storage: BTreeMap<U256, U256>,
	pub storage_shape: Shape,
}

impl Account {
	pub fn eoa(balance: U256) -> Self {
		Self { nonce: 1, balance, code: Bytes::new(), storage: BTreeMap::new(), storage_shape: SMALL_STORAGE }
	}

	pub fn contract(code: Bytes, storage_shape: Shape) -> Self {
		Self { nonce: 1, balance: U256::ZERO, code, storage: BTreeMap::new(), storage_shape }
	}
}

/// The state a case runs on.
#[derive(Clone, Debug, Default)]
pub struct World {
	pub accounts: BTreeMap<Address, Account>,
}

/// What a replay read.
#[derive(Debug, Default)]
pub struct Reads {
	pub accounts: BTreeSet<Address>,
	pub slots: BTreeMap<Address, BTreeSet<U256>>,
}

impl Reads {
	fn prove(&mut self, address: Address, slots: impl IntoIterator<Item = U256>) {
		self.accounts.insert(address);
		self.slots.entry(address).or_default().extend(slots);
	}
}

/// Reads the world, recording what it was asked for.
struct Recorder<'a> {
	world: &'a World,
	made_up: BTreeMap<Address, AccountInfo>,
	reads: Reads,
}

impl Database for Recorder<'_> {
	type Error = Unproven;

	fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Unproven> {
		if let Some(info) = self.made_up.get(&address) {
			return Ok(Some(info.clone()));
		}
		self.reads.accounts.insert(address);
		Ok(self.world.accounts.get(&address).map(|a| AccountInfo {
			balance: a.balance,
			nonce: a.nonce,
			code_hash: keccak256(&a.code),
			account_id: None,
			code: Some(Bytecode::new_raw(a.code.clone())),
		}))
	}

	fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Unproven> {
		if code_hash == KECCAK_EMPTY { Ok(Bytecode::default()) } else { Err(Unproven) }
	}

	fn storage(&mut self, address: Address, index: U256) -> Result<U256, Unproven> {
		if self.made_up.contains_key(&address) {
			return Ok(U256::ZERO);
		}
		self.reads.prove(address, [index]);
		Ok(self.world.accounts.get(&address).and_then(|a| a.storage.get(&index)).copied().unwrap_or_default())
	}

	fn block_hash(&mut self, _number: u64) -> Result<B256, Unproven> {
		Err(Unproven)
	}
}

/// splitmix64: fillers only need to be distinct and repeatable.
struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
		let mut z = self.0;
		z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
		z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
		z ^ (z >> 31)
	}

	fn word(&mut self) -> B256 {
		let mut w = [0u8; 32];
		for chunk in w.chunks_mut(8) {
			chunk.copy_from_slice(&self.next().to_le_bytes());
		}
		B256::from(w)
	}
}

/// A trie's leaves, by key path, as RLP.
type Leaves = BTreeMap<Nibbles, Vec<u8>>;

/// Add filler leaves around `key` so its proof has `shape`'s depth. `filler` makes a leaf value.
fn pad(leaves: &mut Leaves, key: &Nibbles, shape: Shape, rng: &mut Rng, filler: &dyn Fn(&mut Rng) -> Vec<u8>) {
	let path = key.to_vec();
	for depth in 0..shape.full + shape.sparse {
		let siblings = if depth < shape.full { 15 } else { SPARSE_SIBLINGS };
		for s in 1..=siblings {
			let mut nibbles: Vec<u8> = path[..depth].to_vec();
			nibbles.push((path[depth] + s as u8) % 16);
			let rest = Nibbles::unpack(rng.word());
			nibbles.extend_from_slice(&rest.to_vec()[depth + 1..]);
			leaves.entry(Nibbles::from_nibbles(&nibbles)).or_insert_with(|| filler(rng));
		}
	}
}

/// The trie's root, and a proof for each target (present or not).
fn trie(leaves: &Leaves, targets: &[Nibbles]) -> (B256, Vec<Vec<Bytes>>) {
	if leaves.is_empty() {
		return (EMPTY_ROOT_HASH, targets.iter().map(|_| Vec::new()).collect());
	}
	let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets.to_vec()));
	for (key, value) in leaves {
		builder.add_leaf(*key, value);
	}
	let root = builder.root();
	let nodes = builder.take_proof_nodes();
	let proofs = targets.iter().map(|t| nodes.matching_nodes_sorted(t).into_iter().map(|(_, node)| node).collect()).collect();
	(root, proofs)
}

fn rlp(value: &impl Encodable) -> Vec<u8> {
	alloy_rlp::encode(value)
}

/// Prove `reads` against the world's (padded) state: its root and the report's accounts.
pub fn prove(world: &World, reads: &Reads) -> (B256, Vec<AccountWitness>) {
	let mut rng = Rng(0x5eed);
	let mut state = Leaves::new();
	let mut witnesses = Vec::new();
	let addresses: BTreeSet<Address> = world.accounts.keys().chain(&reads.accounts).copied().collect();
	for address in addresses {
		let account = world.accounts.get(&address);
		let read = reads.accounts.contains(&address);
		let slots: Vec<U256> = reads.slots.get(&address).map(|s| s.iter().copied().collect()).unwrap_or_default();
		let (storage_root, slot_proofs) = match account {
			Some(a) => {
				let mut leaves: Leaves = a
					.storage
					.iter()
					.filter(|(_, v)| !v.is_zero())
					.map(|(k, v)| (Nibbles::unpack(keccak256(B256::from(*k))), rlp(v)))
					.collect();
				let targets: Vec<Nibbles> = slots.iter().map(|k| Nibbles::unpack(keccak256(B256::from(*k)))).collect();
				if read {
					for target in &targets {
						pad(&mut leaves, target, a.storage_shape, &mut rng, &|rng| rlp(&U256::from_be_bytes(rng.word().0)));
					}
				}
				trie(&leaves, &targets)
			},
			None => (EMPTY_ROOT_HASH, slots.iter().map(|_| Vec::new()).collect()),
		};
		let trie_account = match account {
			Some(a) => TrieAccount { nonce: a.nonce, balance: a.balance, storage_root, code_hash: keccak256(&a.code) },
			None => TrieAccount::empty(),
		};
		let key = Nibbles::unpack(keccak256(address));
		if account.is_some() {
			state.insert(key, rlp(&trie_account));
		}
		if read {
			pad(&mut state, &key, MAINNET_ACCOUNTS, &mut rng, &|rng| {
				rlp(&TrieAccount {
					nonce: rng.next() % 1000,
					balance: U256::from(rng.next()),
					storage_root: rng.word(),
					code_hash: rng.word(),
				})
			});
			let slots = slots
				.iter()
				.zip(slot_proofs)
				.map(|(k, proof)| Slot {
					key: B256::from(*k),
					value: account.and_then(|a| a.storage.get(k)).copied().unwrap_or_default(),
					proof,
				})
				.collect();
			witnesses.push(AccountWitness {
				address,
				exists: account.is_some(),
				account: trie_account,
				proof: Vec::new(),
				code: account.map(|a| a.code.clone()).unwrap_or_default(),
				slots,
			});
		}
	}
	let targets: Vec<Nibbles> = witnesses.iter().map(|w| Nibbles::unpack(keccak256(w.address))).collect();
	let (root, proofs) = trie(&state, &targets);
	for (witness, proof) in witnesses.iter_mut().zip(proofs) {
		witness.proof = proof;
	}
	(root, witnesses)
}

/// A test case: the bounty's params and a report, whole (`stop_after` 0).
pub struct Case {
	pub name: String,
	pub params: Params,
	pub report: Report,
	/// What the native replay found, before proving anything.
	pub expected: Outcome,
}

/// Build a case: replay `txs` on `world` to find what they read, add `extra` to prove, and prove it all.
pub fn case(name: &str, world: &World, invariant: Bytes, txs: Vec<Tx>, extra: Reads) -> Case {
	let (params, mut reports) = bounty(world, invariant, vec![txs], extra);
	let (report, expected) = reports.remove(0);
	Case { name: name.into(), params, report, expected }
}

/// A bounty on `world` and reports of each list of transactions, all against one state root:
/// replay each list to find what it reads, add `extra`, and prove all of that once. Each report
/// carries every proof, its own and the others', which the check allows. Also what each replay
/// found, before proving anything.
pub fn bounty(world: &World, invariant: Bytes, reports: Vec<Vec<Tx>>, extra: Reads) -> (Params, Vec<(Report, Outcome)>) {
	let mut params = Params {
		state_root: B256::ZERO,
		spec: SpecId::OSAKA as u8,
		chain_id: 1,
		number: 23_000_001,
		timestamp: 1_790_000_000,
		gas_limit: 60_000_000,
		basefee: 1_000_000_000,
		coinbase: COINBASE,
		prevrandao: PREVRANDAO,
		capital: U256::from(CAPITAL),
		invariant,
	};
	let mut recorder = Recorder { world, made_up: made_up(&params).into_iter().collect(), reads: extra };
	let expected: Vec<Outcome> = reports
		.iter()
		.map(|txs| match replay(&params, &mut recorder, txs.clone(), 0, &mut 0) {
			Ok(outcome) | Err(outcome) => outcome,
		})
		.collect();
	let (root, accounts) = prove(world, &recorder.reads);
	params.state_root = root;
	let reports = reports
		.into_iter()
		.zip(expected)
		.map(|(txs, expected)| (Report { accounts: accounts.clone(), txs, stop_after: 0 }, expected))
		.collect();
	(params, reports)
}

// Where things live.
pub const COINBASE: Address = at(0xc0ffee);
pub const PREVRANDAO: B256 = B256::repeat_byte(0x42);
/// What each hunter starts with: 10⁴ ETH.
pub const CAPITAL: u128 = 10_000 * ETHER;
pub const ROUTER: Address = at(0xc000);
pub const BURN: Address = at(0xd000);

pub const fn at(n: u64) -> Address {
	let mut bytes = [0u8; 20];
	let n = n.to_be_bytes();
	let mut i = 0;
	while i < 8 {
		bytes[12 + i] = n[i];
		i += 1;
	}
	Address::new(bytes)
}

/// Pair `i` (pair 0 is the one `PairInvariant` watches) trades token `i` for token `i + 1`.
pub const fn pair(i: u64) -> Address {
	at(0xa000 + i)
}

pub const fn token(i: u64) -> Address {
	at(0xb000 + i)
}

/// Each pair's reserves: `PairInvariant` has pair 0's product, 10⁴⁸, as its floor.
pub const RESERVE: u128 = 1_000_000 * ETHER;
pub const ETHER: u128 = 1_000_000_000_000_000_000;

fn code(hex: &str) -> Bytes {
	hex_bytes(hex.trim())
}

pub fn hex_bytes(hex: &str) -> Bytes {
	(0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect::<Vec<u8>>().into()
}

pub fn token_code() -> Bytes {
	code(include_str!("../contracts/Token.hex"))
}
pub fn pair_code() -> Bytes {
	code(include_str!("../contracts/Pair.hex"))
}
pub fn router_code() -> Bytes {
	code(include_str!("../contracts/Router.hex"))
}
pub fn burn_code() -> Bytes {
	code(include_str!("../contracts/Burn.hex"))
}
pub fn pair_invariant() -> Bytes {
	code(include_str!("../contracts/PairInvariant.hex"))
}
/// An invariant that always holds: returns 1.
pub fn always() -> Bytes {
	hex_bytes("600160005260206000f3")
}

/// Solidity's slot for `mapping(address => _)` at slot `base`, key `key`.
pub fn mapping_slot(key: Address, base: u64) -> U256 {
	let mut preimage = [0u8; 64];
	preimage[12..32].copy_from_slice(key.as_slice());
	preimage[56..64].copy_from_slice(&base.to_be_bytes());
	keccak256(preimage).into()
}

/// ABI calldata: the selector of `signature`, then `words`.
pub fn call(signature: &str, words: &[U256]) -> Bytes {
	let mut data = keccak256(signature.as_bytes())[..4].to_vec();
	for w in words {
		data.extend_from_slice(&w.to_be_bytes::<32>());
	}
	data.into()
}

pub fn word(address: Address) -> U256 {
	U256::from_be_slice(address.as_slice())
}

/// A call from hunter 0.
pub fn tx(to: Address, data: Bytes, gas_limit: u64) -> Tx {
	Tx { hunter: 0, create: false, to, value: U256::ZERO, data, gas_limit }
}

pub fn hunter() -> Address {
	evm_bounty_check::hunter(PREVRANDAO, 0)
}

/// Tokens 0..=n and pairs 0..n, each pair holding [`RESERVE`] of both its tokens, and the router
/// holding `float` of token 0. Big tokens' storage is mainnet-deep, the pairs' shallow.
pub fn pairs_world(n: u64, float: U256) -> World {
	let mut world = World::default();
	world.accounts.insert(COINBASE, Account::eoa(U256::from(ETHER)));
	world.accounts.insert(ROUTER, Account::contract(router_code(), SMALL_STORAGE));
	let reserve = U256::from(RESERVE);
	for i in 0..=n {
		let mut t = Account::contract(token_code(), BIG_STORAGE);
		if i < n {
			t.storage.insert(mapping_slot(pair(i), 0), reserve);
		}
		if i > 0 {
			t.storage.insert(mapping_slot(pair(i - 1), 0), reserve);
		}
		if i == 0 {
			t.storage.insert(mapping_slot(ROUTER, 0), float);
		}
		t.storage.insert(U256::from(2), reserve * U256::from(2) + float);
		t.balance = t.storage[&U256::from(2)];
		world.accounts.insert(token(i), t);
	}
	for i in 0..n {
		let mut p = Account::contract(pair_code(), SMALL_STORAGE);
		p.storage.insert(U256::ZERO, word(token(i)));
		p.storage.insert(U256::from(1), word(token(i + 1)));
		p.storage.insert(U256::from(2), reserve);
		p.storage.insert(U256::from(3), reserve);
		world.accounts.insert(pair(i), p);
	}
	world
}

/// Uniswap V2's amount out, for `amount_in` against equal reserves.
pub fn amount_out(amount_in: U256) -> U256 {
	let reserve = U256::from(RESERVE);
	let with_fee = amount_in * U256::from(997);
	with_fee * reserve / (reserve * U256::from(1000) + with_fee)
}

/// Wrap `amount` wei of ETH as token 0.
fn deposit(amount: U256) -> Tx {
	Tx { value: amount, ..tx(token(0), call("deposit()", &[]), 100_000) }
}

/// A swap on pair 0 the way a trader would: wrap ETH, pay it in, then take the fair amount out.
pub fn fair_swap_txs() -> Vec<Tx> {
	let amount = U256::from(1_000 * ETHER);
	vec![
		deposit(amount),
		tx(token(0), call("transfer(address,uint256)", &[word(pair(0)), amount]), 200_000),
		tx(pair(0), call("swap(uint256,uint256,address)", &[U256::ZERO, amount_out(amount), word(hunter())]), 300_000),
	]
}

/// The planted bug: pay 1 wei in, take 99.8% of the other reserve out. Pair 0's product drops.
pub fn exploit_txs() -> Vec<Tx> {
	let reserve = U256::from(RESERVE);
	vec![
		deposit(U256::from(1)),
		tx(token(0), call("transfer(address,uint256)", &[word(pair(0)), U256::from(1)]), 200_000),
		tx(pair(0), call("swap(uint256,uint256,address)", &[U256::ZERO, reserve - reserve / U256::from(500), word(hunter())]), 300_000),
	]
}

pub fn pair_swap() -> Case {
	case("pair-swap", &pairs_world(1, U256::ZERO), pair_invariant(), fair_swap_txs(), Reads::default())
}

pub fn pair_exploit() -> Case {
	case("pair-exploit", &pairs_world(1, U256::ZERO), pair_invariant(), exploit_txs(), Reads::default())
}

/// The demo's bounty on pair 0, and three reports against it: a fair swap (the invariant holds),
/// the exploit (it breaks), and the exploit on forged state, pair 0's reserves claimed tiny, which
/// no proof backs.
pub fn pair_bounty() -> (Params, [Report; 3]) {
	let (params, reports) = bounty(&pairs_world(1, U256::ZERO), pair_invariant(), vec![fair_swap_txs(), exploit_txs()], Reads::default());
	let [(fair, Outcome::Holds), (exploit, Outcome::Violated)] = <[_; 2]>::try_from(reports).unwrap() else {
		panic!("the replays didn't go as planned");
	};
	let mut forged = exploit.clone();
	let pair = forged.accounts.iter_mut().find(|a| a.address == pair(0)).unwrap();
	for slot in &mut pair.slots {
		if slot.key == B256::from(U256::from(2)) {
			slot.value = U256::from(1);
		}
	}
	(params, [fair, exploit, forged])
}

/// Swap along `hops` pairs through the router: the footprint grows by a pair and a token a hop.
pub fn route(hops: u64) -> Case {
	let world = pairs_world(hops, U256::from(10_000 * ETHER));
	let mut data = call("route(address[],uint256)", &[U256::from(0x40), U256::from(1_000 * ETHER), U256::from(hops)]).to_vec();
	for i in 0..hops {
		data.extend_from_slice(&word(pair(i)).to_be_bytes::<32>());
	}
	let txs = vec![tx(ROUTER, data.into(), 16_000_000)];
	case(&format!("route-{hops}"), &world, pair_invariant(), txs, Reads::default())
}

/// Burn about `evm_gas` on compute alone, in transactions of at most 10⁷ gas (Osaka caps a
/// transaction at 2²⁴).
pub fn burn(name: &str, evm_gas: u64) -> Case {
	let mut world = World::default();
	world.accounts.insert(COINBASE, Account::eoa(U256::from(ETHER)));
	world.accounts.insert(BURN, Account::contract(burn_code(), SMALL_STORAGE));
	let burn = |rounds: u64, gas: u64| tx(BURN, call("burn(uint256)", &[U256::from(rounds)]), gas);
	// Measure a round's gas, to fill each transaction without running out.
	let used = |rounds: u64| {
		let case = case(name, &world, always(), vec![burn(rounds, 1 << 24)], Reads::default());
		evm_bounty_check::run_measured(&alloy_rlp::encode(&case.params), &alloy_rlp::encode(&case.report)).1
	};
	let per_round = (used(2000) - used(1000)) / 1000;
	let base = used(1000) - 1000 * per_round;
	let per_tx = 10_000_000u64;
	let mut txs = Vec::new();
	let mut left = evm_gas;
	while left > 0 {
		let gas = left.min(per_tx);
		txs.push(burn(gas.saturating_sub(base) / per_round, gas + 100_000));
		left -= gas;
	}
	case(name, &world, always(), txs, Reads::default())
}

/// No transactions: prove `accounts` big-token accounts and `slots` slots of each.
pub fn proofs(accounts: u64, slots: u64) -> Case {
	let mut world = World::default();
	let mut extra = Reads::default();
	for i in 0..accounts {
		let mut t = Account::contract(token_code(), BIG_STORAGE);
		let keys: Vec<U256> = (0..slots).map(|s| mapping_slot(at(0x1_0000 + s), 0)).collect();
		for k in &keys {
			t.storage.insert(*k, U256::from(ETHER));
		}
		world.accounts.insert(token(i), t);
		extra.prove(token(i), keys);
	}
	case(&format!("proofs-{accounts}x{slots}"), &world, always(), Vec::new(), extra)
}

/// Every case the spike measures.
pub fn all() -> Vec<Case> {
	vec![
		burn("burn-1m", 1_000_000),
		burn("burn-10m", 10_000_000),
		burn("burn-30m", 30_000_000),
		proofs(10, 10),
		proofs(100, 10),
		proofs(400, 10),
		pair_swap(),
		pair_exploit(),
		route(4),
		route(16),
		route(64),
	]
}

#[cfg(test)]
mod tests {
	use super::*;

	fn run(case: &Case) -> Outcome {
		evm_bounty_check::run(&alloy_rlp::encode(&case.params), &alloy_rlp::encode(&case.report))
	}

	#[test]
	fn the_exploit_wins() {
		let case = pair_exploit();
		assert_eq!(case.expected, Outcome::Violated);
		assert_eq!(run(&case), Outcome::Violated);
	}

	#[test]
	fn a_fair_swap_does_not() {
		let case = pair_swap();
		assert_eq!(case.expected, Outcome::Holds);
		assert_eq!(run(&case), Outcome::Holds);
	}

	#[test]
	fn proofs_are_mainnet_deep() {
		let case = pair_swap();
		let token = case.report.accounts.iter().find(|a| a.address == token(0)).unwrap();
		assert_eq!(token.proof.len(), MAINNET_ACCOUNTS.full + MAINNET_ACCOUNTS.sparse + 1);
		// A present slot's proof ends in its leaf; an absent one's at the branch without it.
		let depth = BIG_STORAGE.full + BIG_STORAGE.sparse;
		assert!(token.slots.iter().all(|s| s.proof.len() == depth + !s.value.is_zero() as usize));
	}

	#[test]
	fn a_missing_proof_fails() {
		let mut case = pair_exploit();
		// The swap pays out token 1; the invariant never reads it.
		case.report.accounts.retain(|a| a.address != token(1));
		assert_eq!(run(&case), Outcome::TxFailed);
	}

	#[test]
	fn a_wrong_value_fails() {
		let mut case = pair_exploit();
		let pair = case.report.accounts.iter_mut().find(|a| a.address == pair(0)).unwrap();
		pair.slots[0].value += U256::from(1);
		assert_eq!(run(&case), Outcome::BadProof);
	}

	#[test]
	fn only_hunters_send() {
		let mut case = pair_exploit();
		case.report.txs[0].hunter = evm_bounty_check::HUNTERS;
		assert_eq!(run(&case), Outcome::Malformed);
	}

	#[test]
	fn a_report_cannot_prove_a_hunter() {
		let mut case = pair_exploit();
		let mut fake = case.report.accounts[0].clone();
		fake.address = hunter();
		case.report.accounts.push(fake);
		assert_eq!(run(&case), Outcome::Malformed);
	}

	#[test]
	fn the_demo_bounty() {
		let (params, [fair, exploit, forged]) = pair_bounty();
		let run = |r: &Report| evm_bounty_check::run(&alloy_rlp::encode(&params), &alloy_rlp::encode(r));
		assert_eq!(run(&fair), Outcome::Holds);
		assert_eq!(run(&exploit), Outcome::Violated);
		assert_eq!(run(&forged), Outcome::BadProof);
	}

	#[test]
	fn a_route_holds() {
		let case = route(4);
		assert_eq!(case.expected, Outcome::Holds);
		assert_eq!(run(&case), Outcome::Holds);
	}
}

