use super::*;
use alloc::{collections::BTreeMap, vec};
use ed25519_dalek::{Signer, SigningKey};
use witness_types::{
	Blobs, BountyTerms, CHECK_INTERFACE_VERSION, CheckFailure, DepositMemo, MEMO_VERSION, check_args, commitment,
	parents_root,
};

const SERVICE: u32 = 7;
const BLOB: &[u8] = b"check blob";
/// Another check, with the same mock behaviour.
const OTHER_BLOB: &[u8] = b"other check blob";
/// Extra blobs for bounties and attestations. The mock check attests those starting "good".
const EXTRA: [&[u8]; 5] = [b"one", b"two", b"good one", b"good two", b"bad"];
const GOOD1: usize = 2;
const GOOD2: usize = 3;
const BAD: usize = 4;
const MISSING: Hash = [0xee; 32];

fn check() -> Hash {
	blake2b256(BLOB)
}

fn other_check() -> Hash {
	blake2b256(OTHER_BLOB)
}

fn extra(i: usize) -> BlobHash {
	BlobHash { hash: blake2b256(EXTRA[i]), len: EXTRA[i].len() as u32 }
}

fn plain(i: usize) -> BlobRef {
	BlobRef::Blob(extra(i))
}

/// Where no extrinsic has a blob.
const NOWHERE: BlobAt = BlobAt { extrinsic: LIBRARY, index: 999 };
/// The extrinsics holding the check blobs, whole, and the extra blobs.
const CHECK_AT: u8 = 0;
const OTHER_CHECK_AT: u8 = 1;
const LIBRARY: u8 = 2;
/// Ops' citations are extrinsics from here on, kept apart from the lists of subjects.
const CITED: u8 = 128;

/// The work item's extrinsics: the two check blobs, each whole, then the library of extra blobs;
/// tests add more (lists of subjects, or raw bytes). Every op in a test sees them all.
///
/// The mock check:
/// - in reveal mode, accepts witness `b"x"`; a witness equal to its blobs' data concatenated;
///   or witness `b"trusted"` if it was given blobs and all of them are trusted;
/// - in attest mode, accepts subjects (the untrusted blobs, after every trusted one) that all
///   start with `b"good"`, unless the witness is `b"no"`.
struct Env {
	extrinsics: Vec<Vec<u8>>,
	/// Extrinsics `CITED`, `CITED + 1`, ...: ops' citations, added as ops are made.
	citations: core::cell::RefCell<Vec<Vec<u8>>>,
}

impl Default for Env {
	fn default() -> Self {
		let library: Blobs = EXTRA.into_iter().map(<[u8]>::to_vec).collect();
		Env { extrinsics: vec![BLOB.to_vec(), OTHER_BLOB.to_vec(), library.encode()], citations: Default::default() }
	}
}

impl Env {
	/// Add extrinsic `data`, whatever it holds, and return its index.
	fn add(&mut self, data: Vec<u8>) -> u8 {
		self.extrinsics.push(data);
		(self.extrinsics.len() - 1) as u8
	}

	/// The blobs of extrinsic `e`, or none if it doesn't decode.
	fn blobs(&self, e: u8) -> Vec<Vec<u8>> {
		let data = self.extrinsics.get(e as usize).map_or(&[][..], |d| &d[..]);
		blobs_in(data).unwrap_or_default().into_iter().map(<[u8]>::to_vec).collect()
	}

	/// Where a blob hashing to `hash` is, if anywhere.
	fn find(&self, hash: &Hash) -> BlobAt {
		(0..self.extrinsics.len() as u8)
			.find_map(|e| {
				let index = self.blobs(e).iter().position(|b| blake2b256(b) == *hash)?;
				Some(BlobAt { extrinsic: e, index: index as u32 })
			})
			.unwrap_or(NOWHERE)
	}

	/// The extrinsic holding the check blob hashing to `hash`, whole.
	fn check_at(&self, hash: &Hash) -> u8 {
		(0..LIBRARY).find(|&e| blake2b256(&self.extrinsics[e as usize]) == *hash).expect("a check blob")
	}

	/// The list extrinsic holding `claim`'s subjects.
	fn list_of(&self, claim: &AttestationClaim) -> u8 {
		(LIBRARY + 1..self.extrinsics.len() as u8)
			.find(|&e| {
				let subjects = self.blobs(e);
				subjects.len() as u32 == claim.subject_count && merkle::root(&leaves(&subjects)) == claim.subjects_root
			})
			.expect("the claim's subjects")
	}

	/// The reference trusting subject `entry` of `claim`, cited as claim `index`.
	fn trusted_ref(&self, index: u16, claim: &AttestationClaim, entry: u32) -> TrustedRef {
		let list = self.list_of(claim);
		let path = merkle::path(&leaves(&self.blobs(list)), entry as usize);
		TrustedRef { claim: index, entry, blob: BlobAt { extrinsic: list, index: entry }, path }
	}

	/// The claims and references for trusting entries of `subjects`'s claims, each claim once.
	fn citations(&self, subjects: &[(AttestationClaim, u32)]) -> Citations {
		let mut claims: Vec<AttestationClaim> = Vec::new();
		let trusted = subjects
			.iter()
			.map(|(claim, entry)| {
				let i = claims.iter().position(|c| c == claim).unwrap_or_else(|| {
					claims.push(claim.clone());
					claims.len() - 1
				});
				self.trusted_ref(i as u16, claim, *entry)
			})
			.collect();
		Citations { claims, trusted }
	}

	/// The extrinsic citing entries of `subjects`'s claims, if any.
	fn cite(&self, subjects: &[(AttestationClaim, u32)]) -> Option<u8> {
		let c = self.citations(subjects);
		(!c.claims.is_empty()).then(|| self.add_citations(&c))
	}

	/// Add an extrinsic holding `citations`, and return its index.
	fn add_citations(&self, citations: &Citations) -> u8 {
		let mut all = self.citations.borrow_mut();
		all.push(citations.encode());
		CITED + u8::try_from(all.len() - 1).expect("fewer than 128 citations a test")
	}

	/// The citations in extrinsic `at`, if any.
	fn cited(&self, at: Option<u8>) -> Citations {
		at.map_or_else(Citations::default, |at| {
			Citations::decode(&mut &self.citations.borrow()[(at - CITED) as usize][..]).unwrap()
		})
	}

	/// Where each of `blobs`'s plain blobs is.
	fn plain_at(&self, blobs: &[BlobRef]) -> Vec<BlobAt> {
		blobs
			.iter()
			.filter_map(|b| match b {
				BlobRef::Blob(p) => Some(self.find(&p.hash)),
				BlobRef::Attested { .. } => None,
			})
			.collect()
	}
}

fn leaves(subjects: &[Vec<u8>]) -> Vec<Hash> {
	subjects.iter().map(|s| merkle::leaf(&blake2b256(s))).collect()
}

/// Split `args` (see `check_args`) into the mode, the blobs (trusted, data) and the witness.
/// Every blob must come with its real hash.
fn parse_args(args: &[u8]) -> (u8, Vec<(bool, Vec<u8>)>, Vec<u8>) {
	let u32_at = |at: usize| u32::from_le_bytes(args[at..at + 4].try_into().unwrap()) as usize;
	assert_eq!(args[0], CHECK_INTERFACE_VERSION);
	let mut at = 6;
	let blobs = (0..u32_at(2))
		.map(|_| {
			let trusted = args[at] == 1;
			let hash = &args[at + 1..at + 33];
			let len = u32_at(at + 33);
			at += 37 + len;
			let data = &args[at - len..at];
			assert_eq!(hash, blake2b256(data), "a blob's hash");
			(trusted, data.to_vec())
		})
		.collect();
	(args[1], blobs, args[at + 4 + u32_at(at)..].to_vec())
}

impl RefineEnv for Env {
	fn extrinsic(&self, index: usize) -> Option<Vec<u8>> {
		match index.checked_sub(CITED as usize) {
			Some(i) => self.citations.borrow().get(i).cloned(),
			None => self.extrinsics.get(index).cloned(),
		}
	}
	fn extrinsic_hash(&self, index: usize) -> Option<Hash> {
		self.extrinsic(index).map(|x| blake2b256(&x))
	}
	fn run_check(&self, blob: &[u8], args: &[u8], _gas: Gas) -> core::result::Result<(), Rejection> {
		assert!(blob == BLOB || blob == OTHER_BLOB);
		let (mode, blobs, witness) = parse_args(args);
		let data: Vec<u8> = blobs.iter().flat_map(|(_, d)| d.clone()).collect();
		let accept = if mode == CheckMode::Attest as u8 {
			let trusted = blobs.iter().take_while(|(t, _)| *t).count();
			let subjects = &blobs[trusted..];
			witness != b"no" &&
				!subjects.is_empty() &&
				subjects.iter().all(|(t, d)| !t && d.starts_with(b"good"))
		} else {
			witness == b"x" ||
				(!blobs.is_empty() && witness == data) ||
				(!blobs.is_empty() && witness == b"trusted" && blobs.iter().all(|(t, _)| *t))
		};
		if accept { Ok(()) } else { Err(Rejection::CheckFailed(CheckFailure::False)) }
	}
}

#[derive(Default)]
struct Chain {
	env: Env,
	storage: BTreeMap<Vec<u8>, Vec<u8>>,
	/// Transfers sent, preimages solicited and upgrades made, in order.
	sent: Vec<(u32, [u8; MEMO_LEN])>,
	solicited: Vec<(Hash, u32)>,
	upgraded: Vec<Hash>,
	now: Slot,
	/// Claims of the attestations recorded so far, as a hunter would keep them to reveal with.
	claims: BTreeMap<AttestationId, AttestationClaim>,
}

impl State for Chain {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		self.storage.get(key).cloned()
	}
}

fn key(seed: u8) -> SigningKey {
	SigningKey::from_bytes(&[seed; 32])
}

fn id(seed: u8) -> AccountId {
	key(seed).verifying_key().to_bytes()
}

/// A test account: a nonce and a balance of [`TEST_ASSET`].
#[derive(Debug, PartialEq, Eq)]
struct Account {
	balance: Amount,
	nonce: u64,
}

/// The deposits the test configuration sets.
const COMMIT_DEPOSIT: Amount = 10;
const ATTEST_DEPOSIT: Amount = 10;
/// An accepted token service, and one that isn't.
const TOKENS: u32 = 40;
const OTHER_TOKENS: u32 = 41;

/// The test build's admin: the witness CLI's `--seed admin`.
fn admin_key() -> SigningKey {
	SigningKey::from_bytes(&blake2b256(b"admin"))
}

const ALICE: u8 = 1;
const BOB: u8 = 2;
const CAROL: u8 = 3;
const MALLORY: u8 = 4;

/// A reveal on bounty 0 of `blobs`, with the plain ones found in the library, trusting nothing.
fn bare_reveal(env: &Env, blobs: Vec<BlobRef>) -> Op {
	Op::Reveal {
		bounty_id: 0,
		check_hash: check(),
		params: vec![],
		check: CHECK_AT,
		plain: env.plain_at(&blobs),
		blobs,
		citations: None,
		check_gas: 1,
		hunter: id(BOB),
		salt: [0; 32],
		witness: b"x".to_vec(),
	}
}

impl Chain {
	/// Refine and accumulate `op` at the current slot.
	fn submit(&mut self, op: Op) -> Result<()> {
		let verified = self.refine(op);
		let fx = accumulate(self, verified, self.now)?;
		self.apply(fx);
		Ok(())
	}

	fn apply(&mut self, fx: Effects) {
		for (k, v) in fx.writes {
			match v {
				Some(v) => self.storage.insert(k, v),
				None => self.storage.remove(&k),
			};
		}
		self.sent.extend(fx.transfers);
		self.solicited.extend(fx.solicit);
		self.upgraded.extend(fx.upgrade);
	}

	/// Service `source` sends a transfer with `memo`.
	fn transfer(&mut self, source: u32, memo: &[u8]) -> Result<()> {
		self.transfer_with(source, 0, memo)
	}

	fn transfer_with(&mut self, source: u32, native: u64, memo: &[u8]) -> Result<()> {
		let fx = on_transfer(self, source, native, memo)?;
		self.apply(fx);
		Ok(())
	}

	/// Token service `service` deposits `amount` of its asset `asset_id` for `seed`.
	fn deposit(&mut self, service: u32, asset_id: u32, seed: u8, amount: Amount) -> Result<()> {
		self.transfer(service, &deposit_memo(asset_id, amount, seed))
	}

	fn balance(&self, seed: u8, asset: Asset) -> Amount {
		self.get_typed(&StorageKey::Balance(id(seed), asset)).unwrap_or(0)
	}

	/// The admin proposes `action`.
	fn propose(&mut self, action: AdminAction) -> Result<()> {
		let nonce = self.nonce_of(&BUILD_ADMIN);
		let signature = admin_key().sign(&witness_types::propose_message(SERVICE, &BUILD_ADMIN, nonce, &action));
		self.submit(Op::Propose { admin: BUILD_ADMIN, nonce, action, signature: signature.to_bytes() })
	}

	fn nonce_of(&self, id: &AccountId) -> u64 {
		self.get_typed::<witness_types::Account>(&StorageKey::Account(*id)).unwrap_or_default().nonce
	}

	fn config(&self) -> Option<Config> {
		self.get_typed(&StorageKey::Config)
	}

	/// Refine `op`, with the extrinsics added so far.
	fn refine(&self, op: Op) -> Verified {
		refine(&self.env, SERVICE, op)
	}

	fn advance(&mut self, slots: Slot) {
		self.now += slots;
	}

	/// `seed`'s nonce and balance of the test asset.
	fn account(&self, seed: u8) -> Account {
		Account { balance: self.balance(seed, TEST_ASSET), nonce: self.nonce_of(&id(seed)) }
	}

	fn bounty(&self, id: BountyId) -> Bounty {
		self.get_typed(&StorageKey::Bounty(id)).unwrap()
	}

	fn get_typed<T: Decode>(&self, key: &StorageKey) -> Option<T> {
		self.storage.get(&key.encode()).map(|v| T::decode(&mut &v[..]).unwrap())
	}

	fn mint(&mut self, seed: u8, amount: Amount) {
		self.submit(Op::Mint { to: id(seed), amount }).unwrap();
	}

	fn terms(&self) -> BountyTerms {
		BountyTerms {
			check_hash: check(),
			check_len: BLOB.len() as u32,
			params: b"params".to_vec(),
			blobs: vec![],
			asset: TEST_ASSET,
			reward: 500,
			check_gas: 1000,
			expiry: self.now + 50,
			claim_window: MIN_CLAIM_WINDOW,
		}
	}

	fn create(&mut self, terms: BountyTerms) -> Result<()> {
		let maker = key(ALICE);
		let nonce = self.account(ALICE).nonce;
		let signature =
			maker.sign(&witness_types::create_message(SERVICE, &id(ALICE), nonce, &terms)).to_bytes();
		self.submit(Op::CreateBounty { maker: id(ALICE), nonce, terms, signature })
	}

	/// `committer` commits to witness `w` for `hunter` on bounty `b`; returns the commitment.
	fn commit_for(&mut self, b: BountyId, committer: u8, hunter: u8, w: &[u8]) -> Result<Hash> {
		let c = commitment(b, w, &id(hunter), &[hunter; 32]);
		self.commit_hash(b, committer, c)?;
		Ok(c)
	}

	/// `committer` posts commitment hash `c` on bounty `b`, whatever it commits to.
	fn commit_hash(&mut self, b: BountyId, committer: u8, c: Hash) -> Result<()> {
		let nonce = self.account(committer).nonce;
		let msg = witness_types::commit_message(SERVICE, b, &id(committer), nonce, &c);
		let signature = key(committer).sign(&msg).to_bytes();
		self.submit(Op::Commit { bounty_id: b, committer: id(committer), nonce, commitment: c, signature })
	}

	fn commit(&mut self, b: BountyId, hunter: u8, w: &[u8]) -> Result<Hash> {
		self.commit_for(b, hunter, hunter, w)
	}

	fn reveal(&mut self, b: BountyId, hunter: u8, w: &[u8]) -> Result<()> {
		self.reveal_with(b, hunter, w, &[])
	}

	/// Reveal, trusting the bounty's attested subjects and then `more`.
	fn reveal_with(&mut self, b: BountyId, hunter: u8, w: &[u8], more: &[(AttestationClaim, u32)]) -> Result<()> {
		self.submit(self.reveal_op(b, hunter, w, more))
	}

	fn reveal_op(&self, b: BountyId, hunter: u8, w: &[u8], more: &[(AttestationClaim, u32)]) -> Op {
		let terms = self.bounty(b).terms;
		let mut subjects: Vec<(AttestationClaim, u32)> = terms
			.blobs
			.iter()
			.filter_map(|blob| match blob {
				BlobRef::Attested { attestation, entry } => Some((self.claims[attestation].clone(), *entry)),
				BlobRef::Blob(_) => None,
			})
			.collect();
		subjects.extend_from_slice(more);
		let citations = self.env.cite(&subjects);
		Op::Reveal {
			bounty_id: b,
			check_hash: terms.check_hash,
			params: terms.params,
			check: self.env.check_at(&terms.check_hash),
			plain: self.env.plain_at(&terms.blobs),
			blobs: terms.blobs,
			citations,
			check_gas: terms.check_gas,
			hunter: id(hunter),
			salt: [hunter; 32],
			witness: w.to_vec(),
		}
	}

	/// Add an extrinsic listing the extra blobs `subjects`, and return its index.
	fn list(&mut self, subjects: &[usize]) -> u8 {
		let blobs: Blobs = subjects.iter().map(|&i| EXTRA[i].to_vec()).collect();
		self.env.add(blobs.encode())
	}

	/// The claim of `attester` attesting the subjects in extrinsic `subjects` with `check_hash`
	/// and `params`, trusting `claims`.
	fn claim(&self, check_hash: Hash, params: &[u8], subjects: u8, claims: &[AttestationClaim]) -> AttestationClaim {
		let subjects = self.env.blobs(subjects);
		let parents: Vec<AttestationId> = claims.iter().map(AttestationClaim::id).collect();
		AttestationClaim {
			check_hash,
			params_hash: blake2b256(params),
			subjects_root: merkle::root(&leaves(&subjects)),
			subject_count: subjects.len() as u32,
			parents_root: parents_root(&parents),
		}
	}

	/// The op for `attester` to attest the subjects in extrinsic `subjects` with `check_hash`
	/// and `params`, trusting `trusted` (claims and entries), and its claim.
	fn attest_op(
		&self,
		attester: u8,
		check_hash: Hash,
		params: &[u8],
		subjects: u8,
		trusted: &[(AttestationClaim, u32)],
	) -> (Op, AttestationClaim) {
		let citations = self.env.citations(trusted);
		let claim = self.claim(check_hash, params, subjects, &citations.claims);
		let nonce = self.account(attester).nonce;
		let msg = witness_types::attest_message(SERVICE, &id(attester), nonce, &claim.id());
		let op = Op::Attest {
			attester: id(attester),
			nonce,
			check_hash,
			check: self.env.check_at(&check_hash),
			params: params.to_vec(),
			subjects,
			citations: (!citations.claims.is_empty()).then(|| self.env.add_citations(&citations)),
			witness: b"proof".to_vec(),
			check_gas: 1000,
			signature: key(attester).sign(&msg).to_bytes(),
		};
		(op, claim)
	}

	/// Submit `op`, recording `claim` if it is accepted.
	fn submit_attest(&mut self, (op, claim): (Op, AttestationClaim)) -> Result<AttestationClaim> {
		self.submit(op)?;
		self.claims.insert(claim.id(), claim.clone());
		Ok(claim)
	}

	/// Carol attests a list of the extra blobs `subjects` with the bounty check and params
	/// `b"batch"`, trusting `trusted`; returns the claim.
	fn attest(&mut self, subjects: &[usize], trusted: &[(AttestationClaim, u32)]) -> Result<AttestationClaim> {
		let list = self.list(subjects);
		self.submit_attest(self.attest_op(CAROL, check(), b"batch", list, trusted))
	}

	/// What refine makes of Carol attesting `subjects` with the bounty check, trusting `trusted`.
	fn refine_attest(&mut self, subjects: &[usize], trusted: &[(AttestationClaim, u32)]) -> Verified {
		let list = self.list(subjects);
		self.refine(self.attest_op(CAROL, check(), b"batch", list, trusted).0)
	}

	fn finalize(&mut self, b: BountyId) -> Result<()> {
		self.submit(Op::Finalize { bounty_id: b })
	}

	fn reclaim(&mut self, b: BountyId) -> Result<()> {
		let nonce = self.account(ALICE).nonce;
		let msg = witness_types::reclaim_message(SERVICE, b, &id(ALICE), nonce);
		let signature = key(ALICE).sign(&msg).to_bytes();
		self.submit(Op::Reclaim { bounty_id: b, maker: id(ALICE), nonce, signature })
	}

	fn winner(&self, b: BountyId) -> AccountId {
		match self.bounty(b).status {
			BountyStatus::Claimed { winner, .. } => winner.hunter,
			s => panic!("not claimed: {s:?}"),
		}
	}
}

/// The test configuration: token service [`TOKENS`], and deposits paid in the test asset.
fn test_config() -> Config {
	Config {
		token_services: vec![TOKENS],
		fee_asset: Some(TEST_ASSET),
		commit_deposit: COMMIT_DEPOSIT,
		attest_deposit: ATTEST_DEPOSIT,
	}
}

/// Witness is configured; Alice has a bounty 0 open; Bob, Carol and Mallory have the test asset
/// for deposits.
fn setup() -> Chain {
	let mut c = Chain { now: 100, ..Default::default() };
	c.propose(AdminAction::Configure(test_config())).unwrap();
	c.mint(ALICE, 1000);
	for h in [BOB, CAROL, MALLORY] {
		c.mint(h, 100);
	}
	let terms = c.terms();
	c.create(terms).unwrap();
	c
}

#[test]
fn happy_path() {
	let mut c = setup();
	assert_eq!(c.account(ALICE), Account { balance: 500, nonce: 1 });

	c.commit(0, BOB, b"x").unwrap();
	assert_eq!(c.account(BOB).balance, 100 - COMMIT_DEPOSIT);
	c.advance(MIN_COMMIT_AGE);
	c.reveal(0, BOB, b"x").unwrap();
	assert_eq!(c.account(BOB).balance, 100, "deposit refunded on a valid reveal");
	assert!(matches!(c.bounty(0).status, BountyStatus::Revealing { .. }));

	assert_eq!(c.finalize(0), Err("claim window still open"));
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(0).unwrap();
	assert_eq!(c.winner(0), id(BOB));
	assert_eq!(c.account(BOB).balance, 600);
	assert_eq!(c.finalize(0), Err("bounty not revealing"));
}

#[test]
fn copied_commitment_on_another_bounty_does_not_block_the_real_one() {
	let mut c = setup();
	let terms = c.terms();
	c.create(terms).unwrap(); // bounty 1
	// Mallory sees Bob's commitment for bounty 0 in flight and posts the same hash on bounty 1
	// first. The hash hides which bounty it is for, so nothing can tell it does not belong there.
	let bob_c = commitment(0, b"x", &id(BOB), &[BOB; 32]);
	c.commit_hash(1, MALLORY, bob_c).unwrap();
	// Bob's own commitment on bounty 0 still goes through, and he still wins.
	assert_eq!(c.commit(0, BOB, b"x"), Ok(bob_c));
	c.advance(MIN_COMMIT_AGE);
	c.reveal(0, BOB, b"x").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(0).unwrap();
	assert_eq!(c.winner(0), id(BOB));
	// Mallory's copy sits apart under bounty 1, where no reveal can ever match it (a reveal on
	// bounty 1 hashes bounty 1 in), until someone releases it.
	assert!(c.get_typed::<CommitRecord>(&StorageKey::Commitment(1, bob_c)).is_some());
	assert!(c.get_typed::<CommitRecord>(&StorageKey::Commitment(0, bob_c)).is_none(), "Bob's was consumed");
}

#[test]
fn copier_loses_to_earlier_commitment_even_if_revealing_first() {
	let mut c = setup();
	c.commit(0, BOB, b"x").unwrap();
	c.advance(1);
	// Bob's reveal is seen (and withheld); Mallory commits to the copied witness...
	c.commit(0, MALLORY, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	// ...and gets her reveal on chain first.
	c.reveal(0, MALLORY, b"x").unwrap();
	c.advance(MIN_CLAIM_WINDOW - 1);
	// Bob's reveal lands before the window closes.
	c.reveal(0, BOB, b"x").unwrap();
	c.advance(1);
	c.finalize(0).unwrap();
	assert_eq!(c.winner(0), id(BOB));
}

#[test]
fn withholding_past_the_window_wins() {
	// The remaining assumption: the original reveal must land within the claim window.
	let mut c = setup();
	c.commit(0, BOB, b"x").unwrap();
	c.advance(1);
	c.commit(0, MALLORY, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	c.reveal(0, MALLORY, b"x").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	assert_eq!(c.reveal(0, BOB, b"x"), Err("reveal window closed"));
	c.finalize(0).unwrap();
	assert_eq!(c.winner(0), id(MALLORY));
}

#[test]
fn same_slot_tie_goes_to_lower_commitment_hash() {
	let mut c = setup();
	let bob = c.commit(0, BOB, b"x").unwrap();
	let carol = c.commit(0, CAROL, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	c.reveal(0, BOB, b"x").unwrap();
	c.reveal(0, CAROL, b"x").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(0).unwrap();
	assert_eq!(c.winner(0), if bob < carol { id(BOB) } else { id(CAROL) });
}

#[test]
fn reveal_rules() {
	let mut c = setup();
	let terms = c.terms();
	c.create(terms).unwrap(); // bounty 1, same check

	// Not committed, wrong bounty, too recent.
	assert_eq!(c.reveal(0, BOB, b"x"), Err("no commitment"));
	c.commit(1, BOB, b"x").unwrap();
	let c0 = commitment(0, b"x", &id(BOB), &[BOB; 32]);
	assert!(c.get_typed::<CommitRecord>(&StorageKey::Commitment(0, c0)).is_none());
	assert_eq!(c.reveal(1, BOB, b"x"), Err("commitment too recent"));

	// A witness the check rejects never reaches the state rules.
	c.commit(0, CAROL, b"wrong").unwrap();
	c.advance(MIN_COMMIT_AGE);
	assert_eq!(c.reveal(0, CAROL, b"wrong"), Err("rejected in refine"));
	assert_eq!(c.account(CAROL).balance, 100 - COMMIT_DEPOSIT, "no refund for a failed check");

	// Revealing with someone else's commitment pays nothing: the hunter is inside the hash.
	c.commit(0, BOB, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	assert_eq!(c.reveal(0, MALLORY, b"x"), Err("no commitment"));

	// Terms must match the bounty's.
	let mut op_terms = c.bounty(0).terms;
	op_terms.params = b"other".to_vec();
	let mut op = c.reveal_op(0, BOB, b"x", &[]);
	let Op::Reveal { params, .. } = &mut op else { unreachable!() };
	*params = op_terms.params;
	assert_eq!(c.submit(op), Err("revealed against different terms"));

	// The same commitment cannot be revealed twice.
	c.reveal(0, BOB, b"x").unwrap();
	assert_eq!(c.reveal(0, BOB, b"x"), Err("no commitment"));
}

#[test]
fn the_check_must_be_in_the_extrinsics() {
	let env = Env::default();
	let bad_blob = Verified::Rejected(Rejection::BadBlob);
	let with_check = |at| {
		let mut op = bare_reveal(&env, vec![]);
		let Op::Reveal { check, .. } = &mut op else { unreachable!() };
		*check = at;
		refine(&env, SERVICE, op)
	};
	assert!(matches!(with_check(CHECK_AT), Verified::Reveal { .. }));
	assert_eq!(with_check(9), bad_blob, "no such extrinsic");
	assert_eq!(with_check(OTHER_CHECK_AT), bad_blob, "another blob");
	assert_eq!(with_check(LIBRARY), bad_blob, "the check among other blobs");
	let mut broken = Env::default();
	broken.extrinsics[LIBRARY as usize] = vec![4, 2, 3];
	let op = bare_reveal(&env, vec![plain(0)]);
	assert_eq!(refine(&broken, SERVICE, op), Verified::Rejected(Rejection::BadExtrinsic));
}

#[test]
fn commit_rules() {
	let mut c = setup();
	// Unknown bounty, double commit, replayed signature, no points.
	assert_eq!(c.commit(9, BOB, b"x"), Err("no such bounty"));
	let commitment = c.commit(0, BOB, b"x").unwrap();
	assert_eq!(c.commit(0, BOB, b"x"), Err("already committed"));
	let msg = witness_types::commit_message(SERVICE, 0, &id(BOB), 0, &commitment);
	let signature = key(BOB).sign(&msg).to_bytes();
	let replay = Op::Commit { bounty_id: 0, committer: id(BOB), nonce: 0, commitment, signature };
	assert_eq!(c.submit(replay), Err("already committed"));
	let other = [9; 32];
	let msg = witness_types::commit_message(SERVICE, 0, &id(BOB), 0, &other);
	let signature = key(BOB).sign(&msg).to_bytes();
	let stale = Op::Commit { bounty_id: 0, committer: id(BOB), nonce: 0, commitment: other, signature };
	assert_eq!(c.submit(stale), Err("bad nonce"));
	let broke = 9;
	assert_eq!(c.commit(0, broke, b"x"), Err("insufficient balance"));

	// A forged signature is caught in refine.
	let forged = Op::Commit {
		bounty_id: 0,
		committer: id(CAROL),
		nonce: 0,
		commitment: [1; 32],
		signature: key(MALLORY).sign(b"anything").to_bytes(),
	};
	assert_eq!(refine(&Env::default(), SERVICE, forged), Verified::Rejected(Rejection::BadSignature));

	// Someone else may pay the deposit; the payout still goes to the hunter in the commitment.
	c.commit_for(0, CAROL, MALLORY, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	c.reveal(0, MALLORY, b"x").unwrap();
	assert_eq!(c.account(CAROL).balance, 100, "deposit refunded to whoever paid it");

	// No commitments at or after expiry.
	c.advance(c.bounty(0).terms.expiry);
	assert_eq!(c.commit(0, CAROL, b"x"), Err("bounty not accepting commitments"));
}

#[test]
fn reveal_grace_and_window_can_outlast_expiry() {
	let mut c = setup();
	let expiry = c.bounty(0).terms.expiry;
	c.advance(expiry - c.now - 1);
	c.commit(0, BOB, b"x").unwrap();
	c.advance(REVEAL_GRACE); // past expiry, inside the grace period
	c.reveal(0, BOB, b"x").unwrap();
	c.advance(MIN_CLAIM_WINDOW - 1);
	assert_eq!(c.reclaim(0), Err("bounty not open"));
	c.advance(1);
	c.finalize(0).unwrap();
	assert_eq!(c.winner(0), id(BOB));
}

#[test]
fn reclaim_rules() {
	let mut c = setup();
	let expiry = c.bounty(0).terms.expiry;
	c.advance(expiry + REVEAL_GRACE - c.now - 1);
	assert_eq!(c.reclaim(0), Err("reveal window still open"));
	c.advance(1);
	c.reclaim(0).unwrap();
	assert_eq!(c.account(ALICE), Account { balance: 1000, nonce: 2 });
	assert_eq!(c.bounty(0).status, BountyStatus::Reclaimed);
	assert_eq!(c.reclaim(0), Err("bounty not open"));
}

#[test]
fn release_rules() {
	let mut c = setup();
	let unrevealed = c.commit(0, CAROL, b"x").unwrap();
	let release = Op::Release { bounty_id: 0, commitment: unrevealed };
	assert_eq!(c.submit(release.clone()), Err("commitment can still be revealed"));
	c.commit(0, BOB, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	c.reveal(0, BOB, b"x").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	// The window has closed, so Carol's commitment is dead weight; anyone may delete it.
	assert_eq!(c.submit(Op::Release { bounty_id: 1, commitment: unrevealed }), Err("no commitment"));
	c.submit(release.clone()).unwrap();
	assert!(c.get_typed::<CommitRecord>(&StorageKey::Commitment(0, unrevealed)).is_none());
	assert_eq!(c.account(CAROL).balance, 100 - COMMIT_DEPOSIT, "forfeit deposit stays forfeit");
	assert_eq!(c.submit(release), Err("no commitment"));
}

#[test]
fn create_rules() {
	let mut c = setup();
	let mut terms = c.terms();
	terms.claim_window = MIN_CLAIM_WINDOW - 1;
	assert_eq!(c.create(terms), Err("claim window out of range"));
	let mut terms = c.terms();
	terms.expiry = c.now + MIN_COMMIT_AGE;
	assert_eq!(c.create(terms), Err("expiry too soon"));
	let mut terms = c.terms();
	terms.reward = 501;
	assert_eq!(c.create(terms), Err("insufficient balance"));
	let mut terms = c.terms();
	terms.params = vec![0; MAX_PARAMS_LEN as usize + 1];
	assert_eq!(c.create(terms), Err("check too large"));
	assert_eq!(c.account(ALICE), Account { balance: 500, nonce: 1 }, "failed creates change nothing");
}

#[test]
fn rejected_ops_write_nothing() {
	let c = setup();
	for v in [
		Verified::Finalize { bounty_id: 0 },
		Verified::Release { bounty_id: 0, commitment: [0; 32] },
		Verified::Rejected(Rejection::BadPayload),
	] {
		assert!(accumulate(&c, v, c.now).is_err());
	}
}

#[test]
fn check_args_layout() {
	let args = check_args(CheckMode::Reveal, &[], b"pp", b"xyz");
	assert_eq!(args, [2, 0, 0, 0, 0, 0, 2, 0, 0, 0, b'p', b'p', b'x', b'y', b'z']);
	let blob = CheckBlob { trusted: true, hash: [7; 32], data: b"ab" };
	let args = check_args(CheckMode::Attest, &[blob], b"", b"x");
	let mut expected = vec![2, 1, 1, 0, 0, 0, 1];
	expected.extend([7; 32]);
	expected.extend([2, 0, 0, 0, b'a', b'b', 0, 0, 0, 0, b'x']);
	assert_eq!(args, expected);
}

/// Alice's bounty 1 uses both extra blobs, in order.
fn with_blobs() -> Chain {
	let mut c = setup();
	let mut terms = c.terms();
	terms.blobs = vec![plain(0), plain(1)];
	terms.reward = 100;
	c.create(terms).unwrap();
	c
}

#[test]
fn blobs_reach_the_check_in_order() {
	let mut c = with_blobs();
	c.commit(1, BOB, b"onetwo").unwrap();
	c.commit(1, CAROL, b"twoone").unwrap();
	c.advance(MIN_COMMIT_AGE);
	assert_eq!(c.reveal(1, CAROL, b"twoone"), Err("rejected in refine"));
	c.reveal(1, BOB, b"onetwo").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(1).unwrap();
	assert_eq!(c.winner(1), id(BOB));
}

#[test]
fn reveal_must_name_the_bounty_blobs() {
	let mut c = with_blobs();
	c.commit(1, BOB, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	let terms = c.bounty(1).terms;
	let b = |i| BlobRef::Blob(extra(i));
	for blobs in [vec![], vec![b(1), b(0)], vec![b(0)]] {
		let op = Op::Reveal {
			bounty_id: 1,
			check_hash: check(),
			params: terms.params.clone(),
			check: CHECK_AT,
			plain: c.env.plain_at(&blobs),
			blobs,
			citations: None,
			check_gas: terms.check_gas,
			hunter: id(BOB),
			salt: [BOB; 32],
			witness: b"x".to_vec(),
		};
		assert_eq!(c.submit(op), Err("revealed against different terms"));
	}
	c.reveal(1, BOB, b"x").unwrap();
}

#[test]
fn blob_limits() {
	let env = Env::default();
	let missing = BlobRef::Blob(BlobHash { hash: MISSING, len: 1 });
	let one = BlobRef::Blob(extra(0));
	let bad_blob = Verified::Rejected(Rejection::BadBlob);
	assert_eq!(refine(&env, SERVICE, bare_reveal(&env, vec![one, missing])), bad_blob);
	let too_many = vec![one; MAX_BLOBS as usize + 1];
	assert_eq!(refine(&env, SERVICE, bare_reveal(&env, too_many)), Verified::Rejected(Rejection::BlobsTooLarge));

	let mut c = setup();
	let mut terms = c.terms();
	terms.blobs = vec![plain(0); MAX_BLOBS as usize + 1];
	assert_eq!(c.create(terms), Err("blobs too large"));
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Blob(BlobHash { hash: MISSING, len: MAX_BLOBS_LEN / 2 + 1 }); 2];
	assert_eq!(c.create(terms), Err("blobs too large"));
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Blob(BlobHash { hash: MISSING, len: MAX_BLOBS_LEN / 2 }); 2];
	terms.reward = 100;
	c.create(terms).unwrap();
}

#[test]
fn attesting_a_batch() {
	let mut c = setup();
	let claim = c.attest(&[GOOD1, GOOD2], &[]).unwrap();
	assert_eq!(claim.parents_root, parents_root(&[]));
	assert_eq!(claim.subject_count, 2);
	let recorded: Attestation = c.get_typed(&StorageKey::Attestation(claim.id())).unwrap();
	let record = Attestation { check_hash: check(), params_hash: blake2b256(b"batch"), slot: c.now, attester: id(CAROL) };
	assert_eq!(recorded, record, "a record, whatever the subjects");
	assert_eq!(c.account(CAROL), Account { balance: 100 - ATTEST_DEPOSIT, nonce: 1 });

	assert_eq!(c.attest(&[GOOD1, GOOD2], &[]), Err("already attested"));
	assert_eq!(c.account(CAROL).balance, 100 - ATTEST_DEPOSIT, "nothing charged twice");
	let rejected = |r| Verified::Rejected(r);
	let check_says_no = rejected(Rejection::CheckFailed(CheckFailure::False));
	assert_eq!(c.refine_attest(&[GOOD1, BAD], &[]), check_says_no, "one bad subject spoils the batch");
	assert_eq!(c.refine_attest(&[], &[]), check_says_no, "the mock wants subjects");
	let op = c.attest_op(CAROL, check(), b"batch", 99, &[]).0;
	assert_eq!(c.refine(op), rejected(Rejection::BadBlob), "no such extrinsic");
	let good: Blobs = vec![b"good one".to_vec()];
	for data in [vec![4, 2, 3], (good, 0u8).encode(), vec![Vec::<u8>::new(); MAX_BLOBS as usize + 1].encode()] {
		let list = c.env.add(data);
		let op = c.attest_op(CAROL, check(), b"batch", list, &[]).0;
		assert_eq!(c.refine(op), rejected(Rejection::BadExtrinsic));
	}
	let big = vec![b"good".repeat(MAX_BLOBS_LEN as usize / 8 + 1); 2];
	let list = c.env.add(big.encode());
	let op = c.attest_op(CAROL, check(), b"batch", list, &[]).0;
	assert_eq!(c.refine(op), rejected(Rejection::BlobsTooLarge));
	// The check is read from the extrinsics and must be the claimed one.
	let list = c.list(&[GOOD1]);
	let (mut op, _) = c.attest_op(CAROL, check(), b"batch", list, &[]);
	let Op::Attest { check: at, .. } = &mut op else { unreachable!() };
	*at = OTHER_CHECK_AT;
	assert_eq!(c.refine(op), rejected(Rejection::BadBlob));

	// The witness reaches the check.
	let (mut op, _) = c.attest_op(CAROL, check(), b"batch", list, &[]);
	let Op::Attest { witness, .. } = &mut op else { unreachable!() };
	*witness = b"no".to_vec();
	assert_eq!(c.refine(op.clone()), check_says_no);
	// It isn't part of the claim, so changing it leaves the signature valid.
	let Op::Attest { witness, .. } = &mut op else { unreachable!() };
	*witness = b"other proof".to_vec();
	c.submit(op).unwrap();

	// The signature covers the claim, so it can't be replayed for other subjects.
	let other = c.list(&[GOOD2]);
	let (Op::Attest { signature, .. }, _) = c.attest_op(CAROL, check(), b"batch", other, &[]) else { unreachable!() };
	let first = c.env.list_of(&claim);
	let mut op = c.attest_op(CAROL, check(), b"batch", first, &[]).0;
	let Op::Attest { signature: s, .. } = &mut op else { unreachable!() };
	*s = signature;
	assert_eq!(c.refine(op), rejected(Rejection::BadSignature));
}

#[test]
fn attestations_form_a_dag() {
	let mut c = setup();
	let a = c.attest(&[GOOD1, GOOD2], &[]).unwrap();
	let b = c.attest(&[GOOD2], &[]).unwrap();
	// Trusting subjects of both: the check gets them trusted, before the subjects to attest.
	let d = c.attest(&[GOOD1], &[(a.clone(), 1), (b.clone(), 0), (a.clone(), 0)]).unwrap();
	assert_eq!(d.parents_root, parents_root(&[b.id(), a.id()]), "parents are a set");
	assert_ne!(d.id(), c.attest(&[GOOD1], &[(a.clone(), 0)]).unwrap().id(), "other parents, other id");
	// Any depth: d's subject is trusted on its own, with no context.
	c.attest(&[GOOD2], &[(d.clone(), 0)]).unwrap();

	// A parent nobody attested: refine runs the check on its claimed subjects, and accumulate
	// finds no such record.
	let unattested = c.list(&[BAD]);
	let made_up = c.claim(check(), b"batch", unattested, &[]);
	assert_eq!(c.attest(&[GOOD2, GOOD1], &[(made_up, 0)]), Err("no such parent attestation"));

	// A parent by another check is refused outright, recorded or not.
	let list = c.list(&[GOOD1]);
	let foreign = c.submit_attest(c.attest_op(CAROL, other_check(), b"batch", list, &[])).unwrap();
	let foreign_attestation = Verified::Rejected(Rejection::ForeignAttestation);
	assert_eq!(c.refine_attest(&[GOOD2], &[(foreign, 0)]), foreign_attestation);
	// So is one attested with other params, which might have been more lenient.
	let lenient = c.submit_attest(c.attest_op(CAROL, check(), b"lenient", list, &[])).unwrap();
	assert_eq!(c.refine_attest(&[GOOD2], &[(lenient, 0)]), foreign_attestation);
}

#[test]
fn citations_are_an_extrinsic_of_their_own() {
	let mut c = setup();
	let a = c.attest(&[GOOD1], &[]).unwrap();
	let list = c.list(&[GOOD2]);
	let (op, _) = c.attest_op(CAROL, check(), b"batch", list, &[(a, 0)]);
	assert!(matches!(c.refine(op.clone()), Verified::Attest { .. }));
	let garbage = c.env.add(vec![9, 9, 9]);
	let with = |citations| {
		let mut op = op.clone();
		let Op::Attest { citations: at, .. } = &mut op else { unreachable!() };
		*at = citations;
		c.refine(op)
	};
	assert_eq!(with(Some(garbage)), Verified::Rejected(Rejection::BadExtrinsic), "not citations");
	assert_eq!(with(Some(CITED + 100)), Verified::Rejected(Rejection::BadBlob), "no such extrinsic");
	// Leaving them out changes the claim's parents, which the signature covers.
	assert_eq!(with(None), Verified::Rejected(Rejection::BadSignature));
}

#[test]
fn trusted_refs_must_be_exact() {
	let mut c = setup();
	let a = c.attest(&[GOOD1, GOOD2], &[]).unwrap();
	let b = c.attest(&[GOOD2], &[]).unwrap();
	let list = c.list(&[GOOD1]);
	let bad_ref = Verified::Rejected(Rejection::BadTrustedRef);
	let bad_blob = Verified::Rejected(Rejection::BadBlob);
	let with = |c: &Chain, claims: Vec<AttestationClaim>, trusted: Vec<TrustedRef>| {
		let (mut op, _) = c.attest_op(CAROL, check(), b"batch", list, &[]);
		// Signing over whatever parents the claims make.
		let claim = c.claim(check(), b"batch", list, &claims);
		let msg = witness_types::attest_message(SERVICE, &id(CAROL), c.account(CAROL).nonce, &claim.id());
		let Op::Attest { citations, signature, .. } = &mut op else { unreachable!() };
		*citations = Some(c.env.add_citations(&Citations { claims, trusted }));
		*signature = key(CAROL).sign(&msg).to_bytes();
		c.refine(op)
	};
	let r = |index, claim: &AttestationClaim, entry| c.env.trusted_ref(index, claim, entry);
	assert!(matches!(with(&c, vec![a.clone()], vec![r(0, &a, 1)]), Verified::Attest { .. }));
	assert_eq!(with(&c, vec![a.clone()], vec![r(1, &a, 0)]), bad_ref, "no such claim");
	assert_eq!(with(&c, vec![a.clone()], vec![r(0, &a, 2)]), bad_blob, "no such entry");
	assert_eq!(with(&c, vec![a.clone(), b.clone()], vec![r(0, &a, 0)]), bad_ref, "a claim unused");
	assert_eq!(with(&c, vec![a.clone(), a.clone()], vec![r(0, &a, 0), r(1, &a, 0)]), bad_ref, "a claim twice");
	let too_many = vec![r(0, &a, 0); MAX_BLOBS as usize];
	assert_eq!(with(&c, vec![a.clone()], too_many), Verified::Rejected(Rejection::BlobsTooLarge));

	// A subject must be the one its path proves, under the claim's root.
	let mut swapped = r(0, &a, 0);
	swapped.blob.index = 1;
	assert_eq!(with(&c, vec![a.clone()], vec![swapped]), bad_blob, "another subject");
	let mut moved = r(0, &a, 0);
	moved.entry = 1;
	assert_eq!(with(&c, vec![a.clone()], vec![moved]), bad_blob, "another entry");
	let mut short = r(0, &a, 0);
	short.path.clear();
	assert_eq!(with(&c, vec![a.clone()], vec![short]), bad_blob, "no path");
	let mut foreign = r(0, &a, 0);
	foreign.path = c.env.trusted_ref(0, &b, 0).path;
	foreign.blob = c.env.trusted_ref(0, &b, 0).blob;
	assert_eq!(with(&c, vec![a], vec![foreign]), bad_blob, "another claim's subject");
}

/// Bounty 1 cites both subjects of a batch attested by its check.
fn with_attested_blobs() -> (Chain, AttestationClaim) {
	let mut c = setup();
	let batch = c.attest(&[GOOD1, GOOD2], &[]).unwrap();
	let mut terms = c.terms();
	let attested = |entry| BlobRef::Attested { attestation: batch.id(), entry };
	terms.blobs = vec![attested(0), attested(1)];
	terms.reward = 100;
	c.create(terms).unwrap();
	(c, batch)
}

#[test]
fn bounties_cite_attested_subjects_as_trusted() {
	let (mut c, batch) = with_attested_blobs();
	c.commit(1, BOB, b"trusted").unwrap();
	c.advance(MIN_COMMIT_AGE);
	c.reveal(1, BOB, b"trusted").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(1).unwrap();
	assert_eq!(c.winner(1), id(BOB));

	// A bounty can mix plain and attested blobs; a plain one is never trusted.
	let mut terms = c.terms();
	terms.blobs = vec![plain(0), BlobRef::Attested { attestation: batch.id(), entry: 1 }];
	terms.reward = 100;
	c.create(terms).unwrap(); // bounty 2
	c.commit(2, BOB, b"trusted").unwrap();
	c.commit(2, CAROL, b"good twoone").unwrap();
	c.advance(MIN_COMMIT_AGE);
	assert_eq!(c.reveal(2, BOB, b"trusted"), Err("rejected in refine"));
	// The check gets the trusted subjects first, then the plain blobs.
	c.reveal(2, CAROL, b"good twoone").unwrap();
}

#[test]
fn bounties_cite_only_their_own_check_attestations() {
	let (mut c, batch) = with_attested_blobs();
	let cite = |c: &mut Chain, blobs| {
		let mut terms = c.terms();
		terms.blobs = blobs;
		terms.reward = 10;
		c.create(terms)
	};
	let a = |claim: &AttestationClaim, entry| BlobRef::Attested { attestation: claim.id(), entry };
	assert_eq!(cite(&mut c, vec![BlobRef::Attested { attestation: [9; 32], entry: 0 }]), Err("no such attestation"));
	// Accumulate doesn't see subjects, so an entry past the end only fails at reveal.
	assert_eq!(cite(&mut c, vec![a(&batch, 2)]), Ok(())); // bounty 2
	let list = c.list(&[GOOD1]);
	let foreign = c.submit_attest(c.attest_op(CAROL, other_check(), b"batch", list, &[])).unwrap();
	assert_eq!(cite(&mut c, vec![a(&foreign, 0)]), Err("attested by another check"));
	let lenient = c.submit_attest(c.attest_op(CAROL, check(), b"lenient", list, &[])).unwrap();
	assert_eq!(cite(&mut c, vec![a(&batch, 0), a(&lenient, 0)]), Err("attested with other params"));
	assert_eq!(cite(&mut c, vec![a(&lenient, 0)]), Ok(()), "any params, if only one set");
	// Subjects can be cited in any order, and any of them alone.
	assert_eq!(cite(&mut c, vec![a(&batch, 1), plain(0), a(&batch, 0)]), Ok(()));
	assert_eq!(cite(&mut c, vec![a(&batch, 1)]), Ok(()));

	// At reveal, a claim by another check is refused in refine.
	c.commit(1, BOB, b"trusted").unwrap();
	c.commit(2, BOB, b"trusted").unwrap();
	c.advance(MIN_COMMIT_AGE);
	assert_eq!(c.refine(c.reveal_op(2, BOB, b"trusted", &[])), Verified::Rejected(Rejection::BadBlob));
	let op = c.reveal_op(1, BOB, b"trusted", &[(foreign, 0)]);
	assert_eq!(c.refine(op), Verified::Rejected(Rejection::ForeignAttestation));
	let op = c.reveal_op(1, BOB, b"trusted", &[(lenient, 0)]);
	assert_eq!(c.refine(op), Verified::Rejected(Rejection::ForeignAttestation));
}

#[test]
fn reveals_cite_attestations_only_if_their_bounty_does() {
	// A bounty citing no attestation leaves a reveal's claims free to share any params. A hunter
	// could cite attestations made with params of their choosing (for Lean, pins under which
	// anything is provable), so such a bounty takes only reveals citing none.
	let mut c = setup();
	let list = c.list(&[GOOD1]);
	let lenient = c.submit_attest(c.attest_op(CAROL, check(), b"lenient", list, &[])).unwrap();
	c.commit(0, BOB, b"trusted").unwrap();
	c.commit(0, CAROL, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	let op = c.reveal_op(0, BOB, b"trusted", &[(lenient, 0)]);
	assert!(matches!(c.refine(op.clone()), Verified::Reveal { .. }), "refine can't tell");
	assert_eq!(c.submit(op), Err("the bounty cites no attestation"));
	c.reveal(0, CAROL, b"x").unwrap();
}

#[test]
fn reveals_must_trust_the_bounty_subjects() {
	let (mut c, _) = with_attested_blobs();
	c.commit(1, BOB, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	// Change a reveal's trusted references, in a new citations extrinsic.
	let recite = |op: &mut Op, f: &dyn Fn(&mut Vec<TrustedRef>)| {
		let Op::Reveal { citations, .. } = op else { unreachable!() };
		let mut cited = c.env.cited(*citations);
		f(&mut cited.trusted);
		*citations = Some(c.env.add_citations(&cited));
	};
	let mut op = c.reveal_op(1, BOB, b"x", &[]);
	recite(&mut op, &|t| drop(t.pop()));
	assert_eq!(c.refine(op.clone()), Verified::Rejected(Rejection::BadTrustedRef), "one left out");
	recite(&mut op, &|t| t.push(t[0].clone()));
	assert_eq!(c.refine(op), Verified::Rejected(Rejection::BadTrustedRef), "the wrong one instead");
	// Order is the hunter's choice.
	let mut op = c.reveal_op(1, BOB, b"x", &[]);
	recite(&mut op, &|t| t.reverse());
	c.submit(op).unwrap();
}

#[test]
fn reveals_can_trust_more_subjects() {
	let mut c = setup();
	let statement = c.attest(&[GOOD1], &[]).unwrap();
	let library = c.attest(&[GOOD2], &[(statement.clone(), 0)]).unwrap();
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Attested { attestation: statement.id(), entry: 0 }, plain(0)];
	terms.reward = 100;
	c.create(terms).unwrap(); // bounty 1
	c.commit(1, BOB, b"trusted").unwrap();
	c.commit(1, CAROL, b"good onegood twoone").unwrap();
	c.advance(MIN_COMMIT_AGE);

	// The bounty's subjects, then the reveal's own, both trusted, then the plain blob. So
	// Carol's witness (all the data in that order) passes, and so would Bob's, if the plain blob
	// were trusted, which it isn't.
	assert_eq!(c.reveal_with(1, BOB, b"trusted", &[(library.clone(), 0)]), Err("rejected in refine"));
	// A claim that passes the check but was never recorded is refused in accumulate.
	let list = c.list(&[GOOD2]);
	let (_, unrecorded) = c.attest_op(CAROL, check(), b"batch", list, &[(library.clone(), 0)]);
	let witness = b"good onegood twoone";
	assert_eq!(c.reveal_with(1, CAROL, witness, &[(unrecorded, 0)]), Err("no such attestation"));
	c.reveal_with(1, CAROL, witness, &[(library, 0)]).unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(1).unwrap();
	assert_eq!(c.winner(1), id(CAROL));
}

#[test]
fn parents_root_is_of_a_set() {
	let (x, y) = ([1; 32], [2; 32]);
	assert_eq!(parents_root(&[x, y]), parents_root(&[y, x, y]));
	assert_ne!(parents_root(&[x]), parents_root(&[x, y]));
	assert_ne!(parents_root(&[]), parents_root(&[x]));
}

#[test]
fn blobs_too_large_in_all() {
	let mut env = Env::default();
	let half = vec![0; MAX_BLOBS_LEN as usize / 2 + 1];
	let blob = BlobRef::Blob(BlobHash { hash: blake2b256(&half), len: half.len() as u32 });
	env.add(vec![half].encode());
	let op = bare_reveal(&env, vec![blob, blob]);
	assert_eq!(refine(&env, SERVICE, op), Verified::Rejected(Rejection::BlobsTooLarge));
}

#[test]
fn reveals_name_their_plain_blobs() {
	let mut c = with_blobs();
	c.commit(1, BOB, b"onetwo").unwrap();
	c.advance(MIN_COMMIT_AGE);
	let bad_blob = Verified::Rejected(Rejection::BadBlob);
	let with_plain = |c: &Chain, f: &dyn Fn(&mut Vec<BlobAt>)| {
		let mut op = c.reveal_op(1, BOB, b"onetwo", &[]);
		let Op::Reveal { plain, .. } = &mut op else { unreachable!() };
		f(plain);
		c.refine(op)
	};
	assert_eq!(with_plain(&c, &|p| p.reverse()), bad_blob, "in the wrong order");
	assert_eq!(with_plain(&c, &|p| { p.pop(); }), bad_blob, "one too few");
	assert_eq!(with_plain(&c, &|p| p.push(p[0])), bad_blob, "one too many");
	// The same bytes anywhere in the extrinsics will do.
	let copy = c.env.add(vec![EXTRA[1].to_vec(), EXTRA[0].to_vec()].encode());
	let moved = with_plain(&c, &|p| *p = vec![BlobAt { extrinsic: copy, index: 1 }, BlobAt { extrinsic: copy, index: 0 }]);
	assert!(matches!(moved, Verified::Reveal { .. }));
	c.reveal(1, BOB, b"onetwo").unwrap();
}

/// A deposit memo: `amount` of asset `asset_id` for `seed`, refundable to account [0x55; 32].
fn deposit_memo(asset_id: u32, amount: Amount, seed: u8) -> [u8; MEMO_LEN] {
	TokenMemo::Deposit(DepositMemo { asset_id, amount, to: id(seed), refund_to: [0x55; 32] }).memo()
}

#[test]
fn deposits_come_only_from_accepted_token_services() {
	let mut c = setup();
	let usd = Asset { service: TOKENS, id: 7 };
	c.deposit(TOKENS, 7, BOB, 250).unwrap();
	c.deposit(TOKENS, 7, BOB, 50).unwrap();
	assert_eq!(c.balance(BOB, usd), 300);
	assert_eq!(c.balance(BOB, Asset { service: TOKENS, id: 8 }), 0, "asset by asset");
	assert_eq!(c.deposit(OTHER_TOKENS, 7, BOB, 1), Err("not from an accepted token service"));
	assert_eq!(c.transfer(TOKENS, &[0; MEMO_LEN]), Err("unknown memo version"));
	assert_eq!(c.transfer(TOKENS, &[MEMO_VERSION, 9]), Err("not a token memo"));
	let withdrawal = TokenMemo::Withdrawal(WithdrawalMemo { asset_id: 7, amount: 1, to: id(BOB) });
	assert_eq!(c.transfer(TOKENS, &withdrawal.memo()), Err("not a deposit"));
	assert_eq!(c.balance(BOB, usd), 300);
	// Native balance sent along is recorded as the recipient's storage credit.
	let memo = deposit_memo(7, 1, CAROL);
	c.transfer_with(TOKENS, 500, &memo).unwrap();
	c.transfer_with(TOKENS, 25, &memo).unwrap();
	assert_eq!(c.get_typed::<u64>(&StorageKey::StorageCredit(id(CAROL))), Some(525));
	assert_eq!(c.get_typed::<u64>(&StorageKey::StorageCredit(id(BOB))), None);
	// Before witness is configured, nothing is accepted.
	let mut fresh = Chain::default();
	assert_eq!(fresh.deposit(TOKENS, 7, BOB, 1), Err("not from an accepted token service"));
}

#[test]
fn deposits_witness_cant_credit_are_refunded() {
	// The refund pays the deposit back to the sender's account with the token service.
	let refunded = TokenMemo::Withdrawal(WithdrawalMemo { asset_id: 7, amount: 40, to: [0x55; 32] }).memo();
	assert_eq!(refund(&deposit_memo(7, 40, BOB)), Some(refunded));
	// Only deposits: refunding a refund could bounce between two services forever.
	assert_eq!(refund(&refunded), None);
	assert_eq!(refund(&[0; MEMO_LEN]), None);
	assert_eq!(refund(&[MEMO_VERSION, 9]), None);
}

#[test]
fn withdrawals_send_a_memo_back() {
	let mut c = setup();
	let usd = Asset { service: TOKENS, id: 7 };
	c.deposit(TOKENS, 7, BOB, 300).unwrap();
	let withdraw = |asset: Asset, amount: Amount, nonce: u64| {
		let to = [0x99; 32];
		let msg = witness_types::withdraw_message(SERVICE, &id(BOB), nonce, &asset, amount, &to);
		let signature = key(BOB).sign(&msg).to_bytes();
		Op::Withdraw { account: id(BOB), nonce, asset, amount, to, signature }
	};
	c.submit(withdraw(usd, 120, 0)).unwrap();
	assert_eq!(c.balance(BOB, usd), 180);
	let memo = TokenMemo::Withdrawal(WithdrawalMemo { asset_id: 7, amount: 120, to: [0x99; 32] });
	assert_eq!(c.sent, vec![(TOKENS, memo.memo())]);
	assert_eq!(c.submit(withdraw(usd, 181, 1)), Err("insufficient balance"));
	assert_eq!(c.submit(withdraw(usd, 1, 0)), Err("bad nonce"), "no replay");
	assert_eq!(c.submit(withdraw(TEST_ASSET, 1, 1)), Err("the test asset can't be withdrawn"));
	let mut forged = withdraw(usd, 1, 1);
	let Op::Withdraw { amount, .. } = &mut forged else { unreachable!() };
	*amount = 180;
	assert_eq!(c.refine(forged), Verified::Rejected(Rejection::BadSignature));
	assert_eq!(c.sent.len(), 1, "failed withdrawals send nothing");

	// A balance can go back where it came from even once its service is no longer accepted.
	c.storage.insert(StorageKey::Config.encode(), Config { token_services: vec![], ..test_config() }.encode());
	c.submit(withdraw(usd, 180, 1)).unwrap();
	assert_eq!(c.balance(BOB, usd), 0);
}

#[test]
fn bounties_pay_in_their_asset_and_deposits_in_the_fee_asset() {
	let mut c = setup();
	let usd = Asset { service: TOKENS, id: 7 };
	c.deposit(TOKENS, 7, ALICE, 1000).unwrap();
	let mut terms = c.terms();
	terms.asset = usd;
	terms.reward = 600;
	c.create(terms).unwrap(); // bounty 1
	assert_eq!(c.balance(ALICE, usd), 400);
	c.commit(1, BOB, b"x").unwrap();
	assert_eq!(c.account(BOB).balance, 100 - COMMIT_DEPOSIT, "the deposit is in the fee asset");
	c.advance(MIN_COMMIT_AGE);
	c.reveal(1, BOB, b"x").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(1).unwrap();
	assert_eq!(c.balance(BOB, usd), 600);
	assert_eq!(c.account(BOB).balance, 100);

	// Only accepted assets.
	let mut terms = c.terms();
	terms.asset = Asset { service: OTHER_TOKENS, id: 7 };
	assert_eq!(c.create(terms), Err("asset not accepted"));
	// Before witness is configured, commitments and attestations have no deposit to take.
	let mut fresh = Chain { now: 100, ..Default::default() };
	fresh.mint(ALICE, 1000);
	fresh.mint(BOB, 100);
	let terms = fresh.terms();
	fresh.create(terms).unwrap();
	assert_eq!(fresh.commit(0, BOB, b"x"), Err("witness is not configured"));
	assert_eq!(fresh.attest(&[GOOD1], &[]), Err("witness is not configured"));
}

#[test]
fn admin_actions_wait_out_the_delay() {
	let mut c = setup();
	assert_eq!(c.config(), Some(test_config()), "the first configuration applies at once");
	let stricter = Config { commit_deposit: 20, ..test_config() };
	c.propose(AdminAction::Configure(stricter.clone())).unwrap(); // proposal 0
	assert_eq!(c.config(), Some(test_config()), "later ones wait");
	assert_eq!(c.submit(Op::Apply { id: 0 }), Err("proposal not yet effective"));
	c.advance(ADMIN_DELAY - 1);
	assert_eq!(c.submit(Op::Apply { id: 0 }), Err("proposal not yet effective"));
	c.advance(1);
	c.submit(Op::Apply { id: 0 }).unwrap();
	assert_eq!(c.config(), Some(stricter));
	assert_eq!(c.submit(Op::Apply { id: 0 }), Err("no such proposal"));

	// Only the admin proposes or cancels.
	let action = AdminAction::SetAdmin(id(MALLORY));
	let nonce = c.account(MALLORY).nonce;
	let signature = key(MALLORY).sign(&witness_types::propose_message(SERVICE, &id(MALLORY), nonce, &action));
	let op = Op::Propose { admin: id(MALLORY), nonce, action, signature: signature.to_bytes() };
	assert_eq!(c.submit(op), Err("not the admin"));

	// A cancelled proposal never applies.
	c.propose(AdminAction::SetAdmin(id(CAROL))).unwrap(); // proposal 1
	let nonce = c.nonce_of(&BUILD_ADMIN);
	let signature = admin_key().sign(&witness_types::cancel_message(SERVICE, &BUILD_ADMIN, nonce, 1));
	c.submit(Op::Cancel { admin: BUILD_ADMIN, nonce, id: 1, signature: signature.to_bytes() }).unwrap();
	c.advance(ADMIN_DELAY);
	assert_eq!(c.submit(Op::Apply { id: 1 }), Err("no such proposal"));

	// Handing the role on: the new admin proposes, the old one no longer can.
	c.propose(AdminAction::SetAdmin(id(CAROL))).unwrap(); // proposal 2
	c.advance(ADMIN_DELAY);
	c.submit(Op::Apply { id: 2 }).unwrap();
	assert_eq!(c.propose(AdminAction::SetAdmin(BUILD_ADMIN)), Err("not the admin"));
	let action = AdminAction::Upgrade { code_hash: [5; 32], code_len: 1000 };
	let nonce = c.account(CAROL).nonce;
	let signature = key(CAROL).sign(&witness_types::propose_message(SERVICE, &id(CAROL), nonce, &action));
	c.submit(Op::Propose { admin: id(CAROL), nonce, action, signature: signature.to_bytes() }).unwrap(); // 3
	assert_eq!(c.solicited, vec![([5; 32], 1000)], "an upgrade solicits its code when proposed");
	assert!(c.upgraded.is_empty());
	c.advance(ADMIN_DELAY);
	c.submit(Op::Apply { id: 3 }).unwrap();
	assert_eq!(c.upgraded, vec![[5; 32]]);
}
