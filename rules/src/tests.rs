use super::*;
use alloc::{collections::BTreeMap, vec};
use ed25519_dalek::{Signer, SigningKey};
use witness_types::{BountyTerms, check_args, commitment};

const SERVICE: u32 = 7;
const CHECK: Hash = [0xc0; 32];
const BLOB: &[u8] = b"check blob";

/// The mock check accepts witness `b"x"` (any params).
struct Env {
	blob_available: bool,
}

impl RefineEnv for Env {
	fn lookup(&self, hash: &Hash) -> Option<Vec<u8>> {
		(self.blob_available && *hash == CHECK).then(|| BLOB.to_vec())
	}
	fn run_check(&self, blob: &[u8], args: &[u8], _gas: Gas) -> core::result::Result<(), Rejection> {
		assert_eq!(blob, BLOB);
		let witness = &args[4 + u32::from_le_bytes(args[..4].try_into().unwrap()) as usize..];
		if witness == b"x" { Ok(()) } else { Err(Rejection::CheckFailed(witness_types::CheckFailure::False)) }
	}
}

const ENV: Env = Env { blob_available: true };

#[derive(Default)]
struct Chain {
	storage: BTreeMap<Vec<u8>, Vec<u8>>,
	solicited: Vec<Hash>,
	forgotten: Vec<Hash>,
	now: Slot,
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

const ALICE: u8 = 1;
const BOB: u8 = 2;
const CAROL: u8 = 3;
const MALLORY: u8 = 4;

impl Chain {
	/// Refine and accumulate `op` at the current slot.
	fn submit(&mut self, op: Op) -> Result<()> {
		let verified = refine(&ENV, SERVICE, op);
		let fx = accumulate(self, verified, self.now)?;
		if let Some((h, _)) = fx.solicit {
			self.solicited.push(h);
		}
		for (k, v) in fx.writes {
			match v {
				Some(v) => self.storage.insert(k, v),
				None => self.storage.remove(&k),
			};
		}
		if let Some((h, _)) = fx.forget {
			self.forgotten.push(h);
		}
		Ok(())
	}

	fn advance(&mut self, slots: Slot) {
		self.now += slots;
	}

	fn account(&self, seed: u8) -> Account {
		self.get_typed(&StorageKey::Account(id(seed))).unwrap_or_default()
	}

	fn bounty(&self, id: BountyId) -> Bounty {
		self.get_typed(&StorageKey::Bounty(id)).unwrap()
	}

	fn get_typed<T: Decode>(&self, key: &StorageKey) -> Option<T> {
		self.storage.get(&key.encode()).map(|v| T::decode(&mut &v[..]).unwrap())
	}

	fn mint(&mut self, seed: u8, amount: Points) {
		self.submit(Op::Mint { to: id(seed), amount }).unwrap();
	}

	fn terms(&self) -> BountyTerms {
		BountyTerms {
			check_hash: CHECK,
			check_len: BLOB.len() as u32,
			params: b"params".to_vec(),
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
		let nonce = self.account(committer).nonce;
		let msg = witness_types::commit_message(SERVICE, b, &id(committer), nonce, &c);
		let signature = key(committer).sign(&msg).to_bytes();
		self.submit(Op::Commit { bounty_id: b, committer: id(committer), nonce, commitment: c, signature })?;
		Ok(c)
	}

	fn commit(&mut self, b: BountyId, hunter: u8, w: &[u8]) -> Result<Hash> {
		self.commit_for(b, hunter, hunter, w)
	}

	fn reveal(&mut self, b: BountyId, hunter: u8, w: &[u8]) -> Result<()> {
		let terms = self.bounty(b).terms;
		self.submit(Op::Reveal {
			bounty_id: b,
			check_hash: terms.check_hash,
			params: terms.params,
			check_gas: terms.check_gas,
			hunter: id(hunter),
			salt: [hunter; 32],
			witness: w.to_vec(),
		})
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

/// Alice has a bounty 0 open; Bob, Carol and Mallory have points for deposits.
fn setup() -> Chain {
	let mut c = Chain { now: 100, ..Default::default() };
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
	assert_eq!(c.solicited, vec![CHECK]);

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
	assert_eq!(c.forgotten, vec![CHECK], "check blob forgotten once no bounty uses it");
	assert_eq!(c.finalize(0), Err("bounty not revealing"));
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
	assert_eq!(c.solicited, vec![CHECK], "a shared check is solicited once");

	// Not committed, wrong bounty, too recent.
	assert_eq!(c.reveal(0, BOB, b"x"), Err("no commitment"));
	c.commit(1, BOB, b"x").unwrap();
	let c0 = commitment(0, b"x", &id(BOB), &[BOB; 32]);
	assert!(c.get_typed::<CommitRecord>(&StorageKey::Commitment(c0)).is_none());
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
	let op = Op::Reveal {
		bounty_id: 0,
		check_hash: CHECK,
		params: op_terms.params,
		check_gas: op_terms.check_gas,
		hunter: id(BOB),
		salt: [BOB; 32],
		witness: b"x".to_vec(),
	};
	assert_eq!(c.submit(op), Err("revealed against different terms"));

	// The same commitment cannot be revealed twice.
	c.reveal(0, BOB, b"x").unwrap();
	assert_eq!(c.reveal(0, BOB, b"x"), Err("no commitment"));
}

#[test]
fn check_unavailable_is_rejected_in_refine() {
	let op = Op::Reveal {
		bounty_id: 0,
		check_hash: CHECK,
		params: vec![],
		check_gas: 1,
		hunter: id(BOB),
		salt: [0; 32],
		witness: b"x".to_vec(),
	};
	let env = Env { blob_available: false };
	assert_eq!(refine(&env, SERVICE, op), Verified::Rejected(Rejection::CheckUnavailable));
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
	assert_eq!(c.commit(0, broke, b"x"), Err("insufficient points"));

	// A forged signature is caught in refine.
	let forged = Op::Commit {
		bounty_id: 0,
		committer: id(CAROL),
		nonce: 0,
		commitment: [1; 32],
		signature: key(MALLORY).sign(b"anything").to_bytes(),
	};
	assert_eq!(refine(&ENV, SERVICE, forged), Verified::Rejected(Rejection::BadSignature));

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
	assert_eq!(c.forgotten, vec![CHECK]);
	assert_eq!(c.reclaim(0), Err("bounty not open"));
}

#[test]
fn release_rules() {
	let mut c = setup();
	let unrevealed = c.commit(0, CAROL, b"x").unwrap();
	assert_eq!(c.submit(Op::Release { commitment: unrevealed }), Err("commitment can still be revealed"));
	c.commit(0, BOB, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	c.reveal(0, BOB, b"x").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	// The window has closed, so Carol's commitment is dead weight; anyone may delete it.
	c.submit(Op::Release { commitment: unrevealed }).unwrap();
	assert!(c.get_typed::<CommitRecord>(&StorageKey::Commitment(unrevealed)).is_none());
	assert_eq!(c.account(CAROL).balance, 100 - COMMIT_DEPOSIT, "forfeit deposit stays forfeit");
	assert_eq!(c.submit(Op::Release { commitment: unrevealed }), Err("no commitment"));
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
	assert_eq!(c.create(terms), Err("insufficient points"));
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
		Verified::Release { commitment: [0; 32] },
		Verified::Rejected(Rejection::BadPayload),
	] {
		assert!(accumulate(&c, v, c.now).is_err());
	}
}

#[test]
fn check_args_layout() {
	let args = check_args(b"pp", b"xyz");
	assert_eq!(args, [2, 0, 0, 0, b'p', b'p', b'x', b'y', b'z']);
}
