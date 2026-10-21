use super::*;
use alloc::{collections::BTreeMap, vec};
use ed25519_dalek::{Signer, SigningKey};
use witness_types::{BountyTerms, CHECK_INTERFACE_VERSION, CheckFailure, check_args, commitment};

const SERVICE: u32 = 7;
const CHECK: Hash = [0xc0; 32];
/// Another check, with the same mock behaviour.
const OTHER_CHECK: Hash = [0xc1; 32];
const BLOB: &[u8] = b"check blob";
/// Extra blobs the environment can look up. The mock check attests those starting "good".
const EXTRA: [(Hash, &[u8]); 5] = [
	([0xe1; 32], b"one"),
	([0xe2; 32], b"two"),
	([0xa1; 32], b"good one"),
	([0xa2; 32], b"good two"),
	([0xa3; 32], b"bad"),
];
const GOOD1: usize = 2;
const GOOD2: usize = 3;
const BAD: usize = 4;
const MISSING: Hash = [0xee; 32];

fn extra(i: usize) -> Preimage {
	Preimage { hash: EXTRA[i].0, len: EXTRA[i].1.len() as u32 }
}

fn plain(i: usize) -> BlobRef {
	BlobRef::Blob(extra(i))
}

/// The mock check:
/// - in reveal mode, accepts witness `b"x"`; a witness equal to its blobs' data concatenated;
///   or witness `b"trusted"` if it was given blobs and all of them are trusted;
/// - in attest mode, accepts a subject (the last blob, untrusted) starting with `b"good"`, if
///   every other blob is trusted.
struct Env {
	blob_available: bool,
}

/// Split `args` (see `check_args`) into the mode, the blobs (trusted, data) and the witness.
fn parse_args(args: &[u8]) -> (u8, Vec<(bool, Vec<u8>)>, Vec<u8>) {
	let u32_at = |at: usize| u32::from_le_bytes(args[at..at + 4].try_into().unwrap()) as usize;
	assert_eq!(args[0], CHECK_INTERFACE_VERSION);
	let mut at = 6;
	let blobs = (0..u32_at(2))
		.map(|_| {
			let trusted = args[at] == 1;
			let len = u32_at(at + 33);
			at += 37 + len;
			(trusted, args[at - len..at].to_vec())
		})
		.collect();
	(args[1], blobs, args[at + 4 + u32_at(at)..].to_vec())
}

impl RefineEnv for Env {
	fn lookup(&self, hash: &Hash) -> Option<Vec<u8>> {
		if *hash == CHECK || *hash == OTHER_CHECK {
			return self.blob_available.then(|| BLOB.to_vec());
		}
		EXTRA.iter().find(|(h, _)| h == hash).map(|(_, data)| data.to_vec())
	}
	fn run_check(&self, blob: &[u8], args: &[u8], _gas: Gas) -> core::result::Result<(), Rejection> {
		assert_eq!(blob, BLOB);
		let (mode, blobs, witness) = parse_args(args);
		let data: Vec<u8> = blobs.iter().flat_map(|(_, d)| d.clone()).collect();
		let accept = if mode == CheckMode::Attest as u8 {
			assert!(witness.is_empty());
			let (subject, parents) = blobs.split_last().unwrap();
			!subject.0 && parents.iter().all(|(t, _)| *t) && subject.1.starts_with(b"good")
		} else {
			witness == b"x" ||
				(!blobs.is_empty() && witness == data) ||
				(!blobs.is_empty() && witness == b"trusted" && blobs.iter().all(|(t, _)| *t))
		};
		if accept { Ok(()) } else { Err(Rejection::CheckFailed(CheckFailure::False)) }
	}
}

const ENV: Env = Env { blob_available: true };

#[derive(Default)]
struct Chain {
	storage: BTreeMap<Vec<u8>, Vec<u8>>,
	solicited: Vec<Hash>,
	forgotten: Vec<Hash>,
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

const ALICE: u8 = 1;
const BOB: u8 = 2;
const CAROL: u8 = 3;
const MALLORY: u8 = 4;

impl Chain {
	/// Refine and accumulate `op` at the current slot.
	fn submit(&mut self, op: Op) -> Result<()> {
		let verified = refine(&ENV, SERVICE, op);
		let fx = accumulate(self, verified, self.now)?;
		self.solicited.extend(fx.solicit.iter().map(|(h, _)| *h));
		for (k, v) in fx.writes {
			match v {
				Some(v) => self.storage.insert(k, v),
				None => self.storage.remove(&k),
			};
		}
		self.forgotten.extend(fx.forget.iter().map(|(h, _)| *h));
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
			blobs: vec![],
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

	/// `blobs` as a reveal names them, with the claims of attested ones.
	fn reveal_blobs(&self, blobs: &[BlobRef]) -> Vec<RevealBlob> {
		blobs
			.iter()
			.map(|b| match b {
				BlobRef::Blob(p) => RevealBlob::Blob(*p),
				BlobRef::Attested(id) => RevealBlob::Attested(self.claims[id].clone()),
			})
			.collect()
	}

	fn reveal(&mut self, b: BountyId, hunter: u8, w: &[u8]) -> Result<()> {
		self.reveal_with(b, hunter, w, vec![])
	}

	/// Reveal, adding the attested layers `extra` after the bounty's chain.
	fn reveal_with(&mut self, b: BountyId, hunter: u8, w: &[u8], extra: Vec<AttestationClaim>) -> Result<()> {
		self.submit(self.reveal_op(b, hunter, w, extra))
	}

	fn reveal_op(&self, b: BountyId, hunter: u8, w: &[u8], extra: Vec<AttestationClaim>) -> Op {
		let terms = self.bounty(b).terms;
		Op::Reveal {
			bounty_id: b,
			check_hash: terms.check_hash,
			params: terms.params,
			blobs: self.reveal_blobs(&terms.blobs),
			extra,
			check_gas: terms.check_gas,
			hunter: id(hunter),
			salt: [hunter; 32],
			witness: w.to_vec(),
		}
	}

	fn pin(&mut self, owner: u8, blob: Preimage) -> Result<()> {
		let nonce = self.account(owner).nonce;
		let msg = witness_types::pin_message(SERVICE, &id(owner), nonce, &blob);
		let signature = key(owner).sign(&msg).to_bytes();
		self.submit(Op::Pin { owner: id(owner), nonce, blob, signature })
	}

	/// The op for `attester` to attest `subject` with `check` and params `b"layer"` after the
	/// chain `ancestors`, and its claim.
	fn attest_op(
		&self,
		attester: u8,
		check: Hash,
		subject: Preimage,
		ancestors: &[AttestationClaim],
	) -> (Op, AttestationClaim) {
		self.attest_op_with_params(attester, check, b"layer", subject, ancestors)
	}

	fn attest_op_with_params(
		&self,
		attester: u8,
		check: Hash,
		params: &[u8],
		subject: Preimage,
		ancestors: &[AttestationClaim],
	) -> (Op, AttestationClaim) {
		let claim = AttestationClaim {
			check_hash: check,
			params_hash: blake2b256(params),
			subject,
			parent: ancestors.last().map(AttestationClaim::id),
		};
		let nonce = self.account(attester).nonce;
		let msg = witness_types::attest_message(SERVICE, &id(attester), nonce, &claim.id());
		let op = Op::Attest {
			attester: id(attester),
			nonce,
			check_hash: check,
			params: params.to_vec(),
			subject,
			ancestors: ancestors.to_vec(),
			check_gas: 1000,
			signature: key(attester).sign(&msg).to_bytes(),
		};
		(op, claim)
	}

	/// `attester` attests `subject` with `check` after `ancestors`; returns the claim it made.
	fn attest_with(
		&mut self,
		attester: u8,
		check: Hash,
		subject: Preimage,
		ancestors: &[AttestationClaim],
	) -> Result<AttestationClaim> {
		let (op, claim) = self.attest_op(attester, check, subject, ancestors);
		self.submit(op)?;
		self.claims.insert(claim.id(), claim.clone());
		Ok(claim)
	}

	/// What refine makes of `subject` attested by Carol with the bounty check after `ancestors`.
	fn refine_attest(&self, subject: Preimage, ancestors: &[AttestationClaim]) -> Verified {
		refine(&ENV, SERVICE, self.attest_op(CAROL, CHECK, subject, ancestors).0)
	}

	fn attest(&mut self, subject: Preimage, ancestors: &[AttestationClaim]) -> Result<AttestationClaim> {
		self.attest_with(CAROL, CHECK, subject, ancestors)
	}

	fn refs(&self, h: Hash) -> Option<u32> {
		self.get_typed(&StorageKey::PreimageRefs(h))
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
	assert_eq!(c.solicited, vec![CHECK], "a shared check is solicited once");

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
	let op = Op::Reveal {
		bounty_id: 0,
		check_hash: CHECK,
		params: op_terms.params,
		blobs: vec![],
		extra: vec![],
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
		blobs: vec![],
		extra: vec![],
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
fn blobs_are_solicited_and_released_with_the_bounty() {
	let mut c = with_blobs();
	assert_eq!(c.solicited, vec![CHECK, EXTRA[0].0, EXTRA[1].0]);
	// Bounty 2 shares blob 0 (twice) with bounty 1, and adds nothing new.
	let mut terms = c.terms();
	terms.blobs = vec![plain(0), plain(0)];
	terms.reward = 100;
	c.create(terms).unwrap();
	assert_eq!(c.solicited.len(), 3, "shared blobs are solicited once");
	let refs = |c: &Chain, h| c.get_typed::<u32>(&StorageKey::PreimageRefs(h));
	assert_eq!(refs(&c, EXTRA[0].0), Some(3));
	assert_eq!(refs(&c, CHECK), Some(3));

	// Bounty 1 finishes: blob 1 is no longer used, blob 0 and the check still are.
	c.commit(1, BOB, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	c.reveal(1, BOB, b"x").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(1).unwrap();
	assert_eq!(c.forgotten, vec![EXTRA[1].0]);
	assert_eq!(refs(&c, EXTRA[0].0), Some(2));

	// Bounties 0 and 2 run out unclaimed; everything is released.
	let expiry = c.bounty(2).terms.expiry;
	c.advance(expiry + REVEAL_GRACE - c.now);
	c.reclaim(0).unwrap();
	c.reclaim(2).unwrap();
	assert_eq!(c.forgotten, vec![EXTRA[1].0, CHECK, EXTRA[0].0]);
	assert_eq!(refs(&c, EXTRA[0].0), None);
	assert_eq!(refs(&c, CHECK), None);
}

#[test]
fn reveal_must_name_the_bounty_blobs() {
	let mut c = with_blobs();
	c.commit(1, BOB, b"x").unwrap();
	c.advance(MIN_COMMIT_AGE);
	let terms = c.bounty(1).terms;
	let b = |i| RevealBlob::Blob(extra(i));
	for blobs in [vec![], vec![b(1), b(0)], vec![b(0)]] {
		let op = Op::Reveal {
			bounty_id: 1,
			check_hash: CHECK,
			params: terms.params.clone(),
			blobs,
			extra: vec![],
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
	let reveal = |blobs| Op::Reveal {
		bounty_id: 0,
		check_hash: CHECK,
		params: vec![],
		blobs,
		extra: vec![],
		check_gas: 1,
		hunter: id(BOB),
		salt: [0; 32],
		witness: b"x".to_vec(),
	};
	let missing = RevealBlob::Blob(Preimage { hash: MISSING, len: 1 });
	let one = RevealBlob::Blob(extra(0));
	assert_eq!(refine(&ENV, SERVICE, reveal(vec![one.clone(), missing])), Verified::Rejected(Rejection::BlobUnavailable));
	let too_many = vec![one; MAX_BLOBS as usize + 1];
	assert_eq!(refine(&ENV, SERVICE, reveal(too_many)), Verified::Rejected(Rejection::BlobsTooLarge));

	let mut c = setup();
	let mut terms = c.terms();
	terms.blobs = vec![plain(0); MAX_BLOBS as usize + 1];
	assert_eq!(c.create(terms), Err("blobs too large"));
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Blob(Preimage { hash: MISSING, len: MAX_BLOBS_LEN / 2 + 1 }); 2];
	assert_eq!(c.create(terms), Err("blobs too large"));
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Blob(Preimage { hash: MISSING, len: MAX_BLOBS_LEN / 2 }); 2];
	terms.reward = 100;
	c.create(terms).unwrap();
}

#[test]
fn pins_hold_a_preimage_for_good() {
	let mut c = setup();
	c.pin(CAROL, extra(GOOD1)).unwrap();
	assert_eq!(c.solicited, vec![CHECK, EXTRA[GOOD1].0]);
	assert_eq!(c.account(CAROL), Account { balance: 100 - PIN_DEPOSIT, nonce: 1 });
	// Pinning the check too keeps it once bounty 0 is over.
	c.pin(CAROL, Preimage { hash: CHECK, len: BLOB.len() as u32 }).unwrap();
	assert_eq!(c.refs(CHECK), Some(2));
	let expiry = c.bounty(0).terms.expiry;
	c.advance(expiry + REVEAL_GRACE - c.now);
	c.reclaim(0).unwrap();
	assert_eq!(c.refs(CHECK), Some(1));
	assert!(c.forgotten.is_empty());

	let too_big = Preimage { hash: MISSING, len: MAX_BLOBS_LEN + 1 };
	assert_eq!(c.pin(CAROL, too_big), Err("blob too large"));
	let forged = Op::Pin { owner: id(CAROL), nonce: 2, blob: extra(0), signature: key(MALLORY).sign(b"x").to_bytes() };
	assert_eq!(refine(&ENV, SERVICE, forged), Verified::Rejected(Rejection::BadSignature));
}

#[test]
fn attesting_a_layer() {
	let mut c = setup();
	let claim = c.attest(extra(GOOD1), &[]).unwrap();
	let recorded: Attestation = c.get_typed(&StorageKey::Attestation(claim.id())).unwrap();
	assert_eq!(recorded, Attestation { claim: claim.clone(), slot: c.now, attester: id(CAROL) });
	assert_eq!(c.account(CAROL), Account { balance: 100 - ATTEST_DEPOSIT, nonce: 1 });
	assert_eq!(c.refs(EXTRA[GOOD1].0), Some(1), "the subject is held for good");

	assert_eq!(c.attest(extra(GOOD1), &[]), Err("already attested"));
	assert_eq!(c.account(CAROL).balance, 100 - ATTEST_DEPOSIT, "nothing charged twice");
	let rejected = |f| Verified::Rejected(Rejection::CheckFailed(f));
	assert_eq!(c.refine_attest(extra(BAD), &[]), rejected(CheckFailure::False), "the check says no");
	let missing = Preimage { hash: MISSING, len: 1 };
	assert_eq!(c.refine_attest(missing, &[]), Verified::Rejected(Rejection::BlobUnavailable));
	// The signature covers the claim, so it can't be replayed for another subject.
	let (Op::Attest { signature, .. }, _) = c.attest_op(CAROL, CHECK, extra(GOOD2), &[]) else { unreachable!() };
	let (Op::Attest { attester, nonce, check_hash, params, subject, ancestors, check_gas, .. }, _) =
		c.attest_op(CAROL, CHECK, extra(GOOD1), &[])
	else {
		unreachable!()
	};
	let replayed = Op::Attest { attester, nonce, check_hash, params, subject, ancestors, check_gas, signature };
	assert_eq!(refine(&ENV, SERVICE, replayed), Verified::Rejected(Rejection::BadSignature));
}

#[test]
fn attesting_on_a_chain() {
	let mut c = setup();
	let layer1 = c.attest(extra(GOOD1), &[]).unwrap();
	let layer2 = c.attest(extra(GOOD2), &[layer1.clone()]).unwrap();
	assert_eq!(layer2.parent, Some(layer1.id()));
	assert_ne!(layer2.id(), c.attest(extra(GOOD2), &[]).unwrap().id(), "other foundations, other id");
	// A third layer names the whole chain, oldest first.
	let layer3 = c.attest(extra(GOOD1), &[layer1.clone(), layer2.clone()]).unwrap();
	assert_eq!(layer3.parent, Some(layer2.id()));

	// The chain must run from its root, each claim following the one before.
	let broken = Verified::Rejected(Rejection::BrokenChain);
	assert_eq!(c.refine_attest(extra(GOOD1), &[layer2.clone()]), broken, "doesn't start at a root");
	assert_eq!(c.refine_attest(extra(GOOD1), &[layer2.clone(), layer1.clone()]), broken, "out of order");
	assert_eq!(c.refine_attest(extra(GOOD1), &[layer1.clone(), layer3.clone()]), broken, "a layer skipped");

	// A parent nobody attested: refine runs the check on the claimed subject, and accumulate
	// finds no such record.
	let made_up = AttestationClaim { check_hash: CHECK, params_hash: blake2b256(b"layer"), subject: extra(BAD), parent: None };
	assert_eq!(c.attest(extra(GOOD2), &[made_up]), Err("no such parent attestation"));
	// A parent by another check is refused outright, recorded or not.
	let foreign = c.attest_with(CAROL, OTHER_CHECK, extra(GOOD1), &[]).unwrap();
	assert_eq!(c.refine_attest(extra(GOOD2), &[foreign]), Verified::Rejected(Rejection::ForeignAttestation));
	// So is a parent attested with other params, which might have been more lenient.
	let (op, lenient) = c.attest_op_with_params(CAROL, CHECK, b"lenient", extra(GOOD1), &[]);
	c.submit(op).unwrap();
	assert_eq!(c.refine_attest(extra(GOOD2), &[lenient]), Verified::Rejected(Rejection::ForeignAttestation));
	let too_many = vec![layer1; MAX_BLOBS as usize];
	assert_eq!(c.refine_attest(extra(GOOD2), &too_many), Verified::Rejected(Rejection::BlobsTooLarge));
}

/// Bounty 1 cites a two-layer chain attested by its check; bounty 2 another check's attestation.
fn with_attested_blobs() -> (Chain, AttestationClaim, AttestationClaim) {
	let mut c = setup();
	let layer1 = c.attest(extra(GOOD1), &[]).unwrap();
	let layer2 = c.attest(extra(GOOD2), &[layer1.clone()]).unwrap();
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Attested(layer1.id()), BlobRef::Attested(layer2.id())];
	terms.reward = 100;
	c.create(terms).unwrap();
	(c, layer1, layer2)
}

#[test]
fn bounties_cite_attested_blobs_as_trusted() {
	let (mut c, layer1, _) = with_attested_blobs();
	assert_eq!(c.solicited, vec![CHECK, EXTRA[GOOD1].0, EXTRA[GOOD2].0]);
	assert_eq!(c.refs(EXTRA[GOOD1].0), Some(1), "a citing bounty adds no hold");
	c.commit(1, BOB, b"trusted").unwrap();
	c.advance(MIN_COMMIT_AGE);
	c.reveal(1, BOB, b"trusted").unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(1).unwrap();
	assert_eq!(c.winner(1), id(BOB));
	assert!(c.forgotten.is_empty(), "attested subjects stay");

	// A bounty can mix plain and attested blobs; a plain one is never trusted.
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Attested(layer1.id()), plain(0)];
	terms.reward = 100;
	c.create(terms).unwrap(); // bounty 2
	c.commit(2, BOB, b"trusted").unwrap();
	c.advance(MIN_COMMIT_AGE);
	assert_eq!(c.reveal(2, BOB, b"trusted"), Err("rejected in refine"));
}

#[test]
fn bounties_cite_only_their_own_check_attestations() {
	let (mut c, layer1, _) = with_attested_blobs();
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Attested([9; 32])];
	assert_eq!(c.create(terms), Err("no such attestation"));
	let foreign = c.attest_with(CAROL, OTHER_CHECK, extra(GOOD1), &[]).unwrap();
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Attested(foreign.id())];
	assert_eq!(c.create(terms), Err("attested by another check"));

	// At reveal, a claim by another check is refused in refine, and so is an attested blob after
	// a plain one. A shorter chain is a chain, but not the bounty's.
	c.commit(1, BOB, b"trusted").unwrap();
	c.advance(MIN_COMMIT_AGE);
	let reveal = |blobs| Op::Reveal {
		bounty_id: 1,
		check_hash: CHECK,
		params: b"params".to_vec(),
		blobs,
		extra: vec![],
		check_gas: 1000,
		hunter: id(BOB),
		salt: [BOB; 32],
		witness: b"x".to_vec(),
	};
	let BlobRef::Attested(layer2_id) = c.bounty(1).terms.blobs[1] else { unreachable!() };
	let layer2 = c.claims[&layer2_id].clone();
	let foreign_blob = RevealBlob::Attested(foreign);
	assert_eq!(refine(&ENV, SERVICE, reveal(vec![foreign_blob])), Verified::Rejected(Rejection::ForeignAttestation));
	let as_plain = vec![RevealBlob::Blob(layer1.subject), RevealBlob::Attested(layer2)];
	assert_eq!(refine(&ENV, SERVICE, reveal(as_plain)), Verified::Rejected(Rejection::BrokenChain));
	let shorter = vec![RevealBlob::Attested(layer1)];
	assert_eq!(c.submit(reveal(shorter)), Err("revealed against different terms"));
}

#[test]
fn bounties_cite_one_chain_from_its_root() {
	let (mut c, layer1, layer2) = with_attested_blobs();
	let cite = |c: &mut Chain, blobs| {
		let mut terms = c.terms();
		terms.blobs = blobs;
		terms.reward = 10;
		c.create(terms)
	};
	let a = |claim: &AttestationClaim| BlobRef::Attested(claim.id());
	// Layer 2 was verified right after layer 1, so it's only trusted there.
	let not_chain = Err("attested blobs are not one chain");
	assert_eq!(cite(&mut c, vec![a(&layer2)]), not_chain, "without its chain");
	assert_eq!(cite(&mut c, vec![a(&layer2), a(&layer1)]), not_chain, "out of order");
	assert_eq!(cite(&mut c, vec![plain(0), a(&layer1)]), not_chain, "after a plain blob");
	// Another root's chain can't be spliced in either.
	let other_root = c.attest(extra(GOOD2), &[]).unwrap();
	assert_eq!(cite(&mut c, vec![a(&other_root), a(&layer2)]), not_chain);
	assert_eq!(cite(&mut c, vec![a(&layer1), a(&layer2), plain(0)]), Ok(()));
	assert_eq!(cite(&mut c, vec![a(&layer1)]), Ok(()), "a chain can stop early");
}

#[test]
fn reveals_extend_the_bounty_chain() {
	let mut c = setup();
	let layer1 = c.attest(extra(GOOD1), &[]).unwrap();
	let layer2 = c.attest(extra(GOOD2), &[layer1.clone()]).unwrap();
	let mut terms = c.terms();
	terms.blobs = vec![BlobRef::Attested(layer1.id()), plain(0)];
	terms.reward = 100;
	c.create(terms).unwrap(); // bounty 1
	c.commit(1, BOB, b"trusted").unwrap();
	c.commit(1, CAROL, b"good onegood twoone").unwrap();
	c.advance(MIN_COMMIT_AGE);

	let refined = |c: &Chain, extra| refine(&ENV, SERVICE, c.reveal_op(1, CAROL, b"good onegood twoone", extra));
	// Extra layers must continue the bounty's chain, by its check and params.
	let other_root = c.attest(extra(GOOD2), &[]).unwrap();
	assert_eq!(refined(&c, vec![other_root]), Verified::Rejected(Rejection::BrokenChain));
	let (_, lenient) = c.attest_op_with_params(CAROL, CHECK, b"lenient", extra(GOOD2), &[layer1.clone()]);
	assert_eq!(refined(&c, vec![lenient]), Verified::Rejected(Rejection::ForeignAttestation));
	let (_, unrecorded) = c.attest_op(CAROL, CHECK, extra(GOOD1), &[layer1.clone(), layer2.clone()]);
	// That one's data passes the check, so accumulate is what refuses it.
	let witness = b"good onegood twogood oneone";
	assert_eq!(c.reveal_with(1, CAROL, witness, vec![layer2.clone(), unrecorded]), Err("no such attestation"));

	// The check gets the chain, then the extra layers, both trusted, then the plain blob. So
	// Carol's witness (all the data in that order) passes, and so would Bob's, if the plain
	// blob were trusted, which it isn't.
	assert_eq!(c.reveal_with(1, BOB, b"trusted", vec![layer2.clone()]), Err("rejected in refine"));
	c.reveal_with(1, CAROL, b"good onegood twoone", vec![layer2]).unwrap();
	c.advance(MIN_CLAIM_WINDOW);
	c.finalize(1).unwrap();
	assert_eq!(c.winner(1), id(CAROL));
}
