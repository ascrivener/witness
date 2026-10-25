//! Builds witness work-item payloads and prints them as hex, for
//! `scripts/jam-submit.py <service> 0x...` (or `jamt item`, for ops without extrinsics).
//! Reveals and attestations also write their work item's extrinsics, the blobs they name, as
//! files (`--extrinsics DIR`: `DIR/0`, `DIR/1`, ...), which jam-submit.py and witness-sim take
//! after the payload.
//!
//! Accounts are derived from a seed phrase (`--maker alice`): the Ed25519 secret key is
//! `blake2b256(seed)`. Fine for tests, not for anything of value. `token-*` commands build ops
//! for `mock-token-service`, the test token service.

use codec::{Decode, Encode};
use ed25519_dalek::{Signer, SigningKey};
use std::{collections::HashMap, process::ExitCode};
use mock_token::{BalanceKey, Holder, TokenOp};
use witness_types::{
	Citations,
	Account, AccountId, AdminAction, Amount, Asset, Attestation, AttestationClaim, AttestationId, BlobAt,
	BlobHash, BlobRef, Blobs, Bounty, BountyTerms, CommitRecord, Config, Hash, MIN_CLAIM_WINDOW, Op,
	Proposal, StorageKey, TEST_ASSET, TrustedRef, Verified, Witness, blake2b256, merkle,
};

/// The longest witness `attest` puts in the op itself; a longer one is an extrinsic.
const INLINE_WITNESS: usize = 1024;

const USAGE: &str = "\
usage: witness <command> [--flag value ...]

  account   --seed S
  hash      --check FILE          the hash of FILE, a check or a blob
  mint      --to S --amount N
  create    --service ID --maker S --nonce N --check FILE PARAMS [--blobs BLOBS] [--asset A]
            --reward N --check-gas G --expiry SLOT [--claim-window SLOTS]
  commit    --service ID --bounty ID --hunter S [--committer S] --nonce N --salt HEX WITNESS
  reveal    --bounty ID --check FILE PARAMS [--blobs BLOBS] [--trust REFS] --check-gas G
            --hunter S --salt HEX WITNESS --extrinsics DIR
            trusts the bounty's attested blobs, in order, then REFS
  finalize  --bounty ID
  reclaim   --service ID --bounty ID --maker S --nonce N
  release   --bounty ID --commitment HEX
  attest    --service ID --attester S --nonce N --check FILE [PARAMS] --subjects PATHS
            [--trust REFS] [WITNESS] --check-gas G --claim-out CLAIM --extrinsics DIR
            attests the files PATHS, in order, trusting REFS, and writes the claim and the
            subjects to CLAIM, for citing the attestation later
  withdraw  --service ID --account S --nonce N --asset A --amount N --to S
            pays out to account S (as a seed) of the asset's token service
  propose   --service ID [--admin S] --nonce N ACTION
            the admin (default seed: admin) proposes ACTION, applied at once if it's the first
            configuration, else by `apply` after the delay
  apply     --id N
  cancel    --service ID [--admin S] --nonce N --id N
  key       (--account S | --balance S --asset A | --bounty ID [--commitment HEX]
            | --attestation CLAIM | --config | --proposal N | --next)
            storage key, for `jamt inspect storage <service> <key>`
  decode    (--output HEX | --account HEX | --balance HEX | --bounty HEX | --commitment HEX
            | --attestation HEX | --config HEX | --proposal HEX)
            decode a refine output or a stored value

The test token service (mock-token-service):
  token-faucet  --to S --asset ID --amount N
  token-send    --from S --asset ID --amount N --to-service ID --to S
                moves tokens to a service, for its account S (witness's, say)
  token-key     (--account S | --service-holder ID) --asset ID
  token-decode  --balance HEX

PARAMS:  --params HEX | --params-str STRING | --params-u128 N | --params-blake2b STRING (its hash)
WITNESS: --witness HEX | --witness-str STRING | --witness-u64 N | --witness-file FILE
PATHS:   comma-separated file paths
BLOBS:   comma-separated, in order: CLAIM:ENTRY for subject ENTRY (from 0) of an attestation, or
         a path of a plain blob
REFS:    comma-separated CLAIM:ENTRY, for entry ENTRY (from 0) of the attestation whose claim
         `attest --claim-out` wrote to CLAIM
A:       SERVICE:ID, an asset of a token service; `test` for the faucet's (the default)
ACTION:  a configuration: [--token-services IDS] --fee-asset A --commit-deposit N --attest-deposit N
         | --set-admin S | --upgrade FILE (the new service blob)

Seeds S are any string; hex may have a 0x prefix. A salt of other than 32 bytes is hashed to 32.
The committer pays the commit deposit and signs; it defaults to the hunter.";

fn main() -> ExitCode {
	let mut args = std::env::args().skip(1).peekable();
	let Some(command) = args.next() else { return usage() };
	let mut flags = HashMap::new();
	while let Some(flag) = args.next() {
		let Some(name) = flag.strip_prefix("--") else { return usage() };
		// A flag followed by another flag, or by nothing, is a switch (`--config`).
		let value = match args.peek() {
			Some(next) if !next.starts_with("--") => args.next().unwrap(),
			_ => String::new(),
		};
		flags.insert(name.to_string(), value);
	}
	match run(&command, &Flags(flags)) {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			eprintln!("error: {e}\n\n{USAGE}");
			ExitCode::FAILURE
		},
	}
}

fn usage() -> ExitCode {
	eprintln!("{USAGE}");
	ExitCode::FAILURE
}

struct Flags(HashMap<String, String>);

impl Flags {
	fn has(&self, name: &str) -> bool {
		self.0.contains_key(name)
	}
	fn str(&self, name: &str) -> Result<&str, String> {
		self.0.get(name).map(String::as_str).ok_or_else(|| format!("missing --{name}"))
	}
	fn num<T: std::str::FromStr>(&self, name: &str) -> Result<T, String> {
		self.str(name)?.parse().map_err(|_| format!("--{name} is not a number"))
	}
	fn hex(&self, name: &str) -> Result<Vec<u8>, String> {
		from_hex(self.str(name)?).ok_or_else(|| format!("--{name} is not hex"))
	}
	fn hash(&self, name: &str) -> Result<Hash, String> {
		self.hex(name)?.try_into().map_err(|_| format!("--{name} must be 32 bytes"))
	}
	fn key(&self, name: &str) -> Result<SigningKey, String> {
		Ok(SigningKey::from_bytes(&blake2b256(self.str(name)?.as_bytes())))
	}
	fn account(&self, name: &str) -> Result<AccountId, String> {
		Ok(self.key(name)?.verifying_key().to_bytes())
	}
	fn params(&self) -> Result<Vec<u8>, String> {
		if self.has("params-str") {
			Ok(self.str("params-str")?.as_bytes().to_vec())
		} else if self.has("params-u128") {
			Ok(self.num::<u128>("params-u128")?.to_le_bytes().to_vec())
		} else if self.has("params-blake2b") {
			Ok(blake2b256(self.str("params-blake2b")?.as_bytes()).to_vec())
		} else {
			self.hex("params")
		}
	}
	fn witness(&self) -> Result<Vec<u8>, String> {
		if self.has("witness-u64") {
			Ok(self.num::<u64>("witness-u64")?.to_le_bytes().to_vec())
		} else if self.has("witness-str") {
			Ok(self.str("witness-str")?.as_bytes().to_vec())
		} else if self.has("witness-file") {
			read(self.str("witness-file")?)
		} else {
			self.hex("witness")
		}
	}
	fn salt(&self) -> Result<Hash, String> {
		let salt = self.hex("salt")?;
		Ok(<Hash>::try_from(&salt[..]).unwrap_or_else(|_| blake2b256(&salt)))
	}
	/// The `--check` blob, and its hash and length.
	fn check(&self) -> Result<(Hash, u32, Vec<u8>), String> {
		let data = read(self.str("check")?)?;
		let blob = blob_hash(&data);
		Ok((blob.hash, blob.len, data))
	}
	/// A comma-separated list flag, empty if absent.
	fn list(&self, name: &str) -> Result<Vec<&str>, String> {
		if !self.has(name) {
			return Ok(vec![]);
		}
		Ok(self.str(name)?.split(',').collect())
	}
	/// `--NAME` as an asset, `test` meaning the faucet's.
	fn asset(&self, name: &str) -> Result<Asset, String> {
		parse_asset(self.str(name)?)
	}
	/// `--NAME` as an asset, or the faucet's if absent.
	fn asset_or_test(&self, name: &str) -> Result<Asset, String> {
		if self.has(name) { self.asset(name) } else { Ok(TEST_ASSET) }
	}
	/// `--admin`, defaulting to the test builds' admin seed.
	fn admin(&self) -> Result<SigningKey, String> {
		if self.has("admin") { self.key("admin") } else { Ok(SigningKey::from_bytes(&blake2b256(b"admin"))) }
	}
	/// The admin action the flags describe.
	fn action(&self) -> Result<AdminAction, String> {
		if self.has("set-admin") {
			Ok(AdminAction::SetAdmin(self.account("set-admin")?))
		} else if self.has("upgrade") {
			let code = read(self.str("upgrade")?)?;
			Ok(AdminAction::Upgrade { code_hash: blake2b256(&code), code_len: code.len() as u32 })
		} else if self.has("fee-asset") {
			let token_services =
				self.list("token-services")?.into_iter().map(|s| s.parse().map_err(|_| format!("{s} is not a service id"))).collect::<Result<_, _>>()?;
			Ok(AdminAction::Configure(Config {
				token_services,
				fee_asset: Some(self.asset("fee-asset")?),
				commit_deposit: self.num("commit-deposit")?,
				attest_deposit: self.num("attest-deposit")?,
			}))
		} else {
			Err("an action: --fee-asset A ... (a configuration), --set-admin S or --upgrade FILE".into())
		}
	}
	/// The `--trust` references, as claims (with their subjects) and entries.
	fn trust(&self) -> Result<Vec<(Cited, u32)>, String> {
		self.list("trust")?
			.into_iter()
			.map(|r| claim_entry(r)?.ok_or_else(|| format!("{r} is not CLAIM:ENTRY")))
			.collect()
	}
	/// The `--blobs`, with the claims of the attested ones and the data of the plain ones.
	fn blobs(&self) -> Result<Vec<(BlobRef, Blob)>, String> {
		self.list("blobs")?
			.into_iter()
			.map(|blob| match claim_entry(blob)? {
				Some((cited, entry)) => {
					Ok((BlobRef::Attested { attestation: cited.0.id(), entry }, Blob::Attested(cited, entry)))
				},
				None => {
					let data = read(blob)?;
					Ok((BlobRef::Blob(blob_hash(&data)), Blob::Plain(data)))
				},
			})
			.collect()
	}
	fn extrinsics(&self) -> Result<&str, String> {
		self.str("extrinsics")
	}
}

/// What a claim file holds: an attestation's claim and its subjects, which citing it needs.
type Cited = (AttestationClaim, Blobs);

/// A blob of a bounty, as given to `--blobs`.
enum Blob {
	Attested(Cited, u32),
	Plain(Vec<u8>),
}

/// `CLAIM:ENTRY` as a claim and an entry, or `None` if it isn't of that form.
fn claim_entry(s: &str) -> Result<Option<(Cited, u32)>, String> {
	let Some((path, entry)) = s.rsplit_once(':') else { return Ok(None) };
	let Ok(entry) = entry.parse() else { return Ok(None) };
	Ok(Some((read_claim(path)?, entry)))
}

/// The claims and references for trusting `subjects`, each claim once, with the subjects added to
/// extrinsic `extrinsic`'s `blobs`.
fn cite(subjects: &[(Cited, u32)], extrinsic: u8, blobs: &mut Blobs) -> Result<(Vec<AttestationClaim>, Vec<TrustedRef>), String> {
	let mut ids: Vec<AttestationId> = Vec::new();
	let mut claims = Vec::new();
	let mut trusted = Vec::new();
	for ((claim, list), entry) in subjects {
		let id = claim.id();
		let i = ids.iter().position(|i| *i == id).unwrap_or_else(|| {
			ids.push(id);
			claims.push(claim.clone());
			ids.len() - 1
		});
		let subject = list.get(*entry as usize).ok_or_else(|| format!("the claim has no subject {entry}"))?;
		let leaves: Vec<Hash> = list.iter().map(|s| merkle::leaf(&blake2b256(s))).collect();
		let blob = BlobAt { extrinsic, index: blobs.len() as u32 };
		blobs.push(subject.clone());
		trusted.push(TrustedRef { claim: i as u16, entry: *entry, blob, path: merkle::path(&leaves, *entry as usize) });
	}
	Ok((claims, trusted))
}

/// Write an op's extrinsics to `dir`, as files `0`, `1`, ..., replacing what was there: the check
/// blob, whole, then `lists` of blobs, then the op's citations, whole, if it cites anything.
/// Returns the citations' extrinsic.
fn write_extrinsics(dir: &str, check: &[u8], lists: &[Blobs], citations: Citations) -> Result<Option<u8>, String> {
	let _ = std::fs::remove_dir_all(dir);
	std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {dir}: {e}"))?;
	write(&format!("{dir}/0"), check)?;
	for (i, blobs) in lists.iter().enumerate() {
		write(&format!("{dir}/{}", i + 1), &blobs.encode())?;
	}
	if citations.claims.is_empty() && citations.trusted.is_empty() {
		return Ok(None);
	}
	let at = lists.len() + 1;
	write(&format!("{dir}/{at}"), &citations.encode())?;
	Ok(Some(at as u8))
}

/// A witness of more than a few bytes goes in extrinsic `at` of its own, the next after the op's
/// others: a work package's payloads have little room.
fn extrinsic_witness(dir: &str, witness: Vec<u8>, at: u8) -> Result<Witness, String> {
	if witness.len() <= INLINE_WITNESS {
		return Ok(Witness::Inline(witness));
	}
	write(&format!("{dir}/{at}"), &witness)?;
	Ok(Witness::Extrinsic(at))
}

fn write(path: &str, data: &[u8]) -> Result<(), String> {
	std::fs::write(path, data).map_err(|e| format!("cannot write {path}: {e}"))
}

fn read(path: &str) -> Result<Vec<u8>, String> {
	std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn parse_asset(s: &str) -> Result<Asset, String> {
	if s == "test" {
		return Ok(TEST_ASSET);
	}
	let bad = || format!("{s} is not an asset: SERVICE:ID, or test");
	let (service, id) = s.split_once(':').ok_or_else(bad)?;
	Ok(Asset { service: service.parse().map_err(|_| bad())?, id: id.parse().map_err(|_| bad())? })
}

fn blob_hash(data: &[u8]) -> BlobHash {
	BlobHash { hash: blake2b256(data), len: data.len() as u32 }
}

fn read_claim(path: &str) -> Result<Cited, String> {
	Cited::decode(&mut &read(path)?[..]).map_err(|e| format!("{path} is not a claim: {e}"))
}

fn decode<T: Decode + std::fmt::Debug>(bytes: &[u8]) -> Result<String, String> {
	T::decode(&mut &bytes[..]).map(|v| format!("{v:?}")).map_err(|e| format!("cannot decode: {e}"))
}

fn run(command: &str, f: &Flags) -> Result<(), String> {
	let op = match command {
		"account" => {
			println!("0x{}", to_hex(&f.account("seed")?));
			return Ok(());
		},
		"hash" => {
			println!("0x{}", to_hex(&f.check()?.0));
			return Ok(());
		},
		"decode" => {
			let decoded = if f.has("account") {
				decode::<Account>(&f.hex("account")?)
			} else if f.has("bounty") {
				decode::<Bounty>(&f.hex("bounty")?)
			} else if f.has("commitment") {
				decode::<CommitRecord>(&f.hex("commitment")?)
			} else if f.has("attestation") {
				decode::<Attestation>(&f.hex("attestation")?)
			} else if f.has("balance") {
				decode::<Amount>(&f.hex("balance")?)
			} else if f.has("config") {
				decode::<Config>(&f.hex("config")?)
			} else if f.has("proposal") {
				decode::<Proposal>(&f.hex("proposal")?)
			} else {
				decode::<Verified>(&f.hex("output")?)
			}?;
			println!("{decoded}");
			return Ok(());
		},
		"key" => {
			let key = if f.has("balance") {
				StorageKey::Balance(f.account("balance")?, f.asset("asset")?)
			} else if f.has("account") {
				StorageKey::Account(f.account("account")?)
			} else if f.has("config") {
				StorageKey::Config
			} else if f.has("proposal") {
				StorageKey::Proposal(f.num("proposal")?)
			} else if f.has("commitment") {
				StorageKey::Commitment(f.num("bounty")?, f.hash("commitment")?)
			} else if f.has("bounty") {
				StorageKey::Bounty(f.num("bounty")?)
			} else if f.has("attestation") {
				StorageKey::Attestation(read_claim(f.str("attestation")?)?.0.id())
			} else {
				StorageKey::NextBountyId
			};
			println!("0x{}", to_hex(&key.encode()));
			return Ok(());
		},
		"token-faucet" | "token-send" => {
			let op = if command == "token-faucet" {
				TokenOp::Faucet { to: f.account("to")?, asset: f.num("asset")?, amount: f.num("amount")? }
			} else {
				TokenOp::Send {
					from: f.account("from")?,
					asset: f.num("asset")?,
					amount: f.num("amount")?,
					service: f.num("to-service")?,
					to: f.account("to")?,
				}
			};
			println!("0x{}", to_hex(&op.encode()));
			return Ok(());
		},
		"token-key" => {
			let holder =
				if f.has("account") { Holder::Account(f.account("account")?) } else { Holder::Service(f.num("service-holder")?) };
			println!("0x{}", to_hex(&BalanceKey(holder, f.num("asset")?).encode()));
			return Ok(());
		},
		"token-decode" => {
			println!("{}", decode::<Amount>(&f.hex("balance")?)?);
			return Ok(());
		},
		"mint" => Op::Mint { to: f.account("to")?, amount: f.num("amount")? },
		"withdraw" => {
			let service: u32 = f.num("service")?;
			let account = f.key("account")?;
			let (nonce, asset, amount, to) = (f.num("nonce")?, f.asset("asset")?, f.num("amount")?, f.account("to")?);
			let account_id = account.verifying_key().to_bytes();
			let message = witness_types::withdraw_message(service, &account_id, nonce, &asset, amount, &to);
			Op::Withdraw { account: account_id, nonce, asset, amount, to, signature: account.sign(&message).to_bytes() }
		},
		"propose" => {
			let service: u32 = f.num("service")?;
			let admin = f.admin()?;
			let (nonce, action) = (f.num("nonce")?, f.action()?);
			let admin_id = admin.verifying_key().to_bytes();
			let message = witness_types::propose_message(service, &admin_id, nonce, &action);
			Op::Propose { admin: admin_id, nonce, action, signature: admin.sign(&message).to_bytes() }
		},
		"apply" => Op::Apply { id: f.num("id")? },
		"cancel" => {
			let service: u32 = f.num("service")?;
			let admin = f.admin()?;
			let (nonce, id) = (f.num("nonce")?, f.num("id")?);
			let admin_id = admin.verifying_key().to_bytes();
			let message = witness_types::cancel_message(service, &admin_id, nonce, id);
			Op::Cancel { admin: admin_id, nonce, id, signature: admin.sign(&message).to_bytes() }
		},
		"create" => {
			let service: u32 = f.num("service")?;
			let maker = f.key("maker")?;
			let nonce = f.num("nonce")?;
			let (check_hash, check_len, _) = f.check()?;
			let claim_window =
				if f.has("claim-window") { f.num("claim-window")? } else { MIN_CLAIM_WINDOW };
			let terms = BountyTerms {
				check_hash,
				check_len,
				params: f.params()?,
				blobs: f.blobs()?.into_iter().map(|(blob, _)| blob).collect(),
				asset: f.asset_or_test("asset")?,
				reward: f.num("reward")?,
				check_gas: f.num("check-gas")?,
				expiry: f.num("expiry")?,
				claim_window,
			};
			let maker_id = maker.verifying_key().to_bytes();
			let message = witness_types::create_message(service, &maker_id, nonce, &terms);
			let signature = maker.sign(&message).to_bytes();
			Op::CreateBounty { maker: maker_id, nonce, terms, signature }
		},
		"commit" => {
			let service: u32 = f.num("service")?;
			let bounty_id = f.num("bounty")?;
			let committer = f.key(if f.has("committer") { "committer" } else { "hunter" })?;
			let nonce = f.num("nonce")?;
			let commitment = witness_types::commitment(
				bounty_id,
				&f.witness()?,
				&f.account("hunter")?,
				&f.salt()?,
			);
			eprintln!("commitment 0x{}", to_hex(&commitment));
			let committer_id = committer.verifying_key().to_bytes();
			let message =
				witness_types::commit_message(service, bounty_id, &committer_id, nonce, &commitment);
			let signature = committer.sign(&message).to_bytes();
			Op::Commit { bounty_id, committer: committer_id, nonce, commitment, signature }
		},
		"reveal" => {
			// Extrinsic 0 is the check, whole; 1 the plain blobs, then the trusted subjects; 2 the
			// citations, if any; then the witness, if it's long.
			let (check_hash, _, check) = f.check()?;
			let blobs = f.blobs()?;
			let mut given = Blobs::new();
			let mut subjects = Vec::new();
			let mut plain = Vec::new();
			for (_, blob) in &blobs {
				match blob {
					Blob::Attested(cited, entry) => subjects.push((cited.clone(), *entry)),
					Blob::Plain(data) => {
						plain.push(BlobAt { extrinsic: 1, index: given.len() as u32 });
						given.push(data.clone());
					},
				}
			}
			subjects.extend(f.trust()?);
			let (claims, trusted) = cite(&subjects, 1, &mut given)?;
			let dir = f.extrinsics()?;
			let citations = write_extrinsics(dir, &check, &[given], Citations { claims, trusted })?;
			let witness = extrinsic_witness(dir, f.witness()?, citations.map_or(2, |c| c + 1))?;
			Op::Reveal {
				bounty_id: f.num("bounty")?,
				check_hash,
				params: f.params()?,
				blobs: blobs.into_iter().map(|(blob, _)| blob).collect(),
				check: 0,
				plain,
				citations,
				check_gas: f.num("check-gas")?,
				hunter: f.account("hunter")?,
				salt: f.salt()?,
				witness,
			}
		},
		"finalize" => Op::Finalize { bounty_id: f.num("bounty")? },
		"reclaim" => {
			let service: u32 = f.num("service")?;
			let bounty_id = f.num("bounty")?;
			let maker = f.key("maker")?;
			let nonce = f.num("nonce")?;
			let maker_id = maker.verifying_key().to_bytes();
			let message = witness_types::reclaim_message(service, bounty_id, &maker_id, nonce);
			let signature = maker.sign(&message).to_bytes();
			Op::Reclaim { bounty_id, maker: maker_id, nonce, signature }
		},
		"release" => Op::Release { bounty_id: f.num("bounty")?, commitment: f.hash("commitment")? },
		"attest" => {
			// Extrinsic 0 is the check, whole; 1 the subjects; 2 the trusted subjects; 3 the
			// citations, if any; then the witness, if it's long.
			let service: u32 = f.num("service")?;
			let attester = f.key("attester")?;
			let nonce = f.num("nonce")?;
			let (check_hash, _, check) = f.check()?;
			let has_params = ["params", "params-str", "params-u128", "params-blake2b"].iter().any(|p| f.has(p));
			let params = if has_params { f.params()? } else { vec![] };
			let subjects: Blobs = f.list("subjects")?.into_iter().map(read).collect::<Result<_, _>>()?;
			let mut given = Blobs::new();
			let (claims, trusted) = cite(&f.trust()?, 2, &mut given)?;
			let parents: Vec<AttestationId> = claims.iter().map(AttestationClaim::id).collect();
			let leaves: Vec<Hash> = subjects.iter().map(|s| merkle::leaf(&blake2b256(s))).collect();
			let claim = AttestationClaim {
				check_hash,
				params_hash: blake2b256(&params),
				subjects_root: merkle::root(&leaves),
				subject_count: subjects.len() as u32,
				parents_root: witness_types::parents_root(&parents),
			};
			let has_witness = ["witness", "witness-str", "witness-u64", "witness-file"].iter().any(|w| f.has(w));
			let witness = if has_witness { f.witness()? } else { vec![] };
			write(f.str("claim-out")?, &(claim.clone(), subjects.clone()).encode())?;
			let dir = f.extrinsics()?;
			let citations = write_extrinsics(dir, &check, &[subjects, given], Citations { claims, trusted })?;
			let witness = extrinsic_witness(dir, witness, citations.map_or(3, |c| c + 1))?;
			eprintln!("attestation 0x{}", to_hex(&claim.id()));
			let attester_id = attester.verifying_key().to_bytes();
			let message = witness_types::attest_message(service, &attester_id, nonce, &claim.id());
			let signature = attester.sign(&message).to_bytes();
			Op::Attest {
				attester: attester_id,
				nonce,
				check_hash,
				check: 0,
				params,
				subjects: 1,
				citations,
				witness,
				check_gas: f.num("check-gas")?,
				signature,
			}
		},
		_ => return Err(format!("unknown command {command}")),
	};
	println!("0x{}", to_hex(&op.encode()));
	Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	if s.len() % 2 != 0 {
		return None;
	}
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}
