//! Builds witness work-item payloads and prints them as hex, for `jamt item <service> 0x...`.
//!
//! Accounts are derived from a seed phrase (`--maker alice`): the Ed25519 secret key is
//! `blake2b256(seed)`. Fine for a points-only prototype, not for anything of value.

use codec::{Decode, Encode};
use ed25519_dalek::{Signer, SigningKey};
use std::{collections::HashMap, process::ExitCode};
use witness_types::{
	Account, AccountId, Attestation, AttestationClaim, Bounty, BountyTerms, CommitRecord, Hash,
	MIN_CLAIM_WINDOW, Op, Preimage, RevealBlob, StorageKey, Verified, blake2b256,
};

const USAGE: &str = "\
usage: witness <command> [--flag value ...]

  account   --seed S
  hash      --check FILE          the preimage hash of FILE, a check or a blob
  mint      --to S --amount N
  create    --service ID --maker S --nonce N --check FILE PARAMS [--blobs FILES] --reward N
            --check-gas G --expiry SLOT [--claim-window SLOTS]
  commit    --service ID --bounty ID --hunter S [--committer S] --nonce N --salt HEX WITNESS
  reveal    --bounty ID --check FILE PARAMS [--blobs FILES] --check-gas G --hunter S --salt HEX
            WITNESS
  finalize  --bounty ID
  reclaim   --service ID --bounty ID --maker S --nonce N
  release   --bounty ID --commitment HEX
  pin       --service ID --owner S --nonce N --blob FILE
  attest    --service ID --attester S --nonce N --check FILE [PARAMS] --subject FILE
            [--parents CLAIMS] --check-gas G --claim-out CLAIM
            writes the claim to CLAIM, for citing the attestation later
  key       (--account S | --bounty ID [--commitment HEX] | --refs HASH | --attestation CLAIM
            | --next)
            storage key, for `jamt inspect storage <service> <key>`
  decode    (--output HEX | --account HEX | --bounty HEX | --commitment HEX | --attestation HEX)
            decode a refine output or a stored value

PARAMS:  --params HEX | --params-u128 N | --params-blake2b STRING (the hash of STRING)
WITNESS: --witness HEX | --witness-u64 N | --witness-str STRING
FILES:   comma-separated, in order: paths of plain blobs, or claim:CLAIM for an attested one
CLAIMS:  comma-separated paths of claim files that `attest --claim-out` wrote

Seeds S are any string; hex may have a 0x prefix. A salt of other than 32 bytes is hashed to 32.
The committer pays the commit deposit and signs; it defaults to the hunter.";

fn main() -> ExitCode {
	let mut args = std::env::args().skip(1);
	let Some(command) = args.next() else { return usage() };
	let mut flags = HashMap::new();
	while let Some(flag) = args.next() {
		let (Some(name), Some(value)) = (flag.strip_prefix("--"), args.next()) else {
			return usage();
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
		if self.has("params-u128") {
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
		} else {
			self.hex("witness")
		}
	}
	fn salt(&self) -> Result<Hash, String> {
		let salt = self.hex("salt")?;
		Ok(<Hash>::try_from(&salt[..]).unwrap_or_else(|_| blake2b256(&salt)))
	}
	fn check(&self) -> Result<(Hash, u32), String> {
		let blob = file_ref(self.str("check")?)?;
		Ok((blob.hash, blob.len))
	}
	/// A comma-separated list flag, empty if absent.
	fn list(&self, name: &str) -> Result<Vec<&str>, String> {
		if !self.has(name) {
			return Ok(vec![]);
		}
		Ok(self.str(name)?.split(',').collect())
	}
	fn blobs(&self) -> Result<Vec<RevealBlob>, String> {
		self.list("blobs")?
			.into_iter()
			.map(|blob| match blob.strip_prefix("claim:") {
				Some(path) => read_claim(path).map(RevealBlob::Attested),
				None => file_ref(blob).map(RevealBlob::Blob),
			})
			.collect()
	}
}

fn read(path: &str) -> Result<Vec<u8>, String> {
	std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn file_ref(path: &str) -> Result<Preimage, String> {
	let blob = read(path)?;
	Ok(Preimage { hash: blake2b256(&blob), len: blob.len() as u32 })
}

fn read_claim(path: &str) -> Result<AttestationClaim, String> {
	AttestationClaim::decode(&mut &read(path)?[..]).map_err(|e| format!("{path} is not a claim: {e}"))
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
			} else {
				decode::<Verified>(&f.hex("output")?)
			}?;
			println!("{decoded}");
			return Ok(());
		},
		"key" => {
			let key = if f.has("account") {
				StorageKey::Account(f.account("account")?)
			} else if f.has("commitment") {
				StorageKey::Commitment(f.num("bounty")?, f.hash("commitment")?)
			} else if f.has("bounty") {
				StorageKey::Bounty(f.num("bounty")?)
			} else if f.has("refs") {
				StorageKey::PreimageRefs(f.hash("refs")?)
			} else if f.has("attestation") {
				StorageKey::Attestation(read_claim(f.str("attestation")?)?.id())
			} else {
				StorageKey::NextBountyId
			};
			println!("0x{}", to_hex(&key.encode()));
			return Ok(());
		},
		"mint" => Op::Mint { to: f.account("to")?, amount: f.num("amount")? },
		"create" => {
			let service: u32 = f.num("service")?;
			let maker = f.key("maker")?;
			let nonce = f.num("nonce")?;
			let (check_hash, check_len) = f.check()?;
			let claim_window =
				if f.has("claim-window") { f.num("claim-window")? } else { MIN_CLAIM_WINDOW };
			let terms = BountyTerms {
				check_hash,
				check_len,
				params: f.params()?,
				blobs: f.blobs()?.iter().map(RevealBlob::blob_ref).collect(),
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
		"reveal" => Op::Reveal {
			bounty_id: f.num("bounty")?,
			check_hash: f.check()?.0,
			params: f.params()?,
			blobs: f.blobs()?,
			check_gas: f.num("check-gas")?,
			hunter: f.account("hunter")?,
			salt: f.salt()?,
			witness: f.witness()?,
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
		"pin" => {
			let service: u32 = f.num("service")?;
			let owner = f.key("owner")?;
			let nonce = f.num("nonce")?;
			let blob = file_ref(f.str("blob")?)?;
			let owner_id = owner.verifying_key().to_bytes();
			let signature = owner.sign(&witness_types::pin_message(service, &owner_id, nonce, &blob)).to_bytes();
			Op::Pin { owner: owner_id, nonce, blob, signature }
		},
		"attest" => {
			let service: u32 = f.num("service")?;
			let attester = f.key("attester")?;
			let nonce = f.num("nonce")?;
			let check_hash = f.check()?.0;
			let has_params = ["params", "params-u128", "params-blake2b"].iter().any(|p| f.has(p));
			let params = if has_params { f.params()? } else { vec![] };
			let subject = file_ref(f.str("subject")?)?;
			let parents = f.list("parents")?.into_iter().map(read_claim).collect::<Result<Vec<_>, _>>()?;
			let claim = AttestationClaim {
				check_hash,
				params_hash: blake2b256(&params),
				subject,
				parents: parents.iter().map(AttestationClaim::id).collect(),
			};
			let out = f.str("claim-out")?;
			std::fs::write(out, claim.encode()).map_err(|e| format!("cannot write {out}: {e}"))?;
			eprintln!("attestation 0x{}", to_hex(&claim.id()));
			let attester_id = attester.verifying_key().to_bytes();
			let message = witness_types::attest_message(service, &attester_id, nonce, &claim.id());
			let signature = attester.sign(&message).to_bytes();
			Op::Attest {
				attester: attester_id,
				nonce,
				check_hash,
				params,
				subject,
				parents,
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
