//! Builds witness work-item payloads and prints them as hex, for `jamt item <service> 0x...`.
//!
//! Accounts are derived from a seed phrase (`--maker alice`): the Ed25519 secret key is
//! `blake2b256(seed)`. Fine for a points-only prototype, not for anything of value.

use codec::{Decode, Encode};
use ed25519_dalek::{Signer, SigningKey};
use std::{collections::HashMap, process::ExitCode};
use witness_types::{
	Account, AccountId, Bounty, BountyTerms, CommitRecord, Hash, MIN_CLAIM_WINDOW, Op, StorageKey,
	Verified, blake2b256,
};

const USAGE: &str = "\
usage: witness <command> [--flag value ...]

  account   --seed S
  mint      --to S --amount N
  create    --service ID --maker S --nonce N --check FILE PARAMS --reward N --check-gas G
            --expiry SLOT [--claim-window SLOTS]
  commit    --service ID --bounty ID --hunter S [--committer S] --nonce N --salt HEX WITNESS
  reveal    --bounty ID --check FILE PARAMS --check-gas G --hunter S --salt HEX WITNESS
  finalize  --bounty ID
  reclaim   --service ID --bounty ID --maker S --nonce N
  release   --commitment HEX
  key       (--account S | --bounty ID | --commitment HEX | --check-refs HASH | --next)
            storage key, for `jamt inspect storage <service> <key>`
  decode    (--output HEX | --account HEX | --bounty HEX | --commitment HEX)
            decode a refine output or a stored value

PARAMS:  --params HEX | --params-u128 N | --params-blake2b STRING (the hash of STRING)
WITNESS: --witness HEX | --witness-u64 N | --witness-str STRING

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
		let path = self.str("check")?;
		let blob = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
		Ok((blake2b256(&blob), blob.len() as u32))
	}
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
		"decode" => {
			let decoded = if f.has("account") {
				decode::<Account>(&f.hex("account")?)
			} else if f.has("bounty") {
				decode::<Bounty>(&f.hex("bounty")?)
			} else if f.has("commitment") {
				decode::<CommitRecord>(&f.hex("commitment")?)
			} else {
				decode::<Verified>(&f.hex("output")?)
			}?;
			println!("{decoded}");
			return Ok(());
		},
		"key" => {
			let key = if f.has("account") {
				StorageKey::Account(f.account("account")?)
			} else if f.has("bounty") {
				StorageKey::Bounty(f.num("bounty")?)
			} else if f.has("commitment") {
				StorageKey::Commitment(f.hash("commitment")?)
			} else if f.has("check-refs") {
				StorageKey::CheckRefs(f.hash("check-refs")?)
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
		"release" => Op::Release { commitment: f.hash("commitment")? },
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
