//! Builds witness work-item payloads and prints them as hex, for `jamt item <service> 0x...`.
//!
//! Accounts are derived from a seed phrase (`--maker alice`): the Ed25519 secret key is
//! `blake2b256(seed)`. Fine for a points-only prototype, not for anything of value.

use codec::{Decode, Encode};
use ed25519_dalek::{Signer, SigningKey};
use std::{collections::HashMap, process::ExitCode};
use witness_types::{
	Account, AccountId, Bounty, BountyTerms, Hash, Op, StorageKey, Verified, blake2b256,
};

const USAGE: &str = "\
usage: witness <command> [--flag value ...]

  account  --seed S
  mint     --to S --amount N
  create   --service ID --maker S --nonce N --check FILE --reward N --check-gas G --expiry SLOT
  commit   --bounty ID (--witness HEX | --witness-u64 N) --hunter S --salt HEX
  reveal   --bounty ID --check FILE --check-gas G (--witness HEX | --witness-u64 N)
           --hunter S --salt HEX
  reclaim  --service ID --bounty ID --maker S --nonce N
  key      (--account S | --bounty ID | --commitment HEX | --next)
           storage key, for `jamt inspect storage <service> <key>`
  decode   (--output HEX | --account HEX | --bounty HEX)
           decode a refine output or a stored value

Seeds S are any string; hex may have a 0x prefix. A salt of other than 32 bytes is hashed to 32.";

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
	fn str(&self, name: &str) -> Result<&str, String> {
		self.0.get(name).map(String::as_str).ok_or_else(|| format!("missing --{name}"))
	}
	fn num<T: std::str::FromStr>(&self, name: &str) -> Result<T, String> {
		self.str(name)?.parse().map_err(|_| format!("--{name} is not a number"))
	}
	fn hex(&self, name: &str) -> Result<Vec<u8>, String> {
		from_hex(self.str(name)?).ok_or_else(|| format!("--{name} is not hex"))
	}
	fn key(&self, name: &str) -> Result<SigningKey, String> {
		Ok(SigningKey::from_bytes(&blake2b256(self.str(name)?.as_bytes())))
	}
	fn account(&self, name: &str) -> Result<AccountId, String> {
		Ok(self.key(name)?.verifying_key().to_bytes())
	}
	fn witness(&self) -> Result<Vec<u8>, String> {
		match self.0.get("witness-u64") {
			Some(n) => Ok(n.parse::<u64>().map_err(|_| "--witness-u64 is not a u64")?.to_le_bytes().to_vec()),
			None => self.hex("witness"),
		}
	}
	fn salt(&self) -> Result<Hash, String> {
		let salt = self.hex("salt")?;
		Ok(match <Hash>::try_from(&salt[..]) {
			Ok(h) => h,
			Err(_) => blake2b256(&salt),
		})
	}
	fn check(&self) -> Result<(Hash, u32), String> {
		let path = self.str("check")?;
		let blob = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
		Ok((blake2b256(&blob), blob.len() as u32))
	}
}

fn run(command: &str, f: &Flags) -> Result<(), String> {
	let op = match command {
		"account" => {
			println!("0x{}", to_hex(&f.account("seed")?));
			return Ok(());
		},
		"decode" => {
			let decoded = if let Ok(bytes) = f.hex("account") {
				Account::decode(&mut &bytes[..]).map(|v| format!("{v:?}"))
			} else if let Ok(bytes) = f.hex("bounty") {
				Bounty::decode(&mut &bytes[..]).map(|v| format!("{v:?}"))
			} else {
				let bytes = f.hex("output")?;
				Verified::decode(&mut &bytes[..]).map(|v| format!("{v:?}"))
			};
			println!("{}", decoded.map_err(|e| format!("cannot decode: {e}"))?);
			return Ok(());
		},
		"key" => {
			let key = if f.0.contains_key("account") {
				StorageKey::Account(f.account("account")?)
			} else if f.0.contains_key("bounty") {
				StorageKey::Bounty(f.num("bounty")?)
			} else if f.0.contains_key("commitment") {
				let c = f.hex("commitment")?;
				StorageKey::Commitment(c.try_into().map_err(|_| "--commitment must be 32 bytes")?)
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
			let terms = BountyTerms {
				check_hash,
				check_len,
				reward: f.num("reward")?,
				check_gas: f.num("check-gas")?,
				expiry: f.num("expiry")?,
			};
			let maker_id = maker.verifying_key().to_bytes();
			let message = witness_types::create_message(service, &maker_id, nonce, &terms);
			let signature = maker.sign(&message).to_bytes();
			Op::CreateBounty { maker: maker_id, nonce, terms, signature }
		},
		"commit" => {
			let bounty_id = f.num("bounty")?;
			let commitment = witness_types::commitment(
				bounty_id,
				&f.witness()?,
				&f.account("hunter")?,
				&f.salt()?,
			);
			eprintln!("commitment 0x{}", to_hex(&commitment));
			Op::Commit { commitment }
		},
		"reveal" => Op::Reveal {
			bounty_id: f.num("bounty")?,
			check_hash: f.check()?.0,
			check_gas: f.num("check-gas")?,
			hunter: f.account("hunter")?,
			salt: f.salt()?,
			witness: f.witness()?,
		},
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
