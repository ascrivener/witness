//! Raise a chain spec's refine gas limit to the full spec's (5×10⁹), leaving everything else.
//!
//!     full-gas-spec IN.json OUT.json
//!
//! PolkaJam's dev chain uses the "tiny" protocol parameters, whose refine limit is 10⁹ gas. Dump
//! its spec with `polkajam --chain dev:40000 dump-spec IN.json`, raise the limit, and run the nodes
//! with `--chain=OUT.json` instead (see the README for doing that under `polkajam-testnet`).
use jam_types::{Decode, Encode, ProtocolParameters};
fn main() {
	let args: Vec<String> = std::env::args().collect();
	let mut spec: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[1]).unwrap()).unwrap();
	let hex = spec["protocol_parameters"].as_str().unwrap().to_string();
	let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
	let mut p = ProtocolParameters::decode(&mut &bytes[..]).unwrap();
	eprintln!("before: {p:?}");
	p.max_refine_gas = ProtocolParameters::full().max_refine_gas;
	eprintln!("after:  max_refine_gas {}", p.max_refine_gas);
	let enc: String = p.encode().iter().map(|b| format!("{b:02x}")).collect();
	spec["protocol_parameters"] = serde_json::Value::String(enc);
	std::fs::write(&args[2], serde_json::to_vec(&spec).unwrap()).unwrap();
}
