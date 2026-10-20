//! Sample check: the witness is a Blake2b-256 preimage of the bounty's hash.
//!
//! Params: the 32-byte hash. Witness: any bytes. One blob serves every hash, so each bounty
//! reuses the same on-chain check.

#![cfg_attr(not(test), no_std)]

fn check(params: &[u8], x: &[u8]) -> bool {
	let h = blake2b_simd::Params::new().hash_length(32).hash(x);
	params == h.as_bytes()
}

witness_check::declare_check!(check);

#[cfg(test)]
mod tests {
	use super::check;

	#[test]
	fn accepts_only_the_preimage() {
		let h = blake2b_simd::Params::new().hash_length(32).hash(b"open sesame");
		assert!(check(h.as_bytes(), b"open sesame"));
		assert!(!check(h.as_bytes(), b"open sesame!"));
		assert!(!check(&h.as_bytes()[..31], b"open sesame"));
	}
}
