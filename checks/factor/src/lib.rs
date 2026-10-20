//! Sample check: the witness is a nontrivial factor of `N`, as 8 little-endian bytes.
//!
//! `N = (2^61 - 1) * 4294967291`, both prime, so the two valid witnesses are those primes. That
//! makes a poor bounty and a convenient test.

#![cfg_attr(not(test), no_std)]

const N: u128 = 2_305_843_009_213_693_951 * 4_294_967_291;

fn check(x: &[u8]) -> bool {
	let Ok(bytes) = <[u8; 8]>::try_from(x) else { return false };
	let d = u64::from_le_bytes(bytes) as u128;
	d > 1 && d < N && N % d == 0
}

witness_check::declare_check!(check);

#[cfg(test)]
mod tests {
	use super::check;

	#[test]
	fn accepts_only_nontrivial_factors() {
		assert!(check(&4_294_967_291u64.to_le_bytes()));
		assert!(check(&2_305_843_009_213_693_951u64.to_le_bytes()));
		assert!(!check(&1u64.to_le_bytes()));
		assert!(!check(&3u64.to_le_bytes()));
		assert!(!check(&[1, 2, 3]));
	}
}
