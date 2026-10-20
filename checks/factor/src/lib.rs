//! Sample check: the witness is a nontrivial factor of `N`.
//!
//! Params: `N` as 16 little-endian bytes. Witness: the factor as 8 little-endian bytes.

#![cfg_attr(not(test), no_std)]

fn check(params: &[u8], x: &[u8]) -> bool {
	let (Ok(n), Ok(d)) = (<[u8; 16]>::try_from(params), <[u8; 8]>::try_from(x)) else {
		return false;
	};
	let n = u128::from_le_bytes(n);
	let d = u64::from_le_bytes(d) as u128;
	d > 1 && d < n && n % d == 0
}

witness_check::declare_check!(check);

#[cfg(test)]
mod tests {
	use super::check;

	const N: u128 = 2_305_843_009_213_693_951 * 4_294_967_291;

	#[test]
	fn accepts_only_nontrivial_factors() {
		let n = N.to_le_bytes();
		assert!(check(&n, &4_294_967_291u64.to_le_bytes()));
		assert!(check(&n, &2_305_843_009_213_693_951u64.to_le_bytes()));
		assert!(!check(&n, &1u64.to_le_bytes()));
		assert!(!check(&n, &3u64.to_le_bytes()));
		assert!(!check(&n, &[1, 2, 3]));
		assert!(!check(&n[..8], &3u64.to_le_bytes()));
		assert!(!check(&15u128.to_le_bytes(), &15u64.to_le_bytes()), "N itself is trivial");
	}
}
