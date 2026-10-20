//! Write a witness check as plain `no_std` Rust:
//!
//! ```ignore
//! #![no_std]
//! fn check(params: &[u8], x: &[u8]) -> bool { x == params }
//! witness_check::declare_check!(check);
//! ```
//!
//! and build it with `witness-build check <crate-dir>`. `params` are the bounty's, so one check
//! blob can serve any number of bounties; `x` is the hunter's witness.
//!
//! The check runs in an inner PVM with no host calls: no allocator, no logging, no I/O. Any host
//! call, panic, page fault or running out of gas counts as `false`.
//!
//! The stack defaults to 8 KiB; overflowing it is a page fault. A check that needs more can say
//! so with `polkavm_derive::min_stack_size!(bytes)` (on RISC-V targets only).

#![no_std]

#[doc(hidden)]
pub use polkavm_derive;

/// Split check arguments `E4(|params|) ++ params ++ witness` (see `witness_types::check_args`).
pub fn split_args(args: &[u8]) -> Option<(&[u8], &[u8])> {
	let (len, rest) = args.split_first_chunk::<4>()?;
	let len = u32::from_le_bytes(*len) as usize;
	(len <= rest.len()).then(|| rest.split_at(len))
}

/// Export `$check: fn(params: &[u8], x: &[u8]) -> bool` as the check blob's entry point.
///
/// The arguments arrive as the standard-program arguments (`ptr`, `len`) and the result goes back
/// in the first return register: 1 for true, 0 for false. Malformed arguments are false.
#[macro_export]
macro_rules! declare_check {
	($check: path) => {
		// The check layout has a single entry point at pc 0, as an authorizer does, and
		// `witness-build` links it under the authorizer's export name. The name itself does not
		// survive linking.
		// Only exported on the PVM; on the host it is dead code (as is `$check`, outside tests).
		#[allow(dead_code)]
		#[$crate::polkavm_derive::polkavm_export]
		extern "C" fn is_authorized_ext(ptr: u32, len: u32) -> u64 {
			let args = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
			let check: fn(&[u8], &[u8]) -> bool = $check;
			match $crate::split_args(args) {
				Some((params, witness)) => check(params, witness) as u64,
				None => 0,
			}
		}
	};
}

#[cfg(target_env = "polkavm")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
	unsafe { core::arch::asm!("unimp", options(noreturn)) }
}

#[cfg(test)]
mod tests {
	#[test]
	fn split_args_inverts_check_args() {
		let args = witness_types::check_args(b"params", b"witness");
		assert_eq!(super::split_args(&args), Some((&b"params"[..], &b"witness"[..])));
		assert_eq!(super::split_args(&witness_types::check_args(b"", b"")), Some((&b""[..], &b""[..])));
		assert_eq!(super::split_args(&[9, 0, 0, 0, 1]), None);
		assert_eq!(super::split_args(&[1, 0]), None);
	}
}
