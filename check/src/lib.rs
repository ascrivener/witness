//! Write a witness check as plain `no_std` Rust:
//!
//! ```ignore
//! #![no_std]
//! fn check(x: &[u8]) -> bool { x == b"open sesame" }
//! witness_check::declare_check!(check);
//! ```
//!
//! and build it with `witness-build check <crate-dir>`.
//!
//! The check runs in an inner PVM with no host calls: no allocator, no logging, no I/O. Any host
//! call, panic, page fault or running out of gas counts as `false`.
//!
//! The stack defaults to 8 KiB; overflowing it is a page fault. A check that needs more can say
//! so with `polkavm_derive::min_stack_size!(bytes)` (on RISC-V targets only).

#![no_std]

#[doc(hidden)]
pub use polkavm_derive;

/// Export `$check: fn(&[u8]) -> bool` as the check blob's entry point.
///
/// The witness arrives as the standard-program arguments (`ptr`, `len`) and the result goes back
/// in the first return register: 1 for true, 0 for false.
#[macro_export]
macro_rules! declare_check {
	($check: path) => {
		// `jam-pvm-builder` only knows the service, authorizer and CoreVM layouts; the authorizer
		// layout has the single entry point at pc 0 that a check needs, so the export borrows its
		// name. The name itself does not survive linking.
		#[$crate::polkavm_derive::polkavm_export]
		extern "C" fn is_authorized_ext(ptr: u32, len: u32) -> u64 {
			let witness = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
			let check: fn(&[u8]) -> bool = $check;
			check(witness) as u64
		}
	};
}

#[cfg(target_env = "polkavm")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
	unsafe { core::arch::asm!("unimp", options(noreturn)) }
}
