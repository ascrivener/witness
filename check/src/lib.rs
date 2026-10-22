//! Write a witness check as plain `no_std` Rust:
//!
//! ```ignore
//! #![no_std]
//! fn check(params: &[u8], x: &[u8]) -> bool { x == params }
//! witness_check::declare_check!(check);
//! ```
//!
//! declare `type = "authorizer"` under `[package.metadata.jam]` in the crate's `Cargo.toml`, and
//! build it with `cargo jam-build -p <crate>`. `params` are the bounty's, so one check blob can
//! serve any number of bounties; `x` is the hunter's witness.
//!
//! A check that reads the bounty's extra blobs takes the whole [`Input`] instead:
//!
//! ```ignore
//! fn check(input: &witness_check::Input) -> bool {
//!     input.mode == witness_check::Mode::Reveal && input.blobs().any(|b| b.data == input.witness)
//! }
//! witness_check::declare_full_check!(check);
//! ```
//!
//! A full check can also attest: in [`Mode::Attest`] it verifies a list of subject blobs once,
//! and the service records that it did. Later attestations, bounties and reveals on the same
//! check can then cite any of those subjects, and the check receives them marked trusted, so it
//! can skip re-verifying them:
//!
//! ```ignore
//! fn check(input: &witness_check::Input) -> bool {
//!     match input.mode {
//!         // Trusted blobs come first; verify every subject given them, with the witness as
//!         // evidence.
//!         Mode::Attest => input.subjects().all(|s| item_is_valid(&input, s)),
//!         // Verify only what isn't trusted, then the witness against it all.
//!         Mode::Reveal => input.blobs().all(|b| b.trusted || item_is_valid(&input, b)) && solves(&input),
//!     }
//! }
//! ```
//!
//! A trusted blob was attested by this same check with the same attest params (the service makes
//! sure of it), so the check can rely on whatever its own attest mode verified.
//!
//! The check runs in an inner PVM with no host calls but one: with this crate's `alloc` feature
//! it gets a global allocator, and the service grows its heap on request. No logging, no I/O.
//! Any other host call, a panic, a page fault or running out of gas counts as `false`.
//!
//! The stack defaults to 8 KiB; overflowing it is a page fault. A check that needs more can say
//! so with `polkavm_derive::min_stack_size!(bytes)` (on RISC-V targets only).

#![no_std]

#[cfg(all(feature = "alloc", target_env = "polkavm"))]
mod heap;

#[doc(hidden)]
pub use polkavm_derive;

/// The argument layout this crate understands (`witness_types::CHECK_INTERFACE_VERSION`).
pub const INTERFACE_VERSION: u8 = 2;

/// Why the check is being run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
	/// Does the witness solve the bounty?
	Reveal,
	/// Do the subjects, every untrusted blob, verify given the trusted ones (subjects of earlier
	/// attestations)? The witness is the attester's evidence. Returning true records an
	/// attestation of all the subjects.
	Attest,
}

/// One of the blobs the check is given: trusted subjects first, in the order the op cites them,
/// then the bounty's plain blobs (when revealing) or the subjects to attest (when attesting).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blob<'a> {
	/// The blob is a subject of an attestation by this same check, with the same attest params,
	/// so the check may rely on whatever it verified in attest mode.
	pub trusted: bool,
	pub hash: &'a [u8; 32],
	pub data: &'a [u8],
}

/// Everything a check receives (see `witness_types::check_args`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input<'a> {
	pub mode: Mode,
	pub params: &'a [u8],
	pub witness: &'a [u8],
	blob_count: u32,
	blob_bytes: &'a [u8],
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
	let (head, rest) = bytes.split_at_checked(n)?;
	*bytes = rest;
	Some(head)
}

fn take_u32(bytes: &mut &[u8]) -> Option<usize> {
	let (n, rest) = bytes.split_first_chunk::<4>()?;
	*bytes = rest;
	Some(u32::from_le_bytes(*n) as usize)
}

/// Read one blob off the front of `bytes`.
fn take_blob<'a>(bytes: &mut &'a [u8]) -> Option<Blob<'a>> {
	let trusted = match take(bytes, 1)? {
		[0] => false,
		[1] => true,
		_ => return None,
	};
	let hash = take(bytes, 32)?.try_into().ok()?;
	let len = take_u32(bytes)?;
	Some(Blob { trusted, hash, data: take(bytes, len)? })
}

impl<'a> Input<'a> {
	/// Parse check arguments; `None` if they are malformed or of another interface version.
	pub fn parse(mut args: &'a [u8]) -> Option<Self> {
		let mode = match take(&mut args, 2)? {
			[INTERFACE_VERSION, 0] => Mode::Reveal,
			[INTERFACE_VERSION, 1] => Mode::Attest,
			_ => return None,
		};
		let blob_count = take_u32(&mut args)?;
		let start = args;
		for _ in 0..blob_count {
			take_blob(&mut args)?;
		}
		let blob_bytes = &start[..start.len() - args.len()];
		let params_len = take_u32(&mut args)?;
		let params = take(&mut args, params_len)?;
		Some(Input { mode, params, witness: args, blob_count: blob_count as u32, blob_bytes })
	}

	/// All the blobs, in order.
	pub fn blobs(&self) -> Blobs<'a> {
		Blobs { left: self.blob_count, bytes: self.blob_bytes }
	}

	/// The `i`th blob.
	pub fn blob(&self, i: usize) -> Option<Blob<'a>> {
		self.blobs().nth(i)
	}

	/// The trusted blobs, which come first.
	pub fn trusted(&self) -> impl Iterator<Item = Blob<'a>> + 'a {
		self.blobs().take_while(|b| b.trusted)
	}

	/// In attest mode, the blobs being attested: the untrusted ones, after the trusted. None in
	/// reveal mode.
	pub fn subjects(&self) -> impl Iterator<Item = Blob<'a>> + 'a {
		let attesting = self.mode == Mode::Attest;
		self.blobs().skip_while(|b| b.trusted).filter(move |_| attesting)
	}
}

/// Iterator over an [`Input`]'s blobs.
#[derive(Clone, Debug)]
pub struct Blobs<'a> {
	left: u32,
	bytes: &'a [u8],
}

impl<'a> Iterator for Blobs<'a> {
	type Item = Blob<'a>;

	fn next(&mut self) -> Option<Blob<'a>> {
		self.left = self.left.checked_sub(1)?;
		// `Input::parse` has already checked every blob is well formed.
		take_blob(&mut self.bytes)
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		(self.left as usize, Some(self.left as usize))
	}
}

impl ExactSizeIterator for Blobs<'_> {}

#[doc(hidden)]
pub fn run_simple(args: &[u8], check: fn(&[u8], &[u8]) -> bool) -> u64 {
	match Input::parse(args) {
		Some(input) if input.mode == Mode::Reveal => check(input.params, input.witness) as u64,
		_ => 0,
	}
}

#[doc(hidden)]
pub fn run_full(args: &[u8], check: fn(&Input) -> bool) -> u64 {
	Input::parse(args).is_some_and(|input| check(&input)) as u64
}

/// Export `$check: fn(params: &[u8], x: &[u8]) -> bool` as the check blob's entry point.
///
/// The check ignores the bounty's blobs and is only ever true when revealing. The arguments
/// arrive as the standard-program arguments (`ptr`, `len`) and the result goes back in the first
/// return register: 1 for true, 0 for false. Malformed arguments are false.
#[macro_export]
macro_rules! declare_check {
	($check: path) => {
		$crate::__declare_entry!($crate::run_simple, $check);
	};
}

/// Export `$check: fn(&witness_check::Input) -> bool` as the check blob's entry point, for a check
/// that reads the bounty's blobs or the mode.
///
/// A check should return false for a mode it does not handle.
#[macro_export]
macro_rules! declare_full_check {
	($check: path) => {
		$crate::__declare_entry!($crate::run_full, $check);
	};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __declare_entry {
	($run: path, $check: path) => {
		// A check has a single entry point at pc 0, as an authorizer does, so check crates build
		// as authorizers and export under the authorizer's name. The name itself does not
		// survive linking.
		// Only exported on the PVM; on the host it is dead code (as is `$check`, outside tests).
		#[allow(dead_code)]
		#[$crate::polkavm_derive::polkavm_export]
		extern "C" fn is_authorized_ext(ptr: u32, len: u32) -> u64 {
			let args = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
			$run(args, $check)
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
	extern crate std;
	use super::*;
	use std::vec::Vec;
	use witness_types::{CheckBlob, CheckMode, check_args};

	#[test]
	fn parse_inverts_check_args() {
		let blobs = [
			CheckBlob { trusted: false, hash: [1; 32], data: b"first" },
			CheckBlob { trusted: true, hash: [2; 32], data: b"" },
		];
		let args = check_args(CheckMode::Reveal, &blobs, b"params", b"witness");
		let input = Input::parse(&args).unwrap();
		assert_eq!((input.mode, input.params, input.witness), (Mode::Reveal, &b"params"[..], &b"witness"[..]));
		let parsed: Vec<_> = input.blobs().collect();
		assert_eq!(parsed.len(), 2);
		assert_eq!(parsed[0], Blob { trusted: false, hash: &[1; 32], data: b"first" });
		assert_eq!(parsed[1], Blob { trusted: true, hash: &[2; 32], data: b"" });
		assert_eq!(input.blob(1), Some(parsed[1]));
		assert_eq!(input.blob(2), None);

		let args = check_args(CheckMode::Attest, &[], b"", b"");
		let input = Input::parse(&args).unwrap();
		assert_eq!((input.mode, input.params, input.witness, input.blobs().len()), (Mode::Attest, &b""[..], &b""[..], 0));
		assert_eq!(input.subjects().count(), 0);

		let blobs = [
			CheckBlob { trusted: true, hash: [1; 32], data: b"parent" },
			CheckBlob { trusted: false, hash: [2; 32], data: b"a" },
			CheckBlob { trusted: false, hash: [3; 32], data: b"b" },
		];
		let args = check_args(CheckMode::Attest, &blobs, b"", b"evidence");
		let input = Input::parse(&args).unwrap();
		assert_eq!(input.witness, b"evidence");
		assert_eq!(input.subjects().map(|b| b.data).collect::<Vec<_>>(), [b"a", b"b"]);
		assert_eq!(input.trusted().map(|b| b.data).collect::<Vec<_>>(), [b"parent"]);
		let args = check_args(CheckMode::Reveal, &blobs, b"", b"");
		let input = Input::parse(&args).unwrap();
		assert_eq!(input.subjects().count(), 0, "no subjects when revealing");
		assert_eq!(input.trusted().count(), 1);
	}

	#[test]
	fn parse_rejects_malformed() {
		let args = check_args(CheckMode::Reveal, &[CheckBlob { trusted: false, hash: [1; 32], data: b"ab" }], b"p", b"");
		for cut in 0..args.len() - 1 {
			assert_eq!(Input::parse(&args[..cut]), None, "truncated to {cut}");
		}
		let mut bad = args.clone();
		bad[0] = 1;
		assert_eq!(Input::parse(&bad), None, "unknown version");
		let mut bad = args.clone();
		bad[1] = 2;
		assert_eq!(Input::parse(&bad), None, "unknown mode");
		let mut bad = args.clone();
		bad[6] = 2;
		assert_eq!(Input::parse(&bad), None, "trusted flag not a bool");
	}

	#[test]
	fn simple_checks_only_reveal() {
		let check: fn(&[u8], &[u8]) -> bool = |params, x| params == x;
		assert_eq!(run_simple(&check_args(CheckMode::Reveal, &[], b"a", b"a"), check), 1);
		assert_eq!(run_simple(&check_args(CheckMode::Reveal, &[], b"a", b"b"), check), 0);
		assert_eq!(run_simple(&check_args(CheckMode::Attest, &[], b"a", b"a"), check), 0);
		assert_eq!(run_simple(&[], check), 0);
	}
}
