//! Sample check that reads a blob and allocates: the witness is a sentence of dictionary words
//! whose Blake2b-256 hash starts with enough zero bits.
//!
//! Blob 0: the dictionary, one word per line. Params: the number of leading zero bits wanted, as
//! one byte. Witness: one or more words separated by single spaces.
//!
//! Many bounties can share one dictionary blob, at different difficulties. The check builds a set
//! of the dictionary's words on the heap, as a check over a large environment would.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::collections::BTreeSet;
use witness_check::{Input, Mode};

fn leading_zero_bits(hash: &[u8]) -> u32 {
	let zero_bytes = hash.iter().take_while(|&&b| b == 0).count();
	let rest = hash.get(zero_bytes).map_or(0, |b| b.leading_zeros());
	zero_bytes as u32 * 8 + rest
}

fn check(input: &Input) -> bool {
	let (Mode::Reveal, Some(dictionary), [difficulty]) = (input.mode, input.blob(0), input.params) else {
		return false;
	};
	let words: BTreeSet<&[u8]> = dictionary.data.split(|&b| b == b'\n').filter(|w| !w.is_empty()).collect();
	let h = blake2b_simd::Params::new().hash_length(32).hash(input.witness);
	!input.witness.is_empty() &&
		input.witness.split(|&b| b == b' ').all(|w| words.contains(w)) &&
		leading_zero_bits(h.as_bytes()) >= *difficulty as u32
}

witness_check::declare_full_check!(check);

#[cfg(test)]
mod tests {
	use super::*;
	use witness_types::{CheckBlob, CheckMode, check_args};

	const DICTIONARY: &[u8] = b"open\nsesame\nsome\nwords\n";

	fn run(mode: CheckMode, blobs: &[CheckBlob], difficulty: &[u8], x: &[u8]) -> bool {
		check(&Input::parse(&check_args(mode, blobs, difficulty, x)).unwrap())
	}

	fn reveal(difficulty: u8, x: &[u8]) -> bool {
		let dictionary = CheckBlob { trusted: false, hash: [0; 32], data: DICTIONARY };
		run(CheckMode::Reveal, &[dictionary], &[difficulty], x)
	}

	#[test]
	fn needs_dictionary_words() {
		assert!(reveal(0, b"open sesame"));
		assert!(reveal(0, b"words"));
		assert!(!reveal(0, b"open sesame!"));
		assert!(!reveal(0, b"open  sesame"), "an empty word is not in the dictionary");
		assert!(!reveal(0, b""));
	}

	#[test]
	fn needs_enough_zero_bits() {
		// Search for a sentence meeting 8 bits, as a hunter would.
		let words = ["open", "sesame", "some", "words"];
		let sentence = (0..4096)
			.map(|n: usize| (0..6).map(|i| words[(n >> (2 * i)) & 3]).collect::<Vec<_>>().join(" "))
			.find(|s| reveal(8, s.as_bytes()))
			.expect("about 1 in 256 sentences qualifies");
		assert!(reveal(0, sentence.as_bytes()));
		let bits = |x: &[u8]| leading_zero_bits(blake2b_simd::Params::new().hash_length(32).hash(x).as_bytes());
		assert!(bits(sentence.as_bytes()) >= 8);
		assert!(bits(b"open sesame") < 8, "so the next line tests the difficulty");
		assert!(!reveal(8, b"open sesame"));
	}

	#[test]
	fn rejects_other_inputs() {
		assert!(!run(CheckMode::Reveal, &[], &[0], b"open"), "no dictionary");
		let dictionary = CheckBlob { trusted: false, hash: [0; 32], data: DICTIONARY };
		assert!(!run(CheckMode::Reveal, &[dictionary], &[], b"open"), "no difficulty");
		assert!(!run(CheckMode::Attest, &[dictionary], &[0], b"open"), "not revealing");
	}

	#[test]
	fn counts_leading_zero_bits() {
		assert_eq!(leading_zero_bits(&[0, 0, 0x10, 0xff]), 19);
		assert_eq!(leading_zero_bits(&[0x80]), 0);
		assert_eq!(leading_zero_bits(&[0, 0]), 16);
	}
}
