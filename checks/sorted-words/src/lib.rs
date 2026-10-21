//! Sample check that attests: word volumes that are verified once, then trusted.
//!
//! A volume is a blob of 16-byte records, each a word of `a`-`z` padded with spaces, in strictly
//! increasing order.
//!
//! - **Attest mode:** the subject is a valid volume, and its first word comes after every word in
//!   its parents. Params must be empty. A chain of attested volumes is one sorted word list,
//!   built in layers.
//! - **Reveal mode:** params are the number of leading zero bits wanted, as one byte. The witness
//!   is words separated by single spaces, each in one of the bounty's volumes, and its Blake2b-256
//!   hash has that many leading zero bits.
//!
//! A trusted volume is binary-searched as it is: O(log n) per word. An untrusted one has to be
//! checked in full first, O(n), on every reveal. That difference is what attesting buys.

#![cfg_attr(not(test), no_std)]

use witness_check::{Blob, Input, Mode};

const RECORD: usize = 16;

fn records(volume: &[u8]) -> impl Iterator<Item = &[u8]> {
	volume.chunks(RECORD)
}

fn valid_record(record: &[u8]) -> bool {
	let word_len = record.iter().position(|&b| b == b' ').unwrap_or(RECORD);
	record.len() == RECORD &&
		word_len > 0 &&
		record[..word_len].iter().all(u8::is_ascii_lowercase) &&
		record[word_len..].iter().all(|&b| b == b' ')
}

/// A non-empty volume of valid records in strictly increasing order.
fn valid_volume(volume: &[u8]) -> bool {
	!volume.is_empty() &&
		volume.len() % RECORD == 0 &&
		records(volume).all(valid_record) &&
		records(volume).zip(records(volume).skip(1)).all(|(a, b)| a < b)
}

/// `word` as a record, or `None` if it can't be one.
fn to_record(word: &[u8]) -> Option<[u8; RECORD]> {
	let mut record = [b' '; RECORD];
	record.get_mut(..word.len())?.copy_from_slice(word);
	valid_record(&record).then_some(record)
}

/// Binary search a valid volume.
fn contains(volume: &[u8], record: &[u8; RECORD]) -> bool {
	let (mut lo, mut hi) = (0, volume.len() / RECORD);
	while lo < hi {
		let mid = (lo + hi) / 2;
		match volume[mid * RECORD..][..RECORD].cmp(record) {
			core::cmp::Ordering::Equal => return true,
			core::cmp::Ordering::Less => lo = mid + 1,
			core::cmp::Ordering::Greater => hi = mid,
		}
	}
	false
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
	let zero_bytes = hash.iter().take_while(|&&b| b == 0).count();
	let rest = hash.get(zero_bytes).map_or(0, |b| b.leading_zeros());
	zero_bytes as u32 * 8 + rest
}

fn attest(input: &Input, subject: Blob) -> bool {
	let after_parents = input.blobs().filter(|b| b.trusted).all(|parent| {
		let last = &parent.data[parent.data.len() - RECORD..];
		last < &subject.data[..RECORD]
	});
	// Every blob but the subject is a parent, which the service always marks trusted.
	input.params.is_empty() && !subject.trusted && valid_volume(subject.data) && after_parents
}

fn reveal(input: &Input) -> bool {
	let [difficulty] = input.params else { return false };
	if input.blobs().len() == 0 || !input.blobs().all(|b| b.trusted || valid_volume(b.data)) {
		return false;
	}
	let found = |word: &[u8]| {
		to_record(word).is_some_and(|record| input.blobs().any(|b| contains(b.data, &record)))
	};
	let h = blake2b_simd::Params::new().hash_length(32).hash(input.witness);
	!input.witness.is_empty() &&
		input.witness.split(|&b| b == b' ').all(found) &&
		leading_zero_bits(h.as_bytes()) >= *difficulty as u32
}

fn check(input: &Input) -> bool {
	match (input.mode, input.subject()) {
		(Mode::Attest, Some(subject)) => attest(input, subject),
		(Mode::Attest, None) => false,
		(Mode::Reveal, _) => reveal(input),
	}
}

witness_check::declare_full_check!(check);

#[cfg(test)]
mod tests {
	use super::*;
	use witness_types::{CheckBlob, CheckMode, check_args};

	fn volume(words: &[&str]) -> Vec<u8> {
		words.iter().flat_map(|w| to_record(w.as_bytes()).unwrap()).collect()
	}

	fn run(mode: CheckMode, blobs: &[(bool, &[u8])], params: &[u8], x: &[u8]) -> bool {
		let blobs: Vec<_> = blobs.iter().map(|&(trusted, data)| CheckBlob { trusted, hash: [0; 32], data }).collect();
		check(&Input::parse(&check_args(mode, &blobs, params, x)).unwrap())
	}

	#[test]
	fn attests_sorted_volumes_in_order() {
		let v1 = volume(&["apple", "banana", "cherry"]);
		let v2 = volume(&["grape", "lemon"]);
		assert!(run(CheckMode::Attest, &[(false, &v1)], b"", b""));
		assert!(run(CheckMode::Attest, &[(true, &v1), (false, &v2)], b"", b""));
		assert!(!run(CheckMode::Attest, &[(true, &v2), (false, &v1)], b"", b""), "must come after its parents");
		assert!(!run(CheckMode::Attest, &[(false, &volume(&["lemon", "grape"]))], b"", b""), "unsorted");
		assert!(!run(CheckMode::Attest, &[(false, &volume(&["fig", "fig"]))], b"", b""), "duplicate");
		assert!(!run(CheckMode::Attest, &[(false, b"Apple           ")], b"", b""), "not lowercase");
		assert!(!run(CheckMode::Attest, &[(false, b"app le          ")], b"", b""), "space inside");
		assert!(!run(CheckMode::Attest, &[(false, &v1[..20])], b"", b""), "not whole records");
		assert!(!run(CheckMode::Attest, &[(false, b"")], b"", b""), "empty");
		assert!(!run(CheckMode::Attest, &[(false, &v1)], b"\x00", b""), "params must be empty");
		assert!(!run(CheckMode::Attest, &[], b"", b""), "no subject");
	}

	#[test]
	fn reveals_against_trusted_and_untrusted_volumes() {
		let v1 = volume(&["apple", "banana", "cherry"]);
		let v2 = volume(&["grape", "lemon"]);
		let both = [(true, &v1[..]), (true, &v2[..])];
		assert!(run(CheckMode::Reveal, &both, &[0], b"cherry lemon apple"));
		assert!(!run(CheckMode::Reveal, &both, &[0], b"cherry kiwi"));
		assert!(!run(CheckMode::Reveal, &both, &[0], b"cherry  lemon"));
		assert!(!run(CheckMode::Reveal, &both, &[0], b"averyveryverylongword"));
		assert!(!run(CheckMode::Reveal, &both, &[0], b""));
		assert!(!run(CheckMode::Reveal, &both, &[], b"apple"), "no difficulty");
		assert!(!run(CheckMode::Reveal, &[], &[0], b"apple"), "no volumes");
		// Untrusted volumes are checked in full.
		assert!(run(CheckMode::Reveal, &[(false, &v1)], &[0], b"banana"));
		let unsorted = volume(&["cherry", "apple"]);
		assert!(!run(CheckMode::Reveal, &[(false, &unsorted)], &[0], b"cherry"));
		// A trusted one is believed (the service only marks this check's own attestations).
		assert!(run(CheckMode::Reveal, &[(true, &volume(&["apple"]))], &[0], b"apple"));
	}

	#[test]
	fn binary_search_finds_every_word() {
		let words = ["a", "ab", "abc", "b", "ba", "zz", "zzzzzzzzzzzzzzzz"];
		let v = volume(&words);
		assert!(valid_volume(&v));
		for w in words {
			assert!(contains(&v, &to_record(w.as_bytes()).unwrap()), "{w}");
		}
		for w in ["", "aa", "c", "zzz"] {
			assert!(!to_record(w.as_bytes()).is_some_and(|r| contains(&v, &r)), "{w}");
		}
	}

	#[test]
	fn needs_enough_zero_bits() {
		let v = volume(&["open", "sesame", "some", "words"]);
		let words = ["open", "sesame", "some", "words"];
		let sentence = (0..4096)
			.map(|n: usize| (0..6).map(|i| words[(n >> (2 * i)) & 3]).collect::<Vec<_>>().join(" "))
			.find(|s| run(CheckMode::Reveal, &[(true, &v)], &[8], s.as_bytes()))
			.expect("about 1 in 256 sentences qualifies");
		assert!(run(CheckMode::Reveal, &[(true, &v)], &[0], sentence.as_bytes()));
		assert!(!run(CheckMode::Reveal, &[(true, &v)], &[8], b"open sesame"));
	}
}
