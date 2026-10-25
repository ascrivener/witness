#![cfg_attr(not(test), no_std)]
extern crate alloc;

fn check(_input: &witness_check::Input) -> bool {
	let _db = revm::database::EmptyDB::default();
	true
}

witness_check::declare_full_check!(check);
