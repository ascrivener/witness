//! A mock token service, for testing witness's deposits and withdrawals. **Test only: anyone can
//! mint and move anyone's tokens.** It speaks witness's memos (see docs/design/tokens.md), as a
//! real multi-asset token service would.
//!
//! The rules here run natively (in witness-sim) and in `mock-token-service`, the JAM service:
//! - [`TokenOp::Faucet`] credits an account with any amount of any asset.
//! - [`TokenOp::Send`] moves an account's tokens to a service, sending it a deposit memo for an
//!   account there. The service then holds them here, as the token service's ledger shows.
//! - A withdrawal memo from a service pays out of what that service holds to an account.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use codec::{Decode, Encode};
use witness_types::{Amount, DepositMemo, MEMO_LEN, MEMO_VERSION, WithdrawalMemo};

/// Who holds tokens: an account (any 32 bytes; the mock checks no signatures) or a service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Holder {
	Account([u8; 32]),
	Service(u32),
}

/// A work item's payload.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum TokenOp {
	Faucet { to: [u8; 32], asset: u32, amount: Amount },
	/// Move `amount` of `asset` from account `from` to service `service`, for its account `to`.
	Send { from: [u8; 32], asset: u32, amount: Amount, service: u32, to: [u8; 32] },
}

/// Storage keys: a holder's balance of an asset.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BalanceKey(pub Holder, pub u32);

pub trait State {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

/// What an op or transfer changes: storage writes (`None` removes), and transfers to send.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Effects {
	pub writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
	pub transfers: Vec<(u32, [u8; MEMO_LEN])>,
}

pub type Result<T> = core::result::Result<T, &'static str>;

struct Tx<'a, S> {
	state: &'a S,
	fx: Effects,
}

impl<S: State> Tx<'_, S> {
	fn balance(&self, holder: Holder, asset: u32) -> Amount {
		let key = BalanceKey(holder, asset).encode();
		let value = match self.fx.writes.get(&key) {
			Some(value) => value.clone(),
			None => self.state.get(&key),
		};
		value.and_then(|v| Amount::decode(&mut &v[..]).ok()).unwrap_or(0)
	}

	fn set(&mut self, holder: Holder, asset: u32, amount: Amount) {
		let value = (amount != 0).then(|| amount.encode());
		self.fx.writes.insert(BalanceKey(holder, asset).encode(), value);
	}

	fn move_tokens(&mut self, from: Holder, to: Holder, asset: u32, amount: Amount) -> Result<()> {
		let left = self.balance(from, asset).checked_sub(amount).ok_or("insufficient balance")?;
		self.set(from, asset, left);
		let total = self.balance(to, asset).checked_add(amount).ok_or("balance overflow")?;
		self.set(to, asset, total);
		Ok(())
	}
}

/// Apply `op`.
pub fn apply(state: &impl State, op: TokenOp) -> Result<Effects> {
	let mut tx = Tx { state, fx: Effects::default() };
	match op {
		TokenOp::Faucet { to, asset, amount } => {
			let total = tx.balance(Holder::Account(to), asset).checked_add(amount).ok_or("balance overflow")?;
			tx.set(Holder::Account(to), asset, total);
		},
		TokenOp::Send { from, asset, amount, service, to } => {
			tx.move_tokens(Holder::Account(from), Holder::Service(service), asset, amount)?;
			let memo = DepositMemo { version: MEMO_VERSION, asset_id: asset, amount, to };
			tx.fx.transfers.push((service, witness_types::memo(&memo)));
		},
	}
	Ok(tx.fx)
}

/// Apply a transfer from service `source`: a withdrawal, paid out of what `source` holds.
pub fn on_transfer(state: &impl State, source: u32, memo: &[u8]) -> Result<Effects> {
	let mut tx = Tx { state, fx: Effects::default() };
	let w = WithdrawalMemo::decode(&mut &memo[..]).map_err(|_| "not a withdrawal")?;
	if w.version != MEMO_VERSION {
		return Err("unknown memo version");
	}
	tx.move_tokens(Holder::Service(source), Holder::Account(w.to), w.asset_id, w.amount)?;
	Ok(tx.fx)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;

	#[derive(Default)]
	struct Chain(BTreeMap<Vec<u8>, Vec<u8>>);

	impl State for Chain {
		fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
			self.0.get(key).cloned()
		}
	}

	impl Chain {
		fn apply(&mut self, fx: Effects) -> Vec<(u32, [u8; MEMO_LEN])> {
			for (k, v) in fx.writes {
				match v {
					Some(v) => self.0.insert(k, v),
					None => self.0.remove(&k),
				};
			}
			fx.transfers
		}

		fn balance(&self, holder: Holder, asset: u32) -> Amount {
			Tx { state: self, fx: Effects::default() }.balance(holder, asset)
		}
	}

	#[test]
	fn send_and_withdraw() {
		let mut c = Chain::default();
		let (alice, bob) = ([1; 32], [2; 32]);
		let fx = apply(&c, TokenOp::Faucet { to: alice, asset: 7, amount: 100 }).unwrap();
		c.apply(fx);
		let fx = apply(&c, TokenOp::Send { from: alice, asset: 7, amount: 60, service: 3, to: [9; 32] }).unwrap();
		let sent = c.apply(fx);
		let memo = DepositMemo { version: MEMO_VERSION, asset_id: 7, amount: 60, to: [9; 32] };
		assert_eq!(sent, vec![(3, witness_types::memo(&memo))]);
		assert_eq!((c.balance(Holder::Account(alice), 7), c.balance(Holder::Service(3), 7)), (40, 60));
		let send_more = TokenOp::Send { from: alice, asset: 7, amount: 41, service: 3, to: [9; 32] };
		assert_eq!(apply(&c, send_more), Err("insufficient balance"));

		let withdrawal = |amount| witness_types::memo(&WithdrawalMemo { version: MEMO_VERSION, asset_id: 7, amount, to: bob });
		let fx = on_transfer(&c, 3, &withdrawal(25)).unwrap();
		c.apply(fx);
		assert_eq!((c.balance(Holder::Service(3), 7), c.balance(Holder::Account(bob), 7)), (35, 25));
		assert_eq!(on_transfer(&c, 3, &withdrawal(36)), Err("insufficient balance"));
		assert_eq!(on_transfer(&c, 4, &withdrawal(1)), Err("insufficient balance"), "only what it holds");
	}
}
