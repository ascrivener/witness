//! Writes the spike's test cases for the evm-bounty check:
//!
//!     evm-report OUT_DIR
//!
//! For each case, `OUT_DIR/<case>.<p>.args` holds the check's arguments (reveal mode, the report
//! as the witness) with `stop_after` = p, for p in 1..=4, and `<case>.0.args` the whole check, so
//! `witness-sim check` measures each phase by difference. `OUT_DIR/cases.tsv` says what each
//! report holds and how the check went natively.

use evm_bounty_check::{Report, run_measured};
use std::{io::Write, path::PathBuf, process::ExitCode, time::Instant};
use witness_types::{CheckMode, check_args};

fn main() -> ExitCode {
	let args: Vec<String> = std::env::args().skip(1).collect();
	let [out] = args.as_slice() else {
		eprintln!("usage: evm-report OUT_DIR");
		return ExitCode::FAILURE;
	};
	let out = PathBuf::from(out);
	std::fs::create_dir_all(&out).expect("create OUT_DIR");
	let mut tsv = std::fs::File::create(out.join("cases.tsv")).expect("create cases.tsv");
	let header = "case\toutcome\tevm_gas\ttxs\taccounts\tslots\tproof_nodes\tproof_bytes\tcode_bytes\treport_bytes\tnative_us";
	writeln!(tsv, "{header}").unwrap();
	println!("{header}");
	for case in evm_report::all() {
		let params = alloy_rlp::encode(&case.params);
		let report = alloy_rlp::encode(&case.report);
		// Natively, best of a few runs.
		let mut best = u128::MAX;
		let mut result = None;
		for _ in 0..5 {
			let start = Instant::now();
			result = Some(run_measured(&params, &report));
			best = best.min(start.elapsed().as_micros());
		}
		let (outcome, evm_gas) = result.unwrap();
		if outcome != case.expected {
			eprintln!("{}: the replay found {:?}, the check {:?}", case.name, case.expected, outcome);
			return ExitCode::FAILURE;
		}
		for stop_after in 0..=4 {
			let report = alloy_rlp::encode(&Report { stop_after, ..case.report.clone() });
			let args = check_args(CheckMode::Reveal, &[], &params, &report);
			std::fs::write(out.join(format!("{}.{stop_after}.args", case.name)), args).expect("write args");
		}
		let accounts = &case.report.accounts;
		let slots: usize = accounts.iter().map(|a| a.slots.len()).sum();
		let proofs = accounts.iter().flat_map(|a| std::iter::once(&a.proof).chain(a.slots.iter().map(|s| &s.proof)));
		let (nodes, proof_bytes) = proofs.fold((0, 0), |(n, b), p| (n + p.len(), b + p.iter().map(|x| x.len()).sum::<usize>()));
		let code: usize = accounts.iter().map(|a| a.code.len()).sum();
		let line = format!(
			"{}\t{outcome:?}\t{evm_gas}\t{}\t{}\t{slots}\t{nodes}\t{proof_bytes}\t{code}\t{}\t{best}",
			case.name,
			case.report.txs.len(),
			accounts.len(),
			report.len(),
		);
		writeln!(tsv, "{line}").unwrap();
		println!("{line}");
	}
	ExitCode::SUCCESS
}
