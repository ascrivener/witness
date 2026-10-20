//! Runs a bounty's check blob on a witness in an inner PVM, within the bounty's gas limit.

use jam_pvm_common::{InvokeOutcome, imports, refine};
use jam_types::{PageMode, PageOperation};
use witness_types::{
	CheckFailure, Gas, MAX_CHECK_PAGES, Rejection,
	program::{Access, StandardProgram, initialize},
};

/// Run `blob` (a standard program) on `witness` with at most `gas`.
///
/// Returns `Ok(())` only if the check halted with 1 in the first return register.
pub fn run_check(blob: &[u8], witness: &[u8], gas: Gas) -> Result<(), Rejection> {
	let program = StandardProgram::parse(blob).ok_or(Rejection::BadCheckBlob)?;
	let layout = initialize(&program, witness).ok_or(Rejection::BadCheckBlob)?;
	if layout.total_pages() > MAX_CHECK_PAGES as u64 {
		return Err(Rejection::BadCheckBlob);
	}

	let vm = refine::machine(layout.code, 0).map_err(|_| Rejection::BadCheckBlob)?;
	let result = (|| {
		for region in &layout.regions {
			// `poke` needs writable pages, so allocate everything writable, fill it, then drop
			// read-only regions to read-only.
			refine::zero(vm, region.first_page, region.pages, PageMode::ReadWrite)
				.map_err(|_| Rejection::BadCheckBlob)?;
			if !region.data.is_empty() {
				refine::poke(vm, region.data, region.first_page * witness_types::program::PAGE_SIZE)
					.map_err(|_| Rejection::BadCheckBlob)?;
			}
			if region.access == Access::ReadOnly {
				let op = PageOperation::SetMode(PageMode::ReadOnly).into();
				// `protect` is not re-exported for refine, so use the raw `pages` host call.
				let r = unsafe { imports::pages(vm, region.first_page, region.pages, op) };
				if r != 0 {
					return Err(Rejection::BadCheckBlob);
				}
			}
		}

		let gas = i64::try_from(gas).map_err(|_| Rejection::CheckGasTooHigh)?;
		let (outcome, _gas_left, regs) =
			refine::invoke(vm, gas, layout.registers).map_err(|_| Rejection::BadCheckBlob)?;
		let failure = match outcome {
			InvokeOutcome::Halt if regs[7] == 1 => return Ok(()),
			InvokeOutcome::Halt => CheckFailure::False,
			InvokeOutcome::Panic => CheckFailure::Panic,
			InvokeOutcome::OutOfGas => CheckFailure::OutOfGas,
			InvokeOutcome::PageFault(_) => CheckFailure::PageFault,
			InvokeOutcome::HostCallFault(_) => CheckFailure::HostCall,
		};
		Err(Rejection::CheckFailed(failure))
	})();
	let _ = refine::expunge(vm);
	result
}
