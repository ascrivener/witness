//! Runs a bounty's check blob in an inner PVM, within the bounty's gas limit.

use jam_pvm_common::{InvokeOutcome, imports, info, refine};
use jam_types::{
	PageMode, PageOperation,
	gas_costs::{GROW_HEAP_BASE, GROW_HEAP_LINEAR},
};
use witness_types::{
	CheckFailure, Gas, MAX_CHECK_PAGES, Rejection,
	program::{Access, Heap, StandardProgram, initialize},
};

/// The one host call a check may make: grow its heap (as `jam-pvm-common`'s allocator does).
const GROW_HEAP: u64 = 1;

/// Run `blob` (a JAM program blob from `cargo jam-build`) on `args` (see
/// `witness_types::check_args`) with at most `gas`.
///
/// Returns `Ok(())` only if the check halted with 1 in the first return register.
pub fn run_check(blob: &[u8], args: &[u8], gas: Gas) -> Result<(), Rejection> {
	let program = StandardProgram::parse_jam_blob(blob).ok_or(Rejection::BadCheckBlob)?;
	let layout = initialize(&program, args).ok_or(Rejection::BadCheckBlob)?;
	if layout.total_pages() > MAX_CHECK_PAGES as u64 {
		return Err(Rejection::BadCheckBlob);
	}

	let vm = refine::machine(layout.code, 0).map_err(|_| Rejection::BadCheckBlob)?;
	let limit = i64::try_from(gas).map_err(|_| Rejection::CheckGasTooHigh)?;
	let mut gas = limit;
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

		let mut heap = Heap::new(&layout, MAX_CHECK_PAGES as u64);
		let mut regs = layout.registers;
		let failure = loop {
			let (outcome, gas_left, new_regs) =
				refine::invoke(vm, gas, regs).map_err(|_| Rejection::BadCheckBlob)?;
			(gas, regs) = (gas_left, new_regs);
			match outcome {
				InvokeOutcome::Halt if regs[7] == 1 => return Ok(()),
				InvokeOutcome::Halt => break CheckFailure::False,
				InvokeOutcome::Panic => break CheckFailure::Panic,
				InvokeOutcome::OutOfGas => break CheckFailure::OutOfGas,
				InvokeOutcome::PageFault(_) => break CheckFailure::PageFault,
				InvokeOutcome::HostCallFault(GROW_HEAP) => {
					// Charge the check what `grow_heap` would cost a service, then resume it with
					// the heap's new end in φ7 (unchanged if it asked for too much).
					if let Some((first, count)) = heap.grow(regs[7]) {
						let cost = GROW_HEAP_BASE + GROW_HEAP_LINEAR * count;
						gas = gas.saturating_sub(cost as i64);
						if gas < 0 {
							break CheckFailure::OutOfGas;
						}
						if count > 0 {
							refine::zero(vm, first, count, PageMode::ReadWrite)
								.map_err(|_| Rejection::BadCheckBlob)?;
						}
					}
					regs[7] = heap.end_page;
				},
				InvokeOutcome::HostCallFault(_) => break CheckFailure::HostCall,
			}
		};
		Err(Rejection::CheckFailed(failure))
	})();
	let _ = refine::expunge(vm);
	info!(target = "witness", "check used {} gas of {limit}", limit - gas.max(0));
	result
}
