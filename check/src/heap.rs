//! A global allocator for checks, on a heap the service grows on request.
//!
//! The service answers host call 1 (`grow_heap`, as in `jam-pvm-common`) by mapping pages after
//! the check's read-write data, up to its page limit, and resuming the check.

struct Heap;

#[polkavm_derive::polkavm_import]
extern "C" {
	/// Grow the heap to end at page `pages`; returns where it now ends.
	#[polkavm_import(index = 1)]
	fn grow_heap(pages: u64) -> u64;
}

impl picoalloc::Env for Heap {
	fn total_space(&self) -> picoalloc::Size {
		// The service's page limit is the real bound.
		const { picoalloc::Size::from_bytes_usize(1 << 30).unwrap() }
	}

	unsafe fn allocate_address_space(&mut self) -> *mut u8 {
		let base = polkavm_derive::heap_base().cast::<u8>();
		// picoalloc needs 32-byte alignment.
		base.with_addr(base.addr().next_multiple_of(32))
	}

	unsafe fn expand_memory_until(&mut self, base: *mut u8, size: picoalloc::Size) -> bool {
		const PAGE_SIZE: usize = 4096;
		let pages = (base.addr() + size.bytes() as usize).div_ceil(PAGE_SIZE) as u64;
		unsafe { grow_heap(pages) >= pages }
	}

	unsafe fn free_address_space(&mut self, _base: *mut u8) {}
}

#[global_allocator]
static ALLOCATOR: picoalloc::Mutex<picoalloc::Allocator<Heap>> =
	picoalloc::Mutex::new(picoalloc::Allocator::new(Heap));
