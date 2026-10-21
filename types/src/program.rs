//! The Gray Paper's standard program format and initialization (GP 0.8.0, appendix A.7, `Y`).
//!
//! Check blobs are JAM program blobs, as `cargo jam-build` writes them: conventional metadata, then
//! the standard program `E3(|o|) ++ E3(|w|) ++ E2(z) ++ E3(s) ++ o ++ w ++ E4(|c|) ++ c`.
//! The service sets up an inner PVM to match `Y(p, a)` with the check arguments as `a`, so a check
//! sees exactly the memory a service or authorizer would at entry.

use alloc::vec::Vec;
use codec::Decode;

pub const PAGE_SIZE: u64 = 4096;
/// `Z_Z`: the initialization zone size.
pub const ZONE_SIZE: u64 = 1 << 16;
/// `Z_I`: the initialization input (argument) size.
pub const INPUT_SIZE: u64 = 1 << 24;

/// A decoded standard program blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardProgram<'a> {
	pub ro_data: &'a [u8],
	pub rw_data: &'a [u8],
	pub rw_padding_pages: u16,
	pub stack_size: u32,
	/// Instructions, opcode bitmask and jump table, as accepted by the `machine` host call.
	pub code: &'a [u8],
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
	let head = bytes.get(..n)?;
	*bytes = &bytes[n..];
	Some(head)
}

fn take_le(bytes: &mut &[u8], n: usize) -> Option<u32> {
	let mut buf = [0u8; 4];
	buf[..n].copy_from_slice(take(bytes, n)?);
	Some(u32::from_le_bytes(buf))
}

impl<'a> StandardProgram<'a> {
	pub fn parse(mut p: &'a [u8]) -> Option<Self> {
		let ro_len = take_le(&mut p, 3)?;
		let rw_len = take_le(&mut p, 3)?;
		let rw_padding_pages = take_le(&mut p, 2)? as u16;
		let stack_size = take_le(&mut p, 3)?;
		let ro_data = take(&mut p, ro_len as usize)?;
		let rw_data = take(&mut p, rw_len as usize)?;
		let code_len = take_le(&mut p, 4)?;
		let code = take(&mut p, code_len as usize)?;
		p.is_empty().then_some(Self { ro_data, rw_data, rw_padding_pages, stack_size, code })
	}

	/// Parse a JAM program blob as `cargo jam-build` writes it: `E(|m|) ++ m ++ p`, conventional
	/// metadata `m` followed by the standard program `p`.
	pub fn parse_jam_blob(mut blob: &'a [u8]) -> Option<Self> {
		let metadata_len = codec::Compact::<u32>::decode(&mut blob).ok()?.0;
		Self::parse(blob.get(metadata_len as usize..)?)
	}

	pub fn to_vec(&self) -> Vec<u8> {
		let mut out = Vec::new();
		out.extend_from_slice(&(self.ro_data.len() as u32).to_le_bytes()[..3]);
		out.extend_from_slice(&(self.rw_data.len() as u32).to_le_bytes()[..3]);
		out.extend_from_slice(&self.rw_padding_pages.to_le_bytes());
		out.extend_from_slice(&self.stack_size.to_le_bytes()[..3]);
		out.extend_from_slice(self.ro_data);
		out.extend_from_slice(self.rw_data);
		out.extend_from_slice(&(self.code.len() as u32).to_le_bytes());
		out.extend_from_slice(self.code);
		out
	}
}

fn page_round(x: u64) -> u64 {
	x.next_multiple_of(PAGE_SIZE)
}

fn zone_round(x: u64) -> u64 {
	x.next_multiple_of(ZONE_SIZE)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
	ReadOnly,
	ReadWrite,
}

/// A run of pages to allocate (zeroed), fill from `data` and leave with `access`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region<'a> {
	pub first_page: u64,
	pub pages: u64,
	pub data: &'a [u8],
	pub access: Access,
}

/// The initial state of a program per `Y(p, a)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout<'a> {
	pub code: &'a [u8],
	/// Read-only data, read-write data (incl. heap padding), stack, arguments. Empty regions are
	/// omitted.
	pub regions: Vec<Region<'a>>,
	pub registers: [u64; 13],
	/// The page just past the read-write data, where the heap grows from.
	pub heap_start_page: u64,
	/// The first page of the stack: the heap may grow up to, but not into, it.
	pub heap_limit_page: u64,
}

impl Layout<'_> {
	pub fn total_pages(&self) -> u64 {
		self.regions.iter().map(|r| r.pages).sum()
	}
}

/// A program's heap: pages mapped after its read-write data as it asks for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heap {
	/// The page just past the heap.
	pub end_page: u64,
	/// The heap may not grow into this page (the stack's first).
	pub limit_page: u64,
	/// How many more pages may be mapped.
	pub pages_left: u64,
}

impl Heap {
	/// A heap starting where `layout` says, with `max_pages` pages for everything.
	pub fn new(layout: &Layout, max_pages: u64) -> Self {
		Heap {
			end_page: layout.heap_start_page,
			limit_page: layout.heap_limit_page,
			pages_left: max_pages.saturating_sub(layout.total_pages()),
		}
	}

	/// Grow the heap to end at page `target`, as `grow_heap(target)` asks. Returns the pages to
	/// map, as (first page, count), which is empty if the heap already reaches `target`, or
	/// `None` if growing would pass a limit.
	pub fn grow(&mut self, target: u64) -> Option<(u64, u64)> {
		let first = self.end_page;
		let count = target.saturating_sub(first);
		if target > self.limit_page || count > self.pages_left {
			return None;
		}
		self.end_page = self.end_page.max(target);
		self.pages_left -= count;
		Some((first, count))
	}
}

/// `Y(p, a)`: the memory and registers a standard program starts with, given arguments `args`.
pub fn initialize<'a>(program: &StandardProgram<'a>, args: &'a [u8]) -> Option<Layout<'a>> {
	let ro_len = program.ro_data.len() as u64;
	let rw_len = program.rw_data.len() as u64;
	let padding = program.rw_padding_pages as u64 * PAGE_SIZE;
	let stack = program.stack_size as u64;
	let args_len = args.len() as u64;
	if args_len > INPUT_SIZE ||
		5 * ZONE_SIZE + zone_round(ro_len) + zone_round(rw_len + padding) + zone_round(stack) + INPUT_SIZE >
			1 << 32
	{
		return None;
	}

	let region = |start: u64, len: u64, data, access| Region {
		first_page: start / PAGE_SIZE,
		pages: page_round(len) / PAGE_SIZE,
		data,
		access,
	};
	let stack_top = (1 << 32) - 2 * ZONE_SIZE - INPUT_SIZE;
	let stack_start = stack_top - page_round(stack);
	let args_start = (1 << 32) - ZONE_SIZE - INPUT_SIZE;
	let rw_start = 2 * ZONE_SIZE + zone_round(ro_len);
	let rw_size = page_round(rw_len) + padding;
	let regions = [
		region(ZONE_SIZE, ro_len, program.ro_data, Access::ReadOnly),
		region(rw_start, rw_size, program.rw_data, Access::ReadWrite),
		region(stack_start, stack, &[][..], Access::ReadWrite),
		region(args_start, args_len, args, Access::ReadOnly),
	]
	.into_iter()
	.filter(|r| r.pages > 0)
	.collect();

	let mut registers = [0; 13];
	registers[0] = (1 << 32) - (1 << 16);
	registers[1] = stack_top;
	registers[7] = args_start;
	registers[8] = args_len;
	Some(Layout {
		code: program.code,
		regions,
		registers,
		heap_start_page: (rw_start + rw_size) / PAGE_SIZE,
		heap_limit_page: stack_start / PAGE_SIZE,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn round_trip() {
		let p = StandardProgram {
			ro_data: &[1, 2, 3],
			rw_data: &[4, 5],
			rw_padding_pages: 7,
			stack_size: 8192,
			code: &[0, 0, 2, 50, 0, 1],
		};
		let bytes = p.to_vec();
		assert_eq!(StandardProgram::parse(&bytes), Some(p));
		assert_eq!(StandardProgram::parse(&bytes[..bytes.len() - 1]), None);
		let mut longer = bytes.clone();
		longer.push(0);
		assert_eq!(StandardProgram::parse(&longer), None);
	}

	#[test]
	fn jam_blob_skips_metadata() {
		use codec::Encode;
		let p = StandardProgram {
			ro_data: &[1],
			rw_data: &[],
			rw_padding_pages: 0,
			stack_size: 4096,
			code: &[0, 0, 2, 50, 0, 1],
		};
		let metadata = alloc::vec![7u8; 200];
		let mut blob = codec::Compact(metadata.len() as u32).encode();
		blob.extend_from_slice(&metadata);
		blob.extend_from_slice(&p.to_vec());
		assert_eq!(StandardProgram::parse_jam_blob(&blob), Some(p));
		assert_eq!(StandardProgram::parse_jam_blob(&blob[..150]), None);
	}

	#[test]
	fn layout_matches_gp() {
		let ro = [9u8; 5000];
		let p = StandardProgram {
			ro_data: &ro,
			rw_data: &[1],
			rw_padding_pages: 2,
			stack_size: 4097,
			code: &[],
		};
		let args = [7u8; 10];
		let l = initialize(&p, &args).unwrap();
		assert_eq!(l.regions.len(), 4);
		// RO at Z_Z, two pages.
		assert_eq!((l.regions[0].first_page, l.regions[0].pages), (16, 2));
		// RW at 2 Z_Z + Q(5000) = 3 Z_Z, one data page plus two padding pages.
		assert_eq!((l.regions[1].first_page, l.regions[1].pages), (3 * 16, 3));
		// Stack: two pages ending at 2^32 - 2 Z_Z - Z_I.
		let stack_top_page = ((1u64 << 32) - 2 * ZONE_SIZE - INPUT_SIZE) / PAGE_SIZE;
		assert_eq!((l.regions[2].first_page, l.regions[2].pages), (stack_top_page - 2, 2));
		// Args at 2^32 - Z_Z - Z_I.
		assert_eq!(l.regions[3].first_page, ((1u64 << 32) - ZONE_SIZE - INPUT_SIZE) / PAGE_SIZE);
		assert_eq!(l.registers[0], 0xffff_0000);
		assert_eq!(l.registers[7], (1 << 32) - ZONE_SIZE - INPUT_SIZE);
		assert_eq!(l.registers[8], 10);
		assert_eq!(l.total_pages(), 2 + 3 + 2 + 1);
		// The heap starts after the RW region and may grow up to the stack.
		assert_eq!(l.heap_start_page, 3 * 16 + 3);
		assert_eq!(l.heap_limit_page, stack_top_page - 2);
	}

	#[test]
	fn heap_grows_within_limits() {
		let mut heap = Heap { end_page: 10, limit_page: 20, pages_left: 8 };
		assert_eq!(heap.grow(5), Some((10, 0)), "already there");
		assert_eq!(heap.grow(14), Some((10, 4)));
		assert_eq!(heap.grow(14), Some((14, 0)));
		assert_eq!(heap.grow(19), None, "more pages than are left");
		assert_eq!(heap.grow(18), Some((14, 4)));
		assert_eq!(heap, Heap { end_page: 18, limit_page: 20, pages_left: 0 });
		let mut heap = Heap { end_page: 10, limit_page: 20, pages_left: 100 };
		assert_eq!(heap.grow(21), None, "into the stack");
		assert_eq!(heap.grow(20), Some((10, 10)));
		assert_eq!(heap.grow(u64::MAX), None);
	}

	#[test]
	fn rejects_oversized() {
		let p = StandardProgram {
			ro_data: &[],
			rw_data: &[],
			rw_padding_pages: u16::MAX,
			stack_size: (1 << 24) - 1,
			code: &[],
		};
		// The largest heap and stack the format can express still fit in 32 bits...
		assert!(initialize(&p, &[]).is_some());
		// ...but arguments may not exceed Z_I.
		let too_long = alloc::vec![0u8; INPUT_SIZE as usize + 1];
		assert!(initialize(&p, &too_long).is_none());
	}
}
