# Binary export format

A compact encoding of the lean4export NDJSON format (version 3.1.0), for checking proofs in JAM
refine, where parsing JSON was the largest cost. `delta/lean_bin.py` converts NDJSON to this
format, and the patched nanoda reads either (`parser.rs`, `BinReader`).

It's about 11% of the JSON size and about 6× cheaper to parse (see [the README](README.md)).

## Encoding

- **File:** the magic `LEANBIN\x01` (8 bytes), then items until the end. No length or count.
- **Item:** a tag byte, then its fields in the order listed below.
- **`uN`:** an unsigned LEB128 varint.
- **`bool`:** one byte, 0 or 1.
- **`str`, `bytes`:** a `u` length, then UTF-8 or raw bytes.
- **`[uN]`:** a `u` count, then that many `uN`.

**Indices are implicit.** In NDJSON, each name, level and expression carries its index
(`"in"`, `"il"`, `"ie"`). Here, each one's index is its position among the items of its kind:
- names start at 1 (0 is the anonymous name),
- levels start at 1 (0 is zero),
- expressions start at 0.

A part that continues an earlier one, such as a delta after a statement environment, continues
its numbering. Duplicates are still rejected, because inserting an item that already exists fails.

## Items

| Tag | NDJSON | Fields |
|---|---|---|
| 0 | `meta` | exporter name `str`, exporter version `str`, Lean githash `str`, Lean version `str`, format version `str` |
| 1 | name `str` | pre `u32`, str `str` |
| 2 | name `num` | pre `u32`, i `u32` |
| 3 | level `succ` | `u32` |
| 4 | level `max` | `u32`, `u32` |
| 5 | level `imax` | `u32`, `u32` |
| 6 | level `param` | name `u32` |
| 7 | expr `natVal` | value `bytes` (little-endian) |
| 8 | expr `strVal` | `str` |
| 9 | expr `letE` | name, type, value, body `u32`; nondep `bool` |
| 10 | expr `const` | name `u32`, levels `[u32]` |
| 11 | expr `app` | fn `u32`, arg `u32` |
| 12 | expr `forallE` | name, type, body `u32`; binder info `u8` |
| 13 | expr `lam` | name, type, body `u32`; binder info `u8` |
| 14 | expr `proj` | type name `u32`, idx `u64`, struct `u32` |
| 15 | expr `sort` | level `u32` |
| 16 | expr `bvar` | `u16` |
| 17 | `axiom` | name `u32`, level params `[u32]`, type `u32`, unsafe `bool` |
| 18 | `thm` | name `u32`, level params `[u32]`, type `u32`, value `u32` |
| 19 | `def` | name `u32`, level params `[u32]`, type `u32`, value `u32`, hint (`0` opaque, `1` abbrev, `2` regular then height `u16`), safety `u8` |
| 20 | `opaque` | name `u32`, level params `[u32]`, type `u32`, value `u32`, unsafe `bool` |
| 21 | `quot` | name `u32`, level params `[u32]`, type `u32`, kind `u8` |
| 22 | `inductive` | types, constructors and recursors, as below |

- **Binder info:** 0 default, 1 implicit, 2 strict implicit, 3 instance implicit.
- **Safety:** 0 safe, 1 unsafe, 2 partial.
- **Quot kind:** 0 type, 1 ctor, 2 lift, 3 ind.

An `inductive` item has a `u` count followed by that many of each:
- **Type:** name `u32`, level params `[u32]`, type `u32`, all `[u32]`, ctors `[u32]`, isRec `bool`,
  isReflexive `bool`, numIndices `u16`, numNested `u16`, numParams `u16`, unsafe `bool`.
- **Constructor:** name `u32`, level params `[u32]`, type `u32`, unsafe `bool`, cidx `u16`,
  numParams `u16`, numFields `u16`, induct `u32`.
- **Recursor:** name `u32`, level params `[u32]`, type `u32`, unsafe `bool`, numParams `u16`,
  numIndices `u16`, numMotives `u16`, numMinors `u16`, then a `u` count of rules (ctor `u32`,
  nfields `u16`, rhs `u32`), then all `[u32]`, k `bool`.

`mdata` expressions aren't supported. lean4export leaves them out unless asked.
