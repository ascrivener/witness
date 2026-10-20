//! Builds PVM blobs for this workspace.
//!
//! ```text
//! witness-build service [CRATE_DIR] [-o OUT_DIR]   # -> witness-service.jam
//! witness-build check CRATE_DIR [-o OUT_DIR]       # -> <crate>.check
//! ```
//!
//! A `.jam` blob is a JAM program blob with conventional metadata, as `jam-pvm-build` produces. A
//! `.check` blob is the same without the metadata prefix: a standard program (GP appendix A.7),
//! exactly what the service hands to the `machine` host call. Its Blake2b-256 hash and length go
//! into the bounty's terms.
//!
//! The build mirrors `jam-pvm-builder`'s: compile the crate as a cdylib for the PolkaVM RISC-V
//! target with `build-std`, then link the ELF into a PVM program.

use codec::Encode;
use jam_program_blob_common::{ConventionalMetadata, CrateInfo, ProgramBlob};
use std::{
	path::{Path, PathBuf},
	process::{Command, ExitCode},
};
use witness_types::{blake2b256, program::StandardProgram};

/// The toolchain `jam-pvm-builder` uses; `rust-src` must be installed for it.
const TOOLCHAIN: &str = "nightly-2025-05-10";
const PROFILE: &str = "production";
const USAGE: &str = "usage: witness-build <service|check> [CRATE_DIR] [-o OUT_DIR]";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
	Service,
	Check,
}

impl Kind {
	fn dispatch_table(self) -> Vec<Vec<u8>> {
		match self {
			Kind::Service => vec![b"refine_ext".into(), b"accumulate_ext".into()],
			// See `witness_check::declare_check!` for the name.
			Kind::Check => vec![b"is_authorized_ext".into()],
		}
	}
}

fn main() -> ExitCode {
	let mut args = std::env::args().skip(1);
	let kind = match args.next().as_deref() {
		Some("service") => Kind::Service,
		Some("check") => Kind::Check,
		_ => return usage(),
	};
	let mut crate_dir = None;
	let mut out_dir = PathBuf::from("out");
	while let Some(arg) = args.next() {
		match arg.as_str() {
			"-o" | "--output" => match args.next() {
				Some(dir) => out_dir = dir.into(),
				None => return usage(),
			},
			_ if crate_dir.is_none() => crate_dir = Some(PathBuf::from(arg)),
			_ => return usage(),
		}
	}
	let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
	let crate_dir = match (crate_dir, kind) {
		(Some(dir), _) => dir,
		(None, Kind::Service) => workspace.join("service"),
		(None, Kind::Check) => return usage(),
	};

	match build(&crate_dir, kind, &workspace.join("target/pvm"), &out_dir) {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			eprintln!("error: {e}");
			ExitCode::FAILURE
		},
	}
}

fn usage() -> ExitCode {
	eprintln!("{USAGE}");
	ExitCode::FAILURE
}

fn build(crate_dir: &Path, kind: Kind, target_dir: &Path, out_dir: &Path) -> Result<(), String> {
	let info = crate_info(crate_dir)?;
	let mut target = polkavm_linker::TargetJsonArgs::default();
	target.is_64_bit = true;
	target.rustc_version = polkavm_linker::RustcVersion::Legacy;
	let target_json = polkavm_linker::target_json_path(target)?;

	let status = Command::new("cargo")
		.current_dir(crate_dir)
		.env_clear()
		.env("PATH", std::env::var("PATH").unwrap_or_default())
		.env("HOME", std::env::var("HOME").unwrap_or_default())
		.env("CARGO_ENCODED_RUSTFLAGS", "-C\x1fpanic=abort")
		.env("CARGO_TARGET_DIR", target_dir)
		.env("RUSTC_BOOTSTRAP", "1")
		.arg(format!("+{TOOLCHAIN}"))
		.args(["rustc", "--lib", "--crate-type=cdylib", "-Z", "build-std=core,alloc"])
		.args(["-Z", "build-std-features=panic_immediate_abort"])
		.arg(format!("--profile={PROFILE}"))
		.arg("--target")
		.arg(&target_json)
		.status()
		.map_err(|e| format!("cannot run cargo: {e}"))?;
	if !status.success() {
		return Err(format!(
			"cargo build failed (is `{TOOLCHAIN}` installed with rust-src? \
			 `rustup toolchain install {TOOLCHAIN} -c rust-src`)"
		));
	}

	let elf_path = target_dir
		.join("riscv64emac-unknown-none-polkavm")
		.join(PROFILE)
		.join(format!("{}.elf", info.name.replace('-', "_")));
	let elf = std::fs::read(&elf_path).map_err(|e| format!("cannot read {}: {e}", elf_path.display()))?;
	let mut config = polkavm_linker::Config::default();
	config.set_strip(true);
	config.set_dispatch_table(kind.dispatch_table());
	let linked =
		polkavm_linker::program_from_elf(config, polkavm_linker::TargetInstructionSet::JamV1, &elf)
			.map_err(|e| format!("cannot link PVM program: {e}"))?;
	let parts = polkavm_linker::ProgramParts::from_bytes(linked.into())
		.map_err(|e| format!("cannot parse linked program: {e}"))?;

	let name = info.name.clone();
	let metadata = ConventionalMetadata::Info(info).encode();
	let jam_blob = ProgramBlob::from_pvm(&parts, metadata.into()).to_vec()?;
	let (blob, ext) = match kind {
		Kind::Service => (jam_blob, "jam"),
		Kind::Check => {
			let mut rest = &jam_blob[..];
			jam_program_blob_common::read_metadata_slice(&mut rest).ok_or("blob has no metadata")?;
			StandardProgram::parse(rest).ok_or("built blob is not a standard program")?;
			(rest.to_vec(), "check")
		},
	};

	std::fs::create_dir_all(out_dir).map_err(|e| format!("cannot create {}: {e}", out_dir.display()))?;
	let out = out_dir.join(format!("{name}.{ext}"));
	std::fs::write(&out, &blob).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
	println!("wrote {}", out.display());
	println!("  len  {}", blob.len());
	println!("  hash 0x{}", hex(&blake2b256(&blob)));
	Ok(())
}

fn crate_info(crate_dir: &Path) -> Result<CrateInfo, String> {
	let output = Command::new("cargo")
		.current_dir(crate_dir)
		.arg("read-manifest")
		.output()
		.map_err(|e| format!("cannot run cargo read-manifest: {e}"))?;
	if !output.status.success() {
		return Err(String::from_utf8_lossy(&output.stderr).into_owned());
	}
	let manifest: serde_json::Value =
		serde_json::from_slice(&output.stdout).map_err(|e| format!("bad manifest json: {e}"))?;
	let field = |name: &str| manifest[name].as_str().unwrap_or_default().to_string();
	Ok(CrateInfo {
		name: field("name"),
		version: field("version"),
		license: field("license"),
		authors: manifest["authors"]
			.as_array()
			.map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
			.unwrap_or_default(),
	})
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}
