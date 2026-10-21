//! Native harness for the no_std port of nanoda.
//!
//!     host-check EXPORT                             check every declaration in an export
//!     host-check bind ENV DELTA STATEMENT THEOREM   check a bounty submission (see binding.rs)
//!
//! `bind` prints ACCEPTED or REJECTED with the reason, and exits 0 or 1.
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["bind", env, delta, statement, theorem] => bind(env, delta, statement, theorem),
        [path] => check_all(path),
        _ => {
            eprintln!("usage: host-check EXPORT | host-check bind ENV DELTA STATEMENT THEOREM");
            std::process::exit(2);
        },
    }
}

/// Exports may be lean4export NDJSON or the binary format; the checker tells them apart.
fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

fn check_all(path: &str) {
    let export = read(path);
    let axioms = ["propext", "Classical.choice", "Quot.sound", "Lean.trustCompiler"].map(String::from).to_vec();
    let t = Instant::now();
    let (file, skipped) =
        nanoda_lib::util::Config::in_memory(axioms).parse_export_bytes(&export).expect("parse");
    let parsed = t.elapsed();
    file.check_all_declars();
    println!(
        "{} bytes, {} declarations, parse {:?}, check {:?}, skipped axioms {:?}",
        export.len(), file.declars.len(), parsed, t.elapsed() - parsed, skipped
    );
}

fn bind(env_path: &str, delta_path: &str, statement: &str, theorem: &str) {
    let (env, delta) = (read(env_path), read(delta_path));
    // Type errors panic inside the checker; report them as rejections.
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<String, String> {
        let t = Instant::now();
        let bound = nanoda_lib::binding::parse(&env, &delta).map_err(|e| e.to_string())?;
        let parsed = t.elapsed();
        bound.check_binding(statement, theorem)?;
        let t = Instant::now();
        bound.check_env();
        let env_checked = t.elapsed();
        let t = Instant::now();
        bound.check_delta();
        let delta_checked = t.elapsed();
        Ok(format!(
            "env {} B / {} decls, delta {} B / {} decls; parse {:?}, check env {:?}, check delta {:?}",
            env.len(),
            bound.env_declars,
            delta.len(),
            bound.file.declars.len() - bound.env_declars,
            parsed,
            env_checked,
            delta_checked,
        ))
    }));
    let result = match outcome {
        Ok(result) => result,
        Err(panic) => Err(panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "checker panicked".into())),
    };
    match result {
        Ok(stats) => println!("ACCEPTED  {stats}"),
        Err(reason) => {
            println!("REJECTED  {reason}");
            std::process::exit(1);
        },
    }
}
