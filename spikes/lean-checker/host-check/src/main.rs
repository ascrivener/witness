//! Native baseline: check a lean4export NDJSON file with the no_std port of nanoda.
use std::time::Instant;

fn main() {
    let path = std::env::args().nth(1).expect("usage: host-check <export.ndjson>");
    let export = std::fs::read_to_string(&path).expect("read export");
    let axioms = ["propext", "Classical.choice", "Quot.sound", "Lean.trustCompiler"].map(String::from).to_vec();
    let t = Instant::now();
    let (file, skipped) =
        nanoda_lib::util::Config::in_memory(axioms).parse_export(&export).expect("parse");
    let parsed = t.elapsed();
    file.check_all_declars();
    println!(
        "{} bytes, {} declarations, parse {:?}, check {:?}, skipped axioms {:?}",
        export.len(), file.declars.len(), parsed, t.elapsed() - parsed, skipped
    );
}
