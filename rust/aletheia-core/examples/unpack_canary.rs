//! End-to-end demo: run the dynamic unpack detector against the benign
//! `test-corpus/canary/target/release/aletheia_canary.exe`.
//!
//! Expected: `detected == true`, with the OEP inside the RWX buffer the
//! canary VirtualAlloc'd (i.e. outside every loaded module).
//!
//! Run:
//!   cargo run -p aletheia-core --release --example unpack_canary

use aletheia_core::unpack::{UnpackOptions, run_unpack};

fn main() {
    // Resolve `../../test-corpus/canary/target/release/aletheia_canary.exe`
    // relative to the workspace root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR"); // rust/aletheia-core
    let candidate = std::path::Path::new(manifest_dir)
        .join("..").join("..")
        .join("test-corpus").join("canary").join("target").join("release")
        .join("aletheia_canary.exe");
    let canary = candidate.canonicalize().unwrap_or_else(|_| candidate.clone());
    println!("[demo] canary path: {}", canary.display());
    if !canary.exists() {
        eprintln!("[demo] canary not built. From repo root:");
        eprintln!("       cd test-corpus/canary && cargo build --release");
        std::process::exit(2);
    }

    // Quote in case the path has spaces.
    let cmd = format!("\"{}\"", canary.display());
    let opts = UnpackOptions { max_steps: 200_000, timeout_ms: 15_000 };

    let started = std::time::Instant::now();
    let r = match run_unpack(&cmd, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[demo] run_unpack failed: {e}");
            std::process::exit(1);
        }
    };
    let elapsed = started.elapsed();

    println!("[demo] elapsed:    {:?}", elapsed);
    println!("[demo] detected:   {}", r.detected);
    println!("[demo] main_base:  {:#x}", r.main_base);
    if let Some(oep) = r.oep {
        println!("[demo] OEP:        {:#x} (outside every loaded module)", oep);
        println!("[demo] OEP - main: {:#x}", oep.wrapping_sub(r.main_base));
    } else {
        println!("[demo] OEP:        (none)");
    }
    println!("[demo] exit_code:  {:?}", r.exit_code);
    println!("[demo] gave_up:    {}", r.gave_up);
    println!("[demo] reason:     {}", r.reason);

    if r.detected {
        println!("\n[demo] PASS - write-then-execute detected on canary");
    } else {
        eprintln!("\n[demo] FAIL - detector did not fire on canary");
        std::process::exit(1);
    }
}
