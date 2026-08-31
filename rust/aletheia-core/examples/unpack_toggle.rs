use aletheia_core::unpack::{UnpackOptions, run_unpack};
fn main() {
    let path = std::env::args().nth(1).expect("usage: unpack_toggle <path.exe>");
    let anti = std::env::args().nth(2).map(|s| s == "1").unwrap_or(false);
    let guard = std::env::args().nth(3).map(|s| s == "1").unwrap_or(false);
    let api = std::env::args().nth(4).map(|s| s == "1").unwrap_or(false);
    let opts = UnpackOptions {
        max_steps: 500_000, timeout_ms: 20_000,
        anti_anti_debug: anti, guard_pages: guard, api_hooks: api,
    };
    println!("[demo] target={} anti={} guard={} api={}", path, anti, guard, api);
    let cmd = format!("\"{}\"", path);
    let t0 = std::time::Instant::now();
    let r = run_unpack(&cmd, &opts).unwrap();
    println!("[demo] elapsed={:?} detected={} reason={}", t0.elapsed(), r.detected, r.reason);
}
