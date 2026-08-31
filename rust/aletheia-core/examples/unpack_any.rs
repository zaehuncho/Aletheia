//! Run the dynamic unpack detector against an arbitrary path.
//! Usage: cargo run -p aletheia-core --release --example unpack_any -- <path.exe>
use aletheia_core::unpack::{UnpackEvent, UnpackOptions, run_unpack};
fn main() {
    let path = std::env::args().nth(1).expect("usage: unpack_any <path.exe>");
    println!("[demo] target: {}", path);
    let cmd = format!("\"{}\"", path);
    let opts = UnpackOptions { max_steps: 500_000, timeout_ms: 20_000, ..Default::default() };
    let t0 = std::time::Instant::now();
    let r = run_unpack(&cmd, &opts).unwrap();
    let el = t0.elapsed();
    println!("[demo] elapsed:   {:?}", el);
    println!("[demo] detected:  {}", r.detected);
    println!("[demo] main_base: {:#x}", r.main_base);
    println!("[demo] OEP:       {}", r.oep.map(|o| format!("{:#x}", o)).unwrap_or("(none)".into()));
    println!("[demo] gave_up:   {}", r.gave_up);
    println!("[demo] reason:    {}", r.reason);
    if !r.events.is_empty() {
        println!("[demo] events ({}):", r.events.len());
        for e in &r.events {
            match e {
                UnpackEvent::Alloc { addr, size, protect } =>
                    println!("   Alloc          addr={:#x} size={:#x} protect={:#x}", addr, size, protect),
                UnpackEvent::ProtectFlipToX { addr, size, new_protect, dumped, .. } =>
                    println!("   ProtectFlipToX addr={:#x} size={:#x} new={:#x} bytes[0..16]={}",
                             addr, size, new_protect, &dumped[..32.min(dumped.len())]),
                UnpackEvent::ThreadFromNonImage { start } =>
                    println!("   ThreadCreate   start={:#x}", start),
                UnpackEvent::Wrote { page } =>
                    println!("   Wrote          page={:#x}", page),
            }
        }
    }
}
