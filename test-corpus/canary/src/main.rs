//! ALETHEIA_TEST_CANARY -- benign write-then-execute demo binary.
//!
//! Exercises the classic self-unpacker shape on purpose so we can point
//! Aletheia at it and see the detectors fire:
//!   1. `VirtualAlloc(RWX)` a page (writable + executable is the W^X flag)
//!   2. Copy a four-byte "shellcode" (xor rax,rax ; ret) into it
//!   3. Jump into the freshly written buffer via a function pointer
//!   4. Return cleanly, print result, exit
//!
//! This binary is HARMLESS. The shellcode zeroes rax and returns. Run it
//! from a terminal to convince yourself; it prints a banner + the result.
//! Do not pack + redistribute this as if it were something else.

use std::ffi::c_void;

use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE,
    PAGE_EXECUTE_READWRITE,
};

/// x64 machine code: `xor rax, rax ; ret` (4 bytes). Zeroes eax + returns.
const SHELLCODE: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3];

/// Marker string the analyzer's `detect` can look for to confirm this is
/// the canary. Not obfuscated -- being visible in `strings` is the point.
const MARKER: &str = "ALETHEIA_TEST_CANARY";

fn main() {
    println!("[{}] benign write-then-execute demo", MARKER);
    println!("  1. VirtualAlloc(RWX, 4 KiB)");

    let region: *mut c_void = unsafe {
        VirtualAlloc(
            core::ptr::null(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if region.is_null() {
        eprintln!("VirtualAlloc failed");
        std::process::exit(1);
    }

    println!("  2. write {} bytes of shellcode into RWX page", SHELLCODE.len());
    unsafe { core::ptr::copy_nonoverlapping(SHELLCODE.as_ptr(), region as *mut u8, SHELLCODE.len()) };

    println!("  3. jump into the buffer via a fn pointer");
    let f: unsafe extern "C" fn() -> u64 = unsafe { core::mem::transmute(region) };
    let rax = unsafe { f() };

    println!("  4. returned; rax = {}", rax);
    unsafe { VirtualFree(region, 0, MEM_RELEASE) };
}
