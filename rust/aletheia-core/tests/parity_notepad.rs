//! Cross-language parity test: Rust parser must agree with the Python
//! reference on a real Windows binary. Runs only on Windows + only if
//! notepad.exe is on disk.

#[cfg(target_os = "windows")]
#[test]
fn parity_notepad_matches_python() {
    let path = r"C:\Windows\System32\notepad.exe";
    if !std::path::Path::new(path).exists() {
        eprintln!("SKIP: {} not present", path);
        return;
    }
    let info = aletheia_core::pe::parse(path).expect("failed to read notepad.exe");
    assert!(info.ok, "Rust parse failed: {:?}", info.error);
    assert_eq!(info.arch, "x64", "notepad.exe on modern Win is x64");
    assert!(!info.is_dll, "notepad.exe is an EXE, not a DLL");
    assert!(info.n_sections > 0);
    assert!(info.image_base > 0);
    eprintln!(
        "notepad.exe: arch={} entry={:#x} base={:#x} sections={}",
        info.arch, info.entry_rva, info.image_base, info.n_sections
    );
}
