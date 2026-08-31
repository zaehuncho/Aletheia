//! Aletheia analysis engine, ported from the Python reference at ../../aletheia/.
//!
//! ## Layout mirrors the Python side so the port stays 1:1 auditable
//!
//! | Python                     | Rust                            |
//! |----------------------------|---------------------------------|
//! | `aletheia/pe.py`           | [`pe`]                          |
//! | `aletheia/detect.py`       | [`detect`]                      |
//! | `aletheia/disasm.py`       | *(next)*                        |
//!
//! ## Correctness gate
//!
//! Every module ported must reproduce byte-identical output on the shared
//! golden files at `../../tests/goldens/decompile/*.golden.c`. The goldens
//! are the contract.
//!
//! ## Design pillars carried over from Python
//!
//! - Fails closed on hostile input. Every parser returns `Result` with a
//!   typed error; never panics on garbage bytes.
//! - Zero required deps beyond stdlib + serde + thiserror. No external PE
//!   crates -- we own the parser exactly as the Python side does.
//! - Honest limits documented on the type itself.

pub mod pe;
pub mod detect;
pub mod disasm;
pub mod decompile;
pub mod unpack;

/// Crate-wide error type. Module errors convert into this.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("PE parse error: {0}")]
    Pe(#[from] pe::PeError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Convenience: parse a PE + compute its packer verdict in one call.
///
/// Reads the file so it can pass the raw bytes to `detect::analyze` (Lethe's
/// magic requires seeing the file body, not just parsed structures).
pub fn analyze_path<P: AsRef<std::path::Path>>(path: P) -> Result<(pe::PeInfo, detect::Verdict)> {
    let raw = std::fs::read(&path)?;
    let info = pe::parse_bytes(&raw);
    let verdict = detect::analyze(&info, Some(&raw));
    Ok((info, verdict))
}
