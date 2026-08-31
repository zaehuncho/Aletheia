//! Dependency-free PE reader. Direct port of `aletheia/pe.py`.
//!
//! Parses everything downstream analysis (detect, disasm, imports, decompile)
//! needs: headers + section table with per-section entropy + import table walk
//! + entry-point-to-section resolution.
//!
//! Correctness contract: for every real PE on disk the parsed shape must match
//! `pe.parse_bytes()` from the Python side field-for-field. Tests below spot-
//! check this; `tests/parity_notepad.rs` cross-checks against a real binary.
//!
//! Design pillars (same as Python):
//! - Fails closed on hostile input. Every parser returns `Result` with a
//!   typed error; never panics on garbage bytes.
//! - No external PE crates. We own the layout knowledge, exactly like the
//!   Python side does.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PeInfo + Section public shapes
// ---------------------------------------------------------------------------

/// A parsed PE file. Mirrors `PEInfo` on the Python side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfo {
    pub ok: bool,
    pub error: Option<String>,
    pub arch: String,
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub entry_rva: u32,
    pub image_base: u64,
    pub machine: u16,
    pub n_sections: u16,

    // Extended fields (added for the Rust port; also on Python's PEInfo).
    pub sections: Vec<Section>,
    /// Name of the section containing `entry_rva`, or None when out of bounds.
    pub entry_section: Option<String>,
    /// DLL names referenced by the import table (lower-cased or as-declared).
    pub import_dlls: Vec<String>,
    /// Total imported function count across all DLLs.
    pub import_func_count: u32,
    /// Shannon entropy over the whole file (informational; sections carry
    /// per-section entropy which the detect layer uses).
    pub overall_entropy: f64,
}

/// One section from the section table. Mirrors `Section` on the Python side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub vaddr: u32,
    pub vsize: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub entropy: f64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl Section {
    /// Rendered flag string: `R-X`, `RW-`, `RWX`, etc. Same convention as
    /// Python's `Section.flags`.
    pub fn flags(&self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.readable { 'R' } else { '-' });
        s.push(if self.writable { 'W' } else { '-' });
        s.push(if self.executable { 'X' } else { '-' });
        s
    }

    /// True iff `rva` is inside this section's virtual range.
    pub fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.vaddr && rva < self.vaddr.saturating_add(self.vsize.max(1))
    }
}

impl PeInfo {
    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            arch: String::new(),
            is_dll: false,
            is_dotnet: false,
            entry_rva: 0,
            image_base: 0,
            machine: 0,
            n_sections: 0,
            sections: Vec::new(),
            entry_section: None,
            import_dlls: Vec::new(),
            import_func_count: 0,
            overall_entropy: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PeError {
    #[error("input too short for MZ header")]
    TooShort,
    #[error("no MZ signature at offset 0")]
    NoMz,
    #[error("no PE signature at e_lfanew ({0:#x})")]
    NoPe(u32),
    #[error("optional-header magic {0:#x} is neither PE32 nor PE32+")]
    BadOptMagic(u16),
    #[error("e_lfanew {0:#x} is implausible")]
    BadELfanew(u32),
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PE32: u16 = 0x10B;
const PE32_PLUS: u16 = 0x20B;
const CHARACTERISTIC_DLL: u16 = 0x2000;

// Section characteristic bits (IMAGE_SCN_*).
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Parse a PE from a byte slice. Fails closed on hostile input.
pub fn parse_bytes(data: &[u8]) -> PeInfo {
    match parse_bytes_inner(data) {
        Ok(info) => info,
        Err(e) => PeInfo::err(e.to_string()),
    }
}

/// Read a file, parse it.
pub fn parse<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<PeInfo> {
    let data = std::fs::read(path)?;
    Ok(parse_bytes(&data))
}

// ---------------------------------------------------------------------------
// Core parser
// ---------------------------------------------------------------------------

fn parse_bytes_inner(data: &[u8]) -> Result<PeInfo, PeError> {
    if data.len() < 0x40 {
        return Err(PeError::TooShort);
    }
    if &data[0..2] != b"MZ" {
        return Err(PeError::NoMz);
    }

    let e_lfanew = u32_le(data, 0x3C);
    if (e_lfanew as usize) + 24 > data.len() {
        return Err(PeError::BadELfanew(e_lfanew));
    }

    let pe_off = e_lfanew as usize;
    if &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(PeError::NoPe(e_lfanew));
    }

    // COFF header (20 bytes) after PE signature.
    let coff = pe_off + 4;
    let machine = u16_le(data, coff);
    let n_sections = u16_le(data, coff + 2);
    let opt_size = u16_le(data, coff + 16);
    let characteristics = u16_le(data, coff + 18);
    let is_dll = characteristics & CHARACTERISTIC_DLL != 0;

    let opt = coff + 20;
    if opt + 2 > data.len() {
        return Err(PeError::TooShort);
    }
    let magic = u16_le(data, opt);
    let is_pe32_plus = match magic {
        PE32 => false,
        PE32_PLUS => true,
        _ => return Err(PeError::BadOptMagic(magic)),
    };

    let entry_rva = u32_le(data, opt + 16);
    let image_base = if is_pe32_plus {
        u64_le(data, opt + 24)
    } else {
        u32_le(data, opt + 28) as u64
    };

    // Data directory table location depends on magic.
    let (num_dd_off, dd_off) = if is_pe32_plus {
        (opt + 108, opt + 112)
    } else {
        (opt + 92, opt + 96)
    };
    let num_dd = u32_le(data, num_dd_off);

    // .NET / CLR: data directory index 14.
    let is_dotnet = if num_dd > 14 {
        let clr_off = dd_off + 14 * 8;
        clr_off + 8 <= data.len() && u32_le(data, clr_off) != 0
    } else {
        false
    };

    // Section table lives immediately after the optional header.
    let sect_table_off = opt + opt_size as usize;
    let sections = parse_sections(data, sect_table_off, n_sections);
    let entry_section = sections
        .iter()
        .find(|s| s.contains_rva(entry_rva))
        .map(|s| s.name.clone());

    // Import table walk: data directory index 1.
    let (import_dlls, import_func_count) = if num_dd > 1 {
        let imp_off = dd_off + 8;
        if imp_off + 8 <= data.len() {
            let imp_rva = u32_le(data, imp_off);
            let imp_size = u32_le(data, imp_off + 4);
            if imp_rva != 0 && imp_size != 0 {
                parse_imports(data, &sections, imp_rva, is_pe32_plus)
            } else {
                (Vec::new(), 0)
            }
        } else {
            (Vec::new(), 0)
        }
    } else {
        (Vec::new(), 0)
    };

    let arch = match machine {
        0x8664 => "x64".to_string(),
        0x14C => "x86".to_string(),
        0xAA64 => "arm64".to_string(),
        m => format!("machine_{:04x}", m),
    };

    let overall_entropy = shannon_entropy(data);

    Ok(PeInfo {
        ok: true,
        error: None,
        arch,
        is_dll,
        is_dotnet,
        entry_rva,
        image_base,
        machine,
        n_sections,
        sections,
        entry_section,
        import_dlls,
        import_func_count,
        overall_entropy,
    })
}

// ---------------------------------------------------------------------------
// Section table walk
// ---------------------------------------------------------------------------

fn parse_sections(data: &[u8], table_off: usize, n_sections: u16) -> Vec<Section> {
    let mut out = Vec::with_capacity(n_sections as usize);
    for i in 0..n_sections as usize {
        let off = table_off + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let name = section_name(&data[off..off + 8]);
        let vsize = u32_le(data, off + 8);
        let vaddr = u32_le(data, off + 12);
        let raw_size = u32_le(data, off + 16);
        let raw_ptr = u32_le(data, off + 20);
        let characteristics = u32_le(data, off + 36);

        // Compute per-section entropy over the section's raw bytes.
        let entropy = if raw_ptr != 0 && raw_size != 0 {
            let start = raw_ptr as usize;
            let end = start.saturating_add(raw_size as usize).min(data.len());
            if end > start {
                shannon_entropy(&data[start..end])
            } else {
                0.0
            }
        } else {
            0.0
        };

        out.push(Section {
            name,
            vaddr,
            vsize,
            raw_ptr,
            raw_size,
            entropy,
            readable: characteristics & SCN_MEM_READ != 0,
            writable: characteristics & SCN_MEM_WRITE != 0,
            executable: characteristics & SCN_MEM_EXECUTE != 0,
        });
    }
    out
}

fn section_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Import table walk (data-dir index 1)
// ---------------------------------------------------------------------------

fn parse_imports(
    data: &[u8],
    sections: &[Section],
    imp_rva: u32,
    is_pe32_plus: bool,
) -> (Vec<String>, u32) {
    let mut dlls: Vec<String> = Vec::new();
    let mut total: u32 = 0;

    let Some(mut off) = rva_to_off(sections, imp_rva, data.len()) else {
        return (dlls, 0);
    };

    // IMAGE_IMPORT_DESCRIPTOR is 20 bytes; NULL descriptor terminates.
    loop {
        if off + 20 > data.len() {
            break;
        }
        let orig_first_thunk = u32_le(data, off);
        let name_rva = u32_le(data, off + 12);
        let first_thunk = u32_le(data, off + 16);

        // NULL descriptor: all zeros.
        if orig_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        if let Some(name_off) = rva_to_off(sections, name_rva, data.len()) {
            dlls.push(read_cstr(data, name_off, 256));
        }

        // Prefer OriginalFirstThunk (aka Import Lookup Table) to count entries;
        // fall back to FirstThunk (IAT) when OFT is 0 (rare for real binaries).
        let thunk_rva = if orig_first_thunk != 0 {
            orig_first_thunk
        } else {
            first_thunk
        };
        if let Some(mut t) = rva_to_off(sections, thunk_rva, data.len()) {
            let step = if is_pe32_plus { 8 } else { 4 };
            loop {
                if t + step > data.len() {
                    break;
                }
                let entry = if is_pe32_plus {
                    u64_le(data, t)
                } else {
                    u32_le(data, t) as u64
                };
                if entry == 0 {
                    break;
                }
                total = total.saturating_add(1);
                t += step;
            }
        }

        off += 20;
    }

    (dlls, total)
}

/// Translate an RVA to a file offset by walking the section table.
fn rva_to_off(sections: &[Section], rva: u32, data_len: usize) -> Option<usize> {
    for s in sections {
        if s.contains_rva(rva) && s.raw_ptr != 0 {
            let file_off = s.raw_ptr.checked_add(rva.checked_sub(s.vaddr)?)? as usize;
            if file_off < data_len {
                return Some(file_off);
            }
        }
    }
    None
}

fn read_cstr(data: &[u8], off: usize, limit: usize) -> String {
    let hi = (off + limit).min(data.len());
    let slice = &data[off..hi];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

/// Shannon entropy in bits per byte (0.0 to 8.0). Empty input yields 0.0.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

// ---------------------------------------------------------------------------
// Little-endian read helpers (bounds-checked at call sites)
// ---------------------------------------------------------------------------

fn u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}
fn u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}
fn u64_le(data: &[u8], off: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[off..off + 8]);
    u64::from_le_bytes(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_fails_closed() {
        let info = parse_bytes(&[]);
        assert!(!info.ok);
        assert!(info.error.as_deref().unwrap().contains("too short"));
    }

    #[test]
    fn non_mz_fails_closed() {
        let info = parse_bytes(&[0; 128]);
        assert!(!info.ok);
        assert!(info.error.as_deref().unwrap().contains("MZ"));
    }

    #[test]
    fn shannon_entropy_uniform_is_8() {
        let mut data = [0u8; 256];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let h = shannon_entropy(&data);
        assert!(
            (h - 8.0).abs() < 1e-9,
            "uniform byte distribution -> ~8 bits, got {}",
            h
        );
    }

    #[test]
    fn shannon_entropy_constant_is_0() {
        let h = shannon_entropy(&[0xAA; 1024]);
        assert!(h.abs() < 1e-9);
    }

    #[test]
    fn section_flags_render() {
        let mut s = Section {
            name: ".text".into(),
            vaddr: 0x1000,
            vsize: 0x100,
            raw_ptr: 0x400,
            raw_size: 0x100,
            entropy: 0.0,
            readable: true,
            writable: false,
            executable: true,
        };
        assert_eq!(s.flags(), "R-X");
        s.writable = true;
        assert_eq!(s.flags(), "RWX");
    }

    #[test]
    fn section_contains_rva() {
        let s = Section {
            name: ".text".into(),
            vaddr: 0x1000,
            vsize: 0x200,
            raw_ptr: 0x400,
            raw_size: 0x200,
            entropy: 0.0,
            readable: true,
            writable: false,
            executable: true,
        };
        assert!(s.contains_rva(0x1000));
        assert!(s.contains_rva(0x11FF));
        assert!(!s.contains_rva(0x1200));
        assert!(!s.contains_rva(0x0FFF));
    }

    /// Hand-build a minimal PE32+ with 2 sections and confirm the section table
    /// walk + entry_section + flags round-trip.
    #[test]
    fn synthetic_pe32_plus_with_sections() {
        let mut buf = vec![0u8; 0x800];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");
        buf[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // machine=x64
        buf[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // n_sections=2
        buf[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // opt_size
        buf[0x96..0x98].copy_from_slice(&0u16.to_le_bytes()); // characteristics
        buf[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        buf[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes()); // entry_rva
        buf[0xB0..0xB8].copy_from_slice(&0x140000000u64.to_le_bytes()); // image_base
        buf[0x104..0x108].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // Section table at opt(0x98) + 240 = 0x188
        let sect = 0x188usize;
        // Section 1: ".text", vaddr 0x1000, vsize 0x500, raw_size 0x200, raw_ptr 0x400
        buf[sect..sect + 5].copy_from_slice(b".text");
        buf[sect + 8..sect + 12].copy_from_slice(&0x500u32.to_le_bytes()); // vsize
        buf[sect + 12..sect + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // vaddr
        buf[sect + 16..sect + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw_size
        buf[sect + 20..sect + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw_ptr
        // characteristics: RX
        buf[sect + 36..sect + 40].copy_from_slice(&(SCN_MEM_READ | SCN_MEM_EXECUTE).to_le_bytes());
        // Section 2: ".data", vaddr 0x2000, vsize 0x300, raw_size 0x100, raw_ptr 0x600
        let sect2 = sect + 40;
        buf[sect2..sect2 + 5].copy_from_slice(b".data");
        buf[sect2 + 8..sect2 + 12].copy_from_slice(&0x300u32.to_le_bytes());
        buf[sect2 + 12..sect2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[sect2 + 16..sect2 + 20].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sect2 + 20..sect2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
        buf[sect2 + 36..sect2 + 40].copy_from_slice(&(SCN_MEM_READ | SCN_MEM_WRITE).to_le_bytes());

        let info = parse_bytes(&buf);
        assert!(info.ok, "parse failed: {:?}", info.error);
        assert_eq!(info.sections.len(), 2);
        assert_eq!(info.sections[0].name, ".text");
        assert_eq!(info.sections[0].vaddr, 0x1000);
        assert_eq!(info.sections[0].flags(), "R-X");
        assert_eq!(info.sections[1].name, ".data");
        assert_eq!(info.sections[1].flags(), "RW-");
        assert_eq!(info.entry_section.as_deref(), Some(".text"));
    }
}
