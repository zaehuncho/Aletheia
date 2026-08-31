//! Static packer / protector detection. Direct port of `aletheia/detect.py`.
//!
//! Given a parsed PE, decide whether it looks packed and name the protector
//! when the fingerprints are unambiguous. Purely static — never runs the
//! sample. Combines cheap robust signals (entropy, W^X, import elision, entry
//! outside `.text`, virtual-vs-raw inflation) with a section-name signature DB.
//!
//! Every signal is a heuristic, not a proof. The verdict carries a confidence
//! and the exact signals that fed it so a human or the dynamic layer can call it.
//!
//! Correctness contract: verdict semantics (packed/confidence/likely_packer/
//! signals list) match `aletheia/detect.py` on the same input. Signal text
//! phrasing may differ; the classification (packed vs clean, which packer)
//! must not.

use crate::pe::PeInfo;
use serde::{Deserialize, Serialize};

/// Packer verdict. Mirrors the Python `Verdict` dataclass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub packed: bool,
    pub confidence: f64,
    pub likely_packer: Option<String>,
    pub signals: Vec<String>,
}

impl Verdict {
    /// Short one-line summary suitable for a UI badge / CLI line.
    pub fn summary(&self) -> String {
        let head = if self.packed {
            format!("PACKED (confidence {:.0}%)", self.confidence * 100.0)
        } else {
            format!(
                "likely clean (confidence {:.0}%)",
                (1.0 - self.confidence) * 100.0
            )
        };
        match &self.likely_packer {
            Some(p) => format!("{} - {}", head, p),
            None => head,
        }
    }
}

/// Known protectors keyed by their characteristic section names. Case-
/// insensitive match; entries here must stay lower-case.
const SECTION_SIGS: &[(&str, &[&str])] = &[
    ("UPX", &["upx0", "upx1", "upx2", "upx!"]),
    ("VMProtect", &[".vmp0", ".vmp1", ".vmp2"]),
    ("Themida/WinLicense", &[".themida", ".winlice", ".winlicen", ".taz"]),
    ("Enigma Protector", &[".enigma1", ".enigma2"]),
    ("ASPack", &[".aspack", ".adata"]),
    ("Petite", &[".petite"]),
    ("MPRESS", &[".mpress1", ".mpress2"]),
    ("PECompact", &["pec1", "pec2"]),
    ("MEW", &["mew"]),
    ("FSG", &["fsg!"]),
    ("Obsidium", &[".obsidium"]),
    // "Lethe" detected by container magic in `raw`, not by section name.
];

/// Section names a normal MSVC/GCC/clang binary uses; anything else is a mild flag.
const NORMAL_NAMES: &[&str] = &[
    ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc", ".bss", ".tls",
    ".idata", ".edata", ".xdata", ".00cfg", ".gfids", ".didat", ".debug",
    ".voltbl", ".sxdata", ".textbss", ".cormeta",
    "fothk", "_rdata", "protdata", ".retplne", ".giats", ".gehcont", "cpadinfo", "malloc_h",
];

/// Return the packer name when a section-name signature matches, else `None`.
fn classify_by_section_names(names: &[String]) -> Option<&'static str> {
    let low: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    for (packer, sigs) in SECTION_SIGS {
        if sigs.iter().any(|s| low.iter().any(|n| n == s)) {
            return Some(packer);
        }
    }
    None
}

/// Analyze a parsed PE. `raw` (the file bytes) enables magic-based fingerprints.
///
/// Mirrors `aletheia/detect.py::analyze` including the score weights, the order
/// signals are checked, and the threshold (`confidence >= 0.5` -> packed).
pub fn analyze(pe: &PeInfo, raw: Option<&[u8]>) -> Verdict {
    let mut signals: Vec<String> = Vec::new();
    let mut score = 0.0f64;
    let names: Vec<String> = pe.sections.iter().map(|s| s.name.clone()).collect();

    let mut packer: Option<String> = classify_by_section_names(&names).map(String::from);
    if let Some(p) = &packer {
        signals.push(format!("known {} section name present", p));
        score += 0.9;
    }

    // Lethe's own container magic.
    if let Some(bytes) = raw {
        if contains_subsequence(bytes, b"LETHE01") {
            if packer.is_none() {
                packer = Some("Lethe".to_string());
            }
            signals.push("Lethe container magic (LETHE01) present".to_string());
            score += 0.9;
        }
    }

    if pe.is_dotnet {
        signals.push(".NET/CLR image (managed - native packing heuristics N/A)".to_string());
    }

    // High-entropy code/data.
    let high: Vec<&crate::pe::Section> = pe
        .sections
        .iter()
        .filter(|s| s.raw_size >= 512 && s.entropy >= 7.2)
        .collect();
    if !high.is_empty() {
        let worst = high
            .iter()
            .max_by(|a, b| a.entropy.partial_cmp(&b.entropy).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap();
        signals.push(format!(
            "{} high-entropy section(s) (max {:.2} bits/byte in '{}')",
            high.len(),
            worst.entropy,
            worst.name
        ));
        score += 0.4;
    }

    // Writable + executable: a self-modifying / unpacking tell.
    let rwx: Vec<&crate::pe::Section> = pe
        .sections
        .iter()
        .filter(|s| s.writable && s.executable)
        .collect();
    if !rwx.is_empty() {
        let joined = rwx
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        signals.push(format!("writable+executable section(s): {}", joined));
        score += 0.5;
    }

    // Entry point outside a conventional code section.
    match &pe.entry_section {
        Some(s) if s.to_lowercase() != ".text" && s.to_lowercase() != ".textbss" => {
            signals.push(format!("entry point in '{}', not .text", s));
            score += 0.3;
        }
        None if pe.entry_rva != 0 => {
            signals.push("entry point maps to no section (out of bounds)".to_string());
            score += 0.4;
        }
        _ => {}
    }

    // Import elision.
    if pe.import_func_count == 0 && !pe.is_dotnet {
        signals.push("no import table (imports fully elided/resolved at runtime)".to_string());
        score += 0.5;
    } else if pe.import_func_count > 0 && pe.import_func_count <= 8 {
        signals.push(format!(
            "very few imports ({} functions from {} DLL(s)) - possible elision",
            pe.import_func_count,
            pe.import_dlls.len()
        ));
        score += 0.35;
    }

    // Virtual size >> raw size on an executable section.
    let inflated: Vec<&crate::pe::Section> = pe
        .sections
        .iter()
        .filter(|s| s.executable && s.raw_size > 0 && s.vsize > 4 * s.raw_size)
        .collect();
    if !inflated.is_empty() {
        signals.push(
            "code section virtual size >> raw size (room reserved for unpacking)".to_string(),
        );
        score += 0.2;
    }

    // Non-standard section names.
    if packer.is_none() {
        let normal: std::collections::HashSet<&str> = NORMAL_NAMES.iter().copied().collect();
        let all_sig_names: std::collections::HashSet<String> = SECTION_SIGS
            .iter()
            .flat_map(|(_, sigs)| sigs.iter().copied().map(String::from))
            .collect();
        let weird: Vec<&String> = names
            .iter()
            .filter(|n| {
                let lower = n.to_lowercase();
                !normal.contains(lower.as_str()) && !all_sig_names.contains(&lower)
            })
            .collect();
        if !weird.is_empty() {
            let sample = weird
                .iter()
                .take(6)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            signals.push(format!("non-standard section name(s): {}", sample));
            score += 0.15;
        }
    }

    let confidence = score.min(1.0);
    Verdict {
        packed: confidence >= 0.5,
        confidence,
        likely_packer: packer,
        signals,
    }
}

/// Fast naive `haystack.contains(needle)` for byte slices.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{PeInfo, Section};

    fn empty_pe() -> PeInfo {
        PeInfo {
            ok: true, error: None, arch: "x64".into(), is_dll: false, is_dotnet: false,
            entry_rva: 0x1000, image_base: 0x140000000, machine: 0x8664, n_sections: 0,
            sections: vec![], entry_section: None, import_dlls: vec![],
            import_func_count: 0, overall_entropy: 0.0,
        }
    }

    fn sect(name: &str, w: bool, x: bool, entropy: f64, raw: u32, v: u32) -> Section {
        Section {
            name: name.to_string(), vaddr: 0x1000, vsize: v, raw_ptr: 0x400,
            raw_size: raw, entropy,
            readable: true, writable: w, executable: x,
        }
    }

    #[test]
    fn clean_binary_reads_clean() {
        let mut pe = empty_pe();
        pe.sections = vec![
            sect(".text",  false, true,  5.5, 4096, 4096),
            sect(".rdata", false, false, 4.5, 2048, 2048),
            sect(".data",  true,  false, 3.5, 1024, 1024),
        ];
        pe.entry_section = Some(".text".into());
        pe.import_dlls = vec!["kernel32.dll".into(), "user32.dll".into()];
        pe.import_func_count = 25;
        let v = analyze(&pe, None);
        assert!(!v.packed, "expected clean, got: {}", v.summary());
        assert!(v.likely_packer.is_none());
    }

    #[test]
    fn upx_section_names_trip_upx() {
        let mut pe = empty_pe();
        pe.sections = vec![
            sect("UPX0", false, false, 0.0, 0, 4096),
            sect("UPX1", true,  true,  7.9, 4096, 4096),
        ];
        pe.entry_section = Some("UPX1".into());
        pe.import_func_count = 3;
        let v = analyze(&pe, None);
        assert!(v.packed);
        assert_eq!(v.likely_packer.as_deref(), Some("UPX"));
    }

    #[test]
    fn lethe_magic_triggers_lethe() {
        let pe = empty_pe();
        let raw = b"...random garbage LETHE01 more garbage...";
        let v = analyze(&pe, Some(raw));
        assert_eq!(v.likely_packer.as_deref(), Some("Lethe"));
        assert!(v.packed);
    }

    #[test]
    fn writable_executable_section_signals() {
        let mut pe = empty_pe();
        pe.sections = vec![sect(".text", true, true, 5.5, 4096, 4096)];
        pe.entry_section = Some(".text".into());
        pe.import_func_count = 10;
        let v = analyze(&pe, None);
        assert!(v.signals.iter().any(|s| s.contains("writable+executable")));
    }

    #[test]
    fn high_entropy_section_flagged() {
        let mut pe = empty_pe();
        pe.sections = vec![sect(".text", false, true, 7.85, 4096, 4096)];
        pe.entry_section = Some(".text".into());
        pe.import_func_count = 10;
        let v = analyze(&pe, None);
        assert!(v.signals.iter().any(|s| s.contains("high-entropy")));
    }

    #[test]
    fn zero_imports_flagged_as_elision() {
        let mut pe = empty_pe();
        pe.sections = vec![sect(".text", false, true, 5.5, 4096, 4096)];
        pe.entry_section = Some(".text".into());
        pe.import_func_count = 0;
        let v = analyze(&pe, None);
        assert!(v.signals.iter().any(|s| s.contains("no import table")));
    }

    #[test]
    fn summary_render() {
        let mut pe = empty_pe();
        pe.sections = vec![sect(".text", false, true, 5.5, 4096, 4096)];
        pe.entry_section = Some(".text".into());
        pe.import_func_count = 25;
        let v = analyze(&pe, None);
        assert!(v.summary().contains("likely clean"));
    }
}
