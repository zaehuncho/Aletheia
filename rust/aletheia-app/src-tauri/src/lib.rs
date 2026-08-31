//! Aletheia Tauri front-end -- thin IPC surface over aletheia-core.
//!
//! Every #[tauri::command] here is a JS-callable seam that hands off to
//! aletheia-core and returns serde-serialized JSON. No analysis logic
//! lives in this crate -- keeping the engine consumable by non-Tauri
//! callers (CLI, tests, future WASM) is the whole reason we split
//! aletheia-core out.

use aletheia_core::detect::Verdict;
use aletheia_core::disasm::{self, BasicBlock, Instruction};
use aletheia_core::pe::{self, PeInfo, Section};
use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_PE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DISASM_BYTES: usize = 16 * 1024 * 1024;
const MAX_INSTRUCTION_COUNT: u32 = 10_000;

fn read_bounded_file(path: &str) -> Result<(PathBuf, Vec<u8>), String> {
    if path.trim().is_empty() {
        return Err("no file selected".to_string());
    }

    let canonical = std::fs::canonicalize(path).map_err(|e| format!("{}: {}", path, e))?;
    let file =
        std::fs::File::open(&canonical).map_err(|e| format!("{}: {}", canonical.display(), e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("{}: {}", canonical.display(), e))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", canonical.display()));
    }
    if metadata.len() > MAX_PE_BYTES {
        return Err(format!(
            "{} is {} bytes; the analysis limit is {} bytes",
            canonical.display(),
            metadata.len(),
            MAX_PE_BYTES
        ));
    }

    let mut raw = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("{}: {}", canonical.display(), e))?;
    if raw.len() as u64 > MAX_PE_BYTES {
        return Err(format!(
            "{} grew beyond the analysis limit while reading",
            canonical.display()
        ));
    }
    Ok((canonical, raw))
}

fn ensure_local_execution_path(path: &Path) -> Result<(), String> {
    let rendered = path.to_string_lossy();
    if rendered.starts_with(r"\\?\UNC\")
        || (rendered.starts_with(r"\\") && !rendered.starts_with(r"\\?\"))
    {
        return Err("dynamic analysis refuses UNC/network paths; copy the sample into the disposable VM first".into());
    }
    Ok(())
}

fn bounded_option(
    value: Option<u32>,
    default: u32,
    minimum: u32,
    maximum: u32,
    name: &str,
) -> Result<u32, String> {
    let value = value.unwrap_or(default);
    if !(minimum..=maximum).contains(&value) {
        return Err(format!(
            "{} must be between {} and {}",
            name, minimum, maximum
        ));
    }
    Ok(value)
}

#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub pe: PeInfo,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisasmView {
    pub base_rva: u32,
    pub instructions: Vec<Instruction>,
    pub blocks: Vec<BasicBlock>,
}

#[tauri::command]
fn parse_pe(path: String) -> Result<PeInfo, String> {
    let (_, raw) = read_bounded_file(&path)?;
    Ok(pe::parse_bytes(&raw))
}

#[tauri::command]
fn analyze(path: String) -> Result<Analysis, String> {
    let (_, raw) = read_bounded_file(&path)?;
    let pe = pe::parse_bytes(&raw);
    let verdict = aletheia_core::detect::analyze(&pe, Some(&raw));
    Ok(Analysis { pe, verdict })
}

/// Normalize an address that could be either an RVA (small) or an absolute
/// VA (image_base + rva) into an RVA that is inside the mapped image. Returns
/// a diagnostic error naming which side of the image the input fell on when
/// the recursive disassembler followed a call into unmapped memory (common
/// on packed sections, which is where this used to overflow).
fn normalize_rva(info: &PeInfo, addr: u64) -> Result<u32, String> {
    // Treat anything at or above image_base as an absolute VA.
    let rva_u64 = if addr >= info.image_base {
        addr - info.image_base
    } else {
        // Smaller than image_base: assume it's already an RVA.
        addr
    };
    if rva_u64 > u32::MAX as u64 {
        return Err(format!(
            "address {:#x} is outside this image (image_base = {:#x}). \
             This usually means the recursive disassembler followed a call \
             target into unmapped memory — expected on packed sections; \
             run dynamic unpack first, then re-analyze the recovered code.",
            addr, info.image_base
        ));
    }
    Ok(rva_u64 as u32)
}

#[tauri::command]
fn disasm_at(path: String, addr: u64, count: u32) -> Result<DisasmView, String> {
    let (_, raw) = read_bounded_file(&path)?;
    let info = pe::parse_bytes(&raw);
    if !info.ok {
        return Err(info.error.unwrap_or_else(|| "parse failed".to_string()));
    }
    let rva = if addr == 0 {
        info.entry_rva
    } else {
        normalize_rva(&info, addr)?
    };
    let sect: &Section = info
        .sections
        .iter()
        .find(|s| s.contains_rva(rva))
        .ok_or_else(|| format!("rva {:#x} maps to no section", rva))?;
    let start = (sect.raw_ptr as usize).saturating_add((rva - sect.vaddr) as usize);
    let end = (sect.raw_ptr as usize + sect.raw_size as usize).min(raw.len());
    if start >= end {
        return Err(format!("rva {:#x} is outside the file", rva));
    }
    let bounded_end = end.min(start.saturating_add(MAX_DISASM_BYTES));
    let code = &raw[start..bounded_end];
    let virtual_addr = info.image_base + rva as u64;
    let bits: u32 = if matches!(info.machine, 0x8664 | 0xAA64) {
        64
    } else {
        32
    };
    let all = disasm::disassemble_recursive(code, virtual_addr, &[virtual_addr], bits);
    let take = count.clamp(1, MAX_INSTRUCTION_COUNT) as usize;
    let take = take.min(all.len());
    let instructions = all[..take].to_vec();
    let blocks = disasm::build_cfg(&instructions);
    Ok(DisasmView {
        base_rva: rva,
        instructions,
        blocks,
    })
}

#[tauri::command]
fn decompile_at(
    path: String,
    addr: u64,
    count: u32,
) -> Result<aletheia_core::decompile::DecompiledFunction, String> {
    // Reuse the same instruction+CFG stream disasm_at builds, then hand it to
    // the pseudocode emitter. `addr` may be either an RVA or a full absolute
    // VA — the FunctionsList emits absolute VAs from iced-x86's block-successor
    // targets, while the initial entry-point drop is an RVA. normalize_rva
    // accepts either and validates the result lies inside the image.
    let (_, raw) = read_bounded_file(&path)?;
    let info = pe::parse_bytes(&raw);
    if !info.ok {
        return Err(info.error.unwrap_or_else(|| "parse failed".into()));
    }
    let rva = if addr == 0 {
        info.entry_rva
    } else {
        normalize_rva(&info, addr)?
    };
    let sect = info
        .sections
        .iter()
        .find(|s| s.contains_rva(rva))
        .ok_or_else(|| format!("rva {:#x} maps to no section", rva))?;
    let start = (sect.raw_ptr as usize).saturating_add((rva - sect.vaddr) as usize);
    let end = (sect.raw_ptr as usize + sect.raw_size as usize).min(raw.len());
    if start >= end {
        return Err(format!("rva {:#x} outside file", rva));
    }
    let bounded_end = end.min(start.saturating_add(MAX_DISASM_BYTES));
    let code = &raw[start..bounded_end];
    let virt = info.image_base + rva as u64;
    let bits: u32 = if info.machine == 0x8664 || info.machine == 0xAA64 {
        64
    } else {
        32
    };
    let all = disasm::disassemble_recursive(code, virt, &[virt], bits);
    let take = count.clamp(1, MAX_INSTRUCTION_COUNT) as usize;
    let take = take.min(all.len());
    let insns = &all[..take];
    let blocks = disasm::build_cfg(insns);
    Ok(aletheia_core::decompile::decompile(
        &format!("func_{:x}", rva),
        insns,
        &blocks,
    ))
}

#[tauri::command]
fn run_unpack(
    path: String,
    timeout_ms: Option<u32>,
    max_steps: Option<u32>,
) -> Result<aletheia_core::unpack::UnpackResult, String> {
    use aletheia_core::unpack::{run_unpack as rp, UnpackOptions};
    let timeout_ms = bounded_option(timeout_ms, 30_000, 1_000, 120_000, "timeout_ms")?;
    let max_steps = bounded_option(max_steps, 200_000, 1_000, 2_000_000, "max_steps")?;
    let opts = UnpackOptions {
        max_steps,
        timeout_ms,
        ..Default::default()
    };
    // DLLs can't be CreateProcess'd (Windows error 193 / BAD_EXE_FORMAT).
    // Detect from the on-disk headers and auto-wrap in rundll32 so the DLL's
    // DllMain runs — that's where cheat / packed-DLL initialization lives,
    // and the write-then-execute detector fires from there just as well.
    // Ordinal #1 is the standard rundll32 target; if the DLL has no export
    // with that ordinal, rundll32's own LoadLibrary still triggers DllMain
    // before it gives up, which is what we want to observe.
    let (canonical, raw) = read_bounded_file(&path)?;
    ensure_local_execution_path(&canonical)?;
    let info = pe::parse_bytes(&raw);
    if !info.ok {
        return Err(info
            .error
            .unwrap_or_else(|| "the selected file is not a valid PE".into()));
    }
    let cmd = if info.ok && info.is_dll {
        let system_root = std::env::var_os("SystemRoot")
            .ok_or_else(|| "SystemRoot is not defined".to_string())?;
        let rundll32 = PathBuf::from(system_root)
            .join("System32")
            .join("rundll32.exe");
        if !rundll32.is_file() {
            return Err(format!(
                "trusted rundll32 host is missing: {}",
                rundll32.display()
            ));
        }
        format!("\"{}\" \"{}\",#1", rundll32.display(), canonical.display())
    } else {
        format!("\"{}\"", canonical.display())
    };
    let mut result = rp(&cmd, &opts).map_err(|e| e.to_string())?;
    if info.ok && info.is_dll {
        result.reason = format!(
            "(target is a DLL — hosted via rundll32.exe ordinal #1) {}",
            result.reason
        );
    }
    Ok(result)
}

#[tauri::command]
fn engine_info() -> serde_json::Value {
    serde_json::json!({
        "engine": "aletheia-core",
        "version": env!("CARGO_PKG_VERSION"),
        "target_arch": std::env::consts::ARCH,
        "target_os": std::env::consts::OS,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            parse_pe,
            analyze,
            disasm_at,
            decompile_at,
            run_unpack,
            engine_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_options_accept_edges_and_reject_outliers() {
        assert_eq!(bounded_option(None, 10, 1, 20, "value").unwrap(), 10);
        assert_eq!(bounded_option(Some(1), 10, 1, 20, "value").unwrap(), 1);
        assert_eq!(bounded_option(Some(20), 10, 1, 20, "value").unwrap(), 20);
        assert!(bounded_option(Some(0), 10, 1, 20, "value").is_err());
        assert!(bounded_option(Some(21), 10, 1, 20, "value").is_err());
    }

    #[test]
    fn dynamic_execution_rejects_network_paths() {
        assert!(ensure_local_execution_path(Path::new(r"\\server\share\sample.exe")).is_err());
        assert!(
            ensure_local_execution_path(Path::new(r"\\?\UNC\server\share\sample.exe")).is_err()
        );
        assert!(ensure_local_execution_path(Path::new(r"C:\samples\sample.exe")).is_ok());
    }
}
