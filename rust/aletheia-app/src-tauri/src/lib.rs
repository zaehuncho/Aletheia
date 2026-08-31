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
    pe::parse(&path).map_err(|e| format!("{}: {}", path, e))
}

#[tauri::command]
fn analyze(path: String) -> Result<Analysis, String> {
    match aletheia_core::analyze_path(&path) {
        Ok((pe, verdict)) => Ok(Analysis { pe, verdict }),
        Err(e) => Err(format!("{}: {}", path, e)),
    }
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
    let raw = std::fs::read(&path).map_err(|e| format!("{}: {}", path, e))?;
    let info = pe::parse_bytes(&raw);
    if !info.ok {
        return Err(info.error.unwrap_or_else(|| "parse failed".to_string()));
    }
    let rva = if addr == 0 { info.entry_rva } else { normalize_rva(&info, addr)? };
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
    let code = &raw[start..end];
    let virtual_addr = info.image_base + rva as u64;
    let bits: u32 = if info.machine == 0x8664 { 64 } else if info.machine == 0xAA64 { 64 } else { 32 };
    let all = disasm::disassemble_recursive(code, virtual_addr, &[virtual_addr], bits);
    let take = (count as usize).max(1).min(all.len());
    let instructions = all[..take].to_vec();
    let blocks = disasm::build_cfg(&instructions);
    Ok(DisasmView { base_rva: rva, instructions, blocks })
}

#[tauri::command]
fn decompile_at(path: String, addr: u64, count: u32) -> Result<aletheia_core::decompile::DecompiledFunction, String> {
    // Reuse the same instruction+CFG stream disasm_at builds, then hand it to
    // the pseudocode emitter. `addr` may be either an RVA or a full absolute
    // VA — the FunctionsList emits absolute VAs from iced-x86's block-successor
    // targets, while the initial entry-point drop is an RVA. normalize_rva
    // accepts either and validates the result lies inside the image.
    let raw = std::fs::read(&path).map_err(|e| format!("{}: {}", path, e))?;
    let info = pe::parse_bytes(&raw);
    if !info.ok { return Err(info.error.unwrap_or_else(|| "parse failed".into())); }
    let rva = if addr == 0 { info.entry_rva } else { normalize_rva(&info, addr)? };
    let sect = info.sections.iter().find(|s| s.contains_rva(rva))
        .ok_or_else(|| format!("rva {:#x} maps to no section", rva))?;
    let start = (sect.raw_ptr as usize).saturating_add((rva - sect.vaddr) as usize);
    let end = (sect.raw_ptr as usize + sect.raw_size as usize).min(raw.len());
    if start >= end { return Err(format!("rva {:#x} outside file", rva)); }
    let code = &raw[start..end];
    let virt = info.image_base + rva as u64;
    let bits: u32 = if info.machine == 0x8664 || info.machine == 0xAA64 { 64 } else { 32 };
    let all = disasm::disassemble_recursive(code, virt, &[virt], bits);
    let take = (count as usize).max(1).min(all.len());
    let insns = &all[..take];
    let blocks = disasm::build_cfg(insns);
    Ok(aletheia_core::decompile::decompile(&format!("func_{:x}", rva), insns, &blocks))
}

#[tauri::command]
fn run_unpack(path: String, timeout_ms: Option<u32>, max_steps: Option<u32>) -> Result<aletheia_core::unpack::UnpackResult, String> {
    use aletheia_core::unpack::{UnpackOptions, run_unpack as rp};
    let opts = UnpackOptions {
        max_steps: max_steps.unwrap_or(200_000),
        timeout_ms: timeout_ms.unwrap_or(30_000),
        ..Default::default()
    };
    // DLLs can't be CreateProcess'd (Windows error 193 / BAD_EXE_FORMAT).
    // Detect from the on-disk headers and auto-wrap in rundll32 so the DLL's
    // DllMain runs — that's where cheat / packed-DLL initialization lives,
    // and the write-then-execute detector fires from there just as well.
    // Ordinal #1 is the standard rundll32 target; if the DLL has no export
    // with that ordinal, rundll32's own LoadLibrary still triggers DllMain
    // before it gives up, which is what we want to observe.
    let raw = std::fs::read(&path).map_err(|e| format!("{}: {}", path, e))?;
    let info = pe::parse_bytes(&raw);
    let cmd = if info.ok && info.is_dll {
        format!("rundll32.exe \"{}\",#1", path)
    } else {
        format!("\"{}\"", path)
    };
    let mut result = rp(&cmd, &opts).map_err(|e| e.to_string())?;
    if info.ok && info.is_dll {
        result.reason = format!("(target is a DLL — hosted via rundll32.exe ordinal #1) {}", result.reason);
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
        .invoke_handler(tauri::generate_handler![parse_pe, analyze, disasm_at, decompile_at, run_unpack, engine_info])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
