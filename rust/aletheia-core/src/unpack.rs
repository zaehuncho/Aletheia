//! Dynamic unpack detection. Port of `aletheia/unpack.py`, extended.
//!
//! Spawns a target under the Win32 Debug API, single-steps from its entry
//! point, and fires the moment `RIP` lands in a page that has the runtime
//! shape of an unpacked payload. Three predicates, `OR`-combined:
//!
//! 1. `MEM_PRIVATE + PAGE_EXECUTE_*` outside every loaded module — the
//!    Themida-style dynamic buffer (canary's `VirtualAlloc(RWX)` jump).
//! 2. Inside a "packer target" section of the main image — either an
//!    on-disk-empty reserved hole (`SizeOfRawData==0`, classic UPX0) or a
//!    `MEM_WRITE | MEM_EXECUTE` self-modifying section.
//! 3. (Lever 2, opt-in) A page that has been *written since load* per our
//!    guard-page write tracker — the general "OEP is wherever the loader
//!    dumped bytes" predicate that covers packers whose destination has
//!    none of the two static tells above.
//!
//! Stealth (Lever 1): before releasing the target, we patch its PEB so
//! the two cheapest anti-debug checks (`IsDebuggerPresent`, the
//! `NtGlobalFlag & 0x70` heap-flag pattern) return "no debugger". Handles
//! most malware samples and every classical packer's stub self-check.
//!
//! API surface (Lever 3, opt-in): we breakpoint `ntdll!NtAllocateVirtualMemory`,
//! `NtProtectVirtualMemory`, and `NtCreateThreadEx`, and record every
//! executable allocation, W-to-X protect flip, and thread spawn. These
//! events fill `UnpackResult::events`; the memory dump on a W-to-X flip
//! is what catches reflective loaders that never make a clean OEP jump.
//!
//! Windows-only (uses `windows-sys`). On other platforms this module still
//! compiles as a `#[cfg]` stub that returns `NotSupported`.
//!
//! Correctness contract: the detection predicate matches `aletheia/unpack.py`
//! (`UnpackMonitor.is_image_address` + `is_dynamic_executable` + the fire
//! condition in `_handle_step`).

use serde::{Deserialize, Serialize};

/// Result of a dynamic-unpack run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackResult {
    /// True iff any fire predicate matched (see module docs for the three
    /// predicates and their reason strings).
    pub detected: bool,
    /// Candidate OEP (absolute address) when `detected`.
    pub oep: Option<u64>,
    /// Main image base (for OEP → RVA conversion by the caller).
    pub main_base: u64,
    /// Guest process exit code (once terminated).
    pub exit_code: Option<u32>,
    /// True when the step budget was exhausted without detecting.
    pub gave_up: bool,
    /// Reason for the outcome (info string; not machine-parsed).
    pub reason: String,
    /// Observations from API hooks and guard-page tracking. See
    /// `UnpackEvent`. Empty when the corresponding lever is disabled.
    pub events: Vec<UnpackEvent>,
}

/// Options tuning a run. Defaults match `aletheia/unpack.py` plus the
/// three levers landed above the Python baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackOptions {
    pub max_steps: u32,
    pub timeout_ms: u32,
    /// Lever 1. Patch the target's `PEB.BeingDebugged` and
    /// `PEB.NtGlobalFlag` before releasing execution, so cheap anti-debug
    /// checks return "no debugger". Default on. Turn off only when
    /// diffing a run against a naked-debugger baseline.
    pub anti_anti_debug: bool,
    /// Lever 2. Install `PAGE_GUARD` on every executable page and track
    /// which pages get written to before executed. Adds "page was written
    /// since load" as a third fire predicate. **Default off**: this
    /// predicate is aimed at packers that unpack into an in-image page
    /// with no static tell (rare — every UPX/ASPack-family target we've
    /// hit is already caught by the packer-target predicate). When both
    /// `guard_pages` and `api_hooks` are enabled they share the BP replant
    /// pool and can double-plant a `0xCC`, so keep at most one on at a
    /// time. Enable this one when the packer-target predicate came up
    /// empty on a known-packed sample.
    pub guard_pages: bool,
    /// Lever 3. Breakpoint `NtAllocateVirtualMemory`,
    /// `NtProtectVirtualMemory`, `NtCreateThreadEx` in ntdll and record
    /// every executable-relevant call in `UnpackResult::events`. Default on.
    pub api_hooks: bool,
}
impl Default for UnpackOptions {
    fn default() -> Self {
        Self {
            max_steps: 200_000,
            timeout_ms: 30_000,
            anti_anti_debug: true,
            guard_pages: false,
            api_hooks: true,
        }
    }
}

/// One observation from an API-hook trigger or a guard-page write.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum UnpackEvent {
    /// `NtAllocateVirtualMemory` returned an executable region.
    Alloc { addr: u64, size: u64, protect: u32 },
    /// `NtProtectVirtualMemory` flipped a region to executable. `dumped`
    /// is a small hex-preview of the first 64 bytes right before the flip.
    ProtectFlipToX {
        addr: u64,
        size: u64,
        old_protect: u32,
        new_protect: u32,
        dumped: String,
    },
    /// `NtCreateThreadEx` spawned a thread whose entry sits in a
    /// non-image page (reflective loader signal).
    ThreadFromNonImage { start: u64 },
    /// A guard-page write fault (Lever 2) noted a write into a page that
    /// later gets executed. The event stays a note; the fire happens on
    /// the execution side.
    Wrote { page: u64 },
}

#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    #[error("dynamic unpack is Windows-only")]
    NotSupported,
    #[error("CreateProcess failed: {0}")]
    CreateProcess(String),
    #[error("Win32 error: {0}")]
    Win32(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Run `command` under the debugger. `command` is a full command line
/// (e.g. `"C:\\path\\to\\sample.exe"`).
pub fn run_unpack(command: &str, opts: &UnpackOptions) -> Result<UnpackResult, UnpackError> {
    #[cfg(target_os = "windows")]
    {
        win::run_unpack_impl(command, opts)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (command, opts);
        Err(UnpackError::NotSupported)
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
mod win {
    use super::*;
    use std::collections::HashMap;
    use std::mem::MaybeUninit;
    use std::time::Instant;

    use windows_sys::Win32::Foundation::{
        BOOL, CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_ACCESS_VIOLATION,
        EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CONTEXT, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent,
        DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
        GetThreadContext, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT,
        ReadProcessMemory, SetThreadContext, UNLOAD_DLL_DEBUG_EVENT, WaitForDebugEvent,
        WriteProcessMemory,
    };
    use windows_sys::Win32::System::Memory::{
        MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, VirtualProtectEx, VirtualQueryEx,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DEBUG_ONLY_THIS_PROCESS, OpenThread, PROCESS_BASIC_INFORMATION,
        PROCESS_INFORMATION, STARTUPINFOW, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
        THREAD_SUSPEND_RESUME, TerminateProcess,
    };

    // NtQueryInformationProcess isn't re-exported through windows-sys; declare
    // it against ntdll directly. Same for the NTSTATUS-style guard-page code.
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            ProcessHandle: HANDLE,
            ProcessInformationClass: u32,
            ProcessInformation: *mut core::ffi::c_void,
            ProcessInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
    }
    const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
    /// Guest wrote to a page we had `PAGE_GUARD` on.
    const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;
    const PAGE_SIZE: u64 = 0x1000;

    // CONTEXT flags (Win SDK constants).
    const CONTEXT_AMD64: u32 = 0x0010_0000;
    const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
    const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
    const CONTEXT_ALL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | (CONTEXT_AMD64 | 0x4);
    const TRAP_FLAG: u32 = 0x100;

    /// Aligned CONTEXT record: the x64 CONTEXT is 1232 bytes and must be
    /// 16-byte aligned. We allocate a padded buffer and slice out the CONTEXT.
    #[repr(align(16))]
    struct AlignedContext([u8; 1232]);
    impl AlignedContext {
        fn new() -> Self {
            Self([0u8; 1232])
        }
        unsafe fn as_ctx(&self) -> *const CONTEXT {
            self.0.as_ptr() as *const CONTEXT
        }
        unsafe fn as_ctx_mut(&mut self) -> *mut CONTEXT {
            self.0.as_mut_ptr() as *mut CONTEXT
        }
    }

    /// A loaded module range `[base, base + size)`.
    #[derive(Debug, Clone, Copy)]
    struct ImageRange {
        base: u64,
        size: u64,
    }

    /// A section of the main image that is a plausible destination for a
    /// packer/loader stub to unpack into. Two forms:
    ///  - `"reserved-empty"`: `SizeOfRawData == 0 && VirtualSize > 0` (the
    ///    classic UPX0/aspack shape — reserved room for the loader to fill).
    ///  - `"self-modifying"`: writable + executable (RWX) — either a full
    ///    unpack destination or a small self-decrypting stub.
    ///
    /// A jump into either kind is the same signal as jumping to a fresh
    /// MEM_PRIVATE executable buffer: something wrote the code we're now
    /// running, and the on-disk section table said so up front.
    #[derive(Debug, Clone, Copy)]
    struct PackerTarget {
        base: u64,
        end: u64,
        kind: &'static str,
    }

    pub fn run_unpack_impl(
        command: &str,
        opts: &UnpackOptions,
    ) -> Result<UnpackResult, UnpackError> {
        // ---- 1. Spawn the target under the Debug API ----
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let mut cmdline: Vec<u16> = command.encode_utf16().collect();
        cmdline.push(0);

        let ok: BOOL = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                DEBUG_ONLY_THIS_PROCESS,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        if ok == 0 {
            let e = unsafe { GetLastError() };
            let hint = match e {
                193 => {
                    " — ERROR_BAD_EXE_FORMAT: not a runnable Win32 EXE. \
                        Common causes: file is a DLL (not directly runnable — needs rundll32.exe), \
                        a driver (.sys — loads via SCM only), a 16-bit binary, \
                        or the wrong architecture for this Windows install."
                }
                2 => {
                    " — ERROR_FILE_NOT_FOUND: the path doesn't resolve. \
                        Check quoting / drive letter."
                }
                5 => {
                    " — ERROR_ACCESS_DENIED: the file is present but Windows \
                        refused to launch it. AV / SmartScreen / MOTW are the \
                        usual suspects; try 'Unblock' in file Properties."
                }
                740 => {
                    " — ERROR_ELEVATION_REQUIRED: the EXE's manifest requests \
                        admin. Aletheia can't self-elevate — relaunch elevated."
                }
                _ => "",
            };
            return Err(UnpackError::CreateProcess(format!(
                "last err = {} ({}){}",
                e, command, hint
            )));
        }
        let hproc = pi.hProcess;

        // ---- 2. Bookkeeping ----
        let mut modules: HashMap<u64, ImageRange> = HashMap::new();
        let mut packer_targets: Vec<PackerTarget> = Vec::new();
        let mut main_base: u64 = 0;
        let mut _entry_point: u64 = 0;
        let mut entry_bp_saved: Option<(u64, u8)> = None; // (addr, saved byte)
        // API-hook breakpoints keyed by address -> (function label, saved byte).
        let mut api_bps: HashMap<u64, (&'static str, u8)> = HashMap::new();
        // Pending step-over of a restored API BP: (addr, orig_byte, label, tid).
        let mut api_step_over: Option<(u64, u8, &'static str, u32)> = None;
        // Pages we've seen written since load. Used by Lever 2's "written
        // then executed" fire predicate. Keyed by page-aligned base.
        let mut written_pages: std::collections::HashSet<u64> = std::collections::HashSet::new();
        // Pending re-arm of PAGE_GUARD on the page we just faulted from
        // (guard clears itself once fired). We re-arm after the single-step.
        let mut guard_rearm: Option<u64> = None;
        let mut stepping_tid: Option<u32> = None;
        let mut step_count: u32 = 0;
        let mut detected: bool = false;
        let mut oep: Option<u64> = None;
        let mut exit_code: Option<u32> = None;
        let mut reason = String::new();
        let mut events: Vec<UnpackEvent> = Vec::new();

        let started = Instant::now();
        let mut result_ready = false;
        let mut running = true;

        // ---- 3. Debug event loop ----
        while running {
            if started.elapsed().as_millis() as u32 > opts.timeout_ms {
                reason = format!("timeout after {} ms", opts.timeout_ms);
                unsafe { TerminateProcess(hproc, 1) };
                break;
            }

            let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            if unsafe { WaitForDebugEvent(&mut ev, 100) } == 0 {
                continue;
            }

            let mut continue_status = DBG_CONTINUE;

            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { &ev.u.CreateProcessInfo };
                    main_base = info.lpBaseOfImage as u64;
                    let img_size = read_image_size(hproc, main_base);
                    modules.insert(
                        main_base,
                        ImageRange {
                            base: main_base,
                            size: img_size,
                        },
                    );

                    // Snapshot the main image's section table for the
                    // packer-target predicate (UPX0-style reserved holes and
                    // any RWX sections). Cheap: one ReadProcessMemory of the
                    // headers, done once at process create.
                    packer_targets = read_packer_target_sections(hproc, main_base);

                    // Lever 1: patch PEB.BeingDebugged + PEB.NtGlobalFlag so
                    // IsDebuggerPresent-class checks return "no debugger".
                    if opts.anti_anti_debug {
                        apply_anti_debug_patches(hproc);
                    }

                    // Lever 2: arm PAGE_GUARD on every executable page in
                    // the main image so we can note writes into them.
                    if opts.guard_pages {
                        arm_guard_pages(hproc, main_base, img_size, &packer_targets);
                    }

                    // Set a one-shot 0xCC breakpoint at the entry point so we
                    // start stepping from a clean in-image moment.
                    _entry_point = read_entry_point(hproc, main_base);
                    if _entry_point != 0
                        && let Some(orig) = write_int3(hproc, _entry_point)
                    {
                        entry_bp_saved = Some((_entry_point, orig));
                    }
                    if !info.hFile.is_null() && info.hFile != INVALID_HANDLE_VALUE {
                        unsafe { CloseHandle(info.hFile) };
                    }
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let dll = unsafe { &ev.u.LoadDll };
                    let base = dll.lpBaseOfDll as u64;
                    let sz = read_image_size(hproc, base);
                    modules.insert(base, ImageRange { base, size: sz });
                    // Lever 3: as soon as ntdll shows up, drop 0xCC on the
                    // three functions we care about so we get a callback on
                    // every executable-relevant allocation, protect-flip,
                    // and thread spawn.
                    if opts.api_hooks && api_bps.is_empty() && looks_like_ntdll(hproc, base, sz) {
                        for name in [
                            "NtAllocateVirtualMemory",
                            "NtProtectVirtualMemory",
                            "NtCreateThreadEx",
                        ] {
                            if let Some(addr) = resolve_export(hproc, base, name)
                                && let Some(orig) = write_int3(hproc, addr)
                            {
                                // Leak-shaped &'static comes from the array literal above.
                                let static_name: &'static str = match name {
                                    "NtAllocateVirtualMemory" => "NtAllocateVirtualMemory",
                                    "NtProtectVirtualMemory" => "NtProtectVirtualMemory",
                                    "NtCreateThreadEx" => "NtCreateThreadEx",
                                    _ => "?",
                                };
                                api_bps.insert(addr, (static_name, orig));
                            }
                        }
                    }
                    if !dll.hFile.is_null() && dll.hFile != INVALID_HANDLE_VALUE {
                        unsafe { CloseHandle(dll.hFile) };
                    }
                }
                UNLOAD_DLL_DEBUG_EVENT => {
                    let base = unsafe { ev.u.UnloadDll.lpBaseOfDll as u64 };
                    modules.remove(&base);
                }
                EXCEPTION_DEBUG_EVENT => {
                    let er = unsafe { &ev.u.Exception.ExceptionRecord };
                    let code: u32 = er.ExceptionCode as u32;
                    let fault_addr = er.ExceptionAddress as u64;

                    // ---- Lever 3: API breakpoint hit ----
                    if code == EXCEPTION_BREAKPOINT as u32 && api_bps.contains_key(&fault_addr) {
                        let (label, orig) = *api_bps.get(&fault_addr).unwrap();
                        // Snapshot register-passed args (x64 stdcall) BEFORE
                        // we let the function run, so we can characterize the
                        // requested region. Actual return value isn't easy to
                        // grab (we'd need a second BP on the caller's return
                        // address); we settle for intent + region.
                        if let Some(ev_out) = read_api_call(hproc, ev.dwThreadId, label) {
                            events.push(ev_out);
                        }
                        // Restore the original byte, rewind RIP, single-step
                        // past that instruction, then we'll re-plant the BP.
                        // Adopt this thread as the stepping thread so the
                        // follow-up SINGLE_STEP gets recognized as ours
                        // even when the first API hit lands before the
                        // entry BP has fired (loader activity is the usual
                        // case for NtAllocateVirtualMemory).
                        write_byte(hproc, fault_addr, orig);
                        rewind_and_set_trap(ev.dwThreadId, fault_addr);
                        api_step_over = Some((fault_addr, 0xCC, label, ev.dwThreadId));
                        stepping_tid = Some(ev.dwThreadId);
                        api_bps.remove(&fault_addr);
                    }
                    // ---- Lever 2: guard-page violation ----
                    else if code == STATUS_GUARD_PAGE_VIOLATION && opts.guard_pages {
                        // ExceptionInformation[0] = access type (0=read, 1=write, 8=exec)
                        // ExceptionInformation[1] = fault address inside the page.
                        let access = er.ExceptionInformation[0] as u64;
                        let page_addr = (er.ExceptionInformation[1] as u64) & !(PAGE_SIZE - 1);
                        if access == 1 {
                            // Write into a guarded page. Note it, re-arm the
                            // guard after we single-step past this write.
                            if !written_pages.contains(&page_addr) {
                                written_pages.insert(page_addr);
                                events.push(UnpackEvent::Wrote { page: page_addr });
                            }
                        } else if access == 8 && written_pages.contains(&page_addr) {
                            // Execution reached a page that was written since
                            // load. That's the general OEP predicate; fire.
                            detected = true;
                            oep = Some(er.ExceptionInformation[1] as u64);
                            reason = format!(
                                "written-then-executed page detected at {:#x} (page {:#x}; main_base {:#x})",
                                oep.unwrap(),
                                page_addr,
                                main_base
                            );
                            unsafe { TerminateProcess(hproc, 0) };
                            result_ready = true;
                        }
                        // In all cases the guard clears once, so re-arm it
                        // after we single-step past this instruction.
                        guard_rearm = Some(page_addr);
                        if !result_ready {
                            set_trap_flag(ev.dwThreadId);
                            stepping_tid = Some(ev.dwThreadId);
                        }
                    } else if code == EXCEPTION_BREAKPOINT as u32
                        && entry_bp_saved.is_some_and(|(a, _)| a == fault_addr)
                    {
                        // Entry breakpoint hit. Restore the byte, rewind RIP,
                        // set the trap flag, start stepping.
                        let (addr, orig) = entry_bp_saved.take().unwrap();
                        write_byte(hproc, addr, orig);
                        rewind_and_set_trap(ev.dwThreadId, addr);
                        stepping_tid = Some(ev.dwThreadId);
                    } else if code == EXCEPTION_SINGLE_STEP as u32
                        && stepping_tid == Some(ev.dwThreadId)
                    {
                        step_count += 1;
                        let rip = read_rip(ev.dwThreadId);
                        // Fire on either shape of unpacked-payload jump:
                        //   (a) RIP outside every loaded module AND in a
                        //       MEM_PRIVATE PAGE_EXECUTE_* region
                        //       (Themida-style dynamic buffer)
                        //   (b) RIP inside a "packer target" section of the
                        //       main image (UPX0-style reserved hole or any
                        //       RWX section) — same signal, just aimed at
                        //       an on-disk reserved destination
                        let hit_dynamic =
                            !is_image_address(&modules, rip) && is_dynamic_executable(hproc, rip);
                        let hit_in_image = packer_targets
                            .iter()
                            .find(|t| rip >= t.base && rip < t.end)
                            .copied();
                        if hit_dynamic || hit_in_image.is_some() {
                            detected = true;
                            oep = Some(rip);
                            reason = if hit_dynamic {
                                format!(
                                    "write-then-execute detected at {:#x} (fresh MEM_PRIVATE executable; main_base {:#x})",
                                    rip, main_base
                                )
                            } else {
                                let t = hit_in_image.unwrap();
                                format!(
                                    "in-image unpacked payload detected at {:#x} (jumped into {} section [{:#x}, {:#x}); main_base {:#x})",
                                    rip, t.kind, t.base, t.end, main_base
                                )
                            };
                            unsafe { TerminateProcess(hproc, 0) };
                            result_ready = true;
                        } else if step_count >= opts.max_steps {
                            reason = format!(
                                "step budget ({}) exhausted; no unpacked payload observed",
                                opts.max_steps
                            );
                            unsafe { TerminateProcess(hproc, 0) };
                            result_ready = true;
                        } else {
                            // Between stops we may need to re-plant an API
                            // breakpoint we just stepped over, and/or re-arm
                            // a guard page whose fault cleared it.
                            let just_stepped_api = api_step_over.is_some();
                            if let Some((addr, _orig, label, _tid)) = api_step_over.take()
                                && let Some(new_orig) = write_int3(hproc, addr)
                            {
                                api_bps.insert(addr, (label, new_orig));
                            }
                            if let Some(page) = guard_rearm.take() {
                                arm_page_guard(hproc, page);
                            }
                            // Only single-step continuously once we're PAST
                            // the entry breakpoint. Before entry, an API BP
                            // step-over should not induce continuous stepping
                            // through the loader (that burns the whole step
                            // budget in ntdll before main() even runs). The
                            // entry BP itself will re-engage stepping.
                            let post_entry = entry_bp_saved.is_none();
                            if just_stepped_api && !post_entry {
                                // clear stepping_tid so unrelated SINGLE_STEPs
                                // aren't misread as ours
                                stepping_tid = None;
                            } else {
                                set_trap_flag(ev.dwThreadId);
                            }
                        }
                    } else if code == EXCEPTION_ACCESS_VIOLATION as u32 {
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                    } else if code != EXCEPTION_BREAKPOINT as u32 {
                        // pass everything else back to the debuggee
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    exit_code = Some(unsafe { ev.u.ExitProcess.dwExitCode });
                    running = false;
                    if reason.is_empty() {
                        reason = "process exited cleanly without triggering detection".to_string();
                    }
                }
                CREATE_THREAD_DEBUG_EVENT
                | EXIT_THREAD_DEBUG_EVENT
                | OUTPUT_DEBUG_STRING_EVENT
                | RIP_EVENT => {}
                _ => {}
            }

            unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continue_status) };
            if result_ready {
                running = false;
            }
        }

        unsafe {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        Ok(UnpackResult {
            detected,
            oep,
            main_base,
            exit_code,
            gave_up: !detected && step_count >= opts.max_steps,
            reason,
            events,
        })
    }

    // ---------------------------------------------------------------------
    // Lever 1: anti-anti-debug
    // ---------------------------------------------------------------------

    /// Patch the target's PEB so the two cheap anti-debug checks return
    /// "no debugger". Best-effort; failures are silent because a target
    /// that hasn't loaded ntdll's PEB yet is common and not fatal.
    fn apply_anti_debug_patches(hproc: HANDLE) {
        let peb = read_peb_address(hproc);
        if peb == 0 {
            return;
        }
        // PEB.BeingDebugged is a single byte at offset 0x02.
        let zero: u8 = 0;
        let mut wrote = 0usize;
        unsafe {
            WriteProcessMemory(
                hproc,
                (peb + 0x02) as _,
                &zero as *const u8 as _,
                1,
                &mut wrote,
            );
        }
        // PEB.NtGlobalFlag is at 0xBC on x64 (matches the standard layout on
        // Win7 through Win11). Clear the debugger-inherit trio (0x10 | 0x20 |
        // 0x40) so heap-flag scanners don't see a debugged pattern.
        let mut cur: u32 = 0;
        let mut got = 0usize;
        unsafe {
            ReadProcessMemory(
                hproc,
                (peb + 0xBC) as _,
                &mut cur as *mut u32 as _,
                4,
                &mut got,
            );
        }
        if got == 4 {
            let clean = cur & !0x70u32;
            unsafe {
                WriteProcessMemory(
                    hproc,
                    (peb + 0xBC) as _,
                    &clean as *const u32 as _,
                    4,
                    &mut wrote,
                );
            }
        }
    }

    fn read_peb_address(hproc: HANDLE) -> u64 {
        let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mut ret_len: u32 = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                hproc,
                PROCESS_BASIC_INFORMATION_CLASS,
                &mut pbi as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut ret_len,
            )
        };
        if status != 0 {
            return 0;
        }
        pbi.PebBaseAddress as u64
    }

    // ---------------------------------------------------------------------
    // Lever 2: guard pages
    // ---------------------------------------------------------------------

    /// Install `PAGE_GUARD` on every executable page in the main image so we
    /// notice writes into them and executions of pages the loader wrote to.
    fn arm_guard_pages(hproc: HANDLE, base: u64, size: u64, packer_targets: &[PackerTarget]) {
        if size == 0 {
            return;
        }
        // Walk pages in the image range; only arm executable ones. Skip
        // packer-target sections' pages — those already get caught by the
        // in-image predicate on the very first execute, and arming the guard
        // fights their loader's own memory writes for no extra signal.
        let mut addr = base & !(PAGE_SIZE - 1);
        let end = base + size;
        while addr < end {
            if !packer_targets
                .iter()
                .any(|t| addr >= t.base && addr < t.end)
                && page_is_executable(hproc, addr)
            {
                arm_page_guard(hproc, addr);
            }
            addr += PAGE_SIZE;
        }
    }

    fn page_is_executable(hproc: HANDLE, addr: u64) -> bool {
        let mut mbi: std::mem::MaybeUninit<MEMORY_BASIC_INFORMATION> =
            std::mem::MaybeUninit::uninit();
        let sz = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let got = unsafe { VirtualQueryEx(hproc, addr as _, mbi.as_mut_ptr(), sz) };
        if got < sz {
            return false;
        }
        let mbi = unsafe { mbi.assume_init() };
        if mbi.State != 0x1000 {
            return false;
        }
        matches!(
            mbi.Protect & !(0x100 | 0x200 | 0x400),
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    fn arm_page_guard(hproc: HANDLE, page_addr: u64) {
        let mut old_prot: u32 = 0;
        // Read current protection to preserve it beyond the GUARD flag.
        let mut mbi: std::mem::MaybeUninit<MEMORY_BASIC_INFORMATION> =
            std::mem::MaybeUninit::uninit();
        let sz = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let got = unsafe { VirtualQueryEx(hproc, page_addr as _, mbi.as_mut_ptr(), sz) };
        if got < sz {
            return;
        }
        let mbi = unsafe { mbi.assume_init() };
        let new_prot = mbi.Protect | PAGE_GUARD;
        unsafe {
            VirtualProtectEx(
                hproc,
                page_addr as _,
                PAGE_SIZE as usize,
                new_prot,
                &mut old_prot,
            );
        }
    }

    // ---------------------------------------------------------------------
    // Lever 3: API hooks
    // ---------------------------------------------------------------------

    /// Cheap check: is the module at `base` ntdll? We match on the export
    /// name of `NtCreateThreadEx` since it's ntdll-exclusive and cheap.
    fn looks_like_ntdll(hproc: HANDLE, base: u64, size: u64) -> bool {
        if size == 0 {
            return false;
        }
        resolve_export(hproc, base, "NtCreateThreadEx").is_some()
    }

    /// Walk `base`'s PE export directory in-process to find the RVA of the
    /// named export, then absolute address = base + rva. `None` if not found.
    fn resolve_export(hproc: HANDLE, base: u64, name: &str) -> Option<u64> {
        // Read the DOS + NT headers.
        let mut hdr = [0u8; 0x400];
        let mut got = 0usize;
        unsafe {
            if ReadProcessMemory(hproc, base as _, hdr.as_mut_ptr() as _, hdr.len(), &mut got) == 0
                || got < 0x40
            {
                return None;
            }
        }
        if &hdr[..2] != b"MZ" {
            return None;
        }
        let e_lfanew = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
        if e_lfanew + 24 > got || &hdr[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return None;
        }
        let opt = e_lfanew + 4 + 20;
        // Optional header magic tells us the layout of the DataDirectory.
        let magic = u16::from_le_bytes(hdr[opt..opt + 2].try_into().unwrap());
        let dd_off = if magic == 0x20b { opt + 112 } else { opt + 96 }; // PE32+ vs PE32
        if dd_off + 8 > got {
            return None;
        }
        let export_rva = u32::from_le_bytes(hdr[dd_off..dd_off + 4].try_into().unwrap()) as u64;
        let export_sz = u32::from_le_bytes(hdr[dd_off + 4..dd_off + 8].try_into().unwrap()) as u64;
        if export_rva == 0 || export_sz == 0 {
            return None;
        }
        // Pull the export directory table + its name/ordinal/address arrays.
        let mut edata = vec![0u8; export_sz as usize];
        let mut got2 = 0usize;
        unsafe {
            if ReadProcessMemory(
                hproc,
                (base + export_rva) as _,
                edata.as_mut_ptr() as _,
                edata.len(),
                &mut got2,
            ) == 0
                || got2 < 40
            {
                return None;
            }
        }
        // IMAGE_EXPORT_DIRECTORY layout: 0x14 num_funcs, 0x18 num_names,
        // 0x1C addr_of_functions, 0x20 addr_of_names, 0x24 addr_of_ordinals.
        let num_names = u32::from_le_bytes(edata[0x18..0x1C].try_into().unwrap()) as usize;
        let addr_funcs = u32::from_le_bytes(edata[0x1C..0x20].try_into().unwrap()) as u64;
        let addr_names = u32::from_le_bytes(edata[0x20..0x24].try_into().unwrap()) as u64;
        let addr_ords = u32::from_le_bytes(edata[0x24..0x28].try_into().unwrap()) as u64;
        // We read the three tables into the guest-relative slice we already
        // have to avoid extra RPMs — but they may live outside `edata` if the
        // export directory is small. Fall back to individual reads for each.
        for i in 0..num_names {
            let name_rva_addr = base + addr_names + (i as u64) * 4;
            let mut name_rva: u32 = 0;
            let mut n = 0usize;
            unsafe {
                if ReadProcessMemory(
                    hproc,
                    name_rva_addr as _,
                    &mut name_rva as *mut u32 as _,
                    4,
                    &mut n,
                ) == 0
                    || n < 4
                {
                    return None;
                }
            }
            let mut buf = [0u8; 64];
            unsafe {
                if ReadProcessMemory(
                    hproc,
                    (base + name_rva as u64) as _,
                    buf.as_mut_ptr() as _,
                    buf.len(),
                    &mut n,
                ) == 0
                    || n == 0
                {
                    continue;
                }
            }
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if &buf[..end] == name.as_bytes() {
                // Found the name; read the matching ordinal, then the func RVA.
                let ord_addr = base + addr_ords + (i as u64) * 2;
                let mut ord: u16 = 0;
                unsafe {
                    if ReadProcessMemory(hproc, ord_addr as _, &mut ord as *mut u16 as _, 2, &mut n)
                        == 0
                    {
                        return None;
                    }
                }
                let fn_rva_addr = base + addr_funcs + (ord as u64) * 4;
                let mut fn_rva: u32 = 0;
                unsafe {
                    if ReadProcessMemory(
                        hproc,
                        fn_rva_addr as _,
                        &mut fn_rva as *mut u32 as _,
                        4,
                        &mut n,
                    ) == 0
                    {
                        return None;
                    }
                }
                if fn_rva == 0 {
                    return None;
                }
                return Some(base + fn_rva as u64);
            }
        }
        None
    }

    /// Snapshot the register-passed args at the moment an API BP fires and
    /// classify the intent. x64 stdcall: rcx, rdx, r8, r9.
    fn read_api_call(hproc: HANDLE, tid: u32, label: &'static str) -> Option<UnpackEvent> {
        let ht = open_thread_for_ctx(tid);
        if ht.is_null() {
            return None;
        }
        let mut buf = AlignedContext::new();
        let (rdx, r8, r9);
        unsafe {
            (*buf.as_ctx_mut()).ContextFlags = CONTEXT_ALL;
            if GetThreadContext(ht, buf.as_ctx_mut()) == 0 {
                CloseHandle(ht);
                return None;
            }
            let c = &*buf.as_ctx();
            // rcx (ProcessHandle) is always -1 for the calling process; we
            // don't need it, and grabbing it just to shut the compiler up
            // masks any legit shadowing bug later. Read rdx/r8/r9 only.
            rdx = c.Rdx;
            r8 = c.R8;
            r9 = c.R9;
            CloseHandle(ht);
        }
        match label {
            "NtAllocateVirtualMemory" => {
                // args: ProcessHandle=rcx, *BaseAddress=rdx, ZeroBits=r8,
                //       *RegionSize=r9, AllocationType=stack, Protect=stack.
                // Region size + protect need stack reads; skip for MVP and
                // just report the requested base (BaseAddress is *PVOID and
                // often NULL on input meaning "OS choose"). We characterize
                // the alloc as executable if the stack Protect suggests X;
                // read that too.
                let (mut base_out, mut size_out) = (0u64, 0u64);
                let mut protect_out: u32 = 0;
                let mut got = 0usize;
                unsafe {
                    ReadProcessMemory(hproc, rdx as _, &mut base_out as *mut u64 as _, 8, &mut got);
                    ReadProcessMemory(hproc, r9 as _, &mut size_out as *mut u64 as _, 8, &mut got);
                    // On x64, args 5+ are on the stack starting at [rsp+0x28]
                    // (past shadow + return addr). We need Rsp; read it again.
                }
                let ht2 = open_thread_for_ctx(tid);
                if !ht2.is_null() {
                    let mut b2 = AlignedContext::new();
                    unsafe {
                        (*b2.as_ctx_mut()).ContextFlags = CONTEXT_ALL;
                        if GetThreadContext(ht2, b2.as_ctx_mut()) != 0 {
                            let rsp = (*b2.as_ctx()).Rsp;
                            // Protect is arg #6 -> [rsp+0x30]
                            ReadProcessMemory(
                                hproc,
                                (rsp + 0x30) as _,
                                &mut protect_out as *mut u32 as _,
                                4,
                                &mut got,
                            );
                        }
                        CloseHandle(ht2);
                    }
                }
                let is_x = matches!(protect_out, 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x400);
                if is_x {
                    Some(UnpackEvent::Alloc {
                        addr: base_out,
                        size: size_out,
                        protect: protect_out,
                    })
                } else {
                    None
                }
            }
            "NtProtectVirtualMemory" => {
                // args: ProcessHandle=rcx, *BaseAddress=rdx, *NumberOfBytes=r8, NewAccessProtection=r9d, *OldAccessProtection=stack.
                let (mut base_out, mut size_out) = (0u64, 0u64);
                let mut got = 0usize;
                unsafe {
                    ReadProcessMemory(hproc, rdx as _, &mut base_out as *mut u64 as _, 8, &mut got);
                    ReadProcessMemory(hproc, r8 as _, &mut size_out as *mut u64 as _, 8, &mut got);
                }
                let new_prot = r9 as u32;
                let is_x = matches!(new_prot, 0x10 | 0x20 | 0x40 | 0x80);
                if !is_x {
                    return None;
                }
                // Dump the first 64 bytes right BEFORE the flip — useful when
                // the loader is about to hand execution to freshly written code.
                let mut dump = [0u8; 64];
                unsafe {
                    ReadProcessMemory(
                        hproc,
                        base_out as _,
                        dump.as_mut_ptr() as _,
                        dump.len(),
                        &mut got,
                    );
                }
                let dumped = dump
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                Some(UnpackEvent::ProtectFlipToX {
                    addr: base_out,
                    size: size_out,
                    old_protect: 0,
                    new_protect: new_prot,
                    dumped,
                })
            }
            "NtCreateThreadEx" => {
                // args (Nt version): *hThread=rcx, DesiredAccess=rdx,
                //   *ObjectAttributes=r8, ProcessHandle=r9,
                //   StartRoutine=[rsp+0x28], StartParameter=[rsp+0x30], ...
                let mut start: u64 = 0;
                let mut got = 0usize;
                let ht2 = open_thread_for_ctx(tid);
                if !ht2.is_null() {
                    let mut b2 = AlignedContext::new();
                    unsafe {
                        (*b2.as_ctx_mut()).ContextFlags = CONTEXT_ALL;
                        if GetThreadContext(ht2, b2.as_ctx_mut()) != 0 {
                            let rsp = (*b2.as_ctx()).Rsp;
                            ReadProcessMemory(
                                hproc,
                                (rsp + 0x28) as _,
                                &mut start as *mut u64 as _,
                                8,
                                &mut got,
                            );
                        }
                        CloseHandle(ht2);
                    }
                }
                if start == 0 {
                    return None;
                }
                Some(UnpackEvent::ThreadFromNonImage { start })
            }
            _ => None,
        }
    }

    // ------------------ helpers ------------------

    fn read_image_size(hproc: HANDLE, base: u64) -> u64 {
        // SizeOfImage lives at optional_header + 56. First fetch e_lfanew from DOS
        // header, then the optional header magic tells us layout is the same for
        // both PE32/PE32+ at that field.
        let mut hdr = [0u8; 0x400];
        let mut got = 0usize;
        if unsafe {
            ReadProcessMemory(hproc, base as _, hdr.as_mut_ptr() as _, hdr.len(), &mut got)
        } == 0
        {
            return 0;
        }
        if got < 0x40 || &hdr[..2] != b"MZ" {
            return 0;
        }
        let e_lfanew = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
        if e_lfanew + 24 > got || &hdr[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return 0;
        }
        let opt = e_lfanew + 4 + 20;
        if opt + 60 > got {
            return 0;
        }
        u32::from_le_bytes(hdr[opt + 56..opt + 60].try_into().unwrap()) as u64
    }

    /// Walk the main image's section table in-process and return every
    /// section that is a plausible packer unpack target. Cheap: one
    /// ReadProcessMemory of the first 4 KiB of headers.
    ///
    /// Classification:
    ///   * `SizeOfRawData == 0 && VirtualSize > 0` -> `"reserved-empty"`
    ///     (classic UPX0-style hole the loader fills at runtime)
    ///   * `Characteristics & (MEM_WRITE|MEM_EXECUTE) == both` -> `"self-modifying"`
    ///     (RWX section; either the full unpack destination or a decrypt stub)
    ///
    /// Sections matching neither are skipped. If both apply we call it
    /// `"reserved-empty"` (the more diagnostic label).
    fn read_packer_target_sections(hproc: HANDLE, base: u64) -> Vec<PackerTarget> {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
        let mut out = Vec::new();
        let mut hdr = [0u8; 0x1000];
        let mut got = 0usize;
        if unsafe {
            ReadProcessMemory(hproc, base as _, hdr.as_mut_ptr() as _, hdr.len(), &mut got)
        } == 0
        {
            return out;
        }
        if got < 0x40 || &hdr[..2] != b"MZ" {
            return out;
        }
        let e_lfanew = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
        if e_lfanew + 24 > got || &hdr[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return out;
        }
        let coff = e_lfanew + 4;
        let n_sections = u16::from_le_bytes(hdr[coff + 2..coff + 4].try_into().unwrap()) as usize;
        let size_opt = u16::from_le_bytes(hdr[coff + 16..coff + 18].try_into().unwrap()) as usize;
        let sect_tbl = coff + 20 + size_opt;
        let sect_sz = 40usize;
        for i in 0..n_sections {
            let off = sect_tbl + i * sect_sz;
            if off + sect_sz > got {
                break;
            }
            let vsize = u32::from_le_bytes(hdr[off + 8..off + 12].try_into().unwrap()) as u64;
            let vaddr = u32::from_le_bytes(hdr[off + 12..off + 16].try_into().unwrap()) as u64;
            let raw_size = u32::from_le_bytes(hdr[off + 16..off + 20].try_into().unwrap()) as u64;
            let chars = u32::from_le_bytes(hdr[off + 36..off + 40].try_into().unwrap());
            if vsize == 0 {
                continue;
            }
            let start = base + vaddr;
            let end = start + vsize.max(1);
            let kind = if raw_size == 0 {
                Some("reserved-empty")
            } else if chars & IMAGE_SCN_MEM_EXECUTE != 0 && chars & IMAGE_SCN_MEM_WRITE != 0 {
                Some("self-modifying")
            } else {
                None
            };
            if let Some(k) = kind {
                out.push(PackerTarget {
                    base: start,
                    end,
                    kind: k,
                });
            }
        }
        out
    }

    fn read_entry_point(hproc: HANDLE, base: u64) -> u64 {
        let mut hdr = [0u8; 0x400];
        let mut got = 0usize;
        if unsafe {
            ReadProcessMemory(hproc, base as _, hdr.as_mut_ptr() as _, hdr.len(), &mut got)
        } == 0
        {
            return 0;
        }
        if got < 0x40 || &hdr[..2] != b"MZ" {
            return 0;
        }
        let e_lfanew = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
        if e_lfanew + 24 > got || &hdr[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return 0;
        }
        let opt = e_lfanew + 4 + 20;
        if opt + 20 > got {
            return 0;
        }
        let entry_rva = u32::from_le_bytes(hdr[opt + 16..opt + 20].try_into().unwrap()) as u64;
        base + entry_rva
    }

    fn write_int3(hproc: HANDLE, addr: u64) -> Option<u8> {
        let mut orig = 0u8;
        let mut got = 0usize;
        if unsafe { ReadProcessMemory(hproc, addr as _, &mut orig as *mut u8 as _, 1, &mut got) }
            == 0
            || got != 1
        {
            return None;
        }
        let cc = 0xCCu8;
        let mut wrote = 0usize;
        if unsafe { WriteProcessMemory(hproc, addr as _, &cc as *const u8 as _, 1, &mut wrote) }
            == 0
            || wrote != 1
        {
            return None;
        }
        Some(orig)
    }

    fn write_byte(hproc: HANDLE, addr: u64, b: u8) {
        let mut wrote = 0usize;
        unsafe { WriteProcessMemory(hproc, addr as _, &b as *const u8 as _, 1, &mut wrote) };
    }

    fn open_thread_for_ctx(tid: u32) -> HANDLE {
        unsafe {
            OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                0,
                tid,
            )
        }
    }

    fn read_rip(tid: u32) -> u64 {
        let ht = open_thread_for_ctx(tid);
        if ht.is_null() {
            return 0;
        }
        let mut buf = AlignedContext::new();
        unsafe {
            (*buf.as_ctx_mut()).ContextFlags = CONTEXT_ALL;
            if GetThreadContext(ht, buf.as_ctx_mut()) == 0 {
                CloseHandle(ht);
                return 0;
            }
            let rip = (*buf.as_ctx()).Rip;
            CloseHandle(ht);
            rip
        }
    }

    fn set_trap_flag(tid: u32) {
        let ht = open_thread_for_ctx(tid);
        if ht.is_null() {
            return;
        }
        let mut buf = AlignedContext::new();
        unsafe {
            (*buf.as_ctx_mut()).ContextFlags = CONTEXT_ALL;
            if GetThreadContext(ht, buf.as_ctx_mut()) == 0 {
                CloseHandle(ht);
                return;
            }
            (*buf.as_ctx_mut()).EFlags |= TRAP_FLAG;
            SetThreadContext(ht, buf.as_ctx());
            CloseHandle(ht);
        }
    }

    fn rewind_and_set_trap(tid: u32, back_to: u64) {
        let ht = open_thread_for_ctx(tid);
        if ht.is_null() {
            return;
        }
        let mut buf = AlignedContext::new();
        unsafe {
            (*buf.as_ctx_mut()).ContextFlags = CONTEXT_ALL;
            if GetThreadContext(ht, buf.as_ctx_mut()) == 0 {
                CloseHandle(ht);
                return;
            }
            (*buf.as_ctx_mut()).Rip = back_to;
            (*buf.as_ctx_mut()).EFlags |= TRAP_FLAG;
            SetThreadContext(ht, buf.as_ctx());
            CloseHandle(ht);
        }
    }

    fn is_image_address(modules: &HashMap<u64, ImageRange>, addr: u64) -> bool {
        modules
            .values()
            .any(|r| addr >= r.base && addr < r.base + r.size.max(1))
    }

    fn is_dynamic_executable(hproc: HANDLE, addr: u64) -> bool {
        let mut mbi: MaybeUninit<MEMORY_BASIC_INFORMATION> = MaybeUninit::uninit();
        let sz = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let got = unsafe { VirtualQueryEx(hproc, addr as _, mbi.as_mut_ptr(), sz) };
        if got < sz {
            return false;
        }
        let mbi = unsafe { mbi.assume_init() };
        // MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000
        if mbi.State != 0x1000 || mbi.Type != 0x20000 {
            return false;
        }
        // strip PAGE_GUARD (0x100) / PAGE_NOCACHE (0x200) / PAGE_WRITECOMBINE (0x400)
        let base_protect = mbi.Protect & !(0x100 | 0x200 | 0x400);
        matches!(
            base_protect,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }
}
