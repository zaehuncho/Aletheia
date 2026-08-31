# Changelog

All notable changes to this project.
Format inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
version scheme is [SemVer](https://semver.org/spec/v2.0.0.html).

## [0.2.0] – 2026-08-31

The Rust + Tauri workbench release. The Python engine is still the reference
implementation (locked by 12 decompiler golden files); the Rust engine now
covers PE parsing, packer detection, disassembly, dynamic unpack, and a
lightweight decompiler, all wired into a native workbench UI.

### Added

- **Rust + Tauri workbench** (`rust/aletheia-app/`). Frameless custom-chrome
  window, three-column layout with drag-and-drop pane reordering, resizable
  splits persisted per-viewer, Ctrl+F find in the disassembly and decompile
  panes, cursor-tracking welcome background, syntax-highlighted operands,
  entropy mini-bars, drag-drop file open. Native x86_64 Windows exe; MSI +
  NSIS installers ship in the release artifacts.
- **`aletheia-core/pe.rs`** — direct port of `aletheia/pe.py`. Zero PE-crate
  dependencies; struct-by-struct byte reader with per-section entropy,
  R/W/X flags, RVA-to-offset resolution, import table walk.
- **`aletheia-core/detect.rs`** — port of `aletheia/detect.py`, byte-verdict
  compatible with the Python side. 11 protector signatures + Lethe magic +
  heuristic scoring. `NORMAL_NAMES` extended with modern Windows-internal
  sections (`fothk`, `_RDATA`, `PROTDATA`, `.retplne`, `.giats`, `.gehcont`,
  `CPADinfo`, `malloc_h`) so `notepad.exe` reads 100% clean instead of the
  previous 85% false positive.
- **`aletheia-core/disasm.rs`** — iced-x86 recursive descent + CFG + xrefs.
- **`aletheia-core/decompile.rs`** — lightweight x64 → C-flavored emitter.
  Per-instruction lowering + if-then triangle collapse. Not a port of the
  full Python SSA pipeline; the emitter is honest about what it recovered
  and points at the Python CLI for full analysis.
- **`aletheia-core/unpack.rs`** — Win32 Debug API single-stepping detector
  with three "levers" over the Python baseline:
  - **Lever 1: anti-anti-debug.** PEB.BeingDebugged + PEB.NtGlobalFlag
    patches so IsDebuggerPresent-class checks report clean.
  - **Lever 2: guard-page tracking** (opt-in). `PAGE_GUARD` on every
    executable page; fires on "written since load" execution.
  - **Lever 3: ntdll API hooks.** `NtAllocateVirtualMemory`,
    `NtProtectVirtualMemory`, `NtCreateThreadEx` breakpointed; every
    executable alloc / W-to-X flip / thread spawn recorded as an event.
- **In-image packer-target predicate**: UPX/ASPack/PECompact-family jumps
  into `SizeOfRawData==0` or RWX sections now fire in single-digit ms.
- **Auto-rundll32 wrap for DLLs**: `run_unpack` detects `is_dll` from the
  headers and wraps as `rundll32.exe "<path>",#1` so `DllMain` runs — the
  detector fires from there just as well.
- **`hv/`** — clean-room Intel VT-x/EPT + AMD-V/NPT VMI hypervisor
  scaffold with a VM-gated WDK build script. The current source has not
  been signed, loaded, or runtime-validated; see `hv/BRINGUP.md` for the
  isolated-VM checklist.
- **Improved dynamic-unpack error messages**: 193 → BAD_EXE_FORMAT with
  DLL / .sys / arch hints; 740 → ELEVATION_REQUIRED; 5 → ACCESS_DENIED
  with AV/SmartScreen guidance; 2 → FILE_NOT_FOUND.
- **`test-corpus/canary/`** — benign `VirtualAlloc(RWX)` + shellcode
  write-then-execute demo. Standalone Rust binary; documented as test
  data only. Detection demo: `cargo run -p aletheia-core --release
  --example unpack_canary`.

### Fixed

- `NORMAL_NAMES` false-positive on `notepad.exe` (was 85%, now 100%).
- IPC address parameter overflow when the recursive disassembler followed
  a call target into unmapped memory on packed sections (`decompile_at`
  and `disasm_at` now accept `u64 addr` with normalization).
- Center pane's `flex-1 min-h-0` was inside non-flex wrappers, so its
  overflow container sized wrong and scrollbars disappeared. Wrappers
  now carry `flex flex-col`.
- Splitter divider was 1 px in a border-matching color (effectively
  invisible). Now 4 px with a distinct surface-3 rest color, cyan on
  hover/drag, and a wider hit target.
- Center split could push the bottom pane off-screen on a small window
  (previous clamp was 160..2000 wall-clock px, not window-relative).
  Now clamps against the container's live height via `ResizeObserver`.

### Changed

- The `viewer/` static browser dashboard remains available as an optional,
  offline legacy viewer; the Rust workbench is now the primary UI.

## [0.1.0] – 2026-08-30

Initial Python-only release. 21 modules, 12,180 LoC, 387 pytest tests,
12 decompiler golden files, Windows CI green. Full pipeline documented
in the top-level `README.md`.
